"""The certificate proposer: an interprocedural abstract interpreter.

Untrusted by construction.  It walks the control-flow graph over the domain in
`abstract_domains.py`, keeping one abstract state per *context*
`(instruction start, routine, ghost NMI-enable bit)`, and writes the result as
a certificate for `formal/verify/certificate.py` to check.  Nothing here is
evidence: a proposal that is too strong produces failed verification
conditions, and a proposal that is too weak produces failed ones too.  Only
the checker's verdicts count.

What it models beyond registers and flags:

* **RAM cells.**  A fixed, small set of *tracked* cells carries a value set.
  Keeping it small matters: every tracked cell becomes a conjunct in every
  query the checker builds.
* **The frame rule at calls.**  A call joins the callee's `Post` over the
  cells of its `Mod` and leaves every other cell alone.
* **Dispatch refinement.**  At a `JSR $8E04` the JumpEngine's effect is
  applied exactly, and if the accumulator was a copy of a RAM cell then the
  target for index `i` refines that cell to the values whose low seven bits
  are `i`.
* **The ghost NMI-enable bit.**  Part of the context key, updated from writes
  to PPU control, which is what decides where an NMI may interleave.
* **The handler as a loop.**  Every context whose enable bit is 1 pushes the
  handler's entry state and receives the handler's `Post` back.

Contracts (`Mod`, `use`, `Post`) and the invariants depend on each other, so
the whole analysis is iterated: contracts start empty (optimistic) and the
analysis is re-run until `Mod` and `use` stop growing, then once more to
produce the invariants that are actually emitted.
"""
from __future__ import annotations

import json
import os
from collections import defaultdict
from dataclasses import dataclass, replace

from analysis.cfg import JUMPENGINE, CFG
from analysis.decoder import Flow, Instruction

from . import abstract_domains as ad
from .abstract_domains import EMPTY, FULL, Abs
from .routine_contracts import ALL_CELLS, Contract, routine_entries

#: cap on how many concrete effective addresses an instruction may have
#: before its target is treated as unknown
ADDRESS_CAP = 96
#: cap on tracked cells; every tracked cell costs a conjunct in every query
TRACKED_CAP = 96
#: how many times a context may be refined before it is widened to the top
#: of the domain.  Value sets grow monotonically under join, so without a
#: budget a loop can take hundreds of passes to settle; widening is sound (it
#: only weakens the proposal) and bounds the analysis.
UPDATE_BUDGET = 20
#: how many refinements before the tracked cells are widened too.  Cells
#: settle much faster than index registers, so they get a longer rope.
CELL_BUDGET = 160
#: depth sets wider than this, or deeper than this, are widened away
DEPTH_SET_CAP = 6
DEPTH_CAP = 48

ENGINE_CELLS = frozenset({0x04, 0x05, 0x06, 0x07})

#: `(flag, relation, register, k)` facts a comparison establishes
COMPARE_REGISTER = {"CMP": "a", "CPX": "x", "CPY": "y"}
LOAD_REGISTER = {"LDA": "a", "LDX": "x", "LDY": "y"}
TRANSFER = {"TAX": ("a", "x"), "TAY": ("a", "y"), "TXA": ("x", "a"),
            "TYA": ("y", "a"), "TSX": ("s", "x")}
BRANCH_FLAG = {"BCC": ("c", False), "BCS": ("c", True),
               "BNE": ("z", False), "BEQ": ("z", True),
               "BPL": ("n", False), "BMI": ("n", True),
               "BVC": ("v", False), "BVS": ("v", True)}
FORBIDDEN = frozenset({"BRK", "JAM", "CLI", "PLP",
                       "XAA", "LXA", "SHA", "SHX", "SHY", "TAS"})


#: which registers an instruction can change, by mnemonic
_CLOBBERS = {"a": frozenset({"LDA", "PLA", "TXA", "TYA", "AND", "ORA", "EOR",
                             "ADC", "SBC", "LAX", "LAS", "XAA", "LXA", "ANC",
                             "ALR", "ARR", "SLO", "RLA", "SRE", "RRA",
                             "USBC", "ASL", "LSR", "ROL", "ROR"}),
             "x": frozenset({"LDX", "TAX", "TSX", "INX", "DEX", "LAX", "SBX",
                             "LAS", "LXA"}),
             "y": frozenset({"LDY", "TAY", "INY", "DEY"})}


def _drop_copies(state: Abs, cells) -> Abs:
    """A `register == RAM[cell]` fact dies when anything may write the cell.

    `set_cell` only does this for *tracked* cells, and a copy may name an
    untracked one, so every write has to be filtered against the whole set of
    cells it can reach.
    """
    if not state.copies:
        return state
    if cells is ALL_CELLS:
        return replace(state, copies=frozenset())
    return replace(state, copies=frozenset(
        (r, c) for r, c in state.copies if c not in cells))


def _clobbered(mnemonic: str) -> frozenset:
    """Registers an instruction may change.  Shifts are counted for `A` even
    in memory mode, which only loses precision."""
    return frozenset(name for name, names in _CLOBBERS.items()
                     if mnemonic in names)


def _is_ppu_control(address: int) -> bool:
    return 0x2000 <= address < 0x4000 and address & 7 == 0


def _widen(state: Abs, *, cells: bool) -> Abs:
    """Forget what the domain cannot settle quickly, registers first.

    The stack pointer, the depth and the frame flag are always kept: they are
    what the frame rule needs, they follow from the call structure rather than
    from data, and they converge in a few passes.

    The flags are never widened: three-valued, they settle after one join,
    and they cost nothing to carry.  Dropping them was what made the `BNE` at
    `$D963` look like it could fall through into the `JAM` at `$D965` -- in
    one of the five routines that own that instruction, and not in the other
    four.

    Registers are widened long before cells.  A counted loop walks an index
    register through dozens of values, so the register's set is what takes
    dozens of passes to settle -- while the cells the loop writes settle at
    once.  Dropping the cells with the registers was what lost
    "PPU-control bit 7 is clear" across the handler's own timer loop at
    `$810E`, and with it the ghost enable bit for the whole program.
    """
    state = replace(state, a=FULL, x=FULL, y=FULL, copies=frozenset(),
                    rel=())
    return replace(state, cells=()) if cells else state


@dataclass(frozen=True)
class Ctx:
    pc: int
    routine: int
    en: int

    @property
    def key(self) -> str:
        return f"{self.pc:04X}@{self.routine:04X}/{self.en}"


# --------------------------------------------------------------------------
# instruction-level transfer
# --------------------------------------------------------------------------

class Transfer:
    """Abstract semantics of one instruction over `Abs`."""

    def __init__(self, prg: bytes, tracked: frozenset):
        self.prg = prg
        self.tracked = tracked

    # -- memory ------------------------------------------------------------

    def addresses(self, state: Abs, instruction: Instruction):
        """Concrete effective addresses, or None when not determined."""
        mode = instruction.info.mode
        operands = instruction.operands
        if mode in ("imp", "acc", "imm", "rel"):
            return frozenset()
        if mode == "zp":
            return frozenset({operands[0]})
        if mode == "abs":
            return frozenset({instruction.operand16})
        if mode in ("zpx", "zpy"):
            index = state.x if mode == "zpx" else state.y
            if ad.size(index) > ADDRESS_CAP:
                return None
            return frozenset((operands[0] + i) & 0xFF
                             for i in ad.values(index))
        if mode in ("abx", "aby"):
            index = state.x if mode == "abx" else state.y
            if ad.size(index) > ADDRESS_CAP:
                return None
            base = instruction.operand16
            return frozenset((base + i) & 0xFFFF for i in ad.values(index))
        if mode == "izx":
            pointers = frozenset((operands[0] + i) & 0xFF
                                 for i in ad.values(state.x))
            if len(pointers) > 8:
                return None
            out = set()
            for pointer in pointers:
                low = state.cell(pointer)
                high = state.cell((pointer + 1) & 0xFF)
                if ad.size(low) * ad.size(high) > ADDRESS_CAP:
                    return None
                for lo in ad.values(low):
                    for hi in ad.values(high):
                        out.add(lo | hi << 8)
            return frozenset(out) if len(out) <= ADDRESS_CAP else None
        if mode == "izy":
            pointer = operands[0]
            low = state.cell(pointer)
            high = state.cell((pointer + 1) & 0xFF)
            if (ad.size(low) * ad.size(high) * ad.size(state.y)
                    > ADDRESS_CAP):
                return None
            out = set()
            for lo in ad.values(low):
                for hi in ad.values(high):
                    for i in ad.values(state.y):
                        out.add(((lo | hi << 8) + i) & 0xFFFF)
            return frozenset(out) if len(out) <= ADDRESS_CAP else None
        return None

    def span(self, state: Abs, instruction: Instruction):
        """A conservative `(low, high)` CPU-address range, or None.

        Used when the exact address set is too wide to enumerate: a store
        whose range stays below `$2000` cannot touch PPU control, and the
        cells it can reach are the mirror images of that range.  Without this
        every wide store would forget every tracked cell *and* fork the ghost
        enable bit, which is what makes the RAM-clearing loop at `$90CC`
        unanalysable.
        """
        mode = instruction.info.mode
        operands = instruction.operands
        if mode in ("zp", "zpx", "zpy"):
            return (0x00, 0xFF)
        if mode == "abs":
            return (instruction.operand16, instruction.operand16)
        if mode in ("abx", "aby"):
            base = instruction.operand16
            return (base, min(0xFFFF, base + 0xFF))
        if mode in ("izx", "izy"):
            if mode == "izx":
                pointers = [(operands[0] + i) & 0xFF
                            for i in ad.values(state.x)]
            else:
                pointers = [operands[0]]
            if len(pointers) > 8:
                return None
            bases = set()
            for pointer in pointers:
                low = state.cell(pointer)
                high = state.cell((pointer + 1) & 0xFF)
                if ad.size(low) * ad.size(high) > 1024:
                    return None
                for lo in ad.values(low):
                    for hi in ad.values(high):
                        bases.add(lo | hi << 8)
            if not bases:
                return None
            index = 0 if mode == "izx" else 0xFF
            return (min(bases), min(0xFFFF, max(bases) + index))
        return None

    def read(self, state: Abs, addresses) -> int:
        if addresses is None:
            return FULL
        mask = 0
        for address in addresses:
            if address >= 0x8000:
                mask |= ad.one(self.prg[address - 0x8000])
            elif address < 0x2000:
                mask |= state.cell(address)
            else:
                return FULL                        # device or open bus
            if mask == FULL:
                return FULL
        return mask

    def write(self, state: Abs, addresses, mask: int, span=None):
        """Returns (state, written cells or ALL_CELLS, enable values)."""
        if addresses is None:
            if span is None:
                return (state.forget_cells(self.tracked), ALL_CELLS,
                        frozenset({0, 1}))
            low, high = span
            if high - low >= 0x800:
                cells = ALL_CELLS
            else:
                cells = frozenset(a & 0x7FF for a in range(low, high + 1)
                                  if a < 0x2000)
            enable = frozenset()
            if high >= 0x2000 and low < 0x4000:
                enable = frozenset({1 if v & 0x80 else 0
                                    for v in ad.values(mask)})
            reached = self.tracked if cells is ALL_CELLS else (
                self.tracked & cells)
            return (_drop_copies(state.forget_cells(reached), cells), cells,
                    enable)
        strong = len(addresses) == 1
        written = set()
        enable = set()
        for address in addresses:
            if address < 0x2000:
                cell = address & 0x7FF
                written.add(cell)
                if cell in self.tracked:
                    value = mask if strong else state.cell(cell) | mask
                    state = state.set_cell(cell, value)
            elif 0x2000 <= address < 0x4000 and address & 7 == 0:
                enable |= {1 if v & 0x80 else 0 for v in ad.values(mask)}
        written = frozenset(written)
        return _drop_copies(state, written), written, frozenset(enable)

    # -- flags and relations ----------------------------------------------

    @staticmethod
    def _kill(state: Abs, *, register: str | None = None,
              flags: tuple = ()) -> Abs:
        rel = tuple(r for r in state.rel
                    if (register is None or r[2] != register)
                    and r[0] not in flags)
        return replace(state, rel=rel)

    def _load(self, state: Abs, register: str, mask: int) -> Abs:
        state = self._kill(state, register=register, flags=("z", "n"))
        state = state.set_register(register, mask).set_nz(mask)
        return replace(state, rel=state.rel + (("z", "eq", register, 0),
                                               ("n", "bit7sub", register, 0)))

    # -- the step ----------------------------------------------------------

    def step(self, state: Abs, instruction: Instruction):
        """Returns (state after, written cells, enable values, ok).

        `ok` is False for an instruction whose effect is not modelled; the
        caller then stops, because the certificate must not claim a context it
        cannot describe.
        """
        info = instruction.info
        name, mode = info.mnemonic, info.mode
        addresses = self.addresses(state, instruction)
        written: frozenset = frozenset()
        enable: frozenset = frozenset()

        if name == "NOP":
            return state, written, enable, True
        if name in LOAD_REGISTER:
            register = LOAD_REGISTER[name]
            if mode == "imm":
                value = ad.one(instruction.operands[0])
            else:
                value = self.read(state, addresses)
            state = self._load(state, register, value)
            if (mode in ("zp", "abs") and addresses is not None
                    and len(addresses) == 1):
                cell = next(iter(addresses))
                if cell < 0x2000:
                    state = replace(state, copies=state.copies
                                    | {(register, cell & 0x7FF)})
            return state, written, enable, True
        if name in ("STA", "STX", "STY"):
            source = {"STA": "a", "STX": "x", "STY": "y"}[name]
            state, written, enable = self.write(
                state, addresses, state.register(source),
                self.span(state, instruction))
            if (mode in ("zp", "abs") and addresses
                    and len(addresses) == 1):
                cell = next(iter(addresses))
                if cell < 0x2000:
                    state = replace(state, copies=state.copies
                                    | {(source, cell & 0x7FF)})
            return state, written, enable, True
        if name in TRANSFER:
            source, destination = TRANSFER[name]
            return (self._load(state, destination, state.register(source)),
                    written, enable, True)
        if name == "TXS":
            state = self._kill(state, register="s")
            return state.set_register("s", state.x), written, enable, True
        if name in ("INX", "INY", "DEX", "DEY"):
            register = "x" if name in ("INX", "DEX") else "y"
            delta = 1 if name in ("INX", "INY") else -1
            mask = ad.shift_by(state.register(register), delta)
            return self._load(state, register, mask), written, enable, True
        if name in ("AND", "ORA", "EOR"):
            operation = {"AND": lambda a, m: a & m,
                         "ORA": lambda a, m: a | m,
                         "EOR": lambda a, m: a ^ m}[name]
            operand = (ad.one(instruction.operands[0]) if mode == "imm"
                       else self.read(state, addresses))
            # Not "absorbing": an unconstrained accumulator does *not* make
            # `AND #$7F` unconstrained, and masking against an immediate is
            # how this program narrows almost everything.
            mask = ad.binary(state.a, operand, operation)
            return self._load(state, "a", mask), written, enable, True
        if name in ("ADC", "SBC"):
            operand = (ad.one(instruction.operands[0]) if mode == "imm"
                       else self.read(state, addresses))
            return (self._addsub(state, operand, subtract=name == "SBC"),
                    written, enable, True)
        if name in COMPARE_REGISTER:
            register = COMPARE_REGISTER[name]
            operand = (ad.one(instruction.operands[0]) if mode == "imm"
                       else self.read(state, addresses))
            return (self._compare(state, register, operand, mode == "imm",
                                  instruction),
                    written, enable, True)
        if name in ("ASL", "LSR", "ROL", "ROR"):
            if mode == "acc":
                mask, carry = self._shift(state, state.a, name)
                state = self._load(state, "a", mask)
                return (self._kill(replace(state, c=carry), flags=("c",)),
                        written, enable, True)
            operand = self.read(state, addresses)
            mask, carry = self._shift(state, operand, name)
            state, written, enable = self.write(state, addresses, mask,
                                                self.span(state, instruction))
            state = self._kill(state, flags=("c", "z", "n"))
            return (replace(state.set_nz(mask), c=carry), written, enable,
                    True)
        if name in ("INC", "DEC"):
            delta = 1 if name == "INC" else -1
            operand = self.read(state, addresses)
            mask = ad.shift_by(operand, delta)
            state, written, enable = self.write(state, addresses, mask,
                                                self.span(state, instruction))
            state = self._kill(state, flags=("z", "n"))
            return state.set_nz(mask), written, enable, True
        if name == "BIT":
            operand = self.read(state, addresses)
            product = ad.binary(state.a, operand, lambda a, m: a & m)
            state = self._kill(state, flags=("z", "n", "v"))
            return (replace(state, z=ad.agree(product, lambda v: v == 0),
                            n=ad.agree(operand, lambda v: v & 0x80 != 0),
                            v=ad.agree(operand, lambda v: v & 0x40 != 0)),
                    written, enable, True)
        if name in ("CLC", "SEC", "CLV", "CLD", "SED", "SEI"):
            state = self._kill(state, flags=("c", "v"))
            field = {"CLC": ("c", False), "SEC": ("c", True),
                     "CLV": ("v", False), "CLD": ("d", False),
                     "SED": ("d", True), "SEI": ("i", True)}[name]
            return replace(state, **{field[0]: field[1]}), written, enable, True
        if name == "PHA":
            return state, written, enable, True
        if name == "PHP":
            return state, written, enable, True
        if name == "PLA":
            return self._load(state, "a", FULL), written, enable, True
        return state, written, enable, False

    @staticmethod
    def pop(state: Abs) -> Abs:
        depth = (None if state.depth is None
                 else frozenset(d - 1 for d in state.depth))
        if depth is not None and any(d < 0 for d in depth):
            depth = None
        return replace(state, depth=depth, s=ad.shift_by(state.s, 1))

    def _addsub(self, state: Abs, operand: int, *, subtract: bool) -> Abs:
        if (state.a == FULL or operand == FULL or state.c is None
                or ad.size(state.a) * ad.size(operand) > 1024):
            state = self._load(state, "a", FULL)
            return self._kill(replace(state, c=None, v=None),
                              flags=("c", "v"))
        carry_in = 1 if state.c else 0
        out, carries, overflows = 0, set(), set()
        for a in ad.values(state.a):
            for m in ad.values(operand):
                if subtract:
                    total = a - m - (1 - carry_in)
                    result = total & 0xFF
                    carries.add(total >= 0)
                    overflows.add(bool((a ^ m) & (a ^ result) & 0x80))
                else:
                    total = a + m + carry_in
                    result = total & 0xFF
                    carries.add(total > 0xFF)
                    overflows.add(bool(~(a ^ m) & (a ^ result) & 0x80))
                out |= 1 << result
        state = self._load(state, "a", out)
        return self._kill(
            replace(state,
                    c=carries.pop() if len(carries) == 1 else None,
                    v=overflows.pop() if len(overflows) == 1 else None),
            flags=("c", "v"))

    def _compare(self, state: Abs, register: str, operand: int,
                 immediate: bool, instruction: Instruction) -> Abs:
        left = state.register(register)
        carry = zero = negative = None
        if left and operand:
            # exact and O(1): every pair agrees on `a >= m` exactly when the
            # sets do not interleave, and on `a == m` exactly when they are
            # disjoint or the same single value
            low_left, high_left = ad.bounds(left)
            low_right, high_right = ad.bounds(operand)
            if low_left >= high_right:
                carry = True
            elif high_left < low_right:
                carry = False
            if not left & operand:
                zero = False
            elif left == operand and ad.size(left) == 1:
                zero = True
            if ad.size(left) * ad.size(operand) <= 1024:
                negative = ad.agree(ad.binary(left, operand,
                                              lambda a, m: (a - m) & 0xFF),
                                    lambda v: v & 0x80 != 0)
        state = self._kill(state, flags=("c", "z", "n"))
        state = replace(state, c=carry, z=zero, n=negative)
        if immediate:
            k = instruction.operands[0]
            state = replace(state, rel=state.rel
                            + (("c", "uge", register, k),
                               ("z", "eq", register, k),
                               ("n", "bit7sub", register, k)))
        return state

    @staticmethod
    def _shift(state: Abs, mask: int, name: str):
        carries = (0, 1) if state.c is None else (1 if state.c else 0,)
        out, carry_out = 0, set()
        for value in ad.values(mask):
            for carry_in in carries:
                if name == "ASL":
                    result, bit = (value << 1) & 0xFF, value & 0x80
                elif name == "LSR":
                    result, bit = value >> 1, value & 1
                elif name == "ROL":
                    result, bit = ((value << 1) | carry_in) & 0xFF, value & 0x80
                else:
                    result, bit = (value >> 1) | (carry_in << 7), value & 1
                out |= 1 << result
                carry_out.add(bool(bit))
        return out, (carry_out.pop() if len(carry_out) == 1 else None)

    # -- branches ----------------------------------------------------------

    def branch(self, state: Abs, instruction: Instruction):
        """[(target, state)] for the feasible sides of a conditional."""
        flag, wanted = BRANCH_FLAG[instruction.info.mnemonic]
        known = getattr(state, flag)
        out = []
        for taken in (True, False):
            value = wanted if taken else not wanted
            if known is not None and known != value:
                continue
            refined = self._refine(replace(state, **{flag: value}), flag,
                                   value)
            if refined is None or not refined.feasible:
                continue
            target = (instruction.branch_target if taken
                      else instruction.end)
            out.append((target, refined))
        return out

    def _refine(self, state: Abs, flag: str, value: bool) -> Abs | None:
        for name, op, register, k in state.rel:
            if name != flag:
                continue
            mask = state.register(register)
            if op == "uge":
                keep = (lambda v: v >= k) if value else (lambda v: v < k)
            elif op == "eq":
                keep = (lambda v: v == k) if value else (lambda v: v != k)
            elif op == "bit7sub":
                keep = ((lambda v: (v - k) & 0x80) if value
                        else (lambda v: not (v - k) & 0x80))
            else:
                continue
            narrowed = ad.restrict(mask, keep)
            if narrowed == EMPTY:
                return None
            state = replace(state, **{register: narrowed})
        return state


# --------------------------------------------------------------------------
# tracked cells
# --------------------------------------------------------------------------

def tracked_cells(graph: CFG, extra: frozenset = frozenset()) -> frozenset:
    """A small set of cells worth carrying a value set for.

    The zero page's first eight cells (indirect-mode pointers and the
    JumpEngine's scratch), the PPU-control mirror, and whatever absolute or
    zero-page location is loaded close before a dispatch site -- those are the
    cells a dispatch index can come from.
    """
    out = set(range(0x08)) | {0x778} | set(extra)
    for site in graph.dispatches:
        frontier = {site}
        for _ in range(14):
            nxt = set()
            for pc in frontier:
                node = graph.nodes.get(pc)
                if node is None:
                    continue
                instruction = node.instruction
                if instruction.info.mnemonic in ("LDA", "LDX", "LDY", "STA",
                                                 "STX", "STY", "INC", "DEC"):
                    mode = instruction.info.mode
                    if mode == "zp":
                        out.add(instruction.operands[0])
                    elif mode == "abs" and instruction.operand16 < 0x2000:
                        out.add(instruction.operand16 & 0x7FF)
                nxt |= {p for p, _ in node.predecessors}
            frontier = nxt
    return frozenset(sorted(out)[:TRACKED_CAP])


# --------------------------------------------------------------------------
# the interprocedural fixpoint
# --------------------------------------------------------------------------

class Proposer:
    def __init__(self, graph: CFG, prg: bytes, *, hints=None,
                 max_rounds: int = 8, max_steps: int = 4_000_000):
        self.graph = graph
        self.prg = prg
        self.hints = hints or {}
        self.max_rounds = max_rounds
        self.max_steps = max_steps
        self.kinds = routine_entries(graph)
        self.root = next(e for e, k in self.kinds.items() if k == "root")
        self.handler = next(e for e, k in self.kinds.items()
                            if k == "handler")
        self.window_pcs = self._windows()
        #: hints that also want the ghost enable bit
        self.wide = {self.hints["*"]} if "*" in self.hints else set()
        self.tracked = tracked_cells(graph)
        self.transfer = Transfer(prg, self.tracked)
        self.contracts = {entry: Contract(entry, kind)
                          for entry, kind in self.kinds.items()}
        self.contracts[self.root].s0 = 0xFF
        self.states: dict[Ctx, Abs] = {}
        self.notes: list[str] = []
        self.steps = 0
        self.round = 0
        #: context -> (register, bit 7 value) forced by a PPU-control store
        self.forks: dict[Ctx, tuple] = {}
        #: the state in which an NMI may begin, joined over every such point:
        #: `I_frame`.  Accumulated during a pass, folded in between passes.
        self.frame_state: Abs = Abs.BOTTOM
        self.next_frame: Abs = Abs.BOTTOM
        #: routines the last pass reached, and those of them with an exit
        self._reached: set = set()
        self._returning: set = set()
        self.unmodelled: dict[int, str] = {}

    # -- one analysis pass -------------------------------------------------

    def _seed(self) -> dict[Ctx, Abs]:
        """Cold boot, plus the handler's accumulated entry state.

        The handler is analysed as a loop whose entry state is `I_frame`
        (design section 6).  Seeding it once per pass, instead of pushing it
        from every context where an NMI may begin, is what keeps the handler's
        prologue off the widening budget -- and the prologue is where the
        invariant "PPU-control bit 7 is clear" is established, so losing it
        there loses the ghost enable bit for the whole program.
        """
        out = {Ctx(self.root, self.root, 0): Abs(i=True, depth=None,
                                                 frame=False)}
        if not self.frame_state.bottom:
            out[Ctx(self.handler, self.handler, 1)] = self.frame_state
        return out

    def analyse(self) -> None:
        self.states = {}
        self.unmodelled = {}
        self.next_frame = Abs.BOTTOM
        pending = dict(self._seed())
        for context, state in pending.items():
            self.states[context] = state
        work = list(pending)
        updates: dict[Ctx, int] = defaultdict(int)
        written: dict[int, set] = defaultdict(set)
        touches: dict[int, bool] = defaultdict(bool)
        clobbers: dict[int, set] = defaultdict(set)
        peak: dict[int, int] = defaultdict(int)
        exits: dict[int, Abs] = defaultdict(lambda: Abs.BOTTOM)
        exit_en: dict[int, set] = defaultdict(set)
        self.steps = 0
        while work:
            context = work.pop()
            state = self.states[context]
            self.steps += 1
            if self.steps > self.max_steps:
                self.notes.append("step cap reached; analysis truncated")
                break
            for target, new in self._successors(context, state, written,
                                                peak, exits, exit_en,
                                                touches, clobbers):
                old = self.states.get(target, Abs.BOTTOM)
                merged = old.join(new)
                if merged.key() == old.key():
                    continue
                updates[target] += 1
                if updates[target] > UPDATE_BUDGET:
                    merged = self._hinted(
                        target.pc, target.routine, target.en,
                        _widen(merged, cells=updates[target]
                               > CELL_BUDGET))
                    if merged.key() == old.key():
                        continue
                self.states[target] = merged
                work.append(target)
        self._reached = {c.routine for c in self.states}
        self._returning = {r for r, e in exit_en.items() if e}
        self._written = written
        self._touches = touches
        self._clobbers = clobbers
        self._peak = peak
        self._exits = exits
        self._exit_en = exit_en

    def _successors(self, context: Ctx, state: Abs, written, peak, exits,
                    exit_en, touches, clobbers):
        """All (context, state) a transition from `context` can reach."""
        node = self.graph.nodes.get(context.pc)
        if node is None:
            return []
        instruction = node.instruction
        info = instruction.info
        routine = context.routine
        depth = state.depth
        peak[routine] = max(peak[routine],
                            max(depth) if depth else 0)
        out = []

        # An NMI may begin here, and the handler eventually returns here --
        # unless this is one of the boundaries the two timing assumptions
        # remove, where by assumption no NMI is taken.  Modelling an entry
        # there anyway would contradict the assumption the certificate
        # declares, and would make the handler re-enter itself.
        if context.en == 1 and context.pc not in self.window_pcs:
            out.extend(self._nmi(context, state))

        if info.mnemonic in FORBIDDEN:
            return out
        if info.flow is Flow.HALT:
            return out

        if info.flow is Flow.CALL and instruction.operand16 == JUMPENGINE:
            written[routine] |= ENGINE_CELLS
            peak[routine] = max(peak[routine],
                                (max(depth) if depth else 0) + 2)
            return out + self._dispatch(context, state, instruction)

        if info.flow is Flow.CALL:
            return out + self._call(context, state, instruction, written,
                                    peak)

        if info.flow is Flow.RETURN:
            if info.mnemonic == "RTS":
                exits[routine] = exits[routine].join(
                    self._after_rts(state))
                exit_en[routine].add(context.en)
            else:                                    # RTI
                exits[routine] = exits[routine].join(state)
                exit_en[routine].add(context.en)
            return out

        if info.flow is Flow.BRANCH:
            for target, refined in self.transfer.branch(state, instruction):
                out.append((Ctx(target, routine, context.en),
                            self._hinted(target, routine, context.en,
                                         refined)))
            return out

        if info.flow is Flow.JUMP:
            target = instruction.operand16
            out.append((Ctx(target, routine, context.en),
                        self._hinted(target, routine, context.en, state)))
            return out

        if info.flow is Flow.INDIRECT_JUMP:
            self.unmodelled[context.pc] = "indirect jump outside the engine"
            return out

        # ordinary instruction
        if info.mnemonic in ("PHA", "PHP"):
            state = self._push(state)
        elif info.mnemonic == "PLA":
            state = self.transfer.pop(state)
        after, cells, enable, ok = self.transfer.step(state, instruction)
        if not ok:
            self.unmodelled[context.pc] = f"{info.mnemonic} {info.mode}"
            return out
        written[routine] |= set(cells)
        clobbers[routine] |= _clobbered(info.mnemonic)
        if enable:
            touches[routine] = True
        target = instruction.end
        for value in (sorted(enable) or [context.en]):
            successor = Ctx(target, routine, value)
            if len(enable) > 1 and info.mnemonic in ("STA", "STX", "STY"):
                # The fork is on bit 7 of the stored byte, so each side knows
                # that bit.  Recording it per context rather than applying it
                # once matters: widening would otherwise throw it away, and
                # it is the fact that keeps the ghost enable bit pinned
                # through `$8EED`.  The checker splits on exactly the same
                # term, so this is a refinement it can discharge.
                self.forks[successor] = (
                    {"STA": "a", "STX": "x", "STY": "y"}[info.mnemonic],
                    value)
            out.append((successor,
                        self._hinted(target, routine, value, after)))
        return out

    @staticmethod
    def _push(state: Abs) -> Abs:
        depth = (None if state.depth is None
                 else frozenset(d + 1 for d in state.depth))
        if depth is not None and (len(depth) > DEPTH_SET_CAP
                                  or max(depth) > DEPTH_CAP):
            depth = None
        return replace(state, depth=depth, s=ad.shift_by(state.s, -1))

    @staticmethod
    def _after_rts(state: Abs) -> Abs:
        return state

    def _call(self, context: Ctx, state: Abs, instruction, written, peak):
        target = instruction.operand16
        routine = context.routine
        contract = self.contracts.get(target)
        depth = state.depth
        if contract is None:
            self.unmodelled[context.pc] = "call to a non-routine"
            return []
        peak[routine] = max(peak[routine],
                            (max(depth) if depth else 0) + 2 + contract.use)
        written[routine] |= set(contract.mod)
        entry = replace(self._push(self._push(state)),
                        depth=frozenset({0}), frame=True, status_i=False,
                        copies=frozenset(), rel=())
        out = [(Ctx(target, target, context.en),
                self._hinted(target, target, context.en, entry))]
        resumed = self._resume(state, contract)
        for register in contract.preserves:
            resumed = resumed.set_register(register, state.register(register))
        if (target in self._reached and target not in self._returning
                and self.round):
            # The callee was analysed and has no reachable `RTS`, so control
            # does not come back -- the JumpEngine's callers are like this.
            # "Not analysed yet" must not count, or the first pass after the
            # contracts appear would stop at every call.
            values = []
        elif contract.no_ppu:
            values = [context.en]
        elif contract.en_bit is not None:
            register, bit = contract.en_bit
            values = sorted({v >> bit & 1
                             for v in ad.values(state.register(register))})
        else:
            values = sorted(contract.post_en) or [context.en]
        for value in values:
            out.append((Ctx(instruction.end, routine, value),
                        self._hinted(instruction.end, routine, value,
                                     resumed)))
        return out

    def _resume(self, state: Abs, contract: Contract) -> Abs:
        """The caller's state after a call, by the frame rule."""
        cells = {cell: mask for cell, mask in state.cells
                 if cell not in contract.mod}
        post = contract.post
        if not post.bottom:
            for cell, mask in post.cells:
                if cell in contract.mod:
                    cells[cell] = mask
        copies = frozenset((r, c) for r, c in state.copies
                           if c not in contract.mod)
        out = Abs(i=True, depth=state.depth, frame=state.frame,
                  status_i=state.status_i, s=state.s,
                  copies=frozenset(), rel=())
        out = out.with_cells(cells)
        if not post.bottom:
            out = replace(out, a=post.a, x=post.x, y=post.y)
            if contract.kind != "handler":
                out = replace(out, c=post.c, z=post.z, n=post.n, v=post.v)
        del copies
        return out

    def _dispatch(self, context: Ctx, state: Abs, instruction):
        site = self.graph.dispatches[context.pc]
        routine = context.routine
        out = []
        copy_cells = [cell for register, cell in state.copies
                      if register == "a"]
        for index, entry in enumerate(site.entries):
            after = replace(state, a=ad.one(entry >> 8),
                            y=ad.one((2 * index + 2) & 0xFF),
                            copies=frozenset(), rel=())
            after = after.set_nz(ad.one(entry >> 8))
            after = after.set_cell(0x04, ad.one((context.pc + 2) & 0xFF))
            after = after.set_cell(0x05, ad.one((context.pc + 2) >> 8))
            after = after.set_cell(0x06, ad.one(entry & 0xFF))
            after = after.set_cell(0x07, ad.one(entry >> 8))
            matching = ad.restrict(state.a, lambda v: v & 0x7F == index)
            if matching == EMPTY:
                continue
            for cell in copy_cells:
                if cell in self.tracked:
                    after = after.set_cell(cell, matching)
            out.append((Ctx(entry, routine, context.en),
                        self._hinted(entry, routine, context.en, after)))
        return out

    # -- the NMI handler ---------------------------------------------------

    def _nmi(self, context: Ctx, state: Abs):
        """The handler's entry state, and the resume state back here.

        Interrupt entry keeps the interrupted registers, so they are carried
        into the handler's entry state rather than widened; the join over
        every point an NMI may begin widens them soon enough.

        On the way back, the registers are whatever `Post[H]` says.  Widening
        them here would be a real loss: the handler leaves the accumulator
        with bit 7 set (`$817C ORA #$80`), and that is what ties the ghost
        enable bit to the accumulator at the exit of `$8EED` -- the routine
        that writes PPU control for both reset and the handler.
        """
        handler = self.contracts[self.handler]
        entry = replace(state, s=ad.shift_by(state.s, -3),
                        depth=frozenset({0}), frame=True, status_i=True,
                        copies=frozenset(), rel=(), i=True)
        self.next_frame = self.next_frame.join(entry)
        out = []
        resumed = self._resume(state, handler)
        for value in (sorted(handler.post_en) or [1]):
            out.append((Ctx(context.pc, context.routine, value),
                        self._hinted(context.pc, context.routine, value,
                                     resumed)))
        return out

    # -- hints -------------------------------------------------------------

    def _normalise(self, routine: int, state: Abs) -> Abs:
        """A root routine's depth follows from its fixed `s0`."""
        if routine != self.root or state.bottom:
            return state
        if ad.size(state.s) > DEPTH_SET_CAP:
            return replace(state, depth=None)
        depth = frozenset((0xFF - v) & 0xFF for v in ad.values(state.s))
        if max(depth) > DEPTH_CAP:
            return replace(state, depth=None)
        return replace(state, depth=depth)

    def _hinted(self, pc: int, routine: int, en: int, state: Abs) -> Abs:
        hint = self.hints.get(f"{pc:04X}@{routine:04X}/{en}")
        if hint is None:
            hint = self.hints.get(f"{pc:04X}")
        if hint is None:
            hint = self.hints.get("*")
        if hint is not None and not state.bottom:
            state = (hint(state, self, en, pc, routine)
                     if hint in self.wide else hint(state, self))
        fork = self.forks.get(Ctx(pc, routine, en))
        if fork is not None and not state.bottom:
            register, value = fork
            state = state.set_register(
                register, ad.restrict(state.register(register),
                                      lambda v: (v >> 7 & 1) == value))
        return self._normalise(routine, state)

    # -- contracts ---------------------------------------------------------

    def derive_contracts(self) -> bool:
        """Fold the pass's observations into the contracts.  True if grown."""
        grown = False
        callees: dict[int, set] = defaultdict(set)
        for context in self.states:
            node = self.graph.nodes.get(context.pc)
            if node is None:
                continue
            instruction = node.instruction
            if (instruction.info.flow is Flow.CALL
                    and instruction.operand16 != JUMPENGINE
                    and instruction.operand16 in self.contracts):
                callees[context.routine].add(instruction.operand16)
        order = list(self.contracts)
        for _ in range(len(order)):
            changed = False
            for entry, contract in self.contracts.items():
                mod = set(contract.mod) | set(self._written.get(entry, ()))
                use = max(contract.use, self._peak.get(entry, 0))
                for callee in callees.get(entry, ()):
                    mod |= set(self.contracts[callee].mod)
                if mod != set(contract.mod) or use != contract.use:
                    contract.mod = frozenset(mod)
                    contract.use = use
                    changed = grown = True
            if not changed:
                break
        for entry, contract in self.contracts.items():
            if self._touches.get(entry):
                if contract.no_ppu:
                    grown = True
                contract.no_ppu = False
        for _ in range(len(order)):
            changed = False
            for entry, contract in self.contracts.items():
                if not contract.no_ppu:
                    continue
                if any(not self.contracts[c].no_ppu
                       for c in callees.get(entry, ())):
                    contract.no_ppu = False
                    changed = grown = True
            if not changed:
                break
        for entry, contract in self.contracts.items():
            keep = contract.preserves - self._clobbers.get(entry, set())
            if keep != contract.preserves:
                contract.preserves = keep
                grown = True
        for _ in range(len(order)):
            changed = False
            for entry, contract in self.contracts.items():
                keep = contract.preserves
                for callee in callees.get(entry, ()):
                    keep = keep & self.contracts[callee].preserves
                if keep != contract.preserves:
                    contract.preserves = keep
                    changed = grown = True
            if not changed:
                break
        for entry, contract in self.contracts.items():
            # `Post` is recomputed from this pass, not joined with earlier
            # ones.  `Mod` and `use` have to grow monotonically to
            # over-approximate, but `Post` does not: joining it across passes
            # makes an early pessimistic exit state permanent, and that is
            # what kept the ghost enable bit flat for every routine whose
            # call tree reaches `$8EED`.  What matters is only that the
            # emitted `Post` is implied by the final pass, which the checker
            # confirms through VC-RET-POST.
            contract.post = self._exits.get(entry, Abs.BOTTOM)
            contract.post_en = frozenset(self._exit_en.get(entry, ()))
            contract.en_bit = self._enable_relation(entry, contract)
            contract.returns = 0
        # Like `Post`, the frame state is taken from this pass rather than
        # joined with earlier ones: a pass that was pessimistic about the
        # ghost enable bit visits the handler from thousands of places, and
        # joining that in would make the handler's entry state permanently
        # useless.  Only the final pass has to be consistent, and the checker
        # is what decides whether it is.
        if self.next_frame.key() != self.frame_state.key():
            self.frame_state = self.next_frame
            grown = True
        return grown

    def _enable_relation(self, entry: int, contract: Contract):
        """`(register, bit)` if every exit's enable value is that bit.

        A routine like `$8EED` writes the accumulator to PPU control, so the
        enable bit it leaves behind is bit 7 of the accumulator.  A flat set
        of exit values is useless there, because the routine is called both to
        enable and to disable NMI.
        """
        if contract.no_ppu or contract.kind != "normal":
            return None
        exits = [(c, s) for c, s in self.states.items()
                 if c.routine == entry and c.pc in self.graph.nodes
                 and self.graph.nodes[c.pc].instruction.info.mnemonic == "RTS"]
        if not exits or len({c.en for c, _ in exits}) < 2:
            return None
        for register in ("a", "x", "y"):
            if register not in contract.preserves:
                continue
            if all(all((v >> 7 & 1) == context.en
                       for v in ad.values(state.register(register)))
                   for context, state in exits):
                return (register, 7)
        return None

    def run(self) -> None:
        for number in range(self.max_rounds):
            self.round = number
            self.analyse()
            if not self.derive_contracts():
                break
        self.round = self.max_rounds
        self.analyse()

    # -- certificate -------------------------------------------------------

    def certificate(self, *, sha1: str, extra_notes=()) -> dict:
        from formal.verify.certificate import FORMAT

        contexts = {}
        for context, state in sorted(self.states.items(),
                                     key=lambda kv: (kv[0].pc,
                                                     kv[0].routine,
                                                     kv[0].en)):
            extra = {}
            if state.status_i:
                extra["status_i"] = True
            contract = self.contracts[context.routine]
            if contract.kind == "normal" and contract.preserves:
                extra["keeps"] = sorted(contract.preserves)
            raw = state.to_json(tracked=self.tracked, extra=extra)
            hint = self.hints.get("json:" + context.key,
                                  self.hints.get(f"json:{context.pc:04X}"))
            if hint is not None and not raw.get("false"):
                raw.update(hint)
            contexts[context.key] = raw
        routines = {f"{entry:04X}": contract.to_json(self.tracked)
                    for entry, contract in sorted(self.contracts.items())
                    if any(c.routine == entry for c in self.states)
                    or contract.kind in ("root", "handler")}
        i_frame = self.i_frame()
        return {
            "format": FORMAT,
            "rom_sha1": sha1,
            "model": "T_V2 (formal/model plus MA-NMI-EDGE, MA-NMI-LATENCY)",
            "proposer": "formal/analysis (untrusted)",
            "tracked_cells": [f"{c:04X}" for c in sorted(self.tracked)],
            "nmi_windows": [f"{pc:04X}" for pc in sorted(self.window_pcs)],
            "reset_clears_enable": True,
            "reset_clears_enable_assumption":
                "MA-PPU-RESET: the reset line clears PPU control, so the "
                "ghost NMI-enable bit is 0 at the reset entry.  "
                "transitions.py carries it across a warm reset unchanged, so "
                "this removes behaviours and is an assumption, not a result.",
            "i_frame": i_frame,
            "routines": routines,
            "contexts": contexts,
            "notes": list(self.notes) + list(extra_notes),
            "unmodelled_instructions": {f"0x{pc:04X}": why for pc, why
                                        in sorted(self.unmodelled.items())},
        }

    def _windows(self) -> frozenset:
        """The instruction starts the two timing assumptions exclude.

        **MA-NMI-EDGE** covers the handler's prologue: from its entry up to
        and including the first write to PPU control that clears bit 7.  A
        second NMI inside that window needs a second vertical blank, tens of
        thousands of cycles away.

        **MA-NMI-LATENCY** covers one boundary: the instruction after the
        handler's last write to PPU control that *sets* bit 7, which must be
        the `RTI`.

        Nothing else is excluded.  In particular, if the certificate ends up
        with the enable bit set anywhere else in the handler -- because the
        write at `$816C` could re-enable NMI -- those contexts keep their
        `VC-NMI-ENTRY` obligation and fail it.  That is the honest outcome:
        neither assumption rules out a re-entry after a fresh enabling write.
        """
        out = set()
        pc = self.handler
        for _ in range(64):
            node = self.graph.nodes.get(pc)
            if node is None:
                break
            out.add(pc)
            instruction = node.instruction
            if (instruction.info.mnemonic == "STA"
                    and instruction.info.mode == "abs"
                    and _is_ppu_control(instruction.operand16)):
                break                       # the disabling write, inclusive
            if instruction.info.flow is not Flow.NORMAL:
                break
            pc = instruction.end
        for pc, node in self.graph.nodes.items():
            if node.instruction.info.mnemonic != "RTI":
                continue
            previous = [q for q, _ in node.predecessors]
            if len(previous) != 1:
                continue
            before = self.graph.nodes[previous[0]].instruction
            if (before.info.mnemonic == "STA" and before.info.mode == "abs"
                    and _is_ppu_control(before.operand16)):
                out.add(pc)
        return frozenset(out)

    def i_frame(self) -> dict:
        """The RAM part of the state in which an NMI may begin."""
        if self.frame_state.bottom:
            return {}
        out = self.frame_state.to_json(tracked=self.tracked)
        return {k: v for k, v in out.items() if k in ("cells", "pairs")}


# --------------------------------------------------------------------------


def propose(graph: CFG, prg: bytes, sha1: str, *, hints=None,
            max_rounds: int = 8) -> tuple[dict, Proposer]:
    proposer = Proposer(graph, prg, hints=hints, max_rounds=max_rounds)
    proposer.run()
    return proposer.certificate(sha1=sha1), proposer


def main() -> int:  # pragma: no cover - CLI
    from rom import b, image
    from analysis.cfg import build_from_vectors

    from .hints import HINTS

    rom = image()
    graph = build_from_vectors(b)
    certificate, proposer = propose(graph, rom.prg, rom.sha1, hints=HINTS)
    path = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "results", "certificates",
        "joint.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as handle:
        json.dump(certificate, handle, indent=1, sort_keys=True)
    print(json.dumps({
        "contexts": len(certificate["contexts"]),
        "routines": len(certificate["routines"]),
        "tracked_cells": len(proposer.tracked),
        "steps": proposer.steps,
        "unmodelled": len(proposer.unmodelled),
        "nmi_windows": certificate["nmi_windows"],
        "notes": certificate["notes"],
    }, indent=2))
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
