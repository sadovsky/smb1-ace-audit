"""Independent checker for a joint-invariant certificate (M4, M6).

This is the trusted part of the joint-invariant track.  It reads a certificate
in the abstract-state language of `formal/verify/JOINT_INVARIANT.md` section 3
and discharges every verification condition of section 4 with Z3, using
`formal.model.cpu.step` on symbolic states.  It shares no code with the
proposer in `formal/analysis`: the proposer's only output is the JSON, and the
only thing that counts is the verdict recorded here.

Design rules, in order of priority:

1. **Soundness.**  A context the certificate does not mention is `false`, and
   stepping into a `false` context from a satisfiable one is a failure.
   Nothing the certificate omits is assumed.  Every hypothesis added to a
   query is either part of the certificate, part of the machine model, or a
   fact about the immutable program image (the `PRG[a] == image[a]` axioms).
2. **Smallness.**  One function per verification condition; no inference, no
   fixpoints, no heuristics.  The checker never repairs a certificate.
3. **Directness.**  An abstract state becomes a quantifier-free
   bit-vector/array formula through `_set_member` and `Invariant.formula`, and
   every obligation is one `hypotheses => claim` solver call.

A context is a triple `(pc, routine, en)`: an instruction start, the routine
whose contract it executes under (named by its entry address), and the ghost
NMI-enable bit.  Keys are written `PPPP@RRRR/E`.

Ghosts per context: `s0` (the stack pointer on entry to `routine`, so
`depth = s0 - S`), `ret` (the 16-bit return address held in the entry frame)
and `status` (the status byte of an interrupt frame).  They are free variables
of a verification condition, and hypothesis and conclusion use the same ones,
which is what turns "the entry frame is still intact" into a one-step check.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from typing import Iterable, Sequence

import z3

from analysis.cfg import JUMPENGINE, CFG
from analysis.decoder import Flow

from ..model import cpu
from ..model.cpu import State
from ..model.memory import fresh
from ..model.transitions import ppu_control_update
from .symexec import havoc_state, through_jumpengine

FORMAT = "smb1-joint-certificate/1"

#: instructions no certificate may claim to reach (section 4, VC-FORBIDDEN)
FORBIDDEN_MNEMONICS = frozenset({"BRK", "JAM", "CLI", "PLP",
                                 "XAA", "LXA", "SHA", "SHX", "SHY", "TAS"})

HOLDS, FAILS, UNKNOWN = "holds", "fails", "unknown"

RAM_CELLS = 0x800


# --------------------------------------------------------------------------
# value sets
# --------------------------------------------------------------------------

def decode_set(runs) -> tuple[int, ...] | None:
    """`[[lo, hi], ...]` -> sorted values.  `None` means unconstrained."""
    if runs is None:
        return None
    out: list[int] = []
    for low, high in runs:
        if not 0 <= low <= high <= 255:
            raise ValueError(f"bad run [{low}, {high}]")
        out.extend(range(low, high + 1))
    values = tuple(sorted(set(out)))
    return None if len(values) == 256 else values


def encode_set(values: Iterable[int]) -> list[list[int]]:
    """Inverse of `decode_set`; here so tests and tools agree on the form."""
    runs: list[list[int]] = []
    for value in sorted(set(values)):
        if runs and value == runs[-1][1] + 1:
            runs[-1][1] = value
        else:
            runs.append([value, value])
    return runs


def _set_member(term, values: Sequence[int]):
    """`term in values`, exactly, as a quantifier-free bit-vector formula."""
    if not values:
        return z3.BoolVal(False)
    if len(values) == 256:
        return z3.BoolVal(True)
    low, high = values[0], values[-1]
    if len(values) == high - low + 1:                    # one contiguous run
        if low == 0:
            return z3.ULE(term, high)
        if high == 255:
            return z3.UGE(term, low)
        return z3.And(z3.UGE(term, low), z3.ULE(term, high))
    if len(values) <= 12:
        return z3.Or(*[term == v for v in values])
    mask = 0
    for value in values:
        mask |= 1 << value
    return z3.LShR(z3.BitVecVal(mask, 256), z3.ZeroExt(248, term)) & 1 == 1


def _ppu_control(address):
    """`address` is PPU control `$2000` or one of its mirrors."""
    return z3.And(z3.UGE(address, 0x2000), z3.ULT(address, 0x4000),
                  z3.Extract(2, 0, address) == 0)


def _flag(term, value):
    if value is None:
        return z3.BoolVal(True)
    return term if value else z3.Not(term)


def parse_cell_runs(entries: Iterable[str]) -> frozenset:
    """`"071F"` or `"0100-01FF"` -> the set of mirror-normalised cells."""
    out: set[int] = set()
    for entry in entries:
        if "-" in entry:
            low, high = entry.split("-")
            out.update(range(int(low, 16) & (RAM_CELLS - 1),
                             (int(high, 16) & (RAM_CELLS - 1)) + 1))
        else:
            out.add(int(entry, 16) & (RAM_CELLS - 1))
    return frozenset(out)


def encode_cell_runs(cells: Iterable[int]) -> list[str]:
    runs: list[list[int]] = []
    for cell in sorted(set(cells)):
        if runs and cell == runs[-1][1] + 1:
            runs[-1][1] = cell
        else:
            runs.append([cell, cell])
    return [f"{low:04X}" if low == high else f"{low:04X}-{high:04X}"
            for low, high in runs]


def _enable_constraint(enable, allowed: Sequence[int]):
    """Restrict a boolean ghost-enable term to the declared value set."""
    allowed = tuple(sorted(set(allowed)))
    if allowed == (0, 1):
        return z3.BoolVal(True)
    if allowed == (0,):
        return z3.Not(enable)
    if allowed == (1,):
        return enable
    raise ValueError(f"enable set {allowed} is empty")


# --------------------------------------------------------------------------
# certificate objects
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Ghosts:
    s0: z3.BitVecRef             # 8 bits
    ret: z3.BitVecRef            # 16 bits
    status: z3.BitVecRef         # 8 bits, interrupt frames only
    #: the values `A`, `X` and `Y` had on entry to the routine, so that a
    #: contract can say "this routine does not change A"
    entry: dict = field(default_factory=dict)

    @classmethod
    def make(cls, tag: str) -> "Ghosts":
        return cls(z3.BitVec(tag + "s0", 8), z3.BitVec(tag + "ret", 16),
                   z3.BitVec(tag + "status", 8),
                   {name: z3.BitVec(f"{tag}{name}0", 8)
                    for name in ("a", "x", "y")})


@dataclass(frozen=True)
class Context:
    pc: int
    routine: int
    en: int

    @property
    def key(self) -> str:
        return f"{self.pc:04X}@{self.routine:04X}/{self.en}"

    def __str__(self) -> str:
        return self.key


def parse_context(key: str) -> Context:
    body, enable = key.split("/")
    pc, routine = body.split("@")
    if int(enable) not in (0, 1):
        raise ValueError(f"{key}: ghost enable must be 0 or 1")
    return Context(int(pc, 16), int(routine, 16), int(enable))


def _cell(state: State, cell: int) -> z3.BitVecRef:
    return z3.Select(state.mem.ram, z3.BitVecVal(cell & (RAM_CELLS - 1), 11))


def _stack_cell(state: State, index) -> z3.BitVecRef:
    return z3.Select(state.mem.ram, z3.Concat(z3.BitVecVal(1, 3), index))


def _frame_terms(state: State, ghosts: Ghosts, frame_bytes: int) -> list:
    """"The entry frame of the current routine still holds what was pushed".

    A `JSR` pushes the high byte of its return address first, so with `s0` the
    stack pointer the routine starts with, the low byte sits at `$0100+s0+1`
    and the high byte at `$0100+s0+2`.  An interrupt frame has the pushed
    status byte below those two.
    """
    low = _stack_cell(state, ghosts.s0 + 1)
    high = _stack_cell(state, ghosts.s0 + 2)
    if frame_bytes == 2:
        return [low == z3.Extract(7, 0, ghosts.ret),
                high == z3.Extract(15, 8, ghosts.ret)]
    if frame_bytes == 3:
        return [low == ghosts.status,
                high == z3.Extract(7, 0, ghosts.ret),
                _stack_cell(state, ghosts.s0 + 3)
                == z3.Extract(15, 8, ghosts.ret)]
    raise ValueError(f"frame of {frame_bytes} bytes")


@dataclass(frozen=True)
class Invariant:
    """One abstract state (section 3).  `false` is the empty state set."""
    false: bool = False
    a: tuple[int, ...] | None = None
    x: tuple[int, ...] | None = None
    y: tuple[int, ...] | None = None
    s: tuple[int, ...] | None = None
    c: bool | None = None
    z: bool | None = None
    n: bool | None = None
    v: bool | None = None
    i: bool | None = True
    d: bool | None = None
    depth: tuple[int, ...] | None = None
    frame: bool = False
    #: the status byte saved in an interrupt frame has `I` set.  Without it
    #: the `RTI` at the end of the handler could restore a cleared `I`, since
    #: the saved byte is a ghost inside the handler's own obligations.
    status_i: bool = False
    cells: dict = field(default_factory=dict)          # cell -> values
    pairs: dict = field(default_factory=dict)          # (a, b) -> ((va, vb),)
    copies: tuple = ()                                 # (register, cell)
    #: registers still holding the value they had on entry to the routine,
    #: as `register == ghost entry value`.  This is what makes `preserves` in
    #: a contract checkable: without an entry ghost there is nothing for the
    #: `RTS` to compare against.
    keeps: tuple = ()
    #: flag-register relations `(flag, op, register, k)`, read as
    #: `flag <=> op(register, k)`.  These are what a `CMP #k` establishes and
    #: what makes the following branch informative about the register; the
    #: certificate language of section 3 has no comparison context, so without
    #: them no comparison-based bound is checkable (see section 7).
    rel: tuple = ()
    #: Parametric zero runs.  Each entry is a dict
    #: `{"page": p, "reg": r, "cmp": c, "upto": u, "when": [g, v]}` and reads
    #: as: if `g == v` (when given), then `RAM[page, k] == 0` for every
    #: `k <= upto` with `cmp(reg, k)`.  `page` is a page number or a register
    #: whose low three bits give one; `cmp` is `"ult"` for `reg < k`, `"ule"`
    #: for `reg <= k` and `"ule1"` for `reg + 1 <= k`, all unsigned on 8
    #: bits.  One conjunct per `k`, so this stays quantifier-free.
    #:
    #: This is not in section 3 of the design.  It exists because the
    #: initialisation loop at `$90CC` has an invariant parametric in the index
    #: register, which no set of per-cell value sets can express, and without
    #: it no RAM cell has any domain at all after a reset (see section 7).
    zero_runs: tuple = ()
    #: `{"reg": r, "except": [cells]}`: every RAM page *signed*-greater than
    #: the register is entirely zero apart from the excepted cells.  Signed,
    #: because the loop's page counter ends at `$FF` and that iteration is
    #: exactly the one in which every page has been cleared.
    zero_pages: dict | None = None

    FALSE: "Invariant" = None     # assigned below

    @classmethod
    def parse(cls, raw: dict) -> "Invariant":
        if raw.get("false"):
            return cls(false=True)
        cells = {}
        for key, runs in (raw.get("cells") or {}).items():
            values = decode_set(runs)
            if values is None:
                raise ValueError(f"cell {key}: unconstrained cells are "
                                 "written by omitting them")
            cells[int(key, 16) & (RAM_CELLS - 1)] = values
        pairs = {}
        for key, entries in (raw.get("pairs") or {}).items():
            left, right = key.split(",")
            pairs[(int(left, 16) & (RAM_CELLS - 1),
                   int(right, 16) & (RAM_CELLS - 1))] = tuple(
                       (int(p[0]) & 0xFF, int(p[1]) & 0xFF) for p in entries)
        zero_pages = raw.get("zero_pages")
        if zero_pages is not None:
            zero_pages = {"reg": str(zero_pages["reg"]),
                          "except": parse_cell_runs(
                              zero_pages.get("except", ()))}
        return cls(
            false=False,
            a=decode_set(raw.get("a")), x=decode_set(raw.get("x")),
            y=decode_set(raw.get("y")), s=decode_set(raw.get("s")),
            c=raw.get("c"), z=raw.get("z"), n=raw.get("n"), v=raw.get("v"),
            i=raw.get("i", True), d=raw.get("d"),
            depth=_parse_depth(raw.get("depth")),
            frame=bool(raw.get("frame", False)),
            status_i=bool(raw.get("status_i", False)),
            cells=cells, pairs=pairs,
            copies=tuple((str(c[0]), int(c[1], 16) & (RAM_CELLS - 1))
                         for c in (raw.get("copies") or ())),
            keeps=tuple(str(r) for r in (raw.get("keeps") or ())),
            rel=tuple((str(r[0]), str(r[1]), str(r[2]), int(r[3]) & 0xFF)
                      for r in (raw.get("rel") or ())),
            zero_runs=tuple(_parse_run(r)
                            for r in (raw.get("zero_runs") or ())),
            zero_pages=zero_pages)

    def mentioned_cells(self) -> frozenset | None:
        """RAM cells this invariant constrains; `None` means "all of them".

        Used to keep the havoc at a call boundary small: replacing a cell no
        claim mentions by a fresh value cannot change whether the claim holds,
        so those stores can be left out of the query without weakening it.
        """
        if self.zero_pages is not None:
            return None
        out = set(self.cells)
        for left, right in self.pairs:
            out.update((left, right))
        out.update(cell for _r, cell in self.copies)
        for run in self.zero_runs:
            pages = (range(8) if isinstance(run["page"], str)
                     else [run["page"]])
            for page in pages:
                out.update((page << 8) | k
                           for k in range(min(run["upto"], 255) + 1))
        return frozenset(out)

    def frame_cells(self, frame_bytes: int) -> frozenset | None:
        """The concrete cells the frame conjunct addresses, if determined.

        `s0 = S + depth`, so when both are single values the frame sits at
        known addresses.  This is only used to decide which cells a call
        boundary has to havoc; `None` means "fall back to the whole stack
        page", which is always sound.
        """
        if not self.frame:
            return frozenset()
        if (self.s is None or len(self.s) != 1
                or self.depth is None or len(self.depth) != 1):
            return None
        s0 = (self.s[0] + self.depth[0]) & 0xFF
        return frozenset(0x100 | ((s0 + i) & 0xFF)
                         for i in range(1, frame_bytes + 1))

    def ram_only(self) -> "Invariant":
        """The RAM part alone: what `I_frame` is allowed to talk about."""
        return Invariant(false=self.false, i=None, cells=self.cells,
                         pairs=self.pairs, zero_runs=self.zero_runs,
                         zero_pages=self.zero_pages)

    # -- encoding ----------------------------------------------------------

    def formula(self, state: State, ghosts: Ghosts, *,
                frame_bytes: int = 2) -> z3.BoolRef:
        """This abstract state as a predicate on a concrete machine state."""
        if self.false:
            return z3.BoolVal(False)
        out = [_flag(state.c, self.c), _flag(state.z, self.z),
               _flag(state.n, self.n), _flag(state.v, self.v),
               _flag(state.i, self.i), _flag(state.d, self.d)]
        for values, term in ((self.a, state.a), (self.x, state.x),
                             (self.y, state.y), (self.s, state.s)):
            if values is not None:
                out.append(_set_member(term, values))
        if self.depth is not None:
            # `S = s0 - depth` is modulo 256, so on its own it orders nothing.
            # The frame-nesting argument needs `S <= s0`: it is what makes a
            # callee's scratch area a subset of its caller's and so keeps it
            # away from the frames below it (`formal/lean/FINDINGS.md` F5).
            out.append(z3.ULE(state.s, ghosts.s0))
            out.append(z3.Or(*[state.s == ghosts.s0 - d
                               for d in self.depth]))
        if self.frame:
            out.extend(_frame_terms(state, ghosts, frame_bytes))
        if self.status_i:
            out.append(z3.Extract(2, 2, ghosts.status) == 1)
        for cell, values in sorted(self.cells.items()):
            out.append(_set_member(_cell(state, cell), values))
        for (left, right), entries in sorted(self.pairs.items()):
            out.append(z3.Or(*[
                z3.And(_cell(state, left) == va, _cell(state, right) == vb)
                for va, vb in entries]) if entries else z3.BoolVal(False))
        for register in self.keeps:
            out.append(getattr(state, register) == ghosts.entry[register])
        for register, cell in self.copies:
            out.append(getattr(state, register) == _cell(state, cell))
        for flag, op, register, k in self.rel:
            term = getattr(state, register)
            if op == "uge":
                condition = z3.UGE(term, k)
            elif op == "eq":
                condition = term == k
            elif op == "bit7sub":
                condition = z3.Extract(7, 7, term - k) == 1
            else:
                raise ValueError(f"unknown flag relation {op!r}")
            out.append(getattr(state, flag) == condition)
        for run in self.zero_runs:
            out.extend(_zero_run_terms(state, run))
        if self.zero_pages is not None:
            value = getattr(state, self.zero_pages["reg"])
            excluded = self.zero_pages["except"]
            for page in range(8):
                # signed: a page counter of $FF (-1) means every page
                guard = z3.BitVecVal(page, 8) > value
                for k in range(256):
                    cell = (page << 8) | k
                    if cell not in excluded:
                        out.append(z3.Implies(guard,
                                              _cell(state, cell) == 0))
        return z3.And(*out) if out else z3.BoolVal(True)


Invariant.FALSE = Invariant(false=True)


def _parse_depth(raw) -> tuple[int, ...] | None:
    if raw is None:
        return None
    values = tuple(sorted(set(int(d) for d in raw)))
    if any(d < 0 or d > 0xFF for d in values):
        raise ValueError(f"depth {values} must lie in 0..255")
    return values


def _parse_run(raw: dict) -> dict:
    page = raw["page"]
    if raw["cmp"] not in ("ult", "ule", "ule1"):
        raise ValueError(f"unknown zero-run comparison {raw['cmp']!r}")
    out = {"page": page if isinstance(page, str) else int(page) & 7,
           "reg": str(raw["reg"]), "cmp": str(raw["cmp"]),
           "upto": int(raw["upto"]) & 0xFF}
    if raw.get("when") is not None:
        out["when"] = (str(raw["when"][0]), int(raw["when"][1]) & 0xFF)
    return out


def _zero_run_terms(state: State, run: dict) -> list:
    register = getattr(state, run["reg"])
    guard = z3.BoolVal(True)
    if "when" in run:
        name, value = run["when"]
        guard = getattr(state, name) == value
    if isinstance(run["page"], str):
        page_bits = z3.Extract(2, 0, getattr(state, run["page"]))
    else:
        page_bits = z3.BitVecVal(run["page"], 3)
    out = []
    for k in range(0, run["upto"] + 1):
        if run["cmp"] == "ult":
            reached = z3.ULT(register, k)
        elif run["cmp"] == "ule":
            reached = z3.ULE(register, k)
        else:
            reached = z3.ULE(register + 1, k)
        out.append(z3.Implies(
            z3.And(guard, reached),
            z3.Select(state.mem.ram,
                      z3.Concat(page_bits, z3.BitVecVal(k, 8))) == 0))
    return out


@dataclass(frozen=True)
class Post:
    """A routine's exit predicate: registers, flags, cells, ghost enable."""
    a: tuple[int, ...] | None = None
    x: tuple[int, ...] | None = None
    y: tuple[int, ...] | None = None
    c: bool | None = None
    z: bool | None = None
    n: bool | None = None
    v: bool | None = None
    i: bool | None = True
    cells: dict = field(default_factory=dict)
    en: tuple[int, ...] = (0, 1)
    #: registers the routine leaves exactly as it found them.  Checked at the
    #: `RTS` against the entry ghost, and used at a call site instead of a
    #: fresh value, which is the only way a caller's knowledge about a
    #: register can survive a call.
    preserves: tuple = ()
    #: `(register, bit)`: on exit the ghost NMI-enable bit equals that bit of
    #: that register.  `$8EED` writes the accumulator to both PPU control and
    #: its RAM mirror, and it is called both to enable and to disable NMI; a
    #: flat `en` set for it leaks the enable bit into every caller, and this
    #: relation is what keeps it pinned.
    en_bit: tuple | None = None

    @classmethod
    def parse(cls, raw: dict) -> "Post":
        raw = raw or {}
        cells = {}
        for key, runs in (raw.get("cells") or {}).items():
            values = decode_set(runs)
            if values is not None:
                cells[int(key, 16) & (RAM_CELLS - 1)] = values
        return cls(a=decode_set(raw.get("a")), x=decode_set(raw.get("x")),
                   y=decode_set(raw.get("y")), c=raw.get("c"),
                   z=raw.get("z"), n=raw.get("n"), v=raw.get("v"),
                   i=raw.get("i", True), cells=cells,
                   en=tuple(sorted(set(raw.get("en", (0, 1))))),
                   preserves=tuple(str(r) for r in
                                   (raw.get("preserves") or ())),
                   en_bit=(None if raw.get("en_bit") is None else
                           (str(raw["en_bit"][0]),
                            int(raw["en_bit"][1]) & 7)))

    def formula(self, state: State) -> z3.BoolRef:
        out = [_flag(state.c, self.c), _flag(state.z, self.z),
               _flag(state.n, self.n), _flag(state.v, self.v),
               _flag(state.i, self.i)]
        for values, term in ((self.a, state.a), (self.x, state.x),
                             (self.y, state.y)):
            if values is not None:
                out.append(_set_member(term, values))
        for cell, values in sorted(self.cells.items()):
            out.append(_set_member(_cell(state, cell), values))
        return z3.And(*out)


@dataclass(frozen=True)
class Routine:
    entry: int
    kind: str                 # "normal" | "handler" | "root"
    mod: frozenset            # RAM cells (11-bit) the routine may write
    use: int                  # bytes of stack below s0 it may use
    post: Post
    s0: int | None            # a concrete entry stack pointer, or None
    #: the routine writes no PPU-control register, directly or through a
    #: callee, so the ghost NMI-enable bit is unchanged across a call to it.
    #: `VC-MOD` checks the routine's own writes and `VC-CALL-PPU` checks that
    #: its callees also declare it.  Without this the enable bit of a
    #: *flat* `Post[q].en` leaks: a routine called once with the bit set would
    #: then be modelled as possibly setting it at every other call site.
    no_ppu: bool = False

    @property
    def frame_bytes(self) -> int:
        return 3 if self.kind == "handler" else 2

    @classmethod
    def parse(cls, entry: int, raw: dict) -> "Routine":
        kind = raw.get("kind", "normal")
        if kind not in ("normal", "handler", "root"):
            raise ValueError(f"{entry:04X}: unknown routine kind {kind!r}")
        return cls(entry, kind, parse_cell_runs(raw.get("mod", ())),
                   int(raw.get("use", 0)), Post.parse(raw.get("post")),
                   raw.get("s0"), bool(raw.get("no_ppu", False)))


@dataclass(frozen=True)
class Verdict:
    id: str
    kind: str
    status: str
    detail: dict = field(default_factory=dict)


# --------------------------------------------------------------------------
# the checker
# --------------------------------------------------------------------------

class Checker:
    """Checks every verification condition of JOINT_INVARIANT.md section 4."""

    def __init__(self, certificate: dict, graph: CFG, prg: bytes, *,
                 timeout_ms: int = 20000, rom_axiom_cap: int = 512):
        if certificate.get("format") != FORMAT:
            raise ValueError(f"certificate format must be {FORMAT!r}")
        self.raw = certificate
        self.graph = graph
        self.prg = prg
        self.timeout_ms = timeout_ms
        self.rom_axiom_cap = rom_axiom_cap
        self.routines = {int(k, 16): Routine.parse(int(k, 16), v)
                         for k, v in certificate["routines"].items()}
        self.invariants: dict[Context, Invariant] = {}
        for key, raw in certificate["contexts"].items():
            context = parse_context(key)
            if context.routine not in self.routines:
                raise ValueError(f"{key}: routine has no contract")
            self.invariants[context] = Invariant.parse(raw)
        self.i_frame = Invariant.parse(
            certificate.get("i_frame") or {}).ram_only()
        self.windows = frozenset(int(a, 16) for a
                                 in certificate.get("nmi_windows", ()))
        roots = [r for r in self.routines.values() if r.kind == "root"]
        handlers = [r for r in self.routines.values() if r.kind == "handler"]
        self._interruptible: frozenset | None = None
        self._effective: frozenset | None = None
        self.root = roots[0] if len(roots) == 1 else None
        self.handler = handlers[0] if len(handlers) == 1 else None

    # -- helpers -----------------------------------------------------------

    def live(self) -> list[Context]:
        """Contexts whose invariant is not `false`, in a stable order."""
        return sorted((c for c, inv in self.invariants.items()
                       if not inv.false),
                      key=lambda c: (c.pc, c.routine, c.en))

    def invariant(self, context: Context) -> Invariant:
        """A context the certificate does not mention is unreachable."""
        return self.invariants.get(context, Invariant.FALSE)

    def _ghosts(self, routine: Routine, tag: str) -> Ghosts:
        ghosts = Ghosts.make(tag)
        if routine.s0 is not None:
            ghosts = replace(ghosts, s0=z3.BitVecVal(routine.s0, 8))
        return ghosts

    def _start(self, context: Context, tag: str):
        routine = self.routines[context.routine]
        state = havoc_state(context.pc, self.prg)
        ghosts = self._ghosts(routine, f"{tag}{context.pc:04X}_")
        inv = self.invariant(context)
        hypotheses = [inv.formula(state, ghosts,
                                  frame_bytes=routine.frame_bytes)]
        return state, ghosts, routine, inv, hypotheses

    def _at(self, pc: int, routine: int, state: State, ghosts: Ghosts,
            enable, frame_bytes: int):
        """`Inv[(pc, routine, en')]` as a claim, split on the enable term."""
        formulas = [
            self.invariant(Context(pc, routine, value)).formula(
                state, ghosts, frame_bytes=frame_bytes) for value in (0, 1)]
        if z3.is_true(enable):
            return formulas[1]
        if z3.is_false(enable):
            return formulas[0]
        return z3.If(enable, formulas[1], formulas[0])

    def _rom_axioms(self, state: State, instruction, inv: Invariant) -> list:
        """`PRG[a] == image[a]` for ROM bytes this instruction may read.

        These are facts about the immutable image, so asserting them is sound
        for any address.  They matter only where `cpu.step` forms a symbolic
        effective address and therefore reads through the `PRG` array.
        """
        mode = instruction.info.mode
        if mode not in ("abx", "aby"):
            return []
        index = inv.x if mode == "abx" else inv.y
        candidates = range(256) if index is None else index
        base = instruction.operand16
        addresses = sorted(a for a in {(base + i) & 0xFFFF
                                       for i in candidates} if a >= 0x8000)
        if not addresses or len(addresses) > self.rom_axiom_cap:
            return []
        return state.mem.prg_axioms(addresses)

    def _ask(self, ident: str, kind: str, hypotheses, claim,
             detail: dict | None = None, *, vacuity: bool = False) -> Verdict:
        detail = dict(detail or {})
        if vacuity:
            # A query whose hypotheses are unsatisfiable is `unsat` whatever
            # it claims.  The call and resume queries build their hypotheses
            # (a havoced state plus a contract), so a mistake there shows up
            # as a vacuous `holds` rather than as a wrong answer
            # (`formal/lean/FINDINGS.md` F4).
            probe = z3.Solver()
            probe.set("timeout", self.timeout_ms)
            probe.add(*hypotheses)
            if probe.check() == z3.unsat:
                detail["reason"] = ("the hypotheses are unsatisfiable, so "
                                    "this condition would hold vacuously")
                return Verdict(ident, kind, FAILS, detail)
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        solver.add(*hypotheses)
        solver.add(z3.Not(claim))
        answer = solver.check()
        if answer == z3.unsat:
            return Verdict(ident, kind, HOLDS, detail)
        if answer == z3.sat:
            detail["counterexample"] = _readable(solver.model())
            return Verdict(ident, kind, FAILS, detail)
        detail["solver"] = str(answer)
        return Verdict(ident, kind, UNKNOWN, detail)

    def interruptible(self) -> frozenset:
        """Routines inside which an NMI may be taken, transitively.

        An interrupt taken inside a callee changes cells of `Mod[H]`, and the
        caller's `VC-CALL-RETURN` havoc has to cover them or the caller
        resumes with an invariant that nothing re-established
        (`formal/lean/FINDINGS.md` F2).
        """
        if self._interruptible is not None:
            return self._interruptible
        direct = {c.routine for c in self.live()
                  if c.en == 1 and c.pc not in self.effective_windows()}
        callers: dict[int, set] = {}
        for context in self.live():
            node = self.graph.nodes.get(context.pc)
            if node is None:
                continue
            instruction = node.instruction
            if (instruction.info.flow is Flow.CALL
                    and instruction.operand16 != JUMPENGINE):
                callers.setdefault(context.routine,
                                   set()).add(instruction.operand16)
        out = set(direct)
        for _ in range(len(self.routines) + 1):
            grown = {r for r, cs in callers.items() if cs & out} - out
            if not grown:
                break
            out |= grown
        self._interruptible = frozenset(out)
        return self._interruptible

    def _ppu_callees(self, entry: int) -> list[int]:
        """Routines `entry` calls that do not themselves declare `no_ppu`."""
        out = set()
        for context in self.live():
            if context.routine != entry:
                continue
            node = self.graph.nodes.get(context.pc)
            if node is None:
                continue
            instruction = node.instruction
            if (instruction.info.flow is not Flow.CALL
                    or instruction.operand16 == JUMPENGINE):
                continue
            callee = self.routines.get(instruction.operand16)
            if callee is None or not callee.no_ppu:
                out.add(instruction.operand16)
        return sorted(out)

    def _relevant(self, pc: int, routine: int,
                  callee: Routine | None = None) -> frozenset | None:
        """Cells the invariants at `(pc, routine, *)` constrain.

        `None` means "every cell", which makes the caller havoc all of
        `Mod[q]`.  The entry frame is addressed through the symbolic ghost
        `s0`, so unless the invariant pins it to known addresses the whole
        stack page counts as constrained.
        """
        frame_bytes = self.routines[routine].frame_bytes
        out: set[int] = set()
        for enable in (0, 1):
            invariant = self.invariant(Context(pc, routine, enable))
            mentioned = invariant.mentioned_cells()
            if mentioned is None:
                return None                   # a parametric zero region
            frame = invariant.frame_cells(frame_bytes)
            if frame is None:
                # the frame conjunct addresses the stack page through the
                # symbolic `s0`, so all of it counts as constrained
                frame = frozenset(range(0x100, 0x200))
            out |= mentioned | frame
        out |= set(self.routines[routine].post.cells)
        if callee is not None:
            # The query also *assumes* `Post[q]`, so a cell of `Post[q]` left
            # un-havoced keeps its pre-call value and can make the hypotheses
            # unsatisfiable -- a vacuous `holds`
            # (`formal/lean/FINDINGS.md` F4).
            out |= set(callee.post.cells)
        return frozenset(out)

    @staticmethod
    def _writes(before: State, after: State):
        return after.mem.writes[len(before.mem.writes):]

    def _mod_claim(self, routine: Routine, ghosts: Ghosts,
                   writes) -> z3.BoolRef:
        """Every write targets `Mod[r]`, the routine's own stack area, or a
        device.

        Writes to `$2000-$FFFF` change no RAM cell: NROM has no registers and
        device state reaches the CPU only through unconstrained reads and
        through the ghost enable bit, which `VC-STEP` tracks (`devices.py`).
        """
        runs = _runs(routine.mod)
        terms = []
        if routine.no_ppu:
            terms.extend(z3.Not(_ppu_control(address))
                         for address, _value in writes)
        for address, _value in writes:
            index = z3.Extract(10, 0, address)
            in_mod = (z3.Or(*[index == low if low == high
                              else z3.And(z3.UGE(index, low),
                                          z3.ULE(index, high))
                              for low, high in runs]) if runs
                      else z3.BoolVal(False))
            in_stack = z3.BoolVal(False) if not routine.use else z3.And(
                z3.ULT(address, 0x2000),
                z3.Extract(10, 8, address) == 1,
                z3.ULE(ghosts.s0 - z3.Extract(7, 0, address),
                       routine.use - 1))
            terms.append(z3.Or(z3.UGE(address, 0x2000), in_mod, in_stack))
        return z3.And(*terms)

    # -- per-context obligations ------------------------------------------

    def check_context(self, context: Context) -> list[Verdict]:
        """Every verification condition owned by one live context."""
        node = self.graph.nodes.get(context.pc)
        if node is None:
            return [Verdict(f"VC-NODE:{context.key}", "VC-NODE", FAILS,
                            {"reason": "not an instruction start in N"})]
        instruction = node.instruction
        info = instruction.info
        state, ghosts, routine, inv, hypotheses = self._start(context, "s")
        hypotheses = hypotheses + self._rom_axioms(state, instruction, inv)

        if info.mnemonic in FORBIDDEN_MNEMONICS or (
                info.mnemonic == "RTI" and routine.kind != "handler"):
            return [Verdict(f"VC-FORBIDDEN:{context.key}", "VC-FORBIDDEN",
                            FAILS,
                            {"instruction": str(instruction),
                             "reason": "the certificate claims a forbidden "
                                       "instruction is reachable"})]
        out: list[Verdict] = []
        if info.mnemonic == "TXS" and routine.kind != "root":
            out.append(Verdict(f"VC-TXS:{context.key}", "VC-FORBIDDEN", FAILS,
                               {"instruction": str(instruction),
                                "reason": "TXS outside a root routine moves "
                                          "the frame base"}))
        if info.flow is Flow.CALL and instruction.operand16 == JUMPENGINE:
            return out + self.vc_dispatch(context, instruction, state, ghosts,
                                          routine, hypotheses)
        if info.flow is Flow.CALL:
            return out + self.vc_call(context, instruction, state, ghosts,
                                      routine, hypotheses)
        if info.mnemonic == "RTS":
            return out + self.vc_ret(context, state, ghosts, routine,
                                     hypotheses)
        if info.mnemonic == "RTI":
            return out + self.vc_nmi_exit(context, state, ghosts, routine,
                                          hypotheses)

        successors = cpu.step(state)
        if not successors:
            return out + [Verdict(f"VC-STEP:{context.key}", "VC-STEP", FAILS,
                                  {"instruction": str(instruction),
                                   "reason": "the model gives no successor"})]
        before = z3.BoolVal(bool(context.en))
        for number, successor in enumerate(successors):
            writes = self._writes(state, successor.state)
            enable = ppu_control_update(before, writes)
            target = successor.state.pc
            ident = f"VC-STEP:{context.key}:{number}"
            if not isinstance(target, int):
                out.append(Verdict(ident, "VC-STEP", FAILS,
                                   {"instruction": str(instruction),
                                    "reason": "successor program counter is "
                                              "not a single address"}))
                continue
            out.append(self._ask(
                ident, "VC-STEP", hypotheses + [successor.guard],
                self._at(target, context.routine, successor.state, ghosts,
                         enable, routine.frame_bytes),
                {"instruction": str(instruction),
                 "successor": f"0x{target:04X}"}))
            if writes:
                out.append(self._ask(
                    f"VC-MOD:{context.key}:{number}", "VC-MOD",
                    hypotheses + [successor.guard],
                    self._mod_claim(routine, ghosts, writes),
                    {"instruction": str(instruction), "writes": len(writes)}))
        return out

    # -- VC-CALL -----------------------------------------------------------

    def vc_call(self, context: Context, instruction, state: State,
                ghosts: Ghosts, routine: Routine,
                hypotheses) -> list[Verdict]:
        target = instruction.operand16
        return_pc = instruction.end
        key = f"{context.key}->{target:04X}"
        if target not in self.routines:
            return [Verdict(f"VC-CALL:{key}", "VC-CALL", FAILS,
                            {"reason": f"no contract for ${target:04X}"})]
        callee = self.routines[target]
        if callee.kind != "normal":
            return [Verdict(f"VC-CALL:{key}", "VC-CALL", FAILS,
                            {"reason": f"${target:04X} is a {callee.kind} "
                                       "routine and cannot be called"})]
        (entered,) = cpu.step(state)
        writes = self._writes(state, entered.state)
        enable = ppu_control_update(z3.BoolVal(bool(context.en)), writes)
        out = [self._ask(f"VC-MOD:{key}", "VC-MOD", hypotheses,
                         self._mod_claim(routine, ghosts, writes),
                         {"instruction": str(instruction)})]

        # 1. the state after the JSR satisfies the callee's entry invariant.
        #    The callee's ghosts are determined here: s0 is the stack pointer
        #    it starts with and ret is the address this JSR pushed.
        callee_ghosts = Ghosts(
            z3.BitVecVal(callee.s0, 8) if callee.s0 is not None
            else entered.state.s,
            z3.BitVecVal((return_pc - 1) & 0xFFFF, 16), fresh("callstatus"),
            {"a": state.a, "x": state.x, "y": state.y})
        out.append(self._ask(
            f"VC-CALL-ENTRY:{key}", "VC-CALL", hypotheses,
            self._at(target, target, entered.state, callee_ghosts, enable,
                     callee.frame_bytes), {"callee": f"0x{target:04X}"}))

        # 2. the callee's stack use fits inside the caller's budget
        inv = self.invariant(context)
        fits = (inv.depth is not None
                and max(inv.depth) + 2 + callee.use <= routine.use)
        out.append(Verdict(f"VC-CALL-USE:{key}", "VC-CALL",
                           HOLDS if fits else FAILS,
                           {"depth": list(inv.depth or ()),
                            "callee_use": callee.use,
                            "caller_use": routine.use}))

        # 3. the return state satisfies the invariant at the return point
        interruptible = target in self.interruptible()
        after = self._havoc_callee(
            state, callee, return_pc, extra_stack=2,
            relevant=self._relevant(return_pc, context.routine, callee),
            also=self.handler.mod if (interruptible and self.handler)
            else frozenset())
        for register in callee.post.preserves:
            after = replace(after, **{register: getattr(state, register)})
        if callee.no_ppu:
            resume = z3.BoolVal(bool(context.en))
            enable_hypothesis = []
            out.append(Verdict(
                f"VC-CALL-PPU:{key}", "VC-CALL",
                HOLDS if not self._ppu_callees(target) else FAILS,
                {"note": "a no_ppu routine leaves the ghost enable bit alone, "
                         "so its callees must declare no_ppu too",
                 "callees_without_no_ppu":
                     [f"0x{c:04X}" for c in self._ppu_callees(target)[:16]]}))
        elif callee.post.en_bit is not None:
            register, bit = callee.post.en_bit
            resume = z3.Extract(bit, bit, getattr(after, register)) == 1
            enable_hypothesis = []
        else:
            resume = z3.Bool(f"en_after_{key}")
            enable_hypothesis = [_enable_constraint(resume, callee.post.en)]
        out.append(self._ask(
            f"VC-CALL-RETURN:{key}", "VC-CALL",
            hypotheses
            + [callee.post.formula(after)] + enable_hypothesis,
            self._at(return_pc, context.routine, after, ghosts, resume,
                     routine.frame_bytes),
            {"callee": f"0x{target:04X}",
             "return_point": f"0x{return_pc:04X}",
             "interruptible": interruptible}, vacuity=True))

        # 4. Mod[q] is a subset of Mod[r]
        extra = sorted(callee.mod - routine.mod)
        out.append(Verdict(f"VC-CALL-MOD:{key}", "VC-CALL",
                           HOLDS if not extra else FAILS,
                           {"count": len(extra),
                            "cells_outside_caller_mod":
                                [f"0x{c:04X}" for c in extra[:16]]}))
        return out

    def _havoc_callee(self, state: State, callee: Routine, pc: int, *,
                      extra_stack: int, relevant: frozenset | None,
                      also: frozenset = frozenset()) -> State:
        """The pre-call state with everything the callee may change havoced.

        Registers and flags become fresh, every cell of `Mod[q]` becomes
        fresh, and the stack bytes from `$0100+S` down to
        `$0100+S-use[q]-extra_stack+1` become fresh.  Bytes above `$0100+S`
        are untouched, which is what carries the caller's own frame across the
        call.  Havocing more than the callee can really change only makes the
        obligation harder, so this stays sound when `Mod[q]` is loose.

        `relevant` is the set of cells the claim actually constrains (`None`
        for "all of them").  A cell outside it is left alone: replacing it by
        a fresh value cannot change whether the claim holds, so skipping the
        store is an identity on the query, not a weakening.  Stack-page cells
        are always havoced because the frame conjunct addresses them through
        the symbolic `s0`.
        """
        blank = havoc_state(pc, self.prg)
        ram = state.mem.ram
        footprint = callee.mod | also
        cells = sorted(footprint if relevant is None
                       else footprint & relevant)
        for cell in cells:
            ram = z3.Store(ram, z3.BitVecVal(cell, 11),
                           fresh(f"mod{cell:03X}"))
        for offset in range(0, callee.use + extra_stack):
            ram = z3.Store(ram, z3.Concat(z3.BitVecVal(1, 3),
                                          state.s - offset),
                           fresh("calleestack"))
        return replace(blank, s=state.s,
                       mem=state.mem._with(ram=ram, writes=()), pc=pc)

    # -- VC-RET ------------------------------------------------------------

    def vc_ret(self, context: Context, state: State, ghosts: Ghosts,
               routine: Routine, hypotheses) -> list[Verdict]:
        inv = self.invariant(context)
        if routine.kind != "normal":
            return [Verdict(f"VC-RET:{context.key}", "VC-RET", FAILS,
                            {"reason": f"RTS in a {routine.kind} routine"})]
        # The caller's VC-CALL assumes control resumes after its JSR.  That
        # needs depth 0 *and* an intact entry frame, so both are required
        # here; section 4 as written named only the first (see section 7).
        if inv.depth != (0,) or not inv.frame:
            return [Verdict(f"VC-RET-FRAME:{context.key}", "VC-RET", FAILS,
                            {"depth": list(inv.depth or ()),
                             "frame_asserted": inv.frame,
                             "reason": "an RTS must be at depth 0 with the "
                                       "entry frame asserted intact"})]
        out = [Verdict(f"VC-RET-FRAME:{context.key}", "VC-RET", HOLDS,
                       {"depth": [0], "frame_asserted": True})]
        (returned,) = cpu.step(state)
        claim = routine.post.formula(returned.state)
        for register in routine.post.preserves:
            claim = z3.And(claim, getattr(returned.state, register)
                           == ghosts.entry[register])
        out.append(self._ask(f"VC-RET-POST:{context.key}", "VC-RET",
                             hypotheses, claim,
                             {"routine": f"0x{routine.entry:04X}",
                              "preserves": list(routine.post.preserves)}))
        if routine.post.en_bit is not None:
            register, bit = routine.post.en_bit
            out.append(self._ask(
                f"VC-RET-EN:{context.key}", "VC-RET", hypotheses,
                (z3.Extract(bit, bit, getattr(state, register)) == 1)
                == z3.BoolVal(bool(context.en)),
                {"en_bit": list(routine.post.en_bit),
                 "context_enable": context.en}))
        else:
            out.append(Verdict(
                f"VC-RET-EN:{context.key}", "VC-RET",
                HOLDS if context.en in routine.post.en else FAILS,
                {"context_enable": context.en, "post_enable":
                    list(routine.post.en)}))
        return out

    # -- VC-DISPATCH -------------------------------------------------------

    def vc_dispatch(self, context: Context, instruction, state: State,
                    ghosts: Ghosts, routine: Routine,
                    hypotheses) -> list[Verdict]:
        site = self.graph.dispatches.get(context.pc)
        if site is None:
            return [Verdict(f"VC-DISPATCH:{context.key}", "VC-DISPATCH",
                            FAILS, {"reason": "no dispatch table recorded"})]
        count = len(site.entries)
        axioms = state.mem.prg_axioms(
            range(site.table, site.table + 2 * count))
        out = [self._ask(f"VC-DISPATCH-INDEX:{context.key}", "VC-DISPATCH",
                         hypotheses + axioms, z3.ULT(state.a & 0x7F, count),
                         {"entries": count, "table": f"0x{site.table:04X}"})]
        # The per-entry queries below are each conditional on the engine
        # landing on that entry, so on their own they would say nothing if the
        # engine could land somewhere else.  This closes that: the address the
        # engine jumps to is one of the table's entries.
        landed = _engine_target(state)
        out.append(self._ask(
            f"VC-DISPATCH-TARGET:{context.key}", "VC-DISPATCH",
            hypotheses + axioms,
            z3.Or(*[landed == entry for entry in site.entries]),
            {"entries": count,
             "note": "the JumpEngine's indirect jump lands on a table entry"}))
        for number, entry in enumerate(site.entries):
            guard, after = through_jumpengine(state, entry)
            writes = self._writes(state, after)
            enable = ppu_control_update(z3.BoolVal(bool(context.en)), writes)
            out.append(self._ask(
                f"VC-DISPATCH:{context.key}:{entry:04X}", "VC-DISPATCH",
                hypotheses + axioms + [guard],
                self._at(entry, context.routine, after, ghosts, enable,
                         routine.frame_bytes),
                {"entry": f"0x{entry:04X}", "index": number}))
            out.append(self._ask(
                f"VC-MOD:{context.key}:{entry:04X}", "VC-MOD",
                hypotheses + axioms + [guard],
                self._mod_claim(routine, ghosts, writes),
                {"note": "the JumpEngine's own writes and pops, charged to "
                         "the calling routine"}))
        return out

    # -- asynchronous transitions -----------------------------------------

    def vc_nmi(self, context: Context) -> list[Verdict]:
        """VC-NMI-ENTRY and VC-NMI-RESUME for one context with `en = 1`."""
        if context.en != 1:
            return []
        if context.pc in self.effective_windows():
            return [Verdict(f"VC-NMI-WINDOW:{context.key}", "VC-NMI-ENTRY",
                            HOLDS,
                            {"excluded_by": "MA-NMI-EDGE / MA-NMI-LATENCY"})]
        if self.handler is None:
            return [Verdict(f"VC-NMI-ENTRY:{context.key}", "VC-NMI-ENTRY",
                            FAILS,
                            {"reason": "exactly one handler routine must be "
                                       "declared"})]
        handler = self.handler
        state, ghosts, routine, inv, hypotheses = self._start(context, "n")
        out = [self._ask(f"VC-NMI-IFRAME:{context.key}", "VC-NMI-ENTRY",
                         hypotheses, self.i_frame.formula(state, ghosts),
                         {"note": "the RAM part of this context implies "
                                  "I_frame"})]
        entered = cpu.enter_interrupt(state, cpu.NMI_VECTOR)
        if entered.pc != handler.entry:
            return out + [Verdict(f"VC-NMI-VECTOR:{context.key}",
                                  "VC-NMI-ENTRY", FAILS,
                                  {"reason": f"the NMI vector is "
                                             f"${entered.pc:04X}, not the "
                                             f"handler ${handler.entry:04X}"})]
        handler_ghosts = Ghosts(
            z3.BitVecVal(handler.s0, 8) if handler.s0 is not None
            else entered.s, z3.BitVecVal(context.pc, 16),
            state.status(b=False),
            {"a": state.a, "x": state.x, "y": state.y})
        out.append(self._ask(
            f"VC-NMI-ENTRY:{context.key}", "VC-NMI-ENTRY", hypotheses,
            self.invariant(Context(handler.entry, handler.entry, 1)).formula(
                entered, handler_ghosts, frame_bytes=3),
            {"handler": f"0x{handler.entry:04X}"}))

        resumed = self._havoc_callee(
            state, handler, context.pc, extra_stack=3,
            relevant=self._relevant(context.pc, context.routine, handler))
        resume = z3.Bool(f"en_resume_{context.key}")
        out.append(self._ask(
            f"VC-NMI-RESUME:{context.key}", "VC-NMI-RESUME",
            hypotheses
            + [handler.post.formula(resumed),
               _enable_constraint(resume, handler.post.en)],
            self._at(context.pc, context.routine, resumed, ghosts, resume,
                     routine.frame_bytes),
            {"note": "the state on return from the handler"},
            vacuity=True))
        return out

    def vc_nmi_exit(self, context: Context, state: State, ghosts: Ghosts,
                    routine: Routine, hypotheses) -> list[Verdict]:
        inv = self.invariant(context)
        if routine.kind != "handler":
            return [Verdict(f"VC-NMI-EXIT:{context.key}", "VC-NMI-EXIT",
                            FAILS, {"reason": "RTI outside the handler"})]
        if inv.depth != (0,) or not inv.frame:
            return [Verdict(f"VC-NMI-EXIT:{context.key}", "VC-NMI-EXIT",
                            FAILS,
                            {"depth": list(inv.depth or ()),
                             "frame_asserted": inv.frame,
                             "reason": "an RTI must be at depth 0 with the "
                                       "interrupt frame asserted intact"})]
        out = [Verdict(f"VC-NMI-EXIT-FRAME:{context.key}", "VC-NMI-EXIT",
                       HOLDS, {"depth": [0], "frame_asserted": True}),
               Verdict(f"VC-NMI-EXIT-EN:{context.key}", "VC-NMI-EXIT",
                       HOLDS if context.en in routine.post.en else FAILS,
                       {"context_enable": context.en,
                        "post_enable": list(routine.post.en)})]
        (returned,) = cpu.step(state)
        out.append(self._ask(f"VC-NMI-EXIT-I:{context.key}", "VC-NMI-EXIT",
                             hypotheses, returned.state.i,
                             {"note": "the pulled status has I set"}))
        # Post[H] is evaluated on the state *after* the RTI, which is the
        # state `VC-NMI-RESUME` assumes it of.  Checking it before the RTI
        # proved nothing about the flags, which the RTI restores from the
        # frame (`formal/lean/FINDINGS.md` F3).
        out.append(self._ask(f"VC-NMI-EXIT-IFRAME:{context.key}",
                             "VC-NMI-EXIT", hypotheses,
                             z3.And(self.i_frame.formula(returned.state,
                                                         ghosts),
                                    routine.post.formula(returned.state)),
                             {"note": "the post-RTI state implies I_frame "
                                      "and Post[H]"}))
        return out

    # -- reset, cold boot, forbidden instructions, safety ------------------

    def vc_reset(self) -> list[Verdict]:
        """Warm reset is available at every boundary (`transitions.py`).

        For `en = 0` a single query covers every context, because its
        hypothesis leaves RAM and the registers completely unconstrained,
        which is weaker than any context's invariant.  For `en = 1` the live
        contexts are few and each gets its own query, because there their RAM
        is what makes the reset state constrainable at all.
        """
        if self.root is None:
            return [Verdict("VC-RESET", "VC-RESET", FAILS,
                            {"reason": "exactly one root routine must be "
                                       "declared"})]
        state = havoc_state(self.root.entry, self.prg)
        out = [self._ask("VC-RESET:any/0", "VC-RESET", [],
                         self._reset_claim(cpu.reset(state), 0),
                         {"note": "RAM and registers unconstrained, so this "
                                  "covers every context with en = 0"})]
        if self.raw.get("reset_clears_enable"):
            # `transitions.py` carries the ghost enable bit across a warm
            # reset unchanged, which is the conservative choice.  A
            # certificate may instead declare that the reset line clears PPU
            # control; that *removes* behaviours, so it is an assumption and
            # is reported as one rather than discharged.
            out.append(Verdict("VC-RESET:assumed-en0", "VC-RESET", HOLDS,
                               {"assumption": self.raw.get(
                                   "reset_clears_enable_assumption",
                                   "reset clears the PPU NMI-enable bit"),
                                "skipped_contexts":
                                    sum(1 for c in self.live()
                                        if c.en == 1)}))
            return out
        for context in self.live():
            if context.en != 1:
                continue
            state, ghosts, routine, inv, hypotheses = self._start(context, "r")
            out.append(self._ask(f"VC-RESET:{context.key}", "VC-RESET",
                                 hypotheses,
                                 self._reset_claim(cpu.reset(state), 1), {}))
        return out

    def _reset_claim(self, after: State, enable: int):
        ghosts = self._ghosts(self.root, "reset_")
        return self.invariant(
            Context(self.root.entry, self.root.entry, enable)).formula(
                replace(after, pc=self.root.entry), ghosts,
                frame_bytes=self.root.frame_bytes)

    def vc_cold(self) -> list[Verdict]:
        if self.root is None:
            return [Verdict("VC-COLD", "VC-COLD", FAILS,
                            {"reason": "exactly one root routine"})]
        vector = (self.prg[cpu.RESET_VECTOR - 0x8000]
                  | self.prg[cpu.RESET_VECTOR - 0x7FFF] << 8)
        if vector != self.root.entry:
            return [Verdict("VC-COLD", "VC-COLD", FAILS,
                            {"reason": f"the reset vector ${vector:04X} is "
                                       f"not the root ${self.root.entry:04X}"})]
        state = replace(havoc_state(vector, self.prg), i=z3.BoolVal(True))
        ghosts = self._ghosts(self.root, "cold_")
        claim = self.invariant(
            Context(self.root.entry, self.root.entry, 0)).formula(
                state, ghosts, frame_bytes=self.root.frame_bytes)
        return [self._ask("VC-COLD", "VC-COLD", [], claim,
                          {"note": "cold boot: all RAM, all registers and "
                                   "every flag but I unconstrained, enable 0 "
                                   "(MA-PPU-POWERON)"})]

    def vc_forbidden(self) -> list[Verdict]:
        """Every forbidden instruction in `N` must be in no live context."""
        out = []
        for pc, node in sorted(self.graph.nodes.items()):
            info = node.instruction.info
            forbidden = info.mnemonic in FORBIDDEN_MNEMONICS
            if not forbidden:
                continue
            reached = sorted(c.key for c in self.live() if c.pc == pc)
            out.append(Verdict(f"VC-FORBIDDEN:{pc:04X}", "VC-FORBIDDEN",
                               HOLDS if not reached else FAILS,
                               {"instruction": str(node.instruction),
                                "live_contexts": reached}))
        return out

    def derived_windows(self) -> tuple[frozenset, dict]:
        """The instruction starts the two timing assumptions can cover.

        MA-NMI-EDGE covers the handler's prologue: from its entry up to and
        including the first write to PPU control that clears bit 7, a second
        NMI needs a second vertical blank.  MA-NMI-LATENCY covers the single
        boundary after the handler's last write that *sets* bit 7, which must
        be the `RTI`.

        Deriving this here rather than reading it from the certificate is the
        point: `vc_nmi` asks the solver nothing inside a window, so a
        certificate that declared a larger window would be hiding the handler
        from every obligation.  `formal/lean/FINDINGS.md` F1 builds a
        certificate for which every other verification condition holds and
        safety fails, by doing exactly that.
        """
        if self.handler is None:
            return frozenset(), {"reason": "no handler routine"}
        prologue, pc = [], self.handler.entry
        for _ in range(64):
            node = self.graph.nodes.get(pc)
            if node is None:
                break
            prologue.append(pc)
            instruction = node.instruction
            if (instruction.info.mnemonic == "STA"
                    and instruction.info.mode == "abs"
                    and 0x2000 <= instruction.operand16 < 0x4000
                    and instruction.operand16 & 7 == 0):
                break
            if instruction.info.flow is not Flow.NORMAL:
                break
            pc = instruction.end
        epilogue = []
        for pc, node in sorted(self.graph.nodes.items()):
            if node.instruction.info.mnemonic != "RTI":
                continue
            previous = [q for q, _ in node.predecessors]
            if len(previous) != 1:
                continue
            before = self.graph.nodes[previous[0]].instruction
            if (before.info.mnemonic == "STA" and before.info.mode == "abs"
                    and 0x2000 <= before.operand16 < 0x4000
                    and before.operand16 & 7 == 0):
                epilogue.append(pc)
        return frozenset(prologue) | frozenset(epilogue), {
            "prologue": [f"0x{a:04X}" for a in prologue],
            "epilogue": [f"0x{a:04X}" for a in epilogue]}

    def effective_windows(self) -> frozenset:
        """Declared windows that the derivation actually supports.

        `vc_windows` reports a declared window the image does not justify, and
        this makes the report binding: an unjustified declaration cannot
        suppress an obligation even for a reader who ignores that verdict.
        """
        if self._effective is None:
            derived, _ = self.derived_windows()
            self._effective = self.windows & derived
        return self._effective

    def vc_windows(self) -> list[Verdict]:
        derived, detail = self.derived_windows()
        extra = sorted(self.windows - derived)
        return [Verdict("VC-NMI-WINDOWS", "VC-NMI-ENTRY",
                        HOLDS if not extra else FAILS,
                        {**detail,
                         "declared": [f"0x{a:04X}"
                                      for a in sorted(self.windows)],
                         "declared_but_not_derivable":
                             [f"0x{a:04X}" for a in extra],
                         "assumptions": ["MA-NMI-EDGE", "MA-NMI-LATENCY"]})]

    def vc_capacity(self) -> list[Verdict]:
        """The stack page is big enough for the deepest chain (F5).

        `VC-CALL-USE` makes `use` nest down a call chain but checks no base
        case, so nothing stopped the stack pointer from wrapping -- which is
        exactly the failure section 1 of the design describes.  The handler
        must also not be interruptible, or the bound is not finite.
        """
        if self.root is None or self.handler is None:
            return [Verdict("VC-CAPACITY", "VC-CAPACITY", FAILS,
                            {"reason": "a root and a handler are needed"})]
        inner = sorted(c.key for c in self.live()
                       if c.routine == self.handler.entry and c.en == 1
                       and c.pc not in self.effective_windows())
        total = self.root.use + 3 + self.handler.use
        return [Verdict("VC-CAPACITY", "VC-CAPACITY",
                        HOLDS if total <= 0x100 and not inner else FAILS,
                        {"use_root": self.root.use,
                         "use_handler": self.handler.use,
                         "interrupt_frame": 3, "total": total, "limit": 0x100,
                         "handler_contexts_with_the_enable_bit_set":
                             inner[:20],
                         "count": len(inner)})]

    def vc_irq(self) -> list[Verdict]:
        """`transitions.py` offers an IRQ entry exactly when `I` is clear.

        There is no VC-IRQ in section 4; the IRQ transition is excluded only
        because every live context asserts `I`, so that is checked here (see
        section 7).  Preservation of `I` is part of every VC-STEP, and the
        base cases are VC-COLD and VC-RESET.
        """
        open_contexts = sorted(c.key for c in self.live()
                               if self.invariant(c).i is not True)
        return [Verdict("VC-IRQ", "VC-IRQ",
                        HOLDS if not open_contexts else FAILS,
                        {"contexts_not_asserting_I":
                            open_contexts[:40],
                         "count": len(open_contexts)})]

    def vc_safety(self) -> list[Verdict]:
        outside = sorted({c.pc for c in self.live()
                          if not 0x8000 <= c.pc <= 0xFFFF})
        return [Verdict("VC-SAFETY", "VC-SAFETY",
                        HOLDS if not outside else FAILS,
                        {"live_contexts": len(self.live()),
                         "outside_rom": [f"0x{a:04X}" for a in outside]})]

    def vc_coverage(self) -> list[Verdict]:
        """Structural preconditions the section 5 meta-argument needs.

        * every instruction start of `N` lies in PRG ROM;
        * the only `JMP (abs)` is the JumpEngine's, and nothing enters the
          engine except by `JSR` from a dispatch site, so `VC-DISPATCH`
          executing the engine inline accounts for all of its fetches;
        * every live context has an invariant whose routine has a contract
          (enforced when the certificate is loaded).
        """
        nodes = self.graph.nodes
        indirect = sorted(pc for pc, n in nodes.items()
                          if n.instruction.info.flow is Flow.INDIRECT_JUMP)
        body, pc = [], JUMPENGINE
        while pc in nodes:
            body.append(pc)
            if nodes[pc].instruction.info.flow is Flow.INDIRECT_JUMP:
                break
            pc = nodes[pc].instruction.end
        side = sorted({p for b in body for p, _ in nodes[b].predecessors
                       if p not in body})
        callers = sorted(pc for pc, n in nodes.items()
                         if n.instruction.info.flow is Flow.CALL
                         and n.instruction.operand16 == JUMPENGINE)
        in_rom = all(0x8000 <= pc <= 0xFFFF for pc in nodes)
        if not body and not indirect and not callers:
            engine_ok = True                  # no dynamic dispatch at all
        else:
            engine_ok = bool(body) and indirect == [body[-1]] and not side
        covered = sorted(c.key for c in self.live() if c.pc in body)
        ok = in_rom and engine_ok and not covered
        return [Verdict("VC-COVERAGE", "VC-COVERAGE",
                        HOLDS if ok else FAILS,
                        {"instruction_starts": len(nodes),
                         "all_in_rom": in_rom,
                         "indirect_jumps": [f"0x{a:04X}" for a in indirect],
                         "engine_body": [f"0x{a:04X}" for a in body],
                         "non_body_predecessors_of_the_engine":
                             [f"0x{a:04X}" for a in side],
                         "dispatch_sites": len(callers),
                         "contexts_inside_the_engine": covered})]

    # -- driver ------------------------------------------------------------

    def check_contexts(self, contexts: Iterable[Context]) -> list[Verdict]:
        out: list[Verdict] = []
        for context in contexts:
            out.extend(self.check_context(context))
            out.extend(self.vc_nmi(context))
        return out

    def check_globals(self) -> list[Verdict]:
        return (self.vc_cold() + self.vc_reset() + self.vc_forbidden()
                + self.vc_irq() + self.vc_windows() + self.vc_capacity()
                + self.vc_safety() + self.vc_coverage())

    def check_all(self, contexts: Iterable[Context] | None = None, *,
                  globals_too: bool = True) -> list[Verdict]:
        out = self.check_contexts(self.live() if contexts is None
                                  else contexts)
        return out + self.check_globals() if globals_too else out


def _engine_target(state: State, limit: int = 24):
    """The address the JumpEngine's indirect jump computes, as a term.

    `symexec.through_jumpengine` replaces the program counter with the target
    it is asked about, which is what the per-entry queries need; this returns
    the term itself so that "the target is one of the entries" can be asked.
    """
    for _ in range(limit):
        if not isinstance(state.pc, int):
            return state.pc
        (successor,) = cpu.step(state)
        state = successor.state
    raise RuntimeError("the JumpEngine did not reach its indirect jump")


def _runs(cells: Iterable[int]) -> list[tuple[int, int]]:
    out: list[list[int]] = []
    for cell in sorted(cells):
        if out and cell == out[-1][1] + 1:
            out[-1][1] = cell
        else:
            out.append([cell, cell])
    return [(low, high) for low, high in out]


def _readable(model) -> dict:
    out = {}
    for declaration in model.decls():
        value = model[declaration]
        if z3.is_bv_value(value) or z3.is_true(value) or z3.is_false(value):
            out[str(declaration)] = str(value)
    return dict(sorted(out.items())[:24])


def load(path: str) -> dict:
    with open(path) as handle:
        return json.load(handle)


def summarise(verdicts: Sequence[Verdict]) -> dict:
    """Counts per verification-condition kind, with the failing ids kept."""
    kinds: dict[str, dict] = {}
    for verdict in verdicts:
        entry = kinds.setdefault(verdict.kind, {HOLDS: 0, FAILS: 0,
                                                UNKNOWN: 0, "failing": []})
        entry[verdict.status] += 1
        if verdict.status != HOLDS and len(entry["failing"]) < 40:
            entry["failing"].append(verdict.id)
    return kinds
