"""Transfer functions and a path explorer over the value-set domain.

`step()` is the instruction semantics; `explore()` walks the CFG forward from
an entry, forking at branches, refining register sets from comparisons, and
dropping edges that the flags prove infeasible.  Anything it cannot model
widens the affected register to the full set, so a derived bound is never
tighter than the instruction semantics support.

Loop handling: a state is only re-entered at an instruction if its key has not
been seen there before, and total state count is capped.  `Exploration.capped`
reports when a cap was hit, because a truncated exploration must not be read as
"nothing else can happen" -- the same reason a solver timeout is not a proof.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Callable

from . import valueset as vs
from .decoder import Flow, Instruction, decode
from .valueset import FULL, Compare, Memory, State

#: instructions whose only effect is on memory or flags we do not track
_IGNORED = {"NOP", "STA", "STX", "STY", "BIT"}


def _addsub(state: State, operand: int, *, subtract: bool) -> State:
    """ADC / SBC over value sets, honouring an unknown carry."""
    if state.a == FULL or operand == FULL:
        # an unconstrained operand makes every result and both flags possible
        return replace(state.load("A", FULL), carry=None, overflow=None)
    carries = (0, 1) if state.carry is None else (1 if state.carry else 0,)
    out, carry_out, overflow_out = 0, set(), set()
    for a in vs.values(state.a):
        for m in vs.values(operand):
            for carry_in in carries:
                if subtract:
                    total = a - m - (1 - carry_in)
                    result = total & 0xFF
                    carry_out.add(total >= 0)
                    signed = (a ^ m) & (a ^ result) & 0x80
                else:
                    total = a + m + carry_in
                    result = total & 0xFF
                    carry_out.add(total > 0xFF)
                    signed = (~(a ^ m)) & (a ^ result) & 0x80
                overflow_out.add(bool(signed))
                out |= 1 << result
    state = state.with_register("A", out).set_nz(out)
    return replace(
        state,
        carry=next(iter(carry_out)) if len(carry_out) == 1 else None,
        overflow=next(iter(overflow_out)) if len(overflow_out) == 1 else None,
        compare=None,
    )


def _shift(state: State, mask: int, *, right: bool, rotate: bool) -> tuple[int, bool | None]:
    carries = (0, 1) if state.carry is None else (1 if state.carry else 0,)
    out, carry_out = 0, set()
    for value in vs.values(mask):
        for carry_in in carries:
            if right:
                result = value >> 1
                if rotate:
                    result |= carry_in << 7
                carry_out.add(bool(value & 0x01))
            else:
                result = (value << 1) & 0xFF
                if rotate:
                    result |= carry_in
                carry_out.add(bool(value & 0x80))
            out |= 1 << result
    return out, (next(iter(carry_out)) if len(carry_out) == 1 else None)


def _effective_addresses(state: State, instruction: Instruction,
                         memory: Memory) -> list[int] | None:
    """Concrete addresses a load could use, or None if not determined."""
    mode = instruction.info.mode
    if mode in ("zp", "abs"):
        operand = (instruction.operands[0] if mode == "zp"
                   else instruction.operand16)
        return [operand]
    if mode in ("zpx", "zpy"):
        index = state.x if mode == "zpx" else state.y
        if vs.count(index) > 64:
            return None
        base = instruction.operands[0]
        return [(base + i) & 0xFF for i in vs.values(index)]
    if mode in ("abx", "aby"):
        index = state.x if mode == "abx" else state.y
        if vs.count(index) > 64:
            return None
        base = instruction.operand16
        return [(base + i) & 0xFFFF for i in vs.values(index)]
    return None


def _operand_set(state: State, instruction: Instruction,
                 memory: Memory) -> int:
    """The value set an instruction's operand can take."""
    mode = instruction.info.mode
    if mode == "imm":
        return vs.singleton(instruction.operands[0])
    if mode == "acc":
        return state.a
    addresses = _effective_addresses(state, instruction, memory)
    if addresses is None:
        return FULL
    return memory.read_set(addresses)


def step(state: State, instruction: Instruction, memory: Memory) -> State:
    """Apply one instruction to the abstract state."""
    info = instruction.info
    name, mode = info.mnemonic, info.mode

    if not info.documented:
        # Undocumented opcodes are decoded (so lengths stay right) but their
        # effects are not modelled: widen everything they could touch.
        return State(a=FULL, x=FULL, y=FULL, s=state.s)

    if name in ("LDA", "LDX", "LDY"):
        register = {"LDA": "A", "LDX": "X", "LDY": "Y"}[name]
        return state.load(register, _operand_set(state, instruction, memory))

    if name in ("TAX", "TAY", "TXA", "TYA", "TSX", "TXS"):
        source, destination = {
            "TAX": ("A", "X"), "TAY": ("A", "Y"), "TXA": ("X", "A"),
            "TYA": ("Y", "A"), "TSX": ("S", "X"), "TXS": ("X", "S"),
        }[name]
        mask = state.register(source)
        if name == "TXS":
            return state.with_register(destination, mask).clear_compare()
        return state.load(destination, mask)

    if name in ("INX", "INY", "DEX", "DEY"):
        register = "X" if name in ("INX", "DEX") else "Y"
        delta = 1 if name in ("INX", "INY") else -1
        mask = vs.map_unary(state.register(register), lambda v: v + delta)
        return state.load(register, mask)

    if name in ("AND", "ORA", "EOR"):
        operation = {"AND": lambda a, m: a & m,
                     "ORA": lambda a, m: a | m,
                     "EOR": lambda a, m: a ^ m}[name]
        mask = vs.map_binary(state.a, _operand_set(state, instruction, memory),
                             operation, full_absorbs=True)
        return state.load("A", mask)

    if name == "ADC":
        return _addsub(state, _operand_set(state, instruction, memory),
                       subtract=False)
    if name == "SBC":
        return _addsub(state, _operand_set(state, instruction, memory),
                       subtract=True)

    if name in ("ASL", "LSR", "ROL", "ROR"):
        right = name in ("LSR", "ROR")
        rotate = name in ("ROL", "ROR")
        if mode == "acc":
            mask, carry = _shift(state, state.a, right=right, rotate=rotate)
            return replace(state.load("A", mask), carry=carry)
        # memory shift: the register file is untouched, flags follow memory
        mask, carry = _shift(state, _operand_set(state, instruction, memory),
                             right=right, rotate=rotate)
        return replace(state.set_nz(mask), carry=carry, compare=None)

    if name in ("INC", "DEC"):
        delta = 1 if name == "INC" else -1
        mask = vs.map_unary(_operand_set(state, instruction, memory),
                            lambda v: v + delta)
        return state.set_nz(mask).clear_compare()

    if name in ("CMP", "CPX", "CPY"):
        register = {"CMP": "A", "CPX": "X", "CPY": "Y"}[name]
        operand = _operand_set(state, instruction, memory)
        left = state.register(register)
        if left == FULL or operand == FULL:
            return replace(state, carry=None, zero=None, negative=None,
                           compare=Compare(register, operand))
        carry = vs.flag_from_set(
            vs.map_binary(left, operand, lambda a, m: 1 if a >= m else 0),
            lambda v: v == 1)
        zero = vs.flag_from_set(
            vs.map_binary(left, operand, lambda a, m: 1 if a == m else 0),
            lambda v: v == 1)
        negative = vs.flag_from_set(
            vs.map_binary(left, operand, lambda a, m: (a - m) & 0xFF),
            lambda v: v & 0x80 != 0)
        return replace(state, carry=carry, zero=zero, negative=negative,
                       compare=Compare(register, operand))

    if name in ("CLC", "SEC"):
        return replace(state, carry=(name == "SEC"), compare=None)
    if name in ("CLV",):
        return replace(state, overflow=False, compare=None)
    if name in ("CLD", "SED", "CLI", "SEI"):
        return state

    if name == "PLA":
        return state.load("A", FULL)
    if name == "PLP":
        return replace(state, carry=None, zero=None, negative=None,
                       overflow=None, compare=None)
    if name in ("PHA", "PHP"):
        return state

    if name in _IGNORED:
        return state

    # JSR / RTS / JMP / branches are handled by the explorer; anything else
    # unmodelled conservatively forgets the register file.
    if name in ("JSR", "RTS", "RTI", "JMP", "BRK"):
        return state
    if info.flow is Flow.BRANCH:
        return state
    return State(a=FULL, x=FULL, y=FULL, s=state.s)


# --------------------------------------------------------------------------
# branch feasibility and refinement
# --------------------------------------------------------------------------

#: branch mnemonic -> (flag attribute, value the flag must have to be taken)
BRANCH_FLAG = {
    "BCC": ("carry", False), "BCS": ("carry", True),
    "BNE": ("zero", False), "BEQ": ("zero", True),
    "BPL": ("negative", False), "BMI": ("negative", True),
    "BVC": ("overflow", False), "BVS": ("overflow", True),
}


def branch_outcomes(state: State, instruction: Instruction) -> list[tuple[bool, State]]:
    """Feasible (taken, refined state) pairs for a conditional branch.

    The flag decides feasibility; a pending comparison additionally refines the
    compared register, which is what makes `CMP #k / BCC` informative.
    """
    attribute, taken_value = BRANCH_FLAG[instruction.info.mnemonic]
    flag = getattr(state, attribute)
    outcomes: list[tuple[bool, State]] = []
    # `candidates` holds taken-ness, not flag values: a known flag selects one
    # side, an unknown flag leaves both feasible.
    if flag is None:
        candidates = [True, False]
    else:
        candidates = [flag == taken_value]
    for taken in candidates:
        refined = _refine(state, instruction.info.mnemonic, taken)
        if refined is not None and refined.is_feasible:
            outcomes.append((taken, refined))
    return outcomes


def _refine(state: State, mnemonic: str, taken: bool) -> State | None:
    """Narrow the compared register on one side of a branch."""
    attribute, taken_value = BRANCH_FLAG[mnemonic]
    flag_value = taken_value if taken else not taken_value
    state = replace(state, **{attribute: flag_value})
    pending = state.compare
    if pending is None or pending.bit_test:
        return state
    if pending.nz_only and attribute in ("carry", "overflow"):
        # the carry and overflow flags were not set by this context
        return state
    if not vs.is_singleton(pending.operand):
        return state
    constant = vs.only(pending.operand)
    current = state.register(pending.register)
    predicate = {
        ("carry", False): lambda v: v < constant,
        ("carry", True): lambda v: v >= constant,
        ("zero", True): lambda v: v == constant,
        ("zero", False): lambda v: v != constant,
        ("negative", True): lambda v: (v - constant) & 0x80 != 0,
        ("negative", False): lambda v: (v - constant) & 0x80 == 0,
    }.get((attribute, flag_value))
    if predicate is None:
        return state
    narrowed = vs.restrict(current, predicate)
    if narrowed == vs.EMPTY:
        return None                       # this side of the branch is dead
    return state.with_register(pending.register, narrowed)


# --------------------------------------------------------------------------
# path exploration
# --------------------------------------------------------------------------


@dataclass
class Exploration:
    """States observed at each instruction, plus why exploration stopped."""

    states: dict[int, list[State]] = field(default_factory=dict)
    capped: bool = False
    visited_states: int = 0
    unmodelled_calls: set[int] = field(default_factory=set)
    infeasible_edges: list[tuple[int, str]] = field(default_factory=list)

    def at(self, address: int) -> list[State]:
        return self.states.get(address, [])

    def register_at(self, address: int, register: str = "A") -> int:
        mask = 0
        for state in self.at(address):
            mask |= state.register(register)
        return mask


def explore(read_byte: Callable[[int], int], entry: int, state: State,
            memory: Memory, *, stop_at: frozenset[int] = frozenset(),
            max_states: int = 20000, max_depth: int = 400,
            follow_calls: bool = True, call_depth: int = 3,
            confine: frozenset[int] | None = None) -> Exploration:
    """Interpret forward from `entry`, forking at feasible branches.

    `stop_at` addresses record their state and do not continue, which is how a
    dispatch site's incoming accumulator set is collected.

    `confine` restricts exploration at call depth zero to a set of addresses --
    normally a backward slice of the instruction of interest.  Dropping a path
    that leaves the slice is sound for the question "what can arrive at the
    slice's end", because such a path cannot reach it without re-entering the
    slice, and re-entry points are themselves slice entries.  Subroutine
    bodies are still interpreted, since a callee changes the register file.
    """
    result = Exploration()
    seen: dict[tuple[int, int], set[tuple]] = {}
    work: list[tuple[int, State, int, int, tuple[int, ...]]] = [
        (entry, state, 0, call_depth, ())
    ]
    while work:
        address, current, depth, calls_left, stack = work.pop()
        if result.visited_states >= max_states or depth >= max_depth:
            result.capped = True
            continue
        result.visited_states += 1
        if confine is not None and not stack and address not in confine \
                and address != entry:
            continue
        bucket = seen.setdefault((address, len(stack)), set())
        key = current.key()
        if key in bucket:
            continue
        bucket.add(key)
        result.states.setdefault(address, []).append(current)
        if address in stop_at:
            continue

        instruction = decode(read_byte, address)
        info = instruction.info
        if info.flow is Flow.HALT:
            continue

        if info.flow is Flow.BRANCH:
            after = step(current, instruction, memory)
            outcomes = branch_outcomes(after, instruction)
            if len(outcomes) < 2:
                untaken = {True, False} - {taken for taken, _ in outcomes}
                for missing in untaken:
                    result.infeasible_edges.append(
                        (address, "branch" if missing else "fallthrough"))
            for taken, refined in outcomes:
                target = (instruction.branch_target if taken
                          else instruction.end)
                work.append((target, refined.clear_compare(), depth + 1,
                             calls_left, stack))
            continue

        if info.flow is Flow.JUMP:
            work.append((instruction.operand16, step(current, instruction, memory),
                         depth + 1, calls_left, stack))
            continue

        if info.flow is Flow.CALL:
            target = instruction.operand16
            if target in stop_at:
                # The callee is the instruction under study (a dispatch is
                # often reached through a one-instruction trampoline such as
                # `JSR $92C8`).  Record the state there instead of stepping
                # over the call, which would lose the very value we want.
                work.append((target, current, depth + 1, calls_left, stack))
                continue
            if follow_calls and calls_left > 0:
                work.append((target, current, depth + 1, calls_left - 1,
                             stack + (instruction.end,)))
            else:
                # not followed: the callee may change anything
                result.unmodelled_calls.add(target)
                work.append((instruction.end,
                             State(s=current.s), depth + 1, calls_left, stack))
            continue

        if info.flow is Flow.RETURN:
            if stack:
                work.append((stack[-1], current, depth + 1, calls_left,
                             stack[:-1]))
            continue

        if info.flow in (Flow.INDIRECT_JUMP, Flow.BREAK):
            continue

        work.append(((instruction.end), step(current, instruction, memory),
                     depth + 1, calls_left, stack))
    return result
