"""Instruction-level semantics of the Ricoh 2A03 as Z3 terms.

One definition serves both purposes: run with concrete inputs it is an
interpreter that can be compared against independent test vectors
(`formal/tests/test_cpu_vectors.py`); run with symbolic inputs it produces the
terms the proof obligations are stated over.  There is deliberately no second
"fast" implementation, because a proof about one definition validated through
another would prove nothing about the thing that was validated.

Granularity is one architectural instruction per step.  A step starts at an
opcode fetch, which is the event the instruction-location property speaks
about, and ends immediately before the next one.  Cycle-level behaviour (dummy
reads, DMA, the exact cycle an interrupt is sampled) is not represented here;
`devices.py` and `transitions.py` say why that is sound for the properties in
scope and what it rules out.

Decimal mode: the 2A03 has the D flag but its adder ignores it.  `SED`, `CLD`,
`PLP` and `RTI` change the flag; `ADC`/`SBC` never consult it.

Unstable undocumented instructions (`XAA`, `LXA`, `SHA`, `SHX`, `SHY`, `TAS`)
depend on analogue effects.  They are modelled as havoc: the affected register
or memory write is unconstrained.  That is conservative, and it means any
proof that reaches one of them has to survive an arbitrary result.
"""
from __future__ import annotations

from dataclasses import dataclass, replace

import z3

from analysis.decoder import OPCODES, Flow

from .memory import as_int, bv8, bv16, fresh

TRUE, FALSE = z3.BoolVal(True), z3.BoolVal(False)
HAVOC = frozenset({"XAA", "LXA", "SHA", "SHX", "SHY", "TAS"})

NMI_VECTOR, RESET_VECTOR, IRQ_VECTOR = 0xFFFA, 0xFFFC, 0xFFFE


class SymbolicFetch(Exception):
    """The opcode or program counter is not a single concrete value."""


@dataclass(frozen=True)
class State:
    a: z3.BitVecRef
    x: z3.BitVecRef
    y: z3.BitVecRef
    s: z3.BitVecRef
    c: z3.BoolRef
    z: z3.BoolRef
    i: z3.BoolRef
    d: z3.BoolRef
    v: z3.BoolRef
    n: z3.BoolRef
    #: an int when concrete, otherwise a 16-bit term
    pc: object
    mem: object
    #: True once a JAM has stopped the processor
    halted: bool = False

    @classmethod
    def symbolic(cls, pc, mem, prefix: str = "") -> "State":
        reg = lambda name: z3.BitVec(prefix + name, 8)
        flag = lambda name: z3.Bool(prefix + name)
        return cls(reg("A"), reg("X"), reg("Y"), reg("S"), flag("C"),
                   flag("Z"), flag("I"), flag("D"), flag("V"), flag("N"),
                   pc, mem)

    @classmethod
    def concrete(cls, *, pc, a, x, y, s, p, mem) -> "State":
        bit = lambda k: z3.BoolVal(bool(p >> k & 1))
        return cls(bv8(a), bv8(x), bv8(y), bv8(s), bit(0), bit(1), bit(2),
                   bit(3), bit(6), bit(7), pc, mem)

    def status(self, *, b: bool) -> z3.BitVecRef:
        """The status byte as pushed.  Bit 5 always reads 1."""
        one = lambda flag: z3.If(flag, z3.BitVecVal(1, 1), z3.BitVecVal(0, 1))
        return z3.simplify(z3.Concat(
            one(self.n), one(self.v), z3.BitVecVal(1, 1),
            z3.BitVecVal(int(b), 1), one(self.d), one(self.i), one(self.z),
            one(self.c)))

    def with_status(self, byte) -> "State":
        """Load flags from a pulled byte; B and bit 5 are not registers."""
        bit = lambda k: z3.simplify(z3.Extract(k, k, byte) == 1)
        return replace(self, c=bit(0), z=bit(1), i=bit(2), d=bit(3), v=bit(6),
                       n=bit(7))


@dataclass(frozen=True)
class Successor:
    guard: z3.BoolRef
    state: State
    #: fallthrough, branch, jump, call, return, interrupt_return,
    #: indirect_jump, break, halt
    kind: str


# -- small helpers ----------------------------------------------------------

def _s(term):
    return z3.simplify(term)


def _nz(state: State, value) -> State:
    value = _s(value)
    return replace(state, z=_s(value == 0), n=_s(z3.Extract(7, 7, value) == 1))


def _word(low, high):
    return _s(z3.Concat(bv8(high), bv8(low)))


def _bit(value, k):
    return _s(z3.Extract(k, k, value) == 1)


def _carry(flag):
    return z3.If(flag, z3.BitVecVal(1, 8), z3.BitVecVal(0, 8))


def push(state: State, value) -> State:
    return replace(state, mem=state.mem.write_stack(state.s, bv8(value)),
                   s=_s(state.s - 1))


def pull(state: State):
    s = _s(state.s + 1)
    value, mem = state.mem.read_stack(s)
    return _s(value), replace(state, s=s, mem=mem)


def _read(state: State, address):
    value, mem = state.mem.read(address)
    return _s(value), replace(state, mem=mem)


def _read_word(state: State, low_address, high_address):
    low, state = _read(state, low_address)
    high, state = _read(state, high_address)
    return _word(low, high), state


def _zext(value):
    return z3.ZeroExt(8, value)


def _effective_address(state: State, mode: str, lo: int, hi: int):
    """The address an instruction operates on, with NMOS wrap rules."""
    if mode == "zp":
        return bv16(lo), state
    if mode == "zpx":
        return _s(_zext(bv8(lo) + state.x)), state
    if mode == "zpy":
        return _s(_zext(bv8(lo) + state.y)), state
    if mode == "abs":
        return bv16(lo | hi << 8), state
    if mode == "abx":
        return _s(bv16(lo | hi << 8) + _zext(state.x)), state
    if mode == "aby":
        return _s(bv16(lo | hi << 8) + _zext(state.y)), state
    if mode == "izx":
        pointer = _s(bv8(lo) + state.x)          # wraps within page zero
        return _read_word(state, _zext(pointer), _zext(_s(pointer + 1)))
    if mode == "izy":
        base, state = _read_word(state, bv16(lo), bv16((lo + 1) & 0xFF))
        return _s(base + _zext(state.y)), state
    raise AssertionError(f"no effective address for mode {mode}")


# -- arithmetic -------------------------------------------------------------

def _adc(state: State, operand) -> State:
    a = state.a
    total = _s(z3.ZeroExt(1, a) + z3.ZeroExt(1, operand)
               + z3.ZeroExt(1, _carry(state.c)))
    result = _s(z3.Extract(7, 0, total))
    overflow = _bit(~(a ^ operand) & (a ^ result), 7)
    state = replace(state, a=result, c=_bit(total, 8), v=overflow)
    return _nz(state, result)


def _compare(state: State, register, operand) -> State:
    state = replace(state, c=_s(z3.UGE(register, operand)))
    return _nz(state, register - operand)


def _asl(state, value):
    return _s(value << 1), _bit(value, 7)


def _lsr(state, value):
    return _s(z3.LShR(value, 1)), _bit(value, 0)


def _rol(state, value):
    return _s((value << 1) | _carry(state.c)), _bit(value, 7)


def _ror(state, value):
    return _s(z3.LShR(value, 1) | (_carry(state.c) << 7)), _bit(value, 0)


_SHIFTS = {"ASL": _asl, "LSR": _lsr, "ROL": _rol, "ROR": _ror,
           "SLO": _asl, "SRE": _lsr, "RLA": _rol, "RRA": _ror}

_BRANCH = {"BPL": ("n", False), "BMI": ("n", True), "BVC": ("v", False),
           "BVS": ("v", True), "BCC": ("c", False), "BCS": ("c", True),
           "BNE": ("z", False), "BEQ": ("z", True)}

_READERS = frozenset({
    "ORA", "AND", "EOR", "ADC", "SBC", "USBC", "CMP", "CPX", "CPY", "BIT",
    "LDA", "LDX", "LDY", "LAX", "ANC", "ALR", "ARR", "SBX", "XAA", "LXA",
    "LAS", "NOP"})
_MODIFIERS = frozenset({"ASL", "LSR", "ROL", "ROR", "INC", "DEC", "SLO", "RLA",
                        "SRE", "RRA", "DCP", "ISC"})
_STORES = frozenset({"STA", "STX", "STY", "SAX"})


def _apply_read(state: State, mnemonic: str, m) -> State:
    a = state.a
    if mnemonic == "ORA":
        return _nz(replace(state, a=_s(a | m)), a | m)
    if mnemonic == "AND":
        return _nz(replace(state, a=_s(a & m)), a & m)
    if mnemonic == "EOR":
        return _nz(replace(state, a=_s(a ^ m)), a ^ m)
    if mnemonic == "ADC":
        return _adc(state, m)
    if mnemonic in ("SBC", "USBC"):
        return _adc(state, _s(~m))
    if mnemonic == "CMP":
        return _compare(state, a, m)
    if mnemonic == "CPX":
        return _compare(state, state.x, m)
    if mnemonic == "CPY":
        return _compare(state, state.y, m)
    if mnemonic == "BIT":
        return replace(state, z=_s((a & m) == 0), n=_bit(m, 7), v=_bit(m, 6))
    if mnemonic == "LDA":
        return _nz(replace(state, a=m), m)
    if mnemonic == "LDX":
        return _nz(replace(state, x=m), m)
    if mnemonic == "LDY":
        return _nz(replace(state, y=m), m)
    if mnemonic == "LAX":
        return _nz(replace(state, a=m, x=m), m)
    if mnemonic == "ANC":
        state = _nz(replace(state, a=_s(a & m)), a & m)
        return replace(state, c=state.n)
    if mnemonic == "ALR":
        masked = _s(a & m)
        result = _s(z3.LShR(masked, 1))
        return _nz(replace(state, a=result, c=_bit(masked, 0)), result)
    if mnemonic == "ARR":
        result = _s(z3.LShR(a & m, 1) | (_carry(state.c) << 7))
        state = replace(state, a=result, c=_bit(result, 6),
                        v=_s(z3.Xor(_bit(result, 6), _bit(result, 5))))
        return _nz(state, result)
    if mnemonic == "SBX":
        masked = _s(a & state.x)
        result = _s(masked - m)
        return _nz(replace(state, x=result, c=_s(z3.UGE(masked, m))), result)
    if mnemonic == "LAS":
        result = _s(m & state.s)
        return _nz(replace(state, a=result, x=result, s=result), result)
    if mnemonic == "XAA":
        result = fresh("xaa")
        return _nz(replace(state, a=result), result)
    if mnemonic == "LXA":
        result = fresh("lxa")
        return _nz(replace(state, a=result, x=result), result)
    if mnemonic == "NOP":
        return state
    raise AssertionError(mnemonic)


def _apply_modify(state: State, mnemonic: str, m):
    """Returns (state, value written back)."""
    if mnemonic in ("INC", "ISC"):
        result = _s(m + 1)
        if mnemonic == "INC":
            return _nz(state, result), result
        return _adc(state, _s(~result)), result
    if mnemonic in ("DEC", "DCP"):
        result = _s(m - 1)
        if mnemonic == "DEC":
            return _nz(state, result), result
        return _compare(state, state.a, result), result
    result, carry = _SHIFTS[mnemonic](state, m)
    state = replace(state, c=carry)
    if mnemonic in ("ASL", "LSR", "ROL", "ROR"):
        return _nz(state, result), result
    if mnemonic == "SLO":
        value = _s(state.a | result)
        return _nz(replace(state, a=value), value), result
    if mnemonic == "RLA":
        value = _s(state.a & result)
        return _nz(replace(state, a=value), value), result
    if mnemonic == "SRE":
        value = _s(state.a ^ result)
        return _nz(replace(state, a=value), value), result
    if mnemonic == "RRA":
        return _adc(state, result), result
    raise AssertionError(mnemonic)


_IMPLIED = {
    "TAX": lambda s: _nz(replace(s, x=s.a), s.a),
    "TAY": lambda s: _nz(replace(s, y=s.a), s.a),
    "TXA": lambda s: _nz(replace(s, a=s.x), s.x),
    "TYA": lambda s: _nz(replace(s, a=s.y), s.y),
    "TSX": lambda s: _nz(replace(s, x=s.s), s.s),
    "TXS": lambda s: replace(s, s=s.x),
    "INX": lambda s: _nz(replace(s, x=_s(s.x + 1)), s.x + 1),
    "INY": lambda s: _nz(replace(s, y=_s(s.y + 1)), s.y + 1),
    "DEX": lambda s: _nz(replace(s, x=_s(s.x - 1)), s.x - 1),
    "DEY": lambda s: _nz(replace(s, y=_s(s.y - 1)), s.y - 1),
    "CLC": lambda s: replace(s, c=FALSE),
    "SEC": lambda s: replace(s, c=TRUE),
    "CLI": lambda s: replace(s, i=FALSE),
    "SEI": lambda s: replace(s, i=TRUE),
    "CLD": lambda s: replace(s, d=FALSE),
    "SED": lambda s: replace(s, d=TRUE),
    "CLV": lambda s: replace(s, v=FALSE),
}


def _pc(term):
    concrete = as_int(term)
    return concrete if concrete is not None else z3.simplify(term)


def enter_interrupt(state: State, vector: int, *, brk: bool = False,
                    return_pc: int | None = None) -> State:
    """Push PC and status, set I, load PC from `vector`."""
    pc = state.pc if return_pc is None else return_pc
    if not isinstance(pc, int):
        raise SymbolicFetch("interrupt entry needs a concrete return address")
    state = push(state, pc >> 8 & 0xFF)
    state = push(state, pc & 0xFF)
    state = push(state, state.status(b=brk))
    target, state = _read_word(state, bv16(vector), bv16(vector + 1))
    return replace(state, i=TRUE, pc=_pc(target))


def reset(state: State) -> State:
    """Warm reset: S drops by three with no writes, I is set."""
    target, state = _read_word(state, bv16(RESET_VECTOR),
                               bv16(RESET_VECTOR + 1))
    return replace(state, s=_s(state.s - 3), i=TRUE, pc=_pc(target),
                   halted=False)


def fetch(state: State):
    """The decoded instruction at the program counter, and its operand bytes."""
    if not isinstance(state.pc, int):
        raise SymbolicFetch("program counter is symbolic")
    pc = state.pc
    opcode_term, state = _read(state, bv16(pc))
    opcode = as_int(opcode_term)
    if opcode is None:
        raise SymbolicFetch(f"opcode at ${pc:04X} is symbolic")
    info = OPCODES[opcode]
    operands = []
    for offset in range(1, info.length):
        term, state = _read(state, bv16((pc + offset) & 0xFFFF))
        value = as_int(term)
        if value is None:
            raise SymbolicFetch(f"operand at ${pc + offset:04X} is symbolic")
        operands.append(value)
    lo = operands[0] if operands else 0
    hi = operands[1] if len(operands) > 1 else 0
    return info, lo, hi, state


def step(state: State) -> list[Successor]:
    """Execute one instruction.  Branches on symbolic flags fork."""
    if state.halted:
        return [Successor(TRUE, state, "halt")]
    info, lo, hi, state = fetch(state)
    pc = state.pc
    mnemonic, mode = info.mnemonic, info.mode
    next_pc = (pc + info.length) & 0xFFFF
    done = lambda st, kind="fallthrough": [
        Successor(TRUE, replace(st, pc=next_pc), kind)]

    # -- control flow -------------------------------------------------------
    if mnemonic in _BRANCH:
        flag_name, wanted = _BRANCH[mnemonic]
        flag = getattr(state, flag_name)
        taken = _s(flag if wanted else z3.Not(flag))
        offset = lo - 0x100 if lo & 0x80 else lo
        target = (next_pc + offset) & 0xFFFF
        out = []
        if not z3.is_false(taken):
            out.append(Successor(taken, replace(state, pc=target), "branch"))
        if not z3.is_true(taken):
            out.append(Successor(_s(z3.Not(taken)),
                                 replace(state, pc=next_pc), "fallthrough"))
        return out
    if info.flow is Flow.JUMP:
        return [Successor(TRUE, replace(state, pc=lo | hi << 8), "jump")]
    if info.flow is Flow.INDIRECT_JUMP:
        pointer = lo | hi << 8
        high_address = (pointer & 0xFF00) | ((pointer + 1) & 0x00FF)
        target, state = _read_word(state, bv16(pointer), bv16(high_address))
        return [Successor(TRUE, replace(state, pc=_pc(target)),
                          "indirect_jump")]
    if mnemonic == "JSR":
        frame = (pc + 2) & 0xFFFF
        state = push(state, frame >> 8)
        state = push(state, frame & 0xFF)
        return [Successor(TRUE, replace(state, pc=lo | hi << 8), "call")]
    if mnemonic == "RTS":
        low, state = pull(state)
        high, state = pull(state)
        return [Successor(TRUE, replace(state, pc=_pc(_word(low, high) + 1)),
                          "return")]
    if mnemonic == "RTI":
        status, state = pull(state)
        state = state.with_status(status)
        low, state = pull(state)
        high, state = pull(state)
        return [Successor(TRUE, replace(state, pc=_pc(_word(low, high))),
                          "interrupt_return")]
    if mnemonic == "BRK":
        state = enter_interrupt(state, IRQ_VECTOR, brk=True,
                                return_pc=(pc + 2) & 0xFFFF)
        return [Successor(TRUE, state, "break")]
    if mnemonic == "JAM":
        return [Successor(TRUE, replace(state, halted=True), "halt")]

    # -- stack --------------------------------------------------------------
    if mnemonic == "PHA":
        return done(push(state, state.a))
    if mnemonic == "PHP":
        return done(push(state, state.status(b=True)))
    if mnemonic == "PLA":
        value, state = pull(state)
        return done(_nz(replace(state, a=value), value))
    if mnemonic == "PLP":
        value, state = pull(state)
        return done(state.with_status(value))

    if mnemonic in _IMPLIED:
        return done(_IMPLIED[mnemonic](state))

    # -- accumulator-mode shifts ---------------------------------------------
    if mode == "acc":
        result, carry = _SHIFTS[mnemonic](state, state.a)
        return done(_nz(replace(state, a=result, c=carry), result))

    # -- unstable stores -----------------------------------------------------
    if mnemonic in ("SHA", "SHX", "SHY", "TAS"):
        if mnemonic == "TAS":
            state = replace(state, s=_s(state.a & state.x))
        return done(replace(state, mem=state.mem.havoc_write()))

    # -- operand readers ------------------------------------------------------
    if mnemonic in _READERS:
        if mode == "imp":                       # one-byte undocumented NOPs
            return done(state)
        if mode == "imm":
            operand = bv8(lo)
        else:
            address, state = _effective_address(state, mode, lo, hi)
            operand, state = _read(state, address)
        return done(_apply_read(state, mnemonic, operand))

    if mnemonic in _MODIFIERS:
        address, state = _effective_address(state, mode, lo, hi)
        operand, state = _read(state, address)
        state, result = _apply_modify(state, mnemonic, operand)
        return done(replace(state, mem=state.mem.write(address, result)))

    if mnemonic in _STORES:
        address, state = _effective_address(state, mode, lo, hi)
        value = {"STA": state.a, "STX": state.x, "STY": state.y,
                 "SAX": _s(state.a & state.x)}[mnemonic]
        return done(replace(state, mem=state.mem.write(address, value)))

    raise AssertionError(f"no semantics for {mnemonic} {mode}")
