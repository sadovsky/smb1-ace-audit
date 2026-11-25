"""Exact 8-bit value-set abstract interpretation (plan sections 3, 11, 13).

Registers hold a *set* of possible byte values, represented as a 256-bit mask.
For 8-bit operations this domain is exact rather than merely sound: there is no
widening to lose, because a set of bytes can always be enumerated.  That makes
it strong enough to answer the audit's central question mechanically --
"what indices can arrive at this dispatch?" -- instead of by hand.

Two things the audit needed and hand-reading kept getting wrong:

*Branch feasibility.*  `LDA #$0B / BNE target` cannot fall through: the load
makes Z=0 unconditionally.  The old tracer followed the fallthrough anyway and
wandered into data, decoding it as `JAM` and `SHA` instructions.  Flags here
are derived from the value set, so an always-taken branch is recognised and the
infeasible edge is dropped.

*Comparison refinement.*  `CMP #k` followed by `BCC` constrains the
accumulator on both sides of the branch.  A comparison records its context so
the branch can refine the register set, which is how `$BDBD`'s real bound
(index <= 8 via `Y <= 13`) and `$B34E`'s *absent* bound are both derived rather
than assumed.

Unknown memory reads widen to the full set, so results over-approximate the
real program.  ROM reads at an exact address are resolved from the cartridge,
which is what makes table-driven routing (`$BDF6`, the enemy-ID dispatchers)
analysable at all.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Callable, Iterable

FULL = (1 << 256) - 1          # every byte value
EMPTY = 0

# --------------------------------------------------------------------------
# ByteSet helpers (a ByteSet is an int bitmask over 0..255)
# --------------------------------------------------------------------------


def singleton(value: int) -> int:
    return 1 << (value & 0xFF)


def from_values(values: Iterable[int]) -> int:
    mask = 0
    for value in values:
        mask |= 1 << (value & 0xFF)
    return mask


def values(mask: int) -> list[int]:
    return [v for v in range(256) if mask >> v & 1]


def count(mask: int) -> int:
    return bin(mask).count("1")


def is_singleton(mask: int) -> bool:
    return mask != 0 and mask & (mask - 1) == 0


def only(mask: int) -> int:
    if not is_singleton(mask):
        raise ValueError("value set is not a singleton")
    return mask.bit_length() - 1


def map_unary(mask: int, function: Callable[[int], int]) -> int:
    out = 0
    for value in values(mask):
        out |= 1 << (function(value) & 0xFF)
    return out


def map_binary(left: int, right: int,
               function: Callable[[int, int], int],
               *, full_absorbs: bool = False) -> int:
    """Apply `function` pointwise over two value sets.

    `full_absorbs` marks operations for which an unconstrained operand forces
    an unconstrained result (AND, ORA, EOR, ADC, SBC all have this property,
    since one operand can realise every output).  That fast path matters: the
    naive product is 65536 evaluations and unconstrained operands are the
    common case when registers enter a slice unknown.
    """
    if full_absorbs and (left == FULL or right == FULL) and left and right:
        return FULL
    out = 0
    for a in values(left):
        for bb in values(right):
            out |= 1 << (function(a, bb) & 0xFF)
    return out


def restrict(mask: int, predicate: Callable[[int], bool]) -> int:
    out = 0
    for value in values(mask):
        if predicate(value):
            out |= 1 << value
    return out


# --------------------------------------------------------------------------
# flags
# --------------------------------------------------------------------------

UNKNOWN = None          # a flag whose value is not determined


def flag_from_set(mask: int, predicate: Callable[[int], bool]) -> bool | None:
    """True/False when every value agrees, otherwise unknown."""
    if mask == EMPTY:
        return None
    results = {predicate(v) for v in values(mask)}
    if len(results) == 1:
        return next(iter(results))
    return None


@dataclass(frozen=True)
class Compare:
    """A pending comparison, so a later branch can refine the register.

    `nz_only` marks a context that came from an instruction which set Z and N
    from a result rather than from a subtraction -- a load, a transfer, an
    increment.  Those make `BNE`/`BEQ`/`BPL`/`BMI` informative about the
    register (it was compared against zero in effect) while leaving the carry
    flag untouched, so a carry branch must not refine anything.
    """

    register: str          # "A", "X" or "Y"
    operand: int           # ByteSet the register was compared against
    bit_test: bool = False  # BIT sets Z from a mask, not a subtraction
    nz_only: bool = False   # flags came from a result, not a comparison


@dataclass(frozen=True)
class State:
    """Abstract CPU state: register value sets plus flag knowledge."""

    a: int = FULL
    x: int = FULL
    y: int = FULL
    s: int = FULL
    carry: bool | None = UNKNOWN
    zero: bool | None = UNKNOWN
    negative: bool | None = UNKNOWN
    overflow: bool | None = UNKNOWN
    compare: Compare | None = None

    def register(self, name: str) -> int:
        return {"A": self.a, "X": self.x, "Y": self.y, "S": self.s}[name]

    def with_register(self, name: str, mask: int) -> "State":
        field = {"A": "a", "X": "x", "Y": "y", "S": "s"}[name]
        return replace(self, **{field: mask})

    def set_nz(self, mask: int) -> "State":
        return replace(self,
                       zero=flag_from_set(mask, lambda v: v == 0),
                       negative=flag_from_set(mask, lambda v: v & 0x80 != 0))

    def load(self, name: str, mask: int) -> "State":
        """Load/transfer: sets Z and N from the value, leaves carry alone.

        The implied comparison against zero is recorded so that a following
        `BNE`/`BEQ` can narrow the register -- without it, `LDY $071F / BNE`
        leaves Y unconstrained and `DEY` then appears able to produce $FF.
        """
        loaded = self.with_register(name, mask).set_nz(mask)
        return replace(loaded, compare=Compare(name, singleton(0),
                                               nz_only=True))

    def clear_compare(self) -> "State":
        return replace(self, compare=None)

    @property
    def is_feasible(self) -> bool:
        return all(m != EMPTY for m in (self.a, self.x, self.y))

    def key(self) -> tuple:
        return (self.a, self.x, self.y, self.carry, self.zero,
                self.negative, self.overflow, self.compare)


# --------------------------------------------------------------------------
# memory model
# --------------------------------------------------------------------------


class Memory:
    """Reads for the interpreter: exact in ROM, unconstrained in RAM.

    `invariants` may map a RAM address to a ByteSet, which is how an
    established invariant (for example `RAM[$071F] <= 8`) is fed into the
    analysis *as an explicit assumption* rather than baked into the model.
    """

    def __init__(self, read_byte: Callable[[int], int], *,
                 invariants: dict[int, int] | None = None,
                 rom_floor: int = 0x8000):
        self.read_byte = read_byte
        self.invariants = invariants or {}
        self.rom_floor = rom_floor

    def read(self, address_mask_lo: int, address_mask_hi: int | None = None,
             *, exact: int | None = None) -> int:
        """Read a byte set.  `exact` is a known concrete address."""
        if exact is not None:
            address = exact & 0xFFFF
            if address in self.invariants:
                return self.invariants[address]
            if address >= self.rom_floor:
                return singleton(self.read_byte(address))
            return FULL
        return FULL

    def read_set(self, addresses: Iterable[int]) -> int:
        out = 0
        for address in addresses:
            out |= self.read(0, exact=address)
            if out == FULL:
                break
        return out
