"""Index transformations in front of the dispatch sites (plan section 3).

The audit's central claim is that every JumpEngine dispatch receives an
in-range index.  For that claim the transformation between the *source
variable* and the *accumulator handed to $8E04* has to be modelled exactly,
because a transformation can substitute, mask, clamp -- or do none of those.

### The $92C8 correction

Earlier revisions described `$92C8` as "`$071F` forced 1..8 -> index 0..7,
structural, provably safe".  The ROM sequence is:

    $92B0  AC 1F 07   LDY $071F
    $92B3  D0 05      BNE $92BA
    $92B5  A0 08      LDY #$08
    $92B7  8C 1F 07   STY $071F      ; write-back, absent from the old note
    $92BA  88         DEY
    $92BB  98         TYA            ; A = index
    $92BC  20 C8 92   JSR $92C8      ; -> JSR $8E04, table at $92CB (8 entries)

`BNE` only separates zero from non-zero.  Nothing clamps the upper end, so the
transformation is a *zero substitution*, not a clamp:

    index = ((value or 8) - 1) & 0xFF

`$00 -> 7` and `$08 -> 7`, but `$09 -> 8` and `$FF -> 254`.  The index is
therefore bounded only by an upstream invariant on `RAM[$071F]`, which makes
the bound STRUCTURAL_CONDITIONAL rather than PROVEN.  See
`analysis.write_census` for the writer manifest that invariant needs.

Every model here is checked against the ROM bytes by `verify_against_rom()`, so
a model that drifts from the cartridge fails loudly instead of silently
describing a different program.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .provenance import Bound, BoundProvenance

# --------------------------------------------------------------------------
# transformations
# --------------------------------------------------------------------------


def identity_index(value: int) -> int:
    """The source byte reaches the accumulator unchanged."""
    return value & 0xFF


def zero_substituted_index(value: int, substitute: int = 8) -> int:
    """`LDY v / BNE / LDY #substitute / DEY / TYA`.

    Substitutes `substitute` for zero and then decrements.  This is *not* a
    clamp: values above `substitute` pass through decremented.
    """
    value &= 0xFF
    return ((value or substitute) - 1) & 0xFF


def subtracted_index(value: int, offset: int) -> int:
    """`SEC / SBC #offset` style routing (used by the enemy-ID sites)."""
    return (value - offset) & 0xFF


def clamped_index(value: int, limit: int) -> int:
    """`CMP #limit / BCS skip` -- a genuine upper clamp."""
    value &= 0xFF
    return value if value < limit else None  # type: ignore[return-value]


# --------------------------------------------------------------------------
# the ROM sequences each model claims to describe
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class IndexModel:
    """How one dispatch site forms its index, and how well it is bounded."""

    dispatch: int           # address of the JSR $8E04
    table: int              # first byte of the dispatch table
    entries: int            # table entries established independently
    source: str             # the variable the index comes from
    transform: Callable[[int], int]
    bound: Bound
    #: (address, bytes) pairs that must match the ROM for this model to apply
    witness: tuple[tuple[int, bytes], ...] = ()

    def index_for(self, value: int) -> int:
        return self.transform(value)

    def source_values_reaching(self, index: int) -> list[int]:
        """Every source byte that produces `index`."""
        return [v for v in range(256) if self.transform(v) == index]

    def verify_against_rom(self, read_byte: Callable[[int], int]) -> None:
        for address, expected in self.witness:
            actual = bytes(read_byte(address + i) for i in range(len(expected)))
            if actual != expected:
                raise AssertionError(
                    f"ROM at ${address:04X} is {actual.hex()} but the index "
                    f"model for ${self.dispatch:04X} expects {expected.hex()}"
                )


#: $071F is written only by the two instructions of its own routine
#: ($92B7 STY = 8, $92BF DEC), so [0,8] follows by induction *provided* no
#: indexed or indirect store reaches it.  write_census.py enumerates those.
_071F_ASSUMPTIONS = (
    "RAM[$071F] <= 8 at $92B0: initialised to 0 by the power-on clear and "
    "written only by $92B7 (STY #$08) and $92BF (DEC) on this path",
    "no indexed or indirect store reaches $071F (see analysis.write_census)",
)

DISPATCH_92C8 = IndexModel(
    dispatch=0x92C8,
    table=0x92CB,
    entries=8,
    source="$071F",
    transform=zero_substituted_index,
    bound=Bound(
        maximum=7,
        provenance=BoundProvenance.STRUCTURAL_CONDITIONAL,
        mechanism=(
            "LDY $071F / BNE / LDY #$08 / STY $071F / DEY / TYA substitutes 8 "
            "for zero; it does not clamp, so index <= 7 holds only while "
            "RAM[$071F] <= 8"
        ),
        assumptions=_071F_ASSUMPTIONS,
    ),
    witness=(
        (0x92B0, bytes.fromhex("ac1f07")),      # LDY $071F
        (0x92B3, bytes.fromhex("d005")),        # BNE $92BA
        (0x92B5, bytes.fromhex("a008")),        # LDY #$08
        (0x92B7, bytes.fromhex("8c1f07")),      # STY $071F
        (0x92BA, bytes.fromhex("88")),          # DEY
        (0x92BB, bytes.fromhex("98")),          # TYA
        (0x92BC, bytes.fromhex("20c892")),      # JSR $92C8
        (0x92C8, bytes.fromhex("20048e")),      # JSR $8E04
    ),
)

MODELS: dict[int, IndexModel] = {DISPATCH_92C8.dispatch: DISPATCH_92C8}


def verify_all(read_byte: Callable[[int], int]) -> None:
    for model in MODELS.values():
        model.verify_against_rom(read_byte)
