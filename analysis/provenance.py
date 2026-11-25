"""Independent dimensions for an audit record (remediation plan section 4).

The earlier classifier collapsed three unrelated questions into one verdict:

  * how well is the index bound established?        -> BoundProvenance
  * can the out-of-range index actually be reached?  -> Reachability
  * what happens if execution goes there?            -> ExecutionOutcome

Collapsing them let an *observed* bound produce the same "excluded" verdict as
a bound enforced by an instruction, which overstates the evidence.  The rule
this module exists to enforce:

    An observation can never justify an unconditional exclusion.

`excludes_unconditionally()` is the single place that decides which provenances
are strong enough to exclude an index outright; everything else downgrades to a
conditional exclusion that must carry its assumptions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class BoundProvenance(str, Enum):
    """How an index bound was established."""

    #: Enforced unconditionally by instructions at the dispatch itself
    #: (a CMP/BCS clamp, an AND mask).  No upstream assumption needed.
    PROVEN = "proven"

    #: Instructions at the dispatch constrain the index, but only given an
    #: upstream invariant on the variable they read (e.g. $92C8 substitutes 8
    #: for zero but never clamps the upper end).
    STRUCTURAL_CONDITIONAL = "structural_conditional"

    #: Computed from ROM routing tables, conditional on the routing holding
    #: (reach.py) and on the identifier being preserved between gate and use.
    DERIVED_CONDITIONAL = "derived_conditional"

    #: Consistent with every state reached by the experiments, not proved for
    #: unreached states.  Cannot exclude anything unconditionally.
    OBSERVED = "observed"

    #: Asserted by an earlier revision without evidence in this repository.
    ASSUMED = "assumed"

    #: No bound established.
    UNPROVED = "unproved"


class Reachability(str, Enum):
    """Whether a particular (site, index) pair can occur at all."""

    PROVEN_UNREACHABLE = "proven_unreachable"
    CONDITIONALLY_UNREACHABLE = "conditionally_unreachable"
    OBSERVED_REACHABLE = "observed_reachable"
    NOT_OBSERVED = "not_observed"
    UNKNOWN = "unknown"


class ExecutionOutcome(str, Enum):
    """What executing at the resolved destination would mean."""

    #: A table entry the dispatch is designed to reach.
    EXPECTED_ROM = "expected_rom"

    #: PRG ROM, but not an intended entry: may land mid-instruction, in data,
    #: or in a routine whose preconditions do not hold.  Not inherently safe.
    UNEXPECTED_ROM = "unexpected_rom"

    #: $0000-$1FFF: the only region whose bytes the player can influence.
    INTERNAL_RAM = "internal_ram"

    #: Instruction fetch from a register region; behaviour is hardware
    #: dependent, not automatically a crash.
    IO_DEPENDENT = "io_dependent"

    #: Unmapped on NROM; fetched bytes depend on bus capacitance.
    OPEN_BUS_DEPENDENT = "open_bus_dependent"

    UNKNOWN = "unknown"


#: Provenances strong enough to exclude an index with no further assumptions.
UNCONDITIONAL = frozenset({BoundProvenance.PROVEN})


def excludes_unconditionally(provenance: BoundProvenance) -> bool:
    """True only for bounds that need no upstream assumption."""
    return BoundProvenance(provenance) in UNCONDITIONAL


@dataclass(frozen=True)
class Bound:
    """An index bound together with what it rests on.

    `assumptions` must be non-empty for every provenance outside
    `UNCONDITIONAL`; `validate()` enforces that so a conditional exclusion can
    never be silently promoted to an unconditional one.
    """

    maximum: int | None
    provenance: BoundProvenance
    mechanism: str
    assumptions: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if self.maximum is not None and not 0 <= self.maximum <= 0xFF:
            raise ValueError(f"index bound {self.maximum} outside 0..255")
        if self.provenance is BoundProvenance.UNPROVED:
            if self.maximum is not None:
                raise ValueError("an unproved bound cannot carry a maximum")
            return
        if self.maximum is None:
            raise ValueError(f"provenance {self.provenance.value} requires a maximum")
        if not excludes_unconditionally(self.provenance) and not self.assumptions:
            raise ValueError(
                f"provenance {self.provenance.value} is conditional and must "
                "list its assumptions"
            )

    @property
    def is_unconditional(self) -> bool:
        return excludes_unconditionally(self.provenance)

    def excludes(self, index: int) -> bool:
        """Whether `index` lies above the bound at all (provenance aside)."""
        return self.maximum is not None and index > self.maximum

    def exclusion_for(self, index: int) -> tuple[Reachability, str]:
        """Classify one index under this bound, honouring provenance."""
        if not self.excludes(index):
            return Reachability.UNKNOWN, "index is within the table / bound"
        if self.is_unconditional:
            return (
                Reachability.PROVEN_UNREACHABLE,
                f"index > {self.maximum}, enforced at the dispatch: {self.mechanism}",
            )
        if self.provenance is BoundProvenance.OBSERVED:
            return (
                Reachability.NOT_OBSERVED,
                f"index > {self.maximum} was never observed ({self.mechanism}); "
                "unreached states are not covered",
            )
        return (
            Reachability.CONDITIONALLY_UNREACHABLE,
            f"index > {self.maximum} given {self.mechanism}; assumes: "
            + "; ".join(self.assumptions),
        )

    def to_json(self) -> dict:
        return {
            "maximum": self.maximum,
            "provenance": self.provenance.value,
            "mechanism": self.mechanism,
            "assumptions": list(self.assumptions),
            "unconditional": self.is_unconditional,
        }
