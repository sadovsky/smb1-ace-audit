"""Every destination every dispatch can reach, for all 256 indices (plan 7).

The audit discarded anomalous destinations as soon as they resolved to PRG ROM.
That is not sound: an unexpected ROM destination can land on an operand byte,
in data, or at a routine whose preconditions do not hold, and any of those can
corrupt control flow further downstream.  So this module records *all* 18 x 256
resolutions with no exclusions, and classifies each destination against the CFG
as an expected entry, an instruction start, an operand byte, or unreached data.

Two JumpEngine properties shape the result and are easy to get wrong:

*Aliasing.*  `ASL A` discards bit 7 into the carry, which the routine never
uses, so index `i` and index `i + 128` produce the **same** Y and therefore the
same destination.  The effective index is `i & 0x7F`, which means a table
overrun can never read further than 256 bytes past the `JSR`: there are only
128 distinct destinations per site, not 256.

*The `$7F` wrap.*  `INY` wraps modulo 256.  At effective index 127, Y reaches
255 for the low byte and then wraps to 0 for the high byte, so the pointer's
high byte is fetched from the return address itself rather than from 256 bytes
later.  `jumpengine.resolve_table` already models this; the matrix records both
read addresses so it is visible rather than implicit.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from typing import Callable

from jumpengine import resolve_table
from memory import memory_region, normalize_internal_ram

from .cfg import CFG
from .provenance import ExecutionOutcome

#: Regions whose bytes a player can influence at all.
RAM_REGIONS = frozenset({"internal_ram", "internal_ram_mirror"})


def effective_index(raw: int) -> int:
    """`ASL A` drops bit 7, so indices 128..255 alias onto 0..127."""
    return raw & 0x7F


def classify_outcome(destination: int, *, expected: bool) -> ExecutionOutcome:
    region = memory_region(destination)
    if region == "prg_rom":
        return (ExecutionOutcome.EXPECTED_ROM if expected
                else ExecutionOutcome.UNEXPECTED_ROM)
    if region in RAM_REGIONS:
        return ExecutionOutcome.INTERNAL_RAM
    if region in ("ppu_registers", "apu_io", "disabled_io"):
        return ExecutionOutcome.IO_DEPENDENT
    return ExecutionOutcome.OPEN_BUS_DEPENDENT


@dataclass(frozen=True)
class Resolution:
    """One (site, index) pair resolved end to end."""

    dispatch: int
    raw_index: int
    effective: int
    low_address: int
    high_address: int
    destination: int
    region: str
    expected: bool
    outcome: ExecutionOutcome
    #: how the destination byte is used by the program, per the CFG
    rom_role: str
    wraps: bool

    def to_json(self) -> dict:
        return {
            "dispatch": f"0x{self.dispatch:04X}",
            "raw_index": self.raw_index,
            "effective_index": self.effective,
            "pointer_low_read_from": f"0x{self.low_address:04X}",
            "pointer_high_read_from": f"0x{self.high_address:04X}",
            "high_byte_wrapped": self.wraps,
            "destination": f"0x{self.destination:04X}",
            "memory_region": self.region,
            "physical_ram": (f"0x{normalize_internal_ram(self.destination):04X}"
                             if self.region in RAM_REGIONS else None),
            "expected_table_entry": self.expected,
            "execution_outcome": self.outcome.value,
            "rom_role": self.rom_role,
        }


def rom_role(graph: CFG, destination: int) -> str:
    """How the CFG sees a PRG-ROM destination byte."""
    if memory_region(destination) != "prg_rom":
        return "not_rom"
    if destination in graph.nodes:
        return "instruction_start"
    occupied = graph.occupied_bytes()
    if destination in occupied:
        return "operand_byte_of_another_instruction"
    return "not_reached_by_the_cfg"


def resolve_all(read_byte: Callable[[int], int], graph: CFG
                ) -> list[Resolution]:
    """The complete matrix: every dispatch, every raw index, no exclusions."""
    occupied = graph.occupied_bytes()
    out: list[Resolution] = []
    for dispatch in sorted(graph.dispatches):
        site = graph.dispatches[dispatch]
        entries = len(site.entries)
        for raw in range(256):
            resolution = resolve_table(read_byte, site.table, raw)
            destination = resolution.target
            effective = effective_index(raw)
            expected = effective < entries
            region = memory_region(destination)
            if region != "prg_rom":
                role = "not_rom"
            elif destination in graph.nodes:
                role = "instruction_start"
            elif destination in occupied:
                role = "operand_byte_of_another_instruction"
            else:
                role = "not_reached_by_the_cfg"
            out.append(Resolution(
                dispatch=dispatch,
                raw_index=raw,
                effective=effective,
                low_address=resolution.low_address,
                high_address=resolution.high_address,
                destination=destination,
                region=region,
                expected=expected,
                outcome=classify_outcome(destination, expected=expected),
                rom_role=role,
                wraps=resolution.high_address < resolution.low_address,
            ))
    return out


def summarise(resolutions: list[Resolution]) -> dict:
    distinct = {(r.dispatch, r.effective) for r in resolutions}
    unexpected_rom = [r for r in resolutions
                      if r.outcome is ExecutionOutcome.UNEXPECTED_ROM]
    return {
        "resolutions": len(resolutions),
        "distinct_site_index_pairs": len(distinct),
        "outcomes": dict(Counter(r.outcome.value for r in resolutions)),
        "unexpected_rom_roles": dict(Counter(r.rom_role
                                             for r in unexpected_rom)),
        "high_byte_wrapped": sum(1 for r in resolutions if r.wraps),
    }


def main() -> None:  # pragma: no cover - CLI
    from rom import b, image

    from .cfg import build_from_vectors

    graph = build_from_vectors(b)
    resolutions = resolve_all(b, graph)
    summary = summarise(resolutions)

    print(f"ROM sha1 {image().sha1}")
    print(f"\nresolutions: {summary['resolutions']} "
          f"(18 sites x 256 raw indices)")
    print(f"distinct (site, effective index) pairs: "
          f"{summary['distinct_site_index_pairs']}  "
          f"-- ASL aliasing halves 256 raw indices to 128 effective ones")
    print("\nexecution outcomes for every resolution:")
    for outcome, count in sorted(summary["outcomes"].items(),
                                 key=lambda kv: -kv[1]):
        print(f"  {outcome:22} {count:5}")

    print("\nunexpected ROM destinations by how the CFG uses that byte:")
    for role, count in sorted(summary["unexpected_rom_roles"].items(),
                              key=lambda kv: -kv[1]):
        print(f"  {role:40} {count:5}")
    print("  (these were previously dropped as 'resolves to ROM, therefore "
          "safe')")

    print("\nper site: non-ROM destinations among the 128 effective indices")
    print("site   expected  unexpected_rom  internal_ram  io  open_bus")
    print("-" * 64)
    for dispatch in sorted(graph.dispatches):
        rows = [r for r in resolutions
                if r.dispatch == dispatch and r.raw_index < 128]
        counts = Counter(r.outcome.value for r in rows)
        print(f"${dispatch:04X} {counts.get('expected_rom', 0):9} "
              f"{counts.get('unexpected_rom', 0):15} "
              f"{counts.get('internal_ram', 0):13} "
              f"{counts.get('io_dependent', 0):3} "
              f"{counts.get('open_bus_dependent', 0):9}")

    wrapped = [r for r in resolutions if r.wraps]
    print(f"\nresolutions whose high pointer byte wrapped (effective index "
          f"127): {len(wrapped)}")
    for resolution in wrapped[:4]:
        print(f"  ${resolution.dispatch:04X} raw {resolution.raw_index:3}: "
              f"low from ${resolution.low_address:04X}, high from "
              f"${resolution.high_address:04X} -> "
              f"${resolution.destination:04X}")

    report = {"rom_sha1": image().sha1, "summary": summary,
              "resolutions": [r.to_json() for r in resolutions]}
    with open("results/destination_matrix.json", "w") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
    print("\nwrote results/destination_matrix.json")


if __name__ == "__main__":  # pragma: no cover
    main()
