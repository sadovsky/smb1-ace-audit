"""Independent evidence for dispatch-table boundaries (plan section 6).

Table sizes came from one heuristic: read words until one falls below `$8000`.
That is a guess about where data stops, not a boundary proof.  It fails in both
directions -- a table whose next bytes happen to form a ROM-range word is
over-read, and a table containing a deliberate low word is under-read -- and
every per-site bound and "in range" verdict depends on the answer.

So each boundary is established from several independent sources and the
results are compared:

`heuristic`
    The original rule, kept for comparison only.

`self_reference`
    The smallest target inside the table's own span.  A table cannot extend
    past an address that one of its own entries points at, because that
    address is executed as code.  `$92CB`'s entry 0 is `$92DB`, exactly 16
    bytes on, which bounds that table at 8 entries with no heuristic at all.

`control_flow`
    The smallest address at or after the table that the CFG reaches by some
    route other than this dispatch -- a branch target, a call, another table's
    entry.  Bytes that are executed as instructions are not table data.

`next_table`
    The start of the next dispatch table in address order, when one follows
    closely enough to bound this one.

Agreement across sources is reported as `agreement`.  Where they disagree the
*smallest* bound is taken, since every source is an upper bound on how far the
table can extend, and the disagreement is recorded rather than hidden.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable

from .cfg import CFG

MAX_ENTRIES = 80


@dataclass(frozen=True)
class BoundaryEvidence:
    """Entry counts implied by each independent source."""

    dispatch: int
    table: int
    heuristic: int
    self_reference: int | None
    control_flow: int | None
    next_table: int | None
    external_code: int | None = None

    def candidates(self) -> dict[str, int]:
        return {name: value for name, value in (
            ("heuristic", self.heuristic),
            ("self_reference", self.self_reference),
            ("control_flow", self.control_flow),
            ("next_table", self.next_table),
            ("external_code", self.external_code),
        ) if value is not None}

    @property
    def entries(self) -> int:
        """The boundary supported by every source: the smallest bound."""
        return min(self.candidates().values())

    @property
    def independent_sources(self) -> int:
        """How many sources other than the heuristic agree on `entries`."""
        return sum(1 for name, value in self.candidates().items()
                   if name != "heuristic" and value == self.entries)

    @property
    def agreement(self) -> str:
        values = set(self.candidates().values())
        if len(values) == 1:
            return "all sources agree"
        if self.independent_sources:
            return (f"smallest bound {self.entries} confirmed by "
                    f"{self.independent_sources} independent source(s)")
        return "sources disagree; smallest bound taken"

    @property
    def heuristic_was_wrong(self) -> bool:
        return self.heuristic != self.entries

    def to_json(self) -> dict:
        return {
            "dispatch": f"0x{self.dispatch:04X}",
            "table": f"0x{self.table:04X}",
            "entries": self.entries,
            "candidates": self.candidates(),
            "independent_sources_confirming": self.independent_sources,
            "agreement": self.agreement,
            "heuristic_differs": self.heuristic_was_wrong,
        }


def _heuristic_entries(read_byte: Callable[[int], int], table: int) -> int:
    count = 0
    for index in range(MAX_ENTRIES):
        low = read_byte((table + 2 * index) & 0xFFFF)
        high = read_byte((table + 2 * index + 1) & 0xFFFF)
        if (low | high << 8) < 0x8000:
            break
        count += 1
    return count


def _self_reference_entries(read_byte: Callable[[int], int], table: int,
                            limit: int) -> int | None:
    span_end = table + 2 * limit
    smallest = None
    for index in range(limit):
        low = read_byte((table + 2 * index) & 0xFFFF)
        high = read_byte((table + 2 * index + 1) & 0xFFFF)
        target = low | high << 8
        if table < target < span_end:
            smallest = target if smallest is None else min(smallest, target)
    if smallest is None:
        return None
    return (smallest - table) // 2


def _control_flow_entries(graph: CFG, dispatch: int, table: int,
                          limit: int) -> int | None:
    """First address after the table that the CFG executes as an instruction.

    Entries reached from *this* dispatch count: a table entry that points into
    its own span proves the span ends there, because that address is executed.
    Excluding them would discard the strongest piece of evidence available.
    """
    span_end = table + 2 * limit
    for address in range(table + 1, span_end):
        if address in graph.nodes:
            return (address - table) // 2
    return None


def _external_code_entries(graph: CFG, dispatch: int, table: int,
                           limit: int) -> int | None:
    """Same, but only addresses reached by a route other than this dispatch.

    This is the fully independent check: it does not rely on the table having
    been read correctly in the first place.
    """
    span_end = table + 2 * limit
    for address in range(table + 1, span_end):
        node = graph.nodes.get(address)
        if node is None:
            continue
        external = [source for source, kind in node.predecessors
                    if not (kind == "dispatch" and source == dispatch)]
        if external:
            return (address - table) // 2
    return None


def _next_table_entries(table: int, tables: list[int], limit: int) -> int | None:
    later = [t for t in tables if t > table]
    if not later:
        return None
    nearest = min(later)
    entries = (nearest - table) // 2
    return entries if entries < limit else None


def rom_only_entries(read_byte: Callable[[int], int], table: int,
                     tables: list[int] | None = None) -> int:
    """Boundary from ROM bytes alone, used to build the CFG in the first place.

    Uses the heuristic and the self-reference bound only, so it cannot inherit
    a phantom dispatch edge from a table that was over-read -- which is exactly
    what happened at $C7AB, where the heuristic swallowed the `RTS / LDY #$05`
    after the table and manufactured a jump to $A060.
    """
    heuristic = _heuristic_entries(read_byte, table)
    limit = max(heuristic, 1) + 8
    candidates = [heuristic]
    self_reference = _self_reference_entries(read_byte, table, limit)
    if self_reference is not None:
        candidates.append(self_reference)
    if tables:
        nearest = _next_table_entries(table, tables, limit)
        if nearest is not None:
            candidates.append(nearest)
    return min(candidates)


def establish(read_byte: Callable[[int], int], graph: CFG
              ) -> dict[int, BoundaryEvidence]:
    tables = [site.table for site in graph.dispatches.values()]
    out: dict[int, BoundaryEvidence] = {}
    for dispatch in sorted(graph.dispatches):
        table = graph.dispatches[dispatch].table
        heuristic = _heuristic_entries(read_byte, table)
        limit = max(heuristic, 1) + 8        # look a little past the heuristic
        out[dispatch] = BoundaryEvidence(
            dispatch=dispatch,
            table=table,
            heuristic=heuristic,
            self_reference=_self_reference_entries(read_byte, table, limit),
            control_flow=_control_flow_entries(graph, dispatch, table, limit),
            next_table=_next_table_entries(table, tables, limit),
            external_code=_external_code_entries(graph, dispatch, table, limit),
        )
    return out


def main() -> None:  # pragma: no cover - CLI
    from rom import b, image

    from .cfg import build_from_vectors

    graph = build_from_vectors(b)
    evidence = establish(b, graph)

    print(f"ROM sha1 {image().sha1}")
    print("\nDispatch-table boundaries from independent sources.\n")
    header = ("site   table   heur  self  cflow  next  extern  final  "
              "agreement")
    print(header)
    print("-" * len(header))
    for dispatch in sorted(evidence):
        row = evidence[dispatch]

        def show(value: int | None) -> str:
            return "-" if value is None else str(value)

        print(f"${dispatch:04X} ${row.table:04X} {row.heuristic:5} "
              f"{show(row.self_reference):>5} {show(row.control_flow):>6} "
              f"{show(row.next_table):>5} {show(row.external_code):>7} "
              f"{row.entries:6}  {row.agreement}")

    disagreed = [r for r in evidence.values() if r.heuristic_was_wrong]
    unconfirmed = [r for r in evidence.values()
                   if not r.independent_sources]
    print(f"\ntables where the heuristic differs from the final boundary: "
          f"{len(disagreed)}")
    for row in disagreed:
        print(f"  ${row.dispatch:04X}: heuristic {row.heuristic}, "
              f"established {row.entries}")
    print(f"tables with no independent confirmation: {len(unconfirmed)}")
    for row in unconfirmed:
        print(f"  ${row.dispatch:04X} (${row.table:04X}): only the heuristic "
              f"supports {row.entries} entries")

    with open("data/dispatch_tables.json", "w") as handle:
        json.dump({"rom_sha1": image().sha1,
                   "tables": [evidence[d].to_json() for d in sorted(evidence)]},
                  handle, indent=2, sort_keys=True)
    print("\nwrote data/dispatch_tables.json")


if __name__ == "__main__":  # pragma: no cover
    main()
