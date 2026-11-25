"""Independent derivation of enemy-identifier routing (plan sections 2, 12).

`reach.py` derives which identifiers can arrive at each enemy dispatch by
reading the routing tables out of `trace.json`.  This module derives the same
sets from the CFG's own dispatch tables, so the two can be compared rather than
one inheriting the other's assumptions (`tests/test_enemy_routing.py` asserts
they agree).

What routing does and does not establish, kept apart as section 12 asks:

  target computation   which index an identifier produces -- pure arithmetic
                       read off the ROM, no assumptions
  legal domain         which identifiers the master table covers ($00..$36)
  dispatch reachability which identifiers are routed to a given dispatch
  preservation         that the slot still holds that identifier when the
                       downstream dispatch runs

Only the first is proved here.  The legal domain follows from the master
table's own size, which is itself a boundary claim (see `dispatch_tables`).
Reachability is conditional on the routing tables being the only path to each
dispatch.  **Preservation is not established at all**: between the `CPY #$15`
gate and a downstream dispatch, the slot could in principle be rewritten, and
an interrupt can run in between.  So every bound derived here is
DERIVED_CONDITIONAL, never PROVEN, and it names preservation as an assumption.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .cfg import CFG
from .provenance import BoundProvenance

#: The master behaviour table at $C27F has 55 entries, so the identifier
#: domain it covers is $00..$36.  This is a *table boundary* claim.
MAX_LEGAL_ID = 0x36

#: Routines the collision dispatch forwards to, each ending in a further
#: JumpEngine dispatch.
COLLISION_FORWARDS = {0xC8E0: 0xC907, 0xC965: 0xC987}


def collision_index(identifier: int) -> int:
    """`$C88F`: `CPY #$15 / BCC` then `SBC #$14`."""
    return 0 if identifier < 0x15 else (identifier - 0x14) & 0xFF


def sub_index(offset: int) -> Callable[[int], int]:
    def index(identifier: int) -> int:
        return (identifier - offset) & 0xFF
    return index


@dataclass(frozen=True)
class Routing:
    """Which identifiers reach one dispatch, and the index each produces."""

    dispatch: int
    role: str
    index_of: Callable[[int], int]
    arriving: frozenset[int]
    entries: int

    @property
    def indices(self) -> set[int]:
        return {self.index_of(i) for i in self.arriving}

    @property
    def out_of_range(self) -> dict[int, int]:
        return {i: self.index_of(i) for i in sorted(self.arriving)
                if self.index_of(i) >= self.entries}

    @property
    def provenance(self) -> BoundProvenance:
        return BoundProvenance.DERIVED_CONDITIONAL

    def assumptions(self) -> tuple[str, ...]:
        return (
            f"identifiers reaching ${self.dispatch:04X} are exactly those the "
            f"routing tables send there ({len(self.arriving)} of "
            f"{MAX_LEGAL_ID + 1})",
            f"the $16,x slot still holds that identifier when "
            f"${self.dispatch:04X} runs (preservation is not established; an "
            "interrupt or an intervening store could change it)",
            f"the identifier domain is $00..${MAX_LEGAL_ID:02X}, which rests "
            "on the $C27F table boundary",
        )

    def to_json(self) -> dict:
        indices = sorted(self.indices)
        return {
            "dispatch": f"0x{self.dispatch:04X}",
            "role": self.role,
            "table_entries": self.entries,
            "arriving_identifiers": [f"0x{i:02X}" for i in sorted(self.arriving)],
            "index_min": min(indices) if indices else None,
            "index_max": max(indices) if indices else None,
            "out_of_range": {f"0x{i:02X}": index
                             for i, index in self.out_of_range.items()},
            "provenance": self.provenance.value,
            "assumptions": list(self.assumptions()),
        }


def derive(graph: CFG) -> dict[int, Routing]:
    """Derive the routing from the CFG's dispatch tables."""
    master = graph.dispatches[0xC27F]
    collision = graph.dispatches[0xC88F]
    domain = frozenset(range(MAX_LEGAL_ID + 1))

    def master_target(identifier: int) -> int | None:
        entries = master.entries
        return entries[identifier] if identifier < len(entries) else None

    def collision_target(identifier: int) -> int | None:
        index = collision_index(identifier)
        entries = collision.entries
        return entries[index] if index < len(entries) else None

    routed_7a8 = frozenset(i for i in domain if master_target(i) == 0xC7A0)
    routed_907 = frozenset(i for i in domain
                           if collision_target(i) == 0xC8E0)
    routed_987 = frozenset(i for i in domain
                           if collision_target(i) == 0xC965)

    return {
        0xC27F: Routing(0xC27F, "behaviour master", lambda i: i, domain,
                        len(master.entries)),
        0xC88F: Routing(0xC88F, "collision", collision_index, domain,
                        len(collision.entries)),
        0xC907: Routing(0xC907, "graphics", lambda i: i, routed_907,
                        len(graph.dispatches[0xC907].entries)),
        0xC987: Routing(0xC987, "sub $24", sub_index(0x24), routed_987,
                        len(graph.dispatches[0xC987].entries)),
        0xC7A8: Routing(0xC7A8, "sub $12", sub_index(0x12), routed_7a8,
                        len(graph.dispatches[0xC7A8].entries)),
    }


def main() -> None:  # pragma: no cover - CLI
    import json

    from rom import b, image

    from .cfg import build_from_vectors
    from memory import memory_region

    graph = build_from_vectors(b)
    routing = derive(graph)
    print(f"ROM sha1 {image().sha1}")
    print("Enemy-ID routing derived from the CFG's dispatch tables.\n")
    print(f"{'site':6} {'role':17} {'N':>3} {'IDs':>4} {'indices':>10}  verdict")
    print("-" * 72)
    for dispatch in sorted(routing):
        route = routing[dispatch]
        indices = sorted(route.indices)
        span = f"{min(indices)}..{max(indices)}" if indices else "-"
        if route.out_of_range:
            verdict = "OUT OF RANGE: " + ", ".join(
                f"ID ${i:02X}->idx {x}" for i, x in route.out_of_range.items())
        else:
            verdict = f"in range (max {max(indices)} <= {route.entries - 1})"
        print(f"${dispatch:04X} {route.role:17} {route.entries:3} "
              f"{len(route.arriving):4} {span:>10}  {verdict}")

    print("\nOut-of-range dispatches and their destinations:")
    found = False
    for dispatch in sorted(routing):
        route = routing[dispatch]
        site = graph.dispatches[dispatch]
        for identifier, index in route.out_of_range.items():
            found = True
            from jumpengine import resolve_table
            target = resolve_table(b, site.table, index).target
            print(f"  ${dispatch:04X} ID ${identifier:02X} -> index {index} "
                  f"-> ${target:04X} [{memory_region(target)}]")
    if not found:
        print("  none")

    print("\nEvery bound above is conditional.  Assumptions:")
    for assumption in routing[0xC907].assumptions():
        print(f"  - {assumption}")

    with open("results/enemy_routing.json", "w") as handle:
        json.dump({"rom_sha1": image().sha1,
                   "routes": [routing[d].to_json() for d in sorted(routing)]},
                  handle, indent=2, sort_keys=True)
    print("\nwrote results/enemy_routing.json")


if __name__ == "__main__":  # pragma: no cover
    main()
