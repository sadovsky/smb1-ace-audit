"""Derive each dispatch site's index set from the ROM (plan sections 3, 4, 12).

The audit's per-site bounds were maintained by hand in a table in `audit.py`
and `classify.py`.  Hand-reading produced wrong bounds at more than one site:
`$92C8` was recorded as clamped to 0..7 when its `BNE` only substitutes for
zero, and `$B34E` was recorded as bounded by `CMP #$03` when that comparison
only decides whether `STY $0789` runs -- both branches dispatch with `$1D`
unchanged.

So the bound is derived instead.  For each dispatch:

1. take a bounded backward slice of the CFG ending at the `JSR $8E04`;
2. find the slice's entry instructions (where control enters the slice);
3. interpret forward from each entry with **all registers unknown**, forking
   at feasible branches and refining register sets at comparisons;
4. union the accumulator value sets arriving at the dispatch.

Starting from unknown registers makes the result an over-approximation: the
derived index set contains every index that can really occur.  So an index
*outside* the derived set is genuinely impossible, while an index inside it may
still be unreachable for reasons the slice does not capture.

A truncated exploration is reported as truncated and never as a bound, for the
same reason a solver timeout is not a proof.  `assumed_invariants` makes the
difference explicit: the same site is derived twice, once with no assumptions
and once with a candidate RAM invariant supplied, so a conditional bound can
never be mistaken for an unconditional one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from . import valueset as vs
from .cfg import CFG
from .decoder import decode
from .interpret import explore
from .provenance import Bound, BoundProvenance
from .valueset import Memory, State

#: edge kinds along which control can arrive at an instruction
INBOUND = frozenset({"fallthrough", "branch", "jump", "call", "dispatch",
                     "return_point", "interrupt"})

#: instructions that load the accumulator, i.e. candidate index sources
ACC_LOADS = {"LDA", "TXA", "TYA", "PLA"}


@dataclass
class SiteDerivation:
    """What the analysis can say about one dispatch site's index."""

    dispatch: int
    table: int
    entries: int
    index_set: int                      # ByteSet of possible indices
    truncated: bool
    slice_entries: tuple[int, ...]
    sources: tuple[str, ...]
    assumed_invariants: dict[int, str] = field(default_factory=dict)
    #: set when the derivation started from a stated local entry rather than
    #: from backward slices, together with the preconditions assumed there
    local_entry: int | None = None
    preconditions: tuple[str, ...] = ()

    @property
    def indices(self) -> list[int]:
        return vs.values(self.index_set)

    @property
    def maximum(self) -> int | None:
        indices = self.indices
        return max(indices) if indices else None

    @property
    def overruns_table(self) -> bool:
        maximum = self.maximum
        return maximum is not None and maximum >= self.entries

    def bound(self, *, mechanism: str = "") -> Bound:
        """The bound this derivation supports, with honest provenance."""
        if self.truncated:
            return Bound(None, BoundProvenance.UNPROVED,
                         mechanism or "exploration truncated before fixpoint")
        maximum = self.maximum
        if maximum is None:
            return Bound(None, BoundProvenance.UNPROVED,
                         mechanism or "no path to the dispatch was found")
        if self.overruns_table:
            # A "bound" that does not keep the index inside the table is not a
            # bound.  Reporting a maximum of 255 over a 47-entry table as
            # PROVEN would read as "proved safe" when it means the opposite.
            return Bound(None, BoundProvenance.UNPROVED,
                         mechanism or
                         f"derived maximum index {maximum} exceeds the "
                         f"{self.entries}-entry table, so no bound keeping "
                         "the index in range is established")
        if self.assumed_invariants:
            assumptions = tuple(
                f"RAM[${address:04X}] {text}"
                for address, text in sorted(self.assumed_invariants.items()))
            return Bound(maximum, BoundProvenance.STRUCTURAL_CONDITIONAL,
                         mechanism or "derived by value-set analysis under "
                         "the stated RAM invariants",
                         assumptions)
        return Bound(maximum, BoundProvenance.PROVEN,
                     mechanism or "derived by value-set analysis from "
                     "unknown registers, no RAM assumption")

    def to_json(self) -> dict:
        indices = self.indices
        return {
            "dispatch": f"0x{self.dispatch:04X}",
            "table": f"0x{self.table:04X}",
            "table_entries": self.entries,
            "derived_index_count": len(indices),
            "derived_index_min": min(indices) if indices else None,
            "derived_index_max": max(indices) if indices else None,
            "overruns_table": self.overruns_table,
            "truncated": self.truncated,
            "slice_entries": [f"0x{a:04X}" for a in self.slice_entries],
            "index_sources": list(self.sources),
            "assumed_invariants": {f"0x{a:04X}": t for a, t
                                   in sorted(self.assumed_invariants.items())},
            "local_entry": (f"0x{self.local_entry:04X}"
                            if self.local_entry is not None else None),
            "preconditions": list(self.preconditions),
            "bound": self.bound().to_json(),
        }


def backward_slice(graph: CFG, target: int, *, depth: int) -> set[int]:
    """Instructions from which `target` is reachable within `depth` steps."""
    frontier = {target}
    collected = {target}
    for _ in range(depth):
        nxt: set[int] = set()
        for address in frontier:
            node = graph.nodes.get(address)
            if node is None:
                continue
            for source, kind in node.predecessors:
                if kind in INBOUND and source not in collected:
                    nxt.add(source)
        if not nxt:
            break
        collected |= nxt
        frontier = nxt
    return collected


def slice_entries(graph: CFG, sliced: set[int], target: int) -> list[int]:
    """Instructions where control enters the slice from outside it.

    A `JSR $8E04` is never used as an entry (other than the target itself).
    The interpreter models instruction semantics, and the JumpEngine leaves
    through `JMP ($0006)`, so an exploration started on a dispatch stops there
    and reaches nothing.  Control really enters the slice at the dispatch's
    *table target*, so a node reached by a `dispatch` edge counts as an entry
    even though its predecessor is inside the slice.
    """
    entries = []
    for address in sorted(sliced):
        node = graph.nodes.get(address)
        if node is None:
            continue
        if address in graph.dispatches and address != target:
            continue
        inbound = [(source, kind) for source, kind in node.predecessors
                   if kind in INBOUND]
        enters_from_outside = any(source not in sliced
                                  for source, _kind in inbound)
        enters_by_dispatch = any(kind == "dispatch" for _source, kind in inbound)
        if not inbound or enters_from_outside or enters_by_dispatch:
            entries.append(address)
    return entries or [target]


def accumulator_sources(read_byte: Callable[[int], int],
                        sliced: set[int]) -> list[str]:
    """Describe the instructions in the slice that write the accumulator."""
    out = []
    for address in sorted(sliced):
        instruction = decode(read_byte, address)
        if instruction.info.mnemonic in ACC_LOADS:
            out.append(f"${address:04X} {instruction}")
    return out


#: slice depths tried for every site; see `derive_site` for why several
DEPTHS = (6, 10, 16, 24, 40)


@dataclass(frozen=True)
class Assumption:
    """A RAM invariant or register precondition fed to the analysis.

    These are *inputs*, not findings.  Each one is the proposition the old
    hand-written bound silently relied on; stating it here is what turns
    "index <= 3, structural" into "index <= 3 provided RAM[$0772] <= 3, which
    is observed and not proved".
    """

    addresses: tuple[int, ...]
    limit: int
    description: str
    provenance: BoundProvenance = BoundProvenance.OBSERVED
    x_range: tuple[int, ...] | None = None      # register precondition
    #: explicit permitted values; when absent, 0..limit is used
    allowed: tuple[int, ...] | None = None
    extra_assumptions: tuple[str, ...] = ()
    #: Derive from this address instead of searching backward slices.  Used
    #: where the index is formed by a short prologue whose preconditions are
    #: stated rather than derived -- the enemy-ID sites, where the slot index
    #: X is set by the caller's loop.  The resulting claim is explicitly local:
    #: "given control arrives here with these preconditions".
    local_entry: int | None = None

    def permitted(self) -> tuple[int, ...]:
        return (self.allowed if self.allowed is not None
                else tuple(range(self.limit + 1)))

    def memory(self) -> dict[int, int]:
        allowed = vs.from_values(self.permitted())
        return {address: allowed for address in self.addresses}

    def notes(self) -> dict[int, str]:
        permitted = self.permitted()
        shape = (f"<= {self.limit}" if self.allowed is None
                 else f"in a set of {len(permitted)} values")
        return {address: f"{shape} ({self.description}; "
                         f"{self.provenance.value})"
                for address in self.addresses}


#: The invariant each site's bound depends on, one per dispatch.  Sources are
#: read off the disassembly (`index sources` in the derivation output); the
#: limits are the ones the earlier revisions asserted, now recorded as
#: assumptions with their provenance instead of as structural facts.
ENEMY_SLOTS = (0x0016, 0x0017, 0x0018, 0x0019, 0x001A)
ENEMY_SITES = frozenset({0xC27F, 0xC7A8, 0xC88F, 0xC907, 0xC987})

#: The instruction that fetches the identifier for each enemy dispatch.
ENEMY_PROLOGUE = {
    0xC27F: 0xC26C,     # LDA $16,X / CMP #$15 / BCS $C27F / ... / TYA
    0xC7A8: 0xC7A0,     # LDA $16,X / STA $06CB / SEC / SBC #$12
    0xC88F: 0xC884,     # LDA #$00 / LDY $16,X / CPY #$15 / BCC / TYA / SBC #$14
    0xC907: 0xC905,     # LDA $16,X
    0xC987: 0xC982,     # LDA $16,X / SEC / SBC #$24
}
ENEMY_IDS = "enemy identifier domain $00..$36 from the $C27F routing table"

CANDIDATE_INVARIANTS: dict[int, Assumption] = {
    0x8215: Assumption((0x0770,), 3, "OperMode counter"),
    0x8234: Assumption((0x0772,), 3, "OperMode_Task counter"),
    0x83A3: Assumption((0x0772,), 4, "OperMode_Task counter"),
    0x856A: Assumption((0x073C,), 14, "screen-routine counter"),
    0x921B: Assumption((0x0772,), 2, "demo/title task counter"),
    0x92C8: Assumption((0x071F,), 8,
                       "written only by $92B7 (STY #$08) and $92BF (DEC)",
                       BoundProvenance.STRUCTURAL_CONDITIONAL),
    # The old table recorded this site as "GameEngine ($0E), bound 46".  The
    # ROM forms its index at $965F-$9662 as `LDA $00 / CLC / ADC $07`: a sum of
    # two zero-page scratch bytes, neither of which is $0E, and which between
    # them have dozens of writers (including $8E14, inside the JumpEngine).
    # Bounding it needs a *relational* invariant over $00 and $07, so no
    # single-variable assumption is offered and the site stays unproved.
    0x9664: Assumption((), 0,
                       "index is $00 + $07, formed at $965F-$9662; the "
                       "documented $0E source is not the index source",
                       BoundProvenance.UNPROVED),
    # The earlier bound of 4 was consistent with a 5-entry table, but the
    # table at $9746 has 3 entries: its own entry 0 points at $974C, which
    # holds `JSR $9BBB`.  The heuristic reader swallowed that instruction's
    # bytes as entries 3 and 4.  So indices 3 and 4 -- which the earlier
    # revision explicitly permitted -- dispatch outside the table, to $BB20
    # and $BD9B.  $0733's only exact writer ($9CA3) stores 0 on one path and
    # a ROL-computed value on the other, and over-approximate analysis of that
    # value does not bound it below 3, so the bound stays as the earlier
    # revision stated it and the overrun is reported rather than assumed away.
    0x9743: Assumption((0x0733,), 4,
                       "state counter, as asserted by the earlier revision; "
                       "the table holds only 3 entries"),
    0xAEDF: Assumption((0x0772,), 3, "OperMode_Task counter"),
    0xB04C: Assumption((0x000E,), 12, "player state"),
    0xB34E: Assumption((0x001D,), 3, "player state; the CMP #$03 at $B345 "
                       "only selects whether STY $0789 runs"),
    0xBDBD: Assumption((), 0, "none needed", BoundProvenance.PROVEN),
    0xC27F: Assumption(ENEMY_SLOTS, 0x36, ENEMY_IDS,
                       BoundProvenance.DERIVED_CONDITIONAL, tuple(range(5))),
    0xC7A8: Assumption(ENEMY_SLOTS, 0x36, ENEMY_IDS,
                       BoundProvenance.DERIVED_CONDITIONAL, tuple(range(5))),
    0xC88F: Assumption(ENEMY_SLOTS, 0x36, ENEMY_IDS,
                       BoundProvenance.DERIVED_CONDITIONAL, tuple(range(5))),
    0xC907: Assumption(ENEMY_SLOTS, 0x36, ENEMY_IDS,
                       BoundProvenance.DERIVED_CONDITIONAL, tuple(range(5))),
    0xC987: Assumption(ENEMY_SLOTS, 0x36, ENEMY_IDS,
                       BoundProvenance.DERIVED_CONDITIONAL, tuple(range(5))),
    0xD2E5: Assumption((), 0, "none needed", BoundProvenance.PROVEN),
}


def _derive_at_depth(read_byte: Callable[[int], int], graph: CFG,
                     dispatch: int, depth: int, memory: Memory,
                     max_states: int, call_depth: int,
                     initial: State | None = None
                     ) -> tuple[int, bool, tuple[int, ...], set[int]]:
    """One sound over-approximation of the index set, at one slice depth.

    Returns (index set, usable, slice entries, sliced addresses).  `usable` is
    false when the exploration was capped or never reached the dispatch, in
    which case the set is not an over-approximation and must be discarded.
    """
    sliced = backward_slice(graph, dispatch, depth=depth)
    entries = slice_entries(graph, sliced, dispatch)
    confine = frozenset(sliced)
    index_set, reached, capped = 0, False, False
    for entry in entries:
        stops = (frozenset(graph.dispatches) - {entry}) | {dispatch}
        exploration = explore(read_byte, entry, initial or State(), memory,
                              stop_at=stops, max_states=max_states,
                              confine=confine, call_depth=call_depth)
        index_set |= exploration.register_at(dispatch, "A")
        reached = reached or bool(exploration.at(dispatch))
        capped = capped or exploration.capped
    return index_set, (reached and not capped), tuple(entries), sliced


def derive_site(read_byte: Callable[[int], int], graph: CFG, dispatch: int, *,
                depths: tuple[int, ...] = DEPTHS,
                invariants: dict[int, int] | None = None,
                invariant_notes: dict[int, str] | None = None,
                max_states: int = 40000,
                call_depth: int = 5,
                initial: State | None = None) -> SiteDerivation:
    """Derive the index set arriving at one dispatch site.

    Every slice depth yields its own sound over-approximation: slice entries
    start with *unknown* registers, which covers every real state that can
    arrive there, and every path to the dispatch must cross some entry.  Depth
    changes precision, not soundness -- a deeper slice models more context but
    also admits more distant entry points -- so the results are **intersected**
    across depths.  An intersection of over-approximations is still an
    over-approximation, so this tightens the bound without weakening it.

    Depths whose exploration was capped or never reached the dispatch are
    discarded rather than intersected: a truncated search has dropped paths and
    is no longer an over-approximation of anything.
    """
    site = graph.dispatches[dispatch]
    memory = Memory(read_byte, invariants=invariants)

    index_set: int | None = None
    all_entries: tuple[int, ...] = ()
    widest_slice: set[int] = set()
    for depth in depths:
        derived, usable, entries, sliced = _derive_at_depth(
            read_byte, graph, dispatch, depth, memory, max_states, call_depth,
            initial)
        if len(sliced) > len(widest_slice):
            widest_slice, all_entries = sliced, entries
        if not usable:
            continue
        index_set = derived if index_set is None else index_set & derived

    return SiteDerivation(
        dispatch=dispatch,
        table=site.table,
        entries=len(site.entries),
        index_set=index_set or 0,
        truncated=index_set is None,
        slice_entries=all_entries,
        sources=tuple(accumulator_sources(read_byte, widest_slice)),
        assumed_invariants=dict(invariant_notes or {}),
    )


def derive_all(read_byte: Callable[[int], int], graph: CFG, **kwargs
               ) -> dict[int, SiteDerivation]:
    return {dispatch: derive_site(read_byte, graph, dispatch, **kwargs)
            for dispatch in sorted(graph.dispatches)}


def enemy_assumptions(graph: CFG) -> dict[int, Assumption]:
    """Assumptions for the five enemy-ID sites, from the routing derivation.

    The identifier set is the *routed* one for that dispatch, not the whole
    legal domain: `$C7A8` subtracts $12, so assuming only "ID <= $36" leaves
    the subtraction able to wrap and tells us nothing.  What bounds the site is
    the narrower claim that the routing tables send only $12..$19 there.
    """
    from .enemy_routing import derive as derive_routing

    out: dict[int, Assumption] = {}
    for dispatch, route in derive_routing(graph).items():
        out[dispatch] = Assumption(
            addresses=ENEMY_SLOTS,
            limit=max(route.arriving) if route.arriving else 0,
            description=(f"$16,x holds an identifier routed to "
                         f"${dispatch:04X} ({len(route.arriving)} of 55)"),
            provenance=route.provenance,
            x_range=tuple(range(5)),
            allowed=tuple(sorted(route.arriving)),
            extra_assumptions=route.assumptions(),
            local_entry=ENEMY_PROLOGUE[dispatch],
        )
    return out


def derive_local(read_byte: Callable[[int], int], graph: CFG, dispatch: int,
                 assumption: Assumption, *, max_states: int = 200000,
                 call_depth: int = 5) -> SiteDerivation:
    """Derive a site from a stated local entry with stated preconditions.

    Used where the index is formed by a short prologue and the surrounding
    context is an assumption rather than a derivation.  The claim this returns
    is local by construction, and `preconditions` records exactly what was
    assumed, so it cannot be read as a whole-program bound.
    """
    site = graph.dispatches[dispatch]
    entry = assumption.local_entry
    assert entry is not None
    memory = Memory(read_byte, invariants=assumption.memory())
    initial = (State(x=vs.from_values(assumption.x_range))
               if assumption.x_range else State())
    stops = (frozenset(graph.dispatches) - {entry}) | {dispatch}
    exploration = explore(read_byte, entry, initial, memory, stop_at=stops,
                          max_states=max_states, call_depth=call_depth)
    index_set = exploration.register_at(dispatch, "A")
    reached = bool(exploration.at(dispatch))
    preconditions = (
        f"control reaches ${entry:04X}",
        *( (f"X in {{{min(assumption.x_range)}..{max(assumption.x_range)}}} "
            "at the load (the enemy slot index set by the caller's loop)",)
           if assumption.x_range else ()),
        *assumption.extra_assumptions,
    )
    return SiteDerivation(
        dispatch=dispatch,
        table=site.table,
        entries=len(site.entries),
        index_set=index_set,
        truncated=exploration.capped or not reached,
        slice_entries=(entry,),
        sources=tuple(accumulator_sources(read_byte, {entry})),
        assumed_invariants=dict(assumption.notes()),
        local_entry=entry,
        preconditions=preconditions,
    )


def derive_conditional(read_byte: Callable[[int], int], graph: CFG,
                       dispatch: int, assumption: Assumption | None = None,
                       **kwargs) -> SiteDerivation:
    """Derive one site under its candidate invariant, recording it as such."""
    if assumption is None and dispatch in ENEMY_SITES:
        assumption = enemy_assumptions(graph).get(dispatch)
    assumption = assumption or CANDIDATE_INVARIANTS.get(dispatch)
    if assumption is None or not assumption.addresses:
        return derive_site(read_byte, graph, dispatch, **kwargs)
    if assumption.local_entry is not None:
        return derive_local(read_byte, graph, dispatch, assumption)
    initial = (State(x=vs.from_values(assumption.x_range))
               if assumption.x_range else None)
    return derive_site(read_byte, graph, dispatch,
                       invariants=assumption.memory(),
                       invariant_notes=assumption.notes(),
                       initial=initial, **kwargs)


def main() -> None:  # pragma: no cover - CLI
    import json

    from rom import b, image

    from .cfg import build_from_vectors

    graph = build_from_vectors(b)
    rows = []
    print(f"ROM sha1 {image().sha1}")
    print("\nIndex sets derived from the ROM by value-set analysis.")
    print("'unconditional' assumes nothing about RAM; 'conditional' assumes "
          "the invariant named in the last column.\n")
    header = ("site    N  unconditional      conditional   in range  "
              "assumption (provenance)")
    print(header)
    print("-" * len(header))

    for dispatch in sorted(graph.dispatches):
        plain = derive_site(b, graph, dispatch)
        assumption = (enemy_assumptions(graph).get(dispatch)
                      if dispatch in ENEMY_SITES
                      else CANDIDATE_INVARIANTS.get(dispatch))
        conditional = derive_conditional(b, graph, dispatch, assumption)
        bound = conditional.bound()

        def describe(derivation: SiteDerivation) -> str:
            if derivation.truncated:
                return "truncated"
            indices = derivation.indices
            if not indices:
                return "none"
            return f"{min(indices)}..{max(indices)} ({len(indices)})"

        in_range = not conditional.overruns_table and not conditional.truncated
        note = ("none required [proven]" if assumption is None
                else f"{assumption.description} "
                     f"[{assumption.provenance.value}]")
        rows.append((dispatch, plain, conditional, assumption))
        print(f"${dispatch:04X} {conditional.entries:3}  "
              f"{describe(plain):18} {describe(conditional):13} "
              f"{'yes' if in_range else 'NO':>8}  {note}")

    unconditional_safe = [d for _, p_, d, a in rows
                          if not d.overruns_table and not d.truncated
                          and not (a and a.addresses)]
    conditional_safe = [d for _, p_, d, a in rows
                        if not d.overruns_table and not d.truncated
                        and (a and a.addresses)]
    still_overrun = [d for _, p_, d, _a in rows if d.overruns_table]

    print(f"\nbounded with no RAM assumption : {len(unconditional_safe)} "
          + ", ".join(f"${d.dispatch:04X}" for d in unconditional_safe))
    print(f"bounded only under an invariant: {len(conditional_safe)} "
          + ", ".join(f"${d.dispatch:04X}" for d in conditional_safe))
    if still_overrun:
        print(f"overrun even under the invariant: {len(still_overrun)} "
              + ", ".join(f"${d.dispatch:04X}" for d in still_overrun))

    report = {
        "rom_sha1": image().sha1,
        "method": ("value-set abstract interpretation over backward CFG "
                   "slices, intersected across slice depths"),
        "sites": [
            {
                "unconditional": plain.to_json(),
                "conditional": conditional.to_json(),
                "assumption": (
                    {
                        "addresses": [f"0x{a:04X}" for a in assumption.addresses],
                        "limit": assumption.limit,
                        "description": assumption.description,
                        "provenance": assumption.provenance.value,
                        "x_range": list(assumption.x_range or ()),
                    } if assumption else None),
            }
            for _dispatch, plain, conditional, assumption in rows
        ],
    }
    with open("results/dispatch_bounds.json", "w") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
    print("\nwrote results/dispatch_bounds.json")


if __name__ == "__main__":  # pragma: no cover
    main()
