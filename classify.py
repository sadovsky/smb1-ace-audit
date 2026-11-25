"""Exploitability classification with separated provenance (plan section 4).

What changed and why
--------------------

The earlier version of this script collapsed three independent questions into
one verdict.  Its test was

    excluded_by_bound = bound is not None and i > bound

applied regardless of where the bound came from, so a bound that was merely
*consistent with observed play* produced the same "excluded" verdict as one
enforced by an instruction.  With nine of the eighteen sites carrying observed
bounds, the headline "2,181 excluded, 0 unknown" claimed far more than the
evidence supports.

This version keeps three dimensions apart (`analysis.provenance`):

  BoundProvenance   how well the index bound is established
  Reachability      whether this (site, index) pair can occur
  ExecutionOutcome  what executing at the destination would mean

and enforces one rule: **only a PROVEN bound excludes an index
unconditionally**.  Everything weaker yields a conditional exclusion that
carries its assumptions, or -- for an observed bound -- `not_observed`, which
is a statement about coverage, not about possibility.

Bounds are no longer written by hand.  They come from
`analysis.index_derivation`, which derives each site's index set from the ROM,
and table sizes come from `analysis.dispatch_tables`, which establishes each
boundary from independent evidence instead of one heuristic.

    python3 classify.py            print the table
    python3 classify.py --json     write exploitability_classification.json
"""
from __future__ import annotations

import json
import os
import sys
from collections import Counter

from analysis.cfg import build_from_vectors
from analysis.destinations import RAM_REGIONS, classify_outcome, resolve_all
from analysis.index_derivation import (
    CANDIDATE_INVARIANTS,
    ENEMY_SITES,
    derive_conditional,
    derive_site,
    enemy_assumptions,
)
from analysis.provenance import BoundProvenance, ExecutionOutcome, Reachability
from memory import normalize_internal_ram
from rom import b, image


def build():
    """One record per (site, raw index) whose destination is not expected ROM."""
    graph = build_from_vectors(b)
    resolutions = resolve_all(b, graph)
    enemy = enemy_assumptions(graph)

    derivations = {}
    for dispatch in sorted(graph.dispatches):
        assumption = (enemy.get(dispatch) if dispatch in ENEMY_SITES
                      else CANDIDATE_INVARIANTS.get(dispatch))
        derivations[dispatch] = (
            derive_site(b, graph, dispatch),
            derive_conditional(b, graph, dispatch, assumption),
            assumption,
        )

    records = []
    for resolution in resolutions:
        if resolution.outcome is ExecutionOutcome.EXPECTED_ROM:
            continue
        unconditional, conditional, assumption = derivations[resolution.dispatch]
        bound = conditional.bound()
        index = resolution.raw_index

        # Reachability is decided against the derived index *sets*, not a
        # scalar bound: at $C88F only index 34 escapes a 34-entry table, and a
        # scalar maximum cannot express that.
        derivable = not unconditional.truncated
        in_unconditional = index in set(unconditional.indices)
        conditional_known = not conditional.truncated
        in_conditional = conditional_known and index in set(conditional.indices)

        if derivable and not in_unconditional:
            reach = Reachability.PROVEN_UNREACHABLE
            why = ("the index set derived while assuming nothing about RAM "
                   "does not contain this index")
        elif conditional_known and not in_conditional:
            observed = (assumption is not None
                        and assumption.provenance is BoundProvenance.OBSERVED)
            if observed:
                reach = Reachability.NOT_OBSERVED
                why = ("outside the index set derived under an *observed* "
                       "invariant; unreached states are not covered: "
                       + "; ".join(bound.assumptions or
                                   (assumption.description,)))
            else:
                reach = Reachability.CONDITIONALLY_UNREACHABLE
                why = ("outside the index set derived under the stated "
                       "invariant; assumes: "
                       + "; ".join(bound.assumptions or
                                   ((assumption.description,) if assumption
                                    else ("no assumption recorded",))))
        elif in_conditional:
            reach = Reachability.NOT_OBSERVED
            why = ("inside the index set derived under the stated invariant, "
                   "so the invariant does not exclude it; no input sequence "
                   "demonstrating it is recorded")
        else:
            reach = Reachability.UNKNOWN
            why = "no bound established for this site"

        ace_capable = resolution.region in RAM_REGIONS
        if reach is Reachability.PROVEN_UNREACHABLE:
            exploitability = "excluded"
        elif reach is Reachability.CONDITIONALLY_UNREACHABLE:
            exploitability = "excluded_conditionally"
        elif not ace_capable:
            exploitability = "not_ace"
        else:
            exploitability = "unknown"

        records.append({
            "entry_point": f"0x{resolution.dispatch:04X}",
            "index": index,
            "effective_index": resolution.effective,
            "index_source": (assumption.description if assumption
                             else "no assumption recorded"),
            "bound": bound.maximum,
            "bound_provenance": bound.provenance.value,
            "bound_unconditional": bound.is_unconditional,
            "bound_assumptions": list(bound.assumptions),
            "table_entries": conditional.entries,
            "destination": f"0x{resolution.destination:04X}",
            "memory_region": resolution.region,
            "physical_ram": (f"0x{normalize_internal_ram(resolution.destination):04X}"
                             if ace_capable else None),
            "execution_outcome": resolution.outcome.value,
            "rom_role": resolution.rom_role,
            "reachability": reach.value,
            "reachability_detail": why,
            "reproducibility": None,
            "exploitability": exploitability,
            "evidence": ("value-set derivation over established table "
                         "boundaries; exact JumpEngine address formation"),
        })
    return records, derivations


def main():
    records, derivations = build()
    by = Counter(r["exploitability"] for r in records)

    print(f"ROM sha1 {image().sha1}")
    print(f"non-expected destinations classified: {len(records)}\n")
    for key in ("demonstrated", "unknown", "not_ace", "excluded_conditionally",
                "excluded"):
        if by[key]:
            print(f"  {key:24}: {by[key]}")

    print("\nHow the exclusions are supported:")
    unconditional = [r for r in records if r["exploitability"] == "excluded"]
    conditional = [r for r in records
                   if r["exploitability"] == "excluded_conditionally"]
    print(f"  unconditional: {len(unconditional):5}  the index is outside the "
          "set derived while assuming nothing about RAM")
    print(f"  conditional  : {len(conditional):5}  excluded only under an "
          "assumption, by the provenance of that assumption:")
    for key, count in Counter(r["bound_provenance"]
                              for r in conditional).most_common():
        print(f"      {key:24}: {count}")
    print(f"\n  {len(conditional)} of the {len(unconditional) + len(conditional)} "
          "exclusions rest on an assumption that is not proved here, and "
          f"{by['unknown']} destinations in")
    print("  controllable RAM are not excluded at all.  The earlier revision "
          "reported 2,181")
    print("  unconditional exclusions and no unknowns, having skipped every "
          "ROM destination")
    print("  and treated observed bounds as proofs.")

    print("\nDestinations in controllable RAM that no proven bound excludes:")
    live = [r for r in records
            if r["exploitability"] in ("unknown", "demonstrated")]
    if not live:
        print("  none")
    for record in sorted(live, key=lambda r: (r["entry_point"], r["index"]))[:14]:
        print(f"  {record['entry_point']} idx {record['index']:3} -> "
              f"{record['destination']} [{record['memory_region']}] "
              f"{record['reachability']}")
    if len(live) > 14:
        print(f"  ... {len(live) - 14} more (see the JSON report)")

    print("\nPer-site bound provenance, derived not asserted:")
    print("site   entries  derived max  under invariant  in range  provenance")
    print("-" * 74)
    for dispatch in sorted(derivations):
        unconditional, conditional, _assumption = derivations[dispatch]
        bound = conditional.bound()
        in_range = not conditional.overruns_table and not conditional.truncated
        print(f"${dispatch:04X} {conditional.entries:8} "
              f"{str(unconditional.maximum):>12} "
              f"{str(conditional.maximum):>16} "
              f"{'yes' if in_range else 'NO':>9}  {bound.provenance.value}"
              f"{'' if bound.is_unconditional else ' (conditional)'}")

    if "--json" in sys.argv:
        out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "exploitability_classification.json")
        with open(out, "w") as handle:
            json.dump({"rom_sha1": image().sha1,
                       "model": ("value-set derivation, established table "
                                 "boundaries, exact JumpEngine semantics"),
                       "records": records}, handle, indent=2, sort_keys=True)
        print(f"\nwrote {out} ({len(records)} records)")


if __name__ == "__main__":
    main()
