"""ACE audit over the computed transfers in SMB1.

This script used to carry a hand-written table of per-site index bounds, with
a note for each explaining why the index was in range.  Three of those notes
were wrong about the ROM:

  $92C8  "forced 1..8 -> 0..7, structural"  -- the BNE only substitutes for
         zero; nothing clamps the upper end, so the index is bounded only by
         an invariant on RAM[$071F].
  $B34E  "CMP #$03, checked"                -- that comparison only decides
         whether STY $0789 runs; both paths dispatch with A = $1D unchanged.
  $9664  "GameEngine ($0E), bound 46"       -- the index is $00 + $07, formed
         at $965F-$9662.  $0E is not the index source.

and one was right for the wrong reason ($BDBD is bounded by $BDF6 returning
Y <= 13, not by its CMP #$09).  So the table is gone: bounds come from
`analysis.index_derivation`, table sizes from `analysis.dispatch_tables`, and
destinations from `analysis.destinations`.

Run `python3 trace.py` first only if you also want the legacy trace.json;
this script builds its own CFG.
"""
from __future__ import annotations

import json

from analysis.cfg import build_from_vectors
from analysis.destinations import RAM_REGIONS, resolve_all
from analysis.dispatch_tables import establish
from analysis.index_derivation import (
    CANDIDATE_INVARIANTS,
    ENEMY_SITES,
    derive_conditional,
    derive_site,
    enemy_assumptions,
)
from analysis.interrupts import masking_report, vectors
from analysis.provenance import ExecutionOutcome
from memory import memory_region
from rom import b, image


def main():
    graph = build_from_vectors(b)
    boundaries = establish(b, graph)
    resolutions = resolve_all(b, graph)
    enemy = enemy_assumptions(graph)

    print(f"ROM sha1 {image().sha1}")
    print(f"instruction starts reached: {len(graph.nodes)} "
          f"({len(graph.occupied_bytes())} bytes, "
          f"{len(graph.occupied_bytes()) * 100 // 0x8000}% of PRG)")
    print(f"overlapping instruction decodings preserved: "
          f"{len(graph.overlapping_starts())}")

    indirect = [u for u in graph.unresolved if u[1] == "indirect_jump"]
    returns = [u for u in graph.unresolved if u[1] in ("rts", "rti")]
    print(f"\ncomputed transfers:")
    print(f"  direct indirect jumps : {len(indirect)}  "
          + ", ".join(f"${a:04X}" for a, _k, _d in indirect))
    print(f"  stack-derived returns : {len(returns)}  (each RTS/RTI takes its "
          "destination from memory)")
    print("  the 'exactly one computed jump' claim counts only the first "
          "kind.")

    print(f"\ndispatch sites: {len(graph.dispatches)}")
    print("\nsite   table  entries  idx(no assumption)  idx(under invariant)  "
          "in range  provenance")
    print("-" * 94)

    overruns = []
    for dispatch in sorted(graph.dispatches):
        site = graph.dispatches[dispatch]
        assumption = (enemy.get(dispatch) if dispatch in ENEMY_SITES
                      else CANDIDATE_INVARIANTS.get(dispatch))
        plain = derive_site(b, graph, dispatch)
        conditional = derive_conditional(b, graph, dispatch, assumption)
        bound = conditional.bound()
        in_range = not conditional.overruns_table and not conditional.truncated
        if not in_range:
            overruns.append((dispatch, conditional))
        print(f"${dispatch:04X} ${site.table:04X} {conditional.entries:8} "
              f"{str(plain.maximum):>19} {str(conditional.maximum):>21} "
              f"{'yes' if in_range else 'NO':>9}  {bound.provenance.value}")

    print("\n--- table boundaries where the old heuristic was wrong ---")
    wrong = [row for row in boundaries.values() if row.heuristic_was_wrong]
    if not wrong:
        print("none")
    for row in wrong:
        print(f"  ${row.dispatch:04X} (${row.table:04X}): heuristic read "
              f"{row.heuristic} entries, independent evidence gives "
              f"{row.entries}")

    print("\n--- sites whose index is not kept inside the table ---")
    if not overruns:
        print("none")
    for dispatch, conditional in overruns:
        site = graph.dispatches[dispatch]
        escaping = [i for i in conditional.indices if i >= conditional.entries]
        print(f"  ${dispatch:04X}: {len(escaping)} index/indices past the "
              f"{conditional.entries}-entry table "
              f"(max {max(escaping) if escaping else '-'})")
        shown = 0
        for index in escaping:
            match = [r for r in resolutions
                     if r.dispatch == dispatch and r.raw_index == index]
            if not match:
                continue
            resolution = match[0]
            if resolution.outcome is ExecutionOutcome.INTERNAL_RAM or shown < 3:
                print(f"      index {index:3} -> ${resolution.destination:04X} "
                      f"[{resolution.region}] {resolution.rom_role}")
                shown += 1
            if shown >= 6:
                break

    ram = [r for r in resolutions if r.region in RAM_REGIONS]
    print(f"\n--- destinations in controllable RAM, over all 18x256 "
          f"resolutions: {len(ram)} ---")
    print("These are the only resolutions that could execute player-influenced "
          "bytes.")
    print("Whether any is reachable is the open question; see classify.py.")

    print("\n--- interrupt entry ---")
    for report in vectors(b, graph):
        print(f"  {report.name:5} vector -> ${report.target:04X} "
              f"[{report.region}] decodes as {report.decoded}")
    masking = masking_report(b, graph)
    print(f"  {masking['conclusion']}")

    report = {
        "rom_sha1": image().sha1,
        "model": "value-set derivation over established table boundaries",
        "instruction_starts": len(graph.nodes),
        "occupied_bytes": len(graph.occupied_bytes()),
        "overlapping_decodings": len(graph.overlapping_starts()),
        "indirect_jumps": [f"0x{a:04X}" for a, _k, _d in indirect],
        "stack_derived_returns": len(returns),
        "sites_overrunning_their_table": [f"0x{d:04X}" for d, _c in overruns],
        "ram_destinations": len(ram),
    }
    with open("results/audit_summary.json", "w") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
    print("\nwrote results/audit_summary.json")


if __name__ == "__main__":
    main()
