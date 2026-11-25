"""Review item 8: exploitability classification for every control-flow anomaly.

One record per (dispatch site, index) pair whose resolved destination is not
PRG ROM, with the fields the review asks for, plus an explicit provenance label
on the bound that excludes it. Provenance matters more than the verdict: a
bound that is *derived* from the ROM is a different kind of claim from one
inferred from observed play.

Bound provenance
  structural   enforced by an instruction at the dispatch (CMP/BCS, masking)
  derived      computed from the routing tables (see reach.py)
  observed     consistent with every state reached by the experiments, but not
               proved for unreached states
  unproved     no bound established

Exploitability
  excluded             the bound keeps the index in range
  not_ace              reachable in principle but the destination holds no
                       controllable executable bytes (PPU/APU, open bus)
  unknown              not excluded and the destination is controllable RAM
  demonstrated         a reproducing input sequence exists

    python3 classify.py            print the table
    python3 classify.py --json     write exploitability_classification.json
"""
from __future__ import annotations

import json
import os
import sys

from jumpengine import resolve_table
from memory import is_internal_ram, memory_region, normalize_internal_ram
from rom import b, image
from reach import c88f_index, derive, load_tables

# site -> (index source, bound, provenance, trigger, controllability)
#
# The enemy-ID sites are filled in from reach.py at run time so this table can
# never drift from the derivation. The rest are game-state counters whose
# bounds are observed, not proved -- that is condition C1.
STATE_SITES = {
    0x8215: ("$0770 OperMode", 3, "observed", "operation mode switch",
             "indirect: input advances game mode"),
    0x8234: ("$0772 OperMode_Task", 3, "observed", "screen routine step",
             "indirect: input advances the task"),
    0x83A3: ("$0772", 4, "observed", "screen routine step",
             "indirect: input advances the task"),
    0x856A: ("$073C screen task", 14, "observed", "screen draw step",
             "indirect"),
    0x921B: ("$0772", 2, "observed", "demo / title task",
             "indirect"),
    0x92C8: ("$071F forced 1..8", 7, "structural",
             "LDY $071F / BNE / LDY #$08 / DEY forces 0..7", "none"),
    0x9664: ("GameEngine ($0E)", 46, "observed", "game engine state",
             "indirect: player state"),
    0x9743: ("$0733", 4, "observed", "state counter", "indirect"),
    0xAEDF: ("$0772", 3, "observed", "task counter", "indirect"),
    0xB04C: ("$0E", 12, "observed", "player state", "indirect: player state"),
    0xB34E: ("$1D (CMP #$03)", 3, "structural", "CMP #$03 before dispatch",
             "indirect: player state"),
    0xBDBD: ("$05 via $BDF6", 8, "structural", "CMP #$09 / BCC",
             "indirect: block contents"),
    0xD2E5: ("$0746 (CMP #$05 / BCS)", 4, "structural", "CMP #$05 / BCS clamp",
             "indirect"),
}

ENEMY_TRIGGER = "an enemy slot holds this identifier when the dispatch runs"
ENEMY_CONTROL = ("indirect: identifiers come from level data in ROM and "
                 "hard-coded spawners; no path writes an arbitrary byte to $16,x")


def build():
    JT = load_tables()
    derived = derive(JT)
    enemy_bounds = {}
    for pc, (role, f, ids) in derived.items():
        idxs = {f(i) for i in ids}
        enemy_bounds[pc] = (f"$16,x -> {role}", max(idxs) if idxs else None,
                            "derived", ENEMY_TRIGGER, ENEMY_CONTROL, ids, f)

    records = []
    for pc, (tbl, n) in sorted(JT.items()):
        if pc in enemy_bounds:
            src, bound, prov, trigger, control, ids, f = enemy_bounds[pc]
        else:
            src, bound, prov, trigger, control = STATE_SITES[pc]
            ids, f = None, None

        for i in range(256):
            r = resolve_table(b, tbl, i)
            region = memory_region(r.target)
            if region == "prg_rom":
                continue                      # in-ROM destinations are not anomalies

            in_bounds = i < n
            excluded_by_bound = bound is not None and i > bound
            ace_capable = is_internal_ram(r.target)

            if in_bounds:
                # should not happen; kept so a regression is visible
                exploitability, reach = "unknown", "in_bounds_non_rom"
            elif excluded_by_bound:
                exploitability = "excluded"
                reach = f"excluded: max index {bound} ({prov})"
            elif not ace_capable:
                exploitability = "not_ace"
                reach = "reachable index, destination not executable"
            else:
                exploitability = "unknown"
                reach = "not excluded by any established bound"

            rec = {
                "entry_point": f"0x{pc:04X}",
                "trigger": trigger,
                "index": i,
                "index_source": src,
                "bound": bound,
                "bound_provenance": prov,
                "destination": f"0x{r.target:04X}",
                "memory_region": region,
                "physical_ram": (f"0x{normalize_internal_ram(r.target):04X}"
                                 if ace_capable else None),
                "controllability": control,
                "reachability": reach,
                "reproducibility": None,
                "exploitability": exploitability,
                "evidence": "static exact-6502 model; bounds from reach.py",
            }
            # the enemy sites know exactly which identifier maps to this index
            if ids is not None and f is not None:
                src_ids = [x for x in ids if f(x) == i]
                rec["enemy_ids_mapping_here"] = [f"0x{x:02X}" for x in src_ids]
            records.append(rec)
    return records


def summarise(records):
    by = {}
    for r in records:
        by.setdefault(r["exploitability"], []).append(r)
    return by


def main():
    records = build()
    by = summarise(records)

    print(f"ROM sha1 {image().sha1}")
    print(f"non-ROM destinations classified: {len(records)}\n")
    for k in ("demonstrated", "unknown", "not_ace", "excluded"):
        if k in by:
            print(f"  {k:14}: {len(by[k])}")

    print("\nAnything NOT excluded by a bound (the live attack surface):")
    live = [r for r in records if r["exploitability"] in ("unknown", "not_ace", "demonstrated")]
    if not live:
        print("  none")
    for r in live:
        ids = r.get("enemy_ids_mapping_here")
        tag = f"  enemy IDs {','.join(ids)}" if ids else ""
        print(f"  {r['entry_point']} idx {r['index']:3} -> {r['destination']} "
              f"[{r['memory_region']}]  {r['exploitability']}{tag}")
        print(f"      {r['reachability']}")

    print("\nBound provenance across the 18 dispatch sites:")
    prov = {}
    for r in records:
        prov.setdefault(r["bound_provenance"], set()).add(r["entry_point"])
    for k in sorted(prov):
        print(f"  {k:10}: {len(prov[k])} sites  {sorted(prov[k])}")

    if "--json" in sys.argv:
        out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "exploitability_classification.json")
        with open(out, "w") as fh:
            json.dump({"rom_sha1": image().sha1,
                       "model": "exact_6502_jumpengine",
                       "records": records}, fh, indent=2, sort_keys=True)
        print(f"\nwrote {out} ({len(records)} records)")


if __name__ == "__main__":
    main()
