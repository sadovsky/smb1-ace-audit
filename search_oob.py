"""Review item 7: targeted search for an out-of-bounds dispatch index.

classify.py leaves nine dispatch sites whose bound is only *observed* -- game
state counters that no static argument pins down. Those are condition C1, and
they are what this search attacks.

Watching each dispatch address directly is what makes it measurable: the
instruction there is `JSR $8E04` and the accumulator at that moment *is* the
index, so a trace event at site `pc` with accumulator `a` is one
(site, index) observation. The search maximises, per site, how close the index
gets to that site's table length, and reports immediately if one reaches it.

The search is evolutionary over controller-input programs. A program is a list
of (button mask, duration) segments; mutation perturbs masks, durations and
segment boundaries. Fitness rewards, in order:

  1. any index at or past a table length        (the goal; reported at once)
  2. the smallest remaining margin to any table length (index - (N-1))
  3. the number of distinct (site, index) pairs seen (coverage)

Controller-only: no RAM writes, no cheats, unmodified ROM.

    python3 search_oob.py [generations] [population]
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import random
import sys

sys.path.insert(0, os.environ.get("CHEAT_ENV_DIR", "../rommage/genie_search"))
with contextlib.redirect_stderr(io.StringIO()):
    from trace_env import TraceNESEnv

from rom import ROM, image
from reach import load_tables

A, B, SELECT, START, UP, DOWN, LEFT, RIGHT = 1, 2, 4, 8, 16, 32, 64, 128
BOOT = [(0, 40), (START, 10), (0, 40)]
BUTTONS = [A, B, UP, DOWN, LEFT, RIGHT, A | B, RIGHT | A, RIGHT | B,
           RIGHT | A | B, LEFT | A, 0, START, SELECT]

JT = load_tables()                      # {dispatch pc: (table addr, N)}
SITES = sorted(JT)
LIMIT = {pc: JT[pc][1] for pc in SITES}  # index must stay < N


def random_program(rng, segments=26):
    return [(rng.choice(BUTTONS), rng.randint(2, 40)) for _ in range(segments)]


def mutate(rng, prog):
    p = [list(s) for s in prog]
    for _ in range(rng.randint(1, 4)):
        op = rng.random()
        i = rng.randrange(len(p))
        if op < 0.45:
            p[i][0] = rng.choice(BUTTONS)
        elif op < 0.80:
            p[i][1] = max(1, p[i][1] + rng.choice((-12, -5, -2, 2, 5, 12)))
        elif op < 0.90 and len(p) > 6:
            p.pop(i)
        else:
            p.insert(i, [rng.choice(BUTTONS), rng.randint(2, 40)])
    return [tuple(s) for s in p]


def evaluate(prog, cap=300_000):
    """Run one program; return (pairs, best_ratio, overflow_list)."""
    env = TraceNESEnv(ROM)
    env.reset()
    env.set_trace_capacity(cap)
    env.watch(SITES)              # A at a dispatch site is the index
    env.record_non_rom(True)      # free derailment check while we are here
    for act, n in BOOT:
        for _ in range(n):
            env.step(act)
    for mask, dur in prog:
        for _ in range(dur):
            env.step(mask)

    pairs, overflow, derail = set(), [], []
    best_ratio = -99
    for e in env.trace_events():
        if e.non_rom:
            derail.append(e.as_dict())
            continue
        n = LIMIT.get(e.pc)
        if n is None:
            continue
        pairs.add((e.pc, e.a))
        # margin = how far past the last valid index (N-1) we got;
        # 0 means we reached the last valid entry, >0 is an overflow
        best_ratio = max(best_ratio, e.a - (n - 1))
        if e.a >= n:
            overflow.append({"site": f"0x{e.pc:04X}", "index": e.a, "table_entries": n})
    env.close()
    return pairs, best_ratio, overflow, derail


def main():
    generations = int(sys.argv[1]) if len(sys.argv) > 1 else 12
    population = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    rng = random.Random(20261125)

    pool = [random_program(rng) for _ in range(population)]
    seen_pairs, best = set(), (-99, 0, None)
    all_overflow, all_derail = [], []

    for gen in range(generations):
        scored = []
        for prog in pool:
            pairs, ratio, overflow, derail = evaluate(prog)
            all_overflow += overflow
            all_derail += derail
            new = len(pairs - seen_pairs)
            seen_pairs |= pairs
            scored.append((ratio, new, prog))
            if ratio > best[0]:
                best = (ratio, len(pairs), prog)
        scored.sort(key=lambda t: (t[0], t[1]), reverse=True)
        margin = scored[0][0]
        print(f"  gen {gen:2}: best margin {margin:+d} past a table's last valid "
              f"index | distinct (site,index) pairs so far {len(seen_pairs)}")
        if all_overflow:
            break
        keep = [p for _r, _n, p in scored[:max(2, population // 3)]]
        pool = keep + [mutate(rng, rng.choice(keep)) for _ in range(population - len(keep))]

    result = {
        "experiment_id": "targeted-oob-search",
        "rom_sha1": image().sha1,
        "experiment_type": "controller_only",
        "generations_run": gen + 1,
        "population": population,
        "distinct_site_index_pairs": len(seen_pairs),
        "best_margin_past_last_valid_index": best[0],
        "note": "margin 0 means the last valid index was reached; >0 is an overflow",
        "out_of_bounds_dispatches": all_overflow,
        "instructions_outside_prg_rom": len(all_derail),
        "result": ("OUT_OF_BOUNDS_FOUND" if all_overflow else "no_out_of_bounds_index_found"),
    }
    print("\n" + json.dumps(result, indent=2))

    print("\nper-site maximum index observed vs table length:")
    per = {}
    for pc, a in seen_pairs:
        per[pc] = max(per.get(pc, -1), a)
    for pc in SITES:
        n = LIMIT[pc]
        mx = per.get(pc)
        if mx is None:
            print(f"  ${pc:04X}: never reached in this search      (N={n})")
        else:
            print(f"  ${pc:04X}: max index {mx:3} of N={n:3}"
                  f"  {'<-- AT OR PAST LIMIT' if mx >= n else ''}")


if __name__ == "__main__":
    main()
