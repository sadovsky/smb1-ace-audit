"""Frame-sampled observation of the dispatch index variables (plan 15).

This is an *observation*, and the plan is explicit that an observation can
never produce an unconditional exclusion.  Two limits apply to everything here
and are recorded in the manifest rather than left to the reader:

1. **Frame sampling is not instruction-level.**  RAM is read once per frame, so
   a value that exists only between two instructions is invisible.  `$0733` is
   written at `$9CA3` and read at `$9740`; if it is non-zero only briefly
   within a frame, sampling will not see it.  So "never observed above 2" does
   not mean "cannot exceed 2" -- it means the sampler did not see it.  A
   site-specific bound needs the instruction-level census
   (`native_dispatch.py`, which requires the tracer-patched emulator).
2. **The index at `$9664` cannot be sampled at all.**  It is `$00 + $07`, two
   scratch bytes rewritten many times per frame, so their values at the moment
   of the dispatch are not recoverable from a frame sample.  The sum is
   reported for completeness and must not be read as that site's index.

What this *can* do is look for a positive result: a sampled value above the
table bound would be direct evidence of an out-of-range dispatch.  The run is
therefore aimed at the two sites this revision found to be unbounded by their
asserted invariants, `$0733` (whose table holds 3 entries, not the 5 the
heuristic read) and `$071F` (whose dispatch has no upper clamp).

    python3 experiments/observe_indices.py [--frames N] [--seed S]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

#: NES controller bits as nes-py encodes them
RIGHT, LEFT, DOWN, UP, START, SELECT, B, A = (
    0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01)

#: address -> (label, how the index is formed, {dispatch site: table entries})
#:
#: A variable can feed several dispatches with *different* table sizes, which
#: is why a single "maximum index" per variable means nothing.  `$0772` indexes
#: four sites whose tables hold 3, 4, 4 and 5 entries, so the value 3 is in
#: range at three of them and out of range at the fourth.  Deciding which site
#: was running when a value appeared needs instruction-level evidence; frame
#: sampling cannot do it, and reporting the value against the tightest table
#: would manufacture a finding.
WATCHED = {
    0x071F: ("$071F", "zero substituted by 8, then DEY", {0x92C8: 8}),
    0x0733: ("$0733", "raw", {0x9743: 3}),
    0x0770: ("$0770", "raw", {0x8215: 4}),
    0x0772: ("$0772", "raw", {0x921B: 3, 0x8234: 4, 0xAEDF: 4, 0x83A3: 5}),
    0x000E: ("$000E", "raw", {0xB04C: 13}),
    0x001D: ("$001D", "raw; the CMP #$03 does not clamp", {0xB34E: 4}),
    0x073C: ("$073C", "raw", {0x856A: 15}),
    0x0746: ("$0746", "clamped at the dispatch by CMP #$05/BCS", {0xD2E5: 5}),
}

ENEMY_SLOTS = (0x0016, 0x0017, 0x0018, 0x0019, 0x001A)
MAX_LEGAL_ID = 0x36


def index_for(address: int, value: int) -> int:
    """The index the dispatch would use for this variable value."""
    if address == 0x071F:
        return ((value or 8) - 1) & 0xFF
    return value


def input_sequence(rng: random.Random, frame: int) -> int:
    """A mix of menu-advancing, structured play and random input."""
    if frame < 120:
        return START if frame % 16 < 2 else 0
    mode = (frame // 600) % 4
    if mode == 0:                      # run right, jump often
        action = RIGHT | B
        if frame % 24 < 6:
            action |= A
        return action
    if mode in (1, 3):                 # structured but erratic
        action = rng.choice([RIGHT, RIGHT | B, LEFT, DOWN, UP, RIGHT | A])
        if frame % 7 == 0:
            action |= A
        return action
    return rng.getrandbits(8)          # fully random, including impossible pairs


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--frames", type=int, default=60000)
    parser.add_argument("--seed", type=int, default=20261125)
    parser.add_argument("--out", default="results/observed_indices.json")
    args = parser.parse_args()

    try:
        from nes_py import NESEnv
    except ImportError:
        print("nes-py is not importable; set PYTHONPATH to the emulator "
              "checkout (see README)", file=sys.stderr)
        return 2

    from rom import image

    rom = image()
    rng = random.Random(args.seed)
    env = NESEnv(rom.path)
    env.reset()

    seen: dict[int, set[int]] = {address: set() for address in WATCHED}
    enemy_seen: set[int] = set()
    out_of_range: list[dict] = []
    initial_state_hash = hashlib.sha1(bytes(env.ram)).hexdigest()
    started = time.time()
    frames = 0
    dropped = 0

    try:
        for frame in range(args.frames):
            action = input_sequence(rng, frame)
            try:
                env.step(action)
            except Exception as exc:          # emulator refused this step
                dropped += 1
                print(f"frame {frame}: step failed ({exc}); continuing",
                      file=sys.stderr)
                continue
            frames += 1
            ram = env.ram
            for address, (label, _how, sites) in WATCHED.items():
                value = int(ram[address])
                if value in seen[address]:
                    continue
                seen[address].add(value)
                index = index_for(address, value)
                exceeded = sorted(site for site, entries in sites.items()
                                  if index >= entries)
                if not exceeded:
                    continue
                every_site = len(exceeded) == len(sites)
                out_of_range.append({
                    "frame": frame,
                    "address": f"0x{address:04X}",
                    "label": label,
                    "value": value,
                    "index": index,
                    "exceeds_tables_at": [f"0x{s:04X}" for s in exceeded],
                    "in_range_at": [f"0x{s:04X}" for s in sorted(sites)
                                    if s not in exceeded],
                    "out_of_range_at_every_site_it_feeds": every_site,
                    "attribution": (
                        "definite: out of range at every site this variable "
                        "feeds" if every_site else
                        "undecidable from frame sampling: in range at some of "
                        "the sites this variable feeds, so which dispatch was "
                        "running when this value held cannot be told apart"),
                })
            for slot in ENEMY_SLOTS:
                enemy_seen.add(int(ram[slot]))
    finally:
        env.close()

    elapsed = time.time() - started
    report = {
        "experiment": "frame-sampled dispatch index observation",
        "assisted": False,
        "manifest": {
            "rom_sha1": rom.sha1,
            "repository_commit": _git_commit(),
            "emulator": "nes-py (local checkout)",
            "emulator_commit": _git_commit("/home/sadovsky/code/nes-py"),
            "seed": args.seed,
            "frames_requested": args.frames,
            "frames_executed": frames,
            "dropped_steps": dropped,
            "initial_state_sha1": initial_state_hash,
            "wall_seconds": round(elapsed, 1),
            "input_model": ("single controller; menu advance, structured play "
                            "and fully random bytes including simultaneous "
                            "opposing directions (TAS-feasible, not "
                            "necessarily physically feasible)"),
            "sampling": "RAM read once per frame, after the step",
        },
        "limitations": [
            "frame sampling cannot see a value that exists only between "
            "instructions, so no bound here is site-specific",
            "the $9664 index is $00 + $07 and is not observable this way",
            "coverage is of states this input sequence reached, nothing more",
        ],
        "observed": [
            {
                "address": f"0x{address:04X}",
                "label": label,
                "sites": {f"0x{site:04X}": entries
                          for site, entries in sorted(sites.items())},
                "index_formation": how,
                "distinct_values": len(seen[address]),
                "min": min(seen[address]) if seen[address] else None,
                "max": max(seen[address]) if seen[address] else None,
                "max_index": (max(index_for(address, v) for v in seen[address])
                              if seen[address] else None),
                "values": sorted(seen[address]),
                "exceeds_smallest_table": any(
                    index_for(address, v) >= min(sites.values())
                    for v in seen[address]),
                "exceeds_every_table": any(
                    index_for(address, v) >= max(sites.values())
                    for v in seen[address]),
            }
            for address, (label, how, sites) in sorted(WATCHED.items())
        ],
        "enemy_identifiers_seen": sorted(int(i) for i in enemy_seen),
        "illegal_enemy_identifiers_seen": sorted(
            int(i) for i in enemy_seen if i > MAX_LEGAL_ID),
        "out_of_range_observations": out_of_range,
    }

    print(f"ROM sha1 {rom.sha1}")
    print(f"frames executed {frames} (dropped {dropped}) in {elapsed:.0f}s, "
          f"seed {args.seed}\n")
    print("variable  N   tables it indexes   values observed")
    print("-" * 76)
    for entry in report["observed"]:
        values = entry["values"]
        shown = (", ".join(str(v) for v in values[:8])
                 + (" ..." if len(values) > 8 else ""))
        tables = "/".join(str(n) for n in sorted(set(entry["sites"].values())))
        flag = ("  <-- out of range at EVERY site"
                if entry["exceeds_every_table"] else
                "  <-- out of range at the smallest table only"
                if entry["exceeds_smallest_table"] else "")
        print(f"{entry['label']:9} {entry['distinct_values']:3} "
              f"{tables:>18}   {shown}{flag}")

    print(f"\nenemy identifiers seen: {len(enemy_seen)} distinct, "
          f"max ${max(enemy_seen):02X}" if enemy_seen else "none")
    illegal = report["illegal_enemy_identifiers_seen"]
    print(f"identifiers above the legal $00-$36 domain: "
          f"{[f'0x{i:02X}' for i in illegal] or 'none'}")

    definite = [r for r in out_of_range
                if r["out_of_range_at_every_site_it_feeds"]]
    undecidable = [r for r in out_of_range
                   if not r["out_of_range_at_every_site_it_feeds"]]
    print(f"\nvalues out of range at every site they feed: {len(definite)}")
    for record in definite[:10]:
        print(f"  frame {record['frame']}: {record['label']} = "
              f"{record['value']} -> index {record['index']}, exceeds "
              f"{', '.join(record['exceeds_tables_at'])}")
    print(f"values out of range at some sites but not others: "
          f"{len(undecidable)}")
    for record in undecidable[:10]:
        print(f"  frame {record['frame']}: {record['label']} = "
              f"{record['value']} -> index {record['index']}; exceeds "
              f"{', '.join(record['exceeds_tables_at'])} but is in range at "
              f"{', '.join(record['in_range_at'])}")
    if undecidable:
        print("  These are NOT findings: a frame sample cannot tell which "
              "dispatch was running,")
        print("  and the earlier revision already noted that $0772 reaches 3 "
              "while indexing its")
        print("  larger tables.  Attributing them needs the "
              "instruction-level census.")
    if not definite:
        print("\nNo value was observed out of range at every site it feeds. "
              "That is an observation")
        print("over the states this input sequence reached, not a bound: see "
              "'limitations' in the")
        print("JSON, and note that $0733 in particular is written at $9CA3 "
              "and read at $9740")
        print("within a single frame, so frame sampling can miss a non-zero "
              "value entirely.")

    path = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), args.out)
    with open(path, "w") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
    print(f"\nwrote {path}")
    return 0


def _git_commit(repo: str | None = None) -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True,
            text=True, check=True).stdout.strip()
    except Exception:
        return "unknown"


if __name__ == "__main__":
    raise SystemExit(main())
