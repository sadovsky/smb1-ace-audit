"""Instruction-level dispatch census and derailment detector.

This is the experiment the frame-granular fuzz could not run. Using the
rommage CPU tracer it watches the jump engine at `$8E04` (where the
accumulator still holds the dispatch index) and arms the non-ROM detector,
which records any instruction executed below `$8000`.

On NROM every byte of code lives in ROM, so an instruction executing outside
`$8000-$FFFF` means the program counter has entered RAM or I/O space. That is
the precondition for arbitrary code execution, and it is directly observable
rather than inferred.

Requires a tracer-patched nes-py exposing `TraceNESEnv`; point at it with
$CHEAT_ENV_DIR. See rommage/nes-py-fork/nes-py-tracer.README.md.

    python3 native_dispatch.py [episodes] [frames]
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import random
import sys
from collections import Counter

sys.path.insert(0, os.environ.get("CHEAT_ENV_DIR", "../rommage/genie_search"))
with contextlib.redirect_stderr(io.StringIO()):
    from trace_env import TraceNESEnv

from rom import ROM, image

JUMPENGINE = 0x8E04
A, B, SELECT, START, UP, DOWN, LEFT, RIGHT = 1, 2, 4, 8, 16, 32, 64, 128
BOOT = [(0, 40), (START, 10), (0, 40)]


def episode(seed: int, frames: int):
    """One controller-only episode. Returns (index counter, non-ROM events)."""
    rng = random.Random(seed)
    env = TraceNESEnv(ROM)
    env.reset()
    env.set_trace_capacity(400_000)
    env.watch(JUMPENGINE)        # A holds the dispatch index at engine entry
    env.record_non_rom(True)     # the derailment detector
    for act, n in BOOT:
        for _ in range(n):
            env.step(act)
    for _ in range(frames):
        r = rng.random()
        if r < 0.55:
            act = RIGHT | (A if rng.random() < 0.4 else 0) | (B if rng.random() < 0.3 else 0)
        elif r < 0.70:
            act = LEFT | (A if rng.random() < 0.4 else 0)
        elif r < 0.85:
            act = A | (B if rng.random() < 0.5 else 0)
        else:
            act = rng.getrandbits(8)
        env.step(act)
    events = env.trace_events()
    idx = Counter(e.a for e in events if e.pc == JUMPENGINE)
    non_rom = [e.as_dict() for e in events if e.non_rom]
    dropped = env.trace_dropped
    env.close()
    return idx, non_rom, dropped


def main():
    episodes = int(sys.argv[1]) if len(sys.argv) > 1 else 6
    frames = int(sys.argv[2]) if len(sys.argv) > 2 else 4000

    total = Counter()
    non_rom = []
    dropped = 0
    for s in range(episodes):
        i, n, d = episode(1000 + s, frames)
        total += i
        non_rom += n
        dropped += d

    largest_table = 55           # $C27F, the biggest dispatch table in the game
    result = {
        "experiment_id": "native-dispatch-census",
        "rom_sha1": image().sha1,
        "experiment_type": "controller_only",
        "episodes": episodes,
        "frames_per_episode": frames,
        "dispatch_invocations": sum(total.values()),
        "distinct_indices": len(total),
        "max_index_observed": max(total) if total else None,
        "largest_table_entries": largest_table,
        "non_rom_instructions": len(non_rom),
        "events_dropped": dropped,
        "result": ("no_derailment_observed" if not non_rom
                   else "DERAILMENT_OBSERVED"),
    }

    print(json.dumps(result, indent=2))
    print("\nindex histogram (dispatch index: times taken)")
    for k in sorted(total):
        print(f"  {k:3} : {total[k]}")
    if non_rom:
        print("\nINSTRUCTIONS EXECUTED OUTSIDE PRG ROM:")
        for e in non_rom[:20]:
            print(" ", e)
    else:
        print("\nThe program counter never left PRG ROM.")


if __name__ == "__main__":
    main()
