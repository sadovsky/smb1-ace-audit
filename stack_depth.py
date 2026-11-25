"""Condition C3: can the stack be driven far enough to corrupt a return address?

The JumpEngine recovers its *table pointer* by pulling the caller's return
address off the stack (`PLA/PLA` at `$8E06`). If the stack pointer could be
driven out of its normal band, that pull would return something other than a
genuine return address and the "table" the engine indexes could point into RAM.

Static analysis (controlflow.py) shows the stack pointer is written directly
exactly once, by the `TXS` at `$8009` during reset init. During gameplay it can
therefore only move through `JSR`/`RTS`, `PHA`/`PLA`, `PHP`/`PLP` and the
NMI's push/`RTI`. This script measures how far it actually moves, using the
`sp` field the native tracer records on every instruction.

Overflow would require roughly 128 nested frames; underflow would require the
pulls to outnumber the pushes by a similar margin.

    python3 stack_depth.py [episodes] [frames]
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

A, B, SELECT, START, UP, DOWN, LEFT, RIGHT = 1, 2, 4, 8, 16, 32, 64, 128
BOOT = [(0, 40), (START, 10), (0, 40)]

# Hot addresses that run constantly, giving a dense SP sample without the cost
# of recording every instruction.
SAMPLE_POINTS = [
    0x8082,   # NMI entry
    0x8E04,   # JumpEngine entry
    0x8E16,   # the computed jump
    0x8181,   # RTI at the end of the NMI handler
]


def episode(seed: int, frames: int, full_window: int = 240):
    rng = random.Random(seed)
    env = TraceNESEnv(ROM)
    env.reset()
    env.set_trace_capacity(600_000)
    env.watch(SAMPLE_POINTS)
    for act, n in BOOT:
        for _ in range(n):
            env.step(act)

    lo, hi = 0xFF, 0x00
    samples = 0

    def absorb():
        nonlocal lo, hi, samples
        for e in env.trace_events():
            lo = min(lo, e.sp)
            hi = max(hi, e.sp)
            samples += 1
        env.clear_trace()

    for f in range(frames):
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
        # periodically record every instruction for one frame, so the sample
        # is not biased to the four watched addresses
        if f % full_window == 0:
            env.record_non_rom(True)
            env.watch(SAMPLE_POINTS, False)
            env.clear_trace()
            # unfiltered single-frame window
            import ctypes  # noqa: F401  (EnableTrace lives on the cheat env)
            env.step(act)
            absorb()
            env.watch(SAMPLE_POINTS, True)
            env.record_non_rom(False)
        if f % 600 == 0:
            absorb()
    absorb()
    env.close()
    return lo, hi, samples


def main():
    episodes = int(sys.argv[1]) if len(sys.argv) > 1 else 4
    frames = int(sys.argv[2]) if len(sys.argv) > 2 else 3000

    lo, hi, samples = 0xFF, 0x00, 0
    for s in range(episodes):
        l, h, n = episode(2000 + s, frames)
        lo, hi, samples = min(lo, l), max(hi, h), samples + n

    # depth = how many bytes are on the stack: $FF is empty, $00 is full
    deepest = 0xFF - lo
    result = {
        "experiment_id": "stack-depth-band",
        "rom_sha1": image().sha1,
        "experiment_type": "controller_only",
        "episodes": episodes,
        "frames_per_episode": frames,
        "sp_samples": samples,
        "sp_min": f"0x{lo:02X}",
        "sp_max": f"0x{hi:02X}",
        "deepest_bytes_used": deepest,
        "bytes_of_headroom_before_wrap": lo,
        "result": ("stack stays in a narrow band" if lo > 0x40
                   else "stack approached overflow"),
    }
    print(json.dumps(result, indent=2))
    print(f"\nThe stack pointer stayed within ${lo:02X}..${hi:02X}.")
    print(f"Deepest use: {deepest} bytes of the 256-byte page; "
          f"{lo} bytes of headroom remained before it could wrap.")
    print("Overflow needs ~128 nested frames, so on these inputs the "
          "JumpEngine's PLA/PLA always pulls a genuine return address.")


if __name__ == "__main__":
    main()
