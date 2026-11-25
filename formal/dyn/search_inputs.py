"""Search for controller-byte sequences that get further into the game.

Why this exists.  Every scripted input model in `formal/dyn/inputs.py`, and the
one in `experiments/observe_indices.py` before it, dies in world 1-1.  So an
observation run driven by them says nothing about the code that only a later
level, a level transition or a different area type reaches, and the graph
coverage it reports is an upper bound on what those inputs could ever cover.
This module gets further by a greedy search with checkpoints, and writes the
resulting byte sequence to a file so that observation runs can **replay** it as
an ordinary open-loop input model.

The search.  From a checkpoint, draw `attempts` candidate blocks of
`block` frames each (hold right and B, or right, or left and B, or nothing,
with one jump of random length and position, and sometimes a crouch), run each
from the checkpoint using nes-py's backup/restore, and commit the one whose
state ranks highest: alive first, then world, level and x position.  No
backtracking beyond the current block.

What a replay is and is not.  It is a sequence of controller bytes.  It is
evidence that the states along it are reachable *in the emulator that was
searched*, from power-on, with no state injection -- nothing is written into
RAM, no save state from elsewhere is loaded, and the search only ever chooses
buttons.  It is not evidence that a state is unreachable if the search failed
to reach it, and replaying the same bytes in a different emulator can diverge,
because the sprite-0 wait loops are timing-dependent (see
`formal.dyn.crossvalidate`): a replay that clears a level under nes-py may die
under the tracer.  Observation runs therefore treat a replay as just another
input model and fall back to the closed-loop policy when it ends.

    python3 -m formal.dyn.search_inputs --seeds 12 --frames 14000
"""
from __future__ import annotations

import argparse
import json
import os
import random
import time
from multiprocessing import Pool

from .inputs import A, B, DOWN, LEFT, RIGHT, START

DEFAULT_DIRECTORY = os.path.expanduser("~/big/smb1-formal/replays")

OPER_MODE = 0x0770
WORLD = 0x075F
LEVEL = 0x0760
LIVES = 0x075A
PLAYER_X_PAGE = 0x006D
PLAYER_X = 0x0086


def rank(ram) -> tuple:
    """Alive first, then progress.  A game over ranks below everything."""
    lives = int(ram[LIVES])
    if int(ram[OPER_MODE]) != 1 or lives == 255:
        return (-1, 0, 0, 0)
    return (lives + 1, int(ram[WORLD]), int(ram[LEVEL]),
            int(ram[PLAYER_X_PAGE]) * 256 + int(ram[PLAYER_X]))


def candidate_block(rng: random.Random, block: int) -> list[int]:
    style = rng.random()
    if style < 0.75:
        hold = RIGHT | B
    elif style < 0.85:
        hold = RIGHT
    elif style < 0.95:
        hold = LEFT | B
    else:
        hold = 0
    jump_at = rng.randrange(0, block) if rng.random() < 0.85 else None
    length = rng.choice([8, 14, 20, 26, 32])
    actions = [hold | (A if (jump_at is not None
                             and jump_at <= index < jump_at + length) else 0)
               for index in range(block)]
    if rng.random() < 0.08:
        for index in range(block // 2, block):
            actions[index] = DOWN
    return actions


def search(seed: int, frames: int, *, block: int = 24, attempts: int = 26,
           directory: str = DEFAULT_DIRECTORY) -> dict:
    from nes_py import NESEnv

    from rom import image

    rng = random.Random(seed)
    env = NESEnv(image().path)
    env.reset()
    actions: list[int] = []
    for frame in range(100):                 # get past the title
        action = START if frame % 16 < 2 else 0
        env.step(action)
        actions.append(action)

    best_seen = rank(env.ram)
    deaths = 0
    started = time.time()
    while len(actions) < frames:
        env._backup()
        candidates = []
        for _ in range(attempts):
            env._restore()
            block_actions = candidate_block(rng, block)
            for action in block_actions:
                env.step(action)
            candidates.append((rank(env.ram), block_actions))
        candidates.sort(key=lambda entry: entry[0], reverse=True)
        chosen = candidates[0]
        env._restore()
        for action in chosen[1]:
            env.step(action)
        actions.extend(chosen[1])
        best_seen = max(best_seen, chosen[0])
        if rank(env.ram)[0] < 0:             # dead or game over: press on
            deaths += 1
            for _ in range(80):
                env.step(START)
                actions.append(START)
    final = {
        "seed": seed,
        "frames": len(actions),
        "block": block,
        "attempts_per_block": attempts,
        "deaths_or_game_overs": deaths,
        "final_world": int(env.ram[WORLD]),
        "final_level": int(env.ram[LEVEL]),
        "best_rank_reached": list(best_seen),
        "wall_seconds": round(time.time() - started, 1),
    }
    env.close()
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, f"replay_{seed}.json")
    with open(path, "w") as handle:
        json.dump({"manifest": final, "actions": actions}, handle)
    final["path"] = path
    return final


def _job(spec):
    seed, frames, block, attempts, directory = spec
    return search(seed, frames, block=block, attempts=attempts,
                  directory=directory)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seeds", type=int, default=12)
    parser.add_argument("--frames", type=int, default=14000)
    parser.add_argument("--block", type=int, default=24)
    parser.add_argument("--attempts", type=int, default=26)
    parser.add_argument("--workers", type=int, default=12)
    parser.add_argument("--directory", default=DEFAULT_DIRECTORY)
    args = parser.parse_args(argv)

    specs = [(seed, args.frames, args.block, args.attempts, args.directory)
             for seed in range(1, args.seeds + 1)]
    with Pool(min(args.workers, len(specs))) as pool:
        results = pool.map(_job, specs)
    results.sort(key=lambda entry: entry["best_rank_reached"], reverse=True)
    for entry in results:
        print(f"seed {entry['seed']:3}: {entry['frames']} frames, "
              f"best world {entry['best_rank_reached'][1] + 1}-"
              f"{entry['best_rank_reached'][2] + 1}, "
              f"{entry['deaths_or_game_overs']} deaths, "
              f"{entry['wall_seconds']}s -> {entry['path']}")
    index = os.path.join(args.directory, "index.json")
    with open(index, "w") as handle:
        json.dump({"replays": results}, handle, indent=2, sort_keys=True)
    print(f"wrote {index}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
