"""A coverage-guided checkpoint search for inputs that play the whole game.

Why this exists.  `formal.dyn.search_inputs` searches greedily on the player's
x position with a one-block horizon, and that objective walks straight into
every pit: a block that leaves the player in mid-air over a hole scores higher
than one that stops at its edge, because the fall has not killed anybody yet.
Its twelve seeds therefore spent most of 16,000 frames dying in world 1-1 and
reached 1-3 at best, so 3 of the 18 dispatch sites were never fetched and 41%
of the recovered control-flow graph was never executed.

What is different here:

* **a receding horizon.**  Each step evaluates plans `horizon` frames long and
  commits only the first `block` frames of the winner, so a fall, a death or a
  game over inside the horizon is scored before anything is committed.
* **a fast path.**  While the committed style keeps advancing safely the search
  does not search at all: it runs `block` frames of that style and keeps them,
  which costs one emulated frame per committed frame instead of
  `attempts + 1`.  Escalation happens only where the style fails, which is at
  pits, pipes, water, stairs and bosses.  This is what makes a whole-game run
  affordable at nes-py's ~680 frames a second.
* **a progress key that is not just x.**  `(alive, world, level, area, x)`
  compared lexicographically, with the death, game-over and fallen-off-screen
  conditions in `alive`, and with area and level ahead of x so that finishing a
  level always beats running further inside it.
* **coverage guidance.**  Candidate plans are run with nes-py's instruction
  tracer on, and the number of control-flow-graph nodes a plan executes that
  the whole search has never executed breaks ties between plans that make
  near-equal progress.  When progress stalls for `stagnation` blocks the order
  inverts and new nodes become the primary objective, which is what gets the
  search out of a maze corridor or off a staircase it cannot climb.
* **scenarios.**  `main` plays from power-on; `twoplayer` picks 2 PLAYER GAME
  off the title screen first; `gameover` spends its lives on purpose to reach
  the game-over and continue paths; `ceiling` scores height as well as x,
  which is how the warp zone above the exit pipe of 1-2 is reached.

What a replay is and is not.  It is a sequence of controller bytes, one per
frame, from power-on, on the unmodified image: nothing is written into RAM and
no save state from elsewhere is loaded.  `_backup`/`_restore` are used only to
re-run candidate plans from the current checkpoint, so the committed bytes
replay identically (`--verify` replays them and compares RAM).  It is evidence
that the states along it are reachable in the emulator that was searched, and
no evidence at all that a state the search failed to reach is unreachable.
Timing-sensitive wait loops mean a replay can diverge in another emulator, so
`formal.dyn.observe` treats a replay as just another input model.

    python3 -m formal.dyn.search_play --scenario main --seed 1 --frames 120000
"""
from __future__ import annotations

import argparse
import json
import os
import random
import time
from multiprocessing import Pool

import numpy as np

from .inputs import A, B, DOWN, LEFT, RIGHT, SELECT, START, UP

_EMPTY = np.zeros(0, dtype=np.uint16)

DEFAULT_DIRECTORY = os.path.expanduser("~/big/smb1-formal/replays")

#: the cells the search reads.  Nothing else in this module assumes anything
#: about RAM, and the observation suite does not read any of them.
OPER_MODE = 0x0770          # 0 title/demo, 1 game, 2 victory, 3 game over
OPER_TASK = 0x0772
ENGINE_SUB = 0x000E         # 8 is PlayerCtrlRoutine, the only controllable one
WORLD = 0x075F
AREA = 0x0760
LEVEL = 0x075C
LIVES = 0x075A              # 255 after the last life is spent
PLAYER_X_PAGE = 0x006D
PLAYER_X = 0x0086
PLAYER_Y = 0x00CE
PLAYER_Y_HIGH = 0x00B5      # 1 on screen, >= 2 fallen below it
AREA_TYPE = 0x074E          # 0 water, 1 ground, 2 underground, 3 castle
AREA_STYLE = 0x0733         # the $9743 dispatch index
WARP_ZONE = 0x06D9

CONTROLLABLE = 8            # ENGINE_SUB value for PlayerCtrlRoutine


# --------------------------------------------------------------------------
# candidate plans

def plan_style(style: tuple, length: int) -> list[int]:
    """Expand a style descriptor into `length` controller bytes."""
    kind = style[0]
    if kind == "hold":
        return [style[1]] * length
    if kind == "pulse":                      # hold, with A on a duty cycle
        hold, period, duty, phase = style[1:]
        return [hold | (A if (index + phase) % period < duty else 0)
                for index in range(length)]
    if kind == "jump":                       # hold, with one jump
        hold, at, duration = style[1:]
        return [hold | (A if at <= index < at + duration else 0)
                for index in range(length)]
    if kind == "turn":                       # one hold, then another
        first, second, at = style[1:]
        return [first if index < at else second for index in range(length)]
    raise ValueError(style)


#: the fixed styles every escalated search tries, whatever the random draw is.
#: `pulse` with a short duty is how the image's swimming controls work, and the
#: long single jumps are what clear a pit or a staircase.
FIXED_STYLES = (
    ("hold", RIGHT | B),
    ("hold", RIGHT),
    ("hold", 0),
    ("hold", DOWN),
    ("hold", UP),
    ("hold", LEFT | B),
    ("hold", RIGHT | B | A),
    ("pulse", RIGHT | B, 12, 3, 0),
    ("pulse", RIGHT | B, 20, 10, 0),
    ("pulse", RIGHT, 16, 6, 0),
    ("jump", RIGHT | B, 0, 32),
    ("jump", RIGHT | B, 0, 20),
    ("jump", RIGHT | B, 6, 28),
    ("jump", RIGHT | B, 14, 24),
    ("jump", RIGHT, 0, 30),
    ("turn", RIGHT | B, LEFT | B, 24),
    ("turn", 0, RIGHT | B | A, 8),
)


def random_style(rng: random.Random) -> tuple:
    hold = rng.choice([RIGHT | B, RIGHT | B, RIGHT | B, RIGHT, LEFT | B,
                       0, DOWN, UP])
    roll = rng.random()
    if roll < 0.45:
        return ("jump", hold, rng.randrange(0, 40), rng.choice(
            [6, 10, 14, 20, 26, 32, 40]))
    if roll < 0.7:
        return ("pulse", hold, rng.choice([8, 10, 12, 16, 20, 28]),
                rng.choice([2, 3, 4, 6, 10, 14]), rng.randrange(0, 8))
    if roll < 0.85:
        return ("turn", hold, rng.choice([RIGHT | B, LEFT | B, DOWN, 0,
                                          RIGHT | B | A]),
                rng.randrange(4, 48))
    return ("hold", hold)


# --------------------------------------------------------------------------
# the searcher

class Searcher:
    """One worker: an emulator, a committed action list and a coverage mask."""

    def __init__(self, seed: int, *, scenario: str = "main",
                 block: int = 24, horizon: int = 72, attempts: int = 24,
                 stagnation: int = 22, trace: bool = True,
                 capacity: int = 1 << 20):
        from rom import image

        from .nespy import TracedNESEnv
        self.rng = random.Random(seed)
        self.seed = seed
        self.scenario = scenario
        self.block = block
        self.horizon = horizon
        self.attempts = attempts
        self.stagnation_limit = stagnation
        self.trace = trace
        self.traced = TracedNESEnv(image().path, record_all=False,
                                   capacity=capacity)
        self.env = self.traced.env
        self.ram = self.env.ram
        self.handle = self.traced.handle
        self.lib = self.traced.lib
        self.actions: list[int] = []
        #: instruction starts of the recovered graph, and which were executed
        self.starts = self._graph_starts()
        self.covered = np.zeros(0x10000, dtype=bool)
        self.style = ("hold", RIGHT | B)
        self.stagnation = 0
        self.best_key = None
        self.deaths = 0
        self.game_overs = 0
        self.escalations = 0
        self.fast_blocks = 0
        self.emulated = 0
        self.stages: dict[tuple, int] = {}
        self.events: list[dict] = []
        self.area_styles: set[int] = set()
        self.area_types: set[int] = set()
        self.warp_values: set[int] = set()
        self.oper_modes: set[int] = set()
        self.in_game_over = False
        self.continue_wanted = False
        self.continues = 0

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _graph_starts() -> np.ndarray:
        from analysis.cfg import build_from_vectors
        from rom import b
        mask = np.zeros(0x10000, dtype=bool)
        mask[list(build_from_vectors(b).instruction_starts)] = True
        return mask

    def advance(self, action: int) -> None:
        self.env._frame_advance(action)
        self.emulated += 1

    def state(self) -> dict:
        ram = self.ram
        return {
            "oper": int(ram[OPER_MODE]),
            "engine": int(ram[ENGINE_SUB]),
            "world": int(ram[WORLD]),
            "level": int(ram[LEVEL]),
            "area": int(ram[AREA]),
            "lives": int(ram[LIVES]),
            "x": int(ram[PLAYER_X_PAGE]) * 256 + int(ram[PLAYER_X]),
            "y": int(ram[PLAYER_Y]),
            "yhigh": int(ram[PLAYER_Y_HIGH]),
            "area_type": int(ram[AREA_TYPE]),
            "area_style": int(ram[AREA_STYLE]),
        }

    def note(self) -> None:
        """Record what the committed stream has reached."""
        ram = self.ram
        self.oper_modes.add(int(ram[OPER_MODE]))
        self.warp_values.add(int(ram[WARP_ZONE]))
        if int(ram[OPER_MODE]) == 1:
            self.area_styles.add(int(ram[AREA_STYLE]))
            self.area_types.add(int(ram[AREA_TYPE]))
            stage = (int(ram[WORLD]), int(ram[LEVEL]), int(ram[AREA]))
            if stage not in self.stages:
                self.stages[stage] = len(self.actions)
                self.events.append({
                    "frame": len(self.actions), "what": "entered area",
                    "world": stage[0] + 1, "level": stage[1] + 1,
                    "area_number": stage[2],
                    "area_type": int(ram[AREA_TYPE]),
                    "area_style": int(ram[AREA_STYLE]),
                    "lives": int(ram[LIVES])})

    # -- scoring -----------------------------------------------------------

    def progress_key(self, start: dict, end: dict, worst: dict) -> tuple:
        """Lexicographic: survival, then stage, then position."""
        alive = 0
        if worst["game_over"]:
            alive = -2
        elif worst["died"]:
            alive = -1
        elif worst["fallen"]:
            alive = -1
        if self.scenario == "gameover":
            # the point of this scenario is the game-over and continue paths,
            # so losing a life is the objective rather than the hazard
            alive = -alive
        height = 0
        if self.scenario == "ceiling":
            # the warp zone above the exit pipe of 1-2 is reached by staying
            # high, so height is scored before x there and nowhere else
            height = (255 - end["y"]) // 16 if end["yhigh"] <= 1 else 0
        return (alive, end["world"], end["level"], end["area"], height,
                end["x"] // 16)

    # -- running a plan ----------------------------------------------------

    def run_plan(self, actions: list[int], *, record: bool) -> tuple:
        """Run `actions` from the current state.

        Returns `(end, worst, new, pcs)`: the state afterwards, the worst thing
        that happened anywhere inside the plan, how many graph nodes the plan
        executed that the committed stream never has, and the distinct program
        counters it fetched (empty when `record` is false).
        """
        start_lives = int(self.ram[LIVES])
        worst = {"died": False, "game_over": False, "fallen": False}
        if record:
            self.lib.TraceClear(self.handle)
            self.lib.EnableTrace(self.handle, 1)
        ram = self.ram
        for action in actions:
            self.advance(action)
            if int(ram[OPER_MODE]) == 3 or int(ram[LIVES]) == 255:
                worst["game_over"] = True
            if int(ram[LIVES]) < start_lives or int(ram[ENGINE_SUB]) in (6, 11):
                worst["died"] = True
            if int(ram[PLAYER_Y_HIGH]) >= 2:
                worst["fallen"] = True
        new = 0
        pcs = _EMPTY
        if record:
            self.lib.EnableTrace(self.handle, 0)
            events = self.traced.drain()
            if len(events):
                pcs = np.unique(events["pc"])
                new = int(np.count_nonzero(self.starts[pcs]
                                           & ~self.covered[pcs]))
        return self.state(), worst, new, pcs

    def absorb(self, pcs) -> None:
        """Fold a committed plan's program counters into the coverage mask."""
        if len(pcs):
            self.covered[pcs] = True

    def commit(self, actions: list[int]) -> None:
        self.actions.extend(actions)
        self.note()

    # -- the non-interactive path ------------------------------------------

    def default_for_context(self, frame: int) -> int:
        oper = int(self.ram[OPER_MODE])
        if oper == 0:                             # title screen or demo
            if self.continue_wanted:
                # A held while START is pressed at the title screen after a
                # game over is the image's continue path, which restarts at
                # the first level of the world the game was lost in
                if frame % 24 < 12:
                    return A
                if frame % 24 < 15:
                    self.continues += 1
                    self.continue_wanted = False
                    return A | START
                return A
            return START if frame % 12 < 3 else 0
        if oper == 3:                             # game over, then continue
            return START if frame % 16 < 3 else 0
        if oper == 2:                             # victory walk, no input
            return 0
        return 0

    # -- the main loop -----------------------------------------------------

    def play(self, frames: int, *, deadline: float | None = None,
             progress_every: int = 0) -> None:
        if self.scenario == "twoplayer":
            # SELECT once to move the cursor to 2 PLAYER GAME, then START
            for action in ([0] * 40 + [SELECT] * 3 + [0] * 12
                           + [START] * 3 + [0] * 8):
                self.advance(action)
                self.actions.append(action)
            self.note()
        last_report = 0
        while len(self.actions) < frames:
            if deadline is not None and time.time() > deadline:
                break
            ram = self.ram
            if int(ram[OPER_MODE]) != 1 or int(ram[ENGINE_SUB]) != CONTROLLABLE:
                # nothing the pad does matters here: the title screen, a level
                # load, the flagpole, a death animation, the victory walk
                for _ in range(8):
                    action = self.default_for_context(len(self.actions))
                    self.advance(action)
                    self.actions.append(action)
                    if len(self.actions) >= frames:
                        break
                self.note()
                continue
            self.step_interactive()
            if progress_every and len(self.actions) - last_report >= progress_every:
                last_report = len(self.actions)
                state = self.state()
                print(f"  seed {self.seed} f{len(self.actions):7} "
                      f"world {state['world'] + 1}-{state['level'] + 1} "
                      f"area {state['area']} x {state['x']:5} "
                      f"lives {state['lives']} "
                      f"cov {int(self.covered[self.starts].sum())} "
                      f"esc {self.escalations} fast {self.fast_blocks}",
                      flush=True)

    def step_interactive(self) -> None:
        start = self.state()
        self.env._backup()
        # the fast path: keep running the style that is working.  One emulated
        # frame per committed frame, plus the tracer, which is what makes a
        # whole-game run affordable.
        actions = plan_style(self.style, self.block)
        end, worst, _, pcs = self.run_plan(actions, record=self.trace)
        if (not worst["died"] and not worst["game_over"]
                and not worst["fallen"]
                and (end["world"], end["level"], end["area"],
                     end["x"]) >= (start["world"], start["level"],
                                   start["area"], start["x"] + 8)):
            self.fast_blocks += 1
            self.absorb(pcs)
            self.commit(actions)
            self.register_progress(start, end)
            return

        # escalate: evaluate plans over the whole horizon from the checkpoint,
        # so a fall, a death or a game over is scored before anything is kept
        self.escalations += 1
        styles = list(FIXED_STYLES) + [random_style(self.rng)
                                       for _ in range(self.attempts)]
        scored = []
        for style in styles:
            self.env._restore()
            plan = plan_style(style, self.horizon)
            end, worst, new, _ = self.run_plan(plan, record=self.trace)
            scored.append((self.progress_key(start, end, worst), new, style))
        stuck = self.stagnation >= self.stagnation_limit
        if stuck:
            # coverage first: this is what leaves a corridor, a staircase or a
            # maze the progress key cannot leave, and it is the sense in which
            # the search is coverage-guided
            scored.sort(key=lambda row: (row[0][0], row[1], row[0][1:]),
                        reverse=True)
            if self.rng.random() < 0.3:
                head = scored[:4]
                self.rng.shuffle(head)
                scored = head + scored[4:]
        else:
            scored.sort(key=lambda row: (row[0], row[1]), reverse=True)
        style = scored[0][2]
        self.env._restore()
        plan = plan_style(style, self.block)
        _, _, _, pcs = self.run_plan(plan, record=self.trace)
        self.absorb(pcs)
        self.style = style
        self.commit(plan)
        self.register_progress(start, self.state())

    def register_progress(self, start: dict, end: dict) -> None:
        key = (end["world"], end["level"], end["area"], end["x"])
        if self.best_key is None or key > self.best_key:
            self.best_key = key
            self.stagnation = 0
        else:
            self.stagnation += 1
        over = int(self.ram[LIVES]) == 255 or int(self.ram[OPER_MODE]) == 3
        if over and not self.in_game_over:
            self.game_overs += 1
            self.continue_wanted = True
            self.events.append({"frame": len(self.actions),
                                "what": "game over",
                                "world": int(self.ram[WORLD]) + 1})
        self.in_game_over = over
        if end["lives"] < start["lives"]:
            self.deaths += 1

    # -- output ------------------------------------------------------------

    def manifest(self, wall: float) -> dict:
        state = self.state()
        return {
            "scenario": self.scenario,
            "seed": self.seed,
            "frames": len(self.actions),
            "emulated_frames": self.emulated,
            "search_overhead": round(self.emulated / max(1, len(self.actions)), 2),
            "block": self.block,
            "horizon": self.horizon,
            "attempts_per_escalation": self.attempts + len(FIXED_STYLES),
            "fast_path_blocks": self.fast_blocks,
            "escalations": self.escalations,
            "areas_entered": len(self.stages),
            "stages": sorted([list(stage) + [frame]
                              for stage, frame in self.stages.items()]),
            "best_world_level": [state["world"] + 1, state["level"] + 1],
            "furthest_world_level": [max(w for w, _, _ in self.stages) + 1,
                                     max(l for _, l, _ in self.stages) + 1]
            if self.stages else None,
            "oper_modes_seen": sorted(self.oper_modes),
            "area_types_seen": sorted(self.area_types),
            "area_styles_seen": sorted(self.area_styles),
            "warp_zone_control_values_seen": sorted(self.warp_values),
            "deaths": self.deaths,
            "game_overs": self.game_overs,
            "continues_taken": self.continues,
            "graph_nodes_executed_during_search":
                int(self.covered[self.starts].sum()),
            "wall_seconds": round(wall, 1),
            "events": self.events,
        }

    def write(self, directory: str, wall: float) -> dict:
        os.makedirs(directory, exist_ok=True)
        manifest = self.manifest(wall)
        path = os.path.join(directory,
                            f"play_{self.scenario}_{self.seed}.json")
        with open(path, "w") as handle:
            json.dump({"manifest": manifest, "actions": self.actions}, handle)
        manifest["path"] = path
        return manifest

    def close(self) -> None:
        self.traced.close()


# --------------------------------------------------------------------------

def verify(path: str) -> dict:
    """Replay a recorded file from power-on and report where it ends up."""
    from nes_py import NESEnv

    from rom import image
    payload = json.load(open(path))
    actions = payload["actions"]
    env = NESEnv(image().path)
    env.reset()
    stages = {}
    for frame, action in enumerate(actions):
        env._frame_advance(action)
        ram = env.ram
        if int(ram[OPER_MODE]) == 1:
            stage = (int(ram[WORLD]), int(ram[LEVEL]), int(ram[AREA]))
            stages.setdefault(stage, frame)
    result = {
        "path": path,
        "frames": len(actions),
        "areas_entered_on_replay": len(stages),
        "areas_entered_during_search":
            payload["manifest"].get("areas_entered"),
        "stages_on_replay": sorted(list(s) + [f] for s, f in stages.items()),
        "matches_search": (len(stages)
                           == payload["manifest"].get("areas_entered")),
    }
    env.close()
    return result


def _job(spec):
    (seed, scenario, frames, block, horizon, attempts, stagnation, directory,
     budget, verbose) = spec
    started = time.time()
    searcher = Searcher(seed, scenario=scenario, block=block, horizon=horizon,
                        attempts=attempts, stagnation=stagnation)
    try:
        searcher.play(frames,
                      deadline=started + budget if budget else None,
                      progress_every=4000 if verbose else 0)
        return searcher.write(directory, time.time() - started)
    finally:
        searcher.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", default="main",
                        choices=("main", "twoplayer", "gameover", "ceiling"))
    parser.add_argument("--seeds", default="1")
    parser.add_argument("--frames", type=int, default=120000)
    parser.add_argument("--block", type=int, default=24)
    parser.add_argument("--horizon", type=int, default=72)
    parser.add_argument("--attempts", type=int, default=24)
    parser.add_argument("--stagnation", type=int, default=22)
    parser.add_argument("--budget", type=float, default=0.0,
                        help="wall-clock seconds per worker, 0 for no limit")
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--directory", default=DEFAULT_DIRECTORY)
    parser.add_argument("--verify", default=None,
                        help="replay a recorded file instead of searching")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    if args.verify:
        print(json.dumps(verify(args.verify), indent=2))
        return 0

    seeds = [int(piece) for piece in args.seeds.split(",")]
    specs = [(seed, args.scenario, args.frames, args.block, args.horizon,
              args.attempts, args.stagnation, args.directory, args.budget,
              not args.quiet) for seed in seeds]
    if len(specs) == 1:
        results = [_job(specs[0])]
    else:
        with Pool(min(args.workers, len(specs))) as pool:
            results = pool.map(_job, specs)
    for entry in results:
        print(f"seed {entry['seed']}: {entry['frames']} frames, "
              f"{entry['areas_entered']} areas, furthest "
              f"{entry['furthest_world_level']}, "
              f"{entry['graph_nodes_executed_during_search']} graph nodes, "
              f"overhead {entry['search_overhead']}x, "
              f"{entry['wall_seconds']}s -> {entry['path']}")
    index = os.path.join(args.directory, f"index_{args.scenario}.json")
    with open(index, "w") as handle:
        json.dump({"replays": results}, handle, indent=2, sort_keys=True)
    print(f"wrote {index}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
