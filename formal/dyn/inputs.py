"""Controller-input models for the dynamic runs.

Every model is a callable `(rng, frame, ram) -> byte`, built fresh by
`model(name)` so that a stateful one starts clean.  `ram` is the 2 KiB of RAM
as the engine sees it at the frame boundary; the open-loop models ignore it.

The point is not to play well; it is to reach as many distinct program states
as a scripted pad can, and to say exactly what was pressed so that a reader can
reproduce the run.  Two of the models press button combinations a physical pad
cannot produce (left and right at once, up and down at once).  Those are
admissible in the abstract model -- `formal/README.md` admits any byte from a
controller read -- and they are reachable on hardware with a modified pad or a
replay device, but they are not "normal play" and are labelled.

The models:

``title``       nothing is ever pressed: title screen, then the attract-mode
                demo, then the title again, forever.
``menu``        START every so often: title, game start, and after a game over
                the continue path.
``run``         START to begin, then right and B with a periodic A: level
                progress of a sort, and many deaths.
``explore``     ``run`` plus random DOWN (pipes), UP, LEFT and SELECT.
``random``      uniformly random bytes, including the impossible direction
                pairs and every combination of START and SELECT.
``advance``     a closed-loop policy: it reads the player's x position and
                jumps when stuck, which is what actually clears levels and
                reaches later worlds.  Still one controller byte per frame.
``mixed``       blocks of 600 frames cycling the policy, ``explore``,
                ``random`` and ``menu``, which the long observation runs use.
``replay[:N]``  a controller-byte sequence recorded by
                `formal.dyn.search_inputs`, which searched for inputs that get
                past world 1-1, followed by ``advance`` once it runs out.
"""
from __future__ import annotations

import random

RIGHT, LEFT, DOWN, UP, START, SELECT, B, A = (
    0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01)

#: RAM the closed-loop policy reads.  Nothing else in `formal/dyn` assumes
#: anything about these cells; the policy only needs to know whether the game
#: is running and whether the player is moving.
OPER_MODE = 0x0770
PLAYER_X_PAGE = 0x006D
PLAYER_X = 0x0086


def title(rng: random.Random, frame: int, ram=None) -> int:
    return 0


def menu(rng: random.Random, frame: int, ram=None) -> int:
    return START if frame % 64 < 3 else 0


def run(rng: random.Random, frame: int, ram=None) -> int:
    if frame < 90:
        return START if frame % 16 < 2 else 0
    action = RIGHT | B
    if frame % 23 < 7:
        action |= A
    return action


def explore(rng: random.Random, frame: int, ram=None) -> int:
    if frame < 90:
        return START if frame % 16 < 2 else 0
    action = run(rng, frame)
    roll = rng.random()
    if roll < 0.04:
        action = DOWN
    elif roll < 0.08:
        action = UP
    elif roll < 0.12:
        action = LEFT | (A if rng.random() < 0.5 else 0)
    elif roll < 0.13:
        action = START
    elif roll < 0.14:
        action = SELECT
    return action


def random_byte(rng: random.Random, frame: int, ram=None) -> int:
    return rng.getrandbits(8)


class Advance:
    """A closed-loop policy that actually gets through levels.

    The open-loop models hold right and jump on a fixed cadence, which clears
    the first few screens of world 1-1 and then dies at the first pipe or pit
    it mistimes, so a run of them never leaves 1-1 and never reaches the
    dispatch sites that only a later level or a level transition uses.  This
    policy reads three cells -- the operating mode and the player's x position
    -- and jumps when the player has stopped advancing, which is enough to
    clear levels, fall into pipes and reach later worlds.

    It is still one controller byte per frame, and it is still an observation
    tool: it does not search or backtrack, so it is no evidence that any state
    is or is not reachable, only a way of reaching more of them.
    """

    def __init__(self):
        self.best = -1
        self.stuck = 0
        self.jump = 0
        self.crouch = 0

    def __call__(self, rng: random.Random, frame: int, ram=None) -> int:
        if ram is None or int(ram[OPER_MODE]) != 1:
            self.best = -1
            self.stuck = 0
            self.jump = 0
            return START if frame % 8 < 2 else 0
        position = int(ram[PLAYER_X_PAGE]) * 256 + int(ram[PLAYER_X])
        if position > self.best:
            self.best = position
            self.stuck = 0
        else:
            self.stuck += 1
        if self.crouch:
            self.crouch -= 1
            return DOWN
        action = RIGHT | B
        if self.jump:
            self.jump -= 1
            action |= A
            if not self.jump:
                self.stuck = 0
        elif self.stuck > 8:
            self.jump = 24
            action |= A
        if rng.random() < 0.01:
            self.crouch = 12                    # look for a pipe
        return action


class Mixed:
    """600-frame blocks cycling the policy and the open-loop models."""

    def __init__(self):
        self.advance = Advance()

    def __call__(self, rng: random.Random, frame: int, ram=None) -> int:
        block = (frame // 600) % 5
        if block in (0, 3):
            return self.advance(rng, frame, ram)
        if block == 1:
            return explore(rng, frame)
        if block == 2:
            return random_byte(rng, frame)
        return menu(rng, frame)


class Replay:
    """Replays a recorded controller-byte sequence, then takes over by policy.

    The sequence comes from `formal.dyn.search_inputs`, which searched for
    bytes that get past world 1-1; see that module for what a replay is
    evidence of and what it is not.  When the recording runs out the closed-
    loop policy continues, so a long run does not fall back to pressing
    nothing.  If the file is missing the model degrades to the policy alone
    and says so in `note`.
    """

    def __init__(self, which: int = 1, directory: str | None = None):
        import json
        import os
        directory = directory or os.path.expanduser(
            "~/big/smb1-formal/replays")
        self.path = os.path.join(directory, f"replay_{which}.json")
        self.fallback = Advance()
        self.actions: list[int] = []
        self.note = f"replay {self.path}"
        try:
            with open(self.path) as handle:
                payload = json.load(handle)
            self.actions = payload["actions"]
            self.manifest = payload.get("manifest", {})
        except (OSError, ValueError, KeyError):
            self.manifest = {}
            self.note = (f"{self.path} is missing; the closed-loop policy ran "
                         "alone")

    def __call__(self, rng: random.Random, frame: int, ram=None) -> int:
        if frame < len(self.actions):
            return self.actions[frame]
        return self.fallback(rng, frame, ram)


class PlayReplay(Replay):
    """Replays a sequence recorded by `formal.dyn.search_play`.

    The file name is `play_<scenario>_<seed>.json` -- where `<seed>` is the
    search seed, or the name a movie was converted under by `formal.dyn.fm2`
    -- and the manifest inside it
    records which areas of the game the sequence entered, which is what the
    observation manifest quotes.  Everything `Replay` says applies: these are
    controller bytes from power-on on the unmodified image, they are evidence
    that the states along them are reachable in the emulator that was
    searched, and they are no evidence at all about states not reached.
    """

    def __init__(self, scenario: str = "main", seed: str = "1",
                 directory: str | None = None):
        import json
        import os
        directory = directory or os.path.expanduser(
            "~/big/smb1-formal/replays")
        self.path = os.path.join(directory, f"play_{scenario}_{seed}.json")
        self.fallback = Advance()
        self.actions = []
        self.note = f"replay {self.path}"
        try:
            with open(self.path) as handle:
                payload = json.load(handle)
            self.actions = payload["actions"]
            self.manifest = payload.get("manifest", {})
        except (OSError, ValueError, KeyError):
            self.manifest = {}
            self.note = (f"{self.path} is missing; the closed-loop policy ran "
                         "alone")


MODELS = {
    "title": lambda: title,
    "menu": lambda: menu,
    "run": lambda: run,
    "explore": lambda: explore,
    "random": lambda: random_byte,
    "advance": Advance,
    "mixed": Mixed,
}

DESCRIPTIONS = {
    "title": "no button is ever pressed (title screen and attract demo)",
    "menu": "START for three frames out of every 64",
    "run": "START until frame 90, then RIGHT+B with A for 7 frames in 23",
    "explore": "run, plus random DOWN/UP/LEFT/START/SELECT at a few per cent",
    "random": ("uniformly random bytes, including LEFT+RIGHT and UP+DOWN "
               "together, which a standard pad cannot produce"),
    "advance": ("closed-loop: holds RIGHT+B, jumps when the player's x "
                "position has not advanced for eight frames, crouches at "
                "random to find pipes; reads $0770, $006D and $0086"),
    "mixed": ("600-frame blocks cycling the advance policy, explore, random "
              "and menu"),
}


def model(name: str):
    """A fresh callable for `name`; a stateful model starts clean.

    `replay` or `replay:N` replays the Nth sequence recorded by
    `formal.dyn.search_inputs`; `play:<scenario>:<seed>` replays one recorded
    by `formal.dyn.search_play`.
    """
    pieces = name.split(":")
    if pieces[0] == "play":
        # the third field is a seed for a searched replay and a name for a
        # replayed movie (`play:movie:warpless`), so it stays a string
        scenario = pieces[1] if len(pieces) > 1 else "main"
        name = pieces[2] if len(pieces) > 2 else "1"
        return PlayReplay(scenario, name)
    if name.split(":")[0] == "replay":
        _, _, which = name.partition(":")
        return Replay(int(which) if which else 1)
    try:
        return MODELS[name]()
    except KeyError:
        raise SystemExit(f"unknown input model {name!r}; choose from "
                         + ", ".join(sorted(MODELS)) + ", replay[:N]")


def describe(name: str) -> str:
    if name.split(":")[0] == "play":
        instance = model(name)
        manifest = instance.manifest
        if not instance.actions:
            return instance.note
        return (f"replayed controller bytes from {instance.path} "
                f"({len(instance.actions)} frames, scenario "
                f"{manifest.get('scenario')}, "
                f"{manifest.get('areas_entered')} areas of the game entered, "
                f"{manifest.get('deaths')} deaths, "
                f"{manifest.get('game_overs')} game overs, furthest world-"
                f"level {manifest.get('furthest_world_level')}), then the "
                "closed-loop advance policy")
    if name.split(":")[0] == "replay":
        instance = model(name)
        return ("replayed controller bytes from "
                f"{instance.path} ({len(instance.actions)} frames, "
                f"{instance.manifest.get('deaths_or_game_overs', '?')} deaths, "
                f"best world "
                f"{instance.manifest.get('best_rank_reached', [0, 0, 0])[1] + 1}"
                f"-{instance.manifest.get('best_rank_reached', [0, 0, 0])[2] + 1}"
                "), then the closed-loop advance policy")
    return DESCRIPTIONS.get(name, name)
