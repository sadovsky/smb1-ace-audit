"""Replay a published FCEUX `.fm2` input movie as ordinary controller bytes.

Approach 2 of the coverage task: rather than search for inputs that play the
whole game, take a recorded human-or-tool-assisted run and replay it.  An
`.fm2` is a plain-text file with one line per frame, so the conversion is
mechanical and auditable -- there is no save state, no memory patch and no
emulator-specific state in what this module uses, only the eight buttons of
controller one per frame and the power-on at frame zero.

The format.  Lines that start with `|` are frames:

    |commands|port0|port1|port2|

`commands` is a bit field: 1 is a soft reset, 2 is a power cycle.  Each port
is eight characters in the order **R L D U T S B A** (`T` is START, `S` is
SELECT), a dot where the button is not pressed.  That is the same high-to-low
order as the byte `nes_py.NESEnv.step` takes, so the conversion is one shift
per character.  A port that is not a standard controller (`port1 2` is the
zapper) is rejected rather than guessed at.

**Why this may not work, and how that is checked.**  A tool-assisted movie is
frame-perfect: it was recorded against one emulator's exact timing, and any
difference in when the sprite-0 flag sets or when vblank starts shifts the
inputs by a frame and the run dies.  `formal.dyn.crossvalidate` already
measures that the tracer and nes-py differ inside six timing-dependent wait
loops, so a desync here is the expected outcome, not a surprise.  `--verify`
therefore replays the movie and reports **which areas of the game it actually
entered**, read out of `$075F`/`$075C`/`$0760`, and how many lives were lost.
A movie that desyncs shows up as a run that dies early and never leaves world
1, and the replay is then worth nothing and is not counted.

The movie file itself is not redistributed: this module reads one from a path
and writes only controller bytes, under `~/big/smb1-formal/replays`.

    python3 -m formal.dyn.fm2 --movie /path/to/run.fm2 --name movie_warpless
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os

BUTTON_ORDER = "RLDUTSBA"          # high bit first, as nes-py takes the byte
CMD_SOFT_RESET = 1
CMD_POWER = 2

OPER_MODE = 0x0770
WORLD = 0x075F
LEVEL = 0x075C
AREA = 0x0760
LIVES = 0x075A
AREA_TYPE = 0x074E
AREA_STYLE = 0x0733
PLAYERS = 0x077A
HARD_MODE = 0x076A          # set for the second quest

DEFAULT_DIRECTORY = os.path.expanduser("~/big/smb1-formal/replays")


def parse(path: str) -> tuple[dict, list[int], list[int]]:
    """Return `(header, actions, commands)` for an `.fm2` file."""
    header: dict = {}
    actions: list[int] = []
    commands: list[int] = []
    with open(path, "r", errors="replace") as handle:
        for line in handle:
            line = line.rstrip("\n").rstrip("\r")
            if not line.startswith("|"):
                key, _, value = line.partition(" ")
                if key:
                    header[key] = value
                continue
            fields = line.split("|")
            # "|cmd|port0|port1|port2|" splits to ['', cmd, p0, p1, p2, '']
            command = int(fields[1] or 0)
            port0 = fields[2]
            if len(port0) != len(BUTTON_ORDER):
                raise ValueError(
                    f"{path}: port 0 field {port0!r} is not eight buttons; "
                    "this module only replays a standard controller")
            byte = 0
            for index, character in enumerate(port0):
                if character not in ".":
                    byte |= 0x80 >> index
            actions.append(byte)
            commands.append(command)
    if header.get("port0") not in (None, "1"):
        raise ValueError(f"{path}: port 0 is not a standard controller "
                         f"(port0 {header.get('port0')})")
    if header.get("palFlag") not in (None, "0"):
        raise ValueError(f"{path}: this is a PAL movie")
    return header, actions, commands


def shift(actions: list[int], commands: list[int],
          offset: int) -> tuple[list[int], list[int]]:
    """Line the movie up with an emulator that has already been powered on."""
    if offset > 0:
        return [0] * offset + actions, [0] * offset + commands
    if offset < 0:
        return actions[-offset:], commands[-offset:]
    return actions, commands


def rom_matches(header: dict, rom_path: str) -> bool:
    """FCEUX's `romChecksum` is the MD5 of the image without its iNES header."""
    import base64
    recorded = header.get("romChecksum", "")
    if not recorded.startswith("base64:"):
        return False
    with open(rom_path, "rb") as handle:
        digest = hashlib.md5(handle.read()[16:]).hexdigest()
    return base64.b64decode(recorded[7:]).hex() == digest


def replay(actions: list[int], commands: list[int]) -> dict:
    """Replay the bytes in nes-py and report where the run actually got to."""
    from nes_py import NESEnv

    from rom import image
    env = NESEnv(image().path)
    env.reset()
    ram = env.ram
    stages: dict[tuple, int] = {}
    lives_lost = 0
    last_lives = None
    oper_modes: set[int] = set()
    area_types: set[int] = set()
    area_styles: set[int] = set()
    players: set[int] = set()
    mid_run_resets = 0
    hard_mode = set()
    events = []
    for frame, action in enumerate(actions):
        if frame and commands[frame] & (CMD_POWER | CMD_SOFT_RESET):
            mid_run_resets += 1
        env._frame_advance(action)
        oper_modes.add(int(ram[OPER_MODE]))
        players.add(int(ram[PLAYERS]))
        hard_mode.add(int(ram[HARD_MODE]))
        lives = int(ram[LIVES])
        if last_lives is not None and 0 <= lives < last_lives:
            lives_lost += 1
        last_lives = lives
        if int(ram[OPER_MODE]) == 1:
            area_types.add(int(ram[AREA_TYPE]))
            area_styles.add(int(ram[AREA_STYLE]))
            stage = (int(ram[WORLD]), int(ram[LEVEL]), int(ram[AREA]))
            if stage not in stages:
                stages[stage] = frame
                events.append({"frame": frame, "what": "entered area",
                               "world": stage[0] + 1, "level": stage[1] + 1,
                               "area_number": stage[2],
                               "area_type": int(ram[AREA_TYPE]),
                               "area_style": int(ram[AREA_STYLE]),
                               "lives": lives})
    env.close()
    furthest = max((stage[:2] for stage in stages), default=None)
    return {
        "frames": len(actions),
        "areas_entered": len(stages),
        "stages": sorted(list(stage) + [frame]
                         for stage, frame in stages.items()),
        "furthest_world_level": ([furthest[0] + 1, furthest[1] + 1]
                                 if furthest else None),
        "deaths": lives_lost,
        "oper_modes_seen": sorted(oper_modes),
        "area_types_seen": sorted(area_types),
        "area_styles_seen": sorted(area_styles),
        "number_of_players_cell_values_seen": sorted(players),
        "mid_run_reset_commands_ignored": mid_run_resets,
        "hard_mode_cell_values_seen": sorted(hard_mode),
        "events": events,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--movie", required=True)
    parser.add_argument("--name", default="movie_1",
                        help="written as play_<name>.json, so that "
                             "formal.dyn.inputs replays it as play:<name>")
    parser.add_argument("--directory", default=DEFAULT_DIRECTORY)
    parser.add_argument("--limit", type=int, default=0,
                        help="replay only the first N frames")
    parser.add_argument("--offset", type=int, default=0,
                        help="drop (negative) or insert (positive) frames at "
                             "the start.  A movie whose frame zero carries a "
                             "power-cycle command is two frames ahead of a "
                             "`nes_py.NESEnv` that has already been reset, "
                             "and `--offset -2` lines the two up; `--scan` "
                             "finds the offset that works, if one does")
    parser.add_argument("--tail", type=int, default=0,
                        help="append N frames after the movie ends.  A movie "
                             "stops at its last input, so this is what lets "
                             "the end-of-game sequence run out and the quest "
                             "that follows it start.  B is pressed on one "
                             "cadence and START on another: the screen after "
                             "world 8 waits for B, and the title screen "
                             "waits for START")
    parser.add_argument("--scan", type=int, default=0,
                        help="try offsets -N..N over the first 5,000 frames "
                             "and report which ones leave world 1-1")
    parser.add_argument("--write", action="store_true",
                        help="write the replay file even if the movie "
                             "plainly desynced")
    args = parser.parse_args(argv)

    from rom import image
    header, actions, commands = parse(args.movie)
    if args.scan:
        for offset in range(-args.scan, args.scan + 1):
            trial, trial_commands = shift(actions, commands, offset)
            outcome = replay(trial[:5000], trial_commands[:5000])
            print(f"offset {offset:+d}: "
                  f"{outcome['areas_entered']} areas, "
                  f"{outcome['deaths']} deaths, "
                  f"furthest {outcome['furthest_world_level']}")
        return 0
    actions, commands = shift(actions, commands, args.offset)
    if args.tail:
        actions = actions + [
            (0x02 if index % 64 < 4 else 0) | (0x08 if index % 97 < 3 else 0)
            for index in range(args.tail)]
        commands = commands + [0] * args.tail
    if args.limit:
        actions = actions[:args.limit]
        commands = commands[:args.limit]
    matched = rom_matches(header, image().path)
    result = replay(actions, commands)
    result["movie"] = {
        "file": os.path.basename(args.movie),
        "emulator_version": header.get("emuVersion"),
        "rerecord_count": header.get("rerecordCount"),
        "rom_filename_in_movie": header.get("romFilename"),
        "rom_checksum_matches_the_image_under_test": matched,
        "start_offset_frames": args.offset,
        "frames_appended_after_the_movie": args.tail,
    }
    print(json.dumps({k: result[k] for k in (
        "frames", "areas_entered", "furthest_world_level", "deaths",
        "oper_modes_seen", "area_types_seen", "movie")}, indent=2))
    synced = result["areas_entered"] > 4
    if not synced:
        print("the movie desynced: it never left world 1-1/1-2, which is what "
              "a frame-perfect run does on an emulator it was not recorded "
              "against.  Nothing is counted from it.")
    if synced or args.write:
        os.makedirs(args.directory, exist_ok=True)
        path = os.path.join(args.directory, f"play_{args.name}.json")
        manifest = dict(result)
        manifest["scenario"] = "movie"
        manifest["seed"] = 0
        manifest["source"] = ("a published .fm2 input movie, replayed as "
                              "controller bytes; see formal.dyn.fm2")
        with open(path, "w") as handle:
            json.dump({"manifest": manifest, "actions": actions}, handle)
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
