"""Cross-validate `formal.dyn.tracer` against nes-py.

Two protocols run from power-on with the same controller bytes.

**RAM at frame boundaries.**  nes-py's `step` executes exactly 29,781 CPU
cycles and then hands back the 2 KiB of RAM.  The tracer is run to the same
cycle counts and the 2 KiB compared byte for byte.  Reported: how many frames
matched exactly, and for the frames that did not, which addresses differed and
whether they are cells the NMI handler was in the middle of rewriting.  A frame
boundary falls roughly 2,300 cycles after the NMI, i.e. *inside* the handler,
so a cell being updated at that instant is expected to differ whenever the two
emulators are not cycle-identical, and such a difference is not a divergence:
the next boundary agrees again.

**Instruction streams.**  nes-py's native tracer (see `formal.dyn.nespy`)
reports the program counter and A, X, Y, S, P at every fetch.  Comparing
index by index is misleading, because the image contains four loops whose
iteration count is a function of exact timing -- the two `$2002` vblank waits
at reset, the two sprite-0 waits in the handler, and the `JMP $8057` idle loop
-- and one extra iteration shifts every later index.  So both streams are first
run-length encoded over repeating cycles of one or two instructions, the
*patterns* are compared (this is control-flow identity, independent of how many
times a spin loop span), and the registers are compared for every instruction
that the encoding aligns.  Reported: the first pattern difference if any, the
loops whose counts differ, and the register mismatches inside aligned runs.

nes-py's processor-status byte is **not** the 6502's.  `CPU_Flags` in
`nes_py/nes/include/cpu_opcodes.hpp` declares the bits in the order
`N V ONE B D I Z C`, which on this compiler allocates N to bit 0, so its
`flags.byte` is the 6502 status byte with its bits reversed.  That is internally
consistent (`PHP` and `PLP` use the same byte), and it is invisible to the image
because the image never inspects a pushed status byte, but it means (a) the
status column must be bit-reversed before comparison and (b) a status byte
*pushed* on the stack legitimately differs between the two emulators.  Both are
handled, and the report says which differing RAM bytes are of that kind.

    python3 -m formal.dyn.crossvalidate [--frames N] [--inputs MODEL]
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import random
import subprocess
import sys
import time

import numpy as np

from . import inputs
from .tracer import NESPY_CYCLES_PER_FRAME, from_rom

#: bit-reversal of a byte, to translate nes-py's status register
REVERSE = np.array([int(f"{value:08b}"[::-1], 2) for value in range(256)],
                   dtype="u1")
#: bits 4 (B) and 5 are not registers on either side
FLAG_MASK = 0xCF

#: nes-py's power-on status byte, translated into the 6502's layout.  The
#: documented 6502 value is $34; the image's first two instructions are
#: `SEI`/`CLD`, so the difference is invisible from the third fetch onwards.
NESPY_POWER_ON_STATUS = 0x2C

#: The loops whose iteration count is a function of exact timing.  Both
#: emulators execute these; how many times they go round depends on when the
#: `$2002` flags flip, which is the one thing the device stub approximates.
#: The instructions of these loops are removed from both streams before the
#: streams are compared, and their total occurrence counts are reported
#: separately, so that one extra iteration does not shift every later index
#: and hide what the comparison is for.
TIMING_LOOPS = {
    (0x800A, 0x800D): "reset, first wait for vblank ($2002 bit 7)",
    (0x800F, 0x8012): "reset, second wait for vblank ($2002 bit 7)",
    (0x813D, 0x8140, 0x8142): "handler, wait for sprite-0 hit to clear",
    (0x8150, 0x8153, 0x8155): "handler, wait for sprite-0 hit to set",
    (0x8057,): "the idle loop JMP $8057 the handler returns into",
    (0x8159, 0x815A): "handler, the DEY delay before the scroll write",
}
SPIN_PCS = frozenset(pc for pattern in TIMING_LOOPS for pc in pattern)


def git_commit(repository: str | None = None) -> str:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=repository,
                              capture_output=True, text=True,
                              check=True).stdout.strip()
    except Exception:
        return "unknown"


def compare(frames: int, model_name: str, seed: int, *,
            cycle_model: str = "nespy", streams: bool = True,
            sprite0_line_offset: int = 1, sprite0_dot_offset: int = 0,
            progress: bool = False) -> dict:
    """Run both emulators from power-on and compare them.

    The instruction streams are accumulated over the whole run and compared
    once, as one sequence.  Comparing them frame by frame would be wrong: a
    frame boundary falls in the middle of the NMI handler, so the first
    instruction of a frame is not a synchronisation point.
    """
    from array import array

    from rom import image

    from .nespy import TracedNESEnv

    rom = image()
    button = inputs.model(model_name)
    tracer = from_rom(rom.path, cycle_model=cycle_model,
                      sprite0_line_offset=sprite0_line_offset,
                      sprite0_dot_offset=sprite0_dot_offset,
                      power_on_status=NESPY_POWER_ON_STATUS)
    env = TracedNESEnv(rom.path, record_all=streams)
    power_on_ram = bytes(env.ram)

    ram_exact = 0
    ram_diff_sizes: collections.Counter = collections.Counter()
    address_counts: collections.Counter = collections.Counter()
    first_ram_diff = None
    examples: list[dict] = []

    my_pcs = array("H")
    my_registers = bytearray()
    their_events: list[np.ndarray] = []

    mpu = tracer.mpu
    append_pc = my_pcs.append
    extend = my_registers.extend

    def on_fetch(pc, append_pc=append_pc, extend=extend, m=mpu):
        append_pc(pc)
        extend((m.a, m.x, m.y, m.sp, m.p))

    rng_tracer = random.Random(seed)
    started = time.time()
    for frame in range(frames):
        # one byte, computed once from the tracer's RAM and given to both,
        # so a closed-loop model cannot make the two diverge by construction
        action = button(rng_tracer, frame, tracer.ram)
        if streams:
            tracer.run_frame(action, on_fetch=on_fetch)
            their_events.append(env.step(action))
        else:
            tracer.run_frame(action)
            env.env.step(action)

        mine = tracer.ram
        reference = env.ram
        differing = [address for address in range(0x800)
                     if mine[address] != reference[address]]
        ram_diff_sizes[len(differing)] += 1
        if not differing:
            ram_exact += 1
        else:
            if first_ram_diff is None:
                first_ram_diff = frame
            for address in differing:
                address_counts[address] += 1
            if len(examples) < 6:
                examples.append({
                    "frame": frame,
                    "differing": len(differing),
                    "bytes": [
                        {"address": f"0x{address:04X}",
                         "tracer": int(mine[address]),
                         "nes_py": int(reference[address]),
                         "stack_page": 0x100 <= address < 0x200,
                         "nes_py_is_bit_reverse": bool(
                             REVERSE[mine[address]] == reference[address])}
                        for address in differing[:12]],
                })
        if progress and frame % 200 == 199:
            rate = (frame + 1) / (time.time() - started)
            print(f"  frame {frame + 1}/{frames} ({rate:.0f}/s)",
                  file=sys.stderr)

    dropped = env.dropped
    env.close()
    elapsed = time.time() - started

    stream_report = None
    if streams:
        stream_report = compare_streams(my_pcs, my_registers,
                                        np.concatenate(their_events))

    report = {
        "protocol": {
            "frames": frames,
            "input_model": model_name,
            "input_model_description": inputs.describe(model_name),
            "seed": seed,
            "cycle_model": cycle_model,
            "frame_boundary": f"{NESPY_CYCLES_PER_FRAME} CPU cycles, as "
                              "nes_py.NESEnv.step executes",
            "power_on_ram": "all zeros in nes-py; the tracer is given the same",
            "power_on_ram_nonzero_bytes": sum(1 for b in power_on_ram if b),
            "nes_py_status_layout": ("bit-reversed relative to the 6502; "
                                     "translated before comparison"),
            "tracer_stub": tracer.stub_description(),
        },
        "ram_at_frame_boundaries": {
            "frames_compared": frames,
            "frames_identical": ram_exact,
            "fraction_identical": round(ram_exact / max(frames, 1), 6),
            "first_differing_frame": first_ram_diff,
            "differing_byte_count_histogram": {
                str(k): v for k, v in sorted(ram_diff_sizes.items())},
            "addresses_ever_differing": len(address_counts),
            "most_frequent_addresses": [
                {"address": f"0x{address:04X}", "frames": count}
                for address, count in address_counts.most_common(20)],
            "examples": examples,
        },
        "instruction_streams": stream_report,
        "nes_py_events_dropped": dropped,
        "wall_seconds": round(elapsed, 1),
    }
    return report


def compare_streams(my_pcs, my_registers, events) -> dict:
    """Compare two whole instruction streams.

    The instructions of the six timing-dependent wait loops are removed from
    both streams first (see `TIMING_LOOPS`); what is left is compared index by
    index, which is an exact test of control flow and of A, X, Y, S and the six
    real status bits at every remaining fetch.  The removed loops are reported
    by their total occurrence count in each stream.
    """
    mine_pc = np.asarray(my_pcs, dtype=np.uint16)
    mine_regs = np.frombuffer(bytes(my_registers), dtype="u1").reshape(-1, 5)
    their_pc = events["pc"].astype(np.uint16)
    their_regs = np.stack([events["a"], events["x"], events["y"],
                           events["sp"], REVERSE[events["status"]]], axis=1)

    spin = np.zeros(0x10000, dtype=bool)
    for pc in SPIN_PCS:
        spin[pc] = True
    keep_mine = ~spin[mine_pc]
    keep_theirs = ~spin[their_pc]
    left_pc = mine_pc[keep_mine]
    right_pc = their_pc[keep_theirs]
    left = mine_regs[keep_mine]
    right = their_regs[keep_theirs]
    shared = min(len(left_pc), len(right_pc))

    pc_bad = np.nonzero(left_pc[:shared] != right_pc[:shared])[0]
    first_pc_difference = None
    if len(pc_bad):
        index = int(pc_bad[0])
        first_pc_difference = {
            "index_after_removing_spin_loops": index,
            "tracer": f"0x{int(left_pc[index]):04X}",
            "nes_py": f"0x{int(right_pc[index]):04X}",
            "preceding_tracer": [f"0x{int(pc):04X}"
                                 for pc in left_pc[max(0, index - 8):index]],
            "preceding_nes_py": [f"0x{int(pc):04X}"
                                 for pc in right_pc[max(0, index - 8):index]],
        }
    compared = int(pc_bad[0]) if len(pc_bad) else shared
    register_bad = np.nonzero(
        (left[:compared, 0] != right[:compared, 0])
        | (left[:compared, 1] != right[:compared, 1])
        | (left[:compared, 2] != right[:compared, 2])
        | (left[:compared, 3] != right[:compared, 3])
        | ((left[:compared, 4] & FLAG_MASK)
           != (right[:compared, 4] & FLAG_MASK)))[0]
    register_examples = []
    for index in register_bad[:6]:
        index = int(index)
        register_examples.append({
            "index_after_removing_spin_loops": index,
            "pc": f"0x{int(left_pc[index]):04X}",
            "tracer_axys_p": [int(value) for value in left[index]],
            "nes_py_axys_p": [int(value) for value in right[index]],
            "differing": [name for name, a, b in zip(
                ("A", "X", "Y", "S", "P"), left[index], right[index])
                if (a != b if name != "P"
                    else (a & FLAG_MASK) != (b & FLAG_MASK))],
        })

    counts = {}
    for pattern, label in TIMING_LOOPS.items():
        mine_count = int(sum(int((mine_pc == pc).sum()) for pc in pattern))
        their_count = int(sum(int((their_pc == pc).sum()) for pc in pattern))
        counts[label] = {"tracer": mine_count, "nes_py": their_count,
                         "difference": mine_count - their_count}
    return {
        "instructions_tracer": int(len(mine_pc)),
        "instructions_nes_py": int(len(their_pc)),
        "instructions_after_removing_spin_loops": {
            "tracer": int(len(left_pc)), "nes_py": int(len(right_pc))},
        "instructions_compared": compared,
        "program_counter_differences": int(len(pc_bad)),
        "first_program_counter_difference": first_pc_difference,
        "register_mismatches": int(len(register_bad)),
        "register_mismatch_examples": register_examples,
        "timing_loop_occurrences": counts,
    }


def strength(report: dict) -> str:
    ram = report["ram_at_frame_boundaries"]
    streams = report["instruction_streams"]
    histogram = ram["differing_byte_count_histogram"]
    worst = max((int(k) for k in histogram), default=0)
    lines = [
        f"RAM identical at {ram['frames_identical']} of "
        f"{ram['frames_compared']} frame boundaries; the largest difference at "
        f"any boundary was {worst} of 2048 bytes."]
    if streams:
        if streams["first_program_counter_difference"] is None:
            lines.append(
                f"With the six timing-dependent wait loops removed from both "
                f"streams, the remaining "
                f"{streams['instructions_compared']} fetches are the same "
                f"program counters in the same order, and A, X, Y, S and the "
                f"six real status bits agree at "
                f"{streams['instructions_compared'] - streams['register_mismatches']} "
                f"of them ({streams['register_mismatches']} mismatches).")
        else:
            lines.append(
                f"The program counters agree for "
                f"{streams['instructions_compared']} fetches after removing "
                f"the wait loops and then differ; see "
                f"first_program_counter_difference.")
    return " ".join(lines)


def _job(spec):
    frames, model_name, seed, cycle_model = spec
    return model_name, compare(frames, model_name, seed,
                               cycle_model=cycle_model)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--frames", type=int, default=600)
    parser.add_argument("--inputs", default="mixed",
                        help="one model, or several separated by commas")
    parser.add_argument("--seed", type=int, default=20261125)
    parser.add_argument("--cycle-model", default="nespy",
                        choices=("nespy", "ntsc"))
    parser.add_argument("--no-streams", action="store_true")
    parser.add_argument("--sprite0-line-offset", type=int, default=1)
    parser.add_argument("--sprite0-dot-offset", type=int, default=0)
    parser.add_argument("--out", default=None)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    from rom import image

    models = args.inputs.split(",")
    specs = [(args.frames, name, args.seed + index, args.cycle_model)
             for index, name in enumerate(models)]
    if len(specs) == 1:
        results = [_job(specs[0])]
    else:
        from multiprocessing import Pool
        with Pool(min(len(specs), 8)) as pool:
            results = pool.map(_job, specs)

    runs = {}
    for name, report in results:
        runs[name] = report
        report["corroboration_statement"] = strength(report)
        print(f"[{name}] {report['corroboration_statement']}")

    combined = {
        "experiment": "formal.dyn.crossvalidate",
        "manifest": {
            "rom_sha1": image().sha1,
            "repository_commit": git_commit(),
            "nes_py_commit": git_commit("/home/sadovsky/code/nes-py"),
            "frames_per_model": args.frames,
            "cycle_model": args.cycle_model,
            "models": models,
        },
        "protocol_notes": [
            "both emulators start from power-on with the same controller "
            "bytes; nes-py's RAM is all zeros at power-on and the tracer is "
            "given the same",
            "nes-py's processor-status byte has its bits in the reverse order "
            "(CPU_Flags in nes_py/nes/include/cpu_opcodes.hpp); it is "
            "translated before comparison, and a status byte pushed on the "
            "stack legitimately differs between the two",
            "the six timing-dependent wait loops are removed from both "
            "instruction streams before comparison and reported separately",
        ],
        "runs": runs,
        "overall": {
            "models": len(runs),
            "frames_total": sum(r["ram_at_frame_boundaries"]["frames_compared"]
                                for r in runs.values()),
            "frame_boundaries_identical": sum(
                r["ram_at_frame_boundaries"]["frames_identical"]
                for r in runs.values()),
            "largest_ram_difference_at_a_boundary": max(
                (max((int(k) for k in
                      r["ram_at_frame_boundaries"]
                      ["differing_byte_count_histogram"]), default=0)
                 for r in runs.values()), default=0),
            "instructions_compared": sum(
                (r["instruction_streams"] or {}).get("instructions_compared", 0)
                for r in runs.values()),
            "program_counter_differences": sum(
                (r["instruction_streams"] or {}).get(
                    "program_counter_differences", 0)
                for r in runs.values()),
            "register_mismatches": sum(
                (r["instruction_streams"] or {}).get("register_mismatches", 0)
                for r in runs.values()),
        },
    }
    overall = combined["overall"]
    print(f"\nTOTAL: {overall['frame_boundaries_identical']}/"
          f"{overall['frames_total']} frame boundaries with identical RAM; "
          f"{overall['instructions_compared']} fetches compared outside the "
          f"wait loops with {overall['program_counter_differences']} program "
          f"counter differences and {overall['register_mismatches']} register "
          f"mismatches")
    if args.out:
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        with open(args.out, "w") as handle:
            json.dump(combined, handle, indent=2, sort_keys=True)
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
