"""Counterexample search for the model variant `T` (no timing assumptions).

**This is not a claim about hardware.**  `formal/model/transitions.py` admits
an NMI at *any* instruction boundary while the ghost enable bit is set, which
is an over-approximation: a console needs a rising edge of (vblank AND enable)
and so needs a new vertical blank, tens of thousands of cycles later.
`formal/verify/JOINT_INVARIANT.md` section 1 names the two timing assumptions
that remove the behaviour this module exercises (`MA-NMI-EDGE`,
`MA-NMI-LATENCY`) and states the belief that without them the theorem is false
*in the model*, with a stack-wrap argument and no concrete trace.  This
produces the trace.

The experiment.  Run the image normally until the idle loop `JMP $8057`, which
is where the reset path parks with the stack empty.  Then deliver `k` NMI
entries back to back, each one taken at the boundary *before* the handler's
first instruction at `$8082`, so no handler instruction ever runs and nothing
is popped.  Each entry pushes three bytes, 256 is not a multiple of three, so
after 86 entries the stack pointer has wrapped the page and the frames written
after the wrap are three-byte-misaligned with the frames written before it.
Then stop forcing NMIs and let the machine run.  The handler finally executes,
and its `RTI` pulls a status byte and a return address out of bytes that were
written as *different* frames.

Reported for each variant: the stack-pointer trajectory, the bytes the first
`RTI` pulled and the address it jumped to, whether that address is an
instruction start of `analysis.cfg`, whether the program counter ever leaves
the graph, whether it ever leaves `$8000-$FFFF`, how many instructions that
took, and every device read the run resolved on the way, because in `T` each
of those reads is an unconstrained byte and this run fixes one choice of them.

    python3 -m formal.dyn.nmi_storm [--entries 86,87,...] [--warmup 400,...]
"""
from __future__ import annotations

import argparse
import json
import os
import time

from analysis.cfg import build_from_vectors
from analysis.decoder import decode

from . import inputs
from .crossvalidate import git_commit
from .cpu6502 import JAM_OPCODES
from .tracer import NMI_PUSH_PC, from_rom

IDLE_LOOP = 0x8057
HANDLER_ENTRY = 0x8082
HANDLER_RTI = 0x8181


class StopRun(Exception):
    """Raised out of an `on_fetch` hook to end a run at a chosen fetch."""


def storm(entries: int, warmup_frames: int, *, model_name: str = "run",
          seed: int = 1, budget: int = 200_000, trace_limit: int = 120,
          tail_limit: int = 40, follow: int = 40,
          cycle_model: str = "ntsc") -> dict:
    """One variant: `entries` forced NMI entries, then run until derailment."""
    import collections
    import random

    from rom import b, image

    cfg = build_from_vectors(b)
    starts = cfg.instruction_starts
    tracer = from_rom(image().path, track_writes=True,
                      cycle_model=cycle_model)
    button = inputs.model(model_name)
    rng = random.Random(seed)

    # -- 1. a normal running game state
    for frame in range(warmup_frames):
        tracer.run_frame(button(rng, frame, tracer.ram))
    # -- 2. park on the idle loop with an empty stack
    reached_idle = False
    for _ in range(60_000):
        if tracer.mpu.pc == IDLE_LOOP and tracer.mpu.sp == 0xFF:
            reached_idle = True
            break
        tracer.run_until(tracer.cycle + 1)
    if not reached_idle:
        return {"entries_forced": entries, "warmup_frames": warmup_frames,
                "error": "the idle loop with an empty stack was not reached"}

    state_at_storm = tracer.snapshot()
    sp_trajectory = [tracer.mpu.sp]
    mpu = tracer.mpu
    counter = {"forced": 0, "stack_page": None}
    trace: list[dict] = []
    tail = collections.deque(maxlen=tail_limit)
    rti_pulls: list[dict] = []
    rts_pulls: list[dict] = []
    returns = collections.Counter()
    follow_trace: list[dict] = []
    first_bad = None
    tracer.bus.read_log = []
    limit = tracer.instructions + budget
    before_instructions = tracer.instructions
    before_nmis = tracer.nmi_count

    def override(_tracer):
        if counter["forced"] >= entries:
            if counter["stack_page"] is None:
                counter["stack_page"] = bytes(_tracer.bus.ram[0x100:0x200])
            return None
        counter["forced"] += 1
        return True

    def on_nmi(pc, sp):
        sp_trajectory.append(sp)

    def on_fetch(pc):
        nonlocal first_bad
        opcode = tracer.bus[pc]
        # The opcode byte is deliberately not recorded: these traces run to
        # thousands of records and the repository does not redistribute the
        # image's bytes (see formal/README.md on `*.rom.smt2`).  Addresses and
        # register contents are enough to replay the trace against the image,
        # and the handful of instructions that run off the graph are named in
        # `trace_after_leaving_the_graph` instead.
        record = {"pc": f"0x{pc:04X}",
                  "in_graph": pc in starts, "a": mpu.a, "x": mpu.x,
                  "y": mpu.y, "sp": mpu.sp, "p": mpu.p}
        if first_bad is None:
            # the tail is frozen at the moment of the stop, so it shows what
            # led up to it rather than what the follow-on trace appended
            if len(trace) < trace_limit:
                trace.append(record)
            tail.append(record)
        if opcode in (0x60, 0x40):
            is_rti = opcode == 0x40
            returns["RTI" if is_rti else "RTS"] += 1
            offset = 1 if is_rti else 0
            low = tracer.bus.ram[0x100 | ((mpu.sp + 1 + offset) & 0xFF)]
            high = tracer.bus.ram[0x100 | ((mpu.sp + 2 + offset) & 0xFF)]
            target = ((high << 8 | low) + (0 if is_rti else 1)) & 0xFFFF
            pull = {
                "instruction": "RTI" if is_rti else "RTS",
                "at_pc": f"0x{pc:04X}",
                "sp_before": mpu.sp,
                "pulled_bytes": (
                    [f"0x{tracer.bus.ram[0x100 | ((mpu.sp + 1 + k) & 0xFF)]:02X}"
                     for k in range(3 if is_rti else 2)]),
                "target": f"0x{target:04X}",
                "target_is_instruction_start": target in starts,
                "target_in_prg": target >= 0x8000,
            }
            if is_rti:
                writers = tracer.bus.last_stack_writer
                pull["pulled_from"] = [
                    f"0x{0x100 | ((mpu.sp + 1 + k) & 0xFF):04X}"
                    for k in range(3)]
                pull["last_written_by"] = [
                    ("NMI entry sequence"
                     if writers[(mpu.sp + 1 + k) & 0xFF] == NMI_PUSH_PC
                     else "never written in this run"
                     if writers[(mpu.sp + 1 + k) & 0xFF] is None
                     else f"0x{writers[(mpu.sp + 1 + k) & 0xFF]:04X} "
                          + describe_pc(writers[(mpu.sp + 1 + k) & 0xFF]))
                    for k in range(3)]
                rti_pulls.append(pull)
            elif len(rts_pulls) < 24:
                rts_pulls.append(pull)
        if first_bad is not None:
            follow_trace.append({**record, "decoded": describe_pc(pc)})
            if len(follow_trace) >= follow:
                raise StopRun
            return
        if pc < 0x8000:
            first_bad = ("fetch outside PRG", pc,
                         tracer.instructions - before_instructions)
            follow_trace.append({**record, "decoded": describe_pc(pc)})
            return
        if pc not in starts:
            first_bad = ("fetch at an address that is not an instruction start",
                         pc, tracer.instructions - before_instructions)
            follow_trace.append({**record, "decoded": describe_pc(pc)})
            return
        if tracer.instructions >= limit:
            raise StopRun

    try:
        tracer.run_until(float("inf"), on_fetch=on_fetch, on_nmi=on_nmi,
                         nmi_override=override)
    except StopRun:
        pass

    outcome = {"stopped": "instruction budget exhausted",
               "instructions_after_storm":
                   tracer.instructions - before_instructions,
               "nmi_entries_total": tracer.nmi_count - before_nmis,
               "returns_executed": dict(returns),
               "rti_pulls": rti_pulls,
               "rts_pulls_first_24": rts_pulls}
    if first_bad:
        kind, pc, reached = first_bad
        outcome["stopped"] = kind
        outcome["stop_pc"] = f"0x{pc:04X}"
        outcome["stop_pc_meaning"] = describe_pc(pc)
        outcome["instructions_from_storm_to_stop"] = reached
    if tracer.jammed:
        outcome["jammed_at"] = f"0x{tracer.jammed[0]:04X}"
        outcome["jam_opcode"] = f"0x{tracer.jammed[1]:02X}"

    page = counter["stack_page"] or bytes(tracer.bus.ram[0x100:0x200])
    reads = tracer.bus.read_log
    read_summary = collections.Counter(
        (address, value) for _pc, address, value in reads)
    return {
        "entries_forced": entries,
        "entries_delivered": len(sp_trajectory) - 1,
        "warmup_frames": warmup_frames,
        "input_model": model_name,
        "seed": seed,
        "cycle_model": cycle_model,
        "state_at_storm_start": {
            **{k: v for k, v in state_at_storm.items() if k != "pc"},
            "pc": f"0x{state_at_storm['pc']:04X}"},
        "stack_pointer": {
            "before_storm": sp_trajectory[0],
            "at_each_entry_first_eight": sp_trajectory[:8],
            "at_each_entry_last_eight": sp_trajectory[-8:],
            "after_storm": (0xFF - 3 * entries) & 0xFF,
            "wrapped_the_page": entries >= 86,
            "distinct_values": len(set(sp_trajectory)),
        },
        "stack_page_after_storm": {
            "distinct_byte_values": [f"0x{value:02X}"
                                     for value in sorted(set(page))],
            "byte_histogram": {f"0x{value:02X}": count for value, count
                               in sorted(collections.Counter(page).items())},
        },
        "outcome": outcome,
        "trace_from_the_storm": trace,
        "trace_tail_before_stop": list(tail),
        "trace_after_leaving_the_graph": follow_trace,
        "device_reads": {
            "total": len(reads),
            "distinct_address_value_pairs": [
                {"address": f"0x{address:04X}", "value": f"0x{value:02X}",
                 "times": count}
                for (address, value), count in read_summary.most_common(24)],
        },
    }


def describe_pc(pc: int) -> str:
    from rom import b
    if pc < 0x8000:
        return "not in PRG: a fetch from RAM, the register area or open bus"
    try:
        instruction = decode(b, pc)
    except Exception:
        return "undecodable"
    return (f"{instruction.info.mnemonic} {instruction.info.mode}"
            + (" (undocumented)" if not instruction.info.documented else "")
            + (" (JAM)" if instruction.info.opcode in JAM_OPCODES else ""))


def _job(spec):
    entries, warmup, model_name, seed, budget, cycle_model = spec
    return storm(entries, warmup, model_name=model_name, seed=seed,
                 budget=budget, cycle_model=cycle_model)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--entries",
                        default="1,2,3,42,85,86,87,88,89,90,129,171,172,256")
    parser.add_argument("--warmup", default="200,400,900")
    parser.add_argument("--model", default="advance")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--budget", type=int, default=200000)
    parser.add_argument("--cycle-model", default="ntsc",
                        choices=("ntsc", "nespy"))
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--out", default=None)
    args = parser.parse_args(argv)

    from rom import image

    counts = [int(value) for value in args.entries.split(",")]
    warmups = [int(value) for value in args.warmup.split(",")]
    specs = [(entries, warmup, args.model, args.seed, args.budget,
              args.cycle_model)
             for warmup in warmups for entries in counts]
    started = time.time()
    if args.workers > 1 and len(specs) > 1:
        from multiprocessing import Pool
        with Pool(min(args.workers, len(specs))) as pool:
            variants = pool.map(_job, specs)
    else:
        variants = [_job(spec) for spec in specs]

    escaped = 0
    for result in variants:
        outcome = result.get("outcome", {})
        stack = result.get("stack_pointer", {})
        if outcome.get("stopped", "").startswith("fetch"):
            escaped += 1
        print(f"warmup {result['warmup_frames']:4} "
              f"entries {result['entries_forced']:4}: "
              f"S {stack.get('before_storm')} -> {stack.get('after_storm')}"
              f"{' (wrapped)' if stack.get('wrapped_the_page') else ''}, "
              f"{outcome.get('returns_executed', {}).get('RTI', 0)} RTI, "
              f"stopped: {outcome.get('stopped')} "
              f"{outcome.get('stop_pc', '')} after "
              f"{outcome.get('instructions_from_storm_to_stop', outcome.get('instructions_after_storm'))}"
              f" instructions")

    report = {
        "experiment": "formal.dyn.nmi_storm",
        "status": "abstract_counterexample_search",
        "model_variant": "T, formal/model/transitions.py without "
                         "MA-NMI-EDGE and without MA-NMI-LATENCY",
        "not_a_hardware_claim": (
            "An NMI is taken here at an instruction boundary chosen by the "
            "experiment, not by a vertical blank.  No NES can deliver two NMI "
            "entries without a new vblank between them, so nothing in this "
            "report says anything about what a console does.  It is a "
            "concrete witness for the model variant T, which admits these "
            "boundaries, and therefore evidence that the two timing "
            "assumptions are load-bearing rather than cosmetic."),
        "what_the_witness_shows": (
            "In T, from a state the image reaches in ordinary play, the "
            "program counter can be made to leave $8000-$FFFF entirely, which "
            "refutes the fetch-from-ROM property for that variant. It says "
            "nothing about T_V2, in which the behaviour is excluded by "
            "assumption, and nothing about hardware."),
        "manifest": {
            "rom_sha1": image().sha1,
            "repository_commit": git_commit(),
            "tracer": "formal.dyn.tracer with the device stub it documents",
            "cycle_model": args.cycle_model,
            "variants": len(variants),
            "variants_whose_pc_left_the_graph_or_prg": escaped,
            "device_read_resolution": (
                "every device read is resolved by the stub: $2002 from the "
                "dot counter, $4016 from the scripted pad, everything else 0. "
                "In T each such read is an unconstrained byte, so this run "
                "fixes one choice out of 256 per read; the reads the run "
                "actually made are listed per variant."),
            "wall_seconds": round(time.time() - started, 1),
        },
        "variants": variants,
    }
    if args.out:
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        with open(args.out, "w") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
