"""Instruction-level observations of the image (plan 15, at instruction grain).

Status of everything here: **observed**.  An observation over the inputs that
were run can refute a proposed invariant (a domain that excludes an observed
value is wrong) and it can produce a positive finding (a program counter that
is not an instruction start, an out-of-range dispatch index).  It can never
establish a bound.  `formal/verify/JOINT_INVARIANT.md` section 6 says the same.

Recorded, per run and merged across runs:

1. every program counter fetched, checked against the instruction starts of
   `analysis.cfg.build_from_vectors`, plus how much of that graph was executed;
2. the accumulator at the moment each of the 18 `JSR $8E04` dispatch sites is
   fetched, **per site**, with `(A and $7F)` compared against that site's own
   table length.  This is the site-specific census `experiments/observe_indices.py`
   could not do, because a frame sample cannot tell which dispatch was running;
3. the stack pointer's range over all fetches and at NMI entry, and every write
   into `$0100-$01FF`, attributed to the program counter that made it and split
   into pushes and non-pushes;
4. for every RAM cell, the set of values it held at NMI entry and the set of
   values ever written into it, written to `dyn_cell_domains.json`;
5. `RAM[$0733]` at `$9740`, `RAM[$071F]` at `$92B0`, bit 7 of `RAM[$0778]` at
   `$8168` (the JOINT_INVARIANT precondition for game logic running with NMI
   disabled), and whether an NMI was ever delivered while `$8082-$8181` was
   executing.

Two engines record these:

``tracer``  `formal.dyn.tracer`, which can see memory, so it records all five.
``nespy``   nes-py's native instruction tracer, which reports only registers at
            a fetch, so it records 1, 2, 3 (without the write attribution) and
            the NMI-entry stack pointer -- about twenty times faster, so those
            three can be run over far more frames.  Agreement between the two
            engines on the items both can see is reported.

    python3 -m formal.dyn.observe --engine tracer --frames 20000 --workers 8
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import random
import sys
import time
from multiprocessing import Pool

import numpy as np

from analysis.cfg import build_from_vectors
from analysis.decoder import decode

from . import inputs
from .crossvalidate import git_commit
from .tracer import NMI_PUSH_PC, from_rom

#: `JSR $8E04`, and the `JMP ($0006)` the JumpEngine ends with
JUMPENGINE = 0x8E04
JUMPENGINE_JMP = 0x8E16
#: the three single-cell questions of observation 5
WATCH_FETCHES = {
    0x9740: ("RAM[$0733] at the fetch of $9740", 0x0733),
    0x92B0: ("RAM[$071F] at the fetch of $92B0", 0x071F),
    0x8168: ("RAM[$0778] at the fetch of $8168", 0x0778),
}
#: instructions that read PPU data back; the stub models VRAM but not the
#: renderer's address updates, so these are counted to bound the exposure
VRAM_READERS = (0x8716, 0x8719)

PUSH_MNEMONICS = frozenset({"PHA", "PHP", "JSR", "BRK"})


def graph():
    from rom import b
    return build_from_vectors(b)


def dispatch_tables(cfg) -> dict[int, int]:
    return {site: len(info.entries) for site, info in cfg.dispatches.items()}


class Observation:
    """Merge-able accumulator for everything the runs record."""

    def __init__(self, sites: dict[int, int]):
        self.sites = dict(sites)
        self.pc_seen = bytearray(0x10000)
        self.pc_counts: collections.Counter = collections.Counter()
        self.sp_min = 0xFF
        self.sp_max = 0x00
        self.nmi_sp_min = 0xFF
        self.nmi_sp_max = 0x00
        self.dispatch_a = {site: bytearray(256) for site in sites}
        self.dispatch_hits: collections.Counter = collections.Counter()
        self.stack_writes: set[tuple[int, int]] = set()
        self.nmi_cells = np.zeros((0x800, 256), dtype=np.uint8)
        self.written_cells = np.zeros((0x800, 256), dtype=np.uint8)
        self.watch_values: dict[int, bytearray] = {
            pc: bytearray(256) for pc in WATCH_FETCHES}
        self.vram_reader_fetches = 0
        self.nmi_count = 0
        self.nmi_during_handler = 0
        self.enable_edge_nmis = 0
        self.frames = 0
        self.instructions = 0
        self.jams: collections.Counter = collections.Counter()
        #: cells watched for the run-level narrative (world, level, lives, ...)
        self.progress: dict[int, bytearray] = {}
        self.engines: collections.Counter = collections.Counter()
        self.seeds: list = []
        #: dispatches whose landing address was checked against the table
        self.dispatch_confirmed: collections.Counter = collections.Counter()
        #: (site, A, landed, expected) where the landing disagreed
        self.dispatch_mismatches: list = []
        #: (site, A) observed with (A and $7F) past the end of the table
        self.dispatch_oob: list = []

    def merge(self, other: "Observation") -> "Observation":
        for index, value in enumerate(other.pc_seen):
            if value:
                self.pc_seen[index] = 1
        self.pc_counts.update(other.pc_counts)
        self.sp_min = min(self.sp_min, other.sp_min)
        self.sp_max = max(self.sp_max, other.sp_max)
        self.nmi_sp_min = min(self.nmi_sp_min, other.nmi_sp_min)
        self.nmi_sp_max = max(self.nmi_sp_max, other.nmi_sp_max)
        for site, bitmap in other.dispatch_a.items():
            mine = self.dispatch_a.setdefault(site, bytearray(256))
            for value, flag in enumerate(bitmap):
                if flag:
                    mine[value] = 1
        self.dispatch_hits.update(other.dispatch_hits)
        self.stack_writes |= other.stack_writes
        if other.nmi_cells.size:
            if self.nmi_cells.size:
                np.bitwise_or(self.nmi_cells, other.nmi_cells,
                              out=self.nmi_cells)
            else:
                self.nmi_cells = other.nmi_cells.copy()
        if other.written_cells.size:
            if self.written_cells.size:
                np.bitwise_or(self.written_cells, other.written_cells,
                              out=self.written_cells)
            else:
                self.written_cells = other.written_cells.copy()
        for pc, bitmap in other.watch_values.items():
            mine = self.watch_values.setdefault(pc, bytearray(256))
            for value, flag in enumerate(bitmap):
                if flag:
                    mine[value] = 1
        for cell, bitmap in other.progress.items():
            mine = self.progress.setdefault(cell, bytearray(256))
            for value, flag in enumerate(bitmap):
                if flag:
                    mine[value] = 1
        self.vram_reader_fetches += other.vram_reader_fetches
        self.nmi_count += other.nmi_count
        self.nmi_during_handler += other.nmi_during_handler
        self.enable_edge_nmis += other.enable_edge_nmis
        self.frames += other.frames
        self.instructions += other.instructions
        self.jams.update(other.jams)
        self.engines.update(other.engines)
        self.seeds.extend(other.seeds)
        self.dispatch_confirmed.update(other.dispatch_confirmed)
        self.dispatch_mismatches.extend(other.dispatch_mismatches)
        self.dispatch_oob.extend(other.dispatch_oob)
        return self


#: RAM cells whose observed values say what the input model actually reached
PROGRESS_CELLS = {
    0x075F: "world number",
    0x0760: "level number",
    0x075A: "lives",
    0x0770: "operating mode (0 title, 1 game, 2 game over, 3 demo)",
    0x0772: "game-engine sub-routine selector",
    0x0E: "player state",
    0x0757: "warp zone control",
}


def run_tracer(frames: int, model_name: str, seed: int) -> Observation:
    """Record everything with the py65-based tracer."""
    cfg = graph()
    cfg_sites = dispatch_tables(cfg)
    entries = {site: info.entries for site, info in cfg.dispatches.items()}
    state = Observation(cfg_sites)
    state.engines["tracer"] = 1
    state.seeds.append({"engine": "tracer", "model": model_name,
                        "seed": seed, "frames": frames})
    tracer = from_rom(track_writes=True)
    button = inputs.model(model_name)
    rng = random.Random(seed)
    mpu = tracer.mpu
    ram = tracer.ram

    special = bytearray(0x10000)
    site_list = sorted(cfg_sites)
    for index, site in enumerate(site_list):
        special[site] = index + 1
    for offset, pc in enumerate(sorted(WATCH_FETCHES)):
        special[pc] = 100 + offset
    for pc in VRAM_READERS:
        special[pc] = 200
    special[JUMPENGINE_JMP] = 150

    pc_seen = state.pc_seen
    dispatch_a = state.dispatch_a
    watch_values = state.watch_values
    watch_cell = {pc: WATCH_FETCHES[pc][1] for pc in WATCH_FETCHES}
    watch_order = sorted(WATCH_FETCHES)
    nmi_cells = np.zeros((0x800, 256), dtype=np.uint8)
    cell_index = np.arange(0x800)
    progress = {cell: bytearray(256) for cell in PROGRESS_CELLS}

    counters = {"sp_min": 0xFF, "sp_max": 0, "nmi_sp_min": 0xFF,
                "nmi_sp_max": 0, "vram": 0}
    #: [armed, site, accumulator]: the JumpEngine's `JMP ($0006)` was the last
    #: instruction fetched, so the next fetch is the dispatch's landing point
    armed = [False, 0, 0]

    def on_fetch(pc, _pc_seen=pc_seen, _special=special, _mpu=mpu,
                 _c=counters, _armed=armed):
        _pc_seen[pc] = 1
        sp = _mpu.sp
        if sp < _c["sp_min"]:
            _c["sp_min"] = sp
        if sp > _c["sp_max"]:
            _c["sp_max"] = sp
        if _armed[0]:
            # the landing point of the dispatch that was armed at its site:
            # check it against that site's own table, which is a dynamic
            # counterpart of the D-xxxx-CONTRACT lemmas
            _armed[0] = False
            site, accumulator = _armed[1], _armed[2]
            table = entries[site]
            index = accumulator & 0x7F
            if index >= len(table):
                state.dispatch_oob.append(
                    (site, accumulator, pc, len(table)))
            elif pc != table[index]:
                state.dispatch_mismatches.append(
                    (site, accumulator, pc, table[index]))
            else:
                state.dispatch_confirmed[site] += 1
        code = _special[pc]
        if code:
            if code <= 18:
                site = site_list[code - 1]
                dispatch_a[site][_mpu.a] = 1
                state.dispatch_hits[site] += 1
                _armed[1] = site
                _armed[2] = _mpu.a
            elif code == 150:
                _armed[0] = True
            elif code >= 200:
                _c["vram"] += 1
            else:
                target = watch_order[code - 100]
                watch_values[target][ram[watch_cell[target] & 0x7FF]] = 1

    def on_nmi(pc, sp, _c=counters):
        if sp < _c["nmi_sp_min"]:
            _c["nmi_sp_min"] = sp
        if sp > _c["nmi_sp_max"]:
            _c["nmi_sp_max"] = sp
        nmi_cells[cell_index, np.frombuffer(bytes(ram), dtype=np.uint8)] = 1

    for frame in range(frames):
        tracer.run_frame(button(rng, frame, ram),
                         on_fetch=on_fetch, on_nmi=on_nmi)
        if tracer.jammed:
            state.jams[f"0x{tracer.jammed[0]:04X}"] += 1
            break
        for cell in progress:
            progress[cell][ram[cell & 0x7FF]] = 1

    state.sp_min = counters["sp_min"]
    state.sp_max = counters["sp_max"]
    state.nmi_sp_min = counters["nmi_sp_min"]
    state.nmi_sp_max = counters["nmi_sp_max"]
    state.vram_reader_fetches = counters["vram"]
    state.nmi_cells = nmi_cells
    written = np.frombuffer(bytes(tracer.bus.written),
                            dtype=np.uint8).reshape(0x800, 256)
    state.written_cells = written.copy()
    state.stack_writes = set(tracer.bus.stack_writes)
    state.nmi_count = tracer.nmi_count
    state.nmi_during_handler = tracer.nmi_during_handler
    state.enable_edge_nmis = tracer.ppu.enable_edge_nmis
    state.frames = tracer.frame
    state.instructions = tracer.instructions
    state.progress = progress
    return state


def run_nespy(frames: int, model_name: str, seed: int) -> Observation:
    """Record observations 1, 2 and 3 with nes-py's native tracer."""
    from rom import image

    from .nespy import TracedNESEnv

    cfg_sites = dispatch_tables(graph())
    state = Observation(cfg_sites)
    state.engines["nespy"] = 1
    state.seeds.append({"engine": "nespy", "model": model_name,
                        "seed": seed, "frames": frames})
    env = TracedNESEnv(image().path, record_all=True)
    button = inputs.model(model_name)
    rng = random.Random(seed)
    sites = np.array(sorted(cfg_sites), dtype=np.uint16)
    seen = np.zeros(0x10000, dtype=np.uint8)
    progress = {cell: bytearray(256) for cell in PROGRESS_CELLS}
    sp_min, sp_max = 0xFF, 0
    nmi_sp_min, nmi_sp_max = 0xFF, 0
    instructions = 0
    nmi_count = 0
    for frame in range(frames):
        events = env.step(button(rng, frame, env.ram))
        if not len(events):
            continue
        instructions += len(events)
        pcs = events["pc"]
        seen[pcs] = 1
        stacks = events["sp"]
        sp_min = min(sp_min, int(stacks.min()))
        sp_max = max(sp_max, int(stacks.max()))
        hits = np.isin(pcs, sites)
        if hits.any():
            for pc, accumulator in zip(pcs[hits], events["a"][hits]):
                state.dispatch_a[int(pc)][int(accumulator)] = 1
                state.dispatch_hits[int(pc)] += 1
        handler = pcs == 0x8082
        if handler.any():
            # the stack pointer at NMI entry is three pushes above the one the
            # handler's first instruction sees
            entry = (events["sp"][handler].astype(np.int16) + 3) & 0xFF
            nmi_sp_min = min(nmi_sp_min, int(entry.min()))
            nmi_sp_max = max(nmi_sp_max, int(entry.max()))
            nmi_count += int(handler.sum())
        ram = env.ram
        for cell in progress:
            progress[cell][ram[cell]] = 1
    env.close()
    state.pc_seen = bytearray(seen.tolist())
    state.sp_min, state.sp_max = sp_min, sp_max
    state.nmi_sp_min, state.nmi_sp_max = nmi_sp_min, nmi_sp_max
    state.frames = frames
    state.instructions = instructions
    state.nmi_count = nmi_count
    state.progress = progress
    return state


def _job(spec):
    engine, frames, model_name, seed = spec
    sys.path.insert(0, os.getcwd())
    if engine == "tracer":
        return run_tracer(frames, model_name, seed)
    return run_nespy(frames, model_name, seed)


def ranges(values: list[int]) -> list:
    """Compact a sorted value list into singletons and [lo, hi] ranges."""
    out: list = []
    for value in values:
        if out and isinstance(out[-1], list) and out[-1][1] == value - 1:
            out[-1][1] = value
        elif out and not isinstance(out[-1], list) and out[-1] == value - 1:
            out[-1] = [out[-1], value]
        else:
            out.append(value)
    return out


def summarise(state: Observation, cfg) -> dict:
    from rom import b

    starts = cfg.instruction_starts
    executed = {pc for pc, flag in enumerate(state.pc_seen) if flag}
    outside = sorted(executed - starts)
    in_rom = {pc for pc in executed if pc >= 0x8000}

    # A check that does not use analysis.cfg at all: decode every program
    # counter that was executed and see whether any of them lies strictly
    # inside another one's bytes.  If execution had ever run misaligned, the
    # misaligned stream and the aligned one would both be in the set and would
    # overlap.  An empty result is independent corroboration of the claim that
    # every fetch was at an instruction start.
    known_overlaps = {(outer, inner)
                      for inner, outers in cfg.overlapping_starts().items()
                      for outer in outers}
    overlaps = []
    for pc in sorted(in_rom):
        try:
            length = decode(b, pc).info.length
        except Exception:
            continue
        for offset in range(1, length):
            inside = (pc + offset) & 0xFFFF
            if inside in executed:
                overlaps.append((pc, inside))
    unexpected_overlaps = [pair for pair in overlaps
                           if pair not in known_overlaps]

    # The table lengths come from analysis.dispatch_tables' boundary evidence.
    # A length that is too large would hide an out-of-range index, so the
    # heuristic reader's length is reported beside it and the index is also
    # compared against the smaller of the two.
    heuristic = dispatch_tables(build_from_vectors(b,
                                                   established_boundaries=False))

    dispatch_report = []
    out_of_range = []
    for site in sorted(state.sites):
        entries = state.sites[site]
        values = [value for value, flag in enumerate(state.dispatch_a[site])
                  if flag]
        indices = sorted({(value & 0x7F) for value in values})
        bad = [index for index in indices if index >= entries]
        smallest = min(entries, heuristic.get(site, entries))
        dispatch_report.append({
            "site": f"0x{site:04X}",
            "table_entries": entries,
            "table_entries_heuristic_reader": heuristic.get(site),
            "out_of_range_against_the_smaller_count": [
                index for index in indices if index >= smallest],
            "fetches": state.dispatch_hits.get(site, 0),
            "landings_confirmed_against_the_table":
                state.dispatch_confirmed.get(site, 0),
            "distinct_a": len(values),
            "a_values": ranges(values),
            "index_min": min(indices) if indices else None,
            "index_max": max(indices) if indices else None,
            "out_of_range_indices": bad,
        })
        if bad:
            out_of_range.append({"site": f"0x{site:04X}",
                                 "table_entries": entries,
                                 "indices": bad})

    pushes = []
    non_pushes = []
    from rom import b
    for pc, cell in sorted(state.stack_writes):
        address = 0x0100 | (cell & 0xFF)
        if pc == NMI_PUSH_PC:
            pushes.append({"pc": "NMI entry sequence",
                           "address": f"0x{address:04X}"})
            continue
        try:
            instruction = decode(b, pc) if pc >= 0x8000 else None
        except Exception:
            instruction = None
        mnemonic = instruction.info.mnemonic if instruction else "?"
        record = {"pc": f"0x{pc:04X}", "mnemonic": mnemonic,
                  "address": f"0x{address:04X}"}
        (pushes if mnemonic in PUSH_MNEMONICS else non_pushes).append(record)

    by_pc: dict[str, list] = {}
    for record in non_pushes:
        by_pc.setdefault(f"{record['pc']} {record['mnemonic']}",
                         []).append(record["address"])

    watch = {}
    for pc in sorted(WATCH_FETCHES):
        label, cell = WATCH_FETCHES[pc]
        values = [value for value, flag in enumerate(state.watch_values[pc])
                  if flag]
        watch[f"0x{pc:04X}"] = {
            "question": label,
            "cell": f"0x{cell:04X}",
            "values": ranges(values),
            "distinct": len(values),
            "max": max(values) if values else None,
            "bit7_set_seen": any(value & 0x80 for value in values),
            "bit7_clear_seen": any(not value & 0x80 for value in values),
        }

    progress = {
        f"0x{cell:04X} {PROGRESS_CELLS[cell]}":
            ranges([v for v, flag in enumerate(bitmap) if flag])
        for cell, bitmap in sorted(state.progress.items())
    }

    return {
        "dispatch_landings": {
            "checked": sum(state.dispatch_confirmed.values()),
            "landed_where_the_table_says": sum(
                state.dispatch_confirmed.values()),
            "landed_elsewhere": [
                {"site": f"0x{site:04X}", "a": a, "landed": f"0x{landed:04X}",
                 "table_entry": f"0x{expected:04X}"}
                for site, a, landed, expected in state.dispatch_mismatches],
            "index_past_the_end_of_the_table": [
                {"site": f"0x{site:04X}", "a": a, "index": a & 0x7F,
                 "landed": f"0x{landed:04X}", "table_entries": length}
                for site, a, landed, length in state.dispatch_oob],
            "note": ("each fetch of a dispatch site arms a check: the first "
                     "fetch after the JumpEngine's JMP ($0006) must be the "
                     "table entry that (A and $7F) selects.  This is the "
                     "dynamic counterpart of the D-xxxx-CONTRACT lemmas and "
                     "is only recorded by the tracer engine."),
        },
        "fetched_program_counters": {
            "distinct": len(executed),
            "distinct_in_prg": len(in_rom),
            "outside_prg": sorted(pc for pc in executed if pc < 0x8000),
            "graph_instruction_starts": len(starts),
            "graph_nodes_executed": len(in_rom & starts),
            "graph_coverage": round(len(in_rom & starts) / len(starts), 6),
            "fetched_but_not_an_instruction_start": [
                f"0x{pc:04X}" for pc in outside],
            "fetched_but_not_an_instruction_start_count": len(outside),
            "executed_instructions_that_overlap": [
                [f"0x{outer:04X}", f"0x{inner:04X}"] for outer, inner
                in overlaps],
            "executed_instructions_that_overlap_count": len(overlaps),
            "overlapping_pairs_the_graph_does_not_already_record": [
                [f"0x{outer:04X}", f"0x{inner:04X}"] for outer, inner
                in unexpected_overlaps],
            "overlap_check_note": (
                "computed by decoding the executed addresses directly: for "
                "each executed program counter, is any interior byte of its "
                "instruction also an executed program counter?  The image "
                "has ten such pairs of its own, each a `BIT $nnnn` whose "
                "operand byte is the entry point of an immediate load, and "
                "analysis.cfg records all ten.  A pair outside that set "
                "would mean the stream ran misaligned, and this check does "
                "not use the graph's edges to say so."),
        },
        "dispatch_sites": dispatch_report,
        "dispatch_out_of_range": out_of_range,
        "stack_pointer": {
            "min_at_any_fetch": state.sp_min,
            "max_at_any_fetch": state.sp_max,
            "min_at_nmi_entry": state.nmi_sp_min,
            "max_at_nmi_entry": state.nmi_sp_max,
            "depth_max_from_0xFF": 0xFF - state.sp_min,
        },
        "stack_page_writes": {
            "distinct_pc_address_pairs": len(state.stack_writes),
            "push_pairs": len(pushes),
            "non_push_pairs": len(non_pushes),
            "non_push_writers": by_pc,
        },
        "single_cell_questions": watch,
        "nmi": {
            "entries": state.nmi_count,
            "delivered_while_handler_running": state.nmi_during_handler,
            "delivered_by_a_0_to_1_enable_write_during_vblank":
                state.enable_edge_nmis,
        },
        "ppu_data_reader_fetches": state.vram_reader_fetches,
        "input_model_reach": progress,
        "jams": dict(state.jams),
    }


def cell_domains(state: Observation) -> dict:
    nmi = {}
    written = {}
    for cell in range(0x800):
        if state.nmi_cells.size:
            values = np.nonzero(state.nmi_cells[cell])[0].tolist()
            if values:
                nmi[f"0x{cell:04X}"] = ranges(values)
        if state.written_cells.size:
            values = np.nonzero(state.written_cells[cell])[0].tolist()
            if values:
                written[f"0x{cell:04X}"] = ranges(values)
    return {"at_nmi_entry": nmi, "ever_written": written}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", default="tracer",
                        choices=("tracer", "nespy"))
    parser.add_argument("--frames", type=int, default=6000,
                        help="frames per worker")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--models", default="mixed,run,explore,random")
    parser.add_argument("--seed", type=int, default=20261125)
    parser.add_argument("--out", default=None)
    parser.add_argument("--domains-out", default=None)
    args = parser.parse_args(argv)

    from rom import image

    models = args.models.split(",")
    specs = [(args.engine, args.frames, models[index % len(models)],
              args.seed + index) for index in range(args.workers)]
    started = time.time()
    if args.workers == 1:
        results = [_job(specs[0])]
    else:
        with Pool(args.workers) as pool:
            results = pool.map(_job, specs)
    merged = results[0]
    for other in results[1:]:
        merged.merge(other)
    elapsed = time.time() - started

    cfg = graph()
    report = {
        "experiment": "formal.dyn.observe",
        "status": "observed",
        "manifest": {
            "rom_sha1": image().sha1,
            "repository_commit": git_commit(),
            "nes_py_commit": git_commit("/home/sadovsky/code/nes-py"),
            "engine": args.engine,
            "workers": args.workers,
            "frames_per_worker": args.frames,
            "frames_total": merged.frames,
            "instructions_total": merged.instructions,
            "runs": merged.seeds,
            "input_models": {name: inputs.describe(name)
                             for name in sorted(set(models))},
            "wall_seconds": round(elapsed, 1),
            "cross_validation": (
                "see formal/results/reports/dyn_crossvalidation.json; the "
                "tracer engine is the one validated there"),
        },
        "limitations": [
            "observed over the inputs that were run; no bound follows",
            "the device stub is not a PPU or APU (formal.dyn.tracer lists what "
            "it does not model)",
            "the nespy engine sees registers at a fetch only, so it cannot "
            "record cell domains, the single-cell questions, or write "
            "attribution",
        ],
        **summarise(merged, cfg),
    }
    print(json.dumps({k: report[k] for k in (
        "fetched_program_counters", "stack_pointer", "nmi",
        "dispatch_out_of_range")}, indent=2)[:4000])
    print(f"frames {merged.frames}, instructions {merged.instructions}, "
          f"{elapsed:.0f}s")
    if args.out:
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        with open(args.out, "w") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
        print(f"wrote {args.out}")
    if args.domains_out and args.engine == "tracer":
        domains = cell_domains(merged)
        domains["manifest"] = report["manifest"]
        domains["status"] = "observed"
        domains["reading"] = (
            "at_nmi_entry[cell] is the set of values the cell held at an NMI "
            "entry, i.e. at a frame boundary with the handler about to run. "
            "ever_written[cell] is the set of values any instruction wrote "
            "into it. A value is written as an integer, a run as [lo, hi]. "
            "A cell absent from a map was never observed in that role.")
        os.makedirs(os.path.dirname(args.domains_out), exist_ok=True)
        with open(args.domains_out, "w") as handle:
            json.dump(domains, handle, indent=2, sort_keys=True)
        print(f"wrote {args.domains_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
