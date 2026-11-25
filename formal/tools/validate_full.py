"""Run `formal/model/cpu.py` on *every* SingleStepTests nes6502 vector.

`formal.validate_model` samples the first 300 vectors per opcode.  This runs
all 10,000 per opcode (2,560,000 recorded instructions) through the same
definition, which is the Z3-term semantics the proofs are stated over -- there
is still no second "fast" interpreter, so what is validated is what is proved
about.

Three groups are reported separately and are never summed into one
"agreement" number:

* **stable** (237 opcodes) -- the model fixes every observable, so the vector
  either matches it exactly or is a mismatch.
* **havoc** (7 encodings: `XAA`, `LXA`, `SHA` x2, `SHX`, `SHY`, `TAS`) -- the
  model leaves a register or a memory write unconstrained, so there is nothing
  to agree with.  What *is* checked is whether the recorded outcome is
  **admitted** by the havoc: everything the model still fixes must match, and
  the recorded memory may differ from the initial memory in at most as many
  cells as the model performed unconstrained writes.  An inadmissible vector
  is a real finding: it would mean the over-approximation is unsound.
* **JAM** (12 encodings) -- the model halts and stops fetching.  The vectors
  record the bus activity of a jammed CPU, which is not an instruction
  outcome.  Not compared at all.

Concrete evaluation goes through Z3 terms, so it is slow (about 700
instructions per second per core).  The work is split over processes by
opcode; `--jobs` is capped at 5.

    python3 -m formal.tools.validate_full [--vectors DIR] [--jobs N]
"""
from __future__ import annotations

import argparse
import json
import multiprocessing
import os
import time

import z3

from analysis.decoder import OPCODES

from ..model.cpu import HAVOC, State, step
from ..model.memory import FlatMemory, as_int

DEFAULT_VECTORS = os.environ.get(
    "NES6502_VECTORS_FULL",
    os.path.expanduser("~/big/smb1-formal/harte-full"))

#: at most this many mismatching vectors are kept verbatim per opcode
MISMATCH_CAP = 200
MAX_JOBS = 5

#: status-byte bit positions of the flags that are registers.  Bit 4 (B) and
#: bit 5 are not: B only exists in a pushed copy, bit 5 always reads 1.
FLAG_BITS = {"c": 0, "z": 1, "i": 2, "d": 3, "v": 6, "n": 7}

JAM_OPCODES = frozenset(op for op, info in OPCODES.items()
                        if info.mnemonic == "JAM")
HAVOC_OPCODES = frozenset(op for op, info in OPCODES.items()
                          if info.mnemonic in HAVOC)


class HavocMemory(FlatMemory):
    """`FlatMemory` that counts unstable writes instead of refusing them.

    `FlatMemory.havoc_write` raises, because a concrete memory cannot hold an
    unconstrained byte at an unconstrained address.  For the admission test we
    do not need to represent it: we only need to know how many such writes
    happened, and that the instruction made no *concrete* write.  Memory is
    returned unchanged, so `writes` stays empty and the cells keep their
    initial values.
    """

    def __init__(self, cells=None, *, array=None, writes=(), log=None):
        super().__init__(cells, array=array, writes=writes)
        self.log = [] if log is None else log

    def havoc_write(self):
        self.log.append(True)
        return self


def _flag(term) -> int | None:
    """0, 1, or None when the model left the flag unconstrained."""
    term = z3.simplify(term)
    if z3.is_true(term):
        return 1
    if z3.is_false(term):
        return 0
    return None


def observe(state: State) -> dict:
    """Every architectural observable, with None where the model is open."""
    out = {"pc": state.pc if isinstance(state.pc, int) else as_int(state.pc)}
    for name in ("a", "x", "y", "s"):
        out[name] = as_int(getattr(state, name))
    for name in FLAG_BITS:
        out[name] = _flag(getattr(state, name))
    return out


def expected(final: dict) -> dict:
    out = {k: final[k] for k in ("pc", "a", "x", "y", "s")}
    for name, bit in FLAG_BITS.items():
        out[name] = final["p"] >> bit & 1
    return out


def _run(case: dict, *, havoc: bool):
    initial = case["initial"]
    cells = {address: value for address, value in initial["ram"]}
    memory = (HavocMemory(cells) if havoc else FlatMemory(cells))
    state = State.concrete(pc=initial["pc"], a=initial["a"], x=initial["x"],
                           y=initial["y"], s=initial["s"], p=initial["p"],
                           mem=memory)
    successors = step(state)
    return successors, memory


def check_stable(case: dict) -> dict | None:
    """None when the model reproduces the vector exactly."""
    successors, _ = _run(case, havoc=False)
    final = case["final"]
    if len(successors) != 1:
        return {"name": case["name"], "fault": "the model forked",
                "successors": len(successors)}
    after = successors[0].state
    got, want = observe(after), expected(final)
    differences = {k: {"vector": want[k], "model": got[k]}
                   for k in want if got[k] != want[k]}
    #: a concrete input must leave nothing unconstrained in a stable opcode
    symbolic = sorted(k for k in want if got[k] is None)
    final_cells = {address: value for address, value in final["ram"]}
    for address, value in final_cells.items():
        actual = as_int(after.mem.read(address)[0])
        if actual != value:
            differences[f"ram[${address:04X}]"] = {"vector": value,
                                                   "model": actual}
    outside = sorted({address for address, _ in after.mem.writes}
                     - set(final_cells))
    if not differences and not outside and not symbolic:
        return None
    report = {"name": case["name"], "initial": case["initial"],
              "final": final, "differences": differences}
    if outside:
        report["wrote_outside_the_vector"] = [f"${a:04X}" for a in outside]
    if symbolic:
        report["left_unconstrained"] = symbolic
    return report


def check_havoc(case: dict) -> dict | None:
    """None when the recorded outcome is admitted by the model's havoc."""
    successors, memory = _run(case, havoc=True)
    final = case["final"]
    if len(successors) != 1:
        return {"name": case["name"], "fault": "the model forked",
                "successors": len(successors)}
    after = successors[0].state
    got, want = observe(after), expected(final)
    #: only the observables the model still fixes can disagree
    differences = {k: {"vector": want[k], "model": got[k]}
                   for k in want if got[k] is not None and got[k] != want[k]}
    initial_cells = {address: value
                     for address, value in case["initial"]["ram"]}
    changed = sorted(address for address, value in final["ram"]
                     if initial_cells.get(address, 0) != value)
    unconstrained_writes = len(memory.log)
    concrete_writes = [a for a, _ in after.mem.writes]
    admitted = (not differences and not concrete_writes
                and len(changed) <= unconstrained_writes)
    if admitted:
        return None
    return {"name": case["name"], "initial": case["initial"], "final": final,
            "differences": differences,
            "cells_the_vector_changed": [f"${a:04X}" for a in changed],
            "unconstrained_writes_the_model_made": unconstrained_writes,
            "concrete_writes_the_model_made": [f"${a:04X}"
                                               for a in concrete_writes]}


def summarise_jam(cases: list) -> dict:
    """What the vectors record for a jammed CPU, and what the model does.

    Nothing here is an agreement check -- a halted processor has no
    instruction outcome.  It is recorded so the report says what the 12
    uncompared encodings actually contain instead of only that they were
    skipped.
    """
    changed, deltas, cycles = set(), set(), set()
    for case in cases:
        initial, final = case["initial"], case["final"]
        for name in ("pc", "a", "x", "y", "s", "p"):
            if initial[name] != final[name]:
                changed.add(name)
        if ({a: v for a, v in initial["ram"]}
                != {a: v for a, v in final["ram"]}):
            changed.add("ram")
        deltas.add((final["pc"] - initial["pc"]) & 0xFFFF)
        cycles.add(len(case["cycles"]))
    model = {}
    if cases:
        successors, _ = _run(cases[0], havoc=False)
        after = successors[0].state
        model = {"halted": after.halted, "kind": successors[0].kind,
                 "pc_delta": (after.pc - cases[0]["initial"]["pc"]) & 0xFFFF}
    return {
        "vector_fields_that_ever_change": sorted(changed),
        "vector_pc_deltas": sorted(deltas),
        "vector_bus_cycles_recorded": sorted(cycles),
        "model": model,
        "divergence": (
            "the vectors leave PC one past the opcode and the model leaves "
            "it at the opcode; the model also sets `halted`, after which it "
            "performs no further fetch, so PC is dead state.  This is why "
            "JAM is reported apart and never counted as agreement."
            if model and model.get("pc_delta") not in deltas else
            "the model's PC after the halt matches the recorded one"),
    }


def check_opcode(job: tuple) -> dict:
    opcode, directory = job
    info = OPCODES[opcode]
    name = f"0x{opcode:02X} {info.mnemonic} {info.mode}"
    started = time.time()
    with open(os.path.join(directory, f"{opcode:02x}.json")) as handle:
        cases = json.load(handle)
    result = {"opcode": f"0x{opcode:02X}", "mnemonic": info.mnemonic,
              "mode": info.mode, "documented": info.documented,
              "name": name, "vectors": len(cases)}
    if opcode in JAM_OPCODES:
        result.update(group="jam", compared=0, agreed=0, admitted=0,
                      mismatches=[], mismatch_count=0,
                      note="halts the processor; the vectors record the bus "
                           "activity of a jammed CPU, not an instruction "
                           "outcome.  Not compared.",
                      what_the_vectors_record=summarise_jam(cases))
        return result
    havoc = opcode in HAVOC_OPCODES
    check = check_havoc if havoc else check_stable
    failures = []
    bad = 0
    for case in cases:
        try:
            failure = check(case)
        except Exception as exc:                   # a crash is also a finding
            failure = {"name": case["name"], "initial": case["initial"],
                       "final": case["final"],
                       "fault": f"{type(exc).__name__}: {exc}"}
        if failure is not None:
            bad += 1
            if len(failures) < MISMATCH_CAP:
                failures.append(failure)
    result.update(group="havoc" if havoc else "stable", compared=len(cases),
                  mismatches=failures, mismatch_count=bad,
                  seconds=round(time.time() - started, 1))
    if havoc:
        result.update(admitted=len(cases) - bad, agreed=0,
                      note="modelled as havoc; the number above is how many "
                           "recorded outcomes the havoc admits, which is not "
                           "agreement")
    else:
        result.update(agreed=len(cases) - bad, admitted=0)
    return result


def run(directory: str, jobs: int, opcodes=None) -> dict:
    opcodes = sorted(opcodes if opcodes is not None else range(256))
    present = [op for op in opcodes
               if os.path.exists(os.path.join(directory, f"{op:02x}.json"))]
    missing = [f"0x{op:02X}" for op in opcodes if op not in present]
    started = time.time()
    jobs = max(1, min(jobs, MAX_JOBS))
    work = [(op, directory) for op in present]
    if jobs == 1:
        results = [check_opcode(job) for job in work]
    else:
        with multiprocessing.Pool(jobs) as pool:
            results = list(pool.imap_unordered(check_opcode, work,
                                               chunksize=1))
    results.sort(key=lambda r: r["opcode"])
    elapsed = time.time() - started
    groups = {}
    for group in ("stable", "havoc", "jam"):
        rows = [r for r in results if r["group"] == group]
        groups[group] = {
            "opcodes": len(rows),
            "vectors": sum(r["vectors"] for r in rows),
            "compared": sum(r["compared"] for r in rows),
            "agreed": sum(r["agreed"] for r in rows),
            "admitted": sum(r["admitted"] for r in rows),
            "mismatches": sum(r["mismatch_count"] for r in rows),
        }
    compared = sum(g["compared"] for g in groups.values())
    return {
        "source": "SingleStepTests/65x02 nes6502/v1, every vector",
        "directory": directory,
        "model": "formal/model/cpu.py",
        "kind": "model validation on the whole published suite, not a proof",
        "not_covered": [
            "cycle-level behaviour: the vectors' bus cycles are not checked, "
            "the model has no cycle granularity",
            "the 12 JAM encodings (halt; nothing to compare)",
            "interrupt and reset entry (no vectors exist; unit-tested in "
            "formal/tests/test_model_full.py)",
            "NESMemory's region map (these vectors assume a flat 64 KiB)",
        ],
        "missing_files": missing,
        "jobs": jobs,
        "wall_seconds": round(elapsed, 1),
        "instructions_per_second": (round(compared / elapsed, 1)
                                    if elapsed else None),
        "mismatch_cap_per_opcode": MISMATCH_CAP,
        "totals": groups,
        "per_opcode": results,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vectors", default=DEFAULT_VECTORS)
    parser.add_argument("--jobs", type=int, default=MAX_JOBS)
    parser.add_argument("--opcodes", default=None,
                        help="comma-separated hex opcodes (default: all)")
    parser.add_argument("--out", default=None)
    args = parser.parse_args(argv)
    if not os.path.isdir(args.vectors):
        print(f"no vectors at {args.vectors}; run "
              f"formal/tools/fetch_vectors.py <dir> --count all")
        return 2
    opcodes = (None if args.opcodes is None
               else [int(t, 16) for t in args.opcodes.split(",")])
    report = run(args.vectors, args.jobs, opcodes)
    out = args.out or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "results", "reports", "model_validation_full.json")
    with open(out, "w") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
    for group, counts in report["totals"].items():
        print(f"{group:7s} opcodes {counts['opcodes']:3d}  "
              f"compared {counts['compared']:8d}  "
              f"agreed {counts['agreed']:8d}  "
              f"admitted {counts['admitted']:7d}  "
              f"mismatches {counts['mismatches']}")
    print(f"{report['wall_seconds']}s on {report['jobs']} cores, "
          f"{report['instructions_per_second']} instructions/second")
    if report["missing_files"]:
        print(f"missing: {', '.join(report['missing_files'])}")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
