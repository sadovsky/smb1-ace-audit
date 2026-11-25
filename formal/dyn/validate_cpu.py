"""Validate `formal/dyn/cpu6502.NMOS2A03` against the SingleStepTests vectors.

This is the same source `formal.validate_model` uses for the symbolic model,
applied to the *interpreter* the tracer runs on.  It checks three things the
tracer depends on and that py65 alone does not give:

1. the 151 documented opcodes still behave after the decimal-mode wrapper, and
   `ADC`/`SBC` with D set produce binary results (the vectors were recorded on
   a 2A03, so their D-set cases are binary);
2. the 105 undocumented opcodes added here match recorded hardware;
3. the per-instruction cycle counts match the number of bus cycles in the
   vector, which is what the device stub's timing is driven by.

Agreement here is agreement on a finite sample of recorded behaviour.  It is
not a proof, and it says nothing about the device stub.

    python3 -m formal.dyn.validate_cpu [--per-opcode N] [--vectors DIR]
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from analysis.decoder import OPCODES

from .cpu6502 import JAM_OPCODES, UNSTABLE_OPCODES, Jam, NMOS2A03

DEFAULT_VECTORS = os.environ.get(
    "NES6502_VECTORS", os.path.expanduser("~/big/smb1-formal/harte"))

#: bits 4 (B) and 5 are not registers
FLAG_MASK = 0xCF


class Flat(list):
    """A flat 64 KiB address space; `MPU` only needs item access."""

    def __init__(self):
        super().__init__([0] * 0x10000)

    def __getitem__(self, address):
        return list.__getitem__(self, address & 0xFFFF)

    def __setitem__(self, address, value):
        list.__setitem__(self, address & 0xFFFF, value & 0xFF)


def run_vector(mpu: NMOS2A03, vector: dict) -> tuple[dict, int] | None:
    initial = vector["initial"]
    for address, value in initial["ram"]:
        mpu.memory[address] = value
    mpu.pc = initial["pc"]
    mpu.sp = initial["s"]
    mpu.a = initial["a"]
    mpu.x = initial["x"]
    mpu.y = initial["y"]
    mpu.p = initial["p"]
    mpu.processorCycles = 0
    try:
        mpu.step()
    except Jam:
        return None
    return ({"pc": mpu.pc, "s": mpu.sp, "a": mpu.a, "x": mpu.x, "y": mpu.y,
             "p": mpu.p & FLAG_MASK}, mpu.processorCycles)


def check(directory: str, per_opcode: int) -> dict:
    report = {
        "source": "SingleStepTests/65x02 nes6502/v1",
        "directory": directory,
        "per_opcode": per_opcode,
        "opcodes_compared": 0,
        "instructions_compared": 0,
        "state_mismatches": [],
        "cycle_mismatches": [],
        "unstable": {},
        "jam": {},
        "missing_files": [],
    }
    mpu = NMOS2A03(memory=Flat(), pc=0)
    for opcode in range(256):
        path = os.path.join(directory, f"{opcode:02x}.json")
        if not os.path.exists(path):
            report["missing_files"].append(f"0x{opcode:02X}")
            continue
        with open(path) as handle:
            vectors = json.load(handle)[:per_opcode]
        name = f"0x{opcode:02X} {OPCODES[opcode].mnemonic}"
        if opcode in JAM_OPCODES:
            report["jam"][name] = ("halts the processor; the vectors record "
                                   "bus activity only")
            continue
        state_bad = cycle_bad = 0
        examples = []
        for vector in vectors:
            outcome = run_vector(mpu, vector)
            if outcome is None:
                continue
            actual, cycles = outcome
            final = vector["final"]
            expected = {"pc": final["pc"], "s": final["s"], "a": final["a"],
                        "x": final["x"], "y": final["y"],
                        "p": final["p"] & FLAG_MASK}
            differences = {k: (expected[k], actual[k])
                           for k in expected if expected[k] != actual[k]}
            for address, value in final["ram"]:
                if mpu.memory[address] != value:
                    differences[f"ram[{address:04X}]"] = (
                        value, mpu.memory[address])
            if differences:
                state_bad += 1
                if len(examples) < 2:
                    examples.append({"name": vector["name"],
                                     "differences": differences})
            if cycles != len(vector["cycles"]):
                cycle_bad += 1
        report["opcodes_compared"] += 1
        report["instructions_compared"] += len(vectors)
        bucket = ("unstable" if opcode in UNSTABLE_OPCODES else None)
        if bucket:
            report["unstable"][name] = {
                "vectors": len(vectors),
                "state_mismatches": state_bad,
                "cycle_mismatches": cycle_bad,
                "note": ("no single hardware behaviour; formal/model/cpu.py "
                         "treats this as havoc.  Counted separately, never as "
                         "agreement."),
                "examples": examples,
            }
            continue
        if state_bad:
            report["state_mismatches"].append(
                {"opcode": name, "vectors": len(vectors), "bad": state_bad,
                 "examples": examples})
        if cycle_bad:
            report["cycle_mismatches"].append(
                {"opcode": name, "vectors": len(vectors), "bad": cycle_bad})
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vectors", default=DEFAULT_VECTORS)
    parser.add_argument("--per-opcode", type=int, default=300)
    parser.add_argument("--json", default=None)
    args = parser.parse_args(argv)

    if not os.path.isdir(args.vectors):
        print(f"vectors not found at {args.vectors}; run "
              "formal/tools/fetch_vectors.py", file=sys.stderr)
        return 2
    report = check(args.vectors, args.per_opcode)
    stable_bad = sum(entry["bad"] for entry in report["state_mismatches"])
    print(f"opcodes compared        {report['opcodes_compared']}")
    print(f"instructions compared   {report['instructions_compared']}")
    print(f"state mismatches        {stable_bad} "
          f"(over {len(report['state_mismatches'])} opcodes)")
    print(f"cycle-count mismatches  "
          f"{sum(e['bad'] for e in report['cycle_mismatches'])} "
          f"(over {len(report['cycle_mismatches'])} opcodes)")
    print(f"unstable, counted apart {len(report['unstable'])}")
    print(f"JAM, not compared       {len(report['jam'])}")
    for entry in report["state_mismatches"][:12]:
        print(f"  {entry['opcode']}: {entry['bad']}/{entry['vectors']}")
        for example in entry["examples"][:1]:
            print(f"    {example['name']}: {example['differences']}")
    for entry in report["cycle_mismatches"][:12]:
        print(f"  cycles {entry['opcode']}: {entry['bad']}/{entry['vectors']}")
    for name, entry in report["unstable"].items():
        print(f"  unstable {name}: state {entry['state_mismatches']}"
              f"/{entry['vectors']}, cycles {entry['cycle_mismatches']}")
    if args.json:
        with open(args.json, "w") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
        print(f"wrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
