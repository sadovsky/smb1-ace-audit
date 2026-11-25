"""Validate `formal/model/cpu.py` against two independent sources (plan 6).

1. SingleStepTests `nes6502` vectors: recorded per-instruction behaviour of the
   NES CPU for all 256 opcodes, including the undocumented ones.  Compared on
   PC, A, X, Y, S, the six flags, and every RAM byte the vector lists.
2. py65, an independently written NMOS 6502 simulator, on random states for
   the 151 documented opcodes.

This is *model validation*: agreement on a finite sample.  It is evidence that
the semantics are right, never a proof that they match silicon, and it says
nothing about cycle-level behaviour, which the model does not represent.

    python3 -m formal.validate_model [--vectors DIR] [--per-opcode N]
"""
from __future__ import annotations

import argparse
import json
import os
import random
import time

from analysis.decoder import OPCODES

from .model.cpu import HAVOC, State, step
from .model.memory import FlatMemory, as_int

DEFAULT_VECTORS = os.environ.get(
    "NES6502_VECTORS", os.path.expanduser("~/big/smb1-formal/harte"))
#: bits 4 and 5 of the status byte are not registers
FLAG_MASK = 0xCF


def run_concrete(pc, a, x, y, s, p, cells):
    state = State.concrete(pc=pc, a=a, x=x, y=y, s=s, p=p,
                           mem=FlatMemory(cells))
    (successor,) = step(state)
    n = successor.state
    registers = dict(pc=n.pc, a=as_int(n.a), x=as_int(n.x), y=as_int(n.y),
                     s=as_int(n.s), p=as_int(n.status(b=False)) & FLAG_MASK)
    return registers, n


def skipped(opcode: int) -> str | None:
    info = OPCODES[opcode]
    if info.mnemonic in HAVOC:
        return "modelled as havoc (unstable); nothing to compare"
    if info.mnemonic == "JAM":
        return "halts the processor; the vectors record bus activity only"
    return None


def check_vectors(directory: str, per_opcode: int) -> dict:
    report = {"source": "SingleStepTests/65x02 nes6502/v1",
              "per_opcode": per_opcode, "opcodes_compared": 0,
              "instructions_compared": 0, "mismatches": [], "skipped": {}}
    for opcode in range(256):
        reason = skipped(opcode)
        if reason:
            report["skipped"][f"0x{opcode:02X} {OPCODES[opcode].mnemonic}"] = reason
            continue
        with open(os.path.join(directory, f"{opcode:02x}.json")) as handle:
            cases = json.load(handle)[:per_opcode]
        report["opcodes_compared"] += 1
        for case in cases:
            i, f = case["initial"], case["final"]
            got, after = run_concrete(i["pc"], i["a"], i["x"], i["y"], i["s"],
                                      i["p"], dict(map(tuple, i["ram"])))
            want = {k: f[k] for k in got}
            want["p"] &= FLAG_MASK
            memory_ok = all(as_int(after.mem.read(address)[0]) == value
                            for address, value in f["ram"])
            report["instructions_compared"] += 1
            if got != want or not memory_ok:
                report["mismatches"].append(
                    {"opcode": f"0x{opcode:02X}", "name": case["name"],
                     "got": got, "want": want, "memory_ok": memory_ok})
    return report


def check_py65(per_opcode: int, seed: int) -> dict:
    from py65.devices.mpu6502 import MPU
    import py65

    rng = random.Random(seed)
    report = {"source": f"py65 {getattr(py65, '__version__', '')}".strip(),
              "seed": seed, "per_opcode": per_opcode,
              "instructions_compared": 0, "mismatches": [],
              "known_difference": "py65 implements decimal-mode ADC/SBC, the "
                                  "2A03 does not; D is cleared for those two"}
    for opcode, info in sorted(OPCODES.items()):
        if not info.documented:
            continue
        for _ in range(per_opcode):
            memory = [rng.randrange(256) for _ in range(0x10000)]
            pc = rng.randrange(0x0200, 0xFF00)
            memory[pc] = opcode
            a, x, y, s = (rng.randrange(256) for _ in range(4))
            p = rng.randrange(256) | 0x20
            if info.mnemonic in ("ADC", "SBC"):
                p &= ~0x08
            reference = MPU(memory=list(memory), pc=pc)
            reference.a, reference.x, reference.y = a, x, y
            reference.sp, reference.p = s, p
            reference.step()
            got, after = run_concrete(pc, a, x, y, s, p,
                                      dict(enumerate(memory)))
            want = dict(pc=reference.pc & 0xFFFF, a=reference.a, x=reference.x,
                        y=reference.y, s=reference.sp,
                        p=reference.p & FLAG_MASK)
            written = dict(after.mem.writes)
            memory_ok = all(reference.memory[address] == value
                            for address, value in written.items()) and all(
                reference.memory[k] == memory[k] or k in written
                for k in range(0x10000))
            report["instructions_compared"] += 1
            if got != want or not memory_ok:
                report["mismatches"].append(
                    {"opcode": f"0x{opcode:02X} {info.mnemonic} {info.mode}",
                     "got": got, "want": want, "memory_ok": memory_ok})
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vectors", default=DEFAULT_VECTORS)
    parser.add_argument("--per-opcode", type=int, default=300)
    parser.add_argument("--py65-per-opcode", type=int, default=40)
    parser.add_argument("--seed", type=int, default=20261125)
    args = parser.parse_args()
    started = time.time()
    report = {"model": "formal/model/cpu.py",
              "kind": "model validation on a finite sample, not a proof",
              "not_covered": [
                  "cycle-level behaviour, dummy reads, DMA",
                  "the six unstable undocumented instructions (havoc)",
                  "NESMemory's region map (unit-tested separately)",
                  "interrupt and reset entry (unit-tested, no vectors)"]}
    if os.path.isdir(args.vectors):
        report["vectors"] = check_vectors(args.vectors, args.per_opcode)
    else:
        report["vectors"] = {"status": "not run",
                             "reason": f"{args.vectors} is absent"}
    try:
        report["py65"] = check_py65(args.py65_per_opcode, args.seed)
    except ImportError:
        report["py65"] = {"status": "not run", "reason": "py65 not installed"}
    report["wall_seconds"] = round(time.time() - started, 1)
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results",
                        "reports", "model_validation.json")
    for key in ("vectors", "py65"):
        section = report[key]
        if "mismatches" in section:
            section["mismatch_count"] = len(section["mismatches"])
            section["mismatches"] = section["mismatches"][:25]
            print(f"{key}: {section['instructions_compared']} compared, "
                  f"{section['mismatch_count']} mismatches")
        else:
            print(f"{key}: {section['reason']}")
    with open(path, "w") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
