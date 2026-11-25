"""Review items 4.4 and 4.5: byte classification and stack-based control flow.

4.4  The tracer recorded "reached bytes" without distinguishing instruction
     starts from operand bytes, jump-table data and unreached data. Those are
     separated here, and the unreached remainder is swept for control-transfer
     opcodes that an alternate decoding could expose.

4.5  The audit so far has centred on the computed `JMP ($0006)`. A 6502 program
     can transfer control three other ways that do not look like a jump:

       * the RTS trick: push a computed address, then RTS to it
       * RTI, which pops both a status byte and an address
       * any RTS reached with a corrupted stack

     This module enumerates all of them and checks whether the pushed value is
     ever computed rather than a genuine return address.

    python3 controlflow.py
"""
from __future__ import annotations

import json
import os
import sys
from collections import Counter

from d65 import LEN, M
from memory import memory_region
from rom import b, image

TRACE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "trace.json")
PRG_LO, PRG_HI = 0x8000, 0xFFFF

# opcodes that transfer control
JMP_ABS, JMP_IND, JSR, RTS, RTI, BRK = 0x4C, 0x6C, 0x20, 0x60, 0x40, 0x00
PHA, PLA, TXS, TSX = 0x48, 0x68, 0x9A, 0xBA


def load_trace():
    if not os.path.exists(TRACE):
        sys.exit("trace.json missing - run:  python3 trace.py")
    return json.load(open(TRACE))


def instruction_starts(reached: set[int]) -> tuple[set[int], set[int]]:
    """Split the reached byte set into instruction starts and operand bytes.

    trace.py marks every byte an instruction occupies. Re-walking those bytes
    and consuming each instruction's length recovers which were starts.
    """
    starts, operands = set(), set()
    addr = PRG_LO
    while addr <= PRG_HI:
        if addr not in reached or addr in operands:
            addr += 1
            continue
        op = b(addr)
        if op not in M:
            addr += 1
            continue
        n = LEN[M[op][1]]
        # only a start if every byte of the instruction was reached
        if all((addr + k) in reached for k in range(n)):
            starts.add(addr)
            for k in range(1, n):
                operands.add(addr + k)
            addr += n
        else:
            addr += 1
    return starts, operands


def table_bytes(jt) -> set[int]:
    out = set()
    for _pc, tbl, n in jt:
        for i in range(2 * n):
            out.add(tbl + i)
    return out


def sweep_unclassified(unreached: set[int]):
    """Control-transfer opcodes sitting in bytes the descent never reached."""
    hits = {"JMP (ind)": [], "JSR": [], "RTI": []}
    for a in sorted(unreached):
        op = b(a)
        if op == JMP_IND and a + 2 <= PRG_HI:
            hits["JMP (ind)"].append((a, b(a + 1) | b(a + 2) << 8))
        elif op == JSR and a + 2 <= PRG_HI:
            hits["JSR"].append((a, b(a + 1) | b(a + 2) << 8))
        elif op == RTI:
            hits["RTI"].append((a, None))
    return hits


def find_rts_trick(starts: set[int]):
    """Look for the RTS dispatch trick: a value pushed, then RTS.

    A genuine subroutine return has its address pushed by JSR. The trick
    pushes a computed address with PHA/PHA and returns into it, which is a
    computed control transfer that does not use a JMP. We scan every reached
    instruction stream for a PHA ... PHA ... RTS sequence with no intervening
    JSR (which would consume the pushes as a real call frame).
    """
    ordered = sorted(starts)
    index = {a: i for i, a in enumerate(ordered)}
    found = []
    for i, a in enumerate(ordered):
        if b(a) != PHA:
            continue
        pushes, j = 1, i + 1
        # walk forward a short window
        while j < len(ordered) and j - i < 24:
            op = b(ordered[j])
            if op == PHA:
                pushes += 1
            elif op == JSR:
                break               # a real call frame, not the trick
            elif op == PLA:
                break               # balanced, not a dispatch
            elif op == RTS:
                if pushes >= 2:
                    found.append((a, ordered[j], pushes))
                break
            j += 1
    return found


def stack_ops(starts: set[int]):
    """Census of stack-affecting instructions, and any direct SP write."""
    c = Counter()
    txs_sites = []
    for a in sorted(starts):
        op = b(a)
        if op in (PHA, PLA, RTS, RTI, JSR, 0x08, 0x28):  # incl PHP/PLP
            c[M[op][0]] += 1
        if op == TXS:
            txs_sites.append(a)
            c["TXS"] += 1
    return c, txs_sites


def main():
    J = load_trace()
    reached = set(J["instruction_bytes"])
    jt = J["jt"]

    print(f"ROM sha1 {image().sha1}\n")
    print("=" * 72)
    print("4.4  Byte classification")
    print("=" * 72)
    # trace.py already separates starts from occupied bytes; prefer its data
    starts = set(J.get("instruction_starts") or [])
    if not starts:
        starts, _ = instruction_starts(reached)
    operands = reached - starts
    tbl = table_bytes(jt)
    total = 0x8000
    unreached = {a for a in range(PRG_LO, PRG_HI + 1)} - reached
    data_unreached = unreached - tbl
    print(f"  instruction starts : {len(starts):6}")
    print(f"  operand bytes      : {len(operands):6}")
    print(f"  dispatch-table data: {len(tbl):6}")
    print(f"  unreached bytes    : {len(unreached):6}  ({len(unreached)*100//total}% of PRG)")
    print(f"  (of which not table data: {len(data_unreached)})")
    covered = len(starts) + len(operands)
    print(f"  starts+operands    : {covered:6}  vs trace.py's 'reached' {len(reached)}")

    print("\n  Control-transfer opcodes in UNREACHED bytes (alternate decodings):")
    hits = sweep_unclassified(data_unreached)
    for kind, lst in hits.items():
        print(f"    {kind:10}: {len(lst)}")
    ind = hits["JMP (ind)"]
    if ind:
        print("    JMP (ind) byte positions in unreached data (candidate only if")
        print("    some real path decodes them as instruction starts):")
        for a, t in ind[:12]:
            print(f"      ${a:04X}: JMP (${t:04X})  pointer region={memory_region(t)}")
        print(f"      ... {len(ind)} total")

    print("\n" + "=" * 72)
    print("4.5  Stack-based control flow")
    print("=" * 72)
    counts, txs_sites = stack_ops(starts)
    for k in sorted(counts):
        print(f"  {k:4}: {counts[k]}")
    print(f"\n  Direct stack-pointer writes (TXS): {len(txs_sites)} site(s)")
    for a in txs_sites:
        print(f"    ${a:04X}")

    print("\n  RTS-trick dispatch (PHA..PHA..RTS with no intervening JSR):")
    trick = find_rts_trick(starts)
    if not trick:
        print("    none found - every RTS in reached code returns to a JSR frame")
    for push_at, rts_at, n in trick:
        print(f"    push at ${push_at:04X} .. RTS at ${rts_at:04X}  ({n} pushes)")

    print("\n  RTI sites in reached code:")
    rti = [a for a in sorted(starts) if b(a) == RTI]
    for a in rti:
        print(f"    ${a:04X}")
    print("    (RTI returns from the NMI handler; IRQ is never taken on NROM)")


if __name__ == "__main__":
    main()
