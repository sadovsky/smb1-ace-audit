"""Derive, rather than assume, which enemy identifiers can reach each dispatch.

Review item 4.3: `audit.py` carried hand-assigned maximum indices for the 18
dispatch sites. For the five sites indexed by the enemy identifier `$16,x` the
bound does not have to be assumed, because the routing is itself table-driven:

    $C27F  behavior master   index = ID                       55 entries
    $C88F  collision         index = 0 if ID < $15 else ID-$14  34 entries
              entry 0       -> $C8E0 -> ... -> $C8FF JSR $C905 -> $C907
              entries 16-22 -> $C965 -> ... -> $C976 JSR $C982 -> $C987
    $C907  graphics          index = raw ID                   21 entries
    $C987  sub               index = ID - $24                  7 entries
    $C7A8  sub               index = ID - $12                  8 entries
             reached when the behavior master routes the ID to $C7A0

Reading those routing tables yields the exact identifier set that can arrive at
each dispatch, hence the exact maximum index. This replaces the earlier
inference "Bowser renders without crashing, so a gate must exist" with the gate
itself: the `CPY #$15 / BCC` in the collision dispatch.

Address formation uses `jumpengine.resolve_table`, the instruction-accurate
model (ASL aliasing and 8-bit Y wrap), not `table + 2*index`. Destinations are
classified with `memory.memory_region`, which understands the `$0800-$1FFF`
mirrors of internal RAM.
"""
from __future__ import annotations

import json
import os
import sys

from jumpengine import resolve_table
from memory import memory_region, normalize_internal_ram
from rom import b, image

TRACE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "trace.json")

MAX_LEGAL_ID = 0x36          # $C27F has 55 entries == IDs $00..$36
RAM_REGIONS = {"internal_ram", "internal_ram_mirror"}


def _read_cpu(addr: int) -> int:
    """CPU read restricted to PRG, which is all the dispatch tables need."""
    addr &= 0xFFFF
    return b(addr) if addr >= 0x8000 else 0


def target(table_addr: int, index: int) -> int:
    return resolve_table(_read_cpu, table_addr, index).target


def load_tables() -> dict[int, tuple[int, int]]:
    if not os.path.exists(TRACE):
        sys.exit("trace.json missing - run:  python3 trace.py")
    return {pc: (tbl, n) for pc, tbl, n in json.load(open(TRACE))["jt"]}


def c88f_index(ID: int) -> int:
    return 0 if ID < 0x15 else (ID - 0x14) & 0xFF


def derive(JT):
    """Return {dispatch_pc: (role, index_fn, arriving_ID_set)}."""
    mt, _ = JT[0xC27F]
    ct, cn = JT[0xC88F]
    all_ids = set(range(MAX_LEGAL_ID + 1))

    c7a8_ids = {i for i in all_ids if target(mt, i) == 0xC7A0}
    c907_ids = {i for i in all_ids
                if c88f_index(i) < cn and target(ct, c88f_index(i)) == 0xC8E0}
    c987_ids = {i for i in all_ids
                if c88f_index(i) < cn and target(ct, c88f_index(i)) == 0xC965}

    return {
        0xC27F: ("behavior master", lambda i: i, all_ids),
        0xC88F: ("collision", c88f_index, all_ids),
        0xC907: ("graphics", lambda i: i, c907_ids),
        0xC987: ("sub $24", lambda i: (i - 0x24) & 0xFF, c987_ids),
        0xC7A8: ("sub $12", lambda i: (i - 0x12) & 0xFF, c7a8_ids),
    }


def analyse(JT):
    """Yield (pc, role, N, ids, idx_range, oob_list)."""
    for pc, (role, f, ids) in derive(JT).items():
        tbl, n = JT[pc]
        idxs = sorted({f(i) for i in ids})
        oob = [(i, f(i), target(tbl, f(i))) for i in sorted(ids) if f(i) >= n]
        yield pc, role, n, ids, (min(idxs), max(idxs)) if idxs else (None, None), oob


def main():
    JT = load_tables()
    print(f"ROM sha1 {image().sha1}")
    print("Derived enemy-ID -> dispatch bounds "
          "(exact JumpEngine semantics, NES mirroring)\n")
    print(f"{'site':6} {'role':16} {'N':>3}  {'arriving IDs':26} {'idx':8} verdict")
    print("-" * 98)
    findings = []
    for pc, role, n, ids, (lo, hi), oob in analyse(JT):
        if not oob:
            verdict = f"SAFE (max {hi} <= N-1={n-1})"
        else:
            verdict = "OOB: " + "; ".join(
                f"ID ${i:02X}->idx {ix}->${v:04X}[{memory_region(v)}]" for i, ix, v in oob)
            findings += [(pc, i, ix, v) for i, ix, v in oob]
        sids = ",".join(f"${i:02X}" for i in sorted(ids)[:5]) + ("..." if len(ids) > 5 else "")
        print(f"${pc:04X} {role:16} {n:3}  {sids:26} {f'{lo}..{hi}':8} {verdict}")

    print("\nOut-of-bounds dispatches, and whether they are ACE-capable:")
    if not findings:
        print("  none")
    for pc, i, ix, v in findings:
        reg = memory_region(v)
        if reg in RAM_REGIONS:
            phys = normalize_internal_ram(v)
            note = f"ACE-CAPABLE: controllable RAM (physical ${phys:04X})"
        else:
            note = f"not ACE: {reg} holds no executable controllable bytes"
        print(f"  ${pc:04X} ID ${i:02X} -> index {ix} -> ${v:04X} [{reg}]  =>  {note}")

    print("\nCandidates that the corrected memory map surfaces but routing excludes:")
    d = derive(JT)
    for ID, pc in ((0x1A, 0xC7A8), (0x2B, 0xC987), (0x34, 0xC907), (0x35, 0xC907)):
        tbl, n = JT[pc]
        role, f, ids = d[pc]
        v = target(tbl, f(ID))
        print(f"  ID ${ID:02X} at ${pc:04X}: idx {f(ID)} (N={n}) -> ${v:04X} "
              f"[{memory_region(v)}]  arrives={ID in ids}")


if __name__ == "__main__":
    main()
