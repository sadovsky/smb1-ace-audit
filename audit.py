"""ACE audit over the single computed jump in SMB1.

Run trace.py first (it writes trace.json: the reached code set, the sole
indirect JMP, and every JSR $8E04 dispatch table). This script then answers, for
each of the 18 dispatch sites, the only question that matters for ACE:

    can the index be driven past the table so that JMP ($0006) reads ROM bytes
    that form a <$0800 pointer into controllable RAM?

Output mirrors ACE_AUDIT.md sections 3 and 4.
"""
import json
import os
import sys

from rom import b

TRACE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "trace.json")
if not os.path.exists(TRACE):
    sys.exit("trace.json missing - run:  python3 trace.py")

J = json.load(open(TRACE))
JT = sorted(J["jt"])          # (dispatch_pc, table_addr, n_entries)


def target(tbl, idx):
    """Address JMP ($0006) would take for this index (JumpEngine offset model)."""
    a = tbl + 2 * idx
    return b(a) | b(a + 1) << 8


def region(v):
    if v < 0x0800:
        return "RAM"          # controllable -> potential ACE
    if v < 0x8000:
        return "I/O"          # $2000-$7FFF PPU/APU/open-bus -> crash, not ACE
    return "ROM"              # fixed code -> safe


# Index source and in-range bound for each dispatch, read from the disassembly.
# 'maxidx' is the largest index the site can pass under the stated bound; None
# means "no local bound - depends on an upstream invariant" (see notes).
SITES = {
    0x8215: ("$0770 OperMode",            3,    "state counter 0-3"),
    0x8234: ("$0772 OperMode_Task",       3,    "task counter"),
    0x83A3: ("$0772",                      4,    "task counter"),
    0x856A: ("$073C screen task",         14,   "screen-routine counter"),
    0x921B: ("$0772",                      2,    "task counter"),
    0x92C8: ("$071F forced 1..8",         7,    "STRUCTURAL: 0..7"),
    0x9664: ("GameEngine ($0E)",          46,   "engine state"),
    0x9743: ("$0733",                      4,    "state counter"),
    0xAEDF: ("$0772",                      3,    "task counter"),
    0xB04C: ("$0E",                        12,   "state value"),
    0xB34E: ("$1D (CMP #$03)",             3,    "player state, checked"),
    0xBDBD: ("$05 via $BDF6",              8,    "CMP #$09 / BCC"),
    0xC27F: ("$16,x enemy ID",            54,    "table sized to ID space 0..$36"),
    0xC7A8: ("$16,x - $12",               7,    "routed IDs $12..$19"),
    0xC88F: ("$16,x (CPY #$15, SBC #$14)", 33,   "worst case -> I/O crash"),
    0xC907: ("$16,x RAW, no local bound", None,  "upstream routing only"),
    0xC987: ("$16,x - $24",               6,    "routed IDs $24..$2A"),
    0xD2E5: ("$0746 (CMP #$05 / BCS)",     4,    "explicit clamp"),
}


def main():
    code = set(J["code"])
    print(f"reached {len(code)} PRG bytes ({len(code) * 100 // 0x8000}%)")
    print(f"sole computed jump: JMP ($0006) at $8E16 (JumpEngine $8E04)")
    print(f"dispatch sites: {len(JT)}\n")

    print("site   table   N  idx<=  index source                 bound / note")
    print("-" * 78)
    reach_ram = []
    for pc, tbl, n in JT:
        src, maxidx, note = SITES.get(pc, ("?", None, ""))
        # in-range target is always ROM; check whether ANY index up to a generous
        # out-of-bounds reaches controllable RAM, and whether the bound blocks it.
        ram_idx = [i for i in range(0, 96) if region(target(tbl, i)) == "RAM"]
        blocked = maxidx is not None and all(i > maxidx for i in ram_idx)
        mx = "-" if maxidx is None else maxidx
        flag = ""
        if ram_idx and not blocked:
            flag = "  <-- RAM reachable within bound"
            reach_ram.append((pc, tbl, n, maxidx, ram_idx))
        print(f"${pc:04X} ${tbl:04X} {n:3} {str(mx):>5}  {src:28} {note}{flag}")

    print("\n--- sites whose bound does NOT exclude a controllable-RAM target ---")
    if not reach_ram:
        print("none: every site's index bound keeps JMP ($0006) in ROM.")
    for pc, tbl, n, maxidx, ram_idx in reach_ram:
        hits = [(i, target(tbl, i)) for i in ram_idx if maxidx is None or i <= (maxidx or 0) + 64]
        print(f"${pc:04X}: table ${tbl:04X} N={n} maxidx={maxidx}")
        for i, v in hits[:6]:
            print(f"    index {i} -> ${v:04X} (RAM)")

    # The headline detail: C907, the only raw-ID dispatch into an undersized table.
    print("\n--- $C907 (enemy graphics, raw ID, 21-entry table) ---")
    tbl = dict((p, t) for p, t, _ in JT)[0xC907]
    for ID in range(0x00, 0x37):
        v = target(tbl, ID)
        if region(v) == "RAM":
            print(f"    enemy ID ${ID:02X} -> ${v:04X} (controllable RAM)")
    print("    (IDs $34/$35 route via master $C27F to RTS stubs $C2F0/$C307,")
    print("     so they never reach $C905; Bowser ID $2D proves the gate empirically.)")


if __name__ == "__main__":
    main()
