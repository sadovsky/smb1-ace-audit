"""Tiny helpers for poking at an NROM image: byte lookup, pattern search.

The ROM is NOT distributed with this repo (it is copyrighted). Supply your own
dump of the NTSC Super Mario Bros. (World) PRG. The loader looks, in order, at:

  1. $SMB1_ROM                         (environment variable)
  2. ./smb1.nes                        (next to this file)

The expected image is the iNES file (16-byte header + 32 KiB PRG), SHA-1
ea343f4e445a9050d4b4fbac2c77d0693b1d0922. A mismatch prints a warning but still
loads, so you can point it at a close variant if you know what you are doing.
"""
import os
import sys
import hashlib

EXPECT_SHA1 = "ea343f4e445a9050d4b4fbac2c77d0693b1d0922"


def _find_rom():
    cands = []
    if os.environ.get("SMB1_ROM"):
        cands.append(os.environ["SMB1_ROM"])
    cands.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "smb1.nes"))
    for p in cands:
        if p and os.path.exists(p):
            return p
    sys.exit(
        "smb1.nes not found. Set $SMB1_ROM or place the ROM next to rom.py.\n"
        "Expected NTSC Super Mario Bros. (World), SHA-1 " + EXPECT_SHA1
    )


ROM = _find_rom()
_raw = open(ROM, "rb").read()
_sha = hashlib.sha1(_raw).hexdigest()
if _sha != EXPECT_SHA1:
    sys.stderr.write(f"warning: {ROM} SHA-1 {_sha} != expected {EXPECT_SHA1}\n")

# iNES: 16-byte header, then 32 KiB PRG mapped at CPU $8000-$FFFF (NROM, mapper 0).
PRG = _raw[16:16 + 0x8000]


def b(addr):            # CPU address -> byte
    return PRG[addr - 0x8000]


def find(hexstr):       # all CPU addresses where the byte pattern occurs
    pat = bytes.fromhex(hexstr.replace(" ", ""))
    out, i = [], PRG.find(pat)
    while i >= 0:
        out.append(0x8000 + i)
        i = PRG.find(pat, i + 1)
    return out


def dump(addr, n=16):
    return " ".join(f"{b(addr + i):02x}" for i in range(n))


if __name__ == "__main__":
    for arg in sys.argv[1:]:
        hits = find(arg)
        print(f"{arg!r}: " + ", ".join(f"${h:04X}" for h in hits))
        for h in hits[:6]:
            print(f"   ${h-8:04X}: {dump(h-8, 32)}")
