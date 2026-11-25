"""Strict loader and byte helpers for the supported SMB1 cartridge."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import sys
from pathlib import Path

EXPECT_SHA1 = "ea343f4e445a9050d4b4fbac2c77d0693b1d0922"
INES_HEADER_SIZE = 16
SMB1_PRG_SIZE = 0x8000
SMB1_CHR_SIZE = 0x2000


class ROMValidationError(ValueError):
    """The supplied image is not the supported SMB1 cartridge."""


@dataclass(frozen=True)
class INESImage:
    path: str
    sha1: str
    mapper: int
    prg: bytes
    chr: bytes
    reset_vector: int
    nmi_vector: int
    irq_vector: int

    def cpu_byte(self, address: int) -> int:
        if not 0x8000 <= address <= 0xFFFF:
            raise ValueError(f"CPU address ${address:04X} is outside NROM PRG")
        return self.prg[address - 0x8000]


def default_rom_path() -> str:
    configured = os.environ.get("SMB1_ROM")
    if configured:
        return configured
    return str(Path(__file__).resolve().with_name("smb1.nes"))


def parse_ines(
    raw: bytes,
    *,
    path: str = "<memory>",
    allow_alternate: bool = False,
    expected_sha1: str = EXPECT_SHA1,
) -> INESImage:
    """Validate an iNES SMB1 image and return its mapped cartridge data."""
    if len(raw) < INES_HEADER_SIZE or raw[:4] != b"NES\x1a":
        raise ROMValidationError("invalid or missing iNES header")

    prg_banks, chr_banks, flags6, flags7 = raw[4], raw[5], raw[6], raw[7]
    if flags7 & 0x0C == 0x08:
        raise ROMValidationError("NES 2.0 images are not supported")
    mapper = (flags6 >> 4) | (flags7 & 0xF0)
    if mapper != 0:
        raise ROMValidationError(f"mapper {mapper} is incompatible; expected mapper 0")
    if prg_banks * 0x4000 != SMB1_PRG_SIZE:
        raise ROMValidationError(
            f"PRG size is {prg_banks * 0x4000} bytes; expected {SMB1_PRG_SIZE}"
        )
    if chr_banks * 0x2000 != SMB1_CHR_SIZE:
        raise ROMValidationError(
            f"CHR size is {chr_banks * 0x2000} bytes; expected {SMB1_CHR_SIZE}"
        )

    trainer_size = 512 if flags6 & 0x04 else 0
    expected_size = INES_HEADER_SIZE + trainer_size + SMB1_PRG_SIZE + SMB1_CHR_SIZE
    if len(raw) != expected_size:
        raise ROMValidationError(
            f"image size is {len(raw)} bytes; header requires {expected_size}"
        )

    digest = hashlib.sha1(raw).hexdigest()
    if digest != expected_sha1 and not allow_alternate:
        raise ROMValidationError(
            f"SHA-1 {digest} is incompatible; expected {expected_sha1} "
            "(pass allow_alternate=True for an explicit variant experiment)"
        )

    prg_start = INES_HEADER_SIZE + trainer_size
    prg = raw[prg_start : prg_start + SMB1_PRG_SIZE]
    chr_data = raw[prg_start + SMB1_PRG_SIZE : expected_size]

    def vector(offset: int) -> int:
        return prg[offset] | (prg[offset + 1] << 8)

    nmi = vector(0x7FFA)
    reset = vector(0x7FFC)
    irq = vector(0x7FFE)
    for name, address in (("NMI", nmi), ("reset", reset), ("IRQ", irq)):
        if not 0x8000 <= address <= 0xFFFF:
            raise ROMValidationError(
                f"{name} vector ${address:04X} does not point into NROM PRG"
            )

    return INESImage(path, digest, mapper, prg, chr_data, reset, nmi, irq)


def load_rom(path: str | None = None, *, allow_alternate: bool = False) -> INESImage:
    selected = path or default_rom_path()
    try:
        raw = Path(selected).read_bytes()
    except FileNotFoundError as exc:
        raise FileNotFoundError(
            f"SMB1 ROM not found at {selected}. Set SMB1_ROM or place smb1.nes "
            f"next to rom.py (expected SHA-1 {EXPECT_SHA1})."
        ) from exc
    return parse_ines(raw, path=selected, allow_alternate=allow_alternate)


ROM = default_rom_path()
_image: INESImage | None = None


def image() -> INESImage:
    global _image
    if _image is None:
        _image = load_rom()
    return _image


def b(addr: int) -> int:
    return image().cpu_byte(addr)


def find(hexstr: str) -> list[int]:
    pat = bytes.fromhex(hexstr.replace(" ", ""))
    prg = image().prg
    out, offset = [], prg.find(pat)
    while offset >= 0:
        out.append(0x8000 + offset)
        offset = prg.find(pat, offset + 1)
    return out


def dump(addr: int, n: int = 16) -> str:
    return " ".join(f"{b(addr + i):02x}" for i in range(n))


def main(argv: list[str]) -> int:
    try:
        loaded = image()
        print(
            f"ROM {loaded.path}: SHA-1 {loaded.sha1}, mapper {loaded.mapper}, "
            f"PRG {len(loaded.prg)}, CHR {len(loaded.chr)}, "
            f"vectors NMI=${loaded.nmi_vector:04X} reset=${loaded.reset_vector:04X} "
            f"IRQ=${loaded.irq_vector:04X}"
        )
        for arg in argv:
            hits = find(arg)
            print(f"{arg!r}: " + ", ".join(f"${hit:04X}" for hit in hits))
            for hit in hits[:6]:
                print(f"   ${hit-8:04X}: {dump(hit-8, 32)}")
    except (FileNotFoundError, ROMValidationError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
