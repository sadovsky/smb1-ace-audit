"""NES CPU address normalization and region classification."""


def normalize_internal_ram(address: int) -> int | None:
    """Return the physical 2 KiB RAM address, including CPU mirrors."""
    address &= 0xFFFF
    return address & 0x07FF if address < 0x2000 else None


def memory_region(address: int) -> str:
    address &= 0xFFFF
    if address < 0x0800:
        return "internal_ram"
    if address < 0x2000:
        return "internal_ram_mirror"
    if address < 0x4000:
        return "ppu_registers"
    if address < 0x4018:
        return "apu_io"
    if address < 0x4020:
        return "disabled_io"
    if address < 0x6000:
        return "cartridge_expansion"
    if address < 0x8000:
        return "cartridge_ram_or_open_bus"
    return "prg_rom"


def is_internal_ram(address: int) -> bool:
    return normalize_internal_ram(address) is not None
