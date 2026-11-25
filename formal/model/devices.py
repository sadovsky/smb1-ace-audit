"""The CPU-visible address map and the abstraction used for everything that
is not RAM or program ROM.

The machine is an NTSC NES with an NROM-256 cartridge: 2 KiB of internal RAM
mirrored through `$1FFF`, 32 KiB of PRG ROM at `$8000-$FFFF`, no PRG RAM and
no mapper registers.

Abstraction (sound for CPU-visible state, deliberately coarse):

* A read from `$2000-$7FFF` returns an **unconstrained** byte.  That covers
  the PPU and APU/controller registers, their mirrors, the unmapped expansion
  area and the absent PRG RAM (open bus).  Every concrete value a real device
  or a floating bus could supply is included, so in particular every legal
  *and illegal* serial controller response is included: the controller model
  is the over-approximation the plan calls "arbitrary serial responses".
* A write to `$2000-$7FFF` changes no CPU-visible state.  Its only effect on a
  real machine is on device state, and device state reaches the CPU only
  through reads (unconstrained, above) and through NMI/IRQ timing (modelled as
  nondeterministic in `transitions.py`).
* A write to `$8000-$FFFF` has no effect: NROM has no registers and the ROM is
  immutable.
* Dummy reads and writes performed by the real CPU inside an instruction are
  not modelled individually.  They can only touch device state, which the two
  rules above already treat as unknown.
* OAM DMA and DMC DMA steal cycles and read memory but write no CPU-visible
  state, so at instruction granularity they are the identity.  (DMC DMA's
  known corruption of a concurrent controller or PPU *read* is covered by
  reads being unconstrained.)

What this abstraction cannot express: any property that depends on a device
returning a *particular* value.  Such properties must be proved for all
values or stay unproved.
"""
from __future__ import annotations

from enum import Enum

RAM_SIZE = 0x0800
RAM_END = 0x2000          # exclusive; mirrors of the 2 KiB RAM
ROM_START = 0x8000


class Region(str, Enum):
    RAM = "ram"
    BUS = "bus"            # devices, mirrors, open bus: unconstrained reads
    ROM = "rom"


def region(address: int) -> Region:
    address &= 0xFFFF
    if address < RAM_END:
        return Region.RAM
    if address >= ROM_START:
        return Region.ROM
    return Region.BUS


def ram_index(address: int) -> int:
    """Mirror normalisation for an address already known to be in RAM."""
    return address & (RAM_SIZE - 1)
