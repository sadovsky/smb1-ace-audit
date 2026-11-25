"""Memory models over Z3 terms.

`NESMemory` is the model the proofs use.  `FlatMemory` is 64 KiB of plain
RAM and exists only so the instruction semantics in `cpu.py` can be compared
against independent single-instruction test vectors, which assume a flat
address space.  Both expose the same three operations, so the CPU semantics
being validated is the CPU semantics being proved about.
"""
from __future__ import annotations

import itertools
from typing import Sequence

import z3

from .devices import RAM_END, ROM_START, Region, ram_index, region

_fresh = itertools.count()


def bv8(value) -> z3.BitVecRef:
    return z3.BitVecVal(value, 8) if isinstance(value, int) else value


def bv16(value) -> z3.BitVecRef:
    return z3.BitVecVal(value, 16) if isinstance(value, int) else value


def as_int(term) -> int | None:
    """The concrete value of a term, or None if it is genuinely symbolic."""
    if isinstance(term, int):
        return term
    term = z3.simplify(term)
    return term.as_long() if z3.is_bv_value(term) else None


def fresh(prefix: str, bits: int = 8) -> z3.BitVecRef:
    return z3.BitVec(f"{prefix}!{next(_fresh)}", bits)


class NESMemory:
    """2 KiB mirrored RAM, unconstrained bus, immutable PRG ROM.

    `ram` is an array from 11-bit indices to bytes, so mirroring is built into
    the sort rather than left to callers.  `prg` is the verified 32 KiB image.
    A read from ROM at a symbolic address goes through the array `PRG`; the
    caller must add `prg_axioms` for the addresses it can reach, otherwise the
    byte is unconstrained (sound, but usually too weak to prove anything).
    """

    PRG = z3.Array("PRG", z3.BitVecSort(15), z3.BitVecSort(8))

    def __init__(self, ram: z3.ArrayRef, prg: bytes, *,
                 writes: tuple = (), inputs: tuple = ()):
        if len(prg) != 0x8000:
            raise ValueError("NROM-256 PRG must be exactly 32 KiB")
        self.ram = ram
        self.prg = prg
        #: every write, as (address term, value term), in execution order
        self.writes = writes
        #: unconstrained bytes introduced by bus reads
        self.inputs = inputs

    @classmethod
    def symbolic(cls, prg: bytes, name: str = "RAM") -> "NESMemory":
        return cls(z3.Array(name, z3.BitVecSort(11), z3.BitVecSort(8)), prg)

    def _with(self, **changes) -> "NESMemory":
        fields = dict(ram=self.ram, writes=self.writes, inputs=self.inputs)
        fields.update(changes)
        return NESMemory(fields.pop("ram"), self.prg, **fields)

    def ram_byte(self, index: int) -> z3.BitVecRef:
        return z3.Select(self.ram, z3.BitVecVal(ram_index(index), 11))

    def read(self, address) -> tuple[z3.BitVecRef, "NESMemory"]:
        concrete = as_int(address)
        if concrete is not None:
            kind = region(concrete)
            if kind is Region.RAM:
                return self.ram_byte(concrete), self
            if kind is Region.ROM:
                return z3.BitVecVal(self.prg[concrete - ROM_START], 8), self
            value = fresh(f"bus_{concrete:04X}")
            return value, self._with(inputs=self.inputs + (value,))
        address = z3.simplify(address)
        value = fresh("bus")
        term = z3.If(
            z3.ULT(address, RAM_END),
            z3.Select(self.ram, z3.Extract(10, 0, address)),
            z3.If(z3.UGE(address, ROM_START),
                  z3.Select(self.PRG, z3.Extract(14, 0, address)),
                  value))
        return term, self._with(inputs=self.inputs + (value,))

    def write(self, address, value) -> "NESMemory":
        value = bv8(value)
        concrete = as_int(address)
        log = self.writes + ((bv16(address if concrete is None else concrete),
                              value),)
        if concrete is not None:
            if region(concrete) is Region.RAM:
                ram = z3.Store(self.ram,
                               z3.BitVecVal(ram_index(concrete), 11), value)
                return self._with(ram=ram, writes=log)
            return self._with(writes=log)
        address = z3.simplify(address)
        ram = z3.If(z3.ULT(address, RAM_END),
                    z3.Store(self.ram, z3.Extract(10, 0, address), value),
                    self.ram)
        return self._with(ram=ram, writes=log)

    def read_stack(self, s) -> tuple[z3.BitVecRef, "NESMemory"]:
        """Read `$0100 + s`.  The index is built directly so the result does
        not depend on the simplifier recognising the address as RAM."""
        return z3.Select(self.ram, z3.Concat(z3.BitVecVal(1, 3), s)), self

    def write_stack(self, s, value) -> "NESMemory":
        log = self.writes + ((z3.Concat(z3.BitVecVal(1, 8), s), bv8(value)),)
        ram = z3.Store(self.ram, z3.Concat(z3.BitVecVal(1, 3), s), bv8(value))
        return self._with(ram=ram, writes=log)

    def havoc_write(self) -> "NESMemory":
        """A write whose address and value are both unknown (unstable ops)."""
        return self.write(fresh("unstable_addr", 16), fresh("unstable_val"))

    def prg_axioms(self, addresses: Sequence[int]) -> list[z3.BoolRef]:
        """`PRG[a] == image[a]` for the given CPU addresses."""
        return [z3.Select(self.PRG, z3.BitVecVal(a - ROM_START, 15))
                == self.prg[a - ROM_START] for a in addresses]


class FlatMemory:
    """64 KiB of RAM with no devices, for instruction-level validation only."""

    def __init__(self, cells: dict[int, int] | None = None, *,
                 array: z3.ArrayRef | None = None, writes: tuple = ()):
        self.cells = dict(cells or {})
        self.array = array
        self.writes = writes
        self.inputs: tuple = ()

    def read(self, address):
        concrete = as_int(address)
        if concrete is None:
            if self.array is None:
                raise ValueError("symbolic read from a concrete FlatMemory")
            return z3.Select(self._as_array(), z3.simplify(address)), self
        if concrete in self.cells:
            return z3.BitVecVal(self.cells[concrete], 8), self
        if self.array is not None:
            return z3.Select(self.array, z3.BitVecVal(concrete, 16)), self
        return z3.BitVecVal(0, 8), self

    def _as_array(self):
        array = self.array
        for address, value in self.cells.items():
            array = z3.Store(array, z3.BitVecVal(address, 16),
                             z3.BitVecVal(value, 8))
        return array

    def write(self, address, value):
        concrete, byte = as_int(address), as_int(value)
        if concrete is None or byte is None:
            raise ValueError("FlatMemory takes concrete writes only")
        cells = dict(self.cells)
        cells[concrete] = byte
        return FlatMemory(cells, array=self.array,
                          writes=self.writes + ((concrete, byte),))

    def read_stack(self, s):
        return self.read(z3.Concat(z3.BitVecVal(1, 8), s))

    def write_stack(self, s, value):
        return self.write(z3.Concat(z3.BitVecVal(1, 8), s), value)

    def havoc_write(self):
        raise NotImplementedError("unstable instruction on a concrete memory")
