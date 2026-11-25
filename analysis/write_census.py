"""Conservative census of every instruction that can write RAM (plan section 10).

An invariant such as `RAM[$071F] <= 8` is only as good as the list of
instructions that can modify it.  This module enumerates the writers of any
address by decoding the PRG and classifying each store's effective-address set
with `effective_address`, keeping three categories apart:

  exact        the address is the operand; the writer definitely can hit it
  indexed      `base,X`/`base,Y` whose range covers the address; needs the
               index range to be bounded before it can be dismissed
  unresolved   `(zp),Y`/`(zp,X)`/stack writes whose target is not yet
               constrained; these are *reported*, never silently dropped

`writers_of()` therefore returns an over-approximation.  A variable whose
manifest contains unresolved writers cannot carry a PROVEN bound, which is why
`$071F` is STRUCTURAL_CONDITIONAL in `analysis.dispatch_index`.

Scope: by default the census decodes the instruction starts discovered by
`trace.py`.  Instruction starts missed by the tracer would be missed here too,
so `scope="linear"` additionally decodes every byte offset in PRG as a
potential instruction start.  That is a much coarser over-approximation and is
the honest default when asking "could anything anywhere write this?".
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence

from d65 import LEN, M

from . import effective_address as ea
from .effective_address import AddressKnowledge, AddressSet

#: Instructions that write memory (plus the register that supplies the value).
STORE_VALUE_SOURCE = {"STA": "A", "STX": "X", "STY": "Y"}

#: Read-modify-write instructions: they both read and write the location.
RMW = {"INC", "DEC", "ASL", "LSR", "ROL", "ROR"}

#: Stack pushes write page one.
PUSH = {"PHA": "A", "PHP": "P"}


@dataclass(frozen=True)
class Writer:
    """One instruction that can modify memory."""

    address: int                 # CPU address of the instruction
    opcode: int
    mnemonic: str
    mode: str
    targets: AddressSet
    value_source: str            # "A"/"X"/"Y"/"P"/"memory" (for RMW)
    reached_by_tracer: bool

    @property
    def is_read_modify_write(self) -> bool:
        return self.mnemonic in RMW

    def category(self) -> str:
        if self.targets.knowledge is AddressKnowledge.UNRESOLVED:
            return "unresolved"
        if self.targets.knowledge is AddressKnowledge.STACK_PAGE:
            return "stack"
        if self.targets.size == 1:
            return "exact"
        return "indexed"

    def to_json(self) -> dict:
        return {
            "address": f"0x{self.address:04X}",
            "opcode": f"0x{self.opcode:02X}",
            "mnemonic": self.mnemonic,
            "mode": self.mode,
            "category": self.category(),
            "value_source": self.value_source,
            "read_modify_write": self.is_read_modify_write,
            "reached_by_tracer": self.reached_by_tracer,
            "targets": self.targets.to_json(),
        }


def _targets_for(mode: str, mnemonic: str, operand_lo: int,
                 operand_hi: int) -> AddressSet | None:
    if mode == "abs":
        return ea.exact(operand_lo | operand_hi << 8)
    if mode in ("abx", "aby"):
        return ea.indexed_absolute(operand_lo | operand_hi << 8)
    if mode == "zp":
        return ea.exact(operand_lo)
    if mode in ("zpx", "zpy"):
        return ea.indexed_page_zero(operand_lo)
    if mode == "izy":
        return ea.unresolved_pointer(operand_lo, "(zp),Y")
    if mode == "izx":
        return ea.unresolved_pointer(operand_lo, "(zp,X)")
    if mode == "imp" and mnemonic in PUSH:
        return ea.stack_page()
    return None


def decode_writer(read_byte: Callable[[int], int], pc: int,
                  *, reached: bool) -> Writer | None:
    """Decode the instruction at `pc`; return a Writer if it modifies memory."""
    opcode = read_byte(pc)
    if opcode not in M:
        return None
    mnemonic, mode = M[opcode]
    if mnemonic not in STORE_VALUE_SOURCE and mnemonic not in RMW \
            and mnemonic not in PUSH:
        return None
    length = LEN[mode]
    if mnemonic in RMW and mode == "acc":
        return None                      # ASL A and friends touch no memory
    operand_lo = read_byte(pc + 1) if length > 1 else 0
    operand_hi = read_byte(pc + 2) if length > 2 else 0
    targets = _targets_for(mode, mnemonic, operand_lo, operand_hi)
    if targets is None:
        return None
    value_source = (STORE_VALUE_SOURCE.get(mnemonic)
                    or PUSH.get(mnemonic)
                    or "memory")
    return Writer(pc, opcode, mnemonic, mode, targets, value_source, reached)


def _tracer_starts(trace_path: str) -> set[int]:
    if not os.path.exists(trace_path):
        return set()
    with open(trace_path) as handle:
        return set(json.load(handle)["instruction_starts"])


def census(read_byte: Callable[[int], int], *, scope: str = "linear",
           trace_path: str = "trace.json",
           prg_range: tuple[int, int] = (0x8000, 0x10000)) -> list[Writer]:
    """Enumerate memory writers in PRG.

    scope="traced"  only instruction starts found by trace.py
    scope="linear"  every byte offset as a candidate instruction start
                    (over-approximates, catches starts the tracer missed)
    """
    reached = _tracer_starts(trace_path)
    if scope == "traced":
        candidates: Iterable[int] = sorted(reached)
    elif scope == "linear":
        candidates = range(*prg_range)
    else:
        raise ValueError(f"unknown scope {scope!r}")

    writers = []
    for pc in candidates:
        writer = decode_writer(read_byte, pc, reached=pc in reached)
        if writer is not None:
            writers.append(writer)
    return writers


def writers_of(address: int, writers: Sequence[Writer]) -> dict[str, list[Writer]]:
    """Partition the writers that could modify `address` by how well resolved."""
    buckets: dict[str, list[Writer]] = {"exact": [], "indexed": [],
                                        "stack": [], "unresolved": []}
    for writer in writers:
        if address in writer.targets:
            buckets[writer.category()].append(writer)
    return buckets


def manifest(address: int, writers: Sequence[Writer], *,
             name: str = "") -> dict:
    """A writer manifest for one variable, suitable for results/*.json."""
    buckets = writers_of(address, writers)
    resolved_only = not buckets["unresolved"] and not buckets["stack"]
    return {
        "address": f"0x{address:04X}",
        "name": name,
        "counts": {k: len(v) for k, v in buckets.items()},
        "fully_resolved": resolved_only,
        "status": ("every writer resolved" if resolved_only
                   else "contains writers whose target is not constrained"),
        "writers": {k: [w.to_json() for w in v] for k, v in buckets.items()},
    }
