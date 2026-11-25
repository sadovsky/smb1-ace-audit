"""Instruction-accurate model of SMB1's JumpEngine at CPU $8E04."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

CPURead = Callable[[int], int]


@dataclass(frozen=True)
class JumpEngineResolution:
    index: int
    return_address: int
    initial_y: int
    low_address: int
    high_address: int
    target: int


def resolve_jumpengine(
    read_cpu: CPURead, *, return_address: int, accumulator: int
) -> JumpEngineResolution:
    """Execute the address-forming semantics of the actual routine."""
    index = accumulator & 0xFF
    pointer = return_address & 0xFFFF
    y = (index << 1) & 0xFF
    initial_y = y
    y = (y + 1) & 0xFF
    low_address = (pointer + y) & 0xFFFF
    low = read_cpu(low_address) & 0xFF
    y = (y + 1) & 0xFF
    high_address = (pointer + y) & 0xFFFF
    high = read_cpu(high_address) & 0xFF
    return JumpEngineResolution(
        index=index,
        return_address=pointer,
        initial_y=initial_y,
        low_address=low_address,
        high_address=high_address,
        target=low | (high << 8),
    )


def resolve_table(read_cpu: CPURead, table_address: int, index: int) -> JumpEngineResolution:
    """Resolve a table placed immediately after the caller's JSR instruction."""
    return resolve_jumpengine(
        read_cpu, return_address=(table_address - 1) & 0xFFFF, accumulator=index
    )
