"""Conservative effective-address sets for 6502 memory writes (plan section 10).

Every store is reduced to the *set of addresses it could possibly write*,
over-approximating wherever the index or pointer is not yet constrained.  The
rule is one-sided on purpose: an over-approximation can only ever add writers
to a variable's manifest, never remove one, so an invariant that survives this
analysis is not an artefact of a missed store.

Address-mode semantics modelled here:

  abs          exact address
  abs,X/abs,Y  base .. base+255 with 16-bit wrap (an indexed store at $FFFF
               wraps to $0000, it does not fault)
  zp           exact, page zero
  zp,X/zp,Y    $00..$FF -- the index wraps *inside* page zero, so a base of
               $F0 can reach $00 but can never reach $0100
  (zp,X)       pointer taken from page zero with wrap; target unresolved
  (zp),Y       pointer plus Y; target unresolved
  stack        $0100 + S, i.e. anywhere in page one as S is not tracked here

`UNRESOLVED` writers are reported, never dropped: "the pointer is unknown" is
a result, not an absence of one.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class AddressKnowledge(str, Enum):
    EXACT = "exact"
    INDEXED_RANGE = "indexed_range"
    PAGE_ZERO = "page_zero"
    STACK_PAGE = "stack_page"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True)
class AddressSet:
    """A set of possible effective addresses, as inclusive ranges."""

    ranges: tuple[tuple[int, int], ...]
    knowledge: AddressKnowledge
    note: str = ""

    def __contains__(self, address: int) -> bool:
        address &= 0xFFFF
        return any(lo <= address <= hi for lo, hi in self.ranges)

    @property
    def size(self) -> int:
        return sum(hi - lo + 1 for lo, hi in self.ranges)

    @property
    def is_resolved(self) -> bool:
        return self.knowledge is not AddressKnowledge.UNRESOLVED

    def to_json(self) -> dict:
        return {
            "ranges": [[lo, hi] for lo, hi in self.ranges],
            "knowledge": self.knowledge.value,
            "size": self.size,
            "note": self.note,
        }


def exact(address: int) -> AddressSet:
    address &= 0xFFFF
    knowledge = (AddressKnowledge.PAGE_ZERO if address < 0x100
                 else AddressKnowledge.EXACT)
    return AddressSet(((address, address),), knowledge)


def indexed_absolute(base: int, *, index_max: int = 0xFF) -> AddressSet:
    """`base,X` / `base,Y` for an unconstrained index, with 16-bit wrap."""
    base &= 0xFFFF
    end = base + index_max
    if end <= 0xFFFF:
        ranges: tuple[tuple[int, int], ...] = ((base, end),)
        note = f"${base:04X}+0..{index_max}"
    else:                                    # wraps past $FFFF
        ranges = ((base, 0xFFFF), (0x0000, end & 0xFFFF))
        note = f"${base:04X}+0..{index_max} (wraps $FFFF->$0000)"
    return AddressSet(ranges, AddressKnowledge.INDEXED_RANGE, note)


def indexed_page_zero(base: int) -> AddressSet:
    """`zp,X` / `zp,Y`: the sum is taken modulo 256, so it stays in page zero."""
    return AddressSet(((0x0000, 0x00FF),), AddressKnowledge.PAGE_ZERO,
                      f"${base & 0xFF:02X}+0..255 wrapped within page zero")


def unresolved_pointer(pointer: int, mode: str) -> AddressSet:
    """`(zp),Y` / `(zp,X)` whose pointer has not been constrained yet."""
    return AddressSet(((0x0000, 0xFFFF),), AddressKnowledge.UNRESOLVED,
                      f"pointer ${pointer & 0xFF:02X} ({mode}) not constrained")


def stack_page() -> AddressSet:
    return AddressSet(((0x0100, 0x01FF),), AddressKnowledge.STACK_PAGE,
                      "$0100+S, stack pointer not tracked")


def constrain_indexed(base: int, index_values: set[int]) -> AddressSet:
    """Refine an indexed store once the index range is known."""
    if not index_values:
        raise ValueError("index_values must not be empty")
    base &= 0xFFFF
    addresses = sorted((base + i) & 0xFFFF for i in index_values)
    ranges: list[tuple[int, int]] = []
    for address in addresses:
        if ranges and address == ranges[-1][1] + 1:
            ranges[-1] = (ranges[-1][0], address)
        else:
            ranges.append((address, address))
    lo, hi = min(index_values), max(index_values)
    return AddressSet(tuple(ranges), AddressKnowledge.INDEXED_RANGE,
                      f"${base:04X}+{lo}..{hi} (index constrained)")
