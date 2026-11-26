"""Abstract domains for the certificate proposer (plan sections 8, 11).

Everything here is **untrusted**: it exists to guess a certificate, and the
only thing that decides whether the guess is a proof is
`formal/verify/certificate.py`.  That is why this module is allowed to be
heuristic, to widen aggressively and to carry hand-supplied hints.

The domain is the one the certificate language can express
(`formal/verify/JOINT_INVARIANT.md` section 3):

* a `ByteSet` (256-bit mask) per register `A`, `X`, `Y`, `S`;
* three-valued flags `C Z N V I D`;
* a sparse map from mirror-normalised RAM cells to `ByteSet`, restricted to a
  fixed set of *tracked* cells so that the formulas the checker builds stay
  small;
* `copies`: facts of the form `register == RAM[cell]`, which is what lets a
  dispatch target refine the cell its index came from;
* `depth`: the set of possible values of `s0 - S` inside the current routine.

`bottom` is the empty set of states, which the certificate writes as `false`.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Iterable

FULL = (1 << 256) - 1
EMPTY = 0

REGISTERS = ("a", "x", "y", "s")
FLAGS = ("c", "z", "n", "v", "i", "d")


def one(value: int) -> int:
    return 1 << (value & 0xFF)


def from_values(values: Iterable[int]) -> int:
    mask = 0
    for value in values:
        mask |= 1 << (value & 0xFF)
    return mask


def values(mask: int) -> list[int]:
    if mask == FULL:
        return list(range(256))
    return [v for v in range(256) if mask >> v & 1]


def size(mask: int) -> int:
    return bin(mask).count("1")


def shift_by(mask: int, delta: int) -> int:
    """`{v + delta mod 256 : v in mask}`, as a rotation of the bit mask.

    `INX`, `DEY`, `INC` and `DEC` are among the most frequently interpreted
    instructions, and doing this as a rotation instead of a 256-step loop is
    most of the proposer's running time.
    """
    delta &= 0xFF
    if delta == 0:
        return mask
    return ((mask << delta) | (mask >> (256 - delta))) & FULL


def bounds(mask: int) -> tuple[int, int]:
    """`(min, max)` of a non-empty value set."""
    return ((mask & -mask).bit_length() - 1, mask.bit_length() - 1)


def unary(mask: int, function) -> int:
    if mask == FULL:
        out = 0
        for value in range(256):
            out |= 1 << (function(value) & 0xFF)
        return out
    out = 0
    for value in values(mask):
        out |= 1 << (function(value) & 0xFF)
    return out


def binary(left: int, right: int, function, *, absorbing: bool = False) -> int:
    if absorbing and FULL in (left, right) and left and right:
        return FULL
    if size(left) * size(right) > 4096:
        return FULL
    out = 0
    for a in values(left):
        for b in values(right):
            out |= 1 << (function(a, b) & 0xFF)
    return out


def restrict(mask: int, predicate) -> int:
    out = 0
    for value in values(mask):
        if predicate(value):
            out |= 1 << value
    return out


def agree(mask: int, predicate) -> bool | None:
    """True/False when every value in the set agrees, else None."""
    if mask == EMPTY:
        return None
    seen = {predicate(v) for v in values(mask)}
    return seen.pop() if len(seen) == 1 else None


def meet_flag(left, right):
    if left is None:
        return right
    if right is None:
        return left
    return left if left == right else "conflict"


def join_flag(left, right):
    return left if left == right else None


# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Abs:
    """One abstract state."""
    bottom: bool = False
    a: int = FULL
    x: int = FULL
    y: int = FULL
    s: int = FULL
    c: bool | None = None
    z: bool | None = None
    n: bool | None = None
    v: bool | None = None
    i: bool | None = True
    d: bool | None = None
    #: tracked cell -> ByteSet.  A cell that is absent is unconstrained.
    cells: tuple = ()                       # sorted ((cell, mask), ...)
    #: (register name, cell) with `register == RAM[cell]`
    copies: frozenset = frozenset()
    #: (flag, relation, register, k) facts a comparison leaves behind
    rel: tuple = ()
    #: possible values of `s0 - S`; None means unknown
    depth: frozenset | None = None
    frame: bool = False
    status_i: bool = False

    BOTTOM: "Abs" = None

    # -- cells -------------------------------------------------------------

    @property
    def cellmap(self) -> dict:
        return dict(self.cells)

    def with_cells(self, mapping: dict) -> "Abs":
        return replace(self, cells=tuple(sorted(
            (c, m) for c, m in mapping.items() if m != FULL)))

    def cell(self, address: int) -> int:
        return self.cellmap.get(address & 0x7FF, FULL)

    def set_cell(self, address: int, mask: int) -> "Abs":
        cells = self.cellmap
        address &= 0x7FF
        if mask == FULL:
            cells.pop(address, None)
        else:
            cells[address] = mask
        copies = frozenset((r, c) for r, c in self.copies if c != address)
        return replace(self.with_cells(cells), copies=copies)

    def forget_cells(self, addresses: Iterable[int]) -> "Abs":
        cells = self.cellmap
        dropped = set()
        for address in addresses:
            address &= 0x7FF
            cells.pop(address, None)
            dropped.add(address)
        copies = frozenset((r, c) for r, c in self.copies if c not in dropped)
        return replace(self.with_cells(cells), copies=copies)

    # -- registers ---------------------------------------------------------

    def register(self, name: str) -> int:
        return getattr(self, name)

    def set_register(self, name: str, mask: int) -> "Abs":
        copies = frozenset((r, c) for r, c in self.copies if r != name)
        return replace(self, copies=copies, **{name: mask})

    def set_nz(self, mask: int) -> "Abs":
        return replace(self, z=agree(mask, lambda v: v == 0),
                       n=agree(mask, lambda v: v & 0x80 != 0))

    @property
    def feasible(self) -> bool:
        if self.bottom:
            return False
        if any(self.register(r) == EMPTY for r in REGISTERS):
            return False
        if any(mask == EMPTY for _c, mask in self.cells):
            return False
        return self.depth != frozenset()

    # -- lattice -----------------------------------------------------------

    def join(self, other: "Abs") -> "Abs":
        if self.bottom:
            return other
        if other.bottom:
            return self
        cells = {}
        mine, theirs = self.cellmap, other.cellmap
        for cell in set(mine) & set(theirs):
            merged = mine[cell] | theirs[cell]
            if merged != FULL:
                cells[cell] = merged
        depth = (None if self.depth is None or other.depth is None
                 else self.depth | other.depth)
        return Abs(
            bottom=False,
            a=self.a | other.a, x=self.x | other.x, y=self.y | other.y,
            s=self.s | other.s,
            c=join_flag(self.c, other.c), z=join_flag(self.z, other.z),
            n=join_flag(self.n, other.n), v=join_flag(self.v, other.v),
            i=join_flag(self.i, other.i), d=join_flag(self.d, other.d),
            cells=tuple(sorted(cells.items())),
            copies=self.copies & other.copies,
            rel=tuple(r for r in self.rel if r in set(other.rel)),
            depth=depth, frame=self.frame and other.frame,
            status_i=self.status_i and other.status_i)

    def key(self) -> tuple:
        return (self.bottom, self.a, self.x, self.y, self.s, self.c, self.z,
                self.n, self.v, self.i, self.d, self.cells,
                tuple(sorted(self.copies)), tuple(sorted(self.rel)),
                None if self.depth is None else tuple(sorted(self.depth)),
                self.frame, self.status_i)

    # -- certificate form --------------------------------------------------

    def to_json(self, *, tracked: frozenset | None = None,
                extra: dict | None = None) -> dict:
        if self.bottom or not self.feasible:
            return {"false": True}
        out: dict = {}
        for name in REGISTERS:
            mask = self.register(name)
            if mask != FULL:
                out[name] = _runs(mask)
        for name in FLAGS:
            value = getattr(self, name)
            if name == "i":
                out["i"] = True if value is True else value
            elif value is not None:
                out[name] = value
        cells = {}
        for cell, mask in self.cells:
            if tracked is not None and cell not in tracked:
                continue
            cells[f"{cell:04X}"] = _runs(mask)
        if cells:
            out["cells"] = cells
        copies = [[r, f"{c:04X}"] for r, c in sorted(self.copies)
                  if tracked is None or c in tracked]
        if copies:
            out["copies"] = copies
        if self.rel:
            out["rel"] = [[f, op, r, k] for f, op, r, k in sorted(self.rel)]
        if self.depth is not None:
            out["depth"] = sorted(self.depth)
        if self.frame:
            out["frame"] = True
        if self.status_i:
            out["status_i"] = True
        if extra:
            out.update(extra)
        return out


Abs.BOTTOM = Abs(bottom=True)


def _runs(mask: int) -> list[list[int]]:
    runs: list[list[int]] = []
    for value in values(mask):
        if runs and value == runs[-1][1] + 1:
            runs[-1][1] = value
        else:
            runs.append([value, value])
    return runs
