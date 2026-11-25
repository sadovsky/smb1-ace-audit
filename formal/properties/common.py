"""Shared context: the verified image, the control-flow graph, predicates."""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

import z3

from analysis.cfg import CFG, build_from_vectors

#: assumptions every slice-based result carries (see verify/symexec.py)
SLICE_ASSUMPTIONS = (
    "J-LOCATION: control reaches an instruction only from a predecessor "
    "recorded in the control-flow graph",
    "J-ASYNC: no interrupt handler runs between the instructions of a slice",
)
CALL_ASSUMPTION = ("J-STACK: a called routine returns to the instruction "
                   "after its JSR with the stack pointer restored")
IRQ_ASSUMPTION = ("J-IRQ: no maskable interrupt is ever serviced (the I "
                  "flag stays set), so the IRQ vector target $FFF0 is never "
                  "entered")

#: Every statement in the ledger is about the machine model in formal/model.
#: How well that model matches a physical console is a separate question with
#: a separate status (formal/results/reports/model_validation.json); it is
#: recorded once on the manifest rather than repeated on each obligation.
MODEL_SCOPE = "statement about the machine model in formal/model"


@dataclass
class Context:
    prg: bytes
    sha1: str
    graph: CFG
    #: filled in by instruction_location.direct_transfers
    computed: tuple = ()

    def read(self, address: int) -> int:
        return self.prg[address - 0x8000]


@lru_cache(maxsize=1)
def context() -> Context:
    from rom import b, image

    rom = image()
    return Context(rom.prg, rom.sha1, build_from_vectors(b))


def ram_cell_hit(address, cell: int):
    """`address` (16-bit term) denotes RAM cell `cell`, mirrors included."""
    return z3.And(z3.ULT(address, 0x2000),
                  z3.Extract(10, 0, address) == (cell & 0x7FF))


def stack_page_hit(address):
    return z3.And(z3.ULT(address, 0x2000),
                  z3.Extract(10, 8, address) == 1)


def ppu_control_hit(address):
    return z3.And(z3.UGE(address, 0x2000), z3.ULT(address, 0x4000),
                  z3.Extract(2, 0, address) == 0)
