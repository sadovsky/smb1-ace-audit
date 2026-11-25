"""Dispatch properties (P2, P3) and the first-milestone lemmas for `$92C8`.

Three layers, kept apart because they are different kinds of evidence:

1. an arithmetic lemma about the *reported* transformation (no ROM involved);
2. the same lemma re-derived by executing the cartridge's own bytes through
   the validated CPU model, which is what ties (1) to the program;
3. for every dispatch site, a contract: if the accumulator's low seven bits
   index inside the table when the `JSR $8E04` is fetched, the next fetch
   after the JumpEngine is at exactly the table's entry for that index.

None of these says the index *is* in range.  That is a program-point
invariant with its own status (`state_domains.py`).
"""
from __future__ import annotations

import z3

from ..model import cpu
from ..model.cpu import State
from ..model.memory import NESMemory
from ..verify.obligations import Ledger, check_valid
from .common import Context

PREP_92C8, SITE_92C8, CELL_92C8 = 0x92B0, 0x92C8, 0x071F


def arithmetic_lemma(ledger: Ledger) -> None:
    v = z3.BitVec("v", 8)
    index = z3.If(v == 0, z3.BitVecVal(8, 8), v) - 1
    ledger.record(
        "L-92C8-ARITH",
        "v <= 8 implies ((v or 8) - 1) mod 256 <= 7",
        "local arithmetic lemma (no program bytes involved)",
        check_valid("L-92C8-ARITH", z3.ULE(index, 7), [z3.ULE(v, 8)]))
    ledger.record(
        "L-92C8-ARITH-NEG",
        "for all v: ((v or 8) - 1) mod 256 <= 7   [expected to be refuted]",
        "negative regression test: the lemma without its precondition",
        check_valid("L-92C8-ARITH-NEG", z3.ULE(index, 7), []),
        detail={"purpose": "shows the precondition is doing the work; a "
                           "'proved' here would mean the check is vacuous"})


def _paths(state: State, stop: int, limit: int = 32):
    """All synchronous paths from `state` to the first fetch at `stop`."""
    pending, finished = [([], state)], []
    for _ in range(limit):
        if not pending:
            return finished
        advanced = []
        for conditions, current in pending:
            if current.pc == stop:
                finished.append((conditions, current))
                continue
            for successor in cpu.step(current):
                advanced.append((conditions + [successor.guard],
                                 successor.state))
        pending = advanced
    raise RuntimeError(f"did not converge on ${stop:04X}")


def rom_lemma(ledger: Ledger, ctx: Context) -> None:
    """Layer 2: the bytes at `$92B0-$92BE` implement the lemma."""
    memory = NESMemory.symbolic(ctx.prg)
    start = State.symbolic(PREP_92C8, memory)
    cell = memory.ram_byte(CELL_92C8)
    paths = _paths(start, SITE_92C8)
    in_range = z3.And(*[z3.Implies(z3.And(*conditions), z3.ULE(state.a, 7))
                        for conditions, state in paths])
    exact = z3.And(*[
        z3.Implies(z3.And(*conditions),
                   state.a == z3.If(cell == 0, z3.BitVecVal(8, 8), cell) - 1)
        for conditions, state in paths])
    detail = {"entry": "0x92B0", "exit": "0x92C8", "paths": len(paths),
              "instructions": "decoded from the verified image by the model"}
    ledger.record(
        "L-92C8-ROM-EXACT",
        "executing $92B0 to the fetch at $92C8 leaves "
        "A = ((RAM[$071F] or 8) - 1) mod 256, for every initial state",
        "local lemma over program bytes",
        check_valid("L-92C8-ROM-EXACT", exact, []),
        detail=detail)
    ledger.record(
        "L-92C8-ROM",
        "RAM[$071F] <= 8 at $92B0 implies A <= 7 at the fetch of $92C8",
        "local lemma over program bytes",
        check_valid("L-92C8-ROM", in_range, [z3.ULE(cell, 8)]),
        detail=detail)
    ledger.record(
        "L-92C8-ROM-NEG",
        "A <= 7 at the fetch of $92C8 for every RAM[$071F]   "
        "[expected to be refuted]",
        "negative regression test over program bytes",
        check_valid("L-92C8-ROM-NEG", in_range, []),
        detail={"purpose": "the routine has no upper clamp"})


def _through_engine(ctx: Context, site: int):
    """Symbolic state at `site`; returns (A at site, final PC term, memory)."""
    memory = NESMemory.symbolic(ctx.prg)
    state = start = State.symbolic(site, memory)
    for _ in range(20):
        if not isinstance(state.pc, int):
            return start, state
        (successor,) = cpu.step(state)
        state = successor.state
    raise RuntimeError("JumpEngine did not finish")


def site_contracts(ledger: Ledger, ctx: Context) -> None:
    starts = ctx.graph.instruction_starts
    for site, record in sorted(ctx.graph.dispatches.items()):
        entries, table, count = record.entries, record.table, len(record.entries)
        start, final = _through_engine(ctx, site)
        index = start.a & 0x7F
        axioms = start.mem.prg_axioms(range(table, table + 2 * count))
        exact = z3.And(*[z3.Implies(index == i, final.pc == entry)
                         for i, entry in enumerate(entries)])
        name = f"D-{site:04X}-CONTRACT"
        foreign = [f"0x{e:04X}" for e in entries if e not in starts]
        ledger.record(
            name,
            f"if (A and $7F) < {count} when JSR $8E04 at ${site:04X} is "
            "fetched, the next fetch after the JumpEngine is at the table "
            "entry for that index, for every stack pointer and RAM content",
            "dispatch contract (P2, P3) for one site",
            check_valid(name, exact, axioms + [z3.ULT(index, count)],
                        rom_derived=True),
            detail={"table": f"0x{table:04X}", "entries": count,
                    "entries_not_instruction_starts": foreign,
                    "frame": "pushed by the JSR itself inside the query, so "
                             "frame authenticity is not an assumption here"})
        if site == SITE_92C8:
            wider = start.mem.prg_axioms(range(table, table + 2 * count + 2))
            ledger.record(
                "D-92C8-CONTRACT-NEG",
                f"the same conclusion for (A and $7F) <= {count}   "
                "[expected to be refuted]",
                "negative regression test: one index past the table",
                check_valid("D-92C8-CONTRACT-NEG",
                            z3.Or(*[final.pc == e for e in entries]),
                            wider + [z3.ULE(index, count)], rom_derived=True),
                detail={"purpose": "index 8 reads the two bytes after the "
                                   "table and leaves it"})


def run(ledger: Ledger, ctx: Context) -> None:
    arithmetic_lemma(ledger)
    rom_lemma(ledger, ctx)
    site_contracts(ledger, ctx)
