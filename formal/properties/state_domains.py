"""State-domain obligations (P6): dispatch indices and the `$071F` invariant.

For each dispatch site the question is whether the index is inside the table
*at the fetch of the `JSR $8E04`*.  The slicer either closes it from the code
alone or returns the shortest suffix it could not close together with a
satisfying assignment.  That assignment is an **abstract** counterexample: it
starts from an unconstrained state and says nothing about whether the game
can reach it.

For `$071F` the plan asks for a program-point invariant, `RAM[$071F] <= 8`
when `$92B0` is fetched.  The evidence record lists every instruction the
model says can write that cell and gives each one its own status.
"""
from __future__ import annotations

import z3

from ..verify.obligations import Ledger, Obligation
from ..verify.symexec import Outcome, Slicer
from .common import (CALL_ASSUMPTION, IRQ_ASSUMPTION, MODEL_SCOPE, SLICE_ASSUMPTIONS, Context,
                     ram_cell_hit)

CELL = 0x071F
IRQ_ENTRY = {0xFFF0: IRQ_ASSUMPTION}
DEPTH = 14


def hexes(addresses) -> list[str]:
    return [f"0x{a:04X}" for a in addresses]


def outcome_fields(outcome: Outcome) -> tuple[str, list[str], dict]:
    """(status, assumptions, detail) for a slicer outcome."""
    detail = {"method": "backward-deepening symbolic execution",
              "scope": MODEL_SCOPE,
              "suffixes_proved": outcome.proved_suffixes,
              "longest_suffix": outcome.max_depth,
              "solver_calls": outcome.solver_calls}
    if outcome.holds:
        assumptions = list(SLICE_ASSUMPTIONS)
        if outcome.used_call_summary:
            assumptions.append(CALL_ASSUMPTION)
        assumptions.extend(sorted(outcome.entry_assumptions))
        return "conditional", assumptions, detail
    detail.update(reason=outcome.reason,
                  unclosed_suffix=hexes(outcome.failing_suffix),
                  abstract_state={k: v for k, v in outcome.model.items()
                                  if "RAM" not in k})
    if outcome.reason in ("solver gave no answer", "suffix budget exhausted"):
        return "unknown", [], detail
    return "abstract_counterexample", [], detail


def writers_of(ctx: Context, hit) -> list[int]:
    """Every graph node the model says can write an address satisfying `hit`.

    Decided by the CPU model from a fully unconstrained state, so it does not
    depend on a separately maintained table of addressing modes.
    """
    slicer = Slicer(ctx.graph, ctx.prg)
    bad = lambda state, writes: z3.Or(
        z3.BoolVal(False), *[hit(address) for address, _ in writes])
    found = []
    for pc in sorted(ctx.graph.nodes):
        answer, _, _ = slicer._bad_at((pc,), bad)
        if answer != "unsat":
            found.append(pc)
    return found


def dispatch_indices(ledger: Ledger, ctx: Context) -> None:
    slicer = Slicer(ctx.graph, ctx.prg, closed_entries=IRQ_ENTRY)
    for site, record in sorted(ctx.graph.dispatches.items()):
        count = len(record.entries)
        bad = lambda state, writes, n=count: z3.Not(
            z3.ULT(state.a & 0x7F, n))
        outcome = slicer.prove_never(site, bad, max_depth=DEPTH)
        status, assumptions, detail = outcome_fields(outcome)
        detail["table_entries"] = count
        ledger.add(Obligation(
            f"P6-{site:04X}-INDEX",
            f"(A and $7F) < {count} whenever JSR $8E04 at ${site:04X} is "
            "fetched",
            "program-point invariant", status, assumptions,
            solver="z3", detail=detail))


def cell_071f(ledger: Ledger, ctx: Context) -> None:
    hit = lambda address: ram_cell_hit(address, CELL)
    in_domain = lambda state: z3.ULE(state.mem.ram_byte(CELL), 8)

    # The index, given the invariant as an inductive hypothesis at $92B0.
    hypothesised = Slicer(
        ctx.graph, ctx.prg, closed_entries=IRQ_ENTRY,
        invariants=lambda s: [in_domain(s)] if s.pc == 0x92B0 else [])
    outcome = hypothesised.prove_never(
        0x92C8, lambda state, writes: z3.Not(z3.ULT(state.a & 0x7F, 8)),
        max_depth=DEPTH)
    status, assumptions, detail = outcome_fields(outcome)
    ledger.add(Obligation(
        "P6-92C8-INDEX-GIVEN-071F",
        "(A and $7F) < 8 at the fetch of $92C8, given RAM[$071F] <= 8 "
        "whenever $92B0 is fetched",
        "program-point invariant, relative to another", status, assumptions,
        dependencies=["P6-071F-PP"], solver="z3", detail=detail))

    # Every writer must preserve the domain.  The hypothesis RAM[$071F] <= 8
    # is assumed at every state of a slice: under induction it holds at all
    # earlier states, and the obligation is that the write keeps it.
    preserving = Slicer(ctx.graph, ctx.prg, closed_entries=IRQ_ENTRY,
                        invariants=lambda s: [in_domain(s)])
    breaks = lambda state, writes: z3.Or(z3.BoolVal(False), *[
        z3.And(hit(address), z3.UGT(value, 8)) for address, value in writes])
    writers = writers_of(ctx, hit)
    ids = []
    for pc in writers:
        outcome = preserving.prove_never(pc, breaks, max_depth=DEPTH)
        status, assumptions, detail = outcome_fields(outcome)
        detail["instruction"] = str(ctx.graph.nodes[pc].instruction)
        ids.append(f"W-071F-{pc:04X}")
        ledger.add(Obligation(
            ids[-1],
            f"the instruction at ${pc:04X} never stores a value above 8 "
            "into RAM[$071F] (mirrors included)",
            "preservation obligation for one writer", status, assumptions,
            solver="z3", detail=detail))

    ledger.add(Obligation(
        "INIT-071F",
        "RAM[$071F] <= 8 at the first fetch of $92B0 after cold boot",
        "initialisation obligation", "unknown",
        detail={"why_open": "cold-boot RAM is unconstrained; the cell is "
                "cleared by the memory-initialisation loop at $90CC, whose "
                "store is the indirect writer $90DC.  Closing this needs a "
                "loop invariant for that routine and a proof that the NMI "
                "handler cannot run before it (MA-PPU-POWERON, MA-PPU-WARMUP "
                "and the PPU-control write obligations).  Not attempted."}))

    closed = [i for i in ids if ledger.items[i].status == "conditional"]
    ledger.add(Obligation(
        "P6-071F-PP",
        "RAM[$071F] <= 8 whenever $92B0 is fetched",
        "program-point invariant", "unknown",
        dependencies=["INIT-071F"] + ids,
        detail={
            "needed_at": ["0x92B0"],
            "candidate_domain": "unsigned interval [0, 8]",
            "possible_writers": len(ids),
            "writers_closed": len(closed),
            "writers_open": len(ids) - len(closed),
            "strengthening": "stated here as a global invariant of the cell, "
                             "which is stronger than the program-point form "
                             "and is what the writer obligations preserve",
            "why_unknown": "initialisation is open and most writers are "
                           "open; see the dependencies"}))


def run(ledger: Ledger, ctx: Context) -> None:
    dispatch_indices(ledger, ctx)
    cell_071f(ledger, ctx)
