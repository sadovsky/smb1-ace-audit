"""The primary theorem P1, decomposed into what a proof of it must discharge.

Candidate invariant: let `N` be the control-flow graph's instruction starts,
all inside PRG ROM.  `J_location(s) := Fetch(s) => PC(s) in N`.  It implies
`P` because `N` is a subset of `$8000-$FFFF`, and it is also P7.

Consecution of `J_location` splits by how the instruction at PC transfers
control.  This module discharges the parts that are properties of single
instructions and records the rest as named dependencies:

LOC-DIRECT    every instruction in `N` whose successors are fixed by its own
              bytes (fallthrough, branch, JMP abs, JSR, BRK) has all of them
              in `N`.  Checked by executing each of them in the CPU model from
              an unconstrained state.
LOC-ENGINE    the single `JMP (abs)` is the JumpEngine's, and the JumpEngine
              is entered only from the dispatch sites; closure then follows
              from the per-site contracts and the per-site index invariants.
LOC-RETURN    every `RTS`/`RTI` lands in `N`.  This is frame integrity (P4,
              P5) and is not established here.
LOC-ASYNC     the three interrupt vectors point into `N`.

`P1` itself is recorded with whatever status those give it.  It is not
`proved`, and this module cannot make it so.
"""
from __future__ import annotations

import z3

from analysis.cfg import JUMPENGINE
from analysis.decoder import Flow

from ..model import cpu
from ..verify.obligations import Ledger, Obligation
from ..verify.symexec import Slicer, havoc_state
from .common import (IRQ_ASSUMPTION, MODEL_SCOPE, Context, ppu_control_hit,
                     stack_page_hit)
from .state_domains import hexes, outcome_fields, writers_of

IRQ_ENTRY = {0xFFF0: IRQ_ASSUMPTION}
EXHAUSTIVE = "exhaustive execution of the CPU model, one node at a time"


def direct_transfers(ledger: Ledger, ctx: Context) -> None:
    nodes, starts = ctx.graph.nodes, ctx.graph.instruction_starts
    escapes, computed, halts = {}, [], []
    for pc in sorted(nodes):
        for successor in cpu.step(havoc_state(pc, ctx.prg)):
            target = successor.state.pc
            if successor.kind == "halt":
                halts.append(pc)
            elif not isinstance(target, int):
                computed.append(pc)
            elif target not in starts:
                escapes.setdefault(pc, []).append(target)
    slicer = Slicer(ctx.graph, ctx.prg, closed_entries=IRQ_ENTRY)
    reachable_escapes, closed = {}, {}
    for pc, targets in escapes.items():
        # is the escaping instruction itself reachable?  `bad` is simply True.
        outcome = slicer.prove_never(pc, lambda s, w: z3.BoolVal(True),
                                     max_depth=14)
        if outcome.holds:
            closed[pc] = sorted(outcome.entry_assumptions) or ["none"]
        else:
            reachable_escapes[pc] = targets
    status = "abstract_counterexample" if reachable_escapes else "conditional"
    assumptions = sorted({a for v in closed.values() for a in v} - {"none"})
    if closed:
        assumptions.insert(0, "J-LOCATION and J-ASYNC, for the nodes shown "
                              "unreachable by slicing")
    ledger.add(Obligation(
        "LOC-DIRECT",
        "every instruction start in N with a statically determined successor "
        "has all its successors in N",
        "consecution of J_location for direct transfers",
        "proved" if not escapes else status,
        assumptions if escapes else [],
        solver=EXHAUSTIVE,
        detail={
            "scope": MODEL_SCOPE,
            "instruction_starts": len(nodes),
            "computed_transfers": len(set(computed)),
            "halting_instructions": hexes(sorted(set(halts))),
            "nodes_with_a_successor_outside_N": {
                f"0x{pc:04X}": hexes(t) for pc, t in escapes.items()},
            "of_those_shown_unreachable": {
                f"0x{pc:04X}": why for pc, why in closed.items()},
            "of_those_not_shown_unreachable": {
                f"0x{pc:04X}": hexes(t)
                for pc, t in reachable_escapes.items()},
        }))
    ctx.computed = sorted(set(computed))


def engine_entry(ledger: Ledger, ctx: Context) -> None:
    nodes = ctx.graph.nodes
    indirect = sorted(pc for pc, n in nodes.items()
                      if n.instruction.info.flow is Flow.INDIRECT_JUMP)
    body, pc = [], JUMPENGINE
    while True:
        body.append(pc)
        if nodes[pc].instruction.info.flow is Flow.INDIRECT_JUMP:
            break
        pc = nodes[pc].instruction.end
    side_entries = {
        f"0x{pc:04X}": hexes(sorted({p for p, _ in nodes[pc].predecessors}
                                    - set(body)))
        for pc in body
        if {p for p, _ in nodes[pc].predecessors} - set(body)}
    callers = sorted(pc for pc, n in nodes.items()
                     if n.instruction.info.flow is Flow.CALL
                     and n.instruction.operand16 == JUMPENGINE)
    jumps_in = sorted(
        pc for pc, n in nodes.items()
        if any(t in body for t, k in n.successors) and pc not in body)
    ok = (indirect == [body[-1]] and not side_entries and not jumps_in
          and callers == sorted(ctx.graph.dispatches))
    sites = sorted(ctx.graph.dispatches)
    ledger.add(Obligation(
        "LOC-ENGINE",
        "the only JMP (abs) in N is the JumpEngine's, the JumpEngine is "
        "straight-line, and it is entered only by JSR from the dispatch sites",
        "structural fact about N", "proved" if ok else "refuted",
        solver="graph inspection",
        detail={"indirect_jumps": hexes(indirect), "body": hexes(body),
                "side_entries": side_entries, "other_jumps_in": hexes(jumps_in),
                "calling_sites": len(callers)}))
    ledger.add(Obligation(
        "LOC-DISPATCH",
        "every fetch that follows the JumpEngine's JMP ($0006) is in N",
        "consecution of J_location for the indirect jump", "unknown",
        dependencies=["LOC-ENGINE"]
        + [f"D-{s:04X}-CONTRACT" for s in sites]
        + [f"P6-{s:04X}-INDEX" for s in sites],
        detail={"why_unknown": "follows from the contracts once every site's "
                               "index invariant holds; see the P6 items"}))


def returns(ledger: Ledger, ctx: Context) -> None:
    """Frame integrity is not proved; record what bears on it."""
    slicer = Slicer(ctx.graph, ctx.prg, closed_entries=IRQ_ENTRY)
    stack_ops = {"PHA", "PHP", "JSR", "BRK"}
    stores = [pc for pc in writers_of(ctx, stack_page_hit)
              if ctx.graph.nodes[pc].instruction.info.mnemonic
              not in stack_ops]
    bad = lambda state, writes: z3.Or(
        z3.BoolVal(False), *[stack_page_hit(a) for a, _ in writes])
    per_store = {}
    for pc in stores:
        outcome = slicer.prove_never(pc, bad, max_depth=12)
        status, assumptions, detail = outcome_fields(outcome)
        per_store[f"0x{pc:04X}"] = {
            "instruction": str(ctx.graph.nodes[pc].instruction),
            "status": status,
            **({"unclosed_suffix": detail["unclosed_suffix"]}
               if "unclosed_suffix" in detail else {})}
    closed = sum(v["status"] == "conditional" for v in per_store.values())
    ledger.add(Obligation(
        "STACK-PAGE-STORES",
        "no instruction other than a push writes $0100-$01FF",
        "frame condition needed by P4 and P5",
        "conditional" if closed == len(per_store) else "abstract_counterexample",
        ["J-LOCATION", "J-ASYNC", IRQ_ASSUMPTION]
        if closed == len(per_store) else [],
        solver="z3",
        detail={"non_push_instructions_that_can_address_the_stack_page":
                len(per_store), "closed_by_slicing": closed,
                "open": len(per_store) - closed, "per_instruction": per_store,
                "note": "stronger than needed: the game legitimately keeps "
                        "data at the bottom of page 1, so an open item here "
                        "is not evidence of a fault"}))
    transfers = [pc for pc in ctx.computed
                 if ctx.graph.nodes[pc].instruction.info.flow is Flow.RETURN]
    ledger.add(Obligation(
        "LOC-RETURN",
        "every RTS and RTI in N transfers to an address in N",
        "consecution of J_location for returns (P4, P5)", "unknown",
        dependencies=["STACK-PAGE-STORES", "J-STACK-SHADOW"],
        detail={"returns_in_N": len(transfers),
                "supporting_evidence_not_a_proof":
                    "results/stack_analysis.json: abstract stack semantics "
                    "find every reachable RTS consuming its entry frame, "
                    "assuming no store corrupts the frame",
                "why_unknown": "no shadow-stack invariant has been stated or "
                               "checked against the transition relation"}))


def asynchronous(ledger: Ledger, ctx: Context) -> None:
    starts = ctx.graph.instruction_starts
    word = lambda a: ctx.read(a) | ctx.read(a + 1) << 8
    vectors = {"nmi": word(cpu.NMI_VECTOR), "reset": word(cpu.RESET_VECTOR),
               "irq": word(cpu.IRQ_VECTOR)}
    ok = all(v in starts for v in vectors.values())
    ledger.add(Obligation(
        "LOC-ASYNC",
        "the NMI, reset and IRQ vectors each point at an instruction start "
        "in N",
        "consecution of J_location for interrupt and reset entry",
        "proved" if ok else "refuted", solver="graph inspection",
        detail={k: f"0x{v:04X}" for k, v in vectors.items()}))

    nodes = ctx.graph.nodes
    clearing = sorted(pc for pc, n in nodes.items()
                      if n.instruction.info.mnemonic in ("CLI", "PLP"))
    ledger.add(Obligation(
        "J-IRQ",
        "the I flag is set at every instruction boundary after reset",
        "invariant used to close the IRQ entry", "unknown",
        dependencies=["LOC-RETURN"],
        detail={"cli_or_plp_in_N": hexes(clearing),
                "why_unknown": "no CLI or PLP is in N, so only RTI can clear "
                               "I, and RTI restores a pushed status byte; "
                               "that the byte it pulls is the one pushed is "
                               "frame integrity, which is open"}))

    slicer = Slicer(ctx.graph, ctx.prg, closed_entries=IRQ_ENTRY)
    enabling = lambda state, writes: z3.Or(z3.BoolVal(False), *[
        z3.And(ppu_control_hit(a), z3.Extract(7, 7, v) == 1)
        for a, v in writes])
    per_writer = {}
    for pc in writers_of(ctx, ppu_control_hit):
        outcome = slicer.prove_never(pc, enabling, max_depth=12)
        per_writer[f"0x{pc:04X}"] = {
            "instruction": str(nodes[pc].instruction),
            "can_set_enable": not outcome.holds}
    ledger.add(Obligation(
        "J-ASYNC",
        "no interrupt handler runs between two instructions of game logic",
        "invariant every slice-based result assumes", "unknown",
        dependencies=["J-IRQ"],
        detail={
            "instructions_that_can_write_ppu_control": len(per_writer),
            "of_those_possibly_setting_nmi_enable":
                sum(v["can_set_enable"] for v in per_writer.values()),
            "per_instruction": per_writer,
            "why_unknown": "needs the invariant 'NMI enable is clear while "
                           "the handler body runs' plus MA-NMI-EDGE; neither "
                           "has been stated as a checked invariant"}))


def theorem(ledger: Ledger) -> None:
    ledger.add(Obligation(
        "P1",
        "for every reachable state s: Fetch(s) implies $8000 <= PC(s) <= $FFFF",
        "primary theorem (unbounded, all admissible inputs)", "unknown",
        dependencies=["LOC-DIRECT", "LOC-DISPATCH", "LOC-RETURN", "LOC-ASYNC",
                      "J-ASYNC"],
        detail={"certificate": "J_location := Fetch => PC in N; initiation is "
                               "LOC-ASYNC (reset vector), safety is N being a "
                               "subset of ROM, consecution is the "
                               "dependencies",
                "why_unknown": "consecution is not discharged: see each "
                               "dependency's status"}))


def run(ledger: Ledger, ctx: Context) -> None:
    direct_transfers(ledger, ctx)
    engine_entry(ledger, ctx)
    returns(ledger, ctx)
    asynchronous(ledger, ctx)
    theorem(ledger)
