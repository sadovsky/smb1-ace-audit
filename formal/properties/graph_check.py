"""The control-flow graph checked, edge by edge, against the machine model.

`N` -- the set of instruction starts every `J_location` result is stated over
-- and the edges between its members come from `analysis/cfg.py`, which walks
the image with the decoder in `analysis/decoder.py`.  Neither is verified, and
`analysis/cfg.py` is listed in the trusted base of every result that carries
`J-LOCATION`.  The *predecessor* half of that assumption cannot be discharged
here: it says control never arrives at an instruction from anywhere but a
recorded edge, which is the theorem itself.  The *successor* half can be, one
instruction at a time, against `model/cpu.step`: the definition the proofs are
stated over and the one validated against external vectors.

For every node of `N` whose successors its own bytes decide, the model is
executed from `havoc_state`, in which every register, every flag and all of
RAM are unconstrained, and the solver is asked two kinds of question.

Both questions are asked over the instruction's transition relation, written
with a free 16-bit variable for the next program counter:

    T  :=  Or(And(guard, next = target))   over every successor the model
                                           returns for this instruction

coverage      `T and not Or(next = t for each recorded successor t)` must be
              unsatisfiable.  Satisfiable means there is a path on which the
              model's next program counter is a value the graph does not
              record -- a missing edge, unless the state it needs is itself
              unreachable.
feasibility   `T and next = t` must be satisfiable for each recorded
              successor `t`.  Unsatisfiable means the graph records a
              transfer the machine cannot make from this instruction.

Writing both over `T` rather than over the guards alone is what makes the
query hashes worth keeping: the SMT-LIB text of each one contains the actual
addresses, so the digest on the obligation commits to the claim made about
every node, and the second solvers re-check one query per node and one per
edge instead of a handful of shapes shared by thousands of them.

Both answers are hashed and re-checked by the second solvers through
`verify/crosscheck`, like every other answer the slice machinery relies on.

What is deliberately *not* checked, and is counted and reported rather than
passed over:

`RTS`/`RTI`      the destination comes off the stack; that is `LOC-RETURN`.
`JMP ($0006)`    the JumpEngine's indirect jump; that is `LOC-ENGINE` plus the
                 per-site `D-xxxx-CONTRACT` items.
`JAM`            the processor stops fetching, so there is no successor.
unstable         the undocumented instructions the model havocs.  Their
                 program counter is in fact ordinary fallthrough, but they are
                 excluded here by construction and counted.
`return_point`   where a `JSR` is *expected* to resume.  The graph records it
                 as its own edge kind precisely because it is an assumption
                 about the callee (`J-STACK`), not a transfer this instruction
                 makes.
`dispatch`       the 18 `JSR $8E04` sites, whose recorded successors are the
                 table entries rather than `$8E04`.  The model's successor
                 there is `$8E04`, and that is what is checked; the entries
                 stand in for the engine's indirect jump and are the subject
                 of the dispatch contracts.

Instruction length is compared too, and the comparison is weaker than it
looks: `model/cpu.py` imports `OPCODES` from `analysis/decoder.py`, so the
length the model advances the program counter by and the length the graph laid
out the instruction with come from one table.  The check catches a graph built
with a stale or patched decoding, not a wrong opcode table.  It is reported
with that caveat attached rather than counted as independent evidence.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

import z3

from analysis.cfg import JUMPENGINE
from analysis.decoder import Flow

from ..model import cpu
from ..verify import crosscheck
from ..verify.obligations import Ledger, Obligation
from ..verify.symexec import havoc_state
from .common import MODEL_SCOPE, Context

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT = os.path.join(HERE, "results", "reports", "graph_check.json")

OBLIGATION = "GRAPH-EDGES"

#: edge kinds that claim "this instruction's own bytes send control here"
DIRECT_KINDS = frozenset({"fallthrough", "branch", "jump", "call",
                          "interrupt"})
#: edge kinds that stand for something other than one instruction's transfer
SUMMARY_KINDS = frozenset({"return_point", "dispatch", "unresolved"})
#: instructions whose successors their own bytes do not decide
EXCLUDED_FLOWS = {Flow.RETURN: "return",
                  Flow.INDIRECT_JUMP: "indirect_jump",
                  Flow.HALT: "halt"}
#: categories that make the aggregate statement false
MISMATCH = frozenset({"successor_not_recorded", "computed_transfer",
                      "recorded_successor_infeasible", "undecodable",
                      "length_disagreement", "opcode_disagreement",
                      "unexpected_halt", "model_error"})
TIMEOUT_MS = 20000

#: the free variable the transition relation is written over
NEXT_PC = z3.BitVec("next_pc", 16)


def hexes(addresses) -> list[str]:
    return [f"0x{a:04X}" for a in addresses]


@dataclass
class Finding:
    address: int
    category: str
    message: str
    extra: dict = field(default_factory=dict)

    def to_json(self) -> dict:
        return {"address": f"0x{self.address:04X}", "category": self.category,
                "finding": self.message, **self.extra}


@dataclass
class Report:
    nodes: int = 0
    checked: int = 0
    excluded: dict = field(default_factory=dict)
    edges_compared: int = 0
    feasible_edges: int = 0
    dispatch_sites: int = 0
    summary_edges: dict = field(default_factory=dict)
    coverage_queries: int = 0
    feasibility_queries: int = 0
    solver_no_answer: int = 0
    findings: list = field(default_factory=list)

    def exclude(self, reason: str) -> None:
        self.excluded[reason] = self.excluded.get(reason, 0) + 1

    def to_json(self, limit: int | None = None) -> dict:
        shown = self.findings if limit is None else self.findings[:limit]
        return {
            "instruction_starts_in_N": self.nodes,
            "nodes_checked": self.checked,
            "nodes_excluded": dict(sorted(self.excluded.items())),
            "recorded_edges_compared": self.edges_compared,
            "recorded_edges_shown_feasible": self.feasible_edges,
            "dispatch_sites_checked_against_the_engine_entry":
                self.dispatch_sites,
            "recorded_edges_not_compared": dict(sorted(
                self.summary_edges.items())),
            "coverage_queries": self.coverage_queries,
            "feasibility_queries": self.feasibility_queries,
            "solver_no_answer": self.solver_no_answer,
            "mismatches": sum(1 for f in self.findings
                              if f.category in MISMATCH),
            "findings_total": len(self.findings),
            "findings": [f.to_json() for f in shown],
        }


def _answer(assertions, kind: str) -> str:
    """One solver call, hashed and queued for the second solvers."""
    solver = z3.Solver()
    solver.set("timeout", TIMEOUT_MS)
    solver.add(*assertions)
    answer = str(solver.check())
    crosscheck.record(list(assertions), answer, kind)
    return answer


def _check_decoding(pc: int, decoded, state, report: Report) -> str | None:
    """None when the model's own fetch agrees with the graph's decoding."""
    try:
        info, _lo, _hi, _after = cpu.fetch(state)
    except cpu.SymbolicFetch as exc:
        report.findings.append(Finding(
            pc, "undecodable",
            f"the model cannot fetch this instruction: {exc}"))
        return "undecodable"
    reason = None
    if info.opcode != decoded.info.opcode:
        reason = "decoding_disagreement"
        report.findings.append(Finding(
            pc, "opcode_disagreement",
            "the model fetches a different opcode than the graph decoded",
            {"model": f"0x{info.opcode:02X}",
             "graph": f"0x{decoded.info.opcode:02X}"}))
    if info.length != decoded.length:
        reason = "decoding_disagreement"
        report.findings.append(Finding(
            pc, "length_disagreement",
            "the model advances the program counter by a different number of "
            "bytes than the graph gave the instruction",
            {"model": info.length, "graph": decoded.length,
             "instruction": str(decoded)}))
    elif (pc + info.length) & 0xFFFF != decoded.end:
        reason = "decoding_disagreement"
        report.findings.append(Finding(
            pc, "length_disagreement",
            "the graph's end address is not its start plus its length",
            {"model": f"0x{(pc + info.length) & 0xFFFF:04X}",
             "graph": f"0x{decoded.end:04X}"}))
    return reason


def _model_successors(instruction, successors, report: Report):
    """{target program counter: [guards]} for the concrete transfers."""
    pc = instruction.address
    model: dict[int, list] = {}
    for successor in successors:
        if successor.kind == "halt":
            report.findings.append(Finding(
                pc, "unexpected_halt",
                "the model stops fetching here, but the graph did not decode "
                "the instruction as JAM", {"instruction": str(instruction)}))
            continue
        target = successor.state.pc
        if not isinstance(target, int):
            report.findings.append(Finding(
                pc, "computed_transfer",
                "the model's next program counter is not a single value, but "
                "the graph treats this instruction's successors as fixed by "
                "its own bytes", {"instruction": str(instruction)}))
            continue
        model.setdefault(target, []).append(successor.guard)
    return model


def check(ctx: Context) -> Report:
    """Compare every direct edge of the graph with the machine model."""
    nodes = ctx.graph.nodes
    report = Report(nodes=len(nodes))
    for pc in sorted(nodes):
        node = nodes[pc]
        info = node.instruction.info
        state = havoc_state(pc, ctx.prg)
        wrong = _check_decoding(pc, node.instruction, state, report)
        if wrong is not None:
            report.exclude(wrong)
            continue
        reason = EXCLUDED_FLOWS.get(info.flow)
        if reason is None and info.unstable:
            reason = "unstable_undocumented"
        if reason is not None:
            report.exclude(reason)
            continue

        try:
            successors = cpu.step(state)
        except Exception as exc:
            # reported, not swallowed: it makes the obligation `refuted`
            report.findings.append(Finding(
                pc, "model_error",
                "the model could not execute this instruction: "
                f"{type(exc).__name__}: {exc}",
                {"instruction": str(node.instruction)}))
            report.exclude("model_error")
            continue
        model = _model_successors(node.instruction, successors, report)
        dispatch = (info.flow is Flow.CALL
                    and node.instruction.operand16 == JUMPENGINE)
        recorded = {t for t, k in node.successors if k in DIRECT_KINDS}
        if dispatch:
            # the graph records the table entries in place of the engine
            # entry; a direct edge here would be a stray and is kept in
            # `recorded` so the feasibility query reports it
            report.dispatch_sites += 1
            recorded |= {JUMPENGINE}
        for _target, kind in node.successors:
            if kind in SUMMARY_KINDS:
                report.summary_edges[kind] = (
                    report.summary_edges.get(kind, 0) + 1)
        report.checked += 1

        # every program counter the model allows is one the graph records
        transition = crosscheck.disjunction([
            z3.simplify(z3.And(guard, NEXT_PC == target))
            for target, guards in sorted(model.items()) for guard in guards])
        recorded_pc = crosscheck.disjunction(
            [NEXT_PC == t for t in sorted(recorded)])
        report.coverage_queries += 1
        answer = _answer([transition, z3.Not(recorded_pc)],
                         "successor_coverage")
        if answer == "sat":
            report.findings.append(Finding(
                pc, "successor_not_recorded",
                "the model allows a program counter the graph does not record "
                "as a successor of this instruction",
                {"instruction": str(node.instruction),
                 "model_successors": hexes(sorted(model)),
                 "recorded_successors": hexes(sorted(recorded)),
                 "not_recorded": hexes(sorted(set(model) - recorded))}))
        elif answer != "unsat":
            report.solver_no_answer += 1
            report.findings.append(Finding(
                pc, "solver_no_answer",
                "the coverage query did not finish inside "
                f"{TIMEOUT_MS} ms; reported as a timeout, not as agreement"))

        # every recorded successor is one the model can actually take
        for target in sorted(recorded):
            report.edges_compared += 1
            report.feasibility_queries += 1
            answer = _answer([transition, NEXT_PC == target],
                             "successor_feasibility")
            if answer == "sat":
                report.feasible_edges += 1
            elif answer == "unsat":
                report.findings.append(Finding(
                    pc, "recorded_successor_infeasible",
                    "the graph records a successor the model cannot reach "
                    "from this instruction",
                    {"instruction": str(node.instruction),
                     "recorded_successor": f"0x{target:04X}",
                     "model_successors": hexes(sorted(model)),
                     "why": ("the model never produces this program counter "
                             "here" if target not in model else
                             "the model produces it only under an "
                             "unsatisfiable guard")}))
            else:
                report.solver_no_answer += 1
                report.findings.append(Finding(
                    pc, "solver_no_answer",
                    "the feasibility query for "
                    f"${target:04X} did not finish inside {TIMEOUT_MS} ms; "
                    "reported as a timeout, not as agreement"))
    return report


def run(ledger: Ledger, ctx: Context) -> None:
    with crosscheck.collect(OBLIGATION) as queries:
        report = check(ctx)
    mismatches = [f for f in report.findings if f.category in MISMATCH]
    queries_detail = queries.summary()
    if mismatches:
        status = "refuted"
    elif report.solver_no_answer:
        status = "unknown"
    elif not queries.clean:
        status = "unknown"
    else:
        status = "proved"

    detail = {
        "scope": MODEL_SCOPE,
        "method": "exhaustive execution of the CPU model from an "
                  "unconstrained state, one instruction start at a time, with "
                  "one coverage query and one feasibility query per recorded "
                  "edge",
        **report.to_json(limit=50),
        "length_check_is_not_independent":
            "formal/model/cpu.py imports OPCODES from analysis/decoder.py, so "
            "the model's instruction lengths and the graph's are the same "
            "table; the comparison catches a stale graph, not a wrong table",
        "what_this_does_not_close":
            "J-LOCATION is the completeness of the graph's predecessor "
            "relation.  The predecessors are derived from the successors, so "
            "this result plus LOC-DIRECT says the recorded successors are "
            "exactly the model's for every node whose bytes decide them; what "
            "remains open are the transfers this check excludes, which are "
            "LOC-RETURN and LOC-DISPATCH, and that is where J-LOCATION still "
            "rests on analysis/cfg.py",
        "slice_queries": queries_detail,
    }
    if status == "unknown" and not queries.clean:
        detail["demoted"] = ("a second solver contradicted Z3 on a query this "
                             "result rests on")
    ledger.add(Obligation(
        OBLIGATION,
        "for every instruction start in N whose successors its own bytes "
        "decide, the graph's recorded successors are exactly the ones the "
        "machine model allows, and the graph's instruction lengths agree with "
        "the model's",
        "the control-flow graph checked against the machine model",
        status,
        solver="z3",
        **crosscheck.obligation_fields(queries),
        detail=detail))

    os.makedirs(os.path.dirname(REPORT), exist_ok=True)
    with open(REPORT, "w") as handle:
        json.dump({"rom_sha1": ctx.sha1, "obligation": OBLIGATION,
                   "status": status, **report.to_json(),
                   "queries": queries_detail},
                  handle, indent=2, sort_keys=True)
