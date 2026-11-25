"""P1 verified for a bounded horizon from cold boot, with no invariant.

Every other P1 result in this track is a *consecution* argument: it assumes
control reached an instruction along a recorded edge (`J-LOCATION`), which is
P1's own certificate, and is therefore one conjunct of a joint induction that
cannot be promoted on its own.  This module answers a weaker question with no
such circularity:

    does the model fetch anything outside the recovered instruction starts
    within a bounded horizon of cold boot?

It executes the transition relation **forwards** from the model's cold-boot
predicate -- PC at the reset vector, I set, the ghost NMI-enable bit clear,
every other register, every flag and all 2 KiB of RAM a free symbol -- and
checks at every boundary that the program counter the model hands to the next
fetch is a single concrete address in `ctx.graph.nodes`.  Nothing is assumed
about where control came from, because the run starts at the only place it can
come from.  The graph is used as the *set the property speaks about*, not as
an assumption about control flow: `analysis/cfg.py` is in the trusted base of
P1's statement here, not of its argument.

Device reads are symbolic.  A read of `$2000-$7FFF` returns a fresh
unconstrained byte (`model/devices.py`), so every controller response, every
PPU status value and every open-bus value is covered at once, including ones
no console can produce.  That is why no input sequence is enumerated.

What "bounded" means here
------------------------

Two statements, with different horizons, both recorded:

`BOUNDED-P1-RESET` (phase 1) runs from cold boot to the first instruction
that sets the ghost NMI-enable bit.  Inside that horizon the result is
*complete*, not sampled: every initial RAM content and every device response
is covered, the warm-boot check's fork is enumerated exhaustively, and the two
`$2002` wait loops are covered for **every** iteration count by a proved loop
summary rather than by an iteration cap or a fairness assumption.  The ghost
bit is shown to stay clear at every boundary of the window rather than assumed
clear, so no NMI is admitted there and the window result restricts nothing.

`BOUNDED-P1-NMI` (phase 2) continues past the enabling write with at most one
NMI taken.  The boundaries at which the model admits that NMI are enumerated
exhaustively -- the tail boundaries after the enabling write, and the idle
loop, whose state repeats term for term and is closed by subsumption -- so
"at most one NMI" is the only restriction and *where* it is taken is not.  The
handler is explored breadth-first to a uniform depth; paths still live at that
depth are `unknown` beyond it and are counted.  The bound is on handler
instructions, not on total execution length: the fetch sequence after an NMI
does not depend on how long the machine idled first.

Loops, and what the horizon is counted in
-----------------------------------------

The horizon is counted in *abstract* steps: one instruction, or one visit to a
summarised loop.  A summarised loop stands for every iteration count, so a
concrete execution covered by a path of K abstract steps may be arbitrarily
longer than K instructions.  A path ends in one of the closures below, each
sound for a safety property and none of them an iteration cap -- or, failing
all of them, at a budget, which is reported as `unknown` for that path:

halted          `JAM` stops the processor fetching, so there is nothing left
                to check on that path.
subsumption     the state at this boundary is term-for-term the state at an
                earlier boundary of the same path, so the whole future repeats
                and adds no fetch that has not been checked.  This is what
                closes the idle loop `JMP $8057`.
loop summary    only for a loop whose body **read a device**, which is what
                makes its trip count somebody else's choice.  The state must
                differ from an earlier visit to the same address only in
                registers or flags, with nothing written; those fields are
                replaced by fresh symbols and the path condition is dropped
                (both weakenings), and the body is re-executed from that
                generalisation.  If every back edge lands in a state that is
                again an instance of it, the generalisation is inductive and
                covers every iteration count.  Exits are followed from the
                generalisation, so they cover the exit after any number of
                iterations, and a path that never leaves fetches only body
                addresses, all of which were checked.  This is what closes the
                `LDA $2002 / BPL` waits, which never terminate for an
                adversarial device: no fairness assumption is made about them.
                Every other loop is unrolled.  A body that reads no device and
                writes nothing is deterministic, so unrolling it either ends
                or repeats a state exactly, which subsumption catches;
                summarising such a loop instead would free registers the rest
                of the program needs, and freeing `Y` inside the RAM clear at
                `$90CC` turns its concrete trip count into a symbolic one.  A
                body that writes memory -- that same RAM clear -- is refused
                by the inductiveness check if it is offered at all.  An
                unrolling that outlasts a budget leaves its path `unknown`:
                no iteration is ever capped silently.
warm reset      `transitions` offers a reset at every boundary.  While the
                ghost bit is clear the post-reset state satisfies the
                cold-boot predicate exactly (PC at the reset vector, I set,
                bit clear, everything else unconstrained), so the horizon
                starts again and the same result covers it; `BOUNDED-RESET`
                records that lemma.  Once the bit is set, the bit carried
                through reset makes the post-reset state *not* a cold-boot
                instance -- the gap `INIT-MEM-NMI-WARM-RESET` records as
                refuted -- so phase 2 states "no warm reset after the enabling
                write" as a restriction on its quantifier and counts the
                boundaries where it applies.

Interrupts are not restricted by hand.  An IRQ successor exists at any
boundary where I is not provably set and is followed like any other
successor; the report counts how many such boundaries occurred (none, in the
window, which is why no `J-IRQ` assumption appears here).

A violation
-----------

A successor whose program counter is off the graph, or symbolic, is a
*candidate* violation: the path condition may be unsatisfiable.  It is handed
to the solver, and only a `sat` answer is reported -- as
`abstract_counterexample`, with the initial RAM bytes and device reads the
model needs, which is a statement about the model and not a claim that a
console can be driven there.  An `unsat` answer prunes the successor.  An
`unknown` answer cuts the path and is reported as a timeout, never as safety.

Reported counterexamples are concrete unless they say otherwise: a summary
attempt whose body contains a candidate violation is *refused*, so the loop is
unrolled and the question is asked again of the concrete path.  A path that
continues through a loop generalisation carries that fact, and a
counterexample found on one says so, because the generalisation weakens the
path condition and such a witness need not be concretely reachable.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field, replace

import z3

from ..model import cpu
from ..model.memory import as_int
from ..model.transitions import Machine, cold_boot, transitions
from ..verify import crosscheck
from ..verify.obligations import Ledger, Obligation, check_valid
from .common import MODEL_SCOPE, Context

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT = os.path.join(HERE, "results", "reports", "bounded.json")

# -- budgets ----------------------------------------------------------------
# Module level so this file can be run on its own:
#     SMB1_ROM=... python3 -m formal.properties.bounded
# Every budget that is reached is reported as `unknown` for the paths it cut,
# never as agreement.

#: abstract steps phase 1 may take in total (all paths)
PHASE1_STEPS = int(os.environ.get("SMB1_BOUNDED_PHASE1_STEPS", "400000"))
#: live paths phase 1 may hold at once
PHASE1_PATHS = int(os.environ.get("SMB1_BOUNDED_PHASE1_PATHS", "64"))
#: abstract steps phase 2 may take in total
PHASE2_STEPS = int(os.environ.get("SMB1_BOUNDED_PHASE2_STEPS", "250000"))
#: live paths phase 2 may hold at once
PHASE2_PATHS = int(os.environ.get("SMB1_BOUNDED_PHASE2_PATHS", "600"))
#: abstract steps past the enabling write phase 2 may follow a path for
PHASE2_DEPTH = int(os.environ.get("SMB1_BOUNDED_PHASE2_DEPTH", "4000"))
#: steps and paths one loop-summary attempt may use on the body
LOOP_BODY_STEPS = 96
LOOP_BODY_PATHS = 12
#: how many values a symbolic program counter may take before the path is cut
PC_VALUES = 16
#: per-query limit; an answer that does not arrive is a timeout
TIMEOUT_MS = int(os.environ.get("SMB1_BOUNDED_TIMEOUT_MS", "20000"))
#: progress on stderr for the long runs; affects nothing that is recorded
VERBOSE = os.environ.get("SMB1_BOUNDED_VERBOSE", "") == "1"

POWERON = ("MA-PPU-POWERON: PPU control is zero at cold boot, so the ghost "
           "NMI-enable bit is false at the first fetch")
NO_RESET_AFTER_ENABLE = (
    "scope restriction, not a model assumption: phase 2 does not follow a "
    "warm reset taken after the ghost NMI-enable bit is set.  The model "
    "carries the bit through reset, so such a reset re-enters the reset code "
    "with an NMI already admissible; that is the gap "
    "INIT-MEM-NMI-WARM-RESET records, not something settled here")

#: CPU state fields compared when looking for a loop
FIELDS = ("a", "x", "y", "s", "c", "z", "i", "d", "v", "n")

#: the free variable every P1 query is written over, so that the SMT-LIB text
#: -- and therefore the hash on the obligation -- commits to the address the
#: question is about and not only to the path that reaches it
NEXT_PC = z3.BitVec("bounded_next_pc", 16)

#: what `locate` did with a successor
OK, PRUNED, VIOLATION, CUT = "ok", "pruned", "violation", "cut"


# -- small helpers ----------------------------------------------------------

def same(left, right) -> bool:
    """Structural identity of two state fields.

    Stronger than solver equality and needs no query: two terms that are
    syntactically the same term denote the same value under every model.
    """
    if isinstance(left, z3.AstRef) and isinstance(right, z3.AstRef):
        return left.sort().eq(right.sort()) and left.eq(right)
    if isinstance(left, z3.AstRef) or isinstance(right, z3.AstRef):
        return False
    return left == right


def runs(values) -> list[tuple[int, int]]:
    """A set of addresses as maximal runs of consecutive addresses."""
    out: list[list[int]] = []
    for value in sorted(values):
        if out and value == out[-1][1] + 1:
            out[-1][1] = value
        else:
            out.append([value, value])
    return [(a, b) for a, b in out]


def in_runs(term, intervals) -> z3.BoolRef:
    """`term` lies in one of `intervals` (16-bit, run-encoded)."""
    clauses = []
    for low, high in intervals:
        lo, hi = z3.BitVecVal(low, 16), z3.BitVecVal(high, 16)
        clauses.append(term == lo if low == high
                       else z3.And(z3.ULE(lo, term), z3.ULE(term, hi)))
    return crosscheck.disjunction(clauses)


def fresh_like(term, name):
    if z3.is_bool(term):
        return z3.Bool(name)
    return z3.BitVec(name, term.size())


def hexa(address) -> str:
    if isinstance(address, int):
        return "${:04X}".format(address & 0xFFFF)
    return str(address)


def trivial_true(guard) -> bool:
    return z3.is_true(z3.simplify(guard))


def trivial_false(guard) -> bool:
    return z3.is_false(z3.simplify(guard))


def live_conditions(conditions) -> list:
    return [c for c in conditions if not z3.is_true(c)]


# -- findings ---------------------------------------------------------------

@dataclass
class Finding:
    """Something that makes the bounded claim weaker, with its address."""
    category: str
    at: object
    message: str
    extra: dict = field(default_factory=dict)

    def to_json(self) -> dict:
        return {"category": self.category, "at": hexa(self.at),
                "finding": self.message, **self.extra}


@dataclass
class Summary:
    """One closed loop: an exact repeat, a proved summary, or a refusal."""
    head: int
    kind: str                       # subsumed | summarised | refused
    body: tuple = ()
    generalised: tuple = ()
    back_edges: int = 0
    exits: int = 0
    body_steps: int = 0
    reason: str = ""

    def to_json(self) -> dict:
        shown = [hexa(p) for p in self.body[:24]]
        if len(self.body) > 24:
            shown.append("... {} more".format(len(self.body) - 24))
        out = {"head": hexa(self.head), "closure": self.kind,
               "body": shown, "body_size": len(self.body),
               "generalised_fields": list(self.generalised),
               "back_edges": self.back_edges,
               "exits_followed": self.exits,
               "body_steps_from_the_generalisation": self.body_steps}
        if self.reason:
            out["reason"] = self.reason
        return out


@dataclass
class Report:
    phase: str
    fetches: int = 0
    distinct_starts: set = field(default_factory=set)
    paths_started: int = 1
    paths_closed: dict = field(default_factory=dict)
    max_live_paths: int = 0
    max_depth: int = 0
    depth_bound: object = None
    handler_depth_bound: object = None
    open_without_an_nmi: int = 0
    boundaries_admitting_irq: int = 0
    irq_followed: int = 0
    nmi_followed: int = 0
    nmi_boundaries: int = 0
    nmi_not_followed: int = 0
    resets_subsumed: int = 0
    resets_not_followed: int = 0
    summaries: list = field(default_factory=list)
    summary_attempts: int = 0
    successors_subsumed: int = 0
    pc_splits: int = 0
    infeasible_pruned: int = 0
    queries: int = 0
    query_timeouts: int = 0
    violations: list = field(default_factory=list)
    nmi_entries: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    seconds: float = 0.0
    window_ends: list = field(default_factory=list)

    def close(self, reason: str) -> None:
        self.paths_closed[reason] = self.paths_closed.get(reason, 0) + 1

    @property
    def cut_paths(self) -> int:
        """Paths that ended short of a closure and short of the depth bound."""
        return sum(v for k, v in self.paths_closed.items()
                   if k.startswith("cut:"))

    @property
    def at_bound(self) -> int:
        return self.paths_closed.get("depth bound reached", 0)

    def to_json(self, limit: int | None = None) -> dict:
        loops = self.summaries if limit is None else self.summaries[:limit]
        findings = self.findings if limit is None else self.findings[:limit]
        return {
            "phase": self.phase,
            "fetches_checked": self.fetches,
            "distinct_instruction_starts_fetched": len(self.distinct_starts),
            "paths_started": self.paths_started,
            "paths_by_how_they_ended": dict(sorted(self.paths_closed.items())),
            "paths_cut_by_budget_or_timeout": self.cut_paths,
            "paths_live_at_the_depth_bound": self.at_bound,
            "max_live_paths": self.max_live_paths,
            "max_abstract_steps_on_a_path": self.max_depth,
            "uniform_depth_bound": self.depth_bound,
            "uniform_depth_bound_past_the_nmi": self.handler_depth_bound,
            "paths_still_open_that_took_no_nmi": self.open_without_an_nmi,
            "boundaries_where_I_was_not_provably_set":
                self.boundaries_admitting_irq,
            "irq_transitions_followed": self.irq_followed,
            "boundaries_admitting_an_nmi": self.nmi_boundaries,
            "nmi_transitions_followed": self.nmi_followed,
            "nmi_taken_at": self.nmi_entries,
            "nmi_transitions_not_followed": self.nmi_not_followed,
            "warm_resets_closed_by_subsumption": self.resets_subsumed,
            "warm_resets_not_followed": self.resets_not_followed,
            "loops_closed_total": len(self.summaries),
            "loops_closed": [s.to_json() for s in loops],
            "loop_summary_attempts": self.summary_attempts,
            "successors_closed_by_subsumption": self.successors_subsumed,
            "symbolic_pc_splits": self.pc_splits,
            "successors_pruned_as_infeasible": self.infeasible_pruned,
            "solver_queries": self.queries,
            "solver_timeouts": self.query_timeouts,
            "violations": self.violations,
            "findings_total": len(self.findings),
            "findings": [f.to_json() for f in findings],
            "seconds": round(self.seconds, 1),
        }


# -- paths ------------------------------------------------------------------

@dataclass
class Path:
    machine: Machine
    conditions: tuple = ()
    #: abstract steps since the phase started
    depth: int = 0
    #: abstract steps since an NMI was taken on this path, or None
    since_nmi: object = None
    nmi: int = 0
    #: address -> machine, for loop detection on this path
    visits: dict = field(default_factory=dict)
    #: addresses in order, so a loop body can be read off
    order: list = field(default_factory=list)
    #: (head, fields) a summary attempt already failed for
    refused: set = field(default_factory=set)
    #: loop heads whose generalisation this path has passed through
    through: tuple = ()
    label: str = "p"

    def child(self, machine, conditions, *, copy: bool, nmi: int | None = None,
              since_nmi: object = "keep", label: str | None = None,
              through: tuple | None = None) -> "Path":
        return Path(
            machine, tuple(conditions), self.depth + 1,
            self.since_nmi if since_nmi == "keep" else since_nmi,
            self.nmi if nmi is None else nmi,
            dict(self.visits) if copy else self.visits,
            list(self.order) if copy else self.order,
            set(self.refused) if copy else self.refused,
            self.through if through is None else through,
            label or self.label)


# -- the engine -------------------------------------------------------------

class Engine:
    """Forward symbolic execution of `model/transitions`, with P1 checked.

    `phase` is 1 (stop where the ghost NMI-enable bit becomes set) or 2 (carry
    on, taking at most `nmi_budget` NMIs).
    """

    def __init__(self, ctx: Context, *, phase: int, nmi_budget: int = 0,
                 step_budget: int = PHASE1_STEPS,
                 path_budget: int = PHASE1_PATHS,
                 depth_budget: int | None = None,
                 timeout_ms: int = TIMEOUT_MS):
        self.ctx = ctx
        self.starts = set(ctx.graph.nodes)
        self.phase = phase
        self.nmi_budget = nmi_budget
        self.step_budget = step_budget
        self.path_budget = path_budget
        self.depth_budget = depth_budget
        self.timeout_ms = timeout_ms
        self.report = Report("phase {}".format(phase))
        #: paths stopped because the ghost bit became set, for phase 2
        self.seeds: list[Path] = []
        self.steps = 0
        self._runs = runs(self.starts)
        #: depths at which a path stopped without being closed
        self.open_depths: list[int] = []
        #: the same, counted from the NMI entry
        self.open_handler_depths: list[int] = []
        self._cex = 0

    def stop_open(self, path: Path, reason: str) -> None:
        """End a path without closing it: `unknown` beyond this depth."""
        self.report.close(reason)
        self.open_depths.append(path.depth)
        if isinstance(path.since_nmi, int):
            self.open_handler_depths.append(path.since_nmi)
        else:
            self.report.open_without_an_nmi += 1

    # -- solver ------------------------------------------------------------

    def ask(self, assertions, kind: str):
        """One satisfiability question, hashed and queued for cvc5/Bitwuzla."""
        assertions = live_conditions(assertions)
        if not assertions:
            return "sat", None
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        solver.add(*assertions)
        answer = str(solver.check())
        crosscheck.record(assertions, answer, kind)
        self.report.queries += 1
        if answer == "unknown":
            self.report.query_timeouts += 1
        return answer, (solver.model() if answer == "sat" else None)

    def member(self, term) -> z3.BoolRef:
        """`term` is an instruction start of N."""
        return in_runs(term, self._runs)

    def witness(self, terms, model) -> dict:
        """The initial RAM bytes and device reads a counterexample needs."""
        ram: dict[str, str] = {}
        reads: dict[str, str] = {}
        if model is None:
            return {"initial_ram": ram, "device_reads": reads,
                    "note": "the path condition is empty: every initial state "
                            "and every device response reaches this state"}
        seen: set[int] = set()
        pending = [t for t in terms if isinstance(t, z3.AstRef)]
        while pending:
            node = pending.pop()
            if node.get_id() in seen:
                continue
            seen.add(node.get_id())
            if z3.is_select(node) and z3.is_const(node.arg(0)):
                index = as_int(node.arg(1))
                if index is not None and node.arg(0).decl().name().startswith(
                        "RAM"):
                    value = model.eval(node, model_completion=True)
                    ram["${:04X}".format(index)] = "${:02X}".format(
                        value.as_long())
            if (z3.is_const(node)
                    and node.decl().kind() == z3.Z3_OP_UNINTERPRETED
                    and node.decl().name().startswith("bus")):
                value = model.eval(node, model_completion=True)
                reads[node.decl().name()] = str(value)
            pending.extend(node.children())
        out = {"initial_ram": dict(sorted(ram.items())),
               "device_reads": dict(sorted(reads.items()))}
        if not ram and not reads:
            out["note"] = ("nothing is required of the initial RAM or of any "
                           "device read: every initial state reaches this "
                           "state")
        return out

    # -- the P1 obligation at one successor ---------------------------------

    def locate(self, path: Path, conditions, machine: Machine, kind: str):
        """Successors of `machine` with a concrete, on-graph program counter.

        Returns `([(conditions, machine)], outcome)`.  `PRUNED` means the
        successor cannot be taken on this path, `VIOLATION` that a candidate
        counterexample was reported, `CUT` that the question did not settle.
        """
        pc = machine.cpu.pc
        if isinstance(pc, int):
            if pc in self.starts:
                return [(tuple(conditions), machine)], OK
            return self.off_graph(path, conditions, machine, kind, pc)
        return self.symbolic_pc(path, conditions, machine, kind)

    def off_graph(self, path, conditions, machine, kind, pc):
        """A successor at a single address that is not an instruction start."""
        live = live_conditions(conditions) + [
            NEXT_PC == z3.BitVecVal(pc & 0xFFFF, 16)]
        name = "BOUNDED-CEX-{:04X}-{}".format(pc & 0xFFFF, self._cex)
        check = check_valid(name, self.member(NEXT_PC), live,
                            timeout_ms=self.timeout_ms, rom_derived=True)
        self.report.queries += 1
        if check.z3_result == "sat":
            _answer, model = self.ask(live, "counterexample_witness")
            self.record_violation(path, kind, hexa(pc),
                                  "the model's next program counter is not an "
                                  "instruction start of the recovered graph",
                                  self.witness(list(live), model), check)
            return [], VIOLATION
        if check.z3_result == "unsat":
            self.report.infeasible_pruned += 1
            return [], PRUNED
        self.report.query_timeouts += 1
        self.report.findings.append(Finding(
            "solver_no_answer", path.machine.cpu.pc,
            "whether the path reaching the off-graph successor {} is "
            "satisfiable did not settle inside {} ms; the path is cut and is "
            "unknown beyond here".format(hexa(pc), self.timeout_ms)))
        return [], CUT

    def symbolic_pc(self, path, conditions, machine, kind):
        """A successor whose program counter is not a single value."""
        pc = machine.cpu.pc
        live = live_conditions(conditions)
        answer, _model = self.ask(live, "path_feasibility")
        if answer == "unsat":
            self.report.infeasible_pruned += 1
            return [], PRUNED
        if answer == "unknown":
            self.report.findings.append(Finding(
                "solver_no_answer", path.machine.cpu.pc,
                "feasibility of a path with a symbolic program counter did "
                "not settle inside {} ms".format(self.timeout_ms)))
            return [], CUT
        values, exhaustive = self.enumerate_pc(pc, live)
        if exhaustive:
            off = sorted(v for v in values if v not in self.starts)
            if off:
                return self.symbolic_violation(path, conditions, machine, kind,
                                               value=off[0])
            self.report.pc_splits += 1
            return [(tuple(conditions) + (pc == value,),
                     Machine(replace(machine.cpu, pc=value),
                             machine.nmi_enable))
                    for value in values], OK
        answer, model = self.ask(
            live + [NEXT_PC == pc, z3.Not(self.member(NEXT_PC))],
            "symbolic_pc_off_graph")
        if answer == "sat":
            return self.symbolic_violation(path, conditions, machine, kind,
                                           model=model)
        self.report.findings.append(Finding(
            "symbolic_pc_not_enumerable", path.machine.cpu.pc,
            "the successor program counter is symbolic with more than {} "
            "values and the question whether it can leave N answered {}; the "
            "path cannot be continued and is unknown beyond here".format(
                PC_VALUES, answer),
            {"transition": kind}))
        return [], CUT

    def enumerate_pc(self, pc, live):
        """Up to `PC_VALUES` values the path admits for `pc`; exhaustive?"""
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        solver.add(*live)
        values: list[int] = []
        answer = "sat"
        while len(values) < PC_VALUES:
            verdict = solver.check()
            self.report.queries += 1
            if verdict == z3.unsat:
                answer = "unsat"
                break
            if verdict != z3.sat:
                answer = "unknown"
                self.report.query_timeouts += 1
                break
            values.append(solver.model().eval(
                pc, model_completion=True).as_long())
            solver.add(pc != values[-1])
        crosscheck.record(live + [pc != v for v in values], answer,
                          "symbolic_pc_enumeration")
        return values, answer == "unsat"

    def symbolic_violation(self, path, conditions, machine, kind, *,
                           value=None, model=None):
        pc = machine.cpu.pc
        live = live_conditions(conditions) + ([] if value is None
                                              else [pc == value])
        if model is None:
            _answer, model = self.ask(live, "counterexample_witness")
        name = "BOUNDED-CEX-SYM-{}-{}".format(
            hexa(path.machine.cpu.pc).lstrip("$"), self._cex)
        check = check_valid(name, self.member(NEXT_PC),
                            live + [NEXT_PC == pc],
                            timeout_ms=self.timeout_ms, rom_derived=True)
        self.report.queries += 1
        if check.z3_result != "sat":
            # the recorded query does not back the violation; report the
            # disagreement and cut rather than claim either way
            self.report.findings.append(Finding(
                "query_disagrees", path.machine.cpu.pc,
                "the enumeration found a program counter outside N here, but "
                "the recorded query answered {}; the path is cut".format(
                    check.z3_result),
                {"query_sha256": check.query_sha256}))
            return [], CUT
        self.record_violation(
            path, kind,
            "a symbolic program counter" if value is None else hexa(value),
            "the model's next program counter can be a value that is not an "
            "instruction start of the recovered graph",
            self.witness(live + [pc], model), check)
        return [], VIOLATION

    def record_violation(self, path, kind, successor, why, needs, check):
        self._cex += 1
        entry = {
            "status": "abstract_counterexample",
            "fetch_from": hexa(path.machine.cpu.pc),
            "transition": kind,
            "successor_pc": successor,
            "why": why,
            "abstract_steps_from_the_phase_start": path.depth,
            "path_condition_satisfiable": True,
            "needs": needs,
            "query_sha256": check.query_sha256,
            "query_answer": check.z3_result,
            "second_solver": check.cvc5_result,
            "note": "a state of the machine model reachable inside the "
                    "horizon; not investigated further, and not a claim that "
                    "a console can be driven there",
        }
        if path.through:
            entry["witness_may_be_spurious"] = (
                "this path passed through the loop generalisation(s) at "
                + ", ".join(hexa(h) for h in path.through)
                + ", which drops path conditions, so the witness shown need "
                  "not be concretely reachable; the violation is a violation "
                  "of the over-approximation")
        self.report.violations.append(entry)

    # -- loops -------------------------------------------------------------

    def repeats(self, path: Path, machine: Machine):
        """An earlier state on this path that `machine` repeats term for term.

        Returns the earlier machine, or None.  When one exists the whole future
        of this successor repeats a future already being explored, so dropping
        the successor adds no unchecked fetch.
        """
        earlier = path.visits.get(machine.cpu.pc)
        if earlier is None or not self.comparable(earlier, machine):
            return None
        if any(not same(getattr(earlier.cpu, f), getattr(machine.cpu, f))
               for f in FIELDS):
            return None
        return earlier

    def comparable(self, earlier: Machine, later: Machine) -> bool:
        """Same address, same memory, same ghost bit: a loop with no writes."""
        return bool(earlier.cpu.pc == later.cpu.pc
                    and earlier.cpu.mem.ram is later.cpu.mem.ram
                    and len(earlier.cpu.mem.writes)
                    == len(later.cpu.mem.writes)
                    and same(earlier.nmi_enable, later.nmi_enable)
                    and earlier.cpu.halted == later.cpu.halted)

    def loop_candidate(self, path: Path, raw):
        """The innermost back edge out of this boundary worth summarising.

        Looking one step ahead, rather than waiting until the back edge has
        been taken, matters: it keeps the engine from exploring the loop's
        exit once concretely and once again from the generalisation, and the
        generalisation covers the concrete exit anyway.

        A loop is a candidate only when its body **read a device**.  That is
        the discriminator between the two kinds of loop in the window.  A body
        that reads no device and writes nothing is deterministic, so unrolling
        it either ends or repeats a state exactly, which subsumption catches;
        summarising it instead would free registers the rest of the program
        still needs -- generalising `Y` inside the RAM clear at `$90CC` turns
        its concrete trip count into a symbolic one and the run then forks
        without end.  A body that reads a device has a trip count an
        adversarial device chooses, so unrolling it is not an option and a
        summary is the only sound way through.
        """
        best = None
        for guard, nxt, kind in raw:
            if kind == "reset" or trivial_false(guard):
                continue
            head = nxt.cpu.pc
            if not isinstance(head, int):
                continue
            earlier = path.visits.get(head)
            if earlier is None or not self.comparable(earlier, nxt):
                continue
            if len(nxt.cpu.mem.inputs) <= len(earlier.cpu.mem.inputs):
                continue
            fields = tuple(f for f in FIELDS
                           if not same(getattr(earlier.cpu, f),
                                       getattr(nxt.cpu, f)))
            if not fields or (head, fields) in path.refused:
                continue
            # the most recent visit is the innermost loop
            index = len(path.order) - 1 - path.order[::-1].index(head)
            if best is None or index > best[0]:
                best = (index, head, earlier, fields)
        return None if best is None else best[1:]

    def body(self, path: Path, head: int) -> tuple:
        """The addresses visited since the last visit to `head`."""
        try:
            start = len(path.order) - 1 - path.order[::-1].index(head)
        except ValueError:                                # pragma: no cover
            return (head,)
        return tuple(dict.fromkeys(path.order[start:]))

    def summarise_loop(self, path: Path, earlier: Machine, fields: tuple):
        """Generalise `fields`, re-execute the body, check inductiveness.

        Returns `(summary, exits)`.  A `refused` summary leaves the caller to
        unroll, and nothing about the loop is assumed in that case.  When it
        succeeds the exits replace *every* successor of the current boundary:
        the body is re-executed from the generalisation, which reaches this
        boundary too, so its own exit is among them.
        """
        head = earlier.cpu.pc
        body = set(self.body(path, head))
        tag = "loop{:04X}_{}".format(head, self.report.summary_attempts)
        state = earlier.cpu
        for name in fields:
            state = replace(state, **{
                name: fresh_like(getattr(earlier.cpu, name),
                                 "{}_{}".format(tag, name))})
        general = Machine(state, earlier.nmi_enable)
        summary = Summary(head, "summarised", body=tuple(sorted(body)),
                          generalised=fields)
        refuse = lambda why: (replace(summary, kind="refused", reason=why), [])

        frontier = [(tuple(path.conditions), general)]
        exits: list = []
        steps = back_edges = 0
        while frontier:
            conditions, current = frontier.pop()
            steps += 1
            if steps > LOOP_BODY_STEPS:
                return refuse("the body did not close inside {} steps".format(
                    LOOP_BODY_STEPS))
            if len(frontier) > LOOP_BODY_PATHS:
                return refuse("the body forks past {} paths".format(
                    LOOP_BODY_PATHS))
            if current.cpu.halted:
                continue
            try:
                body_transitions = list(transitions(current))
            except cpu.SymbolicFetch as exc:
                return refuse("the model cannot decode an instruction in the "
                              "body: {}".format(exc))
            for guard, nxt, kind in body_transitions:
                if kind == "reset":
                    if not self.subsumed_reset(nxt):
                        return refuse("a warm reset inside the body is not "
                                      "covered by the cold-boot predicate")
                    continue
                if kind == "nmi":
                    # unreachable while the body writes nothing, and a
                    # refusal rather than a silent choice if that changes
                    return refuse("the body admits an NMI")
                if trivial_false(guard):
                    continue
                conds = (conditions if trivial_true(guard)
                         else conditions + (z3.simplify(guard),))
                located, outcome = self.locate(path, conds, nxt, kind)
                if outcome == VIOLATION:
                    return refuse("a candidate violation appeared in the body "
                                  "under the generalisation; the loop is "
                                  "unrolled instead, so the question is asked "
                                  "of the concrete path")
                if outcome == CUT:
                    return refuse("a successor of the body could not be "
                                  "resolved on the graph")
                for sub_conditions, sub in located:
                    target = sub.cpu.pc
                    if target == head:
                        back_edges += 1
                        if not self.instance_of(general, sub, fields):
                            return refuse(
                                "the back edge does not land in an instance "
                                "of the generalisation")
                        continue
                    if target in body:
                        frontier.append((sub_conditions, sub))
                        continue
                    exits.append((sub_conditions, sub))
        if not back_edges:
            return refuse("no back edge to the head")
        return replace(summary, back_edges=back_edges, exits=len(exits),
                       body_steps=steps), exits

    def instance_of(self, general: Machine, back: Machine,
                    fields: tuple) -> bool:
        """`back` is `general` with only `fields` changed, nothing written."""
        if back.cpu.mem.ram is not general.cpu.mem.ram:
            return False
        if len(back.cpu.mem.writes) != len(general.cpu.mem.writes):
            return False
        if not same(back.nmi_enable, general.nmi_enable):
            return False
        if back.cpu.halted != general.cpu.halted:
            return False
        return all(same(getattr(general.cpu, f), getattr(back.cpu, f))
                   for f in FIELDS if f not in fields)

    # -- warm reset --------------------------------------------------------

    def subsumed_reset(self, machine: Machine) -> bool:
        """The post-reset state satisfies the model's cold-boot predicate."""
        vector = (self.ctx.read(cpu.RESET_VECTOR)
                  | self.ctx.read(cpu.RESET_VECTOR + 1) << 8)
        return bool(machine.cpu.pc == vector
                    and not machine.cpu.halted
                    and z3.is_true(z3.simplify(machine.cpu.i))
                    and z3.is_false(z3.simplify(machine.nmi_enable)))

    # -- one boundary ------------------------------------------------------

    def advance(self, path: Path) -> list[Path]:
        """Check and take every transition out of `path`'s boundary."""
        machine = path.machine
        pc = machine.cpu.pc
        enable = z3.simplify(machine.nmi_enable)
        if self.phase == 1 and not z3.is_false(enable):
            self.report.window_ends.append({
                "boundary": hexa(pc), "abstract_steps": path.depth,
                "ghost_bit": str(enable), "path": path.label})
            self.report.close(
                "closed: ghost NMI-enable bit set (end of the window)")
            self.seeds.append(path)
            return []
        if machine.cpu.halted:
            self.report.close(
                "closed: halted, the processor fetches nothing more")
            return []
        if self.depth_budget is not None and path.depth >= self.depth_budget:
            self.stop_open(path, "depth bound reached")
            return []

        path.visits[pc] = machine
        path.order.append(pc)
        self.report.fetches += 1
        self.report.distinct_starts.add(pc)
        self.report.max_depth = max(self.report.max_depth, path.depth)
        if not z3.is_true(z3.simplify(machine.cpu.i)):
            self.report.boundaries_admitting_irq += 1

        try:
            raw = list(transitions(machine))
        except cpu.SymbolicFetch as exc:
            # cannot happen while every fetch is at an instruction start in
            # ROM, which is what this module checks; reported rather than
            # raised, so a surprise is a finding and not a crash
            self.report.findings.append(Finding(
                "model_cannot_fetch", pc,
                "the model cannot decode the instruction at this boundary: "
                "{}".format(exc)))
            self.stop_open(path, "cut: the model cannot fetch here")
            return []
        candidate = self.loop_candidate(path, raw)
        if candidate is not None:
            head, earlier, fields = candidate
            self.report.summary_attempts += 1
            summary, continuations = self.summarise_loop(path, earlier, fields)
            self.report.summaries.append(summary)
            if summary.kind == "refused":
                path.refused.add((head, fields))
            else:
                if not continuations:
                    self.report.close("closed: loop summary, the loop has no "
                                      "exit the model admits")
                else:
                    self.report.close("closed: loop summary")
                return self.children(path, continuations,
                                     through=path.through + (head,))

        children: list = []
        kinds: list = []
        subsumed = 0
        for guard, nxt, kind in raw:
            if kind == "reset":
                if self.subsumed_reset(nxt):
                    self.report.resets_subsumed += 1
                else:
                    self.report.resets_not_followed += 1
                continue
            if kind == "nmi":
                self.report.nmi_boundaries += 1
                if path.nmi >= self.nmi_budget:
                    self.report.nmi_not_followed += 1
                    continue
            if trivial_false(guard):
                continue
            repeat = self.repeats(path, nxt)
            if repeat is not None:
                self.report.summaries.append(Summary(
                    nxt.cpu.pc, "subsumed",
                    body=self.body(path, nxt.cpu.pc)))
                subsumed += 1
                self.report.successors_subsumed += 1
                continue
            conditions = (path.conditions if trivial_true(guard)
                          else path.conditions + (z3.simplify(guard),))
            if not trivial_true(guard):
                answer, _ = self.ask(conditions, "branch_feasibility")
                if answer == "unsat":
                    self.report.infeasible_pruned += 1
                    continue
                # an `unknown` answer keeps the successor: carrying one that
                # may be infeasible only adds behaviours
            located, outcome = self.locate(path, conditions, nxt, kind)
            if outcome in (VIOLATION, CUT):
                self.stop_open(path, "cut: " + (
                    "counterexample" if outcome == VIOLATION
                    else "solver gave no answer"))
                return []
            if kind == "irq" and located:
                self.report.irq_followed += 1
            for conds, successor in located:
                children.append((conds, successor))
                kinds.append(kind)
        if not children:
            self.report.close("closed: the state repeats term for term"
                              if subsumed else
                              "closed: no feasible successor")
        return self.children(path, children, kinds=kinds)

    def children(self, path: Path, located, kinds=None,
                 through: tuple | None = None) -> list[Path]:
        copy = len(located) > 1
        out = []
        for index, (conditions, machine) in enumerate(located):
            kind = kinds[index] if kinds else "fallthrough"
            took_nmi = kind == "nmi"
            if took_nmi:
                self.report.nmi_followed += 1
                self.report.nmi_entries.append({
                    "boundary": hexa(path.machine.cpu.pc),
                    "handler": hexa(machine.cpu.pc),
                    "abstract_steps": path.depth, "path": path.label})
            label = (path.label if len(located) == 1
                     else "{}.{}".format(path.label, index))
            out.append(path.child(
                machine, conditions, copy=copy, label=label,
                through=through,
                nmi=path.nmi + 1 if took_nmi else None,
                since_nmi=0 if took_nmi else (
                    "keep" if path.since_nmi is None else path.since_nmi + 1)))
        return out

    # -- the search --------------------------------------------------------

    def exhausted(self, frontier) -> str | None:
        if len(frontier) > self.path_budget:
            return "cut: path budget exhausted"
        if self.steps >= self.step_budget:
            return "cut: step budget exhausted"
        return None

    def trace(self, path: Path, live: int) -> None:
        """Progress for the long runs; nothing recorded depends on it."""
        if VERBOSE and self.steps % 2000 == 0:
            import sys
            print("phase {}: step {}, {} live, depth {} at {}, {} queries"
                  .format(self.phase, self.steps, live, path.depth,
                          hexa(path.machine.cpu.pc), self.report.queries),
                  file=sys.stderr, flush=True)

    def run(self, start: list[Path], *, breadth_first: bool = False) -> Report:
        """Explore from `start`; depth-first unless a uniform depth is
        wanted, in which case level by level."""
        started = time.time()
        self.report.paths_started = len(start)
        frontier = list(start)
        while frontier:
            self.report.max_live_paths = max(self.report.max_live_paths,
                                             len(frontier))
            stop = self.exhausted(frontier)
            if stop:
                for path in frontier:
                    self.stop_open(path, stop)
                break
            if not breadth_first:
                path = frontier.pop()
                self.steps += 1
                self.trace(path, len(frontier))
                frontier.extend(self.advance(path))
                continue
            level, frontier = frontier, []
            for index, path in enumerate(level):
                stop = self.exhausted(frontier)
                if stop:
                    # the level is incomplete: everything left keeps its own
                    # depth, so the uniform bound drops to this level
                    for rest in level[index:]:
                        self.stop_open(rest, stop)
                    frontier = []
                    break
                self.steps += 1
                self.trace(path, len(level) - index)
                frontier.extend(self.advance(path))
        self.report.seconds = time.time() - started
        self.report.depth_bound = (min(self.open_depths)
                                   if self.open_depths else None)
        self.report.handler_depth_bound = (min(self.open_handler_depths)
                                           if self.open_handler_depths
                                           else None)
        return self.report


# -- the two phases ---------------------------------------------------------

def phase1(ctx: Context) -> Engine:
    """Cold boot to the first instruction that sets the ghost enable bit."""
    engine = Engine(ctx, phase=1, nmi_budget=0, step_budget=PHASE1_STEPS,
                    path_budget=PHASE1_PATHS)
    engine.run([Path(cold_boot(ctx.prg), label="boot")])
    return engine


def phase2(ctx: Context, seeds: list[Path]) -> Engine:
    """From the enabling write on, with at most one NMI taken."""
    engine = Engine(ctx, phase=2, nmi_budget=1, step_budget=PHASE2_STEPS,
                    path_budget=PHASE2_PATHS, depth_budget=PHASE2_DEPTH)
    engine.run([Path(seed.machine, seed.conditions, label="nmi:" + seed.label)
                for seed in seeds], breadth_first=True)
    return engine


def reset_lemma(ctx: Context):
    """`BOUNDED-RESET`: a warm reset with the ghost bit clear is a cold boot.

    Asked of an unconstrained state, so it holds at every boundary and not
    only at the ones a run visited.  The ghost bit is not part of the query:
    `transitions` carries it through reset unchanged, which is a syntactic
    fact about the model and is recorded as such.
    """
    from ..verify.symexec import havoc_state

    state = havoc_state(0x8000, ctx.prg)
    after = cpu.reset(state)
    vector = ctx.read(cpu.RESET_VECTOR) | ctx.read(cpu.RESET_VECTOR + 1) << 8
    structural = {
        "pc_is_the_reset_vector": after.pc == vector,
        "not_halted": after.halted is False,
        "ghost_bit_carried_through_reset_unchanged": True,
        "every_other_field_is_unconstrained_in_the_cold_boot_predicate": True,
    }
    # written over NEXT_PC like every other P1 query, so the text commits to
    # the address as well as to the claim
    check = check_valid(
        "BOUNDED-RESET",
        z3.And(after.i, in_runs(NEXT_PC, runs(set(ctx.graph.nodes)))),
        [NEXT_PC == z3.BitVecVal(after.pc, 16)],
        timeout_ms=TIMEOUT_MS, rom_derived=True)
    return check, structural, vector


# -- the ledger -------------------------------------------------------------

def status_of(report: Report, *, horizon_is_complete: bool) -> str:
    """The status the run earns, with the two horizons judged differently.

    A horizon stated as "to the first instruction that sets the ghost bit"
    is a claim about *every* execution reaching that point, so a single path
    left open anywhere makes it `unknown`.  A horizon stated as a depth is a
    claim up to `min(depth at which a path was left open)`, so the paths left
    open are the bound rather than a hole below it, whatever left them open --
    a budget, a solver that did not answer, or a program counter that could
    not be continued.  Each is counted and named in the detail either way.

    A solver timeout is not fatal by itself, and whether it costs anything
    depends on the question: a timeout on *feasibility* keeps the successor,
    which only adds behaviours, while a timeout on the P1 question itself
    ends the path and so lowers the bound.
    """
    if report.violations:
        return "abstract_counterexample"
    if horizon_is_complete and report.depth_bound is not None:
        return "unknown"
    return "bounded"


def run(ledger: Ledger, ctx: Context) -> None:
    with crosscheck.collect("BOUNDED-P1-RESET") as queries1:
        first = phase1(ctx)
    with crosscheck.collect("BOUNDED-P1-NMI") as queries2:
        second = phase2(ctx, first.seeds)
    check, structural, vector = reset_lemma(ctx)

    one, two = first.report, second.report
    summarised = [s for s in one.summaries + two.summaries
                  if s.kind == "summarised"]
    refused = [s for s in one.summaries + two.summaries
               if s.kind == "refused"]
    subsumed = [s for s in one.summaries + two.summaries
                if s.kind == "subsumed"]
    status1 = status_of(one, horizon_is_complete=True)
    status2 = status_of(two, horizon_is_complete=False)
    reach = ("every path closed inside it, so there is no depth bound to "
             "state" if two.depth_bound is None else
             "the first {} abstract steps of every path, which is {} "
             "instructions of the NMI handler on every path that entered it"
             .format(two.depth_bound, two.handler_depth_bound))

    common = {
        "scope": MODEL_SCOPE,
        "method": "forward symbolic execution of model/transitions from the "
                  "cold-boot predicate, with every device read a fresh "
                  "unconstrained byte; at each boundary the successor program "
                  "counter must be a single concrete instruction start of "
                  "ctx.graph.nodes",
        "instruction_starts_in_N": len(ctx.graph.nodes),
        "no_invariant": "nothing is assumed about how control reached a "
                        "state: J-LOCATION, J-ASYNC and J-STACK are not used "
                        "here.  analysis/cfg.py is in the trusted base of the "
                        "property's statement, because it defines N; it is "
                        "not in the trusted base of the argument",
        "fairness_assumptions": "none.  The $2002 waits never terminate for "
                                "an adversarial device and are closed by a "
                                "loop summary, not by an iteration cap and "
                                "not by assuming the device eventually "
                                "answers",
        "path_merges": "none: no two paths were merged, and no path condition "
                       "was dropped except inside a loop generalisation, "
                       "which is recorded with the loop",
        "what_a_solver_timeout_costs":
            "a timeout on a feasibility question keeps the successor, which "
            "only adds behaviours and weakens nothing; a timeout on the P1 "
            "question itself cuts the path, and every such cut is counted in "
            "paths_cut_by_budget_or_timeout",
        "closures": "a path ends only by halting, by an exact repeat of an "
                    "earlier state on the same path, by a loop summary whose "
                    "inductiveness was checked, by a warm reset that "
                    "satisfies the cold-boot predicate, by having no feasible "
                    "successor, or by a budget -- and a budget is reported as "
                    "unknown for that path",
        "never_leaving_a_summarised_loop":
            "a path that stays in a summarised loop for ever fetches only the "
            "body addresses listed with that summary, each of which was "
            "checked from the generalisation, so it needs no bound",
        "abstract_step": "one instruction, or one visit to a summarised loop, "
                         "which stands for every iteration count, so a "
                         "concrete execution covered by K abstract steps may "
                         "be arbitrarily longer than K instructions",
    }

    ledger.add(Obligation(
        "BOUNDED-P1-RESET",
        "every execution of the model from cold boot -- for every initial RAM "
        "content and every device response -- fetches only instruction starts "
        "of N, up to and including the first instruction that sets the ghost "
        "NMI-enable bit; the two $2002 wait loops are covered for every "
        "iteration count by a proved loop summary, and a warm reset taken "
        "inside the window restarts the same horizon",
        "bounded forward execution from cold boot, no invariant",
        status1,
        assumptions=[POWERON],
        dependencies=["BOUNDED-RESET"],
        solver="z3",
        **crosscheck.obligation_fields(queries1),
        detail={
            **common,
            "horizon": "cold boot to the first instruction that sets the "
                       "ghost NMI-enable bit; inside it the quantifier is "
                       "complete, not sampled, and no path was cut",
            "window_end": one.window_ends[:8],
            "window_ends_total": len(one.window_ends),
            "longest_path_in_abstract_steps": one.max_depth,
            "no_nmi_is_admitted_in_the_window":
                "the ghost bit was provably false at all {} boundaries the "
                "run visited; that is checked at every boundary, not assumed, "
                "and the run stops at the first boundary where it is not"
                .format(one.fetches),
            "no_irq_is_admitted_in_the_window":
                "boundaries where I was not provably set: {}.  Where I is "
                "set, transitions() offers no IRQ successor, so no J-IRQ "
                "assumption is needed".format(one.boundaries_admitting_irq),
            "loop_summaries": [s.to_json() for s in summarised],
            "loop_summaries_refused_count": len(refused),
            "loop_summaries_refused": [s.to_json() for s in refused[:12]],
            "why_the_assumption": "the model's cold-boot predicate builds the "
                                  "clear ghost bit in; MA-PPU-POWERON is "
                                  "listed because it is not an "
                                  "over-approximation",
            **one.to_json(limit=40),
            "slice_queries": queries1.summary(),
        }))

    ledger.add(Obligation(
        "BOUNDED-P1-NMI",
        "continuing past the enabling write with at most one NMI taken -- at "
        "any of the boundaries that admit one, which are enumerated -- every "
        "fetch is an instruction start of N for " + reach,
        "bounded forward execution with one interrupt, no invariant",
        status2,
        assumptions=[POWERON, NO_RESET_AFTER_ENABLE],
        dependencies=["BOUNDED-P1-RESET"],
        solver="z3",
        **crosscheck.obligation_fields(queries2),
        detail={
            **common,
            "horizon": "abstract steps past the first instruction that sets "
                       "the ghost NMI-enable bit, explored breadth-first so "
                       "every path reached the same depth",
            "uniform_depth_bound": two.depth_bound,
            "uniform_depth_bound_past_the_nmi": two.handler_depth_bound,
            "what_the_bound_is_on": "the fetch sequence after an NMI does not "
                                    "depend on how long the machine idled "
                                    "first, so the bound is on handler "
                                    "instructions and not on total execution "
                                    "length",
            "nmi_boundaries_enumerated": two.nmi_boundaries,
            "nmi_transitions_followed": two.nmi_followed,
            "second_nmi_not_followed": two.nmi_not_followed,
            "paths_unknown_beyond_the_bound": two.at_bound + two.cut_paths,
            "states_closed_by_subsumption_count": len(subsumed),
            "states_closed_by_subsumption":
                [s.to_json() for s in subsumed[:12]],
            **two.to_json(limit=40),
            "slice_queries": queries2.summary(),
        }))

    ledger.record(
        "BOUNDED-RESET",
        "a warm reset taken while the ghost NMI-enable bit is clear lands in "
        "a state that satisfies the model's cold-boot predicate (PC at the "
        "reset vector, I set, bit clear, every other register, flag and RAM "
        "byte unconstrained), so the bounded horizon starts again there and "
        "BOUNDED-P1-RESET covers what follows",
        "bounded forward execution from cold boot, no invariant",
        check,
        detail={
            "scope": MODEL_SCOPE,
            "checked_structurally": structural,
            "solver_query": "I is set in the post-reset state",
            "reset_vector": hexa(vector),
            "used_by": "every warm-reset successor the phase-1 run met was "
                       "closed this way ({} of them).  Phase 2 cannot use it: "
                       "the model carries the ghost bit through reset, so {} "
                       "warm-reset successors there are outside its "
                       "quantifier".format(one.resets_subsumed,
                                           two.resets_not_followed),
        })

    report = {
        "rom_sha1": ctx.sha1,
        "property": "P1: every instruction fetch is at an instruction start "
                    "recorded in the control-flow graph",
        "statuses": {"BOUNDED-P1-RESET": status1, "BOUNDED-P1-NMI": status2,
                     "BOUNDED-RESET": ledger.items["BOUNDED-RESET"].status},
        "budgets": {
            "phase1_steps": PHASE1_STEPS, "phase1_paths": PHASE1_PATHS,
            "phase2_steps": PHASE2_STEPS, "phase2_paths": PHASE2_PATHS,
            "phase2_depth": PHASE2_DEPTH, "pc_values": PC_VALUES,
            "loop_body_steps": LOOP_BODY_STEPS,
            "solver_timeout_ms": TIMEOUT_MS,
        },
        "phase1": one.to_json(),
        "phase2": two.to_json(),
        "queries": {"BOUNDED-P1-RESET": queries1.summary(),
                    "BOUNDED-P1-NMI": queries2.summary()},
    }
    os.makedirs(os.path.dirname(REPORT), exist_ok=True)
    with open(REPORT, "w") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)


def main() -> int:                                   # pragma: no cover - CLI
    from .common import context

    ledger = Ledger()
    run(ledger, context())
    for key in ("BOUNDED-P1-RESET", "BOUNDED-P1-NMI", "BOUNDED-RESET"):
        print("{}: {}".format(key, ledger.items[key].status))
    with open(REPORT) as handle:
        saved = json.load(handle)
    for phase in ("phase1", "phase2"):
        data = saved[phase]
        print("\n{}: {} fetches, {} distinct starts, {} paths, {} queries, "
              "{} timeouts, {} violations, {:.0f}s".format(
                  phase, data["fetches_checked"],
                  data["distinct_instruction_starts_fetched"],
                  data["paths_started"], data["solver_queries"],
                  data["solver_timeouts"], len(data["violations"]),
                  data["seconds"]))
        print("  ended: " + json.dumps(data["paths_by_how_they_ended"]))
        print("  uniform depth bound: {}".format(data["uniform_depth_bound"]))
    print("\nwrote " + REPORT)
    return 0


if __name__ == "__main__":                           # pragma: no cover - CLI
    raise SystemExit(main())
