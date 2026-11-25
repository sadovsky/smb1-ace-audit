"""Backward-deepening symbolic execution over the control-flow graph.

To show that a bad condition cannot hold when control reaches instruction
`W`, take a *suffix*: a sequence of instruction starts ending at `W` that the
graph says can execute consecutively.  Execute it from a state in which every
register, every flag and all of RAM are unconstrained.  If the bad condition
is unsatisfiable at the end, it is unsatisfiable for **every** execution that
ends with that suffix, whatever came before, because the unconstrained start
includes whatever the prefix could have produced.  If it is satisfiable, the
suffix is extended by one predecessor in every possible way and each longer
suffix is tried in turn.

The result is a finite set of suffixes that together cover every way of
arriving at `W` (according to the graph), each individually proved.  That is
a *consecution* argument, not a bounded one: no path length is assumed.

What it rests on is stated on every result, never assumed silently:

J-LOCATION  the graph's predecessor relation is complete, i.e. control only
            ever reaches an instruction from one of its recorded predecessors.
            This is the instruction-location invariant itself, so every result
            here is one conjunct of a joint induction, not a standalone fact.
J-ASYNC     no interrupt handler runs between two instructions of a suffix
            (the NMI handler does not preserve registers).
J-STACK     a called routine returns to the instruction after its `JSR` with
            the stack pointer restored.  Used only by suffixes that step over
            a call; what the callee did to registers and RAM is then treated
            as completely unknown.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Callable

import z3

from analysis.cfg import CFG, JUMPENGINE
from analysis.decoder import Flow

from ..model import cpu
from ..model.cpu import State
from ..model.memory import NESMemory, fresh

Bad = Callable[[State, tuple], z3.BoolRef]


def havoc_state(pc: int, prg: bytes) -> State:
    tag = f"h{next(_counter)}_"
    memory = NESMemory(z3.Array(tag + "RAM", z3.BitVecSort(11),
                                z3.BitVecSort(8)), prg)
    return State.symbolic(pc, memory, prefix=tag)


def _count():
    n = 0
    while True:
        yield n
        n += 1


_counter = _count()


def havoc_after_call(state: State, return_pc: int) -> State:
    """Everything a callee could have changed, except the stack pointer."""
    blank = havoc_state(return_pc, state.mem.prg)
    return replace(blank, s=state.s)


def through_jumpengine(state: State, target: int, limit: int = 20):
    """Execute a dispatch site and the JumpEngine; constrain PC to `target`."""
    for _ in range(limit):
        if not isinstance(state.pc, int):
            return z3.simplify(state.pc == target), replace(state, pc=target)
        (successor,) = cpu.step(state)
        state = successor.state
    raise RuntimeError("JumpEngine did not reach its indirect jump")


@dataclass
class Outcome:
    holds: bool
    #: suffixes that were individually proved (ending at the target)
    proved_suffixes: int = 0
    max_depth: int = 0
    solver_calls: int = 0
    used_call_summary: bool = False
    entry_assumptions: set = field(default_factory=set)
    #: when not holds: why, and the suffix that could not be closed
    reason: str = ""
    failing_suffix: tuple = ()
    model: dict = field(default_factory=dict)


class Slicer:
    def __init__(self, graph: CFG, prg: bytes, *,
                 invariants: Callable[[State], list] | None = None,
                 closed_entries: dict[int, str] | None = None,
                 timeout_ms: int = 20000):
        #: graph entries assumed never to be taken, with the assumption that
        #: says so; a suffix that backs into one is closed under it
        self.closed_entries = closed_entries or {}
        self.graph = graph
        self.prg = prg
        self.invariants = invariants or (lambda state: [])
        self.timeout_ms = timeout_ms

    # -- one suffix ---------------------------------------------------------

    def _edge_kind(self, source: int, target: int) -> str | None:
        kinds = [k for t, k in self.graph.nodes[source].successors
                 if t == target]
        if not kinds:
            return None
        # a JSR's return_point wins over a coincidental direct edge
        return "return_point" if "return_point" in kinds else kinds[0]

    def resolve_pc(self, state: State, conditions) -> State | None:
        """Make a symbolic PC concrete if the path admits exactly one value."""
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        solver.add(*conditions)
        if solver.check() != z3.sat:
            return None
        value = solver.model().eval(state.pc, model_completion=True).as_long()
        solver.add(state.pc != value)
        if solver.check() != z3.unsat:
            return None
        return replace(state, pc=value)

    def inline_call(self, state: State, return_pc: int, *,
                    max_steps: int = 600, max_paths: int = 48):
        """Execute a JSR and its callee exactly, if that stays tractable.

        Returns a list of (conditions, state at `return_pc`), or None when the
        callee loops past the budget, forks too widely, dispatches, or returns
        through an address the model cannot resolve.  None means "fall back
        to the havoc summary", never "the call is safe".
        """
        (entered,) = cpu.step(state)
        depth0 = state.s
        pending, finished, steps = [([], entered.state)], [], 0
        while pending:
            conditions, current = pending.pop()
            if not isinstance(current.pc, int):
                current = self.resolve_pc(current, conditions)
                if current is None:
                    return None
            if current.pc == return_pc and z3.is_true(
                    z3.simplify(current.s == depth0)):
                finished.append((conditions, current))
                if len(finished) > max_paths:
                    return None
                continue
            node = self.graph.nodes.get(current.pc)
            if node is None or current.halted:
                return None
            if (node.instruction.info.flow is Flow.CALL
                    and node.instruction.operand16 == JUMPENGINE):
                return None
            steps += 1
            if steps > max_steps:
                return None
            for successor in cpu.step(current):
                pending.append((conditions + [successor.guard],
                                successor.state))
        return finished

    def execute(self, suffix: tuple[int, ...]):
        """Returns ([(conditions, state at the last pc)], used_summary)."""
        start = havoc_state(suffix[0], self.prg)
        paths = [(list(self.invariants(start)), start)]
        summary = False
        for here, there in zip(suffix, suffix[1:]):
            kind = self._edge_kind(here, there)
            if kind is None:
                return [], summary
            advanced = []
            for conditions, state in paths:
                if kind == "return_point":
                    inlined = self.inline_call(state, there)
                    if inlined is None:
                        summary = True
                        inlined = [([], havoc_after_call(state, there))]
                    for extra, after in inlined:
                        advanced.append((conditions + extra, after))
                elif kind == "dispatch":
                    guard, after = through_jumpengine(state, there)
                    advanced.append((conditions + [guard], after))
                else:
                    for s in cpu.step(state):
                        if s.state.pc == there:
                            advanced.append((conditions + [s.guard], s.state))
            paths = [(c + list(self.invariants(s)), s) for c, s in advanced]
            if not paths:
                return [], summary
        return paths, summary

    def _bad_at(self, suffix, bad: Bad):
        paths, summary = self.execute(suffix)
        if not paths:
            return "infeasible", {}, False
        node = self.graph.nodes[suffix[-1]]
        verdict = "unsat"
        for conditions, state in paths:
            before = len(state.mem.writes)
            if node.instruction.info.flow is Flow.HALT:
                writes = ()
            else:
                writes = cpu.step(state)[0].state.mem.writes[before:]
            solver = z3.Solver()
            solver.set("timeout", self.timeout_ms)
            solver.add(*conditions)
            solver.add(bad(state, writes))
            answer = solver.check()
            if answer == z3.sat:
                model = solver.model()
                return "sat", {str(d): str(model[d]) for d in model.decls()
                               if z3.is_bv_value(model[d])}, summary
            if answer != z3.unsat:
                verdict = "unknown"
        return verdict, {}, summary

    # -- backward deepening --------------------------------------------------

    def prove_never(self, target: int, bad: Bad, *, max_depth: int = 12,
                    max_suffixes: int = 4000) -> Outcome:
        outcome = Outcome(True)
        stack = [(target,)]
        while stack:
            suffix = stack.pop()
            outcome.solver_calls += 1
            if outcome.solver_calls > max_suffixes:
                return replace(outcome, holds=False, failing_suffix=suffix,
                               reason="suffix budget exhausted")
            answer, model, summary = self._bad_at(suffix, bad)
            outcome.used_call_summary |= summary and answer == "unsat"
            if answer in ("unsat", "infeasible"):
                outcome.proved_suffixes += 1
                outcome.max_depth = max(outcome.max_depth, len(suffix))
                continue
            if answer == "unknown":
                return replace(outcome, holds=False, failing_suffix=suffix,
                               reason="solver gave no answer")
            head = suffix[0]
            if head in self.closed_entries:
                outcome.entry_assumptions.add(self.closed_entries[head])
                continue
            predecessors = sorted({p for p, kind
                                   in self.graph.nodes[head].predecessors})
            if head in self.graph.seeds:
                return replace(outcome, holds=False, failing_suffix=suffix,
                               model=model,
                               reason=f"reached graph entry ${head:04X} with "
                                      "the bad condition still satisfiable")
            if not predecessors:
                return replace(outcome, holds=False, failing_suffix=suffix,
                               model=model,
                               reason=f"${head:04X} has no recorded "
                                      "predecessor")
            if len(suffix) >= max_depth:
                return replace(outcome, holds=False, failing_suffix=suffix,
                               model=model,
                               reason=f"still satisfiable at depth {max_depth}")
            stack.extend((p,) + suffix for p in predecessors)
        return outcome
