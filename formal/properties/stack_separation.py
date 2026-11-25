"""Return-frame separation: the data in page one and the stack never meet.

`STACK-PAGE-STORES` ("no instruction other than a push writes `$0100-$01FF`")
cannot be proved, because it is not true of this program.  The traces in
`results/reports/dyn_observations.json` (key `stack_page_writes`) record 28
ordinary instructions writing into the stack page, and they are supposed to:
the game keeps per-object arrays at the bottom of page one.  A frame-integrity
argument therefore cannot be "nothing else writes the page".  It has to be a
**separation** statement:

    every byte a non-push instruction writes into page one lies strictly
    below every byte a push has written and not yet released.

This module attempts both halves of that against the SMT machine model.

    A  data side    for every instruction in `N` that the model says can write
                    an address in page one otherwise than by pushing, bound the
                    *offset within the page* it can write.  `SEP-DATA` is the
                    maximum of those bounds, `B`.
    B  stack side   a lower bound on the stack pointer, `S >= $FF - D`, by
                    abstract interpretation over the call graph.  The lowest
                    byte any push can write is then at offset `$FF - D + 1`,
                    and every byte at or below offset `$FF - D` is dead.
    A+B             `SEP-SEPARATION`: separation holds iff `B <= $FF - D`.

Offsets, not addresses: `$0100-$01FF` is mirrored at `$0900`, `$1100` and
`$1900`, and a write to `$0939` modifies the same RAM cell as a write to
`$0139`.  Every bound here is on the low byte of the address, which is also
the value the stack pointer would have to take for a push to reach the cell,
so the two halves are directly comparable.

What the two halves rest on
---------------------------

The data side is slice-based, so it carries `J-LOCATION` and `J-ASYNC` like
every other slice result (see `verify/symexec.py`).  Where an index bound is
needed it is supplied as a program-point invariant and *proved by induction
over visits to a set of cut points* -- not by unrolling a loop -- so no path
length is assumed.  One writer gets a hand-supplied candidate invariant
(`HINTS`); the guess is manual, the proof is not, and `provenance` says which
is which on every record.

The stack side adds four assumptions, each named on the obligation:

A-NMI-SINGLE       at most one NMI frame is live at a time.  The model admits
                   unbounded re-entry (`transitions.py` says so in as many
                   words), and the handler clears NMI enable at its fifth
                   instruction, `$808C`, so four boundaries are exposed.
                   Closing this needs `MA-NMI-EDGE` plus the invariant
                   "enable is clear while the handler body runs", which is
                   exactly what `J-ASYNC` records as unproved.
A-RESET-PROLOGUE   after a reset the five instructions `$8000-$8009` run to
                   completion before anything pushes.  Needed because reset
                   drops `S` by three *without writing* (hardware does three
                   dummy stack reads), so resets can walk the pointer down
                   without bound.  `SEP-RESET-NO-DRIFT` is the refutation that
                   makes this assumption necessary rather than decorative.
A-RECURSION        at most `R` nested activations of `$C26C`.  The call graph
                   is *not* acyclic: `$C26C` reaches itself through its own
                   JumpEngine dispatch.  `SEP-RECURSION` reports the cycle and
                   the module computes the largest `R` the separation margin
                   can absorb.
J-STACK-FRAMES     every `RTS`/`RTI` pops the frame its `JSR`/interrupt entry
                   pushed.  This is frame integrity itself, so the stack side
                   is one conjunct of a joint induction with the data side and
                   cannot be promoted on its own.  `SEP-SEPARATION` says so.

The circularity is real and is not hidden: `Phi := (frames intact) and
($FF - S <= D)` is the candidate joint invariant, the data side is the
preservation step for the first conjunct given the second, and the stack side
is the preservation argument for the second given the first.  What is *not*
done here is to discharge the two as a single mechanised induction; that is
`LOC-RETURN`'s remaining gap and this module narrows it rather than closing
it.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Callable

import z3

from analysis.cfg import JUMPENGINE
from analysis.decoder import Flow

from ..model import cpu
from ..model.cpu import State
from ..model.memory import NESMemory, as_int
from ..verify import crosscheck
from ..verify.obligations import Ledger, Obligation, check_valid
from ..verify.symexec import Slicer, havoc_state
from .common import (IRQ_ASSUMPTION, MODEL_SCOPE, SLICE_ASSUMPTIONS, Context,
                     stack_page_hit)
from .state_domains import hexes, outcome_fields, writers_of

REPORT = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "results", "reports", "stack_separation.json")

#: Mnemonics whose write into page one is a push.  Used only to cross-check
#: `write_displacements`, which decides the same question from the model; if
#: the two ever disagree, `SEP-PUSH-PARTITION` says so.
PUSHES = frozenset({"PHA", "PHP", "JSR", "BRK"})

#: the offset the steady-state writers are expected to respect.  Only used to
#: pick the weakest useful index hypothesis; every reported bound is the
#: tightest the method could prove, and the combined result uses the maximum.
TARGET = 0x39

#: edge kinds that carry control between instructions
KINDS = ("fallthrough", "branch", "jump", "call", "dispatch", "return_point",
         "interrupt")

IRQ_ENTRY = {0xFFF0: IRQ_ASSUMPTION}

RESET_TXS = 0x8009
RESET_ENTRY = 0x8000

NMI_SINGLE = ("A-NMI-SINGLE: at most one NMI frame is live at a time (the "
              "model admits unbounded re-entry; needs MA-NMI-EDGE and the "
              "handler's own disabling of NMI enable at $808C)")
RESET_PROLOGUE = ("A-RESET-PROLOGUE: after a reset the prologue $8000-$8009 "
                  "runs to completion before any instruction pushes (reset "
                  "lowers S by three without writing)")
FRAMES = ("J-STACK-FRAMES: every RTS and RTI pops the frame its JSR or "
          "interrupt entry pushed -- frame integrity itself, so this is a "
          "conjunct of a joint induction with the data side")

DEPTH = 16
#: Suffixes one backward-deepening run may try.  Kept low on purpose: the
#: growth loop below wants many cheap runs rather than one long one, because
#: a run that gives up hands back a suffix to put a cut point on.
BUDGET = 400
MAX_CUTS = 6
#: wall-clock budget for one writer's slice work.  An exhausted budget is
#: reported as `unknown`, never as a counterexample: the method ran out of
#: time, which says nothing about the program.
SECONDS_PER_WRITER = float(os.environ.get("SMB1_SEP_SECONDS", "45"))


def offset(address):
    """The low byte of an address: the page-one offset, and an `S` value."""
    return z3.Extract(7, 0, address)


def above(bound: int):
    """Bad condition: some write lands in page one above `bound`."""
    return lambda state, writes: z3.Or(z3.BoolVal(False), *[
        z3.And(stack_page_hit(a), z3.UGT(offset(a), bound))
        for a, _ in writes])


def any_page_write(state, writes):
    return z3.Or(z3.BoolVal(False), *[stack_page_hit(a) for a, _ in writes])


def write_displacements(ctx: Context) -> tuple[dict, dict]:
    """Split `N` into the instructions that push and the rest, from the model.

    Every write the model makes through `write_stack` has the address
    `Concat($01, S - i)`, so its offset within the page is a constant
    displacement from the stack pointer; a write through `write` has an
    address that does not mention `S` at all, so no displacement from it is
    constant.  Classifying by that difference, rather than by a list of
    mnemonics, is what lets the separation statement say "other than a push"
    about the model instead of about an assembler's vocabulary.

    Returns `({pc: [displacements]}, {pc: writes})` for the pushing and the
    non-pushing instructions, both restricted to instructions that write.
    """
    pushes, others = {}, {}
    for pc in sorted(ctx.graph.nodes):
        state = havoc_state(pc, ctx.prg)
        first = len(state.mem.writes)
        writes = [w for successor in cpu.step(state)
                  for w in successor.state.mem.writes[first:]]
        if not writes:
            continue
        shifts = [as_int(z3.simplify(offset(a) - state.s)) for a, _ in writes]
        signed = [None if d is None else d - 0x100 if d > 0x7F else d
                  for d in shifts]
        if all(d is not None and d <= 0 for d in signed):
            pushes[pc] = sorted({-d for d in signed})
        else:
            others[pc] = len(writes)
    return pushes, others


def _ask(assertions, kind: str, *, timeout_ms: int = 20000):
    """One satisfiability question, hashed and cross-checked like the rest."""
    solver = z3.Solver()
    solver.set("timeout", timeout_ms)
    solver.add(*assertions)
    answer = str(solver.check())
    crosscheck.record(list(assertions), answer, kind)
    model = {}
    if answer == "sat":
        found = solver.model()
        model = {str(d): str(found[d]) for d in found.decls()
                 if z3.is_bv_value(found[d])}
    return answer, model


# ---------------------------------------------------------------------------
# A. the data side
# ---------------------------------------------------------------------------

def page_write_terms(pc: int, prg: bytes, bound: int, state: State | None):
    """`(start state, [write-above-bound terms])` for one instruction."""
    state = state or havoc_state(pc, prg)
    first = len(state.mem.writes)
    terms = [z3.And(stack_page_hit(a), z3.UGT(offset(a), bound))
             for successor in cpu.step(state)
             for a, _ in successor.state.mem.writes[first:]]
    return state, terms


def holds_in_one_step(pc: int, prg: bytes, bound: int,
                      hypothesis: Callable[[State], z3.BoolRef] | None = None
                      ) -> bool:
    """Does the instruction alone keep every page-one write at `<= bound`?

    No graph, no slice: the start state is unconstrained, so a `True` here is
    a property of the instruction and carries no assumption at all.
    """
    state, terms = page_write_terms(pc, prg, bound, None)
    if not terms:
        return True
    assertions = ([hypothesis(state)] if hypothesis else []) + [z3.Or(*terms)]
    answer, _ = _ask(assertions, "page_write_bound")
    return answer == "unsat"


def tightest_bound(pc: int, prg: bytes, hypothesis=None) -> int:
    """The least `b` with `holds_in_one_step(pc, b)`; `$FF` means no bound."""
    low, high = 0, 0xFF
    while low < high:
        middle = (low + high) // 2
        if holds_in_one_step(pc, prg, middle, hypothesis):
            high = middle
        else:
            low = middle + 1
    return low


def weakest_index_bound(pc: int, prg: bytes, register: str,
                        bound: int) -> int | None:
    """The largest `k` with `[in page and reg <= k] => offset <= bound`.

    The weakest hypothesis that still gives the bound is the one most likely
    to be inductive, so this is the one to try.  `None` means the register
    does not control the address at all: not even `reg == 0` bounds it, which
    is the signature of an address that comes from memory.
    """
    predicate = lambda k: (lambda state: z3.ULE(getattr(state, register), k))
    if not holds_in_one_step(pc, prg, bound, predicate(0)):
        return None
    low, high = 0, 0xFF
    while low < high:
        middle = (low + high + 1) // 2
        if holds_in_one_step(pc, prg, bound, predicate(middle)):
            low = middle
        else:
            high = middle - 1
    return low


@dataclass
class Hypothesis:
    """A candidate program-point invariant and where it is claimed to hold."""
    name: str
    predicate: Callable[[State], z3.BoolRef]
    cuts: set
    provenance: str
    #: the bound the writer gets if the hypothesis holds
    bound: int


def _clear_loop(ctx: Context) -> Hypothesis:
    """`$90DC`: the reset memory clear, whose guard is the point of it.

    `InitializeMemory` walks pages `$0700` down to `$0000` through the pointer
    at `$06`, and when the page is one it skips every offset at or above
    `$60`, which is what keeps it from erasing the stack it is standing on.
    The invariant that makes that argument go through is about `$06`, `$07`
    and `A`, not about an index register, so it is supplied here by hand and
    checked like any other.
    """
    return Hypothesis(
        "A = 0 and RAM[$06] = 0 and RAM[$07] = X and X <= 7",
        lambda s: z3.And(s.a == 0, s.mem.ram_byte(0x06) == 0,
                         s.mem.ram_byte(0x07) == s.x, z3.ULE(s.x, 7)),
        {0x90D4}, "hand-supplied candidate invariant, checked here", 0x5F)


#: writer -> candidate invariant, for the writers the synthesiser cannot reach
HINTS: dict[int, Callable[[Context], Hypothesis]] = {0x90DC: _clear_loop}


def synthesised(ctx: Context, writer: int) -> list[Hypothesis]:
    """Index-bound hypotheses for `writer`, weakest first, model-derived.

    Which register controls the address is decided by asking the solver
    whether constraining it gives the bound, not by looking at the addressing
    mode.
    """
    out = []
    for register in ("x", "y"):
        k = weakest_index_bound(writer, ctx.prg, register, TARGET)
        if k is None:
            continue
        predicate = lambda s, r=register, kk=k: z3.ULE(getattr(s, r), kk)
        bound = tightest_bound(writer, ctx.prg, predicate)
        out.append(Hypothesis(f"{register.upper()} <= 0x{k:02X}", predicate,
                              {writer}, "synthesised", bound))
    return out


def loop_head(suffix, ctx: Context) -> int | None:
    """A node in `suffix` that heads a loop: the first with a back edge.

    Backward deepening diverges on a loop -- it unrolls it -- and the cure is
    an invariant at a cut point on the cycle.  A node with a predecessor at a
    higher address is where to put one.
    """
    for pc in suffix:
        if any(p >= pc for p, k in ctx.graph.nodes[pc].predecessors
               if k in KINDS):
            return pc
    return None


def consecution(ctx: Context, slicer: Slicer, hypothesis: Hypothesis,
                point: int, source: int, kind: str):
    """Does `hypothesis` hold at `point` after the step `source -> point`?

    The hypothesis is assumed at every cut point *the slice passes through*,
    which for the back edge of a loop is the previous visit: that is the
    induction step for "`hypothesis` holds whenever control is at a cut
    point", with the base case being the suffixes that reach a graph entry
    without meeting one.
    """
    if kind in ("return_point", "dispatch"):
        return None, ("call-boundary edge: what the callee left in the "
                      "registers is unknown, so the invariant would need a "
                      "routine contract")
    bad = lambda state, _writes: z3.Or(z3.BoolVal(False), *[
        z3.And(s.guard, z3.Not(hypothesis.predicate(s.state)))
        for s in cpu.step(state) if s.state.pc == point])
    outcome = slicer.prove_never(source, bad, max_depth=DEPTH,
                                 max_suffixes=BUDGET)
    return outcome, None


def try_hypothesis(ctx: Context, writer: int, hypothesis: Hypothesis, *,
                   deadline: float | None = None) -> dict:
    """Prove the writer's bound under `hypothesis`, and `hypothesis` itself.

    Cut points are grown lazily: when a check is still satisfiable at the
    depth limit, the loop it is unrolling gets an invariant and the check is
    retried.  Growing the set only adds hypotheses to existing checks, so a
    check that closed stays closed.
    """
    cuts = set(hypothesis.cuts)
    slicer = Slicer(ctx.graph, ctx.prg, closed_entries=IRQ_ENTRY,
                    invariants=lambda s: ([hypothesis.predicate(s)]
                                          if s.pc in cuts else []))
    closed, rounds, assumptions = set(), 0, set()
    bound_closed = False
    while True:
        rounds += 1
        failures = []
        if deadline is not None and time.time() > deadline:
            return {"proved": False, "cuts": sorted(cuts), "rounds": rounds,
                    "entry_assumptions": sorted(assumptions),
                    "failures": [{"part": "budget", "cut_point": "",
                                  "from": "", "edge": "",
                                  "reason": "time budget exhausted",
                                  "suffix": []}]}
        # (i) the bound itself, under the hypothesis
        if not bound_closed:
            bound_outcome = slicer.prove_never(writer, above(hypothesis.bound),
                                               max_depth=DEPTH,
                                               max_suffixes=BUDGET)
            if not bound_outcome.holds:
                failures.append(("bound", writer, writer, "",
                                 bound_outcome.reason,
                                 bound_outcome.failing_suffix))
            else:
                bound_closed = True
                assumptions |= bound_outcome.entry_assumptions
                if bound_outcome.used_call_summary:
                    assumptions.add("J-STACK")
        # (ii) the hypothesis, at every cut point.  The in-edges are all the
        # ways control can arrive -- that is what J-LOCATION says -- so they
        # are both the induction step and the base case.  A cut point that is
        # a graph entry has an arrival the graph does not model, and one with
        # no recorded predecessor at all has none; neither can be discharged
        # here, and saying so is the difference between an induction and a
        # vacuous one.
        for point in sorted(cuts):
            in_edges = sorted({(p, k) for p, k
                               in ctx.graph.nodes[point].predecessors
                               if k in KINDS})
            if point in ctx.graph.seeds or not in_edges:
                failures.append(("invariant", point, point, "entry",
                                 "the cut point is a graph entry, so the "
                                 "first arrival is from an unconstrained "
                                 "state and the base case is open"
                                 if point in ctx.graph.seeds else
                                 "the cut point has no recorded predecessor",
                                 ()))
                continue
            for source, kind in in_edges:
                key = (point, source, kind)
                if key in closed:
                    continue
                if deadline is not None and time.time() > deadline:
                    failures.append(("invariant", point, source, kind,
                                     "time budget exhausted", ()))
                    continue
                outcome, why = consecution(ctx, slicer, hypothesis, point,
                                           source, kind)
                if outcome is None:
                    failures.append(("invariant", point, source, kind, why,
                                     ()))
                    continue
                if outcome.holds:
                    closed.add(key)
                    assumptions |= outcome.entry_assumptions
                    if outcome.used_call_summary:
                        assumptions.add("J-STACK")
                else:
                    failures.append(("invariant", point, source, kind,
                                     outcome.reason, outcome.failing_suffix))
        if not failures:
            return {"proved": True, "cuts": sorted(cuts), "rounds": rounds,
                    "entry_assumptions": sorted(assumptions)}
        grown = False
        if len(cuts) <= MAX_CUTS:
            for _what, _point, _source, _kind, _why, suffix in failures:
                head = loop_head(suffix, ctx)
                if head is not None and head not in cuts:
                    cuts.add(head)
                    grown = True
                    break
        if not grown:
            return {"proved": False, "cuts": sorted(cuts), "rounds": rounds,
                    "entry_assumptions": sorted(assumptions),
                    "failures": [
                        {"part": what, "cut_point": f"0x{point:04X}",
                         "from": f"0x{source:04X}", "edge": kind,
                         "reason": why, "suffix": hexes(suffix)}
                        for what, point, source, kind, why, suffix
                        in failures[:4]]}


def classify_writer(ctx: Context, slicer: Slicer, writer: int) -> dict:
    """Bound one writer's page-one writes, as tightly as the method can.

    Order matters: an unconditional one-step bound is the strongest thing on
    offer, "never writes the page at all" is next, and an index invariant
    last.  Each step is attempted only if the previous one did not settle it.
    """
    instruction = ctx.graph.nodes[writer].instruction
    record = {"instruction": str(instruction),
              "mnemonic": instruction.info.mnemonic,
              "mode": instruction.info.mode}
    deadline = time.time() + SECONDS_PER_WRITER

    # (1) the instruction on its own
    one_step = tightest_bound(writer, ctx.prg)
    record["one_step_bound"] = f"0x01{one_step:02X}"
    if one_step <= TARGET:
        check = check_valid(
            f"SEP-W-{writer:04X}",
            z3.Not(z3.Or(z3.BoolVal(False), *page_write_terms(
                writer, ctx.prg, one_step, None)[1])),
            rom_derived=True)
        record.update(status="proved" if check.valid else "unknown",
                      method="one-step bound, from an unconstrained state",
                      bound=f"0x01{one_step:02X}", bound_offset=one_step,
                      assumptions=[], query_sha256=check.query_sha256,
                      query_artifact=check.query_artifact,
                      independent_check=f"cvc5: {check.cvc5_result}")
        return record

    # (2) does it reach the page at all?
    outcome = slicer.prove_never(writer, any_page_write, max_depth=12)
    if outcome.holds:
        unreachable = slicer.prove_never(
            writer, lambda s, w: z3.BoolVal(True), max_depth=10)
        status, assumptions, detail = outcome_fields(outcome)
        record.update(status=status, bound=None, bound_offset=None,
                      method=("the instruction is unreachable" if
                              unreachable.holds else
                              "no execution writes page one"),
                      assumptions=assumptions, slice=detail)
        return record

    # (2b) a bound from the slice alone, with no invariant: enough whenever
    # whatever limits the address is set on the way in rather than carried
    # round a loop.
    if writer not in HINTS:
        outcome = slicer.prove_never(writer, above(TARGET), max_depth=DEPTH,
                                     max_suffixes=BUDGET)
        if outcome.holds:
            bound = TARGET
            low = 0
            while low < bound and time.time() < deadline:   # tighten
                middle = (low + bound) // 2
                if slicer.prove_never(writer, above(middle), max_depth=DEPTH,
                                      max_suffixes=BUDGET).holds:
                    bound = middle
                else:
                    low = middle + 1
            status, assumptions, detail = outcome_fields(outcome)
            record.update(status=status, bound=f"0x01{bound:02X}",
                          bound_offset=bound,
                          method="bound from the backward slice alone",
                          assumptions=assumptions, slice=detail)
            return record

    # (3) an index invariant
    candidates = ([HINTS[writer](ctx)] if writer in HINTS
                  else synthesised(ctx, writer))
    attempts = []
    for hypothesis in candidates:
        result = try_hypothesis(ctx, writer, hypothesis, deadline=deadline)
        attempts.append({"invariant": hypothesis.name,
                         "provenance": hypothesis.provenance,
                         "bound": f"0x01{hypothesis.bound:02X}",
                         "cut_points": hexes(result["cuts"]),
                         "rounds": result["rounds"],
                         **({"failures": result["failures"]}
                            if not result["proved"] else {})})
        if result["proved"]:
            assumptions = list(SLICE_ASSUMPTIONS)
            assumptions.extend(sorted(result["entry_assumptions"]))
            record.update(
                status="conditional", bound=f"0x01{hypothesis.bound:02X}",
                bound_offset=hypothesis.bound,
                method="program-point invariant, proved by induction over "
                       "visits to the cut points",
                invariant=hypothesis.name,
                provenance=hypothesis.provenance,
                cut_points=hexes(result["cuts"]), assumptions=assumptions,
                attempts=attempts)
            return record
    reason = cause(ctx, writer, attempts, bool(candidates))
    record.update(
        status=("unknown" if reason["kind"] == "budget"
                else "abstract_counterexample"),
        bound=None, bound_offset=None,
        method=("no register bound reaches the target offset: the write "
                "address is not determined by X or Y" if not candidates
                else "index invariant not established"),
        cause=reason, assumptions=[], attempts=attempts)
    return record


#: why an open writer is open, in the words of what actually failed
CAUSES = {
    "pointer": "the write address comes from memory, so no bound on X or Y "
               "constrains it",
    "call": "the index crosses a call boundary: the slice steps over a JSR "
            "or a dispatch, where it gives up every register whatever the "
            "callee does, so a deeper slice cannot help",
    "rom_table": "the index is read out of a table at an address the slice "
                 "only knows symbolically, and the model leaves PRG "
                 "unconstrained there (NESMemory.read adds no prg_axioms), "
                 "so the bound is a gap in the tooling rather than in the "
                 "program",
    "loop_head": "a constant bound on the register is not inductive at the "
                 "loop head the growth reached: the loop's exit condition "
                 "depends on memory, so the invariant needed is a relation "
                 "to a cell rather than an interval",
    "entry": "the backward slice reaches a graph entry with the index still "
             "unconstrained, so the code does not bound it locally",
    "depth": "the backward slice was still satisfiable at the depth limit, "
             "and no further cut point suggested itself",
    "budget": "the wall-clock budget for this writer ran out; nothing "
              "follows about the program",
    "unknown": "see the failures on the attempt record",
}


def mentions_prg(term) -> bool:
    """Does `term` read the image through the symbolic-address `PRG` array?"""
    seen, pending = set(), [term]
    while pending:
        current = pending.pop()
        if current.get_id() in seen:
            continue
        seen.add(current.get_id())
        if z3.is_const(current) and current.decl().eq(NESMemory.PRG.decl()):
            return True
        pending.extend(current.children())
    return False


def reads_rom_symbolically(ctx: Context, pc: int) -> bool:
    """Does the instruction at `pc` take a value from `PRG` as an array?

    A read from ROM at a concrete address gives the image byte; at a symbolic
    address it goes through the `PRG` array, which nothing here constrains.
    An index that came through one of those is unbounded for a reason that
    has nothing to do with the program.
    """
    state = havoc_state(pc, ctx.prg)
    first = len(state.mem.writes)
    for successor in cpu.step(state):
        for term in (successor.state.a, successor.state.x, successor.state.y,
                     successor.guard):
            if mentions_prg(term):
                return True
        for address, value in successor.state.mem.writes[first:]:
            if mentions_prg(address) or mentions_prg(value):
                return True
    return False


def crossed_call_in(ctx: Context, suffix) -> str | None:
    """The first node in `suffix` whose edge onward is a call boundary."""
    for here, there in zip(suffix, suffix[1:]):
        for target, kind in ctx.graph.nodes[here].successors:
            if target == there and kind in ("return_point", "dispatch"):
                return f"0x{here:04X}"
    return None


def cause(ctx: Context, writer: int, attempts: list,
          had_candidate: bool) -> dict:
    """Why this writer is open, decided from what actually failed.

    The order is the order of how little a better slice would help: a budget
    that ran out says nothing at all, a call boundary and an unconstrained
    `PRG` are walls, and only the last two are "the method stopped early".
    """
    failures = [f for attempt in attempts for f in attempt.get("failures", ())]
    if any(f["part"] == "budget" or f["reason"] == "time budget exhausted"
           for f in failures):
        # Say what the run was working on when it ran out, so a budget case
        # is not a dead end in the record.
        crossings = sorted({c for f in failures
                            for c in [crossed_call_in(
                                ctx, [int(a, 16) for a in f["suffix"]])]
                            if c is not None})
        return {"kind": "budget", "why": CAUSES["budget"],
                **({"the_slices_it_was_working_on_cross_a_call_at": crossings,
                    "note": "so this writer is most likely a `call` case; it "
                            "is recorded as `budget` because the method did "
                            "not get far enough to say so"}
                   if crossings else {})}
    if not had_candidate:
        return {"kind": "pointer", "why": CAUSES["pointer"]}
    for failure in failures:
        if failure["edge"] in ("return_point", "dispatch"):
            return {"kind": "call", "why": CAUSES["call"], "at": failure}
    for failure in failures:
        suffix = [int(a, 16) for a in failure["suffix"]]
        crossing = crossed_call_in(ctx, suffix)
        if crossing is not None:
            return {"kind": "call", "why": CAUSES["call"], "at": failure,
                    "call_site": crossing}
        rom = [f"0x{pc:04X}" for pc in suffix
               if reads_rom_symbolically(ctx, pc)]
        if rom:
            return {"kind": "rom_table", "why": CAUSES["rom_table"],
                    "at": failure, "symbolic_rom_reads": rom}
    for failure in failures:
        if "graph entry" in (failure["reason"] or ""):
            return {"kind": "entry", "why": CAUSES["entry"], "at": failure}
    for failure in failures:
        if failure["cut_point"] not in ("", f"0x{writer:04X}"):
            return {"kind": "loop_head", "why": CAUSES["loop_head"],
                    "at": failure}
    for failure in failures:
        if "depth" in (failure["reason"] or ""):
            return {"kind": "depth", "why": CAUSES["depth"], "at": failure}
    return {"kind": "unknown", "why": CAUSES["unknown"]}


def data_side(ledger: Ledger, ctx: Context) -> dict:
    """`SEP-W-*` for every non-push writer, and `SEP-DATA` over them."""
    slicer = Slicer(ctx.graph, ctx.prg, closed_entries=IRQ_ENTRY)
    pushes, _others = write_displacements(ctx)
    with crosscheck.collect("SEP-DATA-SCAN") as scan:
        page_writers = writers_of(ctx, stack_page_hit)
    writers = [pc for pc in page_writers if pc not in pushes]
    mnemonics = {ctx.graph.nodes[pc].instruction.info.mnemonic
                 for pc in pushes}
    frames = sorted({max(v) + 1 for v in pushes.values()})
    ledger.add(Obligation(
        "SEP-PUSH-PARTITION",
        "every instruction in N that writes into page one either writes only "
        "at a constant displacement from the stack pointer -- it pushes -- or "
        "writes at an address that does not involve the stack pointer at all",
        "the partition the separation statement is stated over", "proved",
        solver="exhaustive execution of the CPU model, one node at a time",
        detail={
            "scope": MODEL_SCOPE,
            "method": "a write the model makes through write_stack has the "
                      "address Concat($01, S - i); every other write's "
                      "address does not mention S, so offset(a) - S is not a "
                      "constant.  No mnemonic is consulted",
            "pushing_instructions": len(pushes),
            "pushing_mnemonics": sorted(mnemonics),
            "frame_sizes_in_bytes": frames,
            "largest_displacement_below_s": max(
                (max(v) for v in pushes.values()), default=0),
            "agrees_with_the_mnemonic_list": sorted(mnemonics) == sorted(
                m for m in PUSHES if m in mnemonics) and not (
                    mnemonics - set(PUSHES)),
            "page_one_writers": len(page_writers),
            "of_those_pushing": len(page_writers) - len(writers),
            "of_those_not_pushing": len(writers),
            "consequence": "a push writes at offsets S, S-1, ... S-k+1, so "
                           "the lowest byte any push can write is one above "
                           "the lowest value S takes; SEP-DEPTH bounds that "
                           "and SEP-DATA bounds the rest",
        }))
    for hinted in sorted(HINTS):
        if hinted in writers:
            clear_loop_reach(ledger, ctx, hinted)
    records, ids = {}, []
    for writer in writers:
        with crosscheck.collect(f"SEP-W-{writer:04X}") as queries:
            record = classify_writer(ctx, slicer, writer)
        status = record["status"]
        if not queries.clean:
            status = "unknown"
            record["demoted"] = ("a second solver contradicted Z3 on a query "
                                 "this record rests on")
        record["slice_queries"] = queries.summary()
        ids.append(f"SEP-W-{writer:04X}")
        ledger.add(Obligation(
            ids[-1], _statement(writer, record),
            "page-one write bound for one instruction", status,
            record.get("assumptions", []), solver="z3",
            query_artifact=record.get("query_artifact"),
            query_sha256=record.get("query_sha256"),
            independent_check=record.get("independent_check"),
            detail={"scope": MODEL_SCOPE, **record}))
        records[f"0x{writer:04X}"] = record

    settled = [r for r in records.values()
               if r["status"] in ("proved", "conditional")]
    open_writers = [a for a, r in records.items()
                    if r["status"] not in ("proved", "conditional")]
    bounded = [r["bound_offset"] for r in settled
               if r.get("bound_offset") is not None]
    worst = max(bounded) if bounded else None
    if not open_writers:
        status = "conditional"
    elif any(records[a]["status"] == "unknown" for a in open_writers):
        status = "unknown"
    else:
        status = "abstract_counterexample"
    assumptions = sorted({a for r in settled for a in r.get("assumptions", ())})
    ledger.add(Obligation(
        "SEP-DATA",
        "every write into RAM page one by an instruction other than a push "
        + (f"is at offset <= ${worst:02X}" if worst is not None
           else "is bounded"),
        "data half of the separation statement", status,
        assumptions if not open_writers else [],
        dependencies=ids + ["SEP-PUSH-PARTITION"],
        solver="z3",
        detail={
            "scope": MODEL_SCOPE,
            "non_push_writers": len(writers),
            "proved_unconditionally": sum(r["status"] == "proved"
                                          for r in records.values()),
            "conditional": sum(r["status"] == "conditional"
                               for r in records.values()),
            "open": len(open_writers),
            "open_writers": {
                address: {"instruction": records[address]["instruction"],
                          **records[address].get("cause", {})}
                for address in sorted(open_writers)},
            "open_by_cause": _by_cause(records, open_writers),
            "worst_offset": None if worst is None else f"0x01{worst:02X}",
            "steady_state_worst_offset": _steady_worst(records),
            "writer_scan_queries": scan.summary(),
            "why_open": None if not open_writers else
                "see each SEP-W-* record's `attempts`; the common reasons are "
                "an address that comes from a RAM pointer and an index that "
                "crosses a call boundary",
            "callees_the_open_indices_cross": index_restores(
                ctx, crossed_callees(
                    {a: records[a] for a in open_writers}, ctx)),
            "what_would_close_the_call_boundary_cases":
                "a routine contract `X == RAM[cell]` at the return, plus a "
                "domain for that cell.  The evidence above is that the "
                "program restores the index from a zero-page cell rather "
                "than preserving it, which is why a longer slice would not "
                "help and the `copies` facts in verify/JOINT_INVARIANT.md "
                "would",
        }))
    return {"writers": records, "worst_offset": worst,
            "open": sorted(open_writers), "obligations": ids,
            "open_statuses": sorted({records[a]["status"]
                                     for a in open_writers})}


#: edges that stay inside one routine: a call leaves it, a return ends it
LOCAL_KINDS = ("fallthrough", "branch", "jump", "dispatch", "return_point",
               "interrupt")


def closure(ctx: Context, entry: int, kinds) -> set:
    """Instructions reachable from `entry` along `kinds`, stopping at exits."""
    nodes, seen, work = ctx.graph.nodes, set(), [entry]
    while work:
        pc = work.pop()
        if pc in seen or pc not in nodes:
            continue
        seen.add(pc)
        if nodes[pc].instruction.info.flow in (Flow.RETURN, Flow.HALT,
                                               Flow.INDIRECT_JUMP):
            continue
        for target, kind in nodes[pc].successors:
            if kind in kinds:
                work.append(target)
    return seen


def clear_loop_reach(ledger: Ledger, ctx: Context, writer: int) -> None:
    """Is the reset memory clear reset-only?  It is not, and it matters.

    The obvious reading of `$90DC` is that it runs once, out of reset, before
    there is a return address to damage -- in which case its bound would not
    need to be part of a separation argument at all.  The graph says
    otherwise: the routine that contains it is also called from two sites
    inside the NMI handler's call tree, where frames are live.  So the
    `$0160` guard in that routine is not belt and braces, it is what keeps
    the clear off the stack during play, and `SEP-W-90DC`'s bound is
    load-bearing.
    """
    nodes = ctx.graph.nodes
    nmi = closure(ctx, ctx.read(0xFFFA) | ctx.read(0xFFFB) << 8, KINDS)
    reset = closure(ctx, RESET_ENTRY, KINDS)
    routines = [entry for entry in routine_entries(ctx)
                if writer in closure(ctx, entry, LOCAL_KINDS)]
    sites = {}
    for entry in routines:
        for source, kind in sorted({(p, k) for p, k
                                    in nodes[entry].predecessors}):
            if kind != "call":
                continue
            sites[f"0x{source:04X}"] = {
                "calls": f"0x{entry:04X}",
                "instruction": str(nodes[source].instruction),
                "in_the_nmi_handlers_call_tree": source in nmi,
                "in_the_reset_paths_call_tree": source in reset}
    from_play = [a for a, v in sites.items()
                 if v["in_the_nmi_handlers_call_tree"]]
    ledger.add(Obligation(
        "SEP-CLEAR-LOOP-REACH",
        f"the routine containing the page-one writer at ${writer:04X} is "
        "called from inside the NMI handler's call tree, not only from reset",
        "why the clear loop's bound is part of the separation argument",
        "proved" if from_play else "refuted", solver="graph inspection",
        detail={
            "containing_routines": hexes(routines),
            "call_sites": sites,
            "called_from_play": sorted(from_play),
            "consequence": "the clear runs while return frames are live, so "
                           "'it only runs before any return address matters' "
                           "is not available as an argument; the routine's "
                           "own guard is, and SEP-W-"
                           f"{writer:04X} is the proof of it",
            "caveat": "reachable in the graph, which is J-LOCATION's own "
                      "claim; this says the call sites exist and are not "
                      "excluded by slicing, not that the game takes them",
        }))


def crossed_callees(records: dict, ctx: Context) -> list:
    """The routines the open writers' index has to survive a call to."""
    out = set()
    for record in records.values():
        site = record.get("cause", {}).get("at", {})
        if site.get("edge") != "return_point":
            continue
        node = ctx.graph.nodes.get(int(site["from"], 16))
        if node is None or node.instruction.info.flow is not Flow.CALL:
            continue
        out.add(node.instruction.operand16)
    return sorted(out)


def index_restores(ctx: Context, entries) -> dict:
    """Where a routine reloads an index register from a zero-page cell.

    A slice that has to step over a `JSR` gives up every register
    unconditionally (`havoc_after_call`), so a call-crossing index is open
    whatever the callee happens to do, and extending the slice cannot help.
    What this program does is reload the index from a zero-page cell on the
    way out, which means the missing ingredient is a routine contract of the
    form `X == RAM[cell]` at the return plus a domain for that cell -- the
    `copies` facts the certificate language in `verify/JOINT_INVARIANT.md`
    already has.  This records the evidence for that reading of the gap; it
    asserts nothing, and a load is counted wherever it is, not only where it
    would be load-bearing.
    """
    out = {}
    for entry in entries:
        body = set()
        work = [entry]
        nodes = ctx.graph.nodes
        while work:
            pc = work.pop()
            if pc in body or pc not in nodes:
                continue
            body.add(pc)
            flow = nodes[pc].instruction.info.flow
            if flow in (Flow.RETURN, Flow.HALT, Flow.INDIRECT_JUMP):
                continue
            for target, kind in nodes[pc].successors:
                if kind in KINDS:
                    work.append(target)
        loads = {}
        for pc in sorted(body):
            instruction = nodes[pc].instruction
            info = instruction.info
            if info.mnemonic not in ("LDX", "LDY"):
                continue
            if info.mode == "zp":
                cell = instruction.operands[0]
            elif info.mode == "abs" and instruction.operand16 < 0x0100:
                cell = instruction.operand16
            else:
                continue
            before_return = sorted(
                f"0x{t:04X}" for t, kind in nodes[pc].successors
                if kind in KINDS and t in nodes
                and nodes[t].instruction.info.flow is Flow.RETURN)
            loads[f"0x{pc:04X}"] = {
                "instruction": str(instruction), "cell": f"0x{cell:04X}",
                **({"immediately_before": before_return}
                   if before_return else {})}
        restoring = {k: v for k, v in loads.items()
                     if "immediately_before" in v}
        cells: dict = {}
        for value in restoring.values():
            cells[value["cell"]] = cells.get(value["cell"], 0) + 1
        out[f"0x{entry:04X}"] = {
            "instructions_reachable_without_returning": len(body),
            "note": "the walk follows call edges, so this is the entry's "
                    "whole call tree",
            "index_loads_from_a_zero_page_cell": len(loads),
            "of_those_immediately_before_a_return": len(restoring),
            "cells_they_load_from": dict(sorted(cells.items())),
            "restoring_loads": restoring}
    return out


def _statement(writer: int, record: dict) -> str:
    """What the per-writer obligation claims -- the target claim when open."""
    if record.get("bound_offset") is not None:
        return (f"every write the instruction at ${writer:04X} makes into "
                f"RAM page one is at offset <= "
                f"${record['bound_offset']:02X}")
    if record["status"] in ("proved", "conditional"):
        return (f"the instruction at ${writer:04X} writes nothing into RAM "
                "page one")
    return (f"every write the instruction at ${writer:04X} makes into RAM "
            f"page one is at offset <= ${TARGET:02X}")


def _by_cause(records: dict, open_writers) -> dict:
    out: dict = {}
    for address in open_writers:
        kind = records[address].get("cause", {}).get("kind", "unknown")
        out.setdefault(kind, []).append(address)
    return {k: sorted(v) for k, v in sorted(out.items())}


def _steady_worst(records: dict):
    """The worst offset excluding the reset-time memory clear."""
    offsets = [r["bound_offset"] for address, r in records.items()
               if r.get("bound_offset") is not None and address != "0x90DC"]
    return f"0x01{max(offsets):02X}" if offsets else None


# ---------------------------------------------------------------------------
# B. the stack side
# ---------------------------------------------------------------------------

def stack_deltas(ctx: Context) -> tuple[dict, list]:
    """`S' - S` for every instruction in `N`, from the model.

    An instruction *adjusts* the stack pointer when the difference is the same
    constant on every successor, and *assigns* it otherwise.  Deriving this
    from `cpu.step` rather than from a list of mnemonics is what makes the
    depth analysis below a statement about the model: `TXS`, `TAS` and `LAS`
    do not have to be remembered, they show up as assignments.
    """
    deltas, assigns = {}, []
    for pc in sorted(ctx.graph.nodes):
        state = havoc_state(pc, ctx.prg)
        seen = set()
        for successor in cpu.step(state):
            value = as_int(z3.simplify(successor.state.s - state.s))
            seen.add(None if value is None else
                     value - 0x100 if value > 0x7F else value)
        if len(seen) != 1 or None in seen:
            assigns.append(pc)
        else:
            deltas[pc] = seen.pop()
    return deltas, assigns


def engine_effect(ctx: Context) -> dict:
    """What the JumpEngine does to the stack, walked out of the model.

    A `JSR $8E04` pushes two bytes and the engine pulls them back before it
    jumps, so a dispatch costs two bytes while the engine runs and nothing
    afterwards -- the dispatched routine runs on the caller's frame and its
    `RTS` returns past the dispatcher.  The depth analysis depends on that, so
    it is computed rather than asserted.
    """
    pc, net, peak, body = JUMPENGINE, 0, 0, []
    while len(body) < 64:
        state = havoc_state(pc, ctx.prg)
        (successor,) = cpu.step(state)
        value = as_int(z3.simplify(successor.state.s - state.s))
        step = 0 if value is None else (value - 0x100 if value > 0x7F
                                        else value)
        body.append(pc)
        net += step
        peak = min(peak, net)
        if ctx.graph.nodes[pc].instruction.info.flow is Flow.INDIRECT_JUMP:
            break
        pc = ctx.graph.nodes[pc].instruction.end
    return {"body": hexes(body), "net_change_in_s": net,
            "deepest_push_below_entry": -peak}


@dataclass
class Depth:
    """Interprocedural maximum stack use, in bytes below a routine's entry.

    One pass per routine, memoised on the entry address together with how many
    activations of each recursive routine are already on the stack, so a
    summary computed inside a recursion is never reused outside it.  A
    dispatch is a tail call: the target is explored at the *caller's* depth.
    """
    ctx: Context
    deltas: dict
    assigns: set
    recursive: frozenset
    limit: int
    dead: frozenset = frozenset()
    cap: int = 400
    cache: dict = field(default_factory=dict)
    active: set = field(default_factory=set)
    via: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)
    cut: list = field(default_factory=list)
    unbalanced: list = field(default_factory=list)
    seen_returns: set = field(default_factory=set)
    returns: int = 0

    def key(self, entry: int, counts: dict):
        return (entry, tuple(sorted(counts.items())))

    def cost(self, entry: int, counts: dict | None = None) -> int:
        counts = counts or {}
        key = self.key(entry, counts)
        if key in self.cache:
            return self.cache[key]
        if entry in self.recursive and counts.get(entry, 0) >= self.limit:
            # Cut by A-RECURSION: this activation does not happen.
            self.cut.append(f"0x{entry:04X}")
            self.cache[key] = 0
            return 0
        inner = dict(counts)
        if entry in self.recursive:
            inner[entry] = inner.get(entry, 0) + 1
        if key in self.active:
            # A call cycle `recursive` did not catch.  Report, do not guess.
            self.notes.append(f"unrecorded call cycle through 0x{entry:04X}")
            self.cache[key] = None
            return None
        self.active.add(key)
        nodes = self.ctx.graph.nodes
        best, work, peak, through = {}, [(entry, 0)], 0, None
        while work:
            pc, depth = work.pop()
            if pc in self.dead:
                continue
            if pc not in nodes:
                self.notes.append(f"target 0x{pc:04X} is outside N")
                continue
            if best.get(pc, -(1 << 30)) >= depth:
                continue
            best[pc] = depth
            if depth > self.cap:
                # Unbalanced pushes inside a loop: the depth does not
                # converge, so there is no bound to report.
                self.notes.append(f"depth cap reached at 0x{pc:04X} from "
                                  f"0x{entry:04X}")
                return self._give_up(key)
            if depth > peak:
                peak, through = depth, None
            instruction = nodes[pc].instruction
            flow = instruction.info.flow
            if flow is Flow.RETURN:
                self.returns += 1
                self.seen_returns.add(pc)
                if depth != 0:
                    self.unbalanced.append(
                        {"return": f"0x{pc:04X}", "entry": f"0x{entry:04X}",
                         "local_depth": depth})
                continue
            if flow is Flow.HALT:
                continue
            if flow is Flow.INDIRECT_JUMP:
                self.notes.append(f"indirect jump at 0x{pc:04X} reached "
                                  f"from 0x{entry:04X}")
                continue
            if pc == RESET_TXS:
                depth = 0                        # SEP-TXS-8009: S := $FF
                for target, kind in nodes[pc].successors:
                    if kind in KINDS:
                        work.append((target, depth))
                continue
            if pc in self.assigns:
                self.notes.append(f"0x{pc:04X} assigns the stack pointer")
                return self._give_up(key)
            if flow is Flow.BREAK:
                vector = self.ctx.read(0xFFFE) | self.ctx.read(0xFFFF) << 8
                inside = self.cost(vector, inner)
                if inside is None:
                    return self._give_up(key)
                if depth + 3 + inside > peak:
                    peak, through = depth + 3 + inside, (pc, vector)
                continue
            if flow is Flow.CALL:
                if instruction.operand16 == JUMPENGINE:
                    if depth + 2 > peak:
                        peak, through = depth + 2, (pc, JUMPENGINE)
                    for target, kind in nodes[pc].successors:
                        if kind == "dispatch":
                            work.append((target, depth))
                    continue
                inside = self.cost(instruction.operand16, inner)
                if inside is None:
                    return self._give_up(key)
                if depth + 2 + inside > peak:
                    peak, through = depth + 2 + inside, (pc,
                                                         instruction.operand16)
                for target, kind in nodes[pc].successors:
                    if kind == "return_point":
                        work.append((target, depth))
                continue
            depth -= self.deltas[pc]             # a push lowers S
            if depth > peak:
                peak, through = depth, (pc, None)
            for target, kind in nodes[pc].successors:
                if kind in KINDS:
                    work.append((target, depth))
        self.active.discard(key)
        self.cache[key] = peak
        self.via[key] = through
        return peak

    def _give_up(self, key):
        self.active.discard(key)
        self.cache[key] = None
        return None

    def chain(self, entry: int) -> list:
        """The call chain that reaches the maximum, for the record."""
        counts, out = {}, []
        while True:
            key = self.key(entry, counts)
            out.append(f"0x{entry:04X}")
            step = self.via.get(key)
            if not step or step[1] is None:
                return out
            if entry in self.recursive:
                counts = {**counts, entry: counts.get(entry, 0) + 1}
            out.append(f"@0x{step[0]:04X}")
            entry = step[1]
            if entry == JUMPENGINE:
                return out + ["jumpengine"]


def routine_entries(ctx: Context) -> list:
    out = {RESET_ENTRY, ctx.read(0xFFFA) | ctx.read(0xFFFB) << 8}
    for node in ctx.graph.nodes.values():
        instruction = node.instruction
        if (instruction.info.flow is Flow.CALL
                and instruction.operand16 != JUMPENGINE):
            out.add(instruction.operand16)
    return sorted(out)


def callees(ctx: Context, entry: int, dead: frozenset) -> set:
    """Routines `entry` can call, following dispatches as tail calls."""
    nodes, seen, work, calls = ctx.graph.nodes, set(), [entry], set()
    while work:
        pc = work.pop()
        if pc in seen or pc in dead or pc not in nodes:
            continue
        seen.add(pc)
        instruction = nodes[pc].instruction
        flow = instruction.info.flow
        if flow in (Flow.RETURN, Flow.HALT, Flow.INDIRECT_JUMP):
            continue
        if flow is Flow.CALL and instruction.operand16 != JUMPENGINE:
            calls.add(instruction.operand16)
        for target, kind in nodes[pc].successors:
            if kind in KINDS:
                work.append(target)
    return calls


def cycles(graph: dict) -> list:
    """Non-trivial strongly connected components of the call graph."""
    index, low, on, stack, counter, out = {}, {}, {}, [], [0], []
    for root in graph:
        if root in index:
            continue
        work = [(root, iter(sorted(graph.get(root, ()))))]
        index[root] = low[root] = counter[0]
        counter[0] += 1
        stack.append(root)
        on[root] = True
        while work:
            node, children = work[-1]
            descended = False
            for child in children:
                if child not in graph:
                    continue
                if child not in index:
                    index[child] = low[child] = counter[0]
                    counter[0] += 1
                    stack.append(child)
                    on[child] = True
                    work.append((child, iter(sorted(graph.get(child, ())))))
                    descended = True
                    break
                if on.get(child):
                    low[node] = min(low[node], index[child])
            if descended:
                continue
            work.pop()
            if work:
                low[work[-1][0]] = min(low[work[-1][0]], low[node])
            if low[node] == index[node]:
                component = []
                while True:
                    popped = stack.pop()
                    on[popped] = False
                    component.append(popped)
                    if popped == node:
                        break
                out.append(sorted(component))
    return [c for c in out if len(c) > 1 or c[0] in graph.get(c[0], ())]


def dead_nodes(ledger: Ledger, ctx: Context) -> frozenset:
    """Nodes the slicer shows unreachable, with their own obligations.

    Only one matters here: `$F3B1` heads a run of bytes that the decoder
    reaches by falling through `BNE` at `$F3AF`, which cannot be taken because
    `LDX #$08` two bytes earlier leaves `Z` clear.  Inside that run is the
    program's only `TXS` outside the reset prologue, and an unconstrained
    `TXS` would leave the stack pointer unbounded.
    """
    slicer = Slicer(ctx.graph, ctx.prg, closed_entries=IRQ_ENTRY)
    dead = set()
    for pc, why in ((0xF3B1, "head of the run that contains the TXS at "
                             "$F3BA"),):
        with crosscheck.collect(f"SEP-DEAD-{pc:04X}") as queries:
            outcome = slicer.prove_never(
                pc, lambda s, w: z3.BoolVal(True), max_depth=10)
        status, assumptions, detail = outcome_fields(outcome, queries)
        if outcome.holds:
            dead.add(pc)
        ledger.add(Obligation(
            f"SEP-DEAD-{pc:04X}",
            f"the instruction at ${pc:04X} is never fetched",
            "unreachability used by the depth bound", status, assumptions,
            solver="z3", detail={"scope": MODEL_SCOPE, "role": why, **detail}))
    return frozenset(dead)


def pointer_sites(ledger: Ledger, ctx: Context, assigns: list) -> None:
    """Every instruction that assigns `S`, and why each one is harmless."""
    slicer = Slicer(ctx.graph, ctx.prg, closed_entries=IRQ_ENTRY)
    with crosscheck.collect("SEP-TXS-8009") as queries:
        outcome = slicer.prove_never(
            RESET_TXS, lambda s, w: z3.Not(s.x == 0xFF), max_depth=4)
    status, assumptions, detail = outcome_fields(outcome, queries)
    ledger.add(Obligation(
        "SEP-TXS-8009",
        "X = $FF whenever the TXS at $8009 is fetched, so it sets S = $FF",
        "initialisation of the stack pointer", status, assumptions,
        solver="z3", detail={"scope": MODEL_SCOPE, **detail}))
    ledger.add(Obligation(
        "SEP-S-ASSIGNMENTS",
        "the only instructions in N that assign the stack pointer rather "
        "than adjusting it by a constant are the two TXS at $8009 and $F3BA",
        "enumeration of stack-pointer writers", "proved",
        solver="exhaustive execution of the CPU model, one node at a time",
        detail={
            "scope": MODEL_SCOPE,
            "method": "an instruction is an assignment when S' - S is not the "
                      "same constant on every successor, decided from "
                      "cpu.step on an unconstrained state",
            "assignments": {
                f"0x{pc:04X}": str(ctx.graph.nodes[pc].instruction)
                for pc in assigns},
            "note": "TAS and LAS also assign S; neither encoding occurs in N, "
                    "which this enumeration confirms rather than assumes",
        }))


def stack_side(ledger: Ledger, ctx: Context, worst_data: int | None) -> dict:
    """`SEP-DEPTH` and the facts it is built from."""
    deltas, assigns = stack_deltas(ctx)
    dead = dead_nodes(ledger, ctx)
    pointer_sites(ledger, ctx, assigns)
    engine = engine_effect(ctx)
    live_assigns = frozenset(assigns) - dead - {RESET_TXS}

    entries = routine_entries(ctx)
    graph = {entry: callees(ctx, entry, dead) for entry in entries}
    loops = cycles(graph)
    recursive = frozenset(a for component in loops for a in component)
    witnesses = [[f"0x{a:04X}" for a in component] for component in loops]
    ledger.add(Obligation(
        "SEP-RECURSION",
        "the call graph of N is acyclic",
        "precondition a stack-depth bound would otherwise need",
        "proved" if not loops else "refuted", solver="graph inspection",
        detail={
            "routine_entries": len(entries),
            "cycles": witnesses,
            "how": "a JSR $8E04 is a tail call: the JumpEngine pops the "
                   "dispatcher's frame, so a routine can reach itself "
                   "through its own dispatch table.  The cycles listed here "
                   "are real rather than an artefact of merging call and "
                   "dispatch edges, and the dispatch edges they use are the "
                   "ones the D-*-CONTRACT lemmas are about",
            "consequence": "the depth bound is a function of how deep that "
                           "recursion goes; see SEP-DEPTH",
        }))

    nmi_entry = ctx.read(0xFFFA) | ctx.read(0xFFFB) << 8
    interrupt_frame = _interrupt_frame(ctx)

    def total(limit: int):
        analysis = Depth(ctx, deltas, live_assigns, recursive, limit, dead)
        main = analysis.cost(RESET_ENTRY)
        handler = analysis.cost(nmi_entry)
        if main is None or handler is None:
            return None, analysis
        return main + interrupt_frame + handler, analysis

    base, plain = total(1)
    margin = (None if (worst_data is None or base is None)
              else 0xFF - base - worst_data)
    # How much recursion can the margin absorb?  Growing the limit only ever
    # deepens the stack, so the largest admissible limit is found by search.
    limit, admissible, analysis = 1, base, plain
    if base is not None and worst_data is not None:
        low, high = 1, 256
        while low < high:
            middle = (low + high + 1) // 2
            value, _ = total(middle)
            if value is not None and 0xFF - value >= worst_data:
                low = middle
            else:
                high = middle - 1
        limit = low
        admissible, analysis = total(limit)

    profile = {}
    for probe in (1, 2, 4, 8, 16, 32):
        value, _ = total(probe)
        profile[probe] = value

    status = "conditional" if admissible is not None else "unknown"
    cyclic = ", ".join(f"${a:04X}" for a in sorted(recursive)) or "none"
    recursion_assumption = (
        f"A-RECURSION: at most {limit} nested activations of each routine on "
        f"a call-graph cycle ({cyclic}); see SEP-RECURSION")
    assumptions = list(SLICE_ASSUMPTIONS) + [
        IRQ_ASSUMPTION, NMI_SINGLE, RESET_PROLOGUE, recursion_assumption,
        FRAMES]
    ledger.add(Obligation(
        "SEP-DEPTH",
        f"with at most {limit} nested activations of {cyclic} the stack "
        f"pointer never falls below ${0xFF - admissible:02X}, so no push "
        f"writes below offset ${0xFF - admissible + 1:02X} (with none, never "
        f"below ${0xFF - base:02X})"
        if admissible is not None else
        "the stack pointer has a lower bound",
        "stack half of the separation statement", status, assumptions,
        dependencies=["SEP-TXS-8009", "SEP-S-ASSIGNMENTS", "SEP-DEAD-F3B1"],
        solver="abstract interpretation over the call graph, with the "
               "per-instruction stack deltas taken from the CPU model",
        detail={
            "scope": MODEL_SCOPE,
            "maximum_bytes_below_the_base": admissible,
            "lowest_stack_pointer": None if admissible is None
            else f"0x{0xFF - admissible:02X}",
            "composition": {
                "reset_path": analysis.cost(RESET_ENTRY),
                "interrupt_frame": interrupt_frame,
                "nmi_handler": analysis.cost(nmi_entry),
                "why_a_sum": "an NMI may be taken at any boundary of the "
                             "reset path, so the handler's own depth sits on "
                             "top of the deepest point of that path; "
                             "A-NMI-SINGLE is what stops this from recurring",
            },
            "recursion_limit_used": limit,
            "how_the_limit_was_chosen": "the largest value for which the "
                                        "separation margin is still "
                                        "non-negative, found by bisection; a "
                                        "larger limit only ever deepens the "
                                        "stack",
            "depth_without_recursion": base,
            "lowest_stack_pointer_without_recursion":
                None if base is None else f"0x{0xFF - base:02X}",
            "depth_by_recursion_limit": {str(k): v
                                         for k, v in profile.items()},
            "margin_without_recursion": margin,
            "jumpengine": engine,
            "return_visits_examined": analysis.returns,
            "distinct_returns_examined": len(analysis.seen_returns),
            "returns_at_a_nonzero_local_depth": analysis.unbalanced,
            "deepest_chain_without_recursion": plain.chain(nmi_entry),
            "deepest_chain_at_the_limit": analysis.chain(nmi_entry),
            "deepest_chain_from_reset": plain.chain(RESET_ENTRY),
            "routines_analysed": len(graph),
            "notes": sorted(set(analysis.notes)),
            "recursion_cuts": len(analysis.cut),
            "observed_for_comparison": "dyn_observations.json records the "
                                       "stack pointer staying in $E6-$FF, a "
                                       "drop of 25, over the traced inputs; "
                                       "that is evidence, not a bound",
        }))
    ledger.add(Obligation(
        "SEP-RETURNS-BALANCED",
        "every RTS and RTI the abstract interpretation reaches consumes "
        "exactly the frame its routine was entered with",
        "structural support for J-STACK-FRAMES",
        "conditional" if not analysis.unbalanced else "refuted",
        assumptions, dependencies=["SEP-RECURSION"],
        solver="abstract interpretation over the call graph",
        detail={
            "scope": MODEL_SCOPE,
            "return_visits_examined": analysis.returns,
            "distinct_returns_examined": len(analysis.seen_returns),
            "returns_in_N": sum(
                1 for n in ctx.graph.nodes.values()
                if n.instruction.info.flow is Flow.RETURN),
            "unbalanced": analysis.unbalanced,
            "what_this_is_not": "a shadow-stack invariant.  It says the "
                                "push/pull counts along every graph path "
                                "balance, not that the bytes pulled are the "
                                "bytes pushed; that is J-STACK-FRAMES and it "
                                "is what the data side has to protect",
        }))
    reset_drift(ledger, ctx, worst_data)
    return {"depth": admissible, "limit": limit, "profile": profile,
            "lowest_pointer": None if admissible is None else 0xFF - admissible,
            "depth_without_recursion": base,
            "lowest_pointer_without_recursion":
                None if base is None else 0xFF - base,
            "margin_without_recursion": margin,
            "unbalanced": analysis.unbalanced}


def _interrupt_frame(ctx: Context) -> int:
    """How many bytes an interrupt entry pushes, from the model."""
    state = havoc_state(RESET_ENTRY, ctx.prg)
    entered = cpu.enter_interrupt(state, cpu.NMI_VECTOR)
    value = as_int(z3.simplify(state.s - entered.s))
    return value if value is not None else 3


def reset_drift(ledger: Ledger, ctx: Context,
                worst_data: int | None = None) -> None:
    """Why A-RESET-PROLOGUE is needed: reset lowers S without writing.

    `cpu.reset` drops the pointer by three with no write, which is what the
    hardware's three dummy stack reads do.  Reset is available at every
    instruction boundary, and an NMI taken at the reset vector's first
    boundary pushes its frame at the lowered pointer, so the pair can be
    repeated and the pointer walks down three bytes at a time.  The claim
    "one reset followed by an NMI entry leaves the pointer no lower" is
    refuted here, with the model's own numbers.
    """
    state = havoc_state(RESET_ENTRY, ctx.prg)
    after_reset = cpu.reset(state)
    entered = cpu.enter_interrupt(after_reset, cpu.NMI_VECTOR)
    returned = entered
    for _ in range(3):                      # the handler's RTI pulls three
        _value, returned = cpu.pull(returned)
    lowest = entered.mem.writes[-1][0]      # the status byte, pushed last
    # Neither query mentions an image byte -- they are arithmetic on `S` and
    # on the addresses the pushes computed -- so both are saved as plain
    # `.smt2` and can be read by anyone without the image.
    no_drift = check_valid("SEP-RESET-NO-DRIFT", returned.s == state.s)
    rate = check_valid("SEP-RESET-DRIFT-RATE",
                       z3.And(returned.s == state.s - 3,
                              offset(lowest) == state.s - 5))
    ledger.record(
        "SEP-RESET-NO-DRIFT",
        "a reset followed by an NMI entry and the handler's three pulls "
        "leaves the stack pointer no lower than it was",
        "soundness check on A-RESET-PROLOGUE", no_drift,
        detail={"scope": MODEL_SCOPE,
                "expected": "refuted; this is a negative test",
                "consequence": "the pair lowers S by three without passing "
                               "through the TXS at $8009, so repeating it "
                               + (f"{-((worst_data - 0xFF) // 3)} times puts "
                                  f"a push at or below offset "
                                  f"${worst_data:02X}, the highest offset the "
                                  "data side bounds"
                                  if worst_data is not None else
                                  "walks the pointer down without bound")
                               + ", which is why the depth bound carries "
                                 "A-RESET-PROLOGUE",
                "writes_during_reset": "none; cpu.reset performs the three "
                                       "dummy stack reads as a bare "
                                       "decrement"})
    ledger.record(
        "SEP-RESET-DRIFT-RATE",
        "that pair lowers the stack pointer by exactly three and pushes its "
        "lowest byte at offset S - 5",
        "the rate the drift accumulates at", rate,
        detail={"scope": MODEL_SCOPE})


# ---------------------------------------------------------------------------
# A + B
# ---------------------------------------------------------------------------

def _margin_note(stack: dict) -> str:
    """Why the headline margin is the number it is."""
    plain = stack.get("lowest_pointer_without_recursion")
    slack = stack.get("margin_without_recursion")
    if plain is None or slack is None:
        return ("SEP-DEPTH's recursion limit is chosen as the largest the "
                "margin absorbs, so the margin here is where that search "
                "stopped rather than a tight squeeze")
    return ("SEP-DEPTH's recursion limit is chosen as the largest the margin "
            "absorbs, so a margin of zero here is where that search stopped "
            "rather than a tight squeeze.  With one activation of the "
            f"recursive routine the pointer stops at offset 0x01{plain:02X} "
            f"and the margin is {slack} bytes")


def combined(ledger: Ledger, data: dict, stack: dict) -> dict:
    worst, floor = data["worst_offset"], stack["lowest_pointer"]
    holds = (worst is not None and floor is not None and not data["open"]
             and worst <= floor)
    if data["open"]:
        # An open writer with an abstract counterexample says the code does
        # not bound it locally; one that merely ran out of budget says
        # nothing.  The combined status takes the weaker of the two.
        status = ("unknown" if "unknown" in data.get("open_statuses", ())
                  else "abstract_counterexample")
    elif worst is None or floor is None or not holds:
        # Both halves are one-sided: `worst` is an upper bound on the data
        # offsets and `floor` a lower bound on the pointer, so an overlap
        # means neither half is tight enough, not that the program is wrong.
        # There is no witness here, so this is never `refuted`.
        status = "unknown"
    else:
        status = "conditional"
    assumptions = ledger.items["SEP-DEPTH"].assumptions + [
        a for a in ledger.items["SEP-DATA"].assumptions
        if a not in ledger.items["SEP-DEPTH"].assumptions]
    ledger.add(Obligation(
        "SEP-SEPARATION",
        "no instruction other than a push can modify a byte of page one at "
        "or above the live stack region",
        "return-frame separation", status,
        assumptions if status == "conditional" else [],
        dependencies=["SEP-DATA", "SEP-DEPTH"],
        detail={
            "scope": MODEL_SCOPE,
            "highest_data_offset": None if worst is None else f"0x01{worst:02X}",
            "lowest_stack_offset": None if floor is None
            else f"0x01{floor:02X}",
            "margin_in_bytes": None if (worst is None or floor is None)
            else floor - worst,
            "why_the_margin_is_what_it_is": _margin_note(stack),
            "open_writers": data["open"],
            "what_would_close_it": None if status == "conditional" else (
                "the writers listed in SEP-DATA; each one's SEP-W-* record "
                "says what its index or pointer is not bounded by"
                if data["open"] else
                "a tighter bound on one of the two halves: both are "
                "one-sided, so an overlap is a gap in the method rather "
                "than a fault in the program, and no witness is claimed"),
            "joint_induction": "SEP-DATA assumes J-LOCATION, which is P1's "
                               "own certificate, and SEP-DEPTH assumes "
                               "J-STACK-FRAMES, which is what separation is "
                               "for.  Phi := (frames intact) and ($FF - S <= "
                               "D) is the candidate joint invariant and these "
                               "two are its preservation steps; discharging "
                               "them as one mechanised induction is not done "
                               "here and is what LOC-RETURN still needs",
            "relation_to_STACK-PAGE-STORES": "that obligation asks for "
                                             "something the traces in "
                                             "dyn_observations.json already "
                                             "contradict.  This is the "
                                             "weakest statement in its place "
                                             "that still gives frame "
                                             "integrity",
        }))
    return {"status": status, "highest_data_offset": worst,
            "lowest_stack_offset": floor,
            "margin": None if (worst is None or floor is None)
            else floor - worst,
            "recursion_limit": stack.get("limit"),
            "lowest_stack_offset_without_recursion":
                stack.get("lowest_pointer_without_recursion"),
            "margin_without_recursion": stack.get("margin_without_recursion")}


def run(ledger: Ledger, ctx: Context) -> None:
    data = data_side(ledger, ctx)
    stack = stack_side(ledger, ctx, data["worst_offset"])
    verdict = combined(ledger, data, stack)
    report = {
        "rom_sha1": ctx.sha1,
        "statement": "every byte a non-push instruction writes into RAM page "
                     "one lies strictly below every byte a push has written "
                     "and not yet released",
        "verdict": verdict,
        "data_side": data,
        "stack_side": stack,
        "obligations": {key: ledger.items[key].status
                        for key in sorted(ledger.items)
                        if key.startswith("SEP-")},
    }
    os.makedirs(os.path.dirname(REPORT), exist_ok=True)
    with open(REPORT, "w") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
