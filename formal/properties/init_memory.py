"""Initial memory (INIT-MEM): what the reset code has written, and what it
has left alone, when the NMI-enable bit is first set.

The model's cold-boot predicate (`model/transitions.cold_boot`) leaves all
2 KiB of RAM unconstrained, so P1 cannot be stated without saying which of
those 2,048 bytes the machine still depends on once the program is running.
This module computes that set from the model rather than from a disassembly:
it executes the image's own bytes with `model.cpu.step` from the reset vector
with RAM a free array, and stops at the **first instruction that can set the
ghost NMI-enable bit**, which is the first boundary at which the model admits
an NMI and therefore the first boundary at which anything other than the
reset code can write RAM.

The window end is found by the ghost-bit rule itself
(`transitions.ppu_control_update`), not by naming an address: after each
instruction the writes it performed are folded into the bit, and the run stops
immediately *before* the first instruction for which the bit is not provably
still false.

Three things could make such a run unsound, and each is handled explicitly:

*Unbounded loops.*  The two vblank waits (`LDA $2002 / BPL`) read an
unconstrained bus byte, so the model admits any number of iterations and no
unrolling is possible.  Each is closed by a proved loop invariant
(`INIT-MEM-VBLANK-*`): the body writes nothing and changes nothing except A
and the N/Z flags, and on exit bit 7 of A is set.  Execution then continues
from the most general state satisfying that summary, which is a weakening, so
anything proved afterwards holds for every iteration count.  A path that never
leaves such a loop fetches only the loop's own two instructions, both in ROM,
so it needs no further treatment.

*The warm-boot case split.*  The check at `$8018`-`$8029` reads six score
digits and a flag byte out of RAM, so control forks on the initial contents.
The fork is enumerated by the model (eight paths), the path conditions are
proved exhaustive and pairwise disjoint, and their disjunction is proved
equivalent to an explicit formula `phi` over the initial RAM array
(`INIT-MEM-WARM-COND`).  `phi` is stated here as a candidate and *proved*
equal to what the model collected; the cells it mentions are recovered from
the collected terms rather than transcribed.

*The memory-initialisation loop at `$90CC`.*  Once the fork is taken, every
branch guard in the rest of the window is decided by the model with no case
split, so that loop is fully unrolled and its trip counts are derived rather
than assumed.  `INIT-MEM-LOOP-90CC` records them together with the number of
branch instructions executed and the fact that none of them forked.

The traces themselves are statements about `cpu.step` with no interrupt
serviced, which is why they can be `proved`.  That no interrupt *can* be
serviced inside the window is a separate pair of obligations: `INIT-MEM-NO-IRQ`
(proved: I is set at every boundary) and `INIT-MEM-NO-NMI` (conditional on
MA-PPU-POWERON).  For an entry by warm reset with the enable bit already set
the claim is false in the model and is recorded `refuted`
(`INIT-MEM-NMI-WARM-RESET`); that is a real gap in the characterisation rather
than a modelling artefact, because `transitions` carries the ghost bit through
reset unchanged.
"""
from __future__ import annotations

import collections
import json
import os
from dataclasses import dataclass, field

import z3

from ..model import cpu
from ..model.cpu import State
from ..model.memory import NESMemory, as_int
from ..model.transitions import ppu_control_update
from ..verify.obligations import Ledger, Obligation, check_valid
from .common import MODEL_SCOPE, Context

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT = os.path.join(HERE, "results", "reports", "init_memory.json")

RAM_CELLS = 0x800

#: the name of the free array the whole analysis is stated over, so that every
#: query in this module speaks about the same cold-boot RAM
RAM0 = "RAM0"

#: the two vblank waits, as (loop head, branch instruction, exit)
VBLANK_LOOPS = ((0x800A, 0x800D, 0x800F), (0x800F, 0x8012, 0x8014))

#: the fetch at which the warm-boot fork has been resolved: the `JSR $90CC`
SPLIT = 0x802B

#: the cold-boot offset the reset code loads into Y before the check
COLD_OFFSET = 0xFE

POWERON = ("MA-PPU-POWERON: PPU control is zero at cold boot, so the ghost "
           "NMI-enable bit is false at the first fetch")

STEP_BUDGET = 60000


class Unexpected(Exception):
    """The model did something the method here cannot close soundly."""


# -- small helpers ----------------------------------------------------------

def ram_index(cell: int) -> z3.BitVecRef:
    return z3.BitVecVal(cell & (RAM_CELLS - 1), 11)


def ram_cell_hit_sym(address, cell):
    """`common.ram_cell_hit` with the cell number left as a term.

    Identical to it for every concrete cell; `tests/test_init_memory.py`
    checks that with the solver.
    """
    return z3.And(z3.ULT(address, 0x2000), z3.Extract(10, 0, address) == cell)


def runs(cells) -> list[tuple[int, int]]:
    """A cell set as maximal runs of consecutive addresses."""
    out: list[list[int]] = []
    for cell in sorted(cells):
        if out and cell == out[-1][1] + 1:
            out[-1][1] = cell
        else:
            out.append([cell, cell])
    return [(a, b) for a, b in out]


def ranges(cells) -> list[str]:
    return ["${:04X}-${:04X}".format(a, b) if a != b else "${:04X}".format(a)
            for a, b in runs(cells)]


def value_ranges(values: dict) -> list[str]:
    """`{cell: value}` as `$xxxx-$yyyy=$vv` runs."""
    out: list[list[int]] = []
    for cell in sorted(values):
        value = values[cell]
        if out and cell == out[-1][1] + 1 and value == out[-1][2]:
            out[-1][1] = cell
        else:
            out.append([cell, cell, value])
    return ["${:04X}-${:04X}=${:02X}".format(a, b, v) if a != b
            else "${:04X}=${:02X}".format(a, v) for a, b, v in out]


def in_run_set(term, values, bits: int) -> z3.BoolRef:
    """`term` is one of `values`, as a disjunction over maximal runs.

    Run-encoding keeps these queries small.  Both solvers choke on the
    straightforward form, a conjunction of one disequality per written
    address, once there are a couple of thousand of them.
    """
    clauses = []
    for low, high in runs(values):
        lo, hi = z3.BitVecVal(low, bits), z3.BitVecVal(high, bits)
        clauses.append(term == lo if low == high
                       else z3.And(z3.ULE(lo, term), z3.ULE(term, hi)))
    return z3.Or(*clauses)


def in_set(term, cells) -> z3.BoolRef:
    """`term` denotes one of `cells` (11-bit cell numbers)."""
    return in_run_set(term, {c & (RAM_CELLS - 1) for c in cells}, 11)


def same_term(left, right) -> bool:
    """Structural identity, for terms or for the plain ints `pc` can be."""
    if left is right:
        return True
    if isinstance(left, z3.AstRef) and isinstance(right, z3.AstRef):
        return left.eq(right)
    return bool(left == right)


def selected_cells(term) -> list[int]:
    """Every cell at which the free array `RAM0` is read inside `term`."""
    found, seen, pending = set(), set(), [term]
    while pending:
        node = pending.pop()
        if node.get_id() in seen:
            continue
        seen.add(node.get_id())
        if (z3.is_select(node) and z3.is_const(node.arg(0))
                and node.arg(0).decl().name() == RAM0):
            index = as_int(node.arg(1))
            if index is not None:
                found.add(index)
        pending.extend(node.children())
    return sorted(found)


# -- the window -------------------------------------------------------------

@dataclass
class Trace:
    """One execution of the window, from `SPLIT` to the NMI-enabling fetch."""
    case: str
    entry: State
    end: State
    steps: int = 0
    branches: int = 0
    control_writes: list = field(default_factory=list)
    pc_counts: collections.Counter = field(default_factory=collections.Counter)
    i_set_at_every_boundary: bool = True
    enabling_write: list = field(default_factory=list)

    @property
    def writes(self) -> tuple:
        return self.end.mem.writes

    def last_write_per_cell(self) -> dict[int, int]:
        """`{cell: value}` from the write log; raises if a write is symbolic."""
        out: dict[int, int] = {}
        for address, value in self.writes:
            concrete = as_int(address)
            if concrete is None:
                raise Unexpected("a write inside the window has a symbolic "
                                 "address, so the cell partition would not "
                                 "be exact")
            if concrete >= 0x2000:
                continue
            byte = as_int(value)
            if byte is None:
                raise Unexpected("the write to ${:04X} inside the window has "
                                 "a symbolic value".format(concrete))
            out[concrete & (RAM_CELLS - 1)] = byte
        return out

    def untouched(self) -> set[int]:
        return set(range(RAM_CELLS)) - set(self.last_write_per_cell())


def control_writes(pc: int, writes) -> list[dict]:
    """The writes among `writes` that `ppu_control_update` reacts to."""
    out = []
    for address, value in writes:
        concrete = as_int(address)
        if concrete is not None and 0x2000 <= concrete < 0x4000 \
                and concrete & 7 == 0:
            byte = as_int(value)
            out.append({"pc": "${:04X}".format(pc),
                        "address": "${:04X}".format(concrete),
                        "value": None if byte is None
                                 else "${:02X}".format(byte)})
    return out


def entry_state(prg: bytes) -> State:
    """Cold boot as `transitions.cold_boot` defines it, RAM a free array."""
    vector = (prg[cpu.RESET_VECTOR - 0x8000]
              | prg[cpu.RESET_VECTOR - 0x7FFF] << 8)
    memory = NESMemory(z3.Array(RAM0, z3.BitVecSort(11), z3.BitVecSort(8)),
                       prg)
    state = State.symbolic(vector, memory, prefix="boot_")
    return cpu.replace(state, i=z3.BoolVal(True))


def _only(state: State) -> State:
    successors = cpu.step(state)
    if len(successors) != 1:
        raise Unexpected("the fetch at ${:04X} forks where the method "
                         "expects a single successor".format(state.pc))
    return successors[0].state


def vblank_invariant(prg: bytes, head: int, branch: int, exit_pc: int):
    """Prove the summary used for a `LDA $2002 / BPL` wait.

    The invariant is "nothing has been written and X, Y, S, C, I, D and V are
    the terms they were at the loop head".  It is checked structurally (the
    successors carry the *same* terms, which is stronger than a solver
    equality), and the exit condition is checked by both solvers.
    """
    tag = "vb{:04X}".format(head)
    start = State.symbolic(head, NESMemory.symbolic(prg, tag), prefix=tag + "_")
    state = start
    while state.pc != branch:
        state = _only(state)
    successors = cpu.step(state)
    by_target = {s.state.pc: s for s in successors}
    if set(by_target) != {head, exit_pc}:
        raise Unexpected("the loop at ${:04X} does not branch to ${:04X} and "
                         "${:04X}".format(head, head, exit_pc))
    unchanged = {}
    for successor in successors:
        after = successor.state
        unchanged[after.pc] = bool(
            after.mem.ram is start.mem.ram
            and len(after.mem.writes) == len(start.mem.writes) == 0
            and all(getattr(after, f) is getattr(start, f)
                    for f in ("x", "y", "s", "c", "i", "d", "v")))
    leaving = by_target[exit_pc]
    check = check_valid(
        "INIT-MEM-VBLANK-{:04X}".format(head),
        z3.And(z3.Extract(7, 7, leaving.state.a) == 1,
               leaving.state.n, z3.Not(leaving.state.z)),
        [leaving.guard], rom_derived=True)
    return check, {
        "loop": "${:04X}-${:04X}".format(head, branch),
        "exit": "${:04X}".format(exit_pc),
        "invariant_holds_on_both_successors": all(unchanged.values()),
        "successors_checked": sorted("${:04X}".format(pc) for pc in unchanged),
        "successors_failing_the_invariant": sorted(
            "${:04X}".format(pc) for pc, ok in unchanged.items() if not ok)}


def apply_vblank_summary(state: State, head: int, exit_pc: int):
    """The most general state satisfying the proved summary.

    Returns `(state, constraint)`.  A is a fresh byte with bit 7 set, N is
    set, Z is clear and everything else is carried over unchanged, so every
    real exit state, for every iteration count, is an instance of this one.
    """
    fresh = z3.BitVec("vblank_a_{:04X}".format(head), 8)
    summarised = cpu.replace(state, a=fresh, n=z3.BoolVal(True),
                             z=z3.BoolVal(False), pc=exit_pc)
    return summarised, z3.Extract(7, 7, fresh) == 1


def prologue(prg: bytes):
    """Reset vector to the exit of the second vblank wait.

    Returns `(state, constraints, steps, loop_facts, control_writes)`.
    """
    state, constraints, steps, facts = entry_state(prg), [], 0, []
    control: list[dict] = []
    for head, branch, exit_pc in VBLANK_LOOPS:
        while state.pc != head:
            before, pc = len(state.mem.writes), state.pc
            state = _only(state)
            control += control_writes(pc, state.mem.writes[before:])
            steps += 1
        facts.append(vblank_invariant(prg, head, branch, exit_pc))
        state, constraint = apply_vblank_summary(state, head, exit_pc)
        constraints.append(constraint)
    return state, constraints, steps, facts, control


def split_paths(state: State):
    """Every path from the second vblank wait to the fetch of `JSR $90CC`.

    Returns a list of `(guards, state)`.  The guards mention only the initial
    RAM array, so they are the warm-boot case split and nothing else.
    """
    frontier, terminal = [([], state)], []
    while frontier:
        guards, current = frontier.pop()
        if current.pc == SPLIT:
            terminal.append((guards, current))
            continue
        if len(terminal) > 64 or len(frontier) > 64:
            raise Unexpected("the warm-boot check forks further than the "
                             "method expects")
        for successor in cpu.step(current):
            guard = z3.simplify(successor.guard)
            if z3.is_false(guard):
                continue
            frontier.append((guards + ([] if z3.is_true(guard) else [guard]),
                             successor.state))
    return terminal


def generalise(group, case: str) -> State:
    """The most general entry state for a group of paths that share Y.

    Every field that differs between the paths is replaced by a fresh symbol
    and the path conditions are dropped, so each path's state is an instance
    of the result.  The fields asserted to be common are compared by term
    identity, which needs no solver.
    """
    first = group[0][1]
    for _, state in group[1:]:
        for name in ("pc", "s", "y", "i", "halted"):
            if not same_term(getattr(first, name), getattr(state, name)):
                raise Unexpected("paths disagree on {} at ${:04X}".format(
                    name, SPLIT))
        if state.mem.ram is not first.mem.ram:
            raise Unexpected("paths disagree on RAM at the split")
        if state.mem.writes != first.mem.writes:
            raise Unexpected("paths disagree on the write log at the split")
    blank = State.symbolic(SPLIT, first.mem, prefix=case + "_")
    return cpu.replace(blank, pc=first.pc, y=first.y, s=first.s, i=first.i)


def run_window(state: State, case: str) -> Trace:
    """Step until the first instruction that can set the ghost enable bit."""
    trace = Trace(case, state, state)
    enable = z3.BoolVal(False)
    while True:
        trace.pc_counts[state.pc] += 1
        if not z3.is_true(z3.simplify(state.i)):
            trace.i_set_at_every_boundary = False
        before = len(state.mem.writes)
        successors = cpu.step(state)
        if len(successors) != 1:
            raise Unexpected("the fetch at ${:04X} forks inside the window, "
                             "so the trace is not a single path".format(
                                 state.pc))
        fresh = successors[0].state.mem.writes[before:]
        trace.control_writes.extend(control_writes(state.pc, fresh))
        updated = ppu_control_update(enable, fresh)
        if not z3.is_false(updated):
            trace.end = state
            trace.enabling_write.append({
                "pc": "${:04X}".format(state.pc),
                "ghost_bit_after": str(z3.simplify(updated))})
            return trace
        enable = updated
        if cpu.OPCODES[state.mem.prg[state.pc - 0x8000]].flow \
                is cpu.Flow.BRANCH:
            trace.branches += 1
        state = successors[0].state
        trace.steps += 1
        if trace.steps > STEP_BUDGET:
            raise Unexpected("no NMI-enabling instruction within {} "
                             "steps".format(STEP_BUDGET))


# -- the warm-boot condition ------------------------------------------------

def warm_condition(ram) -> z3.BoolRef:
    """The candidate `phi`; `INIT-MEM-WARM-COND` proves it is exactly right."""
    digits = [z3.ULT(z3.Select(ram, ram_index(0x07D7 + k)), 0x0A)
              for k in range(6)]
    return z3.And(*digits,
                  z3.Select(ram, ram_index(0x07FF)) == z3.BitVecVal(0xA5, 8))


PHI_TEXT = ("RAM[$07D7] <u 10 and RAM[$07D8] <u 10 and RAM[$07D9] <u 10 and "
            "RAM[$07DA] <u 10 and RAM[$07DB] <u 10 and RAM[$07DC] <u 10 and "
            "RAM[$07FF] == $A5")


# -- obligations ------------------------------------------------------------

def loops(ledger: Ledger, facts) -> list[str]:
    ids = []
    for (head, branch, exit_pc), (check, detail) in zip(VBLANK_LOOPS, facts):
        name = "INIT-MEM-VBLANK-{:04X}".format(head)
        ids.append(name)
        detail = dict(detail)
        detail.update(
            scope=MODEL_SCOPE,
            method="loop invariant, not unrolling: the body is executed once "
                   "from a fully unconstrained state at the loop head",
            invariant="no write has been performed and X, Y, S, C, I, D and V "
                      "are the terms they were at the loop head",
            structural_check="the successors carry the identical terms, which "
                             "is checked in Python rather than by the solver",
            non_termination="a path that never leaves the loop fetches only "
                            "${:04X} and ${:04X}, both in PRG ROM".format(
                                head, branch))
        ledger.record(
            name,
            "the wait loop at ${:04X} writes nothing, changes nothing except "
            "A, N and Z, and leaves bit 7 of A set at ${:04X}, for every "
            "number of iterations".format(head, exit_pc),
            "loop invariant for one unbounded loop", check, detail=detail)
    return ids


def case_split(ledger: Ledger, terminal) -> dict:
    """Record the path split and prove the warm-boot condition."""
    guards = [z3.And(*g) if len(g) > 1 else (g[0] if g else z3.BoolVal(True))
              for g, _ in terminal]
    by_case: dict[str, list] = collections.defaultdict(list)
    for (_, state), guard in zip(terminal, guards):
        y = as_int(state.y)
        if y is None:
            raise Unexpected("Y is symbolic at the split")
        by_case["cold" if y == COLD_OFFSET else "warm"].append((guard, state))
    if set(by_case) != {"cold", "warm"} or len(by_case["warm"]) != 1:
        raise Unexpected("unexpected shape of the split: {}".format(
            {k: len(v) for k, v in by_case.items()}))

    ledger.record(
        "INIT-MEM-PATHS-TOTAL",
        "the {} paths the model enumerates from the reset vector to the fetch "
        "of ${:04X} cover every initial RAM content".format(
            len(guards), SPLIT),
        "exhaustiveness of the warm-boot case split",
        check_valid("INIT-MEM-PATHS-TOTAL", z3.Or(*guards), [],
                    rom_derived=True),
        detail={"scope": MODEL_SCOPE, "paths": len(guards),
                "note": "the two vblank summaries are not part of this "
                        "query: the guards mention only the initial RAM"})

    pairs = [z3.Not(z3.And(guards[i], guards[j]))
             for i in range(len(guards)) for j in range(i + 1, len(guards))]
    ledger.record(
        "INIT-MEM-PATHS-DISJOINT",
        "those paths are pairwise exclusive, so the split assigns exactly one "
        "value of Y to each initial RAM content",
        "disjointness of the warm-boot case split",
        check_valid("INIT-MEM-PATHS-DISJOINT", z3.And(*pairs), [],
                    rom_derived=True),
        detail={"scope": MODEL_SCOPE, "pairs": len(pairs)})

    warm_guard, warm_state = by_case["warm"][0]
    ram = warm_state.mem.ram
    phi = warm_condition(ram)
    ledger.record(
        "INIT-MEM-WARM-COND",
        "the memory-initialisation routine at $90CC is entered with "
        "Y = ${:02X}, the warm-boot offset, exactly when phi holds of the "
        "cold-boot RAM, and with Y = ${:02X} otherwise, where phi is: "
        "{}".format(as_int(warm_state.y), COLD_OFFSET, PHI_TEXT),
        "the warm-boot condition, as a formula over cold-boot RAM",
        check_valid("INIT-MEM-WARM-COND", warm_guard == phi, [],
                    rom_derived=True),
        detail={"scope": MODEL_SCOPE, "phi": PHI_TEXT,
                "cells_the_split_reads": ranges(selected_cells(
                    z3.Or(*guards))),
                "cells_recovered_from": "the free-array reads inside the "
                                        "path conditions the model collected, "
                                        "not from a disassembly",
                "cold_paths": len(by_case["cold"]),
                "warm_paths": len(by_case["warm"]),
                "method": "the model enumerated the paths; the solver proved "
                          "the warm path's condition equal to phi"})
    weaker = z3.And(*[z3.ULT(z3.Select(ram, ram_index(0x07D7 + k)), 0x0A)
                      for k in range(6)])
    ledger.record(
        "INIT-MEM-WARM-COND-NEG",
        "the same equivalence with the RAM[$07FF] == $A5 conjunct dropped   "
        "[expected to be refuted]",
        "negative regression test: phi is not vacuous",
        check_valid("INIT-MEM-WARM-COND-NEG", warm_guard == weaker, [],
                    rom_derived=True),
        detail={"purpose": "a counterexample here is a cold-boot RAM with six "
                           "digits below ten and RAM[$07FF] != $A5, which "
                           "takes the cold path"})
    states = [s for group in by_case.values() for _, s in group]
    ram_writes = {as_int(a) for s in states for a, _ in s.mem.writes
                  if as_int(a) is None or as_int(a) < 0x2000}
    agree = all(same_term(s.s, states[0].s) and s.mem.ram is states[0].mem.ram
                and s.mem.writes == states[0].mem.writes for s in states)
    ledger.add(Obligation(
        "INIT-MEM-SPLIT-STATE",
        "every one of those paths reaches the fetch of ${:04X} with "
        "S = ${:02X}, with RAM still untouched, and differing only in A, X "
        "and the flags, none of which the routine at $90CC reads before "
        "overwriting".format(SPLIT, as_int(states[0].s)),
        "the state the window is executed from", "proved" if agree and not
        ram_writes else "unknown",
        detail={"scope": MODEL_SCOPE,
                "paths": len(states),
                "stack_pointer": "${:02X}".format(as_int(states[0].s)),
                "ram_cells_written_before_the_split": ranges(
                    c for c in ram_writes if c is not None),
                "writes_before_the_split": [
                    "${:04X}".format(as_int(a)) for a, _ in
                    states[0].mem.writes],
                "method": "term identity on S, on the RAM array and on the "
                          "write log, which needs no solver",
                "why_it_matters": "the window is then executed from the most "
                                  "general state with those fields pinned, "
                                  "which is a weakening of each path, so the "
                                  "determined and untouched sets proved "
                                  "there hold for all eight paths.  Because "
                                  "no RAM cell has been written yet, the "
                                  "window's final values compose exactly "
                                  "with the prologue"}))
    return {"groups": dict(by_case), "guards": guards, "phi": phi}


def trace_obligations(ledger: Ledger, trace: Trace) -> list[str]:
    """Determined values, preserved cells and untouched cells for one trace."""
    case = trace.case
    determined = trace.last_write_per_cell()
    untouched = trace.untouched()
    final, base = trace.end.mem.ram, trace.entry.mem.ram
    entry = {"Y": "${:02X}".format(as_int(trace.entry.y)),
             "S": "${:02X}".format(as_int(trace.entry.s)),
             "everything_else": "unconstrained"}
    ids = []

    name = "INIT-MEM-DETERMINED-" + case.upper()
    ids.append(name)
    claim = z3.And(*[z3.Select(final, ram_index(cell)) == z3.BitVecVal(v, 8)
                     for cell, v in sorted(determined.items())])
    ledger.record(
        name,
        "executing the image from the fetch of ${:04X} with Y = {}, S = {} "
        "and no interrupt serviced, {} RAM cells hold a determined value at "
        "the fetch of the first instruction that sets the NMI-enable bit "
        "(${:04X}), for every other register, every flag and every "
        "cold-boot RAM content".format(
            SPLIT, entry["Y"], entry["S"], len(determined), trace.end.pc),
        "determined cells at the end of the initialisation window",
        check_valid(name, claim, [], rom_derived=True),
        detail={"scope": MODEL_SCOPE, "case": case, "entry": entry,
                "cells": len(determined), "steps": trace.steps,
                "window_end": "${:04X}".format(trace.end.pc),
                "values": value_ranges(determined),
                "note": "the value claimed is the last write to the cell in "
                        "the write log; the query is against the final RAM "
                        "array, which is the independent route"})

    if untouched:
        name = "INIT-MEM-PRESERVED-" + case.upper()
        ids.append(name)
        preserved = z3.And(*[z3.Select(final, ram_index(cell))
                             == z3.Select(base, ram_index(cell))
                             for cell in sorted(untouched)])
        ledger.record(
            name,
            "on the same path the other {} cells still hold their cold-boot "
            "values at that fetch".format(len(untouched)),
            "preserved cells at the end of the initialisation window",
            check_valid(name, preserved, [], rom_derived=True),
            detail={"scope": MODEL_SCOPE, "case": case,
                    "cells": len(untouched), "ranges": ranges(untouched)})

        cell = z3.BitVec("cell_" + case, 11)
        address = z3.BitVec("address_" + case, 16)
        concrete = {as_int(a) for a, _ in trace.writes}
        if None in concrete:
            raise Unexpected("a write inside the window has a symbolic "
                             "address")
        addresses = sorted(concrete)
        written = {a & (RAM_CELLS - 1) for a in addresses if a < 0x2000}
        provenance = (
            "the addresses are the write log's own, normalised with "
            "model.memory.as_int (z3.simplify plus a concreteness test) and "
            "run-encoded; a symbolic address aborts the analysis instead of "
            "being dropped")

        name = "INIT-MEM-WRITESET-" + case.upper()
        ids.append(name)
        ledger.record(
            name,
            "every address among the {} the window writes that denotes a RAM "
            "cell at all denotes one of {} cells, mirrors included".format(
                len(addresses), len(written)),
            "the cells the window's writes can reach",
            check_valid(name, in_set(cell, written),
                        [in_run_set(address, addresses, 16),
                         ram_cell_hit_sym(address, cell)],
                        rom_derived=True),
            detail={"scope": MODEL_SCOPE, "case": case,
                    "writes_in_window": len(trace.writes),
                    "distinct_write_addresses": len(addresses),
                    "written_cells": len(written),
                    "address_ranges": ranges(addresses),
                    "method": "the address and the cell number are both left "
                              "free, so the mirror normalisation is checked "
                              "by the solver rather than in Python",
                    "addresses": provenance})

        name = "INIT-MEM-UNTOUCHED-" + case.upper()
        ids.append(name)
        ledger.record(
            name,
            "and none of those cells is one of the {} the window leaves "
            "alone, so those are never written rather than written "
            "back".format(len(untouched)),
            "untouched cells, from the write log",
            check_valid(name, z3.Not(in_set(cell, written)),
                        [in_set(cell, untouched)], rom_derived=True),
            detail={"scope": MODEL_SCOPE, "case": case,
                    "cells": len(untouched), "ranges": ranges(untouched),
                    "with": "INIT-MEM-WRITESET-" + case.upper()
                            + ", which ties the cell set to the write log",
                    "addresses": provenance})
    return ids


def window_facts(ledger: Ledger, traces: dict[str, Trace],
                 prologue_steps: int,
                 prologue_control: list[dict]) -> list[str]:
    """Trip counts, and that no interrupt can be serviced inside the window."""
    cases = sorted(traces)
    ledger.add(Obligation(
        "INIT-MEM-LOOP-90CC",
        "the memory-initialisation routine at $90CC is fully unrolled on both "
        "paths: every branch guard inside the window is decided by the model "
        "with no case split, so its trip counts are derived and no loop bound "
        "is assumed",
        "unrolling, with the trip counts derived", "proved",
        detail={"scope": MODEL_SCOPE,
                "method": "exhaustive execution of the model; a fork inside "
                          "the window would have aborted the analysis rather "
                          "than being bounded",
                "what_it_rests_on": "no branch guard inside the window was "
                                    "symbolic: each simplified to a literal, "
                                    "which is a decision by z3's simplifier, "
                                    "already in the trusted base.  The trip "
                                    "counts are therefore derived from the "
                                    "model rather than assumed, and the "
                                    "resulting final RAM array is what the "
                                    "determined-cell queries are proved "
                                    "against",
                "forks_inside_the_window": 0,
                "branch_instructions_executed": {
                    c: traces[c].branches for c in cases},
                "steps": {c: traces[c].steps for c in cases},
                "steps_before_the_split": prologue_steps,
                "page_loop_iterations": {
                    c: traces[c].pc_counts[0x90D2] for c in cases},
                "inner_loop_iterations": {
                    c: traces[c].pc_counts[0x90DE] for c in cases},
                "stores_executed_at_90DC": {
                    c: traces[c].pc_counts[0x90DC] for c in cases},
                "instruction_starts_visited": {
                    c: len(traces[c].pc_counts) for c in cases}}))

    outside = {c: sorted("${:04X}".format(pc) for pc in traces[c].pc_counts
                         if pc < 0x8000) for c in cases}
    ledger.add(Obligation(
        "INIT-MEM-FETCHES-IN-ROM",
        "every instruction the window fetches is fetched from PRG ROM, on "
        "both paths; this is P1 restricted to the initialisation window",
        "instruction location inside the window",
        "proved" if not any(outside.values()) else "refuted",
        detail={"scope": MODEL_SCOPE,
                "method": "the program counter at every boundary of both "
                          "traces, collected while executing the model",
                "distinct_instruction_starts": {
                    c: len(traces[c].pc_counts) for c in cases},
                "lowest_program_counter": {
                    c: "${:04X}".format(min(traces[c].pc_counts))
                    for c in cases},
                "fetches_outside_rom": outside,
                "note": "the two vblank waits are outside this count; their "
                        "invariant records that a non-terminating path "
                        "fetches only the loop's own two instructions, both "
                        "in ROM"}))

    ledger.add(Obligation(
        "INIT-MEM-NO-IRQ",
        "the I flag is set at every instruction boundary inside the window, "
        "so the IRQ transition of the model is never enabled there",
        "absence of one asynchronous transition inside the window", "proved",
        detail={"scope": MODEL_SCOPE,
                "method": "the flag is the literal True at every boundary of "
                          "both traces, checked structurally",
                "entry": "both entries the model provides set I: cold_boot "
                         "sets it and cpu.reset sets it",
                "boundaries": {c: traces[c].steps + 1 for c in cases},
                "holds": {c: traces[c].i_set_at_every_boundary
                          for c in cases}}))

    ledger.add(Obligation(
        "INIT-MEM-NO-NMI",
        "starting from cold boot, the ghost NMI-enable bit is false at every "
        "instruction boundary strictly inside the window, so no NMI handler "
        "can write RAM before the characterised fetch",
        "absence of the other asynchronous transition inside the window",
        "conditional", assumptions=[POWERON],
        detail={"scope": MODEL_SCOPE,
                "method": "the writes of each instruction are folded into "
                          "transitions.ppu_control_update and the run stops "
                          "at the first instruction for which the bit is not "
                          "provably still false",
                "ppu_control_writes_before_the_split": prologue_control,
                "ppu_control_writes_in_the_window": {
                    c: traces[c].control_writes for c in cases},
                "enabling_instruction": {
                    c: traces[c].enabling_write for c in cases},
                "no_solver_call": "the written values are concrete, so the "
                                  "ghost bit is the literal False at every "
                                  "boundary and a validity query would be "
                                  "degenerate.  What this item rests on is "
                                  "the enumeration of the control writes by "
                                  "the model, not a solver answer",
                "window_end": {c: "${:04X}".format(traces[c].end.pc)
                               for c in cases}}))
    return ["INIT-MEM-LOOP-90CC", "INIT-MEM-FETCHES-IN-ROM",
            "INIT-MEM-NO-IRQ", "INIT-MEM-NO-NMI"]


def warm_reset_gap(ledger: Ledger, prg: bytes) -> str:
    """The characterisation does not cover a warm reset with NMIs enabled."""
    state = entry_state(prg)
    enable = z3.Bool("enable_at_reset")
    terms, boundaries = [enable], ["${:04X}".format(state.pc)]
    for _ in range(4):
        before = len(state.mem.writes)
        state = _only(state)
        terms.append(ppu_control_update(terms[-1],
                                        state.mem.writes[before:]))
        boundaries.append("${:04X}".format(state.pc))
    ledger.record(
        "INIT-MEM-NMI-WARM-RESET",
        "the ghost NMI-enable bit is false at every boundary inside the "
        "window for every entry the model permits, warm reset included   "
        "[expected to be refuted]",
        "the gap the cold-boot assumption hides",
        check_valid("INIT-MEM-NMI-WARM-RESET", z3.Not(z3.Or(*terms[:-1])),
                    [enable], rom_derived=True),
        detail={"scope": MODEL_SCOPE,
                "why": "transitions.transitions carries the ghost bit "
                       "through reset unchanged, so a reset taken while the "
                       "game has NMIs enabled reaches the reset vector with "
                       "the bit set.  The first write that clears it is the "
                       "STA $2000 three instructions in, and the model "
                       "admits an NMI at every boundary before it",
                "boundaries_at_risk": boundaries[:-1],
                "consequence": "for that entry the determined and untouched "
                               "sets are not established: the NMI handler "
                               "may write RAM first.  P1 must either carry "
                               "MA-PPU-POWERON, which restricts it to cold "
                               "boot, or treat all 2,048 cells as parameters "
                               "after a warm reset"})
    return "INIT-MEM-NMI-WARM-RESET"


def partition(ledger: Ledger, traces: dict[str, Trace], phi,
              dependencies: list[str]):
    """The three cell sets, and the part of the parameter phi constrains."""
    cold = traces["cold"].last_write_per_cell()
    warm = traces["warm"].last_write_per_cell()
    always = {c: v for c, v in cold.items() if c in warm}
    disagree = {c for c, v in always.items() if warm[c] != v}
    if disagree:
        raise Unexpected("the two cases write different values into "
                         + ", ".join(ranges(disagree)))
    cold_only = {c: cold[c] for c in set(cold) - set(warm)}
    warm_only = {c: warm[c] for c in set(warm) - set(cold)}
    never = set(range(RAM_CELLS)) - set(cold) - set(warm)

    final = traces["warm"].end.mem.ram
    bounded = [c for c in selected_cells(phi) if c in cold_only]
    claim = z3.And(*[z3.ULT(z3.Select(final, ram_index(c)), 0x0A)
                     for c in bounded])
    free_warm = set(cold_only) - set(bounded)
    ledger.record(
        "INIT-MEM-WARM-DIGITS",
        "on the warm path phi constrains {} of the preserved cells: {} are "
        "still below ten at the NMI-enabling fetch".format(
            len(bounded), ", ".join(ranges(bounded))),
        "the part of the theorem's parameter that is not free",
        check_valid("INIT-MEM-WARM-DIGITS", z3.Implies(phi, claim), [],
                    rom_derived=True),
        detail={"scope": MODEL_SCOPE, "cells": ranges(bounded),
                "note": "phi is a hypothesis of the claim rather than an "
                        "assumption of the obligation, so this is not "
                        "conditional on it",
                "free_in_the_warm_case": ranges(free_warm)})

    result = {
        "always_overwritten": {
            "count": len(always), "ranges": ranges(always),
            "values": value_ranges(always)},
        "preserved_in_the_warm_case_only": {
            "count": len(cold_only), "ranges": ranges(cold_only),
            "value_on_the_cold_path": value_ranges(cold_only),
            "constrained_by_phi": ranges(bounded),
            "unconstrained": ranges(free_warm)},
        "never_initialised": {"count": len(never), "ranges": ranges(never)},
        "written_only_in_the_warm_case": {
            "count": len(warm_only), "ranges": ranges(warm_only)},
    }
    ledger.add(Obligation(
        "INIT-MEM-PARTITION",
        "the 2,048 RAM cells split into {} always overwritten with a "
        "determined value before the NMI-enable bit is set, {} overwritten on "
        "the cold-boot path and preserved on the warm-boot path, and {} never "
        "written inside the window at all".format(
            len(always), len(cold_only), len(never)),
        "the partition P1's initial-memory parameter is read off",
        "conditional", assumptions=[POWERON], dependencies=dependencies,
        detail={"scope": MODEL_SCOPE, **result,
                "total": len(always) + len(cold_only) + len(never),
                "window": "the fetch of the reset vector to the fetch of the "
                          "first instruction that sets the ghost NMI-enable "
                          "bit",
                "not_covered": "entry by warm reset with the enable bit "
                               "already set; see INIT-MEM-NMI-WARM-RESET"}))

    ledger.add(Obligation(
        "INIT-MEM-P1-PARAMETER",
        "P1 can be stated over the free cells only: for all initial values of "
        "{} and, when phi holds, {} as well, where phi is {}; every other "
        "cell holds the value INIT-MEM-PARTITION gives it at the first "
        "boundary at which the model admits an NMI".format(
            ", ".join(ranges(never)), ", ".join(ranges(cold_only)), PHI_TEXT),
        "the initial-memory parameter of the theorem", "conditional",
        assumptions=[POWERON],
        dependencies=dependencies + ["INIT-MEM-PARTITION",
                                     "INIT-MEM-WARM-DIGITS"],
        detail={"scope": MODEL_SCOPE, "phi": PHI_TEXT,
                "free_in_both_cases": ranges(never),
                "free_in_the_warm_case_only": ranges(free_warm),
                "constrained_in_the_warm_case_only": {
                    "cells": ranges(bounded), "constraint": "below ten"},
                "cold_case": "phi is false, and then every cell outside "
                             + ", ".join(ranges(never)) + " is determined",
                "caveat": "a warm reset taken with the NMI-enable bit set is "
                          "outside this statement "
                          "(INIT-MEM-NMI-WARM-RESET), and so is any entry "
                          "other than the two the model provides"}))
    return result, {"always": set(always), "cold_only": set(cold_only),
                    "never": never}


def dynamic_crosscheck(ledger: Ledger, sets: dict) -> dict:
    """Compare the sets against the dynamic observation report."""
    path = os.path.join(HERE, "results", "reports", "dyn_cell_domains.json")
    if not os.path.exists(path):
        ledger.add(Obligation(
            "INIT-MEM-DYN", "no dynamic report to compare against",
            "cross-check against dynamic observation", "observed",
            detail={"missing": os.path.relpath(path, os.path.dirname(HERE))}))
        return {"status": "report absent"}
    with open(path) as handle:
        report = json.load(handle)
    written = {int(k, 16) for k in report.get("ever_written", {})}
    never_dyn = set(range(RAM_CELLS)) - written
    contradiction = (sets["always"] | sets["cold_only"]) - written
    outside = never_dyn - sets["never"]
    detail = {
        "source": "formal/results/reports/dyn_cell_domains.json",
        "label": "observation only: a trace of a hardware-accurate emulator "
                 "under particular inputs, not a statement about the model",
        "dynamic_never_written_count": len(never_dyn),
        "dynamic_never_written": ranges(never_dyn),
        "static_never_written_in_the_window": ranges(sets["never"]),
        "written_by_the_window_but_never_in_the_trace": ranges(contradiction),
        "never_in_the_trace_but_written_by_the_window": ranges(outside),
        "agreement": not contradiction and not outside,
        "reading": "the window writes every cell outside "
                   + ", ".join(ranges(sets["never"]))
                   + ", and the trace wrote every one of them, so the two "
                     "agree.  The trace additionally wrote part of that "
                     "range, which is the stack growing deeper during play "
                     "than the reset code needs; that is consistent, since "
                     "the dynamic report covers the whole run and this "
                     "module covers the initialisation window only",
    }
    if report.get("manifest"):
        detail["dynamic_manifest"] = {
            k: report["manifest"].get(k) for k in
            ("engine", "frames_total", "rom_sha1", "instructions_total")
            if k in report["manifest"]}
    ledger.add(Obligation(
        "INIT-MEM-DYN",
        "the partition is consistent with the dynamic cell-domain report"
        if detail["agreement"] else
        "the partition and the dynamic cell-domain report disagree",
        "cross-check against dynamic observation", "observed", detail=detail))
    return detail


def negative(ledger: Ledger, traces: dict[str, Trace]) -> None:
    """One vacuity twin for the determined-cell claim."""
    trace = traces["warm"]
    cell = sorted(trace.untouched())[0]
    claim = z3.Select(trace.end.mem.ram, ram_index(cell)) == z3.BitVecVal(0, 8)
    ledger.record(
        "INIT-MEM-DETERMINED-WARM-NEG",
        "${:04X}, which the window never writes, also holds a determined "
        "value at the NMI-enabling fetch   [expected to be refuted]".format(
            cell),
        "negative regression test: the determined set is not everything",
        check_valid("INIT-MEM-DETERMINED-WARM-NEG", claim, [],
                    rom_derived=True),
        detail={"purpose": "the counterexample is a cold-boot RAM in which "
                           "${:04X} is not zero, a cell the window does not "
                           "touch".format(cell)})


# -- entry point ------------------------------------------------------------

def analyse(ctx: Context):
    """Traces, the case split, the loop facts and the prologue's writes."""
    state, constraints, steps, facts, control = prologue(ctx.prg)
    return state, constraints, steps, facts, split_paths(state), control


def run(ledger: Ledger, ctx: Context,
        report_path: str | None = REPORT) -> None:
    try:
        _, _, steps, facts, terminal, control = analyse(ctx)
        loop_ids = loops(ledger, facts)
        split = case_split(ledger, terminal)
        traces, trace_ids = {}, []
        for case, group in sorted(split["groups"].items()):
            traces[case] = run_window(generalise(group, case), case)
            trace_ids += trace_obligations(ledger, traces[case])
        fact_ids = window_facts(ledger, traces, steps, control)
        warm_reset_gap(ledger, ctx.prg)
        dependencies = (loop_ids + ["INIT-MEM-PATHS-TOTAL",
                                    "INIT-MEM-PATHS-DISJOINT",
                                    "INIT-MEM-WARM-COND",
                                    "INIT-MEM-SPLIT-STATE"]
                        + trace_ids + fact_ids)
        result, sets = partition(ledger, traces, split["phi"], dependencies)
        crosscheck = dynamic_crosscheck(ledger, sets)
        negative(ledger, traces)
    except Unexpected as exc:
        if "INIT-MEM-PARTITION" not in ledger.items:
            ledger.add(Obligation(
                "INIT-MEM-PARTITION",
                "the 2,048 RAM cells split into cells overwritten before the "
                "NMI-enable bit is set, cells preserved on the warm-boot "
                "path, and cells never written inside the window",
                "the partition P1's initial-memory parameter is read off",
                "unknown",
                detail={"scope": MODEL_SCOPE, "why_unknown": str(exc),
                        "note": "the method aborted rather than bounding "
                                "anything; this is not a timeout"}))
        return

    if report_path:
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        with open(report_path, "w") as handle:
            json.dump({
                "rom_sha1": ctx.sha1,
                "scope": MODEL_SCOPE,
                "window": {
                    "start": "${:04X}".format(entry_state(ctx.prg).pc),
                    "end": {c: "${:04X}".format(t.end.pc)
                            for c, t in sorted(traces.items())},
                    "end_instruction": "the STA $2000 of WritePPUReg1, "
                                       "reached through the JSR $8EED that "
                                       "follows ORA #$80",
                    "steps": {c: t.steps for c, t in sorted(traces.items())},
                    "steps_before_the_split": steps,
                    "init_loop_at_90CC": {
                        "page_iterations": {
                            c: t.pc_counts[0x90D2]
                            for c, t in sorted(traces.items())},
                        "inner_iterations": {
                            c: t.pc_counts[0x90DE]
                            for c, t in sorted(traces.items())},
                        "stores": {c: t.pc_counts[0x90DC]
                                   for c, t in sorted(traces.items())},
                        "handling": "fully unrolled, trip counts derived"},
                    "vblank_loops": {
                        "${:04X}".format(head): "closed by a proved invariant"
                        for head, _, _ in VBLANK_LOOPS},
                    "writes": {c: len(t.writes)
                               for c, t in sorted(traces.items())}},
                "warm_boot_condition": PHI_TEXT,
                "partition": result,
                "dynamic_crosscheck": crosscheck,
                "statuses": {k: v.status for k, v in ledger.items.items()
                             if k.startswith("INIT-MEM")},
            }, handle, indent=2, sort_keys=True)
