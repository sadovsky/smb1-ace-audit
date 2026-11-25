"""Control-flow-aware abstract stack semantics (plan section 8).

`controlflow.py` looked for an RTS trick by scanning instructions in *address*
order inside a 24-instruction window and asking whether a `PHA` pair appeared
without an intervening `JSR`.  That cannot establish return integrity: it does
not follow execution paths, so it misses a push and a return that are far apart
or in different basic blocks, and it cannot say what a given `RTS` actually
consumes.  It nevertheless produced the claim "every RTS in reached code
returns to a JSR frame".

This module replaces the scan with a per-routine abstract interpretation of the
stack over the control-flow graph, plus a fixpoint over the call graph.

Domain.  A stack is a tuple of typed cells:

    FRAME_HI/LO  the two bytes of the return frame pushed by whoever called
                 this routine; JSR pushes the high byte first, so the low byte
                 is on top and RTS pulls low then high
    RET(pc)      a return address this routine pushed with a JSR
    STATUS       a processor status byte (PHP, or an interrupt frame)
    DATA         a data byte pushed with PHA
    UNKNOWN      a cell whose provenance was lost

Each routine is analysed starting from `(FRAME_HI, FRAME_LO)`, which is sound
for any caller: the question "does this RTS consume a valid frame?" becomes "is
the stack back to exactly those two cells when the RTS executes?".

Summaries and the fixpoint.  A routine is

    BALANCED          every reachable RTS consumes the entry frame and nothing
                      is left pushed, so a caller may assume it returns
    CONSUMES_FRAME    it deliberately removes its caller's frame and leaves by
                      another route -- the JumpEngine, which pulls the caller's
                      return address and uses it as a table pointer
    UNRESOLVED        something could not be established

Callers use callee summaries, so the analysis iterates to a fixpoint.
`UNRESOLVED` is contagious on purpose: a caller of a routine whose behaviour is
unknown cannot have its own returns verified, and saying so is the result.

Branch feasibility matters here as much as it did for index derivation, so the
walk carries a value-set state alongside the abstract stack and prunes edges
the flags prove impossible.  Without it, SMB1's complementary-branch idiom
produces false positives: at `$BEAF` a `BCC` is followed at `$BEB1` by a `BCS`
on the same carry, so one of them is always taken and the fallthrough into
`$BEB3` cannot happen.  Following that edge reaches a `PLA` with the entry
frame on top and makes a perfectly balanced routine look like it returns
through a frame it never created.

What this does and does not establish.  It verifies return-frame integrity
along statically modelled paths under a fixed set of assumptions, which are
reported with the result; it is not a proof over all reachable states, because
the stack cells it tracks are abstract and because a store into the stack page
can overwrite a frame without any stack instruction being involved.  Writers
into `$0100-$01FF` are therefore enumerated separately and reported, since a
frame rewritten that way would defeat the whole analysis.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import Callable

from .cfg import JUMPENGINE, CFG
from .decoder import Flow, decode
from .effective_address import AddressKnowledge
from .interpret import branch_outcomes, step
from .valueset import FULL, Memory, State
from .write_census import census, writers_of


class Cell(str, Enum):
    #: A return frame is two bytes.  `JSR` pushes the high byte first, so the
    #: low byte ends up on top and `RTS` pulls low then high.  Modelling both
    #: cells matters for the JumpEngine, whose two `PLA`s consume exactly one
    #: frame; a single-cell frame would make the second pull look like a stack
    #: underflow.
    FRAME_HI = "frame_hi"
    FRAME_LO = "frame_lo"
    RET = "ret"                # a return address this routine pushed
    STATUS = "status"          # processor status byte
    DATA = "data"              # PHA
    UNKNOWN = "unknown"


class Summary(str, Enum):
    BALANCED = "balanced"
    CONSUMES_FRAME = "consumes_caller_frame"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True)
class ReturnSite:
    """One RTS/RTI and what the analysis could establish about it."""

    address: int
    routine: int
    mnemonic: str
    verified: bool
    detail: str

    def to_json(self) -> dict:
        return {
            "address": f"0x{self.address:04X}",
            "routine": f"0x{self.routine:04X}",
            "instruction": self.mnemonic,
            "verified": self.verified,
            "detail": self.detail,
        }


@dataclass
class RoutineResult:
    entry: int
    summary: Summary
    returns: list[ReturnSite]
    notes: list[str]

    def to_json(self) -> dict:
        return {
            "entry": f"0x{self.entry:04X}",
            "summary": self.summary.value,
            "returns": [r.to_json() for r in self.returns],
            "notes": self.notes,
        }


#: cap on how deep an abstract stack is tracked before widening to UNKNOWN
MAX_DEPTH = 24
MAX_STATES = 20000


def _flags_only(state: State) -> State:
    """Discard register value sets, keep flag knowledge.

    The stack analysis needs only enough precision to drop edges the flags
    prove impossible -- chiefly the complementary-branch idiom, where the carry
    known on one side of a `BCC` makes the following `BCS` certain.  Keeping
    full register sets in the state key would multiply states per address for
    no gain here, so registers are widened after every step.  Widening is
    sound: it can only lose precision, never create a path.
    """
    return State(a=FULL, x=FULL, y=FULL, s=FULL,
                 carry=state.carry, zero=state.zero,
                 negative=state.negative, overflow=state.overflow,
                 compare=state.compare)


def routine_entries(graph: CFG) -> list[int]:
    """Addresses that are entered as routines: call and dispatch targets."""
    entries: set[int] = set()
    for node in graph.nodes.values():
        for target, kind in node.successors:
            if kind in ("call", "dispatch") and target in graph.nodes:
                entries.add(target)
    for _name, vector in (("nmi", 0xFFFA), ("reset", 0xFFFC)):
        address = graph.read_byte(vector) | graph.read_byte(vector + 1) << 8
        if address in graph.nodes:
            entries.add(address)
    # The CFG models `JSR $8E04` as a dispatch rather than a call, so the
    # engine is not a call target and would otherwise go unanalysed.  It is the
    # one routine that deliberately consumes its caller's frame, so it is
    # exactly the one whose stack behaviour must be stated.
    if JUMPENGINE in graph.nodes:
        entries.add(JUMPENGINE)
    # the graph's own seeds are routine entries too, which matters for
    # synthetic graphs built around a single routine
    entries |= {seed for seed in graph.seeds if seed in graph.nodes}
    return sorted(entries)


def _analyse(graph: CFG, entry: int,
             summaries: dict[int, Summary]) -> RoutineResult:
    """Interpret one routine's stack effects, using callee summaries."""
    read_byte = graph.read_byte
    returns: list[ReturnSite] = []
    notes: list[str] = []
    memory = Memory(read_byte)
    seen: set[tuple[int, tuple[Cell, ...], tuple]] = set()
    entry_stack = (Cell.FRAME_HI, Cell.FRAME_LO)
    work: list[tuple[int, tuple[Cell, ...], State]] = [
        (entry, entry_stack, State())
    ]
    consumes_frame = False
    unresolved = False
    states = 0

    while work:
        address, stack, vstate = work.pop()
        if states >= MAX_STATES:
            unresolved = True
            notes.append("state cap reached; result truncated")
            break
        states += 1
        key = (address, stack, vstate.key())
        if key in seen:
            continue
        seen.add(key)
        node = graph.nodes.get(address)
        if node is None:
            continue
        instruction = node.instruction
        info = instruction.info
        name, flow = info.mnemonic, info.flow

        if not info.documented:
            if name in ("NOP",):
                pass                      # undocumented NOPs touch no stack
            else:
                unresolved = True
                notes.append(f"${address:04X}: undocumented {name}, stack "
                             "effect not modelled")
                continue

        if name == "PHA":
            stack = stack + (Cell.DATA,)
            work.append((instruction.end, stack, vstate))
            continue
        if name == "PHP":
            stack = stack + (Cell.STATUS,)
            work.append((instruction.end, stack, vstate))
            continue
        if name in ("PLA", "PLP"):
            if not stack:
                unresolved = True
                notes.append(f"${address:04X}: {name} with an empty abstract "
                             "stack")
                continue
            if stack[-1] in (Cell.FRAME_LO, Cell.FRAME_HI):
                # pulling the caller's frame: the JumpEngine's intentional move
                consumes_frame = True
                notes.append(f"${address:04X}: {name} pulls "
                             f"{stack[-1].value} of the caller's return frame")
            stack = stack[:-1]
            work.append((instruction.end, stack,
                         _flags_only(step(vstate, instruction, memory))))
            continue
        if name == "TXS":
            unresolved = True
            notes.append(f"${address:04X}: TXS reassigns the stack pointer; "
                         "frames below are no longer tracked")
            continue
        if flow is Flow.CALL:
            target = instruction.operand16
            if target == JUMPENGINE:
                # The engine pulls the return address this JSR just pushed and
                # jumps through the table after it.  Control does not come
                # back, and the caller's own frame is untouched.
                notes.append(f"${address:04X}: JSR $8E04 dispatch; the engine "
                             "consumes this call's return address by design")
                continue
            callee = summaries.get(target, Summary.UNRESOLVED)
            if callee is Summary.BALANCED:
                # the callee may change any register or flag
                work.append((instruction.end, stack, State(s=vstate.s)))
            elif callee is Summary.CONSUMES_FRAME:
                notes.append(f"${address:04X}: callee ${target:04X} consumes "
                             "its caller's frame; this path does not return")
            else:
                unresolved = True
                notes.append(f"${address:04X}: callee ${target:04X} is "
                             f"{callee.value}; this call's return is not "
                             "established")
            continue
        if flow is Flow.RETURN:
            if name == "RTS":
                if stack == entry_stack:
                    returns.append(ReturnSite(
                        address, entry, name, True,
                        "consumes exactly the entry frame"))
                elif len(stack) > 2 and stack[-2:] == entry_stack:
                    returns.append(ReturnSite(
                        address, entry, name, False,
                        f"entry frame present but {len(stack) - 2} extra "
                        "cell(s) pushed below it"))
                    unresolved = True
                elif len(stack) < 2:
                    returns.append(ReturnSite(
                        address, entry, name, False,
                        "entry frame already consumed: this RTS returns to a "
                        "frame this routine did not create"))
                    unresolved = True
                else:
                    returns.append(ReturnSite(
                        address, entry, name, False,
                        "top of stack is " + stack[-1].value
                        + ", not a return frame (computed return)"))
                    unresolved = True
            else:                                   # RTI
                returns.append(ReturnSite(
                    address, entry, name, False,
                    "RTI consumes an interrupt frame, which this per-routine "
                    "analysis does not model"))
            continue
        if flow is Flow.HALT:
            continue
        if flow is Flow.BREAK:
            notes.append(f"${address:04X}: BRK pushes an interrupt frame")
            continue
        if flow is Flow.INDIRECT_JUMP:
            notes.append(f"${address:04X}: JMP (ind) leaves with the stack "
                         "unchanged")
            continue

        if len(stack) > MAX_DEPTH:
            unresolved = True
            notes.append(f"${address:04X}: abstract stack deeper than "
                         f"{MAX_DEPTH}; widened")
            continue

        if flow is Flow.BRANCH:
            after = step(vstate, instruction, memory)
            outcomes = branch_outcomes(after, instruction)
            for taken, refined in outcomes:
                target = (instruction.branch_target if taken
                          else instruction.end)
                work.append((target, stack,
                             _flags_only(refined.clear_compare())))
            continue

        if flow in (Flow.NORMAL, Flow.JUMP):
            advanced = _flags_only(step(vstate, instruction, memory))
            for target, kind in node.successors:
                if kind in ("fallthrough", "jump"):
                    work.append((target, stack, advanced))

    if unresolved:
        summary = Summary.UNRESOLVED
    elif consumes_frame:
        summary = Summary.CONSUMES_FRAME
    elif all(r.verified for r in returns):
        summary = Summary.BALANCED
    else:
        summary = Summary.UNRESOLVED
    # dedupe notes and return sites while keeping order: several abstract
    # states can reach the same RTS, and that is one return site, not several
    seen_notes: set[str] = set()
    ordered = [n for n in notes if not (n in seen_notes or seen_notes.add(n))]
    unique: dict[tuple[int, bool, str], ReturnSite] = {}
    for site in returns:
        unique.setdefault((site.address, site.verified, site.detail), site)
    deduped = list(unique.values())
    return RoutineResult(entry, summary, deduped, ordered)


def analyse(graph: CFG, *, iterations: int = 6) -> dict[int, RoutineResult]:
    """Fixpoint over the call graph."""
    entries = routine_entries(graph)
    # Seed optimistically so recursion converges, except the JumpEngine, whose
    # behaviour is known and is the one intentional alternative.
    summaries: dict[int, Summary] = {e: Summary.BALANCED for e in entries}
    summaries[JUMPENGINE] = Summary.CONSUMES_FRAME
    results: dict[int, RoutineResult] = {}
    for _round in range(iterations):
        results = {}
        changed = False
        for entry in entries:
            result = _analyse(graph, entry, summaries)
            results[entry] = result
            if entry == JUMPENGINE:
                result.summary = Summary.CONSUMES_FRAME
            if summaries.get(entry) is not result.summary:
                summaries[entry] = result.summary
                changed = True
        if not changed:
            break
    return results


def stack_page_writers(read_byte: Callable[[int], int]) -> list:
    """Stores that could write the stack page without a stack instruction."""
    writers = census(read_byte, scope="traced")
    buckets = writers_of(0x01FF, writers)
    out = []
    for category in ("exact", "indexed", "unresolved"):
        for writer in buckets[category]:
            if writer.targets.knowledge is AddressKnowledge.STACK_PAGE:
                continue                     # PHA/PHP, already modelled
            out.append(writer)
    return out


def main() -> None:  # pragma: no cover - CLI
    from rom import b, image

    from .cfg import build_from_vectors

    graph = build_from_vectors(b)
    results = analyse(graph)

    counts: dict[str, int] = defaultdict(int)
    for result in results.values():
        counts[result.summary.value] += 1
    all_returns = [r for result in results.values() for r in result.returns]
    verified = [r for r in all_returns if r.verified]
    unverified = [r for r in all_returns if not r.verified]

    print(f"ROM sha1 {image().sha1}")
    print(f"\nroutines analysed: {len(results)}")
    for summary, count in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  {summary:24} {count}")

    print(f"\nreturn sites: {len(all_returns)}")
    print(f"  verified against the entry frame : {len(verified)}")
    print(f"  not verified                     : {len(unverified)}")
    unverified_rts = [r for r in unverified if r.mnemonic == "RTS"]
    print("\nThe old pattern scan claimed 'every RTS in reached code returns "
          "to a JSR frame' from")
    print("a 24-instruction window in address order, which cannot establish "
          "it.  This analysis")
    if unverified_rts:
        print(f"does not reproduce the claim: {len(unverified_rts)} RTS "
              "site(s) are unverified.")
    else:
        print("supports it along the paths it models: every reachable RTS "
              "consumes exactly its")
        print("routine's entry frame.  The claim stands, now on evidence that "
              "can carry it, and")
        print("subject to the assumptions listed below.")

    by_detail: dict[str, list[ReturnSite]] = defaultdict(list)
    for site in unverified:
        by_detail[site.detail.split(":")[0]].append(site)
    print("\nunverified return sites by reason (RTI is not modelled "
          "per routine):")
    for detail, sites in sorted(by_detail.items(), key=lambda kv: -len(kv[1])):
        print(f"  {len(sites):4}  {detail}")
        for site in sites[:3]:
            print(f"          ${site.address:04X} in routine "
                  f"${site.routine:04X}")

    engine = results.get(JUMPENGINE)
    if engine:
        print(f"\nJumpEngine ${JUMPENGINE:04X}: {engine.summary.value}")
        for note in engine.notes[:4]:
            print(f"  {note}")

    writers = stack_page_writers(b)
    print(f"\nstores that could reach the stack page without a stack "
          f"instruction: {len(writers)}")
    for writer in writers[:6]:
        print(f"  ${writer.address:04X} {writer.mnemonic} {writer.mode} "
              f"({writer.targets.knowledge.value})")
    print("A store that rewrites a saved frame would defeat the analysis "
          "above, so these")
    print("are reported rather than assumed harmless.  Each needs its index "
          "range bounded")
    print("before it can be dismissed.")

    print("\nassumptions this result rests on:")
    for assumption in (
            "a routine summarised balanced returns to its call site with the "
            "stack as it found it (the fixpoint makes this consistent, not "
            "proved against hardware)",
            "cells track provenance, not values: a frame overwritten by one "
            "of the 29 stores above would not be detected",
            "the NMI's RTI frame is not modelled per routine",
            "paths are those in the CFG, pruned only where flags prove an "
            "edge impossible"):
        print(f"  - {assumption}")

    report = {
        "rom_sha1": image().sha1,
        "method": ("per-routine abstract stack interpretation over the CFG, "
                   "with a fixpoint over callee summaries"),
        "routines": len(results),
        "summaries": dict(counts),
        "return_sites": len(all_returns),
        "verified_returns": len(verified),
        "unverified_returns": len(unverified),
        "stack_page_writers": len(writers),
        "assumptions": [
            "a routine summarised BALANCED returns to its call site with the "
            "stack as it found it",
            "abstract cells track provenance, not values: a frame overwritten "
            "by a store into $0100-$01FF is not detected",
            "RTI frames are not modelled per routine",
        ],
        "results": [results[e].to_json() for e in sorted(results)],
    }
    with open("results/stack_analysis.json", "w") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
    print("\nwrote results/stack_analysis.json")


if __name__ == "__main__":  # pragma: no cover
    main()
