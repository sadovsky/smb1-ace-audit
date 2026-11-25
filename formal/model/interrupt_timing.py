"""A cycle-level model of NMI arrival, and the two derivations it exists for.

`transitions.py` is an instruction-granularity relation: it cannot say *when*
inside an instruction an NMI is taken, so it lets an NMI be taken at every
boundary at which the ghost enable bit is set.  Two statements that the joint
invariant needs are therefore listed there as *assumptions*:

    MA-NMI-EDGE     after an NMI is taken, no further NMI is taken until the
                    PPU NMI-enable bit has been written 0 -> 1 again.
    MA-NMI-LATENCY  an NMI whose edge is caused by the final cycle of an
                    instruction is serviced only after the *following*
                    instruction completes.

This module states a small cycle-level model of only what those two statements
depend on, and discharges them against it by exhaustive enumeration.  Nothing
here is imported by `transitions.py` or `cpu.py`; their semantics are
unchanged.  What this module produces is a *status* for each assumption and
the premises that status rests on.

--------------------------------------------------------------------------
The model
--------------------------------------------------------------------------

Three parts, and nothing else.

1. **Instruction shape.**  For each instruction in the two windows: how many
   cycles it takes, and on which cycle its write lands.  Both are read out of
   the SingleStepTests `nes6502` vectors, which record per-cycle bus activity
   (`cycle_shapes`); nothing is typed from memory.

2. **The CPU's NMI path.**  An edge detector and a poll point:

   - the line: ``/NMI low  <=>  vblank_flag AND NMI_output``.
     NMI: "The PPU pulls /NMI low if and only if both vblank_flag and
     NMI_output are true."  <https://www.nesdev.org/wiki/NMI>
   - edge sensitivity: a high->low transition of /NMI sets a flip-flop.
     NMI: "if other circuitry on the board pulls the /NMI pin from high to low
     voltage, this sets a flip-flop in the CPU."  <.../wiki/NMI>
   - when the detector looks: "This edge detector polls the status of the NMI
     line during phi2 of each CPU cycle".
     <https://www.nesdev.org/wiki/CPU_interrupts>
   - detector latency: "The internal signal goes high during phi1 of the cycle
     that follows the one where the edge is detected," and "stays high until
     the NMI has been handled."  <.../wiki/CPU_interrupts>
   - the poll point: "it's really the status of the interrupt lines at the end
     of the second-to-last cycle that matters."  <.../wiki/CPU_interrupts>
     The same page notes the loose rule it corrects: "For most instructions,
     this polling happens during the final cycle of the instruction".
   - the flip-flop is cleared by servicing: NMI's service sequence, step 5,
     "Clear the NMI handler flip-flop."  <.../wiki/NMI>
   - the interrupt sequence does not poll: "The interrupt sequences themselves
     do not perform interrupt polling," <.../wiki/CPU_interrupts>, so no
     second NMI can be taken inside it.
   - its length is **7 cycles**.  CPU_interrupts gives a seven-tick
     "IRQ and NMI tick-by-tick execution" table (labelled as derived from
     Visual 6502) but states no total in words, and the vectors do not cover
     interrupt entry, so the 7 is read off that table: see
     `SOURCING["entry-sequence-7"]`.

   Documented exceptions to the uniform poll rule, and why they do not bear on
   either window (`_check_poll_rule_applies` enforces this, and refuses to run
   on a window where it would not hold):

   - taken branches: "Interrupts are always polled before the second CPU cycle
     (the operand fetch)" "but not before the third CPU cycle on a taken
     branch", and for page-crossing taken branches "interrupts are polled
     before the PCH fixup cycle".  Neither window contains a branch.
   - BRK hijack: an NMI asserted during BRK's first four ticks redirects it.
     Neither window contains a BRK.
   - CLI/SEI/PLP defer by one instruction, and RTI "restor[es] the I flag from
     the stack before polling for interrupts".  All four concern the **I**
     flag, which does not mask NMI, so they change nothing here.  The `RTI` at
     `$8181` is in the latency window and is covered by this remark, not by an
     exception.

   Two rules the pages do **not** settle are left as model parameters and both
   settings are enumerated (`Timing`), so the derivations do not rest on a
   guess:

   - `write_visible_same_cycle`: a `$2000` write lands during phi2 of the
     write cycle, and the detector samples during phi2 of each cycle.  Whether
     the detector sees the new `NMI_output` in that same phi2 or one cycle
     later is a race across two chips that neither page addresses.
   - `detector_latency`: whether the CPU's end-of-cycle poll reads the delayed
     internal signal (as modelled) or the flip-flop directly.  The two facts
     are stated separately; their composition is an inference.

3. **The PPU, reduced to one bit.**  `vblank_flag`.  The CPU clears it by
   reading `$2002`; the adversary may set it, and may clear it, on any cycle.
   That over-approximates both stated hardware events --
   "Start of vertical blanking (scanline 241, dot 1): Set vblank_flag in PPU
   to true." and "End of vertical blanking (scanline 261, dot 1): Set
   vblank_flag to false."  <.../wiki/NMI> -- by dropping *when* they happen.
   Where a derivation needs the timing back, it is named as a premise
   (`PREMISES`), never assumed silently.

No PPU dot counter, no scanline, no rendering, no DMA, no APU, no RAM: the
windows are straight-line code whose only inputs are the two bits above.

--------------------------------------------------------------------------
What this model is and is not validated against
--------------------------------------------------------------------------

Validated: per-instruction cycle counts and write-cycle positions, against the
SingleStepTests `nes6502` vectors, field `cycles` (one entry per CPU cycle:
address, value, `read`/`write`).  `validation_report` gives the counts.

Not validated by anything here: the interrupt entry sequence (the vectors
contain no interrupts), the edge detector and poll point (prose only), PPU dot
timing, and the two race parameters above.  No hardware measurement was taken.
The model is a transcription of wiki prose plus a vector-derived cycle table;
agreement with a console is not established.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, replace
from typing import Callable, Iterable

from analysis.decoder import OPCODES, Flow, Instruction, decode

#: where `formal/tools/fetch_vectors.py` puts the nes6502 vectors
DEFAULT_VECTORS = os.environ.get(
    "NES6502_VECTORS", os.path.expanduser("~/big/smb1-formal/harte"))

NMI_HANDLER = 0x8082
LATENCY_SEQUENCE = 0x817E
PPUCTRL = 0x2000
PPUSTATUS = 0x2002

#: NESdev's seven-tick table for interrupt entry; see the module docstring.
ENTRY_SEQUENCE_CYCLES = 7


def is_ppuctrl(address: int) -> bool:
    """`$2000` and its mirrors every eight bytes through `$3FFF`."""
    return 0x2000 <= address < 0x4000 and address & 7 == 0


def is_ppustatus(address: int) -> bool:
    return 0x2000 <= address < 0x4000 and address & 7 == 2


# --------------------------------------------------------------------------
# 1. instruction shape, from the vectors
# --------------------------------------------------------------------------

class VectorError(RuntimeError):
    """The vectors are missing, or disagree about an opcode's cycle shape."""


@dataclass(frozen=True)
class CycleShape:
    """One opcode's cycle count and bus positions, as the vectors record."""
    opcode: int
    cycles: int
    write_cycles: tuple[int, ...]       # 1-based cycle indices
    #: 1-based cycles whose bus address is not one of the instruction's
    #: own bytes: the cycles that touch its operand or the stack
    operand_cycles: tuple[int, ...]
    vectors: int                        # how many vectors agreed

    def to_json(self) -> dict:
        return {"opcode": f"0x{self.opcode:02X}", "cycles": self.cycles,
                "write_cycles": list(self.write_cycles),
                "operand_access_cycles": list(self.operand_cycles),
                "vectors_agreeing": self.vectors}


def cycle_shapes(opcodes: Iterable[int],
                 vector_dir: str = DEFAULT_VECTORS) -> dict[int, CycleShape]:
    """Read each opcode's cycle shape out of the nes6502 vectors.

    Every vector for an opcode must agree on the number of cycles and on which
    cycles are writes, or `VectorError` is raised rather than a majority taken.
    The addressing modes involved here are all fixed-length with no
    page-crossing penalty, so agreement is expected; a disagreement would mean
    the opcode is the wrong one to model this way.
    """
    out: dict[int, CycleShape] = {}
    for opcode in sorted(set(opcodes)):
        path = os.path.join(vector_dir, f"{opcode:02x}.json")
        if not os.path.exists(path):
            raise VectorError(
                f"no vectors for opcode 0x{opcode:02X} at {path}; run "
                f"formal/tools/fetch_vectors.py")
        with open(path) as handle:
            cases = json.load(handle)
        if not cases:
            raise VectorError(f"{path} is empty")
        length = OPCODES[opcode].length
        shapes = set()
        for case in cases:
            cycles = case["cycles"]
            own = {(case["initial"]["pc"] + k) & 0xFFFF
                   for k in range(length)}
            shapes.add((len(cycles),
                        tuple(i + 1 for i, entry in enumerate(cycles)
                              if entry[2] == "write"),
                        tuple(i + 1 for i, entry in enumerate(cycles)
                              if entry[0] not in own)))
        if len(shapes) != 1:
            raise VectorError(
                f"opcode 0x{opcode:02X}: vectors disagree on cycle shape: "
                f"{sorted(shapes)}")
        count, writes, operands = shapes.pop()
        out[opcode] = CycleShape(opcode, count, writes, operands, len(cases))
    return out


# --------------------------------------------------------------------------
# 2. the windows, read out of the image
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Step:
    """One instruction (or the interrupt entry sequence) as cycles."""
    name: str
    cycles: int
    polls: bool
    #: 1-based cycle whose *end* is the poll point: the second-to-last cycle
    poll_cycle: int | None
    #: 1-based cycle on which a write to PPUCTRL lands, if any
    ppuctrl_write_cycle: int | None = None
    #: bit 7 of the value that write puts in PPUCTRL (True = NMI enabled)
    ppuctrl_write_enables: bool | None = None
    #: 1-based cycle on which a read of PPUSTATUS lands, if any
    ppustatus_read_cycle: int | None = None

    @staticmethod
    def entry_sequence() -> "Step":
        # "The interrupt sequences themselves do not perform interrupt
        # polling," <https://www.nesdev.org/wiki/CPU_interrupts>
        return Step("nmi entry sequence", ENTRY_SEQUENCE_CYCLES, False, None)


def _poll_cycle(cycles: int) -> int:
    """The second-to-last cycle: "the status of the interrupt lines at
    the end of the second-to-last cycle".  For a two-cycle instruction that
    is cycle 1, which is what the same page says of CLI/SEI/PLP: "like all
    two-cycle instructions they poll the interrupt lines at the end of the
    first cycle"."""
    if cycles < 2:
        raise ValueError("no instruction is shorter than two cycles")
    return cycles - 1


class WindowError(RuntimeError):
    """The window contains something the uniform poll rule does not cover."""


def _check_poll_rule_applies(instruction: Instruction) -> None:
    """Refuse to model an instruction whose poll point NESdev says is special.

    Taken branches poll earlier than the second-to-last cycle and `BRK` can be
    hijacked; both are documented exceptions, so rather than model them wrongly
    this raises.  `RTI`/`PLP`/`CLI`/`SEI` are *not* refused: their documented
    peculiarity is when the I flag takes effect, and I does not mask NMI.
    """
    info = instruction.info
    if info.flow is Flow.BRANCH:
        raise WindowError(
            f"${instruction.address:04X} {instruction}: taken branches poll "
            f"before the third cycle, not the second-to-last; this model does "
            f"not cover them")
    if info.flow is Flow.BREAK:
        raise WindowError(
            f"${instruction.address:04X}: BRK can be hijacked by an NMI; this "
            f"model does not cover it")
    if not info.documented or info.unstable:
        raise WindowError(
            f"${instruction.address:04X} {instruction}: undocumented, no "
            f"cycle shape worth trusting")


#: the only mnemonics the bit-7 tracker understands; anything else makes the
#: value written to PPUCTRL unknown and the window unusable
_BIT7_KNOWN = {"LDA", "AND", "ORA", "STA", "PLA", "EOR"}


def _bit7_after(instruction: Instruction, bit7: bool | None) -> bool | None:
    """Three-valued bit 7 of A after `instruction` (None = unknown).

    Only the forms the two windows actually contain are handled, and anything
    else returns `None`, which the callers treat as "the window does not
    determine what is written to PPUCTRL".
    """
    name, mode = instruction.info.mnemonic, instruction.info.mode
    if name == "AND" and mode == "imm":
        # masking with a byte whose bit 7 is clear clears bit 7 whatever A was
        return False if not instruction.operands[0] & 0x80 else bit7
    if name == "ORA" and mode == "imm":
        return True if instruction.operands[0] & 0x80 else bit7
    if name == "EOR" and mode == "imm":
        return None if instruction.operands[0] & 0x80 else bit7
    if name == "STA":
        return bit7                              # a store does not change A
    if name in ("LDA", "PLA"):
        return None                              # value comes from memory
    return None


@dataclass(frozen=True)
class Window:
    """A straight-line stretch of the image, as cycles, plus what it writes."""
    label: str
    steps: tuple[Step, ...]
    instructions: tuple[Instruction, ...]

    @property
    def cycles(self) -> int:
        return sum(step.cycles for step in self.steps)

    def to_json(self) -> dict:
        return {
            "label": self.label,
            "cycles": self.cycles,
            "steps": [
                {"name": step.name, "cycles": step.cycles,
                 "poll_at_end_of_cycle":
                     step.poll_cycle if step.polls else None,
                 "ppuctrl_write_cycle": step.ppuctrl_write_cycle,
                 "ppuctrl_write_enables_nmi": step.ppuctrl_write_enables,
                 "ppustatus_read_cycle": step.ppustatus_read_cycle}
                for step in self.steps],
            "instructions": [f"${i.address:04X}: {i}"
                             for i in self.instructions],
            "bytes": "".join(i.bytes.hex() for i in self.instructions),
        }


def build_window(read_byte: Callable[[int], int], start: int, *,
                 label: str, shapes: dict[int, CycleShape] | None = None,
                 vector_dir: str = DEFAULT_VECTORS,
                 stop_after_ppuctrl_write: bool = False,
                 count: int | None = None,
                 lead_in: Step | None = None,
                 bit7_in: bool | None = None) -> Window:
    """Decode from `start` and turn the instructions into cycle `Step`s.

    Either `stop_after_ppuctrl_write` (take instructions up to and including
    the first write to a PPUCTRL mirror) or `count` must say where to stop.
    Cycle counts and write positions come from the vectors, not from a table in
    this file.  `bit7_in` is bit 7 of A on entry (None = unknown); it is
    carried forward so that the value each PPUCTRL write puts in the enable bit
    is *derived from the image's own immediate masks* where the image
    determines it.
    """
    if count is None and not stop_after_ppuctrl_write:
        raise ValueError("give stop_after_ppuctrl_write or count")
    instructions: list[Instruction] = []
    address = start
    while True:
        instruction = decode(read_byte, address)
        _check_poll_rule_applies(instruction)
        instructions.append(instruction)
        address = instruction.end
        if count is not None and len(instructions) >= count:
            break
        if stop_after_ppuctrl_write and _writes_ppuctrl(instruction):
            break
        if len(instructions) > 64:
            raise WindowError(f"no PPUCTRL write within 64 instructions of "
                              f"${start:04X}")
    if shapes is None:
        shapes = cycle_shapes((i.info.opcode for i in instructions),
                              vector_dir)
    steps: list[Step] = [] if lead_in is None else [lead_in]
    bit7 = bit7_in
    for instruction in instructions:
        shape = shapes[instruction.info.opcode]
        write_cycle = enables = read_cycle = None
        if _writes_ppuctrl(instruction):
            if len(shape.write_cycles) != 1:
                raise WindowError(
                    f"${instruction.address:04X}: {len(shape.write_cycles)} "
                    f"write cycles, expected exactly one")
            write_cycle = shape.write_cycles[0]
            if shape.operand_cycles != (write_cycle,):
                raise WindowError(
                    f"${instruction.address:04X}: the write cycle "
                    f"{write_cycle} is not the only operand access "
                    f"{shape.operand_cycles}")
            enables = bit7
            if enables is None:
                raise WindowError(
                    f"${instruction.address:04X}: the window does not "
                    f"determine bit 7 of the value written to PPUCTRL")
        if _reads_ppustatus(instruction):
            if len(shape.operand_cycles) != 1:
                raise WindowError(
                    f"${instruction.address:04X}: "
                    f"{len(shape.operand_cycles)} operand accesses, expected "
                    f"exactly one")
            read_cycle = shape.operand_cycles[0]
        steps.append(Step(f"${instruction.address:04X} {instruction}",
                          shape.cycles, True, _poll_cycle(shape.cycles),
                          write_cycle, enables, read_cycle))
        bit7 = _bit7_after(instruction, bit7)
    return Window(label, tuple(steps), tuple(instructions))


def _writes_ppuctrl(instruction: Instruction) -> bool:
    return (instruction.info.mnemonic == "STA"
            and instruction.info.mode == "abs"
            and is_ppuctrl(instruction.operand16))


def _reads_ppustatus(instruction: Instruction) -> bool:
    return (instruction.info.mnemonic == "LDA"
            and instruction.info.mode == "abs"
            and is_ppustatus(instruction.operand16))


# --------------------------------------------------------------------------
# 3. the NMI path as a finite state machine
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Timing:
    """The two rules the sources do not settle.  Both are enumerated."""
    write_visible_same_cycle: bool
    detector_latency: bool

    @property
    def label(self) -> str:
        return (f"write_visible_same_cycle="
                f"{str(self.write_visible_same_cycle).lower()},"
                f"detector_latency={str(self.detector_latency).lower()}")


ALL_TIMINGS = tuple(Timing(w, d) for w in (True, False) for d in (True, False))


@dataclass(frozen=True)
class Adversary:
    """What the environment may do to `vblank_flag` on any given cycle."""
    may_set: bool
    may_clear: bool

    def actions(self) -> tuple[str, ...]:
        out = ["none"]
        if self.may_set:
            out.append("set")
        if self.may_clear:
            out.append("clear")
        return tuple(out)


@dataclass(frozen=True)
class Conf:
    """The whole state of the modelled NMI path."""
    vblank: bool
    enable: bool            # PPU NMI_output, i.e. bit 7 of the last $2000 write
    line_low_prev: bool     # what the detector sampled during the previous phi2
    flipflop: bool          # set by an edge, cleared by servicing
    signal: bool            # the internal signal the CPU polls

    @staticmethod
    def consistent(vblank: bool, enable: bool, *, flipflop: bool = False,
                   signal: bool = False) -> "Conf":
        """`line_low_prev` is not free: the detector samples every cycle, and
        nothing changes the line between that sample and the next cycle, so the
        stored value is always the previous cycle's AND."""
        return Conf(vblank, enable, vblank and enable, flipflop, signal)


@dataclass(frozen=True)
class Service:
    """A point at which the interrupt sequence is entered."""
    after_step: int             # index into the window's steps
    step_name: str
    poll_cycle: int             # absolute cycle (1-based) of the poll
    service_begins_cycle: int   # absolute cycle on which the sequence starts
    initial: Conf
    timing: str
    trace: tuple[tuple[int, str], ...]   # (cycle, adversary action)

    def to_json(self) -> dict:
        return {"after_step": self.after_step, "step": self.step_name,
                "poll_at_end_of_absolute_cycle": self.poll_cycle,
                "interrupt_sequence_begins_on_absolute_cycle":
                    self.service_begins_cycle,
                "initial_state": {"vblank_flag": self.initial.vblank,
                                  "nmi_output": self.initial.enable,
                                  "flipflop": self.initial.flipflop,
                                  "internal_signal": self.initial.signal},
                "timing_parameters": self.timing,
                "adversary_trace": [{"cycle": c, "vblank_flag": a}
                                    for c, a in self.trace if a != "none"]}


@dataclass(frozen=True)
class Exploration:
    """The result of enumerating every adversary strategy over a window."""
    window: Window
    services: tuple[Service, ...]
    states_explored: int
    strategies_covered: int
    flipflop_set_at_window_end: bool
    reachable_at_end: int

    def services_after(self, step: int) -> tuple[Service, ...]:
        return tuple(s for s in self.services if s.after_step == step)

    def earliest(self) -> Service | None:
        return min(self.services, key=lambda s: s.service_begins_cycle,
                   default=None)


def _flatten(window: Window) -> list[dict]:
    """One descriptor per cycle of the window."""
    out = []
    absolute = 0
    for index, step in enumerate(window.steps):
        for cycle in range(1, step.cycles + 1):
            absolute += 1
            out.append({
                "absolute": absolute, "step": index, "name": step.name,
                "last": cycle == step.cycles,
                "poll": step.polls and cycle == step.poll_cycle,
                "write": (step.ppuctrl_write_enables
                          if cycle == step.ppuctrl_write_cycle else None),
                "read_status": cycle == step.ppustatus_read_cycle,
                "step_ends_on": absolute + (step.cycles - cycle),
            })
    return out


def explore(window: Window, initial: Iterable[Conf], adversary: Adversary,
            timing: Timing) -> Exploration:
    """Enumerate *every* adversary strategy over the window, exhaustively.

    Breadth-first over (cycle, configuration).  The configuration space is 32
    states and the window is a couple of dozen cycles, so this covers all
    `|actions|^cycles` strategies without enumerating them one at a time: two
    strategies that reach the same configuration at the same cycle have the
    same futures.
    """
    cycles = _flatten(window)
    actions = adversary.actions()
    services: list[Service] = []
    explored = 0
    terminal: set[Conf] = set()
    starts = tuple(initial)
    for start in starts:
        frontier = {start: ()}          # conf -> one witnessing action trace
        for descriptor in cycles:
            following: dict[Conf, tuple] = {}
            for conf, trace in frontier.items():
                explored += 1
                for action in actions:
                    nxt, polled = _step_cycle(conf, descriptor, action, timing)
                    path = trace + ((descriptor["absolute"], action),)
                    if polled:
                        services.append(Service(
                            descriptor["step"], descriptor["name"],
                            descriptor["absolute"],
                            descriptor["step_ends_on"] + 1,
                            start, timing.label, path))
                    following.setdefault(nxt, path)
            frontier = following
        explored += len(frontier)
        terminal |= set(frontier)
    return Exploration(
        window, tuple(services), explored,
        len(starts) * len(actions) ** len(cycles) if cycles else len(starts),
        any(conf.flipflop for conf in terminal),
        len(terminal))


def _step_cycle(conf: Conf, descriptor: dict, action: str,
                timing: Timing) -> tuple[Conf, bool]:
    """One CPU cycle.  Returns the next configuration and whether a poll fired.

    Order inside the cycle:
      phi1   the internal signal takes the flip-flop's value, so an edge
             detected during cycle i is visible to a poll from cycle i+1 on
             ("goes high during phi1 of the cycle that follows the one where
             the edge is detected");
      bus    the CPU's read or write for this cycle;
      env    the adversary's action on `vblank_flag`;
      phi2   the detector samples the line and latches a high->low transition
             ("polls the status of the NMI line during phi2 of each CPU
             cycle");
      end    the CPU polls, if this is the second-to-last cycle.
    """
    signal = conf.flipflop                       # phi1
    vblank, enable = conf.vblank, conf.enable
    if descriptor["read_status"]:                # bus: LDA $2002
        vblank = False
    written = descriptor["write"]                 # bus: STA $2000
    if action == "set":                           # env
        vblank = True
    elif action == "clear":
        vblank = False
    sampled_enable = enable
    if written is not None and timing.write_visible_same_cycle:
        sampled_enable = written
    line_low = vblank and sampled_enable          # phi2
    flipflop = conf.flipflop or (line_low and not conf.line_low_prev)
    if written is not None:
        enable = written
    polled = (descriptor["poll"]
              and (signal if timing.detector_latency else flipflop))
    nxt = Conf(vblank, enable, line_low, flipflop, signal)
    return nxt, polled


def no_edge_while_disabled() -> dict:
    """Exhaustive, horizon-free: with `NMI_output` false no edge can be latched.

    This is the whole content of MA-NMI-EDGE's second half.  It is checked over
    the entire 32-element configuration space and every adversary action,
    rather than over a window of some length, so it holds for an unbounded
    number of cycles: the conclusion does not depend on how long the enable bit
    stays clear.
    """
    checked = 0
    for vblank in (False, True):
        for line_low_prev in (False, True):
            for flipflop in (False, True):
                for signal in (False, True):
                    conf = Conf(vblank, False, line_low_prev, flipflop, signal)
                    for action in ("none", "set", "clear"):
                        for timing in ALL_TIMINGS:
                            descriptor = {"absolute": 1, "step": 0, "name": "",
                                          "last": False, "poll": False,
                                          "write": None, "read_status": False,
                                          "step_ends_on": 1}
                            nxt, _ = _step_cycle(conf, descriptor, action,
                                                 timing)
                            checked += 1
                            if nxt.flipflop and not conf.flipflop:
                                raise AssertionError(
                                    f"edge latched with NMI_output clear: "
                                    f"{conf} --{action}--> {nxt}")
                            if nxt.enable:
                                raise AssertionError("enable rose by itself")
    return {"configurations_checked": checked,
            "edges_latched_with_nmi_output_clear": 0}


# --------------------------------------------------------------------------
# 4. premises, with their sourcing
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Premise:
    """An extra physical or program fact a derivation needs.

    `sourcing` is one of:
      "stated"     a NESdev page says it, and the quote is here;
      "implied"    it follows by arithmetic or by "if and only if" from stated
                   sentences, but no page says it;
      "silent"     no page consulted says it either way;
      "program"    not a hardware fact at all: a property of the image, to be
                   established by the rest of the formal track;
      "vectors"    established here from the SingleStepTests vectors.
    """
    key: str
    statement: str
    sourcing: str
    evidence: str
    page: str = ""

    def to_json(self) -> dict:
        return {"premise": self.key, "statement": self.statement,
                "sourcing": self.sourcing, "evidence": self.evidence,
                "page": self.page}


PREMISES: dict[str, Premise] = {p.key: p for p in (
    Premise(
        "P-EDGE-NO-SET",
        "From the first cycle of the NMI interrupt sequence, no event sets "
        "vblank_flag to true for the next 23 CPU cycles (the length of the "
        "window from interrupt entry to the completion of the disabling write "
        "at $808C).",
        "implied",
        "Arithmetic from stated numbers, not a stated sentence. vblank_flag is "
        "set true by one event only, 'Start of vertical blanking (scanline "
        "241, dot 1): Set vblank_flag in PPU to true.' (NMI); a frame is "
        "'341*262/3 = 29780 2/3 CPU clocks long' and 'The NTSC PPU runs at 3 "
        "times the CPU clock rate' (PPU_frame_timing), so consecutive sets are "
        "about 29780 CPU cycles apart. The edge that caused this NMI needed "
        "vblank_flag true, and 'the VBL flag is cleared 6820 PPU clocks "
        "(exactly 20 scanlines) after it is set' (PPU_frame_timing), i.e. "
        "about 2273 CPU cycles, so that edge was at most ~2273 cycles after "
        "the last set; servicing follows the edge within one instruction plus "
        "one detector cycle. The next set is therefore some 27000 CPU cycles "
        "away, far outside a 23-cycle window. Neither page states 'vblank_flag "
        "is set once per frame' in words, and neither states the vblank "
        "duration in CPU cycles.",
        "https://www.nesdev.org/wiki/NMI, "
        "https://www.nesdev.org/wiki/PPU_frame_timing"),
    Premise(
        "P-LATENCY-DISABLED",
        "At the first cycle of the handler epilogue at $8178, NMI_output is "
        "false and no NMI is pending (neither the edge-detector flip-flop nor "
        "the internal signal is set).",
        "program",
        "Not a hardware premise. NMI_output false has to come from the image. "
        "The graph has three PPUCTRL writes that can happen between $808C and "
        "$817E, and the bit-7 provenance analysis settles each: $808C writes "
        "bit 7 clear (from the image's own AND #$7F / AND #$7E masks), $816C "
        "writes bit 7 of RAM[$0778], and the routine at $8EED, which the "
        "handler body reaches through JSR $8EED at $8E23, also writes bit 7 "
        "of RAM[$0778]. All three reduce to one RAM invariant - bit 7 of "
        "RAM[$0778] is clear - which verify/JOINT_INVARIANT.md section 1 "
        "already lists as open. 'No NMI pending' then follows from "
        "L-NMI-EDGE-DISABLED: with NMI_output false no edge can be latched. "
        "Not settled: the nine stores through a RAM pointer that the handler "
        "body reaches, whose effective address is not bounded here.",
        "formal/verify/JOINT_INVARIANT.md section 1"),
    Premise(
        "P-ENTRY-SEQUENCE-7",
        "The NMI interrupt entry sequence is 7 CPU cycles long and polls no "
        "interrupt during them.",
        "stated",
        "The no-polling half is stated: 'The interrupt sequences themselves do "
        "not perform interrupt polling,' (CPU_interrupts). The length is not "
        "stated in words; CPU_interrupts gives a seven-row 'IRQ and NMI "
        "tick-by-tick execution' table, labelled as derived from Visual 6502, "
        "and the 7 is read off that table. The vectors do not cover interrupt "
        "entry, so this number is not validated here. L-NMI-EDGE-WINDOW is "
        "re-run for entry lengths 1..12 and its verdict does not change, so "
        "the number is not load-bearing.",
        "https://www.nesdev.org/wiki/CPU_interrupts"),
    Premise(
        "P-WRITE-ON-LAST-CYCLE",
        "STA abs takes 4 cycles and its write lands on the fourth; LDA abs "
        "takes 4 and reads its operand on the fourth; AND/ORA immediate take "
        "2; PLA takes 4; RTI takes 6.",
        "vectors",
        "Read out of the SingleStepTests nes6502 vectors' per-cycle 'cycles' "
        "field; every vector for each opcode agrees. See the validation "
        "section of the report for the counts.",
        "https://github.com/SingleStepTests/65x02"),
    Premise(
        "P-ENABLE-IMMEDIATE-EDGE",
        "A PPUCTRL write that sets bit 7 while vblank_flag is already true "
        "pulls /NMI low in time for the edge detector's phi2 sample on that "
        "same cycle.",
        "silent",
        "Neither CPU_interrupts nor NMI states this. The closest is 'The PPU "
        "pulls /NMI low if and only if both vblank_flag and NMI_output are "
        "true.' (NMI), which is a condition, not a timing. Both settings are "
        "enumerated as the model parameter write_visible_same_cycle, and "
        "neither derivation's verdict depends on it, so this premise is NOT "
        "needed. It would be needed only for a liveness claim (that the "
        "re-enabling write at $817E does cause the next NMI promptly), which "
        "no obligation in this track makes.",
        "https://www.nesdev.org/wiki/NMI"),
    Premise(
        "P-POLL-READS-DELAYED-SIGNAL",
        "The CPU's end-of-second-to-last-cycle poll reads the edge detector's "
        "delayed internal signal, not the flip-flop directly.",
        "implied",
        "Composed from two separately stated sentences: 'it's really the "
        "status of the interrupt lines at the end of the second-to-last cycle "
        "that matters.' and 'The internal signal goes high during phi1 of the "
        "cycle that follows the one where the edge is detected,' "
        "(CPU_interrupts). No page composes them. Both settings are "
        "enumerated as the model parameter detector_latency, and neither "
        "derivation's verdict depends on it.",
        "https://www.nesdev.org/wiki/CPU_interrupts"),
    Premise(
        "P-NO-STATUS-READ-IN-WINDOW",
        "No instruction between $8082 and the disabling write at $808C reads "
        "PPUSTATUS, so the CPU does not clear vblank_flag inside that window.",
        "program",
        "Checked from the image by the derivation itself: the window decodes "
        "to LDA $0778 / AND #$7F / STA $0778 / AND #$7E / STA $2000 and "
        "contains no $2002 access. Reported as window_has_no_ppustatus_read.",
        "the image"),
)}


# --------------------------------------------------------------------------
# 5. the derivations
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Result:
    """One derivation's honest status."""
    key: str
    claim: str
    status: str                       # proved | conditional | refuted
    method: str
    premises: tuple[str, ...]
    detail: dict

    def to_json(self) -> dict:
        return {"obligation": self.key, "claim": self.claim,
                "status": self.status, "method": self.method,
                "premises": [PREMISES[k].to_json() for k in self.premises],
                "detail": self.detail}


def _initial_states(*, enable: Iterable[bool], pending: bool) -> list[Conf]:
    """Every configuration consistent with the detector sampling every cycle.

    `line_low_prev` is determined by `vblank and enable`, so it is not free.
    With `pending` the flip-flop and the internal signal are also free, which
    is what "we do not know whether an NMI is already pending" means.
    """
    out = []
    for vblank in (False, True):
        for en in enable:
            flags = ((False, False),) if not pending else (
                (False, False), (True, False), (True, True))
            for flipflop, signal in flags:
                out.append(Conf.consistent(vblank, en, flipflop=flipflop,
                                           signal=signal))
    return out


def _witness_classes(services: Iterable[dict], limit: int = 4) -> list[dict]:
    """One witness per distinct initial state: which half of a premise failed.

    A premise with two halves ("NMI_output is clear" and "no NMI is pending")
    has two ways to fail, and reporting only the earliest witness hides one of
    them.
    """
    best: dict[tuple, dict] = {}
    for service in services:
        state = service["initial_state"]
        key = tuple(sorted(state.items()))
        current = best.get(key)
        if current is None or (service["poll_at_end_of_absolute_cycle"]
                               < current["poll_at_end_of_absolute_cycle"]):
            best[key] = service
    ordered = sorted(best.values(),
                     key=lambda s: s["poll_at_end_of_absolute_cycle"])
    return ordered[:limit]


def derive_nmi_latency(read_byte: Callable[[int], int], *,
                       shapes: dict[int, CycleShape] | None = None,
                       vector_dir: str = DEFAULT_VECTORS) -> Result:
    """MA-NMI-LATENCY, over the real epilogue `$8178`-`$8181`.

    The question asked of the model is exactly the one the assumption answers:
    can the interrupt sequence be entered *between* the `STA $2000` at `$817E`
    and the `RTI` at `$8181`?  Every adversarial `vblank_flag` timing is
    enumerated, under both unsettled timing parameters, twice: once with
    `P-LATENCY-DISABLED` and once without it.
    """
    window = build_window(read_byte, 0x8178, label="$8178-$8181 epilogue",
                          shapes=shapes, vector_dir=vector_dir, count=5)
    names = [step.name for step in window.steps]
    sta = next(i for i, step in enumerate(window.steps)
               if step.ppuctrl_write_cycle is not None)
    if sta != len(window.steps) - 2:
        raise WindowError("the PPUCTRL write is not the second-to-last step")
    if window.steps[sta].ppuctrl_write_enables is not True:
        raise WindowError("the write at $817E does not set the enable bit")
    if window.steps[sta].ppuctrl_write_cycle != window.steps[sta].cycles:
        raise WindowError("the write at $817E is not on the instruction's "
                          "last cycle")
    rti = window.instructions[-1]
    if rti.info.mnemonic != "RTI":
        raise WindowError(f"${rti.address:04X} is {rti}, not RTI")

    adversary = Adversary(may_set=True, may_clear=True)
    with_premise, without_premise = {}, {}
    for timing in ALL_TIMINGS:
        good = explore(window, _initial_states(enable=(False,), pending=False),
                       adversary, timing)
        bad = explore(window, _initial_states(enable=(False, True),
                                              pending=True),
                      adversary, timing)
        with_premise[timing.label] = good
        without_premise[timing.label] = bad

    between = {label: [s.to_json() for s in e.services_after(sta)]
               for label, e in with_premise.items()}
    violated = {label: [s.to_json() for s in e.services_after(sta)]
                for label, e in without_premise.items()}
    after_rti = {}
    for label, exploration in with_premise.items():
        services = exploration.services_after(len(window.steps) - 1)
        earliest = min((s.service_begins_cycle for s in services),
                       default=None)
        after_rti[label] = earliest

    holds = not any(between.values())
    status = "conditional" if holds else "refuted"
    # every distinct way the premise can fail, not just the earliest
    witnesses = _witness_classes(
        [s for services in violated.values() for s in services])
    detail = {
        "window": window.to_json(),
        "question": "can the interrupt sequence be entered between the "
                    "STA $2000 at $817E and the RTI at $8181?",
        "answer_with_premise": "no" if holds else "yes",
        "services_between_sta_and_rti": between,
        "earliest_service_after_the_rti_completes": after_rti,
        "rti_completes_on_absolute_cycle": window.cycles,
        "adversary": "vblank_flag may be set or cleared on any cycle",
        "states_explored": {label: e.states_explored
                            for label, e in with_premise.items()},
        "adversary_strategies_covered": {
            label: e.strategies_covered for label, e in with_premise.items()},
        "verdict_identical_under_all_timing_parameters":
            len({bool(v) for v in between.values()}) == 1,
        "not_vacuous": "the model does admit a service in this window: under "
                       "every timing parameter setting there is an adversarial "
                       "vblank_flag timing for which the NMI is serviced on "
                       "absolute cycle "
                       f"{min(c for c in after_rti.values() if c)}, the cycle "
                       "after the RTI completes. The derivation says the NMI "
                       "arrives one instruction late, not that it never "
                       "arrives.",
        "without_the_premise": {
            "status": "refuted" if any(violated.values()) else "holds anyway",
            "witnesses": witnesses,
            "reading": "if NMI_output is already set, or an NMI is already "
                       "pending, when the epilogue starts, then the interrupt "
                       "sequence can be entered between the STA and the RTI. "
                       "MA-NMI-LATENCY is therefore not a statement about the "
                       "instruction pair alone.",
        },
        "step_names": names,
    }
    return Result(
        "L-NMI-LATENCY",
        "No NMI is taken between the enabling write STA $2000 at $817E and "
        "the completion of the RTI at $8181; an NMI whose edge that write "
        "causes is serviced only after the RTI.",
        status,
        "exhaustive enumeration of every adversarial vblank_flag timing over "
        "the window, by reachability over the 32-state NMI path; all four "
        "settings of the two unsettled timing parameters",
        ("P-LATENCY-DISABLED", "P-WRITE-ON-LAST-CYCLE",
         "P-POLL-READS-DELAYED-SIGNAL"),
        detail)


def derive_nmi_edge_window(read_byte: Callable[[int], int], *,
                           shapes: dict[int, CycleShape] | None = None,
                           vector_dir: str = DEFAULT_VECTORS,
                           entry_lengths: Iterable[int] = range(1, 13)
                           ) -> Result:
    """MA-NMI-EDGE, first half: the window from entry to the disabling write.

    From the moment the NMI is taken to the completion of `STA $2000` at
    `$808C` the enable bit is still set, so this is the only stretch in which a
    second NMI could be taken without an intervening 0->1 write.  The window is
    the 7-cycle entry sequence plus the instructions the image actually has at
    `$8082`, with the value written at `$808C` derived from the image's own
    immediate masks.
    """
    window = build_window(read_byte, NMI_HANDLER,
                          label="$8082-$808C handler prologue", shapes=shapes,
                          vector_dir=vector_dir, stop_after_ppuctrl_write=True,
                          lead_in=Step.entry_sequence())
    disabling = window.steps[-1]
    if disabling.ppuctrl_write_enables is not False:
        raise WindowError("the write at $808C does not clear the enable bit")
    if any(step.ppustatus_read_cycle is not None for step in window.steps):
        raise WindowError("the prologue reads PPUSTATUS; the premise "
                          "P-NO-STATUS-READ-IN-WINDOW does not hold")

    # the NMI was taken, so the flip-flop was cleared by servicing (NMI page,
    # step 5).  vblank_flag and NMI_output are left free: all four combinations
    # are enumerated, including the physically intended (true, true).
    initial = _initial_states(enable=(False, True), pending=False)
    constrained = Adversary(may_set=False, may_clear=True)  # P-EDGE-NO-SET
    free = Adversary(may_set=True, may_clear=True)           # without it

    with_premise, without_premise = {}, {}
    for timing in ALL_TIMINGS:
        with_premise[timing.label] = explore(window, initial, constrained,
                                             timing)
        without_premise[timing.label] = explore(window, initial, free, timing)

    inside = {label: [s.to_json() for s in e.services]
              for label, e in with_premise.items()}
    violations = {label: [s.to_json() for s in e.services]
                  for label, e in without_premise.items()}
    holds = not any(inside.values())

    # is the 7 load-bearing?  re-run with other entry lengths.
    sensitivity = {}
    for length in entry_lengths:
        variant = replace(window, steps=(Step("nmi entry sequence", length,
                                              False, None),)
                          + window.steps[1:])
        sensitivity[length] = not any(
            explore(variant, initial, constrained, timing).services
            for timing in ALL_TIMINGS)

    witnesses = _witness_classes(
        [s for services in violations.values() for s in services])
    detail = {
        "window": window.to_json(),
        "question": "with the enable bit still set, can a second edge be "
                    "detected and a second NMI serviced between interrupt "
                    "entry and the completion of the write at $808C?",
        "answer_with_premise": "no" if holds else "yes",
        "window_cycles": window.cycles,
        "disabling_write_lands_on_absolute_cycle": window.cycles,
        "window_has_no_ppustatus_read": True,
        "services_inside_the_window": inside,
        "nmi_pending_at_window_end": {
            label: e.flipflop_set_at_window_end
            for label, e in with_premise.items()},
        "states_explored": {label: e.states_explored
                            for label, e in with_premise.items()},
        "adversary_strategies_covered": {
            label: e.strategies_covered for label, e in with_premise.items()},
        "verdict_identical_under_all_timing_parameters":
            len({bool(v) for v in inside.values()}) == 1,
        "verdict_identical_for_entry_sequence_lengths_1_to_12":
            all(sensitivity.values()),
        "entry_length_sensitivity": sensitivity,
        "not_vacuous": "the window's poll points can fire: dropping "
                       "P-EDGE-NO-SET produces a service inside the window "
                       "(see without_the_premise), so the 'no service' result "
                       "is not an artefact of a window in which nothing can "
                       "happen.",
        "why": "the enable bit is 1 throughout the window and the only "
               "PPUCTRL write in it, at $808C, writes bit 7 clear (derived "
               "from the image's AND #$7F and AND #$7E), so NMI_output never "
               "goes 0->1 inside the window. /NMI can therefore only go "
               "high->low again if vblank_flag goes 0->1, which is exactly "
               "what P-EDGE-NO-SET excludes.",
        "without_the_premise": {
            "status": "refuted" if any(violations.values()) else "holds anyway",
            "witnesses": witnesses,
            "reading": "if vblank_flag may be cleared and set again inside "
                       "the window, a second NMI is serviced before $8085. "
                       "The whole weight of MA-NMI-EDGE's first half is on "
                       "P-EDGE-NO-SET, a PPU frame-timing premise that the "
                       "instruction-level model cannot see.",
        },
    }
    return Result(
        "L-NMI-EDGE-WINDOW",
        "No second NMI is taken between an NMI being taken and the "
        "completion of the disabling write STA $2000 at $808C.",
        "conditional" if holds else "refuted",
        "exhaustive enumeration of every adversarial vblank_flag timing over "
        "the 23-cycle window, by reachability over the 32-state NMI path; all "
        "four settings of the two unsettled timing parameters; entry-sequence "
        "length varied over 1..12",
        ("P-EDGE-NO-SET", "P-NO-STATUS-READ-IN-WINDOW", "P-ENTRY-SEQUENCE-7",
         "P-WRITE-ON-LAST-CYCLE", "P-POLL-READS-DELAYED-SIGNAL"),
        detail)


def derive_nmi_edge_disabled() -> Result:
    """MA-NMI-EDGE, second half, and the only part that needs no premise.

    Once `$808C` has written bit 7 clear, no further NMI can be taken until
    some PPUCTRL write sets it again, whatever the PPU does.  This is checked
    over the whole configuration space rather than over a window of some
    length, so no horizon enters the argument.
    """
    detail = dict(no_edge_while_disabled())
    detail.update({
        "question": "with NMI_output false, can the edge detector latch an "
                    "edge, for any vblank_flag behaviour whatever?",
        "answer": "no",
        "horizon": "none: the check is over every configuration and every "
                   "adversary action, not over a window of some length, so "
                   "the conclusion holds for an unbounded number of cycles",
        "why": "/NMI low requires vblank_flag AND NMI_output; with NMI_output "
               "false the line is high on every phi2 sample, so no high->low "
               "transition occurs and the flip-flop is never set.",
        "what_this_does_not_say": "it does not say when the enable bit is "
                                  "next set. That is a program question: see "
                                  "PROG-PPUCTRL-WRITERS.",
    })
    return Result(
        "L-NMI-EDGE-DISABLED",
        "While the PPU NMI-enable bit is clear no NMI can be taken, so two "
        "NMI entries must have an intervening 0->1 write of that bit.",
        "proved",
        "exhaustive enumeration over the whole 32-state configuration space "
        "and all three adversary actions, under all four settings of the two "
        "unsettled timing parameters; no horizon",
        (),
        detail)


# --------------------------------------------------------------------------
# 6. the program side of MA-NMI-EDGE: who can write PPUCTRL
# --------------------------------------------------------------------------

#: instructions that write their effective address
_WRITERS = frozenset((
    "STA", "STX", "STY", "SAX", "SHA", "SHX", "SHY", "SLO", "RLA", "SRE",
    "RRA", "DCP", "ISC", "ASL", "LSR", "ROL", "ROR", "INC", "DEC"))



# --------------------------------------------------------------------------
# 6a. where each PPUCTRL write gets its bit 7
# --------------------------------------------------------------------------

#: the lattice: "clear", "set", "copy:$xxxx" (bit 7 of a RAM cell), "unknown"
UNKNOWN = "unknown"


def _join(left: str, right: str) -> str:
    return left if left == right else UNKNOWN


def _transfer(instruction: Instruction, value: str) -> str:
    """Bit 7 of A after `instruction`, given bit 7 of A before it.

    Anything not listed yields `unknown`, which is the top of the lattice, so
    an unhandled instruction weakens the answer and never strengthens it.
    """
    name, mode = instruction.info.mnemonic, instruction.info.mode
    immediate = instruction.operands[0] if instruction.operands else 0
    if name == "AND" and mode == "imm":
        return "clear" if not immediate & 0x80 else value
    if name == "ORA" and mode == "imm":
        return "set" if immediate & 0x80 else value
    if name == "EOR" and mode == "imm":
        if not immediate & 0x80:
            return value
        return {"clear": "set", "set": "clear"}.get(value, UNKNOWN)
    if name == "LDA":
        if mode == "imm":
            return "set" if immediate & 0x80 else "clear"
        if mode == "abs":
            return f"copy:${instruction.operand16:04X}"
        if mode == "zp":
            return f"copy:${immediate:02X}"
        return UNKNOWN
    if name == "LSR" and mode == "acc":
        return "clear"                      # a zero is shifted into bit 7
    # instructions that provably leave A alone
    if name in ("STA", "STX", "STY", "PHA", "PHP", "PLP", "INC", "DEC",
                "INX", "INY", "DEX", "DEY", "CMP", "CPX", "CPY", "BIT",
                "NOP", "SEI", "CLI", "CLD", "SED", "CLC", "SEC", "CLV",
                "LDX", "LDY", "TAX", "TAY", "TSX", "TXS", "JSR", "JMP",
                "BCC", "BCS", "BEQ", "BNE", "BMI", "BPL", "BVC", "BVS"):
        return value
    return UNKNOWN


#: CFG edge kinds across which the accumulator does not survive
_OPAQUE_EDGES = frozenset(("return_point", "dispatch", "indirect_jump"))


def bit7_at(graph, read_byte: Callable[[int], int], address: int, *,
            depth: int = 24, seen: frozenset = frozenset()) -> str:
    """Bit 7 of A on entry to the instruction at `address`.

    A small backward join over the control-flow graph: the value on entry is
    the join of each predecessor's transfer.  Recursion is bounded and a
    predecessor reached across an opaque edge (a return, a dispatch) gives
    `unknown`, so the result is sound by construction and may be weaker than
    the truth.
    """
    if depth <= 0 or address in seen:
        return UNKNOWN
    node = graph.nodes.get(address)
    if node is None or not node.predecessors:
        return UNKNOWN
    value = None
    for predecessor, kind in node.predecessors:
        if kind in _OPAQUE_EDGES:
            incoming = UNKNOWN
        else:
            before = bit7_at(graph, read_byte, predecessor, depth=depth - 1,
                             seen=seen | {address})
            incoming = _transfer(decode(read_byte, predecessor), before)
        value = incoming if value is None else _join(value, incoming)
        if value == UNKNOWN:
            break
    return value or UNKNOWN


def enable_bit_provenance(graph, read_byte: Callable[[int], int],
                          sites: Iterable[int]) -> dict:
    """For each PPUCTRL write site, where bit 7 of the written value comes from.

    This is what turns "no PPUCTRL write sets the enable bit inside the
    handler" from a claim into a named obligation: every site whose answer is
    `copy:$0778` reduces to the one RAM invariant, and any site whose answer is
    `unknown` or `set` is a hole that has to be closed elsewhere.
    """
    out = {}
    for site in sorted(set(sites)):
        value = bit7_at(graph, read_byte, site)
        out[f"${site:04X}"] = {
            "instruction": str(decode(read_byte, site)),
            "bit7_of_the_value_written": value,
            "reduces_to": ("the RAM invariant on " + value.split(":")[1]
                           if value.startswith("copy:") else value),
        }
    return out


def ppuctrl_write_census(read_byte: Callable[[int], int]) -> dict:
    """Every instruction start in the graph that could write a PPUCTRL mirror.

    `L-NMI-EDGE-DISABLED` says no NMI can be taken while the enable bit is
    clear.  Turning that into "no NMI between `$808C` and `$817E`" needs the
    *program* fact that nothing in between sets the bit again.  This census
    reports what the graph says, including the part that stays open: stores
    through a RAM pointer, whose effective address this module does not bound.
    """
    from analysis.cfg import build_from_vectors         # local: slow import

    graph = build_from_vectors(read_byte)
    direct, indexed, indirect = [], [], []
    for address in sorted(graph.instruction_starts):
        instruction = decode(read_byte, address)
        if instruction.info.mnemonic not in _WRITERS:
            continue
        mode = instruction.info.mode
        if mode == "abs" and is_ppuctrl(instruction.operand16):
            direct.append((address, str(instruction)))
        elif (mode in ("abx", "aby")
              and 0x1F01 <= instruction.operand16 < 0x4000):
            indexed.append((address, str(instruction)))
        elif mode in ("izx", "izy"):
            indirect.append((address, str(instruction)))

    # which of them the handler body can reach: $8175 is `JSR $8212`
    reachable, queue = {0x8212}, [0x8212]
    while queue:
        node = graph.nodes.get(queue.pop())
        if node is None:
            continue
        for successor, _kind in node.successors:
            if successor not in reachable:
                reachable.add(successor)
                queue.append(successor)

    def fmt(items):
        return [{"at": f"${a:04X}", "instruction": text,
                 "reachable_from_the_handler_body": a in reachable}
                for a, text in items]

    # every direct write site, plus the call sites of the routine at $8EED,
    # which writes PPUCTRL from whatever the caller left in A
    sites = [a for a, _ in direct]
    for address, _text in direct:
        node = graph.nodes.get(address)
        for predecessor, kind in (node.predecessors if node else ()):
            if kind == "call":
                sites.append(predecessor)
    provenance = enable_bit_provenance(graph, read_byte, sites)
    inside = {key: value for key, value in provenance.items()
              if int(key[1:], 16) in reachable}

    return {
        "enable_bit_provenance": provenance,
        "provenance_of_the_sites_the_handler_body_reaches": inside,
        "graph": "analysis/cfg.py, built from the three vectors",
        "instruction_starts": len(graph.instruction_starts),
        "handler_body_reachable_starts": len(reachable),
        "direct_ppuctrl_writes": fmt(direct),
        "indexed_writes_whose_range_may_include_a_mirror": fmt(indexed),
        "writes_through_a_RAM_pointer": fmt(indirect),
        "closed": "there are five direct writes to a PPUCTRL mirror in the "
                  "graph: $8004 and the routine at $8EED (both on the reset "
                  "path), $808C and $816C in the handler prologue, and $817E "
                  "in its epilogue. $808C writes bit 7 clear, derived from "
                  "the image's own AND #$7F / AND #$7E masks, and $817E "
                  "writes it set, derived from its ORA #$80.",
        "open": "two things. First, the routine at $8EED writes PPUCTRL from "
                "whatever A holds, and the handler body does reach it: the "
                "graph has $8212 -> ... -> $858E -> $8E19 -> JSR $8EED at "
                "$8E23. So a PPUCTRL write does occur inside the game logic, "
                "and the premise is not 'no write' but 'no write with bit 7 "
                "set'. See enable_bit_provenance: at $8E23 bit 7 of A is bit "
                "7 of RAM[$0778], the same cell $816C writes from, so this "
                "site reduces to the same RAM invariant and adds no new "
                "assumption - but that invariant is open "
                "(verify/JOINT_INVARIANT.md section 1). Second, the stores "
                "through a RAM pointer are not bounded here. If any of the "
                "nine the handler body reaches can be made to address a "
                "PPUCTRL mirror with bit 7 of the stored value set, the "
                "enable bit can be raised inside the handler body and both "
                "halves of MA-NMI-EDGE lose their program premise. Both are "
                "residual obligations, not results.",
    }


# --------------------------------------------------------------------------
# 7. the report
# --------------------------------------------------------------------------

#: every rule of the cycle model, with the sentence it came from
RULES = (
    {"rule": "/NMI is low if and only if vblank_flag and NMI_output are both "
             "true",
     "sourcing": "stated",
     "quote": "The PPU pulls /NMI low if and only if both vblank_flag and "
              "NMI_output are true.",
     "page": "https://www.nesdev.org/wiki/NMI"},
    {"rule": "a high->low transition of /NMI sets a flip-flop in the CPU",
     "sourcing": "stated",
     "quote": "if other circuitry on the board pulls the /NMI pin from high "
              "to low voltage, this sets a flip-flop in the CPU.",
     "page": "https://www.nesdev.org/wiki/NMI"},
    {"rule": "the edge detector samples the line during phi2 of every cycle",
     "sourcing": "stated",
     "quote": "This edge detector polls the status of the NMI line during "
              "phi2 of each CPU cycle",
     "page": "https://www.nesdev.org/wiki/CPU_interrupts"},
    {"rule": "the internal signal rises one cycle after detection and stays "
             "up until the NMI is handled",
     "sourcing": "stated",
     "quote": "The internal signal goes high during phi1 of the cycle that "
              "follows the one where the edge is detected, ... stays high "
              "until the NMI has been handled.",
     "page": "https://www.nesdev.org/wiki/CPU_interrupts"},
    {"rule": "the CPU's decision is made at the end of the second-to-last "
             "cycle of an instruction",
     "sourcing": "stated",
     "quote": "it's really the status of the interrupt lines at the end of "
              "the second-to-last cycle that matters.",
     "page": "https://www.nesdev.org/wiki/CPU_interrupts"},
    {"rule": "a two-cycle instruction therefore polls at the end of its first "
             "cycle",
     "sourcing": "stated",
     "quote": "like all two-cycle instructions they poll the interrupt lines "
              "at the end of the first cycle",
     "page": "https://www.nesdev.org/wiki/CPU_interrupts"},
    {"rule": "the interrupt sequence itself polls no interrupt",
     "sourcing": "stated",
     "quote": "The interrupt sequences themselves do not perform interrupt "
              "polling,",
     "page": "https://www.nesdev.org/wiki/CPU_interrupts"},
    {"rule": "servicing clears the flip-flop",
     "sourcing": "stated",
     "quote": "Clear the NMI handler flip-flop.",
     "page": "https://www.nesdev.org/wiki/NMI (step 5 of the NMI sequence)"},
    {"rule": "vblank_flag is set true at the start of vertical blanking and "
             "false at its end or by a PPUSTATUS read",
     "sourcing": "stated",
     "quote": "Start of vertical blanking (scanline 241, dot 1): Set "
              "vblank_flag in PPU to true. ... End of vertical blanking "
              "(scanline 261, dot 1): Set vblank_flag to false. ... Read "
              "PPUSTATUS: Return old status of vblank_flag in bit 7, then "
              "set vblank_flag to false.",
     "page": "https://www.nesdev.org/wiki/NMI"},
    {"rule": "the interrupt entry sequence is 7 cycles",
     "sourcing": "stated as a seven-row table, not as a number",
     "quote": "(no sentence; the 'IRQ and NMI tick-by-tick execution' table "
              "has seven numbered ticks and is labelled as derived from "
              "Visual 6502)",
     "page": "https://www.nesdev.org/wiki/CPU_interrupts"},
    {"rule": "taken branches poll earlier than the second-to-last cycle, and "
             "BRK can be hijacked: both are refused by this model rather than "
             "approximated",
     "sourcing": "stated",
     "quote": "Interrupts are always polled before the second CPU cycle (the "
              "operand fetch) ... but not before the third CPU cycle on a "
              "taken branch ... The BRK instruction, however, can effectively "
              "be cancelled by an NMI (or an IRQ) this way",
     "page": "https://www.nesdev.org/wiki/CPU_interrupts"},
    {"rule": "RTI/PLP/CLI/SEI are peculiar about the I flag only, which does "
             "not mask NMI, so the uniform poll rule is used for them",
     "sourcing": "stated",
     "quote": "RTI ... restoring the I flag from the stack before polling "
              "for interrupts",
     "page": "https://www.nesdev.org/wiki/CPU_interrupts"},
    {"rule": "whether a PPUCTRL write is visible to the detector on its own "
             "cycle",
     "sourcing": "silent: enumerated both ways (write_visible_same_cycle)",
     "quote": "(no page consulted addresses this)",
     "page": ""},
    {"rule": "whether the CPU's poll reads the delayed internal signal or the "
             "flip-flop",
     "sourcing": "implied by two separate sentences, not composed anywhere: "
                 "enumerated both ways (detector_latency)",
     "quote": "(see P-POLL-READS-DELAYED-SIGNAL)",
     "page": "https://www.nesdev.org/wiki/CPU_interrupts"},
)

NOT_VALIDATED = (
    "the interrupt entry sequence: the nes6502 vectors contain no interrupts, "
    "so its 7 cycles and its no-polling rule are prose only",
    "the edge detector and the poll point: prose only, no vectors and no "
    "measurement",
    "PPU dot timing: there is no dot or scanline counter in this model; the "
    "PPU is one bit",
    "the two race parameters (write visibility, detector latency): enumerated "
    "rather than resolved",
    "no hardware measurement of any kind was taken",
    "DMA: OAM and DMC DMA stall the CPU and would stretch any window in real "
    "cycles. They cannot create a PPUCTRL write or a vblank_flag set, so they "
    "do not affect these two derivations, but the cycle counts here are "
    "stall-free",
)


def validation_report(shapes: dict[int, CycleShape]) -> dict:
    return {
        "source": "SingleStepTests nes6502 vectors",
        "field_compared": "cycles: one entry per CPU cycle, "
                          "[address, value, read|write]",
        "derived_from_it": ["cycle count per opcode",
                            "which cycle each write lands on",
                            "which cycles touch the operand rather than the "
                            "instruction's own bytes"],
        "opcodes": {f"0x{op:02X}": shape.to_json()
                    for op, shape in sorted(shapes.items())},
        "vectors_read": sum(shape.vectors for shape in shapes.values()),
        "opcodes_read": len(shapes),
        "disagreements": 0,
        "note": "every vector for each opcode agreed on the whole shape; a "
                "disagreement would have raised rather than been averaged",
    }


RECOMMENDED_WORDING = {
    "MA-NMI-EDGE": "Split in two. The half that needs nothing: while the PPU "
                   "NMI-enable bit is clear no NMI can be taken, so two NMI "
                   "entries must have an intervening 0->1 write of that bit "
                   "(L-NMI-EDGE-DISABLED, proved against the cycle model in "
                   "model/interrupt_timing.py, no premise). The half that is "
                   "still an assumption: no second NMI inside the 23 cycles "
                   "from interrupt entry to the disabling write at $808C. "
                   "That is derived (L-NMI-EDGE-WINDOW) but conditional on "
                   "P-EDGE-NO-SET, a PPU frame-timing premise NESdev implies "
                   "by arithmetic and states nowhere. Drop the phrase 'at "
                   "least one frame apart': the frame is not what the "
                   "derivation uses, and the program premise that no PPUCTRL "
                   "write between $808C and $817E sets bit 7 is open for nine "
                   "stores through a RAM pointer.",
    "MA-NMI-LATENCY": "Keep it as an assumption, but say what it rests on. "
                      "Derived (L-NMI-LATENCY) by exhaustive enumeration over "
                      "the real epilogue $8178-$8181 and every adversarial "
                      "vblank_flag timing, and conditional on "
                      "P-LATENCY-DISABLED, which is a *program* premise, not "
                      "a timing one: NMI_output must be clear and no NMI "
                      "pending when the epilogue starts. Without it the "
                      "statement is refuted with a witness. The sample point "
                      "is quoted, the consequence is derived, and the "
                      "'wrong for taken branches' caveat can go: the model "
                      "refuses branches rather than approximating them, and "
                      "neither window contains one.",
}


def build_report(read_byte: Callable[[int], int], *, sha1: str = "",
                 vector_dir: str = DEFAULT_VECTORS,
                 census: bool = True) -> dict:
    opcodes = set()
    address = NMI_HANDLER
    for _ in range(8):
        instruction = decode(read_byte, address)
        opcodes.add(instruction.info.opcode)
        if _writes_ppuctrl(instruction):
            break
        address = instruction.end
    address = 0x8178
    for _ in range(5):
        instruction = decode(read_byte, address)
        opcodes.add(instruction.info.opcode)
        address = instruction.end
    shapes = cycle_shapes(opcodes, vector_dir)

    results = [
        derive_nmi_latency(read_byte, shapes=shapes, vector_dir=vector_dir),
        derive_nmi_edge_window(read_byte, shapes=shapes,
                               vector_dir=vector_dir),
        derive_nmi_edge_disabled(),
    ]
    report = {
        "obligation": "MA-NMI-EDGE and MA-NMI-LATENCY, derived rather than "
                      "assumed",
        "kind": "derivation against a stated cycle-level model. The model is "
                "a transcription of NESdev prose plus a vector-derived cycle "
                "table. Nothing here is a hardware measurement, and nothing "
                "here changes model/transitions.py or model/cpu.py.",
        "image_sha1": sha1,
        "cycle_model": {
            "rules": list(RULES),
            "ppu_reduced_to": "one bit, vblank_flag, which the CPU clears by "
                              "reading $2002 and which the environment may "
                              "set or clear on any cycle. Where a derivation "
                              "needs the real timing back it names it as a "
                              "premise.",
            "state_space": "32 configurations (vblank_flag, NMI_output, the "
                           "detector's previous sample, the flip-flop, the "
                           "internal signal)",
        },
        "validation": validation_report(shapes),
        "not_validated": list(NOT_VALIDATED),
        "premises": [p.to_json() for p in PREMISES.values()],
        "results": [r.to_json() for r in results],
        "status_counts": {},
        "recommended_assumption_wording": RECOMMENDED_WORDING,
    }
    counts: dict[str, int] = {}
    for result in results:
        counts[result.status] = counts.get(result.status, 0) + 1
    report["status_counts"] = counts
    if census:
        report["program_side"] = ppuctrl_write_census(read_byte)
    return report


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vectors", default=DEFAULT_VECTORS)
    parser.add_argument("--out", default=os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "results", "reports", "interrupt_timing.json"))
    parser.add_argument("--no-census", action="store_true",
                        help="skip the control-flow graph build")
    arguments = parser.parse_args(argv)

    import rom
    image = rom.image()
    report = build_report(rom.b, sha1=image.sha1, vector_dir=arguments.vectors,
                          census=not arguments.no_census)
    with open(arguments.out, "w") as handle:
        json.dump(report, handle, indent=1, sort_keys=True)
        handle.write("\n")
    for result in report["results"]:
        premises = ", ".join(p["premise"] for p in result["premises"])
        print(f"{result['obligation']:22s} {result['status']:12s} "
              f"{premises or '(no premise)'}")
    print(f"written to {arguments.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
