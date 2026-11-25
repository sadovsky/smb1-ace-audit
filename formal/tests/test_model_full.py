"""Tests for the full-suite validation, the exhaustive equivalence and the
interrupt sequences of `formal/model/cpu.py`.

Three groups:

* `TestInterruptVectors` -- vector-style tests for `enter_interrupt` (NMI,
  IRQ, BRK), `RTI` and `reset`, which no published vector set covers.  Every
  expectation cites the NESdev wiki page it comes from; where the wiki does
  not document a behaviour this file says so instead of asserting one.
* `TestFullVectorSuite` -- spot checks and vacuity checks for
  `formal.tools.validate_full`, plus a check of the saved report.  Skips when
  the full vector set is absent.
* `TestExhaustiveEquivalence` -- the same for `formal.tools.exhaustive`,
  which needs no downloaded data.

    python3 -m unittest formal.tests.test_model_full
"""
from __future__ import annotations

import copy
import itertools
import json
import os
import unittest

from analysis.decoder import OPCODES

from ..model.cpu import (IRQ_VECTOR, NMI_VECTOR, RESET_VECTOR, State,
                         SymbolicFetch, enter_interrupt, reset, step)
from ..model.memory import FlatMemory, as_int
from ..tools import exhaustive, validate_full

REPORTS = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "results", "reports")


# ---------------------------------------------------------------------------
# interrupt entry, RTI and reset
# ---------------------------------------------------------------------------
#
# Sources (fetched 2026-11-25).  Quoted text is from the NESdev wiki.
#
# [CPU interrupts]  https://www.nesdev.org/wiki/CPU_interrupts
#   "Normally, the NMI vector is at $FFFA, the reset vector at $FFFC, and the
#   IRQ and BRK vector at $FFFE."
#   Tick-by-tick for IRQ/NMI: "3 $0100,S W push PCH on stack, decrement S /
#   4 $0100,S W push PCL on stack, decrement S / 5 $0100,S W push P on stack
#   (with B flag *clear*), decrement S / 6 A R fetch PCL ..., set I flag /
#   7 A R fetch PCH".  For BRK the same sequence runs but "the status word
#   will be pushed with the B flag set".
#   Reset: "A reset also goes through the same sequence, but suppresses
#   writes, decrementing the stack pointer thrice without modifying memory.
#   This is why the I flag is always set on reset."
#
# [Status flags]  https://www.nesdev.org/wiki/Status_flags
#   Layout "NV1B DIZC"; bit 5 "(No CPU effect; always pushed as 1)"; bit 4
#   "(No CPU effect; see: the B flag)".  "The two bits with no CPU effect are
#   ignored when pulling flags from the stack".  "B is 0 when pushed by
#   interrupts (NMI and IRQ) and 1 when pushed by instructions (BRK and
#   PHP)."  I is "Automatically set by the CPU after pushing flags to the
#   stack when any interrupt is triggered (NMI, IRQ/BRK, or reset)."
#
# [Instruction reference]  https://www.nesdev.org/wiki/Instruction_reference
#   BRK: "push PC + 2 high byte to stack / push PC + 2 low byte to stack /
#   push NV11DIZC flags to stack / PC = ($FFFE)".
#   RTI: "pull NVxxDIZC flags from stack / pull PC low byte from stack / pull
#   PC high byte from stack ... the return address is the exact address of
#   the next instruction instead of 1 byte before it."
#
# [Stack]  https://www.nesdev.org/wiki/Stack
#   "a 256-byte array whose location is hardcoded at page $01
#   ($0100-$01FF)"; an empty descending stack, so "if S = $FD, and the
#   program pushes something, it'll be written to $01FD and then S becomes
#   $FC"; S "wrap[s] within the stack page".
#
# [CPU power up state]  https://www.nesdev.org/wiki/CPU_power_up_state
#   After reset: A, X, Y "unchanged", PC "($FFFC)", S "S -= 3", I "1", and
#   C, Z, D, V, N "unchanged".
#
# [CPU unofficial opcodes]  https://www.nesdev.org/wiki/CPU_unofficial_opcodes
#   of the undocumented encodings, "some halt the CPU until reset".
#
# NOT documented on any of those pages, and therefore NOT asserted here:
#   * what the suppressed reset "pushes" read, if anything;
#   * the cycle on which an interrupt is taken relative to an instruction
#     boundary (the model has no cycle granularity: see `transitions.py`);
#   * interrupt hijacking, where an NMI asserted during the first four ticks
#     of a BRK redirects it to the NMI vector.  [CPU interrupts] documents it
#     as real hardware behaviour; the model is instruction-granular and
#     cannot express it.  That is a gap in the model, not an expectation.

#: initial flags: N set, V clear, D clear, I *clear*, Z clear, C set
P_START = 0xA1
#: the same flags after an interrupt sets I
P_WITH_I = 0xA5

INTERRUPT_VECTORS = [
    {
        "name": "NMI from $1234, S=$FD",
        "source": "[CPU interrupts] push PCH, PCL, P(B clear); set I; "
                  "PC = ($FFFA).  [Stack] push writes $0100+S, then S--",
        "action": "nmi",
        "initial": {"pc": 0x1234, "a": 0x11, "x": 0x22, "y": 0x33,
                    "s": 0xFD, "p": P_START,
                    "ram": {NMI_VECTOR: 0x78, NMI_VECTOR + 1: 0x56}},
        "final": {"pc": 0x5678, "a": 0x11, "x": 0x22, "y": 0x33, "s": 0xFA,
                  "p": P_WITH_I,
                  "ram": {0x01FD: 0x12, 0x01FC: 0x34, 0x01FB: P_START}},
    },
    {
        "name": "IRQ from $1234, S=$FD",
        "source": "[CPU interrupts] same sequence, PC = ($FFFE)",
        "action": "irq",
        "initial": {"pc": 0x1234, "a": 0x11, "x": 0x22, "y": 0x33,
                    "s": 0xFD, "p": P_START,
                    "ram": {IRQ_VECTOR: 0xBC, IRQ_VECTOR + 1: 0x9A}},
        "final": {"pc": 0x9ABC, "a": 0x11, "x": 0x22, "y": 0x33, "s": 0xFA,
                  "p": P_WITH_I,
                  "ram": {0x01FD: 0x12, 0x01FC: 0x34, 0x01FB: P_START}},
    },
    {
        "name": "BRK at $1234 pushes $1236 and sets B in the pushed status",
        "source": "[Instruction reference] BRK: push PC+2 high, PC+2 low, "
                  "NV11DIZC, PC = ($FFFE).  [Status flags] B is 1 when "
                  "pushed by BRK",
        "action": "step",
        "initial": {"pc": 0x1234, "a": 0x11, "x": 0x22, "y": 0x33,
                    "s": 0xFD, "p": P_START,
                    "ram": {0x1234: 0x00,
                            IRQ_VECTOR: 0xBC, IRQ_VECTOR + 1: 0x9A}},
        "final": {"pc": 0x9ABC, "a": 0x11, "x": 0x22, "y": 0x33, "s": 0xFA,
                  "p": P_WITH_I,
                  #: $B1 is $A1 with bit 4 (B) set
                  "ram": {0x01FD: 0x12, 0x01FC: 0x36, 0x01FB: 0xB1}},
    },
    {
        "name": "NMI with S=$01 wraps inside page one",
        "source": "[Stack] the stack is hardcoded to page $01 and S wraps "
                  "within it",
        "action": "nmi",
        "initial": {"pc": 0x1234, "a": 0, "x": 0, "y": 0, "s": 0x01,
                    "p": P_START,
                    "ram": {NMI_VECTOR: 0x78, NMI_VECTOR + 1: 0x56}},
        "final": {"pc": 0x5678, "a": 0, "x": 0, "y": 0, "s": 0xFE,
                  "p": P_WITH_I,
                  "ram": {0x0101: 0x12, 0x0100: 0x34, 0x01FF: P_START}},
    },
    {
        "name": "NMI with S=$00 wraps on the first push",
        "source": "[Stack] as above",
        "action": "nmi",
        "initial": {"pc": 0x1234, "a": 0, "x": 0, "y": 0, "s": 0x00,
                    "p": P_START,
                    "ram": {NMI_VECTOR: 0x78, NMI_VECTOR + 1: 0x56}},
        "final": {"pc": 0x5678, "a": 0, "x": 0, "y": 0, "s": 0xFD,
                  "p": P_WITH_I,
                  "ram": {0x0100: 0x12, 0x01FF: 0x34, 0x01FE: P_START}},
    },
    {
        "name": "RTI pulls status then PCL then PCH, and ignores bits 4 and 5",
        "source": "[Instruction reference] RTI pulls NVxxDIZC, then PCL, "
                  "then PCH; the return address is exact.  [Status flags] "
                  "bits 4 and 5 are ignored when pulling",
        "action": "step",
        "initial": {"pc": 0x2000, "a": 0x11, "x": 0x22, "y": 0x33,
                    "s": 0xFA, "p": 0x20,
                    #: $5F sets N=0 V=1 B=1 D=1 I=1 Z=1 C=1 with bit 5 clear
                    "ram": {0x2000: 0x40, 0x01FB: 0x5F, 0x01FC: 0x34,
                            0x01FD: 0x12}},
        #: $6F is $5F with bit 5 forced to 1 and bit 4 (B) dropped
        "final": {"pc": 0x1234, "a": 0x11, "x": 0x22, "y": 0x33, "s": 0xFD,
                  "p": 0x6F, "ram": {}},
    },
    {
        "name": "RTI with S=$FE pulls across the page-one boundary",
        "source": "[Stack] S wraps within page $01",
        "action": "step",
        "initial": {"pc": 0x2000, "a": 0, "x": 0, "y": 0, "s": 0xFE,
                    "p": 0x20,
                    "ram": {0x2000: 0x40, 0x01FF: 0x5F, 0x0100: 0x34,
                            0x0101: 0x12}},
        "final": {"pc": 0x1234, "a": 0, "x": 0, "y": 0, "s": 0x01,
                  "p": 0x6F, "ram": {}},
    },
    {
        "name": "reset drops S by three, sets I and writes nothing",
        "source": "[CPU interrupts] reset suppresses writes, decrementing S "
                  "thrice without modifying memory.  [CPU power up state] "
                  "after reset PC = ($FFFC), S -= 3, I = 1, A/X/Y and the "
                  "other flags unchanged",
        "action": "reset",
        "initial": {"pc": 0x2000, "a": 0x11, "x": 0x22, "y": 0x33,
                    "s": 0x40, "p": P_START,
                    "ram": {RESET_VECTOR: 0x00, RESET_VECTOR + 1: 0x80}},
        "final": {"pc": 0x8000, "a": 0x11, "x": 0x22, "y": 0x33, "s": 0x3D,
                  "p": P_WITH_I, "ram": {}},
        "no_writes": True,
    },
    {
        "name": "reset wraps S inside page one without writing",
        "source": "[CPU interrupts], [Stack]",
        "action": "reset",
        "initial": {"pc": 0x2000, "a": 0, "x": 0, "y": 0, "s": 0x01,
                    "p": P_START,
                    "ram": {RESET_VECTOR: 0x34, RESET_VECTOR + 1: 0x12}},
        "final": {"pc": 0x1234, "a": 0, "x": 0, "y": 0, "s": 0xFE,
                  "p": P_WITH_I, "ram": {}},
        "no_writes": True,
    },
]


def _state(initial: dict) -> State:
    return State.concrete(pc=initial["pc"], a=initial["a"], x=initial["x"],
                          y=initial["y"], s=initial["s"], p=initial["p"],
                          mem=FlatMemory(dict(initial["ram"])))


def _apply(action: str, state: State) -> State:
    if action == "nmi":
        return enter_interrupt(state, NMI_VECTOR)
    if action == "irq":
        return enter_interrupt(state, IRQ_VECTOR)
    if action == "reset":
        return reset(state)
    if action == "step":
        successors = step(state)
        assert len(successors) == 1, successors
        return successors[0].state
    raise AssertionError(action)


class TestInterruptVectors(unittest.TestCase):
    """Interrupt entry, RTI and reset against the documented sequences."""

    def test_vectors(self):
        for vector in INTERRUPT_VECTORS:
            with self.subTest(vector["name"]):
                after = _apply(vector["action"], _state(vector["initial"]))
                final = vector["final"]
                self.assertEqual(after.pc, final["pc"], "PC")
                for name in ("a", "x", "y", "s"):
                    self.assertEqual(as_int(getattr(after, name)),
                                     final[name], name.upper())
                #: the pushed form of the status byte, so bit 5 (documented as
                #: always 1) and bit 4 (B, 0 outside BRK/PHP) are both checked
                self.assertEqual(as_int(after.status(b=False)), final["p"],
                                 "status byte")
                for address, value in final["ram"].items():
                    self.assertEqual(as_int(after.mem.read(address)[0]),
                                     value, f"${address:04X}")
                if vector.get("no_writes"):
                    self.assertEqual(after.mem.writes, (),
                                     "reset must not write to memory")

    def test_vectors_are_not_vacuous(self):
        """Every asserted byte must actually be able to disagree."""
        for vector in INTERRUPT_VECTORS:
            after = _apply(vector["action"], _state(vector["initial"]))
            for address, value in vector["final"]["ram"].items():
                with self.subTest(f"{vector['name']} ${address:04X}"):
                    self.assertNotEqual(
                        as_int(after.mem.read(address)[0]), (value + 1) & 0xFF,
                        "a perturbed expectation would still pass")

    def test_nmi_then_rti_is_the_identity_on_the_architectural_state(self):
        """[CPU interrupts] + [Instruction reference] RTI: the pushed frame is
        exactly what RTI restores, including the I flag's previous state."""
        initial = {"pc": 0x1234, "a": 0x11, "x": 0x22, "y": 0x33, "s": 0xFD,
                   "p": P_START,
                   "ram": {NMI_VECTOR: 0x00, NMI_VECTOR + 1: 0x90,
                           0x9000: 0x40}}          # the handler is a bare RTI
        start = _state(initial)
        entered = enter_interrupt(start, NMI_VECTOR)
        self.assertEqual(entered.pc, 0x9000)
        self.assertEqual(as_int(entered.s), 0xFA)
        (successor,) = step(entered)
        back = successor.state
        self.assertEqual(back.pc, initial["pc"])
        self.assertEqual(as_int(back.s), initial["s"])
        self.assertEqual(as_int(back.status(b=False)), P_START,
                         "RTI must restore I to its pre-interrupt value")
        for name in ("a", "x", "y"):
            self.assertEqual(as_int(getattr(back, name)), initial[name])

    def test_brk_sets_i_even_when_it_was_clear_and_pushes_b(self):
        """[Status flags] I is set by any interrupt; B is 1 when pushed by
        BRK.  Checked over all 64 architectural status bytes."""
        for p in exhaustive.P64:
            with self.subTest(f"P=0x{p:02X}"):
                state = _state({"pc": 0x1234, "a": 0, "x": 0, "y": 0,
                                "s": 0xFD, "p": p,
                                "ram": {0x1234: 0x00, IRQ_VECTOR: 0xBC,
                                        IRQ_VECTOR + 1: 0x9A}})
                (successor,) = step(state)
                after = successor.state
                pushed = as_int(after.mem.read(0x01FB)[0])
                self.assertEqual(pushed & 0x30, 0x30,
                                 "BRK pushes bit 5 and B both set")
                self.assertEqual(pushed & 0xCF, p & 0xCF,
                                 "the other six flags are pushed unchanged")
                self.assertTrue(as_int(after.status(b=False)) & 0x04,
                                "I is set after entry")

    def test_interrupt_entry_on_nmi_and_irq_clears_b(self):
        """[Status flags] B is 0 when pushed by interrupts (NMI and IRQ)."""
        for vector in (NMI_VECTOR, IRQ_VECTOR):
            for p in exhaustive.P64:
                with self.subTest(f"${vector:04X} P=0x{p:02X}"):
                    state = _state({"pc": 0x1234, "a": 0, "x": 0, "y": 0,
                                    "s": 0xFD, "p": p,
                                    "ram": {vector: 0x00, vector + 1: 0x90}})
                    after = enter_interrupt(state, vector)
                    pushed = as_int(after.mem.read(0x01FB)[0])
                    self.assertEqual(pushed & 0x30, 0x20,
                                     "bit 5 set, B clear")

    def test_reset_decrements_s_by_three_for_every_s(self):
        """[CPU power up state] "S -= 3", and [Stack] it wraps in page one."""
        for s in range(256):
            with self.subTest(f"S=0x{s:02X}"):
                state = _state({"pc": 0x2000, "a": 0, "x": 0, "y": 0, "s": s,
                                "p": 0x20,
                                "ram": {RESET_VECTOR: 0x00,
                                        RESET_VECTOR + 1: 0x80}})
                after = reset(state)
                self.assertEqual(as_int(after.s), (s - 3) & 0xFF)
                self.assertEqual(after.mem.writes, ())

    def test_reset_from_power_on_s_zero_gives_fd(self):
        """[CPU power up state] at power "S  $00 - 3 = $FD"."""
        state = _state({"pc": 0x2000, "a": 0, "x": 0, "y": 0, "s": 0x00,
                        "p": 0x20, "ram": {RESET_VECTOR: 0x00,
                                           RESET_VECTOR + 1: 0x80}})
        self.assertEqual(as_int(reset(state).s), 0xFD)

    def test_reset_resumes_a_halted_cpu(self):
        """[CPU unofficial opcodes] of the undocumented encodings, "some halt
        the CPU until reset"."""
        state = _state({"pc": 0x1234, "a": 0, "x": 0, "y": 0, "s": 0xFD,
                        "p": 0x20, "ram": {0x1234: 0x02,       # JAM
                                           RESET_VECTOR: 0x00,
                                           RESET_VECTOR + 1: 0x80}})
        (successor,) = step(state)
        self.assertTrue(successor.state.halted)
        self.assertEqual(successor.kind, "halt")
        #: a halted CPU stays halted at every further step
        (again,) = step(successor.state)
        self.assertTrue(again.state.halted)
        after = reset(successor.state)
        self.assertFalse(after.halted)
        self.assertEqual(after.pc, 0x8000)

    def test_interrupt_entry_needs_a_concrete_return_address(self):
        """A model-API property, not a hardware one: `enter_interrupt`
        refuses a symbolic PC rather than silently dropping the frame."""
        import z3
        vectors = {NMI_VECTOR: 0, NMI_VECTOR + 1: 0}
        symbolic = State.symbolic(z3.BitVec("pc", 16), FlatMemory(vectors))
        with self.assertRaises(SymbolicFetch):
            enter_interrupt(symbolic, NMI_VECTOR)


# ---------------------------------------------------------------------------
# the full vector suite
# ---------------------------------------------------------------------------

FULL = validate_full.DEFAULT_VECTORS


def _vectors(opcode: int, count: int) -> list:
    with open(os.path.join(FULL, f"{opcode:02x}.json")) as handle:
        return json.load(handle)[:count]


@unittest.skipUnless(os.path.isdir(FULL),
                     f"the full vector set is absent from {FULL}; run "
                     f"formal/tools/fetch_vectors.py <dir> --count all")
class TestFullVectorSuite(unittest.TestCase):
    """Spot checks for `formal.tools.validate_full` over the real data."""

    def test_every_opcode_has_a_file(self):
        missing = [f"0x{op:02X}" for op in range(256)
                   if not os.path.exists(os.path.join(FULL, f"{op:02x}.json"))]
        self.assertEqual(missing, [])

    def test_the_files_hold_ten_thousand_vectors_each(self):
        for opcode in (0x00, 0x69, 0x8B, 0xF2, 0xFF):
            with self.subTest(f"0x{opcode:02X}"):
                self.assertEqual(len(_vectors(opcode, 100000)), 10000)

    def test_stable_opcodes_agree_on_a_slice(self):
        for opcode in (0x09, 0x20, 0x40, 0x60, 0x6B, 0x6C, 0x7D, 0xB1, 0xEE):
            with self.subTest(f"0x{opcode:02X} {OPCODES[opcode].mnemonic}"):
                for case in _vectors(opcode, 25):
                    self.assertIsNone(validate_full.check_stable(case),
                                      case["name"])

    def test_havoc_opcodes_admit_a_slice(self):
        for opcode in sorted(validate_full.HAVOC_OPCODES):
            with self.subTest(f"0x{opcode:02X} {OPCODES[opcode].mnemonic}"):
                for case in _vectors(opcode, 25):
                    self.assertIsNone(validate_full.check_havoc(case),
                                      case["name"])

    def test_the_stable_check_is_not_vacuous(self):
        case = _vectors(0x69, 1)[0]
        for field in ("a", "p", "pc", "s"):
            with self.subTest(field):
                perturbed = copy.deepcopy(case)
                perturbed["final"][field] ^= 1
                failure = validate_full.check_stable(perturbed)
                self.assertIsNotNone(failure)
                self.assertTrue(failure["differences"])
        perturbed = copy.deepcopy(case)
        address, value = perturbed["final"]["ram"][0]
        perturbed["final"]["ram"][0] = [address, value ^ 1]
        self.assertIsNotNone(validate_full.check_stable(perturbed))

    def test_the_havoc_check_rejects_what_the_model_still_fixes(self):
        """XAA leaves A open but fixes X; TAS fixes S.  A vector that
        disagrees on those is not admitted."""
        xaa = _vectors(0x8B, 1)[0]
        self.assertIsNone(validate_full.check_havoc(xaa))
        open_register = copy.deepcopy(xaa)
        open_register["final"]["a"] ^= 0xFF
        self.assertIsNone(validate_full.check_havoc(open_register),
                          "A is havoc, so any A must be admitted")
        fixed_register = copy.deepcopy(xaa)
        fixed_register["final"]["x"] ^= 1
        self.assertIsNotNone(validate_full.check_havoc(fixed_register))
        tas = _vectors(0x9B, 1)[0]
        self.assertIsNone(validate_full.check_havoc(tas))
        moved_s = copy.deepcopy(tas)
        moved_s["final"]["s"] ^= 1
        self.assertIsNotNone(validate_full.check_havoc(moved_s))

    def test_the_havoc_check_bounds_the_number_of_changed_cells(self):
        """One unconstrained write admits one changed cell, not two."""
        case = copy.deepcopy(_vectors(0x9F, 1)[0])
        case["initial"]["ram"] += [[0x4321, 0x00], [0x4322, 0x00]]
        case["final"]["ram"] += [[0x4321, 0x5A], [0x4322, 0x5B]]
        failure = validate_full.check_havoc(case)
        self.assertIsNotNone(failure)
        self.assertEqual(failure["unconstrained_writes_the_model_made"], 1)

    def test_what_the_jam_vectors_record(self):
        """All 120,000 JAM vectors change PC by exactly one and nothing else.
        The model leaves PC at the opcode and sets `halted`, so it diverges
        in a register it will never read again -- recorded, not compared."""
        for opcode in sorted(validate_full.JAM_OPCODES):
            with self.subTest(f"0x{opcode:02X}"):
                summary = validate_full.summarise_jam(_vectors(opcode, 10000))
                self.assertEqual(summary["vector_fields_that_ever_change"],
                                 ["pc"])
                self.assertEqual(summary["vector_pc_deltas"], [1])
                self.assertTrue(summary["model"]["halted"])
                self.assertEqual(summary["model"]["kind"], "halt")
                self.assertEqual(summary["model"]["pc_delta"], 0)

    def test_jam_and_havoc_are_classified_as_the_plan_says(self):
        self.assertEqual(len(validate_full.JAM_OPCODES), 12)
        self.assertEqual(
            sorted(OPCODES[op].mnemonic
                   for op in validate_full.HAVOC_OPCODES),
            ["LXA", "SHA", "SHA", "SHX", "SHY", "TAS", "XAA"])
        self.assertEqual(
            256 - len(validate_full.JAM_OPCODES)
            - len(validate_full.HAVOC_OPCODES), 237)


class TestFullVectorReport(unittest.TestCase):
    """The saved artifact must show no mismatch and nothing inadmissible."""

    path = os.path.join(REPORTS, "model_validation_full.json")

    @unittest.skipUnless(os.path.exists(path), "report not generated yet")
    def test_report_has_no_mismatches(self):
        with open(self.path) as handle:
            report = json.load(handle)
        self.assertEqual(report["missing_files"], [])
        totals = report["totals"]
        self.assertEqual(totals["stable"]["opcodes"], 237)
        self.assertEqual(totals["stable"]["mismatches"], 0)
        self.assertEqual(totals["stable"]["compared"], 2370000)
        self.assertEqual(totals["havoc"]["opcodes"], 7)
        self.assertEqual(totals["havoc"]["mismatches"], 0)
        self.assertEqual(totals["havoc"]["agreed"], 0,
                         "havoc is never counted as agreement")
        self.assertEqual(totals["jam"]["opcodes"], 12)
        self.assertEqual(totals["jam"]["compared"], 0)
        for row in report["per_opcode"]:
            if row["group"] == "jam":
                self.assertEqual(
                    row["what_the_vectors_record"]["vector_pc_deltas"], [1],
                    row["opcode"])


# ---------------------------------------------------------------------------
# exhaustive equivalence against formal/dyn/cpu6502.py
# ---------------------------------------------------------------------------

class TestExhaustiveEquivalence(unittest.TestCase):
    """Spot checks for `formal.tools.exhaustive`; needs no downloaded data."""

    @classmethod
    def setUpClass(cls):
        try:
            import py65                                   # noqa: F401
        except ImportError:
            raise unittest.SkipTest("py65 is not installed")

    def test_every_opcode_has_domains_except_jam(self):
        for opcode in range(256):
            domains = exhaustive.domains_for(opcode)
            with self.subTest(f"0x{opcode:02X}"):
                if opcode in exhaustive.JAM_OPCODES:
                    self.assertEqual(domains, [])
                else:
                    self.assertTrue(domains)
                    for domain in domains:
                        self.assertGreater(domain.count, 0)
                        self.assertTrue(domain.label)

    def test_the_arithmetic_domains_are_the_full_square(self):
        """ADC/SBC immediate must enumerate 256x256 values and both carries,
        plus a D-set sweep: the 2A03's adder ignores D."""
        for opcode in (0x69, 0xE9, 0xEB):
            with self.subTest(f"0x{opcode:02X}"):
                domains = exhaustive.domains_for(opcode)
                sizes = {d.count for d in domains}
                self.assertEqual(sizes, {131072, 65536})
                axes = dict(domains[0].axes)
                self.assertEqual(len(axes["a"]), 256)
                self.assertEqual(len(axes["m"]), 256)
                self.assertEqual(len(axes["c"]), 2)

    def test_a_strided_slice_of_every_domain_agrees(self):
        reference = exhaustive.Reference()
        checked = 0
        for opcode in range(256):
            havoc = opcode in exhaustive.HAVOC_OPCODES
            for domain in exhaustive.domains_for(opcode):
                stride = max(1, domain.count // 7)
                for case in itertools.islice(domain.cases(), 0, None, stride):
                    checked += 1
                    self.assertIsNone(
                        exhaustive.compare(case, reference, havoc=havoc),
                        f"0x{opcode:02X} {OPCODES[opcode].mnemonic} "
                        f"{domain.label}")
        self.assertGreater(checked, 2000)

    def test_the_comparison_is_not_vacuous(self):
        """Feed the two implementations different operands: the comparison
        must see it.  Otherwise agreement would mean nothing."""
        reference = exhaustive.Reference()
        case = exhaustive._case(0x69, a=0x40, operands=(0x10,))
        other = exhaustive._case(0x69, a=0x40, operands=(0x11,))
        self.assertIsNone(exhaustive.compare(case, reference, havoc=False))
        successors, _ = exhaustive.run_model(case, havoc=False)
        got = validate_full.observe(successors[0].state)
        want, _, _ = reference.run(other)
        self.assertNotEqual(got["a"], want["a"],
                            "the harness cannot tell two results apart")

    def test_a_store_difference_would_be_caught(self):
        """The memory comparison looks at what each side wrote."""
        reference = exhaustive.Reference()
        case = exhaustive._case(0x8D, a=0x5A, operands=(0x34, 0x20))
        self.assertIsNone(exhaustive.compare(case, reference, havoc=False))
        successors, _ = exhaustive.run_model(case, havoc=False)
        writes = dict(successors[0].state.mem.writes)
        self.assertEqual(writes, {0x2034: 0x5A})

    def test_the_reference_restores_its_memory_between_cases(self):
        reference = exhaustive.Reference()
        case = exhaustive._case(0x8D, a=0x5A, operands=(0x34, 0x20))
        reference.run(case)
        self.assertEqual(sum(reference.memory), 0,
                         "a leaked cell would make later cases disagree")


class TestExhaustiveReport(unittest.TestCase):
    path = os.path.join(REPORTS, "model_exhaustive_equivalence.json")

    @unittest.skipUnless(os.path.exists(path), "report not generated yet")
    def test_report_has_no_mismatches(self):
        with open(self.path) as handle:
            report = json.load(handle)
        totals = report["totals"]
        self.assertEqual(totals["stable"]["mismatches"], 0)
        self.assertEqual(totals["havoc"]["mismatches"], 0)
        self.assertEqual(totals["stable"]["opcodes"], 237)
        self.assertEqual(totals["havoc"]["opcodes"], 7)
        self.assertEqual(totals["jam"]["opcodes"], 12)
        #: every opcode but the twelve JAMs reports the domains it exhausted
        for row in report["per_opcode"]:
            if row["group"] != "jam":
                self.assertTrue(row["domains"], row["opcode"])


if __name__ == "__main__":
    unittest.main()
