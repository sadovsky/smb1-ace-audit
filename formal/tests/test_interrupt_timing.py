"""Tests for `model/interrupt_timing`.

The module exists to turn two assumptions into derivations, so the tests that
matter are the ones that would catch it deriving them wrongly:

* the reachability search must agree with literal enumeration of every
  adversary strategy, or "exhaustive" is a claim and not a fact;
* the edge detector must latch on a transition and not on a level;
* the cycle shapes must come from the vectors and a disagreement among them
  must raise rather than be averaged away;
* a window containing a taken branch or a `BRK` must be refused, because
  NESdev documents a different poll point for both;
* each derivation must be *refuted* when its premise is dropped -- otherwise
  the premise is decoration and the status is misleading.

The image-dependent tests are skipped when the verified image is absent, and
the vector-dependent ones when the vectors are.
"""
from __future__ import annotations

import itertools
import json
import os
import tempfile
import unittest

from analysis.decoder import OPCODES, decode
from formal.model import interrupt_timing as it

try:
    from rom import b as read_rom_byte, image

    image()
    ROM, WHY = True, ""
except Exception as exc:                                  # pragma: no cover
    ROM, WHY = False, f"verified SMB1 ROM unavailable: {exc}"

VECTORS = it.DEFAULT_VECTORS


def step(cycles: int, **kwargs) -> it.Step:
    """A one-instruction step that polls at its second-to-last cycle."""
    return it.Step(kwargs.pop("name", f"{cycles}-cycle step"), cycles, True,
                   it._poll_cycle(cycles), **kwargs)


def window(*steps: it.Step, label: str = "synthetic") -> it.Window:
    return it.Window(label, steps, ())


# --------------------------------------------------------------------------
# the search
# --------------------------------------------------------------------------

class ExhaustivenessTest(unittest.TestCase):
    """The reachability search must equal literal strategy enumeration."""

    def _brute_force(self, win, initial, adversary, timing):
        """Every action sequence, one at a time, with no state merging."""
        cycles = it._flatten(win)
        found = set()
        for actions in itertools.product(adversary.actions(),
                                         repeat=len(cycles)):
            for start in initial:
                conf = start
                for descriptor, action in zip(cycles, actions):
                    conf, polled = it._step_cycle(conf, descriptor, action,
                                                  timing)
                    if polled:
                        found.add((descriptor["step"],
                                   descriptor["absolute"]))
        return found

    def test_search_agrees_with_literal_enumeration(self):
        win = window(step(4, ppuctrl_write_cycle=4,
                          ppuctrl_write_enables=True),
                     step(2))
        initial = it._initial_states(enable=(False, True), pending=True)
        adversary = it.Adversary(may_set=True, may_clear=True)
        for timing in it.ALL_TIMINGS:
            with self.subTest(timing=timing.label):
                exploration = it.explore(win, initial, adversary, timing)
                fast = {(s.after_step, s.poll_cycle)
                        for s in exploration.services}
                self.assertEqual(
                    fast, self._brute_force(win, initial, adversary, timing))

    def test_strategy_count_is_reported_honestly(self):
        win = window(step(3), step(3))
        adversary = it.Adversary(may_set=True, may_clear=True)
        initial = it._initial_states(enable=(False,), pending=False)
        exploration = it.explore(win, initial, adversary, it.ALL_TIMINGS[0])
        self.assertEqual(exploration.strategies_covered,
                         len(initial) * 3 ** 6)


class DetectorTest(unittest.TestCase):

    def _cycle(self, conf, timing=it.ALL_TIMINGS[0], action="none", **kwargs):
        descriptor = {"absolute": 1, "step": 0, "name": "", "last": False,
                      "poll": False, "write": None, "read_status": False,
                      "step_ends_on": 1}
        descriptor.update(kwargs)
        return it._step_cycle(conf, descriptor, action, timing)

    def test_latches_on_a_transition_not_a_level(self):
        """A line that is already low must not latch a fresh edge."""
        already = it.Conf(vblank=True, enable=True, line_low_prev=True,
                          flipflop=False, signal=False)
        nxt, _ = self._cycle(already)
        self.assertFalse(nxt.flipflop, "a steady low line latched an edge")

        rising = it.Conf(vblank=False, enable=True, line_low_prev=False,
                         flipflop=False, signal=False)
        nxt, _ = self._cycle(rising, action="set")
        self.assertTrue(nxt.flipflop, "a high->low transition did not latch")

    def test_falling_line_does_not_latch(self):
        low = it.Conf(vblank=True, enable=True, line_low_prev=True,
                      flipflop=False, signal=False)
        nxt, _ = self._cycle(low, action="clear")
        self.assertFalse(nxt.flipflop)
        self.assertFalse(nxt.line_low_prev)

    def test_signal_lags_the_flipflop_by_one_cycle(self):
        """"goes high during phi1 of the cycle that follows"."""
        conf = it.Conf(False, True, False, False, False)
        timing = it.Timing(write_visible_same_cycle=True,
                           detector_latency=True)
        after_edge, polled = self._cycle(conf, timing, "set", poll=True)
        self.assertTrue(after_edge.flipflop)
        self.assertFalse(polled, "the poll saw the edge in its own cycle")
        _, polled_next = self._cycle(after_edge, timing, "none", poll=True)
        self.assertTrue(polled_next, "the poll never saw the edge")

    def test_no_edge_while_disabled_is_exhaustive_and_clean(self):
        result = it.no_edge_while_disabled()
        self.assertEqual(result["edges_latched_with_nmi_output_clear"], 0)
        self.assertEqual(result["configurations_checked"],
                         2 * 2 * 2 * 2 * 3 * len(it.ALL_TIMINGS))

    def test_entry_sequence_polls_nothing(self):
        """A pending NMI must survive the entry sequence without being taken."""
        win = window(it.Step.entry_sequence())
        pending = [it.Conf(True, True, True, True, True)]
        for timing in it.ALL_TIMINGS:
            exploration = it.explore(win, pending,
                                     it.Adversary(True, True), timing)
            self.assertEqual(exploration.services, ())

    def test_line_low_prev_is_not_a_free_variable(self):
        for vblank, enable in itertools.product((False, True), repeat=2):
            conf = it.Conf.consistent(vblank, enable)
            self.assertEqual(conf.line_low_prev, vblank and enable)


# --------------------------------------------------------------------------
# cycle shapes
# --------------------------------------------------------------------------

class CycleShapeTest(unittest.TestCase):

    def _vector(self, pc, cycles):
        return {"name": "synthetic", "initial": {"pc": pc},
                "final": {}, "cycles": cycles}

    def test_disagreement_raises_rather_than_averaging(self):
        with tempfile.TemporaryDirectory() as directory:
            with open(os.path.join(directory, "8d.json"), "w") as handle:
                json.dump([
                    self._vector(0x1000, [[0x1000, 0x8D, "read"],
                                          [0x1001, 0x00, "read"],
                                          [0x1002, 0x20, "read"],
                                          [0x2000, 0x55, "write"]]),
                    self._vector(0x1000, [[0x1000, 0x8D, "read"],
                                          [0x1001, 0x00, "read"],
                                          [0x2000, 0x55, "write"]]),
                ], handle)
            with self.assertRaises(it.VectorError):
                it.cycle_shapes([0x8D], directory)

    def test_missing_vectors_raise(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(it.VectorError):
                it.cycle_shapes([0x8D], directory)

    def test_empty_file_raises(self):
        with tempfile.TemporaryDirectory() as directory:
            with open(os.path.join(directory, "8d.json"), "w") as handle:
                json.dump([], handle)
            with self.assertRaises(it.VectorError):
                it.cycle_shapes([0x8D], directory)

    def test_shape_is_read_from_the_cycles_field(self):
        with tempfile.TemporaryDirectory() as directory:
            with open(os.path.join(directory, "8d.json"), "w") as handle:
                json.dump([self._vector(0x1000, [[0x1000, 0x8D, "read"],
                                                 [0x1001, 0x00, "read"],
                                                 [0x1002, 0x20, "read"],
                                                 [0x2000, 0x55, "write"]])],
                          handle)
            shape = it.cycle_shapes([0x8D], directory)[0x8D]
        self.assertEqual((shape.cycles, shape.write_cycles,
                          shape.operand_cycles), (4, (4,), (4,)))

    @unittest.skipUnless(os.path.isdir(VECTORS), f"{VECTORS} absent")
    def test_real_vectors_give_the_shapes_the_derivations_use(self):
        shapes = it.cycle_shapes((0xAD, 0x29, 0x09, 0x8D, 0x40, 0x68),
                                 VECTORS)
        self.assertEqual((shapes[0x8D].cycles, shapes[0x8D].write_cycles),
                         (4, (4,)), "STA abs must write on its last cycle")
        self.assertEqual(shapes[0x40].cycles, 6)
        self.assertEqual(shapes[0xAD].cycles, 4)
        self.assertEqual(shapes[0xAD].operand_cycles, (4,))
        self.assertEqual(shapes[0x29].cycles, 2)
        self.assertEqual(shapes[0x09].cycles, 2)
        self.assertEqual(shapes[0x68].cycles, 4)
        for shape in shapes.values():
            self.assertGreaterEqual(shape.vectors, 300)


# --------------------------------------------------------------------------
# window construction
# --------------------------------------------------------------------------

def synthetic_reader(blob: bytes, base: int = 0x9000):
    prg = bytearray(0x8000)
    prg[base - 0x8000:base - 0x8000 + len(blob)] = blob
    return lambda address: prg[(address & 0xFFFF) - 0x8000]


class WindowTest(unittest.TestCase):

    def _shapes(self, *opcodes):
        return {opcode: it.CycleShape(opcode, 4, (4,) if OPCODES[opcode]
                                      .mnemonic == "STA" else (), (4,), 1)
                for opcode in opcodes}

    def test_taken_branch_is_refused(self):
        reader = synthetic_reader(bytes.fromhex("d0fe"))      # BNE $9000
        with self.assertRaises(it.WindowError) as caught:
            it.build_window(reader, 0x9000, label="x", count=1,
                            shapes=self._shapes(0xD0))
        self.assertIn("branch", str(caught.exception))

    def test_brk_is_refused(self):
        reader = synthetic_reader(bytes.fromhex("00"))
        with self.assertRaises(it.WindowError) as caught:
            it.build_window(reader, 0x9000, label="x", count=1,
                            shapes=self._shapes(0x00))
        self.assertIn("BRK", str(caught.exception))

    def test_undocumented_is_refused(self):
        reader = synthetic_reader(bytes.fromhex("0f0010"))    # SLO $1000
        with self.assertRaises(it.WindowError):
            it.build_window(reader, 0x9000, label="x", count=1,
                            shapes=self._shapes(0x0F))

    def test_a_ppuctrl_write_with_an_unknown_value_is_refused(self):
        """If the window does not determine bit 7, say so instead of guessing."""
        reader = synthetic_reader(bytes.fromhex("8d0020"))    # STA $2000
        with self.assertRaises(it.WindowError) as caught:
            it.build_window(reader, 0x9000, label="x",
                            stop_after_ppuctrl_write=True,
                            shapes=self._shapes(0x8D))
        self.assertIn("bit 7", str(caught.exception))

    def test_bit7_comes_from_the_images_own_masks(self):
        # LDA $0778 / AND #$7F / STA $0778 / AND #$7E / STA $2000
        blob = bytes.fromhex("ad7807" "297f" "8d7807" "297e" "8d0020")
        reader = synthetic_reader(blob)
        shapes = {0xAD: it.CycleShape(0xAD, 4, (), (4,), 1),
                  0x29: it.CycleShape(0x29, 2, (), (), 1),
                  0x8D: it.CycleShape(0x8D, 4, (4,), (4,), 1)}
        win = it.build_window(reader, 0x9000, label="x", shapes=shapes,
                              stop_after_ppuctrl_write=True)
        self.assertIs(win.steps[-1].ppuctrl_write_enables, False)

        # the same code with ORA #$80 instead must come out set
        blob = bytes.fromhex("ad7807" "0980" "8d0020")
        shapes[0x09] = it.CycleShape(0x09, 2, (), (), 1)
        win = it.build_window(synthetic_reader(blob), 0x9000, label="x",
                              shapes=shapes, stop_after_ppuctrl_write=True)
        self.assertIs(win.steps[-1].ppuctrl_write_enables, True)

    def test_poll_cycle_is_the_second_to_last(self):
        self.assertEqual(it._poll_cycle(2), 1)
        self.assertEqual(it._poll_cycle(4), 3)
        self.assertEqual(it._poll_cycle(6), 5)
        with self.assertRaises(ValueError):
            it._poll_cycle(1)


# --------------------------------------------------------------------------
# the derivations, on synthetic windows: each must fail without its premise
# --------------------------------------------------------------------------

class DerivationShapeTest(unittest.TestCase):
    """The STA-then-RTI argument, independent of the image."""

    def setUp(self):
        self.window = window(
            step(4, name="STA $2000", ppuctrl_write_cycle=4,
                 ppuctrl_write_enables=True),
            step(6, name="RTI"))
        self.adversary = it.Adversary(may_set=True, may_clear=True)

    def test_no_service_between_the_pair_when_the_enable_bit_starts_clear(self):
        initial = it._initial_states(enable=(False,), pending=False)
        for timing in it.ALL_TIMINGS:
            with self.subTest(timing=timing.label):
                exploration = it.explore(self.window, initial, self.adversary,
                                         timing)
                self.assertEqual(exploration.services_after(0), (),
                                 "an NMI was taken between the STA and the RTI")

    def test_the_nmi_does_arrive_after_the_rti(self):
        """Not vacuous: the deferred NMI is taken, one instruction late."""
        initial = it._initial_states(enable=(False,), pending=False)
        for timing in it.ALL_TIMINGS:
            exploration = it.explore(self.window, initial, self.adversary,
                                     timing)
            after = exploration.services_after(1)
            self.assertTrue(after)
            self.assertEqual(min(s.service_begins_cycle for s in after), 11)

    def test_refuted_when_the_enable_bit_may_start_set(self):
        initial = it._initial_states(enable=(False, True), pending=True)
        witnesses = []
        for timing in it.ALL_TIMINGS:
            witnesses.extend(it.explore(self.window, initial, self.adversary,
                                        timing).services_after(0))
        self.assertTrue(witnesses,
                        "dropping the premise changed nothing, so the premise "
                        "is decoration")
        self.assertEqual(min(s.poll_cycle for s in witnesses), 3)

    def test_edge_window_turns_on_whether_vblank_may_be_set(self):
        prologue = window(
            it.Step.entry_sequence(),
            step(4, name="LDA $0778"), step(2, name="AND #$7F"),
            step(4, name="STA $0778"), step(2, name="AND #$7E"),
            step(4, name="STA $2000", ppuctrl_write_cycle=4,
                 ppuctrl_write_enables=False))
        initial = it._initial_states(enable=(False, True), pending=False)
        self.assertEqual(prologue.cycles, 23)
        for timing in it.ALL_TIMINGS:
            with self.subTest(timing=timing.label):
                safe = it.explore(prologue, initial,
                                  it.Adversary(may_set=False, may_clear=True),
                                  timing)
                self.assertEqual(safe.services, ())
                self.assertFalse(safe.flipflop_set_at_window_end)
                unsafe = it.explore(prologue, initial,
                                    it.Adversary(may_set=True,
                                                 may_clear=True), timing)
                self.assertTrue(unsafe.services,
                                "P-EDGE-NO-SET is doing no work")


# --------------------------------------------------------------------------
# bit-7 provenance
# --------------------------------------------------------------------------

class ProvenanceTest(unittest.TestCase):

    def test_unhandled_instructions_give_unknown(self):
        reader = synthetic_reader(bytes.fromhex("8a"))        # TXA
        self.assertEqual(it._transfer(decode(reader, 0x9000), "clear"),
                         it.UNKNOWN)

    def test_masks_and_loads(self):
        def transfer(hexbytes, before):
            reader = synthetic_reader(bytes.fromhex(hexbytes))
            return it._transfer(decode(reader, 0x9000), before)

        self.assertEqual(transfer("297f", it.UNKNOWN), "clear")
        self.assertEqual(transfer("29f0", "set"), "set")
        self.assertEqual(transfer("0980", "clear"), "set")
        self.assertEqual(transfer("0901", "clear"), "clear")
        self.assertEqual(transfer("ad7807", "set"), "copy:$0778")
        self.assertEqual(transfer("4a", "set"), "clear")       # LSR A
        self.assertEqual(transfer("8d0020", "set"), "set")     # STA
        self.assertEqual(transfer("68", "clear"), it.UNKNOWN)  # PLA

    def test_join_is_a_lattice(self):
        self.assertEqual(it._join("clear", "clear"), "clear")
        self.assertEqual(it._join("clear", "set"), it.UNKNOWN)
        self.assertEqual(it._join("copy:$0778", "copy:$0778"), "copy:$0778")
        self.assertEqual(it._join("copy:$0778", "copy:$0779"), it.UNKNOWN)


# --------------------------------------------------------------------------
# on the real image
# --------------------------------------------------------------------------

@unittest.skipUnless(ROM, WHY)
@unittest.skipUnless(os.path.isdir(VECTORS), f"{VECTORS} absent")
class ImageTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.shapes = it.cycle_shapes((0xAD, 0x29, 0x09, 0x8D, 0x40, 0x68),
                                     VECTORS)

    def test_prologue_is_the_code_the_derivation_claims(self):
        win = it.build_window(read_rom_byte, it.NMI_HANDLER, label="p",
                              shapes=self.shapes,
                              stop_after_ppuctrl_write=True,
                              lead_in=it.Step.entry_sequence())
        self.assertEqual(
            [str(i) for i in win.instructions],
            ["LDA $0778", "AND #$7F", "STA $0778", "AND #$7E", "STA $2000"])
        self.assertEqual(win.cycles, 23)
        self.assertIs(win.steps[-1].ppuctrl_write_enables, False)
        self.assertEqual(win.steps[-1].ppuctrl_write_cycle, 4)

    def test_epilogue_is_the_code_the_derivation_claims(self):
        win = it.build_window(read_rom_byte, 0x8178, label="e",
                              shapes=self.shapes, count=5)
        self.assertEqual(
            [str(i) for i in win.instructions],
            ["LDA $2002", "PLA", "ORA #$80", "STA $2000", "RTI"])
        self.assertEqual(win.cycles, 20)
        self.assertIs(win.steps[-2].ppuctrl_write_enables, True)
        self.assertEqual(win.steps[-2].ppuctrl_write_cycle, 4)
        self.assertEqual(win.steps[0].ppustatus_read_cycle, 4)

    def test_latency_is_conditional_and_refuted_without_its_premise(self):
        result = it.derive_nmi_latency(read_rom_byte, shapes=self.shapes,
                                       vector_dir=VECTORS)
        self.assertEqual(result.status, "conditional")
        self.assertIn("P-LATENCY-DISABLED", result.premises)
        self.assertEqual(result.detail["answer_with_premise"], "no")
        self.assertEqual(result.detail["without_the_premise"]["status"],
                         "refuted")
        self.assertTrue(result.detail["without_the_premise"]["witnesses"])
        self.assertTrue(
            result.detail["verdict_identical_under_all_timing_parameters"])
        self.assertEqual(result.detail["rti_completes_on_absolute_cycle"], 20)
        self.assertEqual(
            set(result.detail["earliest_service_after_the_rti_completes"]
                .values()), {21})

    def test_edge_window_is_conditional_and_insensitive_to_the_entry_length(
            self):
        result = it.derive_nmi_edge_window(read_rom_byte, shapes=self.shapes,
                                           vector_dir=VECTORS)
        self.assertEqual(result.status, "conditional")
        self.assertIn("P-EDGE-NO-SET", result.premises)
        self.assertEqual(result.detail["answer_with_premise"], "no")
        self.assertTrue(result.detail[
            "verdict_identical_for_entry_sequence_lengths_1_to_12"])
        self.assertEqual(result.detail["without_the_premise"]["status"],
                         "refuted")
        self.assertTrue(all(
            not pending for pending
            in result.detail["nmi_pending_at_window_end"].values()))

    def test_disabled_half_is_proved_without_premises(self):
        result = it.derive_nmi_edge_disabled()
        self.assertEqual(result.status, "proved")
        self.assertEqual(result.premises, ())

    def test_every_premise_is_used_or_absent(self):
        results = [it.derive_nmi_latency(read_rom_byte, shapes=self.shapes,
                                         vector_dir=VECTORS),
                   it.derive_nmi_edge_window(read_rom_byte,
                                             shapes=self.shapes,
                                             vector_dir=VECTORS),
                   it.derive_nmi_edge_disabled()]
        for result in results:
            for key in result.premises:
                self.assertIn(key, it.PREMISES)
        for premise in it.PREMISES.values():
            self.assertIn(premise.sourcing,
                          ("stated", "implied", "silent", "program",
                           "vectors"))
        # the one premise the derivations do NOT need must say so
        self.assertEqual(it.PREMISES["P-ENABLE-IMMEDIATE-EDGE"].sourcing,
                         "silent")
        self.assertNotIn(
            "P-ENABLE-IMMEDIATE-EDGE",
            {key for result in results for key in result.premises})


@unittest.skipUnless(ROM, WHY)
class CensusTest(unittest.TestCase):
    """The program side: who can raise the enable bit."""

    @classmethod
    def setUpClass(cls):
        cls.census = it.ppuctrl_write_census(read_rom_byte)

    def test_the_known_ppuctrl_writes_are_found(self):
        found = {entry["at"] for entry in self.census["direct_ppuctrl_writes"]}
        self.assertEqual(found, {"$8004", "$808C", "$816C", "$817E", "$8EED"})

    def test_provenance_of_the_two_handler_writes(self):
        provenance = self.census["enable_bit_provenance"]
        self.assertEqual(provenance["$808C"]["bit7_of_the_value_written"],
                         "clear")
        self.assertEqual(provenance["$817E"]["bit7_of_the_value_written"],
                         "set")
        self.assertEqual(provenance["$816C"]["bit7_of_the_value_written"],
                         "copy:$0778")

    def test_the_handler_body_does_reach_a_ppuctrl_write(self):
        """The finding this census exists for: $8EED is reachable from $8212."""
        inside = self.census[
            "provenance_of_the_sites_the_handler_body_reaches"]
        self.assertIn("$8E23", inside)
        self.assertEqual(inside["$8E23"]["bit7_of_the_value_written"],
                         "copy:$0778")

    def test_the_pointer_stores_are_reported_as_open(self):
        pointers = self.census["writes_through_a_RAM_pointer"]
        self.assertTrue(pointers)
        self.assertTrue(any(entry["reachable_from_the_handler_body"]
                            for entry in pointers))
        self.assertIn("not bounded here", self.census["open"])


@unittest.skipUnless(
    os.path.exists(os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "results", "reports",
        "interrupt_timing.json")),
    "report not generated yet")
class ReportTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "results", "reports",
            "interrupt_timing.json")
        with open(path) as handle:
            cls.report = json.load(handle)

    def test_statuses_are_from_the_allowed_set(self):
        for result in self.report["results"]:
            self.assertIn(result["status"],
                          ("proved", "conditional", "refuted"))

    def test_a_conditional_result_names_at_least_one_premise(self):
        for result in self.report["results"]:
            if result["status"] == "conditional":
                self.assertTrue(result["premises"])

    def test_a_proved_result_names_none(self):
        for result in self.report["results"]:
            if result["status"] == "proved":
                self.assertEqual(result["premises"], [])

    def test_the_report_says_what_is_not_validated(self):
        text = " ".join(self.report["not_validated"])
        self.assertIn("hardware measurement", text)
        self.assertIn("dot", text)

    def test_validation_counts_are_present(self):
        validation = self.report["validation"]
        self.assertEqual(validation["disagreements"], 0)
        self.assertGreaterEqual(validation["vectors_read"], 300)
        self.assertIn("cycles", validation["field_compared"])

    def test_every_rule_carries_a_sourcing_verdict(self):
        for rule in self.report["cycle_model"]["rules"]:
            self.assertTrue(rule["rule"])
            self.assertTrue(rule["sourcing"])


if __name__ == "__main__":
    unittest.main()
