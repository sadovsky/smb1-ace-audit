"""Tests for the bounded forward execution in `properties/bounded`.

Three kinds, as elsewhere in the track:

* negative tests on synthetic images, which are the point: a program that
  leaves the recovered instruction starts inside the horizon must be
  *reported*, with the address and with what the model needs to get there --
  once for a concrete off-graph target and once for a program counter computed
  out of device reads.  A loop the summariser cannot close soundly must leave
  the path `unknown`, never silently capped at some iteration count;
* unit tests on the closures, which are where the soundness of a bounded run
  lives: the inductiveness check must refuse a generalisation that is not
  inductive, exact repeats must close, and a warm reset must only be subsumed
  while the ghost NMI-enable bit is clear;
* the handover between the phases, on an image that enables NMI and idles:
  phase 1 must stop at the enabling write rather than choose a successor for
  the interrupt, and phase 2 must take the interrupt, follow the handler
  through its `RTI`, and close the idle loop instead of capping it;
* a ROM-dependent smoke test, skipped when the verified image is absent,
  which checks the first few hundred boundaries of the real run and nothing
  more.  The full run is `python3 -m formal.properties.bounded`.

Passing tests show the engine behaves. They are not proofs about the game.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from dataclasses import replace

import z3

from analysis.cfg import CFG
from formal.model.transitions import Machine, cold_boot
from formal.properties import bounded
from formal.properties.common import Context
from formal.verify.obligations import Ledger

try:
    from rom import image

    image()
    ROM, WHY = True, ""
except Exception as exc:                              # pragma: no cover
    ROM, WHY = False, "verified SMB1 ROM unavailable: {}".format(exc)


# LDA $2000 / BPL $8000 / JMP $8005: a wait on a device read, then an idle
# loop.  Every fetch is an instruction start, and neither loop terminates for
# an adversarial device, so both have to be closed without a cap.
WAIT = bytes.fromhex("ad0020" "10fb" "4c0580")
# JMP $4000: one instruction, straight off the graph.
OFF_GRAPH = bytes.fromhex("4c0040")
# LDA $2000 / STA $06 / LDA $2000 / STA $07 / JMP ($0006): the program counter
# is two device reads.
INDIRECT = bytes.fromhex("ad0020" "8506" "ad0020" "8507" "6c0600")
# LDA $2000 / STA $0300 / JMP $8000: a loop whose body writes RAM, so the
# summariser must refuse it and the path must end `unknown`.
WRITING_LOOP = bytes.fromhex("ad0020" "8d0003" "4c0080")
# LDA $2000 / JAM
HALTING = bytes.fromhex("ad0020" "02")


# LDA #$80 / STA $2000 / JMP $8005, with an NMI handler at $9000 that reads a
# device and returns: the ghost NMI-enable bit goes up, so phase 1 stops and
# phase 2 has an interrupt to take.
ENABLES_NMI = bytes.fromhex("a980" "8d0020" "4c0580")
HANDLER = bytes.fromhex("ad0020" "40")


def fixture(blob: bytes, base: int = 0x8000, vector: int = 0x8000,
            nmi: bytes = b"", nmi_at: int = 0x9000) -> Context:
    """A 32 KiB image that is zero except for `blob`, with a reset vector."""
    prg = bytearray(0x8000)
    prg[base - 0x8000:base - 0x8000 + len(blob)] = blob
    prg[0x7FFC], prg[0x7FFD] = vector & 0xFF, vector >> 8
    if nmi:
        prg[nmi_at - 0x8000:nmi_at - 0x8000 + len(nmi)] = nmi
        prg[0x7FFA], prg[0x7FFB] = nmi_at & 0xFF, nmi_at >> 8
    prg = bytes(prg)
    graph = CFG(lambda a: prg[(a & 0xFFFF) - 0x8000])
    graph.add_entry(vector, "reset vector")
    if nmi:
        graph.add_entry(nmi_at, "nmi vector")
    graph.build()
    return Context(prg, "synthetic", graph)


def execute(ctx: Context, **kwargs) -> bounded.Report:
    engine = bounded.Engine(ctx, phase=1, **kwargs)
    engine.run([bounded.Path(cold_boot(ctx.prg), label="boot")])
    return engine.report


def closures(report: bounded.Report, kind: str) -> list:
    return [s for s in report.summaries if s.kind == kind]


class HelperTests(unittest.TestCase):
    def test_runs_merges_only_consecutive_addresses(self):
        self.assertEqual(bounded.runs([5, 6, 7, 9, 20, 21]),
                         [(5, 7), (9, 9), (20, 21)])

    def test_in_runs_is_exactly_membership(self):
        members = {0x8000, 0x8001, 0x8002, 0x9000, 0xFFF0}
        term = z3.BitVec("pc", 16)
        claim = bounded.in_runs(term, bounded.runs(members))
        explicit = z3.Or(*[term == z3.BitVecVal(m, 16) for m in members])
        solver = z3.Solver()
        solver.add(claim != explicit)
        self.assertEqual(solver.check(), z3.unsat)

    def test_same_is_structural_and_sort_aware(self):
        self.assertTrue(bounded.same(z3.BitVec("a", 8), z3.BitVec("a", 8)))
        self.assertFalse(bounded.same(z3.BitVec("a", 8), z3.BitVec("b", 8)))
        self.assertFalse(bounded.same(z3.BitVec("a", 8), z3.Bool("a")))
        self.assertTrue(bounded.same(3, 3))
        self.assertFalse(bounded.same(3, z3.BitVecVal(3, 8)))


class ShapeTests(unittest.TestCase):
    def test_the_fixtures_decode_as_intended(self):
        self.assertEqual(sorted(fixture(WAIT).graph.nodes),
                         [0x8000, 0x8003, 0x8005])
        self.assertEqual(sorted(fixture(INDIRECT).graph.nodes),
                         [0x8000, 0x8003, 0x8005, 0x8008, 0x800A])
        self.assertEqual(sorted(fixture(OFF_GRAPH).graph.nodes), [0x8000])


class HonestProgramTests(unittest.TestCase):
    """A program that stays on the graph must come back clean."""

    def setUp(self):
        self.report = execute(fixture(WAIT), step_budget=200)

    def test_nothing_is_reported(self):
        self.assertEqual(self.report.violations, [])
        self.assertEqual(self.report.findings, [])
        self.assertEqual(self.report.cut_paths, 0)
        self.assertEqual(bounded.status_of(self.report,
                                           horizon_is_complete=True),
                         "bounded")

    def test_the_device_wait_is_closed_by_a_proved_summary(self):
        summarised = closures(self.report, "summarised")
        self.assertEqual([s.head for s in summarised], [0x8000])
        summary = summarised[0]
        self.assertEqual(summary.body, (0x8000, 0x8003))
        self.assertEqual(summary.generalised, ("a", "z", "n"))
        self.assertGreaterEqual(summary.back_edges, 1)
        self.assertGreaterEqual(summary.exits, 1)

    def test_the_idle_loop_is_closed_by_subsumption(self):
        self.assertEqual({s.head for s in closures(self.report, "subsumed")},
                         {0x8005})
        self.assertIn("closed: the state repeats term for term",
                      self.report.paths_closed)

    def test_every_warm_reset_met_was_closed_by_subsumption(self):
        # every boundary offers one, except those a loop summary replaced,
        # where `summarise_loop` makes the same check on the body
        self.assertGreaterEqual(self.report.resets_subsumed, 1)
        self.assertEqual(self.report.resets_not_followed, 0)


class OffGraphTests(unittest.TestCase):
    """The negative test: a fetch off the graph inside the horizon."""

    def setUp(self):
        self.report = execute(fixture(OFF_GRAPH))

    def test_the_violation_is_reported_with_its_address(self):
        self.assertEqual(len(self.report.violations), 1)
        violation = self.report.violations[0]
        self.assertEqual(violation["status"], "abstract_counterexample")
        self.assertEqual(violation["fetch_from"], "$8000")
        self.assertEqual(violation["successor_pc"], "$4000")
        self.assertEqual(violation["transition"], "jump")
        self.assertTrue(violation["path_condition_satisfiable"])
        self.assertEqual(violation["query_answer"], "sat")
        self.assertTrue(violation["query_sha256"])

    def test_the_path_is_cut_not_closed(self):
        self.assertEqual(self.report.paths_closed,
                         {"cut: counterexample": 1})
        self.assertEqual(bounded.status_of(self.report,
                                           horizon_is_complete=True),
                         "abstract_counterexample")

    def test_no_spuriousness_warning_on_a_concrete_path(self):
        self.assertNotIn("witness_may_be_spurious", self.report.violations[0])


class SymbolicProgramCounterTests(unittest.TestCase):
    """A program counter computed out of device reads must be reported."""

    def setUp(self):
        self.report = execute(fixture(INDIRECT))

    def test_the_violation_names_the_device_reads_it_needs(self):
        self.assertEqual(len(self.report.violations), 1)
        violation = self.report.violations[0]
        self.assertEqual(violation["fetch_from"], "$800A")
        self.assertEqual(violation["transition"], "indirect_jump")
        reads = violation["needs"]["device_reads"]
        self.assertEqual(len(reads), 2, reads)
        self.assertTrue(all(name.startswith("bus_2000") for name in reads),
                        reads)

    def test_the_target_is_really_off_the_graph(self):
        reads = self.report.violations[0]["needs"]["device_reads"]
        low, high = (int(reads[name]) for name in sorted(reads))
        self.assertNotIn(low | high << 8, set(fixture(INDIRECT).graph.nodes))


class LoopsAreNeverSilentlyCappedTests(unittest.TestCase):
    def test_a_loop_whose_body_writes_memory_is_unrolled_then_cut(self):
        report = execute(fixture(WRITING_LOOP), step_budget=40)
        self.assertEqual(report.violations, [])
        self.assertEqual(closures(report, "summarised"), [])
        self.assertEqual(report.paths_closed,
                         {"cut: step budget exhausted": 1})
        self.assertEqual(bounded.status_of(report, horizon_is_complete=True),
                         "unknown")
        self.assertEqual(report.depth_bound, 40)
        # the same run judged as a depth-bounded claim: the cut path is the
        # bound, not a hole below it, and the bound is what it reached
        self.assertEqual(bounded.status_of(report, horizon_is_complete=False),
                         "bounded")

    def test_an_unsound_generalisation_is_refused(self):
        """The inductiveness check is what makes a summary a proof."""
        ctx = fixture(WAIT)
        engine = bounded.Engine(ctx, phase=1)
        (path,) = engine.advance(bounded.Path(cold_boot(ctx.prg)))
        self.assertEqual(path.machine.cpu.pc, 0x8003)
        # keep the engine from summarising the loop on its own, so the state
        # at the back edge can be handed to the check directly
        path.refused.add((0x8000, ("a", "z", "n")))
        back = [p for p in engine.advance(path)
                if p.machine.cpu.pc == 0x8000]
        self.assertEqual(len(back), 1)
        earlier = back[0].visits[0x8000]
        honest, exits = engine.summarise_loop(back[0], earlier,
                                              ("a", "z", "n"))
        self.assertEqual(honest.kind, "summarised", honest.reason)
        self.assertTrue(exits)
        # the device read also changes Z and N, so generalising A alone is not
        # inductive and must be refused rather than assumed
        narrow, nothing = engine.summarise_loop(back[0], earlier, ("a",))
        self.assertEqual(narrow.kind, "refused")
        self.assertIn("instance of the generalisation", narrow.reason)
        self.assertEqual(nothing, [])

    def test_halting_closes_a_path_without_a_cap(self):
        report = execute(fixture(HALTING), step_budget=20)
        self.assertEqual(report.violations, [])
        self.assertEqual(
            report.paths_closed,
            {"closed: halted, the processor fetches nothing more": 1})


class WarmResetTests(unittest.TestCase):
    def setUp(self):
        self.ctx = fixture(WAIT)
        self.engine = bounded.Engine(self.ctx, phase=1)
        self.machine = cold_boot(self.ctx.prg)

    def test_a_reset_with_the_bit_clear_is_a_cold_boot_instance(self):
        self.assertTrue(self.engine.subsumed_reset(self.machine))

    def test_a_reset_with_the_bit_set_is_not(self):
        enabled = Machine(self.machine.cpu, z3.BoolVal(True))
        self.assertFalse(self.engine.subsumed_reset(enabled))

    def test_nor_is_one_whose_i_flag_is_not_provably_set(self):
        open_irq = Machine(replace(self.machine.cpu, i=z3.Bool("i")),
                           z3.BoolVal(False))
        self.assertFalse(self.engine.subsumed_reset(open_irq))

    def test_nor_is_one_that_is_not_at_the_reset_vector(self):
        elsewhere = Machine(replace(self.machine.cpu, pc=0x9000),
                            z3.BoolVal(False))
        self.assertFalse(self.engine.subsumed_reset(elsewhere))

    def test_the_lemma_is_checked_against_an_unconstrained_state(self):
        check, structural, vector = bounded.reset_lemma(self.ctx)
        self.assertTrue(check.valid, check)
        self.assertEqual(vector, 0x8000)
        self.assertTrue(all(structural.values()), structural)


class LedgerTests(unittest.TestCase):
    """`run` must put the engine's verdict in the ledger, good or bad."""

    def ledger_for(self, blob: bytes) -> Ledger:
        ledger = Ledger()
        saved, handle = bounded.REPORT, tempfile.mkdtemp()
        bounded.REPORT = os.path.join(handle, "bounded.json")
        try:
            bounded.run(ledger, fixture(blob))
            with open(bounded.REPORT) as stream:
                self.written = json.load(stream)
        finally:
            bounded.REPORT = saved
        return ledger

    def test_a_clean_program_is_bounded(self):
        ledger = self.ledger_for(WAIT)
        self.assertEqual(ledger.items["BOUNDED-P1-RESET"].status, "bounded")
        self.assertEqual(self.written["phase1"]["violations"], [])
        self.assertEqual(self.written["statuses"]["BOUNDED-P1-RESET"],
                         "bounded")

    def test_a_violating_program_is_an_abstract_counterexample(self):
        ledger = self.ledger_for(OFF_GRAPH)
        item = ledger.items["BOUNDED-P1-RESET"]
        self.assertEqual(item.status, "abstract_counterexample")
        self.assertEqual(len(item.detail["violations"]), 1)
        self.assertEqual(item.detail["violations"][0]["successor_pc"],
                         "$4000")

    def test_the_reset_lemma_is_recorded_and_the_window_depends_on_it(self):
        ledger = self.ledger_for(WAIT)
        self.assertEqual(ledger.items["BOUNDED-RESET"].status, "proved")
        self.assertIn("BOUNDED-RESET",
                      ledger.items["BOUNDED-P1-RESET"].dependencies)

    def test_no_result_carries_a_slice_assumption(self):
        ledger = self.ledger_for(WAIT)
        for key in ("BOUNDED-P1-RESET", "BOUNDED-P1-NMI"):
            text = " ".join(ledger.items[key].assumptions)
            for assumption in ("J-LOCATION", "J-ASYNC", "J-STACK", "J-IRQ"):
                self.assertNotIn(assumption, text)


class InterruptTests(unittest.TestCase):
    """Phase 1 must stop where the ghost bit goes up; phase 2 must go on."""

    def setUp(self):
        self.ctx = fixture(ENABLES_NMI, nmi=HANDLER)
        self.first = bounded.phase1(self.ctx)
        self.second = bounded.phase2(self.ctx, self.first.seeds)

    def test_phase_one_stops_at_the_enabling_write(self):
        report = self.first.report
        self.assertEqual(report.violations, [])
        self.assertEqual(len(self.first.seeds), 1)
        self.assertEqual(report.window_ends[0]["boundary"], "$8005")
        self.assertEqual(
            report.paths_closed,
            {"closed: ghost NMI-enable bit set (end of the window)": 1})
        # no NMI is admitted inside the window, so none was skipped either
        self.assertEqual(report.nmi_boundaries, 0)
        self.assertEqual(report.nmi_not_followed, 0)

    def test_phase_two_takes_the_interrupt_and_follows_the_handler(self):
        report = self.second.report
        self.assertEqual(report.violations, [])
        self.assertEqual(report.nmi_followed, 1)
        self.assertEqual(report.nmi_entries[0]["boundary"], "$8005")
        self.assertEqual(report.nmi_entries[0]["handler"], "$9000")
        self.assertIn(0x9000, report.distinct_starts)
        self.assertIn(0x9003, report.distinct_starts)      # the RTI
        self.assertGreaterEqual(report.nmi_not_followed, 1)

    def test_phase_two_closes_the_idle_loop_rather_than_capping_it(self):
        report = self.second.report
        self.assertGreaterEqual(report.successors_subsumed, 1)
        self.assertEqual(report.cut_paths, 0)
        self.assertEqual(bounded.status_of(report, horizon_is_complete=False),
                         "bounded")

    def test_a_warm_reset_after_the_enabling_write_is_out_of_scope(self):
        # the model carries the ghost bit through reset, so these successors
        # cannot be closed by the cold-boot predicate and are not followed
        self.assertEqual(self.first.report.resets_not_followed, 0)
        self.assertGreaterEqual(self.second.report.resets_not_followed, 1)
        self.assertEqual(self.second.report.resets_subsumed, 0)


@unittest.skipUnless(ROM, WHY)
class RomSmokeTests(unittest.TestCase):
    """A few hundred boundaries of the real run; the rest is the module CLI."""

    @classmethod
    def setUpClass(cls):
        from formal.properties.common import context

        cls.ctx = context()
        cls.report = execute(cls.ctx, step_budget=400)

    def test_nothing_leaves_the_graph_in_the_first_boundaries(self):
        self.assertEqual(self.report.violations, [])
        self.assertEqual(self.report.findings, [])
        self.assertTrue(self.report.distinct_starts
                        <= set(self.ctx.graph.nodes))

    def test_the_two_vblank_waits_are_summarised(self):
        heads = {s.head for s in closures(self.report, "summarised")}
        self.assertLessEqual({0x800A, 0x800F}, heads)
        for summary in closures(self.report, "summarised"):
            if summary.head in (0x800A, 0x800F):
                self.assertEqual(summary.generalised, ("a", "z", "n"))
                self.assertGreaterEqual(summary.back_edges, 1)

    def test_no_interrupt_is_admitted_that_early(self):
        self.assertEqual(self.report.boundaries_admitting_irq, 0)
        self.assertEqual(self.report.nmi_boundaries, 0)

    def test_the_budget_cut_is_reported_as_unknown(self):
        self.assertEqual(self.report.paths_closed.get(
            "cut: step budget exhausted", 0), self.report.cut_paths)
        self.assertGreaterEqual(self.report.cut_paths, 1)
        self.assertEqual(bounded.status_of(self.report,
                                           horizon_is_complete=True),
                         "unknown")


if __name__ == "__main__":                            # pragma: no cover - CLI
    unittest.main()
