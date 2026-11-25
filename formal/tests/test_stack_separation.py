"""Tests for the return-frame separation module.

The infrastructure tests run on synthetic images, so they need no ROM, and
each positive test has a negative twin: the point of a negative twin is that
the method must *fail* to prove a bound the program does not have.  A method
that says yes to everything would pass every positive test here.

The ROM-dependent tests check the saved report against a fresh run of the
cheap half of the module, and are skipped when the verified image is absent.
"""
from __future__ import annotations

import json
import os
import unittest

import z3

from analysis.cfg import CFG
from formal.properties import stack_separation as sep
from formal.properties.common import Context
from formal.verify.obligations import Ledger
from formal.verify.symexec import Slicer

try:
    from rom import image

    image()
    ROM, WHY = True, ""
except Exception as exc:                                  # pragma: no cover
    ROM, WHY = False, f"verified SMB1 ROM unavailable: {exc}"


def synthetic(blob: bytes, base: int = 0x9000, *, entries=()) -> Context:
    """A 32 KiB image that is zero except for `blob` at `base`.

    The reset vector is made to point at `base` so the graph has one entry and
    `Context.read` works; everything outside the blob decodes as `BRK`, which
    the graph records as an interrupt edge rather than walking on.
    """
    prg = bytearray(0x8000)
    prg[base - 0x8000:base - 0x8000 + len(blob)] = blob
    prg[0xFFFC - 0x8000] = base & 0xFF
    prg[0xFFFD - 0x8000] = base >> 8
    prg = bytes(prg)
    read = lambda a: prg[(a & 0xFFFF) - 0x8000]
    graph = CFG(read, code_range=(base, base + len(blob)))
    graph.add_entry(base, "test entry")
    for entry in entries:
        graph.add_entry(entry, "test entry")
    return Context(prg, "synthetic", graph.build())


#: LDX #count / loop: STA $0130,X / DEX / BPL loop / RTS
def counted_loop(count: int) -> bytes:
    return bytes([0xA2, count,                 # LDX #count
                  0x9D, 0x30, 0x01,            # STA $0130,X
                  0xCA,                        # DEX
                  0x10, 0xFB,                  # BPL -5
                  0x60])                       # RTS


WRITER = 0x9002                                # the STA in counted_loop


class OneStepBoundTests(unittest.TestCase):
    def test_absolute_store_is_bounded_by_its_own_operand(self):
        ctx = synthetic(bytes([0x8D, 0x0D, 0x01, 0x60]))      # STA $010D
        self.assertEqual(sep.tightest_bound(0x9000, ctx.prg), 0x0D)
        self.assertTrue(sep.holds_in_one_step(0x9000, ctx.prg, 0x0D))

    def test_a_store_above_the_target_is_not_claimed(self):
        ctx = synthetic(bytes([0x8D, 0x90, 0x01, 0x60]))      # STA $0190
        self.assertEqual(sep.tightest_bound(0x9000, ctx.prg), 0x90)
        self.assertFalse(sep.holds_in_one_step(0x9000, ctx.prg, sep.TARGET))

    def test_a_mirror_of_the_stack_page_is_bounded_by_its_offset(self):
        ctx = synthetic(bytes([0x8D, 0x39, 0x09, 0x60]))      # STA $0939
        self.assertEqual(sep.tightest_bound(0x9000, ctx.prg), 0x39)

    def test_an_indexed_store_has_no_bound_without_a_hypothesis(self):
        ctx = synthetic(counted_loop(5))
        self.assertEqual(sep.tightest_bound(WRITER, ctx.prg), 0xFF)

    def test_the_index_hypothesis_needed_is_derived_from_the_model(self):
        ctx = synthetic(counted_loop(5))
        # base $0130: offset <= $39 needs X <= 9, and Y does not matter.
        self.assertEqual(
            sep.weakest_index_bound(WRITER, ctx.prg, "x", 0x39), 9)
        self.assertIsNone(
            sep.weakest_index_bound(WRITER, ctx.prg, "y", 0x39))

    def test_a_pointer_store_is_bounded_by_no_register(self):
        ctx = synthetic(bytes([0x91, 0x06, 0x60]))            # STA ($06),Y
        for register in ("x", "y"):
            self.assertIsNone(
                sep.weakest_index_bound(0x9000, ctx.prg, register, 0x39))


class IndexInvariantTests(unittest.TestCase):
    def prove(self, count: int, bound: int):
        ctx = synthetic(counted_loop(count))
        hypothesis = sep.Hypothesis(
            f"X <= 0x{bound - 0x30:02X}",
            lambda s, k=bound - 0x30: z3.ULE(s.x, k), {WRITER}, "test", bound)
        return sep.try_hypothesis(ctx, WRITER, hypothesis)

    def test_a_dex_loop_closes_at_its_initial_value(self):
        result = self.prove(5, 0x35)
        self.assertTrue(result["proved"], result)
        self.assertEqual(result["cuts"], [WRITER])

    def test_the_same_loop_one_wider_is_not_proved(self):
        """The negative twin: `LDX #$70` really can write $01A0."""
        result = self.prove(0x70, 0x35)
        self.assertFalse(result["proved"], result)
        self.assertTrue(result["failures"])

    def test_an_unbounded_entry_is_reported_not_assumed(self):
        """X comes from outside the graph, so nothing bounds it."""
        #  loop: STA $0130,X / DEX / BPL loop / RTS   -- no LDX
        ctx = synthetic(bytes([0x9D, 0x30, 0x01, 0xCA, 0x10, 0xFB, 0x60]))
        hypothesis = sep.Hypothesis("X <= 5", lambda s: z3.ULE(s.x, 5),
                                    {0x9000}, "test", 0x35)
        result = sep.try_hypothesis(ctx, 0x9000, hypothesis)
        self.assertFalse(result["proved"], result)
        self.assertIn("graph entry", json.dumps(result["failures"]))


class CauseTests(unittest.TestCase):
    """The open writers are only useful if the reason given is the real one."""

    def test_a_rom_table_read_is_recognised(self):
        #  LDA $9100,Y  -- a ROM base, so the address is symbolic in PRG
        ctx = synthetic(bytes([0xB9, 0x00, 0x91, 0x60]))
        self.assertTrue(sep.reads_rom_symbolically(ctx, 0x9000))

    def test_an_immediate_and_a_ram_read_are_not_rom_tables(self):
        ctx = synthetic(bytes([0xA9, 0x05, 0xB9, 0x10, 0x00, 0x60]))
        self.assertFalse(sep.reads_rom_symbolically(ctx, 0x9000))  # LDA #$05
        self.assertFalse(sep.reads_rom_symbolically(ctx, 0x9002))  # LDA $0010,Y

    def test_a_call_boundary_in_a_suffix_is_found(self):
        #  $9000 JSR $9005 / $9003 NOP / ...  $9005 RTS
        ctx = synthetic(bytes([0x20, 0x05, 0x90, 0xEA, 0xEA, 0x60]))
        self.assertEqual(sep.crossed_call_in(ctx, [0x9000, 0x9003]), "0x9000")
        self.assertIsNone(sep.crossed_call_in(ctx, [0x9003, 0x9004]))

    def test_a_budget_failure_outranks_a_slice_failure(self):
        attempts = [{"failures": [
            {"part": "invariant", "cut_point": "0x9000", "from": "0x9002",
             "edge": "branch", "reason": "still satisfiable at depth 16",
             "suffix": []},
            {"part": "budget", "cut_point": "", "from": "", "edge": "",
             "reason": "time budget exhausted", "suffix": []}]}]
        ctx = synthetic(counted_loop(5))
        self.assertEqual(
            sep.cause(ctx, WRITER, attempts, True)["kind"], "budget")


class ClearLoopTests(unittest.TestCase):
    def test_a_routine_called_from_two_entries_lists_both_sites(self):
        #  $9000 JSR $900A / RTS      (entry one)
        #  $9004 NOP NOP NOP NOP      (filler)
        #  $900A STA $0130 / RTS      (the writer's routine)
        blob = bytes([0x20, 0x0A, 0x90, 0x60,
                      0x20, 0x0A, 0x90, 0x60, 0xEA, 0xEA,
                      0x8D, 0x30, 0x01, 0x60])
        ctx = synthetic(blob, entries=(0x9004,))
        ledger = Ledger()
        sep.clear_loop_reach(ledger, ctx, 0x900A)
        detail = ledger.items["SEP-CLEAR-LOOP-REACH"].detail
        self.assertEqual(sorted(detail["call_sites"]), ["0x9000", "0x9004"])
        self.assertEqual(detail["containing_routines"], ["0x900A"])


class StackDeltaTests(unittest.TestCase):
    def test_deltas_come_out_of_the_model(self):
        #  PHA / PLA / JSR $9010 / RTS / RTI / TXS / NOP
        ctx = synthetic(bytes([0x48, 0x68, 0x20, 0x10, 0x90, 0x60, 0x40,
                               0x9A, 0xEA]),
                        entries=(0x9006, 0x9007))
        deltas, assigns = sep.stack_deltas(ctx)
        self.assertEqual(deltas[0x9000], -1)           # PHA
        self.assertEqual(deltas[0x9001], +1)           # PLA
        self.assertEqual(deltas[0x9002], -2)           # JSR
        self.assertEqual(deltas[0x9005], +2)           # RTS
        self.assertEqual(deltas[0x9006], +3)           # RTI
        self.assertEqual(assigns, [0x9007])            # TXS

    def test_an_interrupt_frame_is_three_bytes(self):
        ctx = synthetic(bytes([0xEA, 0x60]))
        self.assertEqual(sep._interrupt_frame(ctx), 3)


class DepthTests(unittest.TestCase):
    def analysis(self, ctx: Context, limit: int = 2, recursive=frozenset()):
        deltas, assigns = sep.stack_deltas(ctx)
        return sep.Depth(ctx, deltas, frozenset(assigns), recursive, limit)

    def test_a_push_in_a_called_routine_is_counted_once(self):
        #  $9000 JSR $9004 / RTS       $9004 PHA / PHA / PLA / PLA / RTS
        blob = bytes([0x20, 0x04, 0x90, 0x60,
                      0x48, 0x48, 0x68, 0x68, 0x60])
        ctx = synthetic(blob)
        self.assertEqual(self.analysis(ctx).cost(0x9004), 2)
        self.assertEqual(self.analysis(ctx).cost(0x9000), 4)

    def test_an_unbalanced_return_is_reported(self):
        #  $9000 PHA / RTS  -- returns one byte deep
        ctx = synthetic(bytes([0x48, 0x60]))
        analysis = self.analysis(ctx)
        analysis.cost(0x9000)
        self.assertEqual([u["local_depth"] for u in analysis.unbalanced], [1])

    def test_an_unbalanced_loop_has_no_bound(self):
        #  $9000 PHA / JMP $9000
        ctx = synthetic(bytes([0x48, 0x4C, 0x00, 0x90]))
        analysis = self.analysis(ctx)
        self.assertIsNone(analysis.cost(0x9000))
        self.assertTrue(any("depth cap" in n for n in analysis.notes))

    def test_a_stack_pointer_assignment_has_no_bound(self):
        #  $9000 TXS / RTS
        ctx = synthetic(bytes([0x9A, 0x60]))
        analysis = self.analysis(ctx)
        self.assertIsNone(analysis.cost(0x9000))
        self.assertTrue(any("assigns" in n for n in analysis.notes))

    def test_recursion_is_detected_in_the_call_graph(self):
        #  $9000 JSR $9000 / RTS
        ctx = synthetic(bytes([0x20, 0x00, 0x90, 0x60]))
        graph = {e: sep.callees(ctx, e, frozenset())
                 for e in sep.routine_entries(ctx)}
        self.assertIn([0x9000], sep.cycles(graph))

    def test_recursion_costs_two_bytes_a_level_once_cut(self):
        ctx = synthetic(bytes([0x20, 0x00, 0x90, 0x60]))
        for limit in (1, 2, 3):
            analysis = self.analysis(ctx, limit, frozenset({0x9000}))
            self.assertEqual(analysis.cost(0x9000), 2 * limit)

    def test_an_uncut_cycle_is_reported_rather_than_guessed(self):
        """If the cycle set is wrong, the answer must be `no bound`."""
        ctx = synthetic(bytes([0x20, 0x00, 0x90, 0x60]))
        analysis = self.analysis(ctx, 2, frozenset())        # cycle not listed
        self.assertIsNone(analysis.cost(0x9000))
        self.assertTrue(any("call cycle" in n for n in analysis.notes))


class SeparationVerdictTests(unittest.TestCase):
    """The combined verdict must follow the two halves, never improve them."""

    def verdict(self, worst, floor, open_writers=(), statuses=()):
        from formal.verify.obligations import Obligation

        ledger = Ledger()
        ledger.add(Obligation("SEP-DATA", "s", "scope", "conditional", ["a"]))
        ledger.add(Obligation("SEP-DEPTH", "s", "scope", "conditional", ["b"]))
        return sep.combined(
            ledger, {"worst_offset": worst, "open": list(open_writers),
                     "open_statuses": list(statuses)},
            {"lowest_pointer": floor}), ledger

    def test_separation_holds_when_the_data_stays_below_the_pointer(self):
        verdict, ledger = self.verdict(0x5F, 0xDC)
        self.assertEqual(verdict["status"], "conditional")
        self.assertEqual(verdict["margin"], 0xDC - 0x5F)
        self.assertEqual(ledger.items["SEP-SEPARATION"].status, "conditional")

    def test_an_overlap_is_not_reported_as_holding(self):
        """Both halves are one-sided, so an overlap is a gap, not a fault."""
        verdict, ledger = self.verdict(0xE0, 0xDC)
        self.assertEqual(verdict["status"], "unknown")
        self.assertIn("one-sided",
                      ledger.items["SEP-SEPARATION"].detail[
                          "what_would_close_it"])

    def test_one_open_writer_blocks_the_verdict(self):
        verdict, _ = self.verdict(0x5F, 0xDC, open_writers=["0x1234"],
                                  statuses=["abstract_counterexample"])
        self.assertEqual(verdict["status"], "abstract_counterexample")

    def test_a_writer_that_ran_out_of_budget_leaves_it_unknown(self):
        """Out of time says nothing, so it must not look like evidence."""
        verdict, _ = self.verdict(0x5F, 0xDC, open_writers=["0x1234"],
                                  statuses=["unknown"])
        self.assertEqual(verdict["status"], "unknown")

    def test_the_verdict_carries_both_halves_assumptions(self):
        _verdict, ledger = self.verdict(0x5F, 0xDC)
        self.assertEqual(sorted(ledger.items["SEP-SEPARATION"].assumptions),
                         ["a", "b"])


@unittest.skipUnless(ROM, WHY)
class RomTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from formal.properties.common import context

        cls.ctx = context()
        cls.report = None
        if os.path.exists(sep.REPORT):
            with open(sep.REPORT) as handle:
                cls.report = json.load(handle)

    def setUp(self):
        if self.report is None and self.id().endswith(
                ("test_the_report_is_for_this_image",
                 "test_the_saved_verdict_matches_the_saved_halves")):
            self.skipTest(f"{sep.REPORT} not generated yet; run the module")

    def test_the_report_is_for_this_image(self):
        self.assertEqual(self.report["rom_sha1"], self.ctx.sha1)

    def test_the_clear_loop_invariant_still_holds_at_its_cut_point(self):
        """`$90DC`'s hand-supplied invariant, re-proved from scratch."""
        hypothesis = sep.HINTS[0x90DC](self.ctx)
        result = sep.try_hypothesis(self.ctx, 0x90DC, hypothesis)
        self.assertTrue(result["proved"], result)
        self.assertEqual(hypothesis.bound, 0x5F)

    def test_the_clear_loop_bound_is_tight(self):
        """One offset lower is not provable, so $015F is not slack."""
        hypothesis = sep.HINTS[0x90DC](self.ctx)
        tighter = sep.Hypothesis(hypothesis.name, hypothesis.predicate,
                                 hypothesis.cuts, hypothesis.provenance,
                                 hypothesis.bound - 1)
        self.assertFalse(
            sep.try_hypothesis(self.ctx, 0x90DC, tighter)["proved"])

    def test_the_only_pointer_assignments_are_the_two_txs(self):
        _deltas, assigns = sep.stack_deltas(self.ctx)
        self.assertEqual(assigns, [0x8009, 0xF3BA])

    def test_the_dead_txs_is_unreachable(self):
        slicer = Slicer(self.ctx.graph, self.ctx.prg,
                        closed_entries=sep.IRQ_ENTRY)
        self.assertTrue(slicer.prove_never(
            0xF3B1, lambda s, w: z3.BoolVal(True), max_depth=10).holds)

    def test_the_jumpengine_releases_the_dispatchers_frame(self):
        engine = sep.engine_effect(self.ctx)
        self.assertEqual(engine["net_change_in_s"], 2)
        self.assertEqual(engine["deepest_push_below_entry"], 0)

    def test_the_call_graph_has_exactly_one_cycle(self):
        graph = {e: sep.callees(self.ctx, e, frozenset({0xF3B1}))
                 for e in sep.routine_entries(self.ctx)}
        self.assertEqual(sep.cycles(graph), [[0xC26C]])

    def test_the_saved_verdict_matches_the_saved_halves(self):
        verdict = self.report["verdict"]
        data = self.report["data_side"]
        stack = self.report["stack_side"]
        self.assertEqual(verdict["highest_data_offset"], data["worst_offset"])
        self.assertEqual(verdict["lowest_stack_offset"],
                         stack["lowest_pointer"])
        if verdict["status"] == "conditional":
            self.assertFalse(data["open"])
            self.assertLessEqual(verdict["highest_data_offset"],
                                 verdict["lowest_stack_offset"])


if __name__ == "__main__":                                # pragma: no cover
    unittest.main()
