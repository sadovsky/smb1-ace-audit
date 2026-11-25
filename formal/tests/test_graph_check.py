"""Tests for `properties/graph_check`, on synthetic images.

The point of the module is to catch a control-flow graph that disagrees with
the machine model, so most of what is worth testing is negative: a deliberate
wrong edge, a deliberately missing edge and a deliberately wrong decoding must
each be reported, with the address, and must not be papered over.

No verified image is needed; the fixtures are hand-assembled programs.
"""
from __future__ import annotations

import os
import unittest

from analysis.cfg import CFG
from analysis.decoder import OPCODES, Instruction
from formal.properties import graph_check
from formal.properties.common import Context
from formal.verify import crosscheck
from formal.verify.obligations import Ledger

#: LDA #$05 / BNE $9007 / JMP $9008 / NOP / JSR $900C / RTS / STA $0300 / RTS
PROGRAM = bytes.fromhex("a905" "d003" "4c0890" "ea" "200c90" "60"
                        "8d0003" "60")
BASE = 0x9000


def fixture(blob: bytes = PROGRAM, base: int = BASE):
    prg = bytearray(0x8000)
    prg[base - 0x8000:base - 0x8000 + len(blob)] = blob
    prg = bytes(prg)
    graph = CFG(lambda a: prg[(a & 0xFFFF) - 0x8000],
                code_range=(base, base + len(blob)))
    graph.add_entry(base, "test entry")
    graph.build()
    return Context(prg, "synthetic", graph)


def categories(report) -> set:
    return {f.category for f in report.findings}


def addresses(report, category) -> set:
    return {f.address for f in report.findings if f.category == category}


class ShapeTests(unittest.TestCase):
    def test_the_fixture_decodes_as_intended(self):
        ctx = fixture()
        self.assertEqual(sorted(ctx.graph.nodes),
                         [0x9000, 0x9002, 0x9004, 0x9007, 0x9008, 0x900B,
                          0x900C, 0x900F])


class AgreementTests(unittest.TestCase):
    def test_an_honest_graph_has_no_findings(self):
        report = graph_check.check(fixture())
        self.assertEqual(report.findings, [], [f.to_json()
                                               for f in report.findings])
        self.assertEqual(report.nodes, 8)

    def test_returns_are_excluded_and_counted_not_checked(self):
        report = graph_check.check(fixture())
        self.assertEqual(report.excluded.get("return"), 2)
        self.assertEqual(report.checked, 6)

    def test_every_direct_edge_is_compared_and_feasible(self):
        report = graph_check.check(fixture())
        # 9000->9002, 9002->{9004,9007}, 9004->9008, 9007->9008,
        # 9008->900C (the call; its return_point is not a direct edge),
        # 900C->900F
        self.assertEqual(report.edges_compared, 7)
        self.assertEqual(report.feasible_edges, 7)
        self.assertEqual(report.summary_edges.get("return_point"), 1)

    def test_one_query_per_node_plus_one_per_edge(self):
        report = graph_check.check(fixture())
        self.assertEqual(report.coverage_queries, 6)
        self.assertEqual(report.feasibility_queries, 7)
        self.assertEqual(report.solver_no_answer, 0)


class WrongEdgeTests(unittest.TestCase):
    """The negative cases: a graph that lies must be caught."""

    def test_a_recorded_edge_the_model_cannot_take_is_reported(self):
        ctx = fixture()
        ctx.graph.nodes[0x9004].successors.append((0x9FFF, "jump"))
        report = graph_check.check(ctx)
        self.assertIn("recorded_successor_infeasible", categories(report))
        self.assertEqual(addresses(report, "recorded_successor_infeasible"),
                         {0x9004})
        finding, = [f for f in report.findings
                    if f.category == "recorded_successor_infeasible"]
        self.assertEqual(finding.extra["recorded_successor"], "0x9FFF")

    def test_a_missing_branch_edge_is_reported(self):
        ctx = fixture()
        node = ctx.graph.nodes[0x9002]
        node.successors = [(t, k) for t, k in node.successors
                           if t != 0x9007]
        report = graph_check.check(ctx)
        self.assertEqual(addresses(report, "successor_not_recorded"),
                         {0x9002})
        finding, = [f for f in report.findings
                    if f.category == "successor_not_recorded"]
        self.assertEqual(finding.extra["not_recorded"], ["0x9007"])

    def test_a_missing_fallthrough_edge_is_reported(self):
        ctx = fixture()
        ctx.graph.nodes[0x900C].successors = []
        report = graph_check.check(ctx)
        self.assertEqual(addresses(report, "successor_not_recorded"),
                         {0x900C})

    def test_an_edge_to_the_wrong_branch_target_is_reported_both_ways(self):
        ctx = fixture()
        node = ctx.graph.nodes[0x9002]
        node.successors = [(t if t != 0x9007 else 0x9008, k)
                           for t, k in node.successors]
        report = graph_check.check(ctx)
        self.assertEqual(addresses(report, "successor_not_recorded"),
                         {0x9002})
        self.assertEqual(addresses(report, "recorded_successor_infeasible"),
                         {0x9002})

    def test_a_wrong_decoding_is_reported_and_the_node_is_not_checked(self):
        ctx = fixture()
        # claim $9000 holds a three-byte JMP; the image holds LDA #$05
        ctx.graph.nodes[0x9000].instruction = Instruction(
            0x9000, OPCODES[0x4C], (0x08, 0x90))
        report = graph_check.check(ctx)
        self.assertEqual(categories(report),
                         {"opcode_disagreement", "length_disagreement"})
        self.assertEqual(report.excluded.get("decoding_disagreement"), 1)
        self.assertEqual(report.checked, 5)


class ObligationTests(unittest.TestCase):
    def ledger(self, ctx) -> Ledger:
        ledger = Ledger()
        report = graph_check.REPORT
        graph_check.REPORT = os.path.join(
            os.environ.get("TMPDIR", "/tmp"), "graph_check_test.json")
        try:
            graph_check.run(ledger, ctx)
        finally:
            graph_check.REPORT = report
        return ledger

    def test_a_clean_graph_is_proved_and_carries_its_query_record(self):
        item = self.ledger(fixture()).items[graph_check.OBLIGATION]
        self.assertEqual(item.status, "proved")
        self.assertEqual(item.assumptions, [])
        record = item.detail["slice_queries"]
        self.assertEqual(record["solver_queries"], 13)
        self.assertRegex(record["query_digest"], r"^[0-9a-f]{64}$")
        self.assertEqual(record["cross_check"], "clean")
        for solver, tally in record["second_solver"].items():
            with self.subTest(solver=solver):
                self.assertEqual(tally.get("disagree", 0), 0)

    def test_a_wrong_edge_refutes_the_obligation_and_names_the_address(self):
        ctx = fixture()
        ctx.graph.nodes[0x9004].successors.append((0x9FFF, "jump"))
        item = self.ledger(ctx).items[graph_check.OBLIGATION]
        self.assertEqual(item.status, "refuted")
        self.assertEqual(item.detail["mismatches"], 1)
        self.assertEqual([f["address"] for f in item.detail["findings"]],
                         ["0x9004"])

    def test_the_graph_is_not_repaired(self):
        """A finding must not change the graph it is about."""
        ctx = fixture()
        ctx.graph.nodes[0x9004].successors.append((0x9FFF, "jump"))
        before = list(ctx.graph.nodes[0x9004].successors)
        self.ledger(ctx)
        self.assertEqual(ctx.graph.nodes[0x9004].successors, before)


class CrossCheckTests(unittest.TestCase):
    """A second solver contradicting Z3 must be visible, never dropped."""

    def test_a_disagreement_is_reported_and_demotes_the_obligation(self):
        ctx = fixture()
        with crosscheck.collect("probe") as queries:
            graph_check.check(ctx)
        self.assertTrue(queries.clean)
        poisoned = sorted(queries.rechecked)[0]
        kept = dict(crosscheck._ANSWERS[poisoned])
        flipped = "sat" if queries.answers[poisoned] == "unsat" else "unsat"
        crosscheck._ANSWERS[poisoned] = {**kept, "cvc5": flipped}
        try:
            self.assertFalse(queries.clean)
            summary = queries.summary()
            self.assertEqual(summary["second_solver"]["cvc5"]["disagree"], 1)
            self.assertIn("disagreement", summary["cross_check"])
            self.assertEqual(
                summary["second_solver"]["cvc5"]["disagreements"][0]
                ["query_sha256"], poisoned)
        finally:
            crosscheck._ANSWERS[poisoned] = kept

    def test_the_same_query_hashes_the_same_whenever_it_is_built(self):
        first = graph_check.check(fixture())
        second = graph_check.check(fixture())
        with crosscheck.collect("a") as one:
            graph_check.check(fixture())
        with crosscheck.collect("b") as two:
            graph_check.check(fixture())
        self.assertEqual(one.summary()["query_digest"],
                         two.summary()["query_digest"])
        self.assertEqual(first.coverage_queries, second.coverage_queries)


if __name__ == "__main__":
    unittest.main()
