"""Tests for the formal track.

Three kinds, kept apart on purpose:

* infrastructure tests on original synthetic fixtures (no ROM needed), which
  include negative cases: the checker must *fail* to prove a false claim;
* model unit tests for what the instruction vectors do not cover;
* ROM-dependent regression tests, skipped when the verified image is absent.

Passing tests show the tooling behaves; they are not proofs of the game.
"""
from __future__ import annotations

import json
import os
import unittest

import z3

from analysis.cfg import CFG
from formal.model import cpu, transitions
from formal.model.cpu import State
from formal.model.memory import FlatMemory, NESMemory, as_int
from formal.verify.obligations import Ledger, Obligation, check_valid
from formal.verify.symexec import Slicer

try:
    from rom import image

    image()
    ROM, WHY = True, ""
except Exception as exc:  # pragma: no cover
    ROM, WHY = False, f"verified SMB1 ROM unavailable: {exc}"

VECTORS = os.environ.get("NES6502_VECTORS",
                         os.path.expanduser("~/big/smb1-formal/harte"))


def synthetic(blob: bytes, base: int = 0x9000):
    """A 32 KiB image that is zero except for `blob` at `base`."""
    prg = bytearray(0x8000)
    prg[base - 0x8000:base - 0x8000 + len(blob)] = blob
    prg = bytes(prg)
    graph = CFG(lambda a: prg[(a & 0xFFFF) - 0x8000],
                code_range=(base, base + len(blob)))
    graph.add_entry(base, "test entry")
    return graph.build(), prg


def store_above(limit: int, cell: int):
    return lambda state, writes: z3.Or(z3.BoolVal(False), *[
        z3.And(a == cell, z3.UGT(v, limit)) for a, v in writes])


class CheckerTests(unittest.TestCase):
    def test_valid_claim_is_proved_by_both_solvers(self):
        v = z3.BitVec("v", 8)
        check = check_valid("t", z3.ULE(v & 7, 7), [], save=False)
        self.assertTrue(check.valid)
        self.assertEqual(check.cvc5_result, "unsat")

    def test_false_claim_is_refuted_with_a_model(self):
        v = z3.BitVec("v", 8)
        check = check_valid("t", z3.ULE(v, 7), [], save=False)
        self.assertFalse(check.valid)
        self.assertIn("v", check.model)

    def test_the_plan_lemma_and_its_negative(self):
        v = z3.BitVec("v", 8)
        index = z3.If(v == 0, z3.BitVecVal(8, 8), v) - 1
        self.assertTrue(check_valid("t", z3.ULE(index, 7), [z3.ULE(v, 8)],
                                    save=False).valid)
        self.assertFalse(check_valid("t", z3.ULE(index, 7), [],
                                     save=False).valid)


class LedgerTests(unittest.TestCase):
    def test_proved_cannot_carry_assumptions(self):
        with self.assertRaises(ValueError):
            Obligation("x", "s", "scope", "proved", ["something"])

    def test_assumptions_make_a_valid_check_conditional(self):
        v = z3.BitVec("v", 8)
        check = check_valid("t", v == v, [], save=False)
        ledger = Ledger()
        self.assertEqual(ledger.record("a", "s", "scope", check).status,
                         "proved")
        self.assertEqual(ledger.record("b", "s", "scope", check,
                                       assumptions=["x"]).status,
                         "conditional")

    def test_settle_demotes_proved_with_unproved_dependency(self):
        ledger = Ledger()
        ledger.add(Obligation("a", "s", "scope", "proved",
                              dependencies=["b"]))
        ledger.add(Obligation("b", "s", "scope", "unknown"))
        ledger.settle()
        self.assertEqual(ledger.items["a"].status, "conditional")

    def test_a_dependency_cycle_proves_nothing(self):
        ledger = Ledger()
        ledger.add(Obligation("a", "s", "scope", "proved",
                              dependencies=["b"]))
        ledger.add(Obligation("b", "s", "scope", "proved",
                              dependencies=["a", "missing"]))
        ledger.settle()
        self.assertEqual({o.status for o in ledger.items.values()},
                         {"conditional"})


class MemoryModelTests(unittest.TestCase):
    def setUp(self):
        self.memory = NESMemory.symbolic(bytes(range(256)) * 128)

    def test_ram_mirrors_alias(self):
        memory = self.memory.write(0x1F1F, 0x5A)
        for mirror in (0x071F, 0x0F1F, 0x171F, 0x1F1F):
            self.assertEqual(as_int(memory.read(mirror)[0]), 0x5A)

    def test_rom_is_immutable(self):
        memory = self.memory.write(0x8005, 0xFF)
        self.assertEqual(as_int(memory.read(0x8005)[0]), 5)

    def test_bus_reads_are_unconstrained_and_distinct(self):
        first, memory = self.memory.read(0x4016)
        second, _ = memory.read(0x4016)
        self.assertIsNone(as_int(first))
        solver = z3.Solver()
        solver.add(first != second)
        self.assertEqual(solver.check(), z3.sat)

    def test_bus_writes_do_not_change_ram(self):
        memory = self.memory.write(0x2000, 0x80)
        self.assertTrue(z3.eq(memory.ram, self.memory.ram))

    def test_symbolic_write_reaches_ram_only_below_2000(self):
        address = z3.BitVec("addr", 16)
        memory = self.memory.write(address, 0x11)
        solver = z3.Solver()
        solver.add(z3.UGE(address, 0x2000),
                   memory.ram_byte(0x0123) != self.memory.ram_byte(0x0123))
        self.assertEqual(solver.check(), z3.unsat)


class InterruptModelTests(unittest.TestCase):
    def machine(self, **registers):
        cells = {0xFFFA: 0x82, 0xFFFB: 0x80, 0xFFFC: 0x00, 0xFFFD: 0x80,
                 0xFFFE: 0xF0, 0xFFFF: 0xFF}
        return State.concrete(pc=0x9000, a=1, x=2, y=3, s=0xFD, p=0x00,
                              mem=FlatMemory(cells))

    def test_nmi_pushes_pc_then_status_with_b_clear(self):
        after = cpu.enter_interrupt(self.machine(), cpu.NMI_VECTOR)
        self.assertEqual(after.pc, 0x8082)
        self.assertEqual(as_int(after.s), 0xFA)
        cells = after.mem.cells
        self.assertEqual((cells[0x01FD], cells[0x01FC]), (0x90, 0x00))
        self.assertEqual(cells[0x01FB] & 0x30, 0x20)
        self.assertTrue(z3.is_true(after.i))

    def test_reset_writes_nothing_and_drops_s_by_three(self):
        before = self.machine()
        after = cpu.reset(before)
        self.assertEqual(after.pc, 0x8000)
        self.assertEqual(as_int(after.s), 0xFA)
        self.assertEqual(after.mem.writes, before.mem.writes)

    def test_ghost_nmi_enable_follows_ppu_control_writes(self):
        enable = z3.BoolVal(False)
        value = z3.BitVecVal(0x90, 8)
        for address, expected in ((0x2000, True), (0x3FF8, True),
                                  (0x2001, False), (0x4000, False)):
            with self.subTest(address=hex(address)):
                got = transitions.ppu_control_update(
                    enable, [(z3.BitVecVal(address, 16), value)])
                self.assertEqual(z3.is_true(got), expected)

    def test_irq_transition_exists_only_when_i_is_clear(self):
        prg = bytes(0x8000)
        memory = NESMemory.symbolic(prg)
        state = State.symbolic(0x9000, memory)
        masked = cpu.replace(state, i=z3.BoolVal(True))
        kinds = lambda s: {k for _, _, k in transitions.transitions(
            transitions.Machine(s, z3.BoolVal(False)))}
        self.assertNotIn("irq", kinds(masked))
        self.assertIn("irq", kinds(cpu.replace(state, i=z3.BoolVal(False))))
        self.assertNotIn("nmi", kinds(masked))
        self.assertIn("reset", kinds(masked))


class SlicerTests(unittest.TestCase):
    """Synthetic fixtures; includes the negative cases the plan asks for."""

    def test_clamped_store_is_proved(self):
        #: AND #$07 / STA $0300 / RTS
        graph, prg = synthetic(bytes.fromhex("2907" "8d0003" "60"))
        outcome = Slicer(graph, prg).prove_never(0x9002, store_above(7, 0x0300))
        self.assertTrue(outcome.holds)
        self.assertEqual(outcome.max_depth, 2)

    def test_unclamped_store_is_not_proved(self):
        #: STA $0300 / RTS -- A is whatever the caller left
        graph, prg = synthetic(bytes.fromhex("8d0003" "60"))
        outcome = Slicer(graph, prg).prove_never(0x9000, store_above(7, 0x0300))
        self.assertFalse(outcome.holds)
        self.assertIn("graph entry", outcome.reason)

    def test_zero_substitution_without_a_clamp_is_not_proved(self):
        """The `$92C8` shape: BNE / LDY #8 / DEY bounds nothing above."""
        #: LDY $0300 / BNE +2 / LDY #$08 / DEY / STY $0301 / RTS
        graph, prg = synthetic(bytes.fromhex("ac0003" "d002" "a008" "88"
                                             "8c0103" "60"))
        slicer = Slicer(graph, prg)
        self.assertFalse(slicer.prove_never(
            0x9008, store_above(7, 0x0301)).holds)
        bounded = Slicer(graph, prg, invariants=lambda s: [
            z3.ULE(s.mem.ram_byte(0x0300), 8)] if s.pc == 0x9000 else [])
        self.assertTrue(bounded.prove_never(
            0x9008, store_above(7, 0x0301)).holds)

    def test_complementary_branches_make_the_fallthrough_infeasible(self):
        #: BCC +3 / BCS +1 / (STA $0300 unreachable... 3 bytes) -- use LDA
        #: $9000 BCC $9007 / $9002 BCS $9007 / $9004 STA $0300 / $9007 RTS
        graph, prg = synthetic(bytes.fromhex("9005" "b003" "8d0003" "60"))
        outcome = Slicer(graph, prg).prove_never(0x9004,
                                                 store_above(0, 0x0300))
        self.assertTrue(outcome.holds)

    def test_call_is_inlined_when_tractable(self):
        #: $9000 JSR $9007 / $9003 STA $0300 / $9006 RTS / $9007 LDA #$03 / RTS
        graph, prg = synthetic(bytes.fromhex("200790" "8d0003" "60"
                                             "a903" "60"))
        outcome = Slicer(graph, prg).prove_never(0x9003, store_above(3, 0x0300))
        self.assertTrue(outcome.holds)
        self.assertFalse(outcome.used_call_summary)

    def test_callee_that_loops_falls_back_to_havoc_and_fails(self):
        #: $9000 JSR $9007 / STA $0300 / RTS / $9007 LDA #$03 / $9009 JMP $9009
        graph, prg = synthetic(bytes.fromhex("200790" "8d0003" "60"
                                             "a903" "4c0990"))
        outcome = Slicer(graph, prg).prove_never(0x9003, store_above(3, 0x0300))
        self.assertFalse(outcome.holds)

    def test_indexed_store_reaches_mirrors(self):
        #: LDX #$00 / STA $0F00,X -- $0F00 mirrors $0700
        graph, prg = synthetic(bytes.fromhex("a200" "9d000f" "60"))
        hit = lambda state, writes: z3.Or(z3.BoolVal(False), *[
            z3.And(z3.ULT(a, 0x2000), z3.Extract(10, 0, a) == 0x700)
            for a, _ in writes])
        self.assertFalse(Slicer(graph, prg).prove_never(0x9002, hit).holds)


@unittest.skipUnless(os.path.isdir(VECTORS), f"{VECTORS} absent")
class VectorSampleTests(unittest.TestCase):
    def test_a_sample_of_every_comparable_opcode_matches(self):
        from formal.validate_model import check_vectors

        report = check_vectors(VECTORS, 6)
        self.assertEqual(report["mismatches"], [])
        self.assertEqual(report["opcodes_compared"], 237)


@unittest.skipUnless(ROM, WHY)
class ROMTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from formal.properties import dispatch
        from formal.properties.common import context

        cls.ctx = context()
        cls.ledger = Ledger()
        dispatch.run(cls.ledger, cls.ctx)

    def status(self, key):
        return self.ledger.items[key].status

    def test_arithmetic_lemma_and_negative(self):
        self.assertEqual(self.status("L-92C8-ARITH"), "proved")
        self.assertEqual(self.status("L-92C8-ARITH-NEG"), "refuted")

    def test_rom_lemma_and_negative(self):
        self.assertEqual(self.status("L-92C8-ROM"), "proved")
        self.assertEqual(self.status("L-92C8-ROM-EXACT"), "proved")
        self.assertEqual(self.status("L-92C8-ROM-NEG"), "refuted")

    def test_all_eighteen_contracts_hold_and_the_negative_is_refuted(self):
        contracts = [k for k in self.ledger.items
                     if k.startswith("D-") and k.endswith("-CONTRACT")]
        self.assertEqual(len(contracts), 18)
        for key in contracts:
            with self.subTest(key=key):
                self.assertEqual(self.status(key), "proved")
        self.assertEqual(self.status("D-92C8-CONTRACT-NEG"), "refuted")

    def test_both_solvers_answered_every_query(self):
        for item in self.ledger.items.values():
            with self.subTest(id=item.id):
                self.assertIn(item.independent_check,
                              ("cvc5: unsat", "cvc5: sat"))

    def test_d2e5_index_closes_from_the_code_alone(self):
        from formal.properties.state_domains import IRQ_ENTRY

        slicer = Slicer(self.ctx.graph, self.ctx.prg, closed_entries=IRQ_ENTRY)
        bad = lambda s, w: z3.Not(z3.ULT(s.a & 0x7F, 5))
        self.assertTrue(slicer.prove_never(0xD2E5, bad).holds)

    def test_92c8_index_does_not_close_without_the_invariant(self):
        slicer = Slicer(self.ctx.graph, self.ctx.prg)
        bad = lambda s, w: z3.Not(z3.ULT(s.a & 0x7F, 8))
        self.assertFalse(slicer.prove_never(0x92C8, bad).holds)


MANIFEST = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "results", "manifests", "obligations.json")


@unittest.skipUnless(os.path.exists(MANIFEST), "manifest not generated")
class ManifestTests(unittest.TestCase):
    """The committed manifest must not claim more than it shows."""

    @classmethod
    def setUpClass(cls):
        with open(MANIFEST) as handle:
            cls.manifest = json.load(handle)
        cls.items = {o["id"]: o for o in cls.manifest["obligations"]}

    def test_the_primary_theorem_is_not_claimed(self):
        self.assertNotEqual(self.items["P1"]["status"], "proved")

    def test_nothing_proved_rests_on_something_unproved(self):
        for item in self.items.values():
            if item["status"] != "proved":
                continue
            self.assertEqual(item["assumptions"], [], item["id"])
            for dependency in item["dependencies"]:
                self.assertEqual(self.items[dependency]["status"], "proved",
                                 f"{item['id']} -> {dependency}")

    def test_solver_backed_items_carry_a_query_hash(self):
        for item in self.items.values():
            if item["solver"] == "z3" and item["independent_check"]:
                self.assertRegex(item["query_sha256"] or "", r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
