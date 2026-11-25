"""Tests for the initial-memory characterisation.

Three kinds, as elsewhere in the track:

* infrastructure tests on synthetic images, including negative ones: the loop
  summariser must *refuse* a loop whose body writes memory, and the helpers
  must agree with the predicates in `properties/common.py`;
* shape tests on the formula and the partition that need no ROM;
* ROM-dependent tests, skipped when the verified image is absent.

Passing tests show the tooling behaves.  They are not proofs of the game.
"""
from __future__ import annotations

import unittest

import z3

from analysis.cfg import CFG
from formal.properties import init_memory as im
from formal.properties.common import ram_cell_hit
from formal.verify.obligations import Ledger, check_valid

try:
    from rom import image

    image()
    ROM, WHY = True, ""
except Exception as exc:  # pragma: no cover
    ROM, WHY = False, f"verified SMB1 ROM unavailable: {exc}"


def synthetic(blob: bytes, base: int = 0x9000) -> bytes:
    """A 32 KiB image that is zero except for `blob` at `base`."""
    prg = bytearray(0x8000)
    prg[base - 0x8000:base - 0x8000 + len(blob)] = blob
    return bytes(prg)


class HelperTests(unittest.TestCase):
    def test_symbolic_cell_hit_agrees_with_common(self):
        """`ram_cell_hit_sym` is `common.ram_cell_hit` with a free cell."""
        address = z3.BitVec("address", 16)
        for cell in (0x000, 0x006, 0x160, 0x1FF, 0x7D7, 0x7FF):
            claim = (im.ram_cell_hit_sym(address, im.ram_index(cell))
                     == ram_cell_hit(address, cell))
            check = check_valid("t", claim, [], save=False)
            self.assertTrue(check.valid, f"cell 0x{cell:03X}: {check}")

    def test_in_set_is_exactly_the_set(self):
        cells = set(range(0x160, 0x1FC)) | {0x7FF}
        term = z3.BitVec("cell", 11)
        member = z3.Or(*[term == im.ram_index(c) for c in sorted(cells)])
        check = check_valid("t", im.in_set(term, cells) == member, [],
                            save=False)
        self.assertTrue(check.valid)

    def test_ranges_and_value_ranges_round_trip(self):
        self.assertEqual(im.ranges({1, 2, 3, 7}), ["$0001-$0003", "$0007"])
        self.assertEqual(im.value_ranges({1: 0, 2: 0, 3: 5}),
                         ["$0001-$0002=$00", "$0003=$05"])

    def test_selected_cells_finds_only_the_cold_boot_array(self):
        ram = z3.Array(im.RAM0, z3.BitVecSort(11), z3.BitVecSort(8))
        other = z3.Array("OTHER", z3.BitVecSort(11), z3.BitVecSort(8))
        term = z3.And(z3.Select(ram, im.ram_index(0x123)) == 1,
                      z3.Select(other, im.ram_index(0x456)) == 2)
        self.assertEqual(im.selected_cells(term), [0x123])

    def test_same_term_distinguishes_values(self):
        self.assertTrue(im.same_term(z3.BitVecVal(5, 8), z3.BitVecVal(5, 8)))
        self.assertFalse(im.same_term(z3.BitVecVal(5, 8), z3.BitVecVal(6, 8)))
        self.assertTrue(im.same_term(0x802B, 0x802B))


class LoopSummaryTests(unittest.TestCase):
    """The summariser must close a clean wait loop and refuse a dirty one."""

    def test_clean_wait_loop_satisfies_the_invariant(self):
        # $9000  LDA $2002 ; $9003  BPL $9000 ; $9005 ...
        prg = synthetic(bytes([0xAD, 0x02, 0x20, 0x10, 0xFB]))
        check, detail = im.vblank_invariant(prg, 0x9000, 0x9003, 0x9005)
        self.assertTrue(check.valid, str(check))
        self.assertTrue(detail["invariant_holds_on_both_successors"])
        self.assertEqual(detail["successors_failing_the_invariant"], [])

    def test_loop_that_writes_memory_is_refused(self):
        # $9000  LDA $2002 ; $9003  STA $0000 ; $9005  BPL $9000
        prg = synthetic(bytes([0xAD, 0x02, 0x20, 0x8D, 0x00, 0x00,
                               0x10, 0xF8]))
        _, detail = im.vblank_invariant(prg, 0x9000, 0x9006, 0x9008)
        self.assertFalse(detail["invariant_holds_on_both_successors"])
        self.assertEqual(sorted(detail["successors_failing_the_invariant"]),
                         ["$9000", "$9008"])

    def test_loop_that_clobbers_x_is_refused(self):
        # $9000  LDA $2002 ; $9003  INX ; $9004  BPL $9000
        prg = synthetic(bytes([0xAD, 0x02, 0x20, 0xE8, 0x10, 0xFA]))
        _, detail = im.vblank_invariant(prg, 0x9000, 0x9004, 0x9006)
        self.assertFalse(detail["invariant_holds_on_both_successors"])

    def test_exit_condition_is_not_vacuous(self):
        """A `BMI` loop exits with bit 7 *clear*, so the summary must fail."""
        # $9000  LDA $2002 ; $9003  BMI $9000
        prg = synthetic(bytes([0xAD, 0x02, 0x20, 0x30, 0xFB]))
        check, _ = im.vblank_invariant(prg, 0x9000, 0x9003, 0x9005)
        self.assertFalse(check.valid)
        self.assertEqual(check.z3_result, "sat")

    def test_summary_state_is_the_general_one(self):
        prg = synthetic(bytes([0xAD, 0x02, 0x20, 0x10, 0xFB]))
        before = im.entry_state(prg)
        after, constraint = im.apply_vblank_summary(before, 0x9000, 0x9005)
        self.assertEqual(after.pc, 0x9005)
        self.assertTrue(z3.is_true(z3.simplify(after.n)))
        self.assertTrue(z3.is_false(z3.simplify(after.z)))
        for field in ("x", "y", "s", "c", "i", "d", "v"):
            self.assertIs(getattr(after, field), getattr(before, field))
        self.assertIs(after.mem, before.mem)
        # the constraint is satisfiable and pins only bit 7 of A
        solver = z3.Solver()
        solver.add(constraint, z3.Extract(6, 0, after.a) == 0x7F)
        self.assertEqual(solver.check(), z3.sat)


@unittest.skipUnless(ROM, WHY)
class ImageTests(unittest.TestCase):
    """The characterisation itself, on the verified image."""

    @classmethod
    def setUpClass(cls):
        """One analysis and one `run` for the whole class: each costs ~20s."""
        from formal.properties.common import context

        cls.ctx = context()
        (_, _, cls.steps, cls.facts, cls.terminal,
         cls.control) = im.analyse(cls.ctx)
        cls.split = {}
        for guards, state in cls.terminal:
            key = "cold" if im.as_int(state.y) == im.COLD_OFFSET else "warm"
            cls.split.setdefault(key, []).append((guards, state))
        cls.traces = {case: im.run_window(im.generalise(cls.split[case], case),
                                          case)
                      for case in ("cold", "warm")}
        cls.ledger = Ledger()
        im.run(cls.ledger, cls.ctx, report_path=None)

    def test_window_starts_at_the_reset_vector(self):
        self.assertEqual(im.entry_state(self.ctx.prg).pc, 0x8000)

    def test_the_split_is_eight_paths_one_of_them_warm(self):
        self.assertEqual(len(self.terminal), 8)
        self.assertEqual(len(self.split["warm"]), 1)
        self.assertEqual(len(self.split["cold"]), 7)

    def test_warm_condition_matches_the_collected_path_condition(self):
        guards, state = self.split["warm"][0]
        collected = z3.And(*guards)
        phi = im.warm_condition(state.mem.ram)
        check = check_valid("t", collected == phi, [], save=False)
        self.assertTrue(check.valid, str(check))

    def test_warm_condition_reads_only_seven_cells(self):
        phi = im.warm_condition(
            z3.Array(im.RAM0, z3.BitVecSort(11), z3.BitVecSort(8)))
        self.assertEqual(im.selected_cells(phi),
                         list(range(0x7D7, 0x7DD)) + [0x7FF])

    def test_window_ends_at_the_nmi_enabling_store(self):
        for case, trace in self.traces.items():
            self.assertEqual(trace.end.pc, 0x8EED, case)
            self.assertTrue(trace.i_set_at_every_boundary, case)
            # inside the window: one write with bit 7 clear, then the
            # enabling one.  $8004's write is in the prologue, not here.
            self.assertEqual(
                [w["value"] for w in trace.control_writes], ["$10", "$90"])
            self.assertEqual(trace.control_writes[-1]["pc"], "$8EED")

    def test_the_prologue_clears_the_enable_bit_first(self):
        self.assertEqual(
            [(w["pc"], w["address"], w["value"]) for w in self.control],
            [("$8004", "$2000", "$10")])

    def test_every_fetch_in_the_window_is_in_rom(self):
        for case, trace in self.traces.items():
            self.assertGreaterEqual(min(trace.pc_counts), 0x8000, case)

    def test_partition_covers_every_cell_exactly_once(self):
        traces = self.traces
        cold = set(traces["cold"].last_write_per_cell())
        warm = set(traces["warm"].last_write_per_cell())
        always, cold_only = cold & warm, cold - warm
        never = set(range(im.RAM_CELLS)) - cold - warm
        self.assertEqual(warm - cold, set())
        self.assertEqual(len(always) + len(cold_only) + len(never),
                         im.RAM_CELLS)
        self.assertEqual(im.ranges(cold_only), ["$07D7-$07FE"])
        self.assertEqual(im.ranges(never), ["$0160-$01FB"])
        self.assertEqual(
            {traces["cold"].last_write_per_cell()[c] for c in cold_only}, {0})

    def test_every_write_in_the_window_has_a_concrete_address(self):
        for case, trace in self.traces.items():
            for address, value in trace.writes:
                self.assertIsNotNone(im.as_int(address), case)
                self.assertIsNotNone(im.as_int(value), case)

    def test_run_records_the_three_sets(self):
        items = self.ledger.items
        self.assertEqual(items["INIT-MEM-PARTITION"].status, "conditional")
        detail = items["INIT-MEM-PARTITION"].detail
        self.assertEqual(detail["total"], im.RAM_CELLS)
        self.assertEqual(detail["never_initialised"]["ranges"],
                         ["$0160-$01FB"])
        self.assertEqual(
            detail["preserved_in_the_warm_case_only"]["ranges"],
            ["$07D7-$07FE"])
        for name in ("INIT-MEM-VBLANK-800A", "INIT-MEM-VBLANK-800F",
                     "INIT-MEM-PATHS-TOTAL", "INIT-MEM-PATHS-DISJOINT",
                     "INIT-MEM-WARM-COND", "INIT-MEM-SPLIT-STATE",
                     "INIT-MEM-DETERMINED-COLD",
                     "INIT-MEM-DETERMINED-WARM", "INIT-MEM-PRESERVED-COLD",
                     "INIT-MEM-PRESERVED-WARM", "INIT-MEM-UNTOUCHED-COLD",
                     "INIT-MEM-UNTOUCHED-WARM", "INIT-MEM-WRITESET-COLD",
                     "INIT-MEM-WRITESET-WARM", "INIT-MEM-WARM-DIGITS",
                     "INIT-MEM-NO-IRQ", "INIT-MEM-LOOP-90CC",
                     "INIT-MEM-FETCHES-IN-ROM"):
            self.assertEqual(items[name].status, "proved", name)
        self.assertEqual(items["INIT-MEM-NO-NMI"].status, "conditional")
        for name in ("INIT-MEM-WARM-COND-NEG", "INIT-MEM-NMI-WARM-RESET",
                     "INIT-MEM-DETERMINED-WARM-NEG"):
            self.assertEqual(items[name].status, "refuted", name)
        self.assertEqual(items["INIT-MEM-DYN"].status, "observed")

    def test_no_obligation_claims_proved_with_assumptions(self):
        for item in self.ledger.items.values():
            if item.status == "proved":
                self.assertEqual(item.assumptions, [], item.id)
                self.assertEqual(item.dependencies, [], item.id)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
