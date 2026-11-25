"""Table boundaries and the destination matrix (plan sections 6, 7)."""

from __future__ import annotations

import unittest

from analysis.destinations import classify_outcome, effective_index
from analysis.provenance import ExecutionOutcome

try:
    from rom import b, image

    image()
    ROM_AVAILABLE, ROM_SKIP = True, ""
except Exception as exc:  # pragma: no cover
    ROM_AVAILABLE, ROM_SKIP = False, f"verified SMB1 ROM unavailable: {exc}"


class AliasingTests(unittest.TestCase):
    def test_bit_seven_is_discarded_by_asl(self):
        """`ASL A` drops bit 7, so i and i+128 share a destination."""
        for raw in range(128):
            with self.subTest(raw=raw):
                self.assertEqual(effective_index(raw),
                                 effective_index(raw + 128))

    def test_only_128_distinct_indices_exist(self):
        self.assertEqual(len({effective_index(i) for i in range(256)}), 128)


class OutcomeClassificationTests(unittest.TestCase):
    def test_expected_and_unexpected_rom_are_distinguished(self):
        self.assertIs(classify_outcome(0x9000, expected=True),
                      ExecutionOutcome.EXPECTED_ROM)
        self.assertIs(classify_outcome(0x9000, expected=False),
                      ExecutionOutcome.UNEXPECTED_ROM)

    def test_ram_mirror_counts_as_internal_ram(self):
        self.assertIs(classify_outcome(0x1695, expected=False),
                      ExecutionOutcome.INTERNAL_RAM)

    def test_registers_are_io_dependent_not_crash(self):
        """An instruction fetch from a register is a bus transaction."""
        for address in (0x2060, 0x4015, 0x4018):
            with self.subTest(address=address):
                self.assertIs(classify_outcome(address, expected=False),
                              ExecutionOutcome.IO_DEPENDENT)

    def test_unmapped_cartridge_space_is_open_bus(self):
        self.assertIs(classify_outcome(0x4747, expected=False),
                      ExecutionOutcome.OPEN_BUS_DEPENDENT)


@unittest.skipUnless(ROM_AVAILABLE, ROM_SKIP)
class BoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from analysis.cfg import build_from_vectors
        from analysis.dispatch_tables import establish

        cls.graph = build_from_vectors(b)
        cls.evidence = establish(b, cls.graph)

    def test_every_table_has_a_boundary(self):
        self.assertEqual(len(self.evidence), 18)
        for dispatch, row in self.evidence.items():
            with self.subTest(dispatch=f"${dispatch:04X}"):
                self.assertGreater(row.entries, 0)

    def test_c7a8_table_has_six_entries_not_eight(self):
        """Entry 1 points at $C7B7, which holds RTS: the span ends there."""
        row = self.evidence[0xC7A8]
        self.assertEqual(row.entries, 6)
        self.assertEqual(row.heuristic, 8)
        self.assertEqual(row.self_reference, 6)
        self.assertGreaterEqual(row.independent_sources, 2)

    def test_9743_table_has_three_entries_not_five(self):
        """Entry 0 points at $974C, which holds JSR $9BBB."""
        row = self.evidence[0x9743]
        self.assertEqual(row.entries, 3)
        self.assertEqual(row.heuristic, 5)
        self.assertEqual(row.self_reference, 3)

    def test_92c8_boundary_is_independently_confirmed(self):
        row = self.evidence[0x92C8]
        self.assertEqual(row.entries, 8)
        self.assertGreaterEqual(row.independent_sources, 1)

    def test_two_tables_were_over_read_by_the_heuristic(self):
        wrong = sorted(d for d, r in self.evidence.items()
                       if r.heuristic_was_wrong)
        self.assertEqual(wrong, [0x9743, 0xC7A8])

    def test_established_boundaries_remove_the_phantom_a060_edge(self):
        """The $C7AB over-read manufactured a dispatch target at $A060."""
        from analysis.cfg import build_from_vectors

        heuristic = build_from_vectors(b, established_boundaries=False)
        self.assertIn(0xA060, heuristic.nodes)
        self.assertNotIn(0xA060, self.graph.nodes)

    def test_established_boundaries_reduce_reachable_jams(self):
        from analysis.cfg import build_from_vectors

        heuristic = build_from_vectors(b, established_boundaries=False)
        self.assertLess(len(self.graph.halts), len(heuristic.halts))


@unittest.skipUnless(ROM_AVAILABLE, ROM_SKIP)
class DestinationMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from analysis.cfg import build_from_vectors
        from analysis.destinations import resolve_all, summarise

        cls.graph = build_from_vectors(b)
        cls.resolutions = resolve_all(b, cls.graph)
        cls.summary = summarise(cls.resolutions)

    def test_matrix_is_complete_and_excludes_nothing(self):
        self.assertEqual(len(self.resolutions), 18 * 256)

    def test_aliasing_halves_the_distinct_pairs(self):
        self.assertEqual(self.summary["distinct_site_index_pairs"], 18 * 128)

    def test_unexpected_rom_destinations_are_retained(self):
        """They were previously discarded as 'resolves to ROM, so safe'."""
        self.assertGreater(self.summary["outcomes"]["unexpected_rom"], 500)

    def test_some_unexpected_rom_destinations_are_operand_bytes(self):
        """Landing mid-instruction is not a safe outcome."""
        roles = self.summary["unexpected_rom_roles"]
        self.assertGreater(roles["operand_byte_of_another_instruction"], 100)

    def test_high_pointer_byte_wraps_at_effective_index_127(self):
        wrapped = [r for r in self.resolutions if r.wraps]
        self.assertEqual(len(wrapped), 36)      # two raw indices per site
        for resolution in wrapped:
            with self.subTest(dispatch=f"${resolution.dispatch:04X}"):
                self.assertEqual(resolution.effective, 127)

    def test_every_expected_entry_resolves_into_rom(self):
        for resolution in self.resolutions:
            if resolution.expected:
                with self.subTest(dispatch=f"${resolution.dispatch:04X}",
                                  index=resolution.raw_index):
                    self.assertEqual(resolution.region, "prg_rom")

    def test_c88f_index_34_reaches_a_ppu_register(self):
        match = [r for r in self.resolutions
                 if r.dispatch == 0xC88F and r.raw_index == 34]
        self.assertEqual(match[0].destination, 0x2060)
        self.assertIs(match[0].outcome, ExecutionOutcome.IO_DEPENDENT)


if __name__ == "__main__":
    unittest.main()
