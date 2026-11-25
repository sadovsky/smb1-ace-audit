"""Interrupt entry and the writer census on the ROM (plan sections 9, 10).

The interrupt result is the one place this revision *strengthens* the earlier
conclusion, so it gets regression tests of its own: the old argument ("NROM has
no mapper IRQ") would still pass if SMB1 enabled a DMC IRQ tomorrow, whereas
the argument tested here -- I is set at reset and no reachable instruction can
clear it -- does not depend on the APU at all.
"""

from __future__ import annotations

import unittest

try:
    from rom import b, image

    image()
    ROM_AVAILABLE, ROM_SKIP = True, ""
except Exception as exc:  # pragma: no cover
    ROM_AVAILABLE, ROM_SKIP = False, f"verified SMB1 ROM unavailable: {exc}"


@unittest.skipUnless(ROM_AVAILABLE, ROM_SKIP)
class InterruptMaskingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from analysis.cfg import build_from_vectors
        from analysis.interrupts import masking_report, vectors

        cls.graph = build_from_vectors(b)
        cls.masking = masking_report(b, cls.graph)
        cls.vectors = {v.name: v for v in vectors(b, cls.graph)}

    def test_reset_begins_with_sei(self):
        self.assertIn("0x8000", self.masking["sei_sites"])

    def test_no_reachable_cli(self):
        self.assertEqual(self.masking["cli_sites"], [])

    def test_no_reachable_plp(self):
        """PLP would restore I from the stack, so it matters as much as CLI."""
        self.assertEqual(self.masking["plp_sites"], [])

    def test_interrupt_flag_is_not_clearable(self):
        self.assertFalse(self.masking["i_flag_clearable_on_reachable_paths"])

    def test_only_one_reachable_rti(self):
        self.assertEqual(self.masking["rti_sites"], ["0x8181"])

    def test_stray_cli_bytes_are_reported_not_hidden(self):
        """The induction covers instruction starts, so say so."""
        self.assertGreater(self.masking["stray_cli_bytes_in_prg"], 0)
        self.assertTrue(any("derailment" in caveat
                            for caveat in self.masking["caveats"]))

    def test_irq_vector_points_at_data(self):
        irq = self.vectors["irq"]
        self.assertEqual(irq.target, 0xFFF0)
        self.assertFalse(irq.also_reached_by_normal_flow)

    def test_nmi_and_reset_point_at_real_code(self):
        self.assertEqual(self.vectors["reset"].target, 0x8000)
        self.assertEqual(self.vectors["nmi"].target, 0x8082)
        for name in ("reset", "nmi"):
            with self.subTest(vector=name):
                self.assertEqual(self.vectors[name].region, "prg_rom")


@unittest.skipUnless(ROM_AVAILABLE, ROM_SKIP)
class WriteCensusOnROMTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from analysis.write_census import census

        cls.traced = census(b, scope="traced")
        cls.linear = census(b, scope="linear")

    def test_linear_scope_is_the_coarser_approximation(self):
        self.assertGreater(len(self.linear), len(self.traced))

    def test_071f_has_exactly_two_exact_writers(self):
        """Both are in the $92C8 routine itself: STY #$08 and DEC."""
        from analysis.write_census import writers_of

        exact = writers_of(0x071F, self.traced)["exact"]
        self.assertEqual(sorted(w.address for w in exact), [0x92B7, 0x92BF])
        self.assertEqual({w.mnemonic for w in exact}, {"STY", "DEC"})

    def test_071f_is_not_fully_resolved(self):
        """Indirect stores keep the invariant from being provable."""
        from analysis.write_census import manifest

        record = manifest(0x071F, self.traced, name="$92C8 index")
        self.assertFalse(record["fully_resolved"])
        self.assertGreater(record["counts"]["unresolved"], 0)

    def test_no_critical_variable_is_fully_resolved(self):
        """This is exactly why proof obligation C is open."""
        from analysis.write_census import CRITICAL_VARIABLES, manifest

        for address in CRITICAL_VARIABLES:
            with self.subTest(address=f"${address:04X}"):
                self.assertFalse(
                    manifest(address, self.traced)["fully_resolved"])

    def test_jumpengine_writes_the_pointer_scratch(self):
        """$8E14 STA $07 is inside the engine and shares $9664's index byte."""
        from analysis.write_census import writers_of

        addresses = {w.address for w in writers_of(0x0007, self.traced)["exact"]}
        self.assertIn(0x8E14, addresses)


@unittest.skipUnless(ROM_AVAILABLE, ROM_SKIP)
class ProofObligationTests(unittest.TestCase):
    """The obligations file must not permit an impossibility claim."""

    @classmethod
    def setUpClass(cls):
        from tools.proof_obligations import build

        cls.report = build()

    def test_all_six_obligations_present(self):
        ids = [o["id"] for o in self.report["obligations"]]
        self.assertEqual(ids, ["A", "B", "C", "D", "E", "F"])

    def test_no_obligation_is_met(self):
        for obligation in self.report["obligations"]:
            with self.subTest(obligation=obligation["id"]):
                self.assertNotEqual(obligation["status"], "met")

    def test_impossibility_claim_is_not_permitted(self):
        self.assertFalse(self.report["impossibility_claim_permitted"])
        self.assertIn("not claimed", self.report["summary"])

    def test_every_obligation_states_its_limitations(self):
        for obligation in self.report["obligations"]:
            with self.subTest(obligation=obligation["id"]):
                self.assertTrue(obligation["limitations"])


if __name__ == "__main__":
    unittest.main()
