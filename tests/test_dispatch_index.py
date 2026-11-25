"""The $92C8 index transformation and the provenance rules (plan sections 3-4).

These tests encode the correction: the sequence in front of `$92C8`
substitutes 8 for zero and does *not* clamp.  They are written so that
reinstating the old "forced 1..8 / provably safe" claim fails.
"""

from __future__ import annotations

import unittest

from analysis.dispatch_index import (
    DISPATCH_92C8,
    identity_index,
    subtracted_index,
    zero_substituted_index,
)
from analysis.provenance import (
    Bound,
    BoundProvenance,
    Reachability,
    excludes_unconditionally,
)

try:  # ROM-dependent assertions are skipped when the cartridge is absent
    from rom import ROMValidationError, b, image

    image()
    ROM_AVAILABLE = True
    ROM_SKIP = ""
except Exception as exc:  # pragma: no cover - depends on the environment
    ROM_AVAILABLE = False
    ROM_SKIP = f"verified SMB1 ROM unavailable: {exc}"


class ZeroSubstitutionTests(unittest.TestCase):
    """`index = ((value or 8) - 1) & 0xFF`."""

    def test_zero_substitution(self):
        self.assertEqual(zero_substituted_index(0), 7)

    def test_eight_also_yields_seven(self):
        """$00 and $08 collide on index 7 -- the only reason 0..8 is safe."""
        self.assertEqual(zero_substituted_index(8), 7)

    def test_does_not_clamp(self):
        """The regression that matters: nine is not clamped to seven."""
        self.assertEqual(zero_substituted_index(9), 8)
        self.assertEqual(zero_substituted_index(255), 254)

    def test_plan_table(self):
        for value, expected in ((0x00, 7), (0x01, 0), (0x08, 7), (0x09, 8),
                                (0x80, 127), (0xFF, 254)):
            with self.subTest(value=value):
                self.assertEqual(zero_substituted_index(value), expected)

    def test_all_256_inputs(self):
        """Exhaustive: the model is a decrement with a single substitution."""
        for value in range(256):
            with self.subTest(value=value):
                expected = 7 if value == 0 else (value - 1) & 0xFF
                self.assertEqual(zero_substituted_index(value), expected)

    def test_only_values_up_to_eight_stay_in_table(self):
        """Exactly $00..$08 keep the index inside the 8-entry table."""
        in_table = {v for v in range(256) if zero_substituted_index(v) < 8}
        self.assertEqual(in_table, set(range(0, 9)))

    def test_index_is_not_injective_on_the_safe_range(self):
        self.assertEqual(DISPATCH_92C8.source_values_reaching(7), [0, 8])


class IndexHelperTests(unittest.TestCase):
    def test_identity_masks_to_eight_bits(self):
        self.assertEqual(identity_index(0x1FF), 0xFF)

    def test_subtraction_wraps(self):
        self.assertEqual(subtracted_index(0x12, 0x12), 0)
        self.assertEqual(subtracted_index(0x11, 0x12), 0xFF)


class BoundProvenanceTests(unittest.TestCase):
    """An observation must never produce an unconditional exclusion."""

    def test_only_proven_excludes_unconditionally(self):
        self.assertTrue(excludes_unconditionally(BoundProvenance.PROVEN))
        for weaker in (BoundProvenance.STRUCTURAL_CONDITIONAL,
                       BoundProvenance.DERIVED_CONDITIONAL,
                       BoundProvenance.OBSERVED,
                       BoundProvenance.ASSUMED,
                       BoundProvenance.UNPROVED):
            with self.subTest(provenance=weaker):
                self.assertFalse(excludes_unconditionally(weaker))

    def test_conditional_bound_requires_assumptions(self):
        with self.assertRaises(ValueError):
            Bound(maximum=7, provenance=BoundProvenance.STRUCTURAL_CONDITIONAL,
                  mechanism="no assumptions listed")

    def test_unproved_bound_carries_no_maximum(self):
        with self.assertRaises(ValueError):
            Bound(maximum=7, provenance=BoundProvenance.UNPROVED, mechanism="x")

    def test_observed_bound_yields_not_observed_not_unreachable(self):
        bound = Bound(maximum=3, provenance=BoundProvenance.OBSERVED,
                      mechanism="never exceeded in the native census",
                      assumptions=("coverage of the reached state space",))
        reach, why = bound.exclusion_for(9)
        self.assertIs(reach, Reachability.NOT_OBSERVED)
        self.assertIn("unreached states", why)

    def test_proven_bound_yields_proven_unreachable(self):
        bound = Bound(maximum=4, provenance=BoundProvenance.PROVEN,
                      mechanism="CMP #$05 / BCS")
        reach, _ = bound.exclusion_for(5)
        self.assertIs(reach, Reachability.PROVEN_UNREACHABLE)

    def test_92c8_bound_is_conditional_and_says_why(self):
        bound = DISPATCH_92C8.bound
        self.assertIs(bound.provenance, BoundProvenance.STRUCTURAL_CONDITIONAL)
        self.assertFalse(bound.is_unconditional)
        self.assertTrue(bound.assumptions)
        reach, why = bound.exclusion_for(8)
        self.assertIs(reach, Reachability.CONDITIONALLY_UNREACHABLE)
        self.assertIn("$071F", why)


@unittest.skipUnless(ROM_AVAILABLE, ROM_SKIP)
class ROMWitnessTests(unittest.TestCase):
    """The modelled instruction sequence is the one on the cartridge."""

    def test_92c8_sequence_matches_rom(self):
        DISPATCH_92C8.verify_against_rom(b)

    def test_no_clamp_instruction_between_load_and_dispatch(self):
        """No CPY/CMP bounds $071F between $92B0 and the JSR at $92BC."""
        opcodes = {b(addr) for addr in range(0x92B0, 0x92BC)}
        for compare in (0xC0, 0xC4, 0xCC,        # CPY imm/zp/abs
                        0xC9, 0xC5, 0xCD,        # CMP imm/zp/abs
                        0xE0, 0xE4, 0xEC,        # CPX imm/zp/abs
                        0x29):                   # AND imm
            with self.subTest(opcode=compare):
                self.assertNotIn(compare, opcodes)

    def test_table_at_92cb_has_eight_rom_entries(self):
        for index in range(8):
            target = b(0x92CB + 2 * index) | b(0x92CB + 2 * index + 1) << 8
            with self.subTest(index=index):
                self.assertGreaterEqual(target, 0x8000)

    def test_index_eight_leaves_prg_rom(self):
        """$071F == 9 resolves outside ROM: the bound is load-bearing."""
        from jumpengine import resolve_table
        from memory import memory_region

        resolution = resolve_table(b, 0x92CB, zero_substituted_index(9))
        self.assertEqual(resolution.target, 0x26EE)
        self.assertNotEqual(memory_region(resolution.target), "prg_rom")


if __name__ == "__main__":
    unittest.main()
