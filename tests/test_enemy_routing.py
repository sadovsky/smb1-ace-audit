"""Enemy-ID routing: independent reproduction and local bounds (plan 2, 12).

`analysis.enemy_routing` derives the routed identifier sets from the CFG's own
dispatch tables; `reach.py` derives them from `trace.json`.  Agreement between
two independently written derivations is the point of these tests -- it is the
"independently reproduce existing empirical results" obligation, and it is the
reason the enemy bounds can be called derived rather than assumed.

What is *not* claimed: preservation of the identifier between the `CPY #$15`
gate and the downstream dispatch.  `test_bounds_are_never_unconditional`
asserts that no enemy bound is ever promoted to PROVEN.
"""

from __future__ import annotations

import unittest

from analysis.enemy_routing import MAX_LEGAL_ID, collision_index, derive, sub_index
from analysis.provenance import BoundProvenance

try:
    from rom import b, image

    image()
    ROM_AVAILABLE, ROM_SKIP = True, ""
except Exception as exc:  # pragma: no cover
    ROM_AVAILABLE, ROM_SKIP = False, f"verified SMB1 ROM unavailable: {exc}"


class IndexArithmeticTests(unittest.TestCase):
    def test_collision_index_substitutes_zero_below_the_gate(self):
        for identifier in range(0x15):
            with self.subTest(identifier=identifier):
                self.assertEqual(collision_index(identifier), 0)

    def test_collision_index_subtracts_above_the_gate(self):
        self.assertEqual(collision_index(0x15), 1)
        self.assertEqual(collision_index(0x36), 34)

    def test_subtraction_wraps_below_the_offset(self):
        """`SBC #$12` on ID $11 wraps to $FF: the offset is not a clamp."""
        self.assertEqual(sub_index(0x12)(0x11), 0xFF)
        self.assertEqual(sub_index(0x12)(0x12), 0)


@unittest.skipUnless(ROM_AVAILABLE, ROM_SKIP)
class RoutingAgreementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from analysis.cfg import build_from_vectors

        cls.graph = build_from_vectors(b)
        cls.routing = derive(cls.graph)

    def test_all_five_enemy_sites_present(self):
        self.assertEqual(sorted(self.routing),
                         [0xC27F, 0xC7A8, 0xC88F, 0xC907, 0xC987])

    def test_agrees_with_reach_py(self):
        """Two independent derivations of the arriving identifier sets."""
        import reach

        tables = reach.load_tables()
        expected = reach.derive(tables)
        for dispatch, (_role, _index, identifiers) in expected.items():
            with self.subTest(dispatch=f"${dispatch:04X}"):
                self.assertEqual(set(self.routing[dispatch].arriving),
                                 set(identifiers))

    def test_agrees_with_reach_py_on_index_spans(self):
        import reach

        tables = reach.load_tables()
        for dispatch, (_role, index_of, identifiers) in \
                reach.derive(tables).items():
            with self.subTest(dispatch=f"${dispatch:04X}"):
                self.assertEqual(self.routing[dispatch].indices,
                                 {index_of(i) for i in identifiers})

    def test_only_c88f_goes_out_of_range(self):
        out_of_range = {d: r.out_of_range for d, r in self.routing.items()
                        if r.out_of_range}
        self.assertEqual(sorted(out_of_range), [0xC88F])
        self.assertEqual(out_of_range[0xC88F], {0x36: 34})

    def test_c88f_out_of_range_destination_is_a_ppu_register(self):
        from jumpengine import resolve_table
        from memory import memory_region

        table = self.graph.dispatches[0xC88F].table
        target = resolve_table(b, table, 34).target
        self.assertEqual(target, 0x2060)
        self.assertEqual(memory_region(target), "ppu_registers")

    def test_identifier_domain_matches_the_master_table(self):
        master = self.graph.dispatches[0xC27F]
        self.assertEqual(len(master.entries), MAX_LEGAL_ID + 1)

    def test_bounds_are_never_unconditional(self):
        """Routing cannot prove preservation, so nothing here is PROVEN."""
        for dispatch, route in self.routing.items():
            with self.subTest(dispatch=f"${dispatch:04X}"):
                self.assertIs(route.provenance,
                              BoundProvenance.DERIVED_CONDITIONAL)
                self.assertTrue(any("preservation" in assumption
                                    for assumption in route.assumptions()))


@unittest.skipUnless(ROM_AVAILABLE, ROM_SKIP)
class LocalDerivationTests(unittest.TestCase):
    """The value-set derivation must reproduce the routing arithmetic."""

    @classmethod
    def setUpClass(cls):
        from analysis.cfg import build_from_vectors

        cls.graph = build_from_vectors(b)

    def derived(self, dispatch: int):
        from analysis.index_derivation import derive_conditional

        return derive_conditional(b, self.graph, dispatch)

    def test_local_derivations_match_the_routing_arithmetic(self):
        routing = derive(self.graph)
        for dispatch in (0xC27F, 0xC7A8, 0xC88F, 0xC907, 0xC987):
            with self.subTest(dispatch=f"${dispatch:04X}"):
                derivation = self.derived(dispatch)
                self.assertFalse(derivation.truncated)
                self.assertEqual(set(derivation.indices),
                                 routing[dispatch].indices)

    def test_local_derivations_record_their_preconditions(self):
        derivation = self.derived(0xC907)
        self.assertIsNotNone(derivation.local_entry)
        self.assertTrue(derivation.preconditions)
        self.assertTrue(any("X in" in p for p in derivation.preconditions))

    def test_c88f_overruns_by_exactly_one_index(self):
        derivation = self.derived(0xC88F)
        self.assertEqual(derivation.maximum, 34)
        self.assertEqual(derivation.entries, 34)
        self.assertTrue(derivation.overruns_table)

    def test_9664_index_is_not_sourced_from_0e(self):
        """The old table named $0E; the ROM adds $00 and $07."""
        from analysis.index_derivation import CANDIDATE_INVARIANTS

        assumption = CANDIDATE_INVARIANTS[0x9664]
        self.assertIs(assumption.provenance, BoundProvenance.UNPROVED)
        self.assertEqual(assumption.addresses, ())
        sources = self.derived(0x9664).sources
        self.assertTrue(any("$00" in s for s in sources))


if __name__ == "__main__":
    unittest.main()
