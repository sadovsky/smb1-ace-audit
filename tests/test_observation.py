"""The observation experiment's pure logic (plan section 15).

These tests need no emulator.  They pin the one thing the experiment must not
get wrong: a variable that feeds several dispatches with different table sizes
cannot be judged against the tightest of them.  `$0772` indexes tables of 3, 4,
4 and 5 entries, so the value 3 is in range at three sites and out of range at
one, and a frame sample cannot say which dispatch was running.  The first
version of this experiment reported that as an out-of-range finding, which is
exactly the error the plan warns about: an aggregate maximum is not a
site-specific bound.
"""

from __future__ import annotations

import importlib.util
import pathlib
import unittest

_spec = importlib.util.spec_from_file_location(
    "observe_indices",
    pathlib.Path(__file__).resolve().parent.parent
    / "experiments" / "observe_indices.py")
observe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(observe)


class IndexFormationTests(unittest.TestCase):
    def test_071f_uses_the_zero_substitution(self):
        self.assertEqual(observe.index_for(0x071F, 0), 7)
        self.assertEqual(observe.index_for(0x071F, 8), 7)
        self.assertEqual(observe.index_for(0x071F, 9), 8)

    def test_other_variables_are_used_raw(self):
        self.assertEqual(observe.index_for(0x0733, 3), 3)
        self.assertEqual(observe.index_for(0x0772, 3), 3)

    def test_matches_the_analysis_model(self):
        from analysis.dispatch_index import zero_substituted_index

        for value in range(256):
            with self.subTest(value=value):
                self.assertEqual(observe.index_for(0x071F, value),
                                 zero_substituted_index(value))


class SiteAttributionTests(unittest.TestCase):
    def test_0772_feeds_four_sites_with_different_tables(self):
        _label, _how, sites = observe.WATCHED[0x0772]
        self.assertEqual(sorted(sites.values()), [3, 4, 4, 5])

    def test_value_three_is_in_range_at_three_of_those_sites(self):
        _label, _how, sites = observe.WATCHED[0x0772]
        exceeded = [site for site, entries in sites.items() if 3 >= entries]
        in_range = [site for site, entries in sites.items() if 3 < entries]
        self.assertEqual(exceeded, [0x921B])
        self.assertEqual(len(in_range), 3)

    def test_single_site_variables_are_unambiguous(self):
        for address in (0x071F, 0x0733, 0x0770, 0x000E, 0x001D, 0x073C,
                        0x0746):
            with self.subTest(address=f"${address:04X}"):
                _label, _how, sites = observe.WATCHED[address]
                self.assertEqual(len(sites), 1)

    def test_9743_table_size_matches_the_established_boundary(self):
        """3 entries, not the 5 the old heuristic read."""
        _label, _how, sites = observe.WATCHED[0x0733]
        self.assertEqual(sites[0x9743], 3)

    def test_c7a8_is_not_watched_because_its_index_is_not_a_ram_byte(self):
        self.assertNotIn(0x0016, observe.WATCHED)


class InputModelTests(unittest.TestCase):
    def test_actions_are_single_bytes(self):
        import random

        rng = random.Random(1)
        for frame in range(0, 3000, 7):
            with self.subTest(frame=frame):
                action = observe.input_sequence(rng, frame)
                self.assertIsInstance(action, int)
                self.assertTrue(0 <= action <= 0xFF)

    def test_random_mode_can_emit_opposing_directions(self):
        """TAS-feasible input is permitted and must be labelled as such."""
        import random

        rng = random.Random(0)
        # mode 2 (frames 1200-1799) is the fully random segment
        actions = {observe.input_sequence(rng, f) for f in range(1200, 1800)}
        self.assertTrue(any(a & observe.LEFT and a & observe.RIGHT
                            for a in actions))


if __name__ == "__main__":
    unittest.main()
