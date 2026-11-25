"""Abstract stack semantics (plan section 8).

The synthetic fixtures pin the behaviours the old pattern scan could not see,
and one ROM test is a regression guard for a false positive this analysis
produced before it modelled branch feasibility: at `$BEAF` a `BCC` is followed
by a `BCS` on the same carry, so the fallthrough into `$BEB3` cannot occur.
Following it reached a `PLA` with the entry frame on top and made the balanced
routine at `$BE70` look as though it returned through a frame it never created.
"""

from __future__ import annotations

import unittest

from analysis.cfg import CFG
from analysis.stack import Cell, Summary, analyse, routine_entries

try:
    from rom import b, image

    image()
    ROM_AVAILABLE, ROM_SKIP = True, ""
except Exception as exc:  # pragma: no cover
    ROM_AVAILABLE, ROM_SKIP = False, f"verified SMB1 ROM unavailable: {exc}"


def reader(base: int, blob: bytes):
    def read(address: int) -> int:
        offset = (address & 0xFFFF) - base
        return blob[offset] if 0 <= offset < len(blob) else 0x00
    return read


def graph_for(blob: bytes, entries: tuple[int, ...] = (0x9000,),
              base: int = 0x9000) -> CFG:
    graph = CFG(reader(base, blob), code_range=(base, base + len(blob)))
    for entry in entries:
        graph.add_entry(entry, "test entry")
    return graph.build()


class FrameCellTests(unittest.TestCase):
    def test_a_frame_is_two_cells(self):
        """JSR pushes the high byte first, so the low byte is on top."""
        self.assertIsNot(Cell.FRAME_LO, Cell.FRAME_HI)


class SyntheticRoutineTests(unittest.TestCase):
    def test_plain_routine_is_balanced(self):
        #: $9000 LDA #$01 / RTS
        results = analyse(graph_for(bytes.fromhex("a901" "60")))
        self.assertEqual(results[0x9000].summary, Summary.BALANCED)
        self.assertTrue(all(r.verified for r in results[0x9000].returns))

    def test_balanced_push_and_pull_is_balanced(self):
        #: PHA / PLA / RTS
        results = analyse(graph_for(bytes.fromhex("48" "68" "60")))
        self.assertEqual(results[0x9000].summary, Summary.BALANCED)

    def test_leaked_push_is_caught(self):
        """PHA then RTS: the RTS returns through the pushed byte."""
        #: PHA / RTS
        results = analyse(graph_for(bytes.fromhex("48" "60")))
        result = results[0x9000]
        self.assertEqual(result.summary, Summary.UNRESOLVED)
        self.assertFalse(result.returns[0].verified)
        self.assertIn("computed return", result.returns[0].detail)

    def test_rts_trick_is_caught(self):
        """Push a computed address, then RTS to it -- a computed return."""
        #: LDA #$12 / PHA / LDA #$34 / PHA / RTS  (after the entry frame)
        blob = bytes.fromhex("a912" "48" "a934" "48" "60")
        result = analyse(graph_for(blob))[0x9000]
        self.assertEqual(result.summary, Summary.UNRESOLVED)
        self.assertFalse(result.returns[0].verified)

    def test_consuming_the_caller_frame_is_recognised(self):
        """Two PLAs take the whole frame, then leave by an indirect jump.

        This is the JumpEngine's shape: consume the caller's return address,
        use it as a table pointer, and jump.  A routine that consumed the
        frame and then executed RTS would instead be making a computed return,
        which the analysis reports as unresolved.
        """
        #: PLA / PLA / JMP ($0006)
        blob = bytes.fromhex("68" "68" "6c0600")
        result = analyse(graph_for(blob))[0x9000]
        self.assertEqual(result.summary, Summary.CONSUMES_FRAME)
        self.assertTrue(any("return frame" in note for note in result.notes))

    def test_consuming_the_frame_then_returning_is_unresolved(self):
        #: PLA / PLA / RTS
        result = analyse(graph_for(bytes.fromhex("68" "68" "60")))[0x9000]
        self.assertEqual(result.summary, Summary.UNRESOLVED)
        self.assertFalse(result.returns[0].verified)

    def test_txs_makes_the_routine_unresolved(self):
        #: LDX #$FF / TXS / RTS
        result = analyse(graph_for(bytes.fromhex("a2ff" "9a" "60")))[0x9000]
        self.assertEqual(result.summary, Summary.UNRESOLVED)
        self.assertTrue(any("TXS" in note for note in result.notes))

    def test_complementary_branches_prune_the_impossible_path(self):
        """`BCC +2 / BCS +2` leaves no fallthrough: the PLA is unreachable.

        Without flag-driven pruning the fallthrough is followed, the PLA eats
        the entry frame, and the RTS is wrongly reported unverified.
        """
        #: $9000 BCC $9005 / $9002 BCS $9006 / $9004 PLA (unreachable) /
        #: $9005 RTS / $9006 RTS
        blob = bytes.fromhex("9003" "b002" "68" "60" "60")
        result = analyse(graph_for(blob))[0x9000]
        self.assertEqual(result.summary, Summary.BALANCED)
        self.assertTrue(all(r.verified for r in result.returns))


@unittest.skipUnless(ROM_AVAILABLE, ROM_SKIP)
class ROMStackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from analysis.cfg import build_from_vectors

        cls.graph = build_from_vectors(b)
        cls.results = analyse(cls.graph)
        cls.returns = [r for result in cls.results.values()
                       for r in result.returns]

    def test_every_reachable_rts_consumes_its_entry_frame(self):
        """Supports the earlier claim, by a method that can carry it."""
        unverified = [r for r in self.returns
                      if not r.verified and r.mnemonic == "RTS"]
        self.assertEqual(unverified, [])

    def test_the_only_unverified_return_is_the_nmi_rti(self):
        unverified = [r for r in self.returns if not r.verified]
        self.assertEqual([r.address for r in unverified], [0x8181])
        self.assertEqual(unverified[0].mnemonic, "RTI")

    def test_be70_is_balanced_not_a_computed_return(self):
        """Regression: this routine was a false positive before flag pruning."""
        result = self.results[0xBE70]
        self.assertEqual(result.summary, Summary.BALANCED)
        self.assertTrue(all(r.verified for r in result.returns))

    def test_jumpengine_is_the_one_frame_consuming_routine(self):
        consuming = sorted(entry for entry, result in self.results.items()
                           if result.summary is Summary.CONSUMES_FRAME)
        self.assertEqual(consuming, [0x8E04])

    def test_jumpengine_pulls_both_frame_bytes(self):
        notes = " ".join(self.results[0x8E04].notes)
        self.assertIn("frame_lo", notes)
        self.assertIn("frame_hi", notes)

    def test_reset_is_unresolved_because_it_sets_the_stack_pointer(self):
        result = self.results[0x8000]
        self.assertEqual(result.summary, Summary.UNRESOLVED)
        self.assertTrue(any("TXS" in note for note in result.notes))

    def test_jumpengine_is_analysed_at_all(self):
        """The CFG models JSR $8E04 as a dispatch, not a call."""
        self.assertIn(0x8E04, routine_entries(self.graph))

    def test_stack_page_stores_are_reported(self):
        """A store into $0100-$01FF could rewrite a frame undetected."""
        from analysis.stack import stack_page_writers

        writers = stack_page_writers(b)
        self.assertTrue(writers)
        for writer in writers:
            with self.subTest(address=f"${writer.address:04X}"):
                self.assertIn(0x01FF, writer.targets)


if __name__ == "__main__":
    unittest.main()
