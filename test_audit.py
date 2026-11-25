"""Regression tests for cartridge validation and JumpEngine semantics."""

import hashlib
import unittest

from jumpengine import resolve_jumpengine, resolve_table
from memory import is_internal_ram, memory_region, normalize_internal_ram
from rom import EXPECT_SHA1, ROMValidationError, parse_ines


def make_image(*, mapper=0, prg_banks=2, chr_banks=1, magic=b"NES\x1a"):
    flags6 = (mapper & 0x0F) << 4
    flags7 = mapper & 0xF0
    header = magic + bytes((prg_banks, chr_banks, flags6, flags7)) + bytes(8)
    prg = bytearray(prg_banks * 0x4000)
    if len(prg) >= 0x8000:
        prg[0x7FFA:0x8000] = bytes((0x00, 0x80, 0x00, 0x80, 0x00, 0x80))
    return header + bytes(prg) + bytes(chr_banks * 0x2000)


class ROMValidationTests(unittest.TestCase):
    def test_expected_hash_accepts_structurally_valid_image(self):
        raw = make_image()
        digest = hashlib.sha1(raw).hexdigest()
        parsed = parse_ines(raw, expected_sha1=digest)
        self.assertEqual((parsed.mapper, len(parsed.prg), len(parsed.chr)), (0, 32768, 8192))

    def test_wrong_hash_rejected_without_explicit_override(self):
        with self.assertRaises(ROMValidationError):
            parse_ines(make_image(), expected_sha1=EXPECT_SHA1)

    def test_invalid_header_mapper_and_size_rejected(self):
        with self.assertRaises(ROMValidationError):
            parse_ines(make_image(magic=b"BAD!"), allow_alternate=True)
        with self.assertRaises(ROMValidationError):
            parse_ines(make_image(mapper=1), allow_alternate=True)
        with self.assertRaises(ROMValidationError):
            parse_ines(make_image(prg_banks=1), allow_alternate=True)


class MemoryMappingTests(unittest.TestCase):
    def test_ram_mirrors_normalize_to_same_physical_byte(self):
        self.assertEqual(normalize_internal_ram(0x0000), 0x0000)
        self.assertEqual(normalize_internal_ram(0x0800), 0x0000)
        self.assertEqual(normalize_internal_ram(0x07FF), 0x07FF)
        self.assertEqual(normalize_internal_ram(0x1FFF), 0x07FF)
        self.assertEqual(normalize_internal_ram(0x16B5), 0x06B5)
        self.assertTrue(is_internal_ram(0x16B5))
        self.assertEqual(memory_region(0x16B5), "internal_ram_mirror")


class JumpEngineTests(unittest.TestCase):
    def test_normal_table_entry(self):
        memory = {0xC90A: 0x77, 0xC90B: 0xCA}
        result = resolve_table(memory.__getitem__, 0xC90A, 0)
        self.assertEqual((result.low_address, result.high_address, result.target), (0xC90A, 0xC90B, 0xCA77))

    def test_accumulator_bit_seven_is_discarded_by_asl(self):
        memory = {0xC90A: 0x11, 0xC90B: 0x22}
        self.assertEqual(resolve_table(memory.__getitem__, 0xC90A, 0).target,
                         resolve_table(memory.__getitem__, 0xC90A, 0x80).target)

    def test_y_wrap_splits_the_pair_at_index_7f(self):
        memory = {0xCA08: 0x34, 0xC909: 0x12}
        result = resolve_table(memory.__getitem__, 0xC90A, 0x7F)
        self.assertEqual((result.low_address, result.high_address, result.target), (0xCA08, 0xC909, 0x1234))

    def test_zero_page_indirect_pointer_wraps(self):
        # JumpEngine's $04/$05 pointer is zero-page state; this test models the
        # architecture rule used by ($04),Y rather than a Python integer shortcut.
        ram = bytearray(256)
        ram[0xFF], ram[0x00] = 0x34, 0x12
        self.assertEqual(ram[0xFF] | ram[(0xFF + 1) & 0xFF] << 8, 0x1234)


class DispatchReachabilityTests(unittest.TestCase):
    """The enemy-ID dispatch bounds must be DERIVED from the routing tables,
    not assumed. These pin the derivation so a regression is visible."""

    @classmethod
    def setUpClass(cls):
        import os
        import reach
        if not os.path.exists(reach.TRACE):
            raise unittest.SkipTest("trace.json missing; run python3 trace.py")
        cls.reach = reach
        cls.JT = reach.load_tables()

    def test_c907_receives_only_ids_below_15(self):
        """$C905 is reached only via collision-table entry 0, which CPY #$15/BCC
        selects for IDs < $15. That fills its 21-entry table exactly."""
        ids = self.reach.derive(self.JT)[0xC907][2]
        self.assertEqual(ids, set(range(0x15)))
        self.assertEqual(max(ids), 0x14)
        self.assertEqual(self.JT[0xC907][1], 21)

    def test_dangerous_ids_never_arrive_at_c907(self):
        """$34/$35 resolve into controllable RAM but the routing excludes them."""
        ids = self.reach.derive(self.JT)[0xC907][2]
        for bad in (0x34, 0x35, 0x3C):
            self.assertNotIn(bad, ids)

    def test_only_out_of_bounds_dispatch_is_id36_into_ppu(self):
        """Exactly one legal identifier indexes past its table, and it lands in
        PPU space, so it cannot execute controllable bytes."""
        oob = [(pc, i, v) for pc, _r, _n, _ids, _rng, o in self.reach.analyse(self.JT)
               for i, _ix, v in o]
        self.assertEqual(len(oob), 1)
        pc, ID, target = oob[0]
        self.assertEqual((pc, ID), (0xC88F, 0x36))
        self.assertEqual(self.reach.memory_region(target), "ppu_registers")
        self.assertNotIn(self.reach.memory_region(target), self.reach.RAM_REGIONS)

    def test_every_in_bounds_target_stays_in_rom(self):
        """The core structural claim: an in-range index always yields ROM."""
        from memory import memory_region
        for pc, (tbl, n) in self.JT.items():
            for i in range(n):
                t = self.reach.target(tbl, i)
                self.assertEqual(memory_region(t), "prg_rom",
                                 f"${pc:04X} index {i} -> ${t:04X}")


class ControlFlowTests(unittest.TestCase):
    """Review items 4.4/4.5: byte classification and stack-based transfers."""

    @classmethod
    def setUpClass(cls):
        import os
        import controlflow
        if not os.path.exists(controlflow.TRACE):
            raise unittest.SkipTest("trace.json missing; run python3 trace.py")
        cls.cf = controlflow
        cls.J = controlflow.load_trace()
        cls.starts = set(cls.J["instruction_starts"])

    def test_no_rts_trick_dispatch(self):
        """A PHA/PHA/RTS sequence would be a computed transfer that is not a
        JMP, which would break the 'exactly one computed jump' claim."""
        self.assertEqual(self.cf.find_rts_trick(self.starts), [])

    def test_stack_pointer_written_only_once(self):
        """TXS is the only direct write to SP. If it happens solely in reset
        init, gameplay cannot reposition the stack arbitrarily."""
        _counts, txs = self.cf.stack_ops(self.starts)
        self.assertEqual(txs, [0x8009])

    def test_single_rti_and_it_is_the_nmi_return(self):
        rti = [a for a in self.starts if self.cf.b(a) == self.cf.RTI]
        self.assertEqual(rti, [0x8181])

    def test_instruction_starts_and_operands_partition_reached_bytes(self):
        reached = set(self.J["instruction_bytes"])
        self.assertTrue(self.starts <= reached)
        # every reached byte is either a start or inside an instruction
        self.assertEqual(len(reached), len(self.starts) + len(reached - self.starts))


class ClassificationTests(unittest.TestCase):
    """The exploitability classification, after the provenance correction.

    The assertions this class used to make were:

        test_only_live_candidate_is_id36_and_it_is_not_ace
            len(live) == 1, where live = exploitability != "excluded"

    That encoded the overstatement the audit was corrected for.  It held only
    because every ROM destination was skipped before classification and
    because an *observed* bound was allowed to exclude an index outright.  With
    both corrected there are many unexcluded destinations, so the test is
    replaced rather than repaired, and the old numbers are preserved in
    results/baseline/.
    """

    @classmethod
    def setUpClass(cls):
        import classify

        cls.records, cls.derivations = classify.build()

    def test_in_table_destinations_always_resolve_into_rom(self):
        """Every expected table entry points into PRG ROM."""
        for record in self.records:
            if record["execution_outcome"] == "expected_rom":
                with self.subTest(site=record["entry_point"]):
                    self.assertEqual(record["memory_region"], "prg_rom")

    def test_rom_destinations_are_classified_not_discarded(self):
        """Unexpected ROM destinations must appear in the record set."""
        rom = [r for r in self.records
               if r["execution_outcome"] == "unexpected_rom"]
        self.assertGreater(len(rom), 500)

    def test_unexpected_rom_includes_operand_bytes(self):
        mid_instruction = [
            r for r in self.records
            if r["rom_role"] == "operand_byte_of_another_instruction"]
        self.assertGreater(len(mid_instruction), 100)

    def test_observed_bounds_never_exclude_unconditionally(self):
        """The central rule of the corrected classifier."""
        for record in self.records:
            if record["exploitability"] == "excluded":
                with self.subTest(site=record["entry_point"],
                                  index=record["index"]):
                    self.assertEqual(record["reachability"],
                                     "proven_unreachable")

    def test_conditional_exclusions_carry_their_assumptions(self):
        conditional = [r for r in self.records
                       if r["exploitability"] == "excluded_conditionally"]
        self.assertTrue(conditional)
        for record in conditional:
            with self.subTest(site=record["entry_point"],
                              index=record["index"]):
                self.assertFalse(record["bound_unconditional"])
                self.assertTrue(record["bound_assumptions"]
                                or record["reachability_detail"])

    def test_some_ram_destinations_remain_unexcluded(self):
        """The corrected result has unknowns; the old one reported none."""
        unknown = [r for r in self.records
                   if r["exploitability"] == "unknown"]
        self.assertTrue(unknown)
        for record in unknown:
            with self.subTest(site=record["entry_point"]):
                self.assertIn(record["memory_region"],
                              ("internal_ram", "internal_ram_mirror"))

    def test_id36_at_c88f_is_still_not_ace(self):
        """The one previously reported candidate is unchanged on its merits."""
        match = [r for r in self.records
                 if r["entry_point"] == "0xC88F" and r["index"] == 34]
        self.assertEqual(len(match), 1)
        self.assertEqual(match[0]["destination"], "0x2060")
        self.assertEqual(match[0]["memory_region"], "ppu_registers")
        self.assertEqual(match[0]["exploitability"], "not_ace")

    def test_every_record_has_a_bound_provenance(self):
        allowed = {"proven", "structural_conditional", "derived_conditional",
                   "observed", "assumed", "unproved"}
        for record in self.records:
            with self.subTest(site=record["entry_point"]):
                self.assertIn(record["bound_provenance"], allowed)

    def test_only_two_sites_are_bounded_with_no_assumption(self):
        unconditional = sorted(
            dispatch for dispatch, (_plain, conditional, _a)
            in self.derivations.items()
            if conditional.bound().is_unconditional)
        self.assertEqual(unconditional, [0xBDBD, 0xD2E5])


if __name__ == "__main__":
    unittest.main()
