"""Decoder, CFG and interpreter tests (plan sections 5, 19).

Synthetic fixtures are original hand-assembled byte sequences; the ROM-backed
cases are skipped when the verified cartridge is absent.  The fixture named
`BIT_TRICK` deserves a note: `$2C` as a one-byte filler makes the following
two-byte instruction into the operand of a `BIT`, so the same bytes mean
different things depending on the entry point.  SMB1 really does this (at
`$8220`, `$996A`, `$BDD4` and elsewhere), and the old tracer dropped the second
reading, which is the bug these tests pin down.
"""

from __future__ import annotations

import unittest

from analysis import valueset as vs
from analysis.cfg import CFG, build_from_vectors
from analysis.decoder import (
    DOCUMENTED_COUNT,
    MODE_LENGTH,
    OPCODES,
    Flow,
    decode,
    indirect_jump_pointer,
    zero_page_indexed,
)
from analysis.interpret import branch_outcomes, explore, step
from analysis.valueset import Memory, State

try:
    from rom import b, image

    image()
    ROM_AVAILABLE, ROM_SKIP = True, ""
except Exception as exc:  # pragma: no cover
    ROM_AVAILABLE, ROM_SKIP = False, f"verified SMB1 ROM unavailable: {exc}"


def reader(base: int, blob: bytes, *, fill: int = 0x00):
    def read(address: int) -> int:
        offset = (address & 0xFFFF) - base
        return blob[offset] if 0 <= offset < len(blob) else fill
    return read


class OpcodeTableTests(unittest.TestCase):
    def test_all_256_encodings_decode(self):
        self.assertEqual(len(OPCODES), 256)

    def test_documented_instruction_count(self):
        """The NMOS 6502 has 151 documented encodings, 105 undocumented."""
        self.assertEqual(DOCUMENTED_COUNT, 151)
        self.assertEqual(256 - DOCUMENTED_COUNT, 105)

    def test_twelve_jam_encodings(self):
        jams = [i for i in OPCODES.values() if i.flow is Flow.HALT]
        self.assertEqual(len(jams), 12)

    def test_undocumented_opcodes_are_not_all_nops(self):
        """SLO/RLA/SRE/RRA/DCP/ISC write memory; SAX/SHA/SHX/SHY store."""
        undocumented = {i.mnemonic for i in OPCODES.values()
                        if not i.documented}
        for mnemonic in ("SLO", "RLA", "SRE", "RRA", "DCP", "ISC", "SAX",
                         "LAX", "SHA", "SHX", "SHY"):
            with self.subTest(mnemonic=mnemonic):
                self.assertIn(mnemonic, undocumented)

    def test_undocumented_lengths_are_not_all_one(self):
        """Treating an undocumented opcode as a 1-byte stop mis-aligns code."""
        multi = [i for i in OPCODES.values()
                 if not i.documented and i.length > 1]
        self.assertGreater(len(multi), 60)

    def test_mode_lengths_consistent(self):
        for info in OPCODES.values():
            with self.subTest(opcode=info.opcode):
                self.assertEqual(info.length, MODE_LENGTH[info.mode])


class AddressingSemanticsTests(unittest.TestCase):
    def test_branch_displacement_is_signed_from_next_instruction(self):
        forward = decode(reader(0x9000, bytes.fromhex("d005")), 0x9000)
        self.assertEqual(forward.branch_target, 0x9007)
        backward = decode(reader(0x9000, bytes.fromhex("d0f8")), 0x9000)
        self.assertEqual(backward.branch_target, 0x8FFA)

    def test_branch_wraps_at_64k(self):
        wrapping = decode(reader(0xFFFE, bytes.fromhex("d005")), 0xFFFE)
        self.assertEqual(wrapping.branch_target, 0x0005)

    def test_indirect_jmp_page_wrap_bug(self):
        self.assertEqual(indirect_jump_pointer(0x10FF), (0x10FF, 0x1000))
        self.assertEqual(indirect_jump_pointer(0x1000), (0x1000, 0x1001))

    def test_zero_page_index_wraps_in_page_zero(self):
        self.assertEqual(zero_page_indexed(0xF0, 0x20), 0x10)

    def test_instruction_end_wraps(self):
        instruction = decode(reader(0xFFFF, bytes.fromhex("ea")), 0xFFFF)
        self.assertEqual(instruction.end, 0x0000)


class OverlappingDecodingTests(unittest.TestCase):
    #: $9000 LDY #$00 / $9002 .byte $2C (BIT) swallowing $9003 LDY #$04,
    #: both continuing at $9005 RTS -- two entry points, one byte stream.
    BIT_TRICK = bytes.fromhex("a000" "2c" "a004" "60")

    def graph(self) -> CFG:
        graph = CFG(reader(0x9000, self.BIT_TRICK),
                    code_range=(0x9000, 0x9006))
        graph.add_entry(0x9000, "outer entry")
        graph.add_entry(0x9003, "inner entry")
        return graph.build()

    def test_both_alignments_are_kept(self):
        starts = self.graph().instruction_starts
        self.assertIn(0x9002, starts)      # BIT $04A0
        self.assertIn(0x9003, starts)      # LDY #$04, inside that BIT

    def test_overlap_is_reported(self):
        overlap = self.graph().overlapping_starts()
        self.assertIn(0x9003, overlap)
        self.assertIn(0x9002, overlap[0x9003])

    def test_entering_one_byte_later_changes_the_instruction(self):
        read = reader(0x9000, self.BIT_TRICK)
        self.assertEqual(decode(read, 0x9002).info.mnemonic, "BIT")
        self.assertEqual(decode(read, 0x9003).info.mnemonic, "LDY")


class UnresolvedTransferTests(unittest.TestCase):
    def test_rts_is_recorded_as_unresolved(self):
        graph = CFG(reader(0x9000, bytes.fromhex("60")),
                    code_range=(0x9000, 0x9001))
        graph.add_entry(0x9000, "entry")
        graph.build()
        self.assertEqual(len(graph.unresolved), 1)
        self.assertEqual(graph.unresolved[0][1], "rts")

    def test_undocumented_opcode_does_not_stop_the_walk(self):
        """`$1A` (undocumented NOP) then `LDA #$01`: both must be decoded."""
        graph = CFG(reader(0x9000, bytes.fromhex("1a" "a901" "60")),
                    code_range=(0x9000, 0x9005))
        graph.add_entry(0x9000, "entry")
        graph.build()
        self.assertIn(0x9001, graph.instruction_starts)
        self.assertIn(0x9000, graph.undocumented)

    def test_jam_has_no_successors(self):
        graph = CFG(reader(0x9000, bytes.fromhex("02" "a901")),
                    code_range=(0x9000, 0x9003))
        graph.add_entry(0x9000, "entry")
        graph.build()
        self.assertEqual(graph.nodes[0x9000].successors, [])
        self.assertIn(0x9000, graph.halts)


class BranchFeasibilityTests(unittest.TestCase):
    def test_load_of_nonzero_makes_bne_unconditional(self):
        """`LDA #$0B / BNE` cannot fall through -- the old tracer thought it could."""
        read = reader(0x9000, bytes.fromhex("a90b" "d002" "ea" "ea" "60"))
        memory = Memory(read, rom_floor=0x9000)
        state = step(State(), decode(read, 0x9000), memory)
        outcomes = branch_outcomes(state, decode(read, 0x9002))
        self.assertEqual([taken for taken, _ in outcomes], [True])

    def test_load_of_zero_makes_beq_unconditional(self):
        read = reader(0x9000, bytes.fromhex("a900" "f002" "ea" "ea" "60"))
        memory = Memory(read, rom_floor=0x9000)
        state = step(State(), decode(read, 0x9000), memory)
        outcomes = branch_outcomes(state, decode(read, 0x9002))
        self.assertEqual([taken for taken, _ in outcomes], [True])

    def test_comparison_refines_both_sides(self):
        """`CMP #$05 / BCS` splits the accumulator at five."""
        read = reader(0x9000, bytes.fromhex("c905" "b002"))
        memory = Memory(read, rom_floor=0x9000)
        state = step(State(), decode(read, 0x9000), memory)
        outcomes = dict((taken, refined)
                        for taken, refined in branch_outcomes(
                            state, decode(read, 0x9002)))
        self.assertEqual(vs.values(outcomes[False].a), list(range(0, 5)))
        self.assertEqual(vs.values(outcomes[True].a), list(range(5, 256)))

    def test_unknown_flag_leaves_both_edges_feasible(self):
        read = reader(0x9000, bytes.fromhex("d002"))
        state = State()
        outcomes = branch_outcomes(state, decode(read, 0x9000))
        self.assertEqual(sorted(taken for taken, _ in outcomes), [False, True])

    def test_zero_substitution_sequence_derives_the_corrected_model(self):
        """The `$92C8` idiom, on a synthetic fixture: no clamp appears."""
        #: LDY $0400 / BNE +5 / LDY #$08 / STY $0400 / DEY / TYA / RTS
        blob = bytes.fromhex("ac0004" "d005" "a008" "8c0004" "88" "98" "60")
        read = reader(0x9000, blob)
        memory = Memory(read, rom_floor=0x9000)      # $0400 reads unknown
        exploration = explore(read, 0x9000, State(), memory,
                              stop_at=frozenset({0x900C}))
        derived = vs.values(exploration.register_at(0x900C, "A"))
        expected = sorted({((v or 8) - 1) & 0xFF for v in range(256)})
        self.assertEqual(derived, expected)
        self.assertIn(8, derived)        # index 8 is reachable: no clamp
        self.assertNotIn(255, derived)


@unittest.skipUnless(ROM_AVAILABLE, ROM_SKIP)
class ROMDerivationTests(unittest.TestCase):
    """The derivation and the hand-written model must agree on the ROM."""

    @classmethod
    def setUpClass(cls):
        cls.graph = build_from_vectors(b)

    def test_eighteen_dispatch_sites(self):
        self.assertEqual(len(self.graph.dispatches), 18)

    def test_single_indirect_jump(self):
        indirect = [u for u in self.graph.unresolved
                    if u[1] == "indirect_jump"]
        self.assertEqual(len(indirect), 1)
        self.assertEqual(indirect[0][0], 0x8E16)

    def test_rts_instructions_are_unresolved_transfers(self):
        """The 'one computed jump' claim ignores every RTS; there are many."""
        returns = [u for u in self.graph.unresolved if u[1] == "rts"]
        self.assertGreater(len(returns), 100)

    def test_overlapping_starts_exist_in_the_rom(self):
        self.assertTrue(self.graph.overlapping_starts())

    def test_cfg_reaches_at_least_as_much_as_the_old_tracer(self):
        self.assertGreaterEqual(len(self.graph.occupied_bytes()), 22783)

    def test_derived_92c8_matches_the_hand_model(self):
        """Two independent models of the same site agree exactly."""
        from analysis.dispatch_index import zero_substituted_index
        from analysis.index_derivation import derive_site

        derived = set(derive_site(b, self.graph, 0x92C8).indices)
        modelled = {zero_substituted_index(v) for v in range(256)}
        self.assertEqual(derived, modelled)

    def test_derived_92c8_is_in_range_only_under_the_invariant(self):
        from analysis.index_derivation import derive_conditional, derive_site

        self.assertTrue(derive_site(b, self.graph, 0x92C8).overruns_table)
        conditional = derive_conditional(b, self.graph, 0x92C8)
        self.assertFalse(conditional.overruns_table)
        self.assertEqual(conditional.maximum, 7)
        self.assertTrue(conditional.bound().assumptions)
        self.assertFalse(conditional.bound().is_unconditional)

    def test_d2e5_is_bounded_with_no_assumption(self):
        """`CMP #$05 / BCS` is a real clamp: this one was documented right."""
        from analysis.index_derivation import derive_site

        derivation = derive_site(b, self.graph, 0xD2E5)
        self.assertEqual(derivation.indices, [0, 1, 2, 3, 4])
        self.assertFalse(derivation.overruns_table)
        self.assertTrue(derivation.bound().is_unconditional)

    def test_b34e_has_no_local_bound(self):
        """`CMP #$03 / BEQ` at $B345 does not clamp: both paths dispatch."""
        from analysis.index_derivation import derive_site

        derivation = derive_site(b, self.graph, 0xB34E)
        self.assertEqual(len(derivation.indices), 256)
        self.assertTrue(derivation.overruns_table)

    def test_bdbd_is_bounded_interprocedurally(self):
        """Bounded by $BDF6 returning Y <= 13, not by the CMP #$09."""
        from analysis.index_derivation import derive_site

        derivation = derive_site(b, self.graph, 0xBDBD)
        self.assertEqual(derivation.maximum, 8)
        self.assertFalse(derivation.overruns_table)


if __name__ == "__main__":
    unittest.main()
