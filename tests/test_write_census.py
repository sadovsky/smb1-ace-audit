"""Effective-address and write-census tests on synthetic byte streams.

Fixtures here are hand-assembled original byte sequences; they contain no ROM
content.  The point of each test is the one-sided direction of the
approximation: a store whose target is unknown must appear in a variable's
manifest, not vanish from it.
"""

from __future__ import annotations

import unittest

from analysis import effective_address as ea
from analysis.effective_address import AddressKnowledge
from analysis.write_census import census, decode_writer, manifest, writers_of


def reader(base: int, blob: bytes):
    """A CPU read function serving `blob` at `base`, zero elsewhere."""

    def read(address: int) -> int:
        address &= 0xFFFF
        offset = address - base
        return blob[offset] if 0 <= offset < len(blob) else 0x00

    return read


class EffectiveAddressTests(unittest.TestCase):
    def test_absolute_is_exact(self):
        addresses = ea.exact(0x071F)
        self.assertEqual(addresses.size, 1)
        self.assertIn(0x071F, addresses)
        self.assertNotIn(0x0720, addresses)

    def test_indexed_absolute_covers_the_whole_index_range(self):
        addresses = ea.indexed_absolute(0x06A1)
        self.assertEqual(addresses.size, 256)
        self.assertIn(0x06A1, addresses)
        self.assertIn(0x071F, addresses)          # $06A1 + 126
        self.assertIn(0x07A0, addresses)          # $06A1 + 255
        self.assertNotIn(0x07A1, addresses)

    def test_indexed_absolute_wraps_at_64k(self):
        addresses = ea.indexed_absolute(0xFFF0)
        self.assertIn(0xFFFF, addresses)
        self.assertIn(0x0000, addresses)
        self.assertIn(0x00EF, addresses)
        self.assertNotIn(0x00F0, addresses)

    def test_zero_page_indexed_stays_in_page_zero(self):
        """`STA $F0,X` can reach $00 but never $0100."""
        addresses = ea.indexed_page_zero(0xF0)
        self.assertIn(0x00FF, addresses)
        self.assertIn(0x0000, addresses)
        self.assertNotIn(0x0100, addresses)

    def test_unresolved_pointer_covers_everything(self):
        addresses = ea.unresolved_pointer(0x06, "(zp),Y")
        self.assertFalse(addresses.is_resolved)
        self.assertEqual(addresses.size, 0x10000)
        self.assertIn(0x071F, addresses)

    def test_constraining_an_index_shrinks_the_set(self):
        addresses = ea.constrain_indexed(0x06A1, set(range(0, 14)))
        self.assertEqual(addresses.size, 14)
        self.assertIn(0x06A1, addresses)
        self.assertNotIn(0x071F, addresses)
        self.assertIs(addresses.knowledge, AddressKnowledge.INDEXED_RANGE)


class DecodeWriterTests(unittest.TestCase):
    def test_absolute_store_decoded(self):
        read = reader(0x8000, bytes.fromhex("8d1f07"))      # STA $071F
        writer = decode_writer(read, 0x8000, reached=True)
        self.assertEqual(writer.mnemonic, "STA")
        self.assertEqual(writer.category(), "exact")
        self.assertEqual(writer.value_source, "A")

    def test_indexed_store_is_a_range(self):
        read = reader(0x8000, bytes.fromhex("9da106"))      # STA $06A1,X
        writer = decode_writer(read, 0x8000, reached=True)
        self.assertEqual(writer.category(), "indexed")
        self.assertIn(0x071F, writer.targets)

    def test_indirect_store_is_unresolved(self):
        read = reader(0x8000, bytes.fromhex("9106"))        # STA ($06),Y
        writer = decode_writer(read, 0x8000, reached=True)
        self.assertEqual(writer.category(), "unresolved")
        self.assertFalse(writer.targets.is_resolved)

    def test_read_modify_write_recognised(self):
        read = reader(0x8000, bytes.fromhex("ce1f07"))      # DEC $071F
        writer = decode_writer(read, 0x8000, reached=True)
        self.assertTrue(writer.is_read_modify_write)
        self.assertEqual(writer.value_source, "memory")

    def test_accumulator_shift_is_not_a_memory_writer(self):
        read = reader(0x8000, bytes.fromhex("0a"))          # ASL A
        self.assertIsNone(decode_writer(read, 0x8000, reached=True))

    def test_push_writes_the_stack_page(self):
        read = reader(0x8000, bytes.fromhex("48"))          # PHA
        writer = decode_writer(read, 0x8000, reached=True)
        self.assertEqual(writer.category(), "stack")
        self.assertIn(0x01FF, writer.targets)

    def test_load_is_not_a_writer(self):
        read = reader(0x8000, bytes.fromhex("ad1f07"))      # LDA $071F
        self.assertIsNone(decode_writer(read, 0x8000, reached=True))


class ManifestTests(unittest.TestCase):
    #: STA $071F / STA $06A1,X / STA ($06),Y / LDA $071F
    BLOB = bytes.fromhex("8d1f07" "9da106" "9106" "ad1f07")

    def census(self):
        return census(reader(0x8000, self.BLOB), scope="linear",
                      trace_path="(absent)",
                      prg_range=(0x8000, 0x8000 + len(self.BLOB)))

    def test_manifest_sees_all_three_kinds_of_writer(self):
        buckets = writers_of(0x071F, self.census())
        self.assertEqual(len(buckets["exact"]), 1)
        self.assertEqual(len(buckets["indexed"]), 1)
        self.assertEqual(len(buckets["unresolved"]), 1)

    def test_unresolved_writer_blocks_a_fully_resolved_manifest(self):
        record = manifest(0x071F, self.census(), name="test variable")
        self.assertFalse(record["fully_resolved"])
        self.assertIn("not constrained", record["status"])

    def test_resolved_only_manifest_is_marked_resolved(self):
        read = reader(0x8000, bytes.fromhex("8d1f07"))
        writers = census(read, scope="linear", trace_path="(absent)",
                         prg_range=(0x8000, 0x8003))
        record = manifest(0x071F, writers)
        self.assertTrue(record["fully_resolved"])

    def test_address_outside_every_writer_has_an_empty_manifest(self):
        record = manifest(0x0400, [w for w in self.census()
                                   if w.targets.is_resolved
                                   and w.targets.size == 1])
        self.assertEqual(sum(record["counts"].values()), 0)


if __name__ == "__main__":
    unittest.main()
