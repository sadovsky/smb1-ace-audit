"""Unit tests for the tracer's CPU, device stub and interrupt entry.

These check the parts of `formal/dyn` that are *decisions* rather than
measurements: the decimal-mode wrapper, the completeness of the opcode table,
the geometry of the `$2002` flags, the controller shift register, the NMI entry
sequence, and the address decode.  The behaviour of the whole machine is
checked elsewhere, against hardware vectors (`formal.dyn.validate_cpu`) and
against nes-py (`formal.dyn.crossvalidate`).

    python3 -m unittest formal.dyn.test_dyn
"""
from __future__ import annotations

import os
import unittest

from .cpu6502 import JAM_OPCODES, Jam, NMOS2A03, unimplemented_opcodes
from .tracer import (DOTS_PER_SCANLINE, Controller, PPUMemory, PPUStub,
                     Tracer, VBLANK_SCANLINE)
from .validate_cpu import Flat


def tiny_prg(code: bytes, *, nmi: int = 0x9000, reset: int = 0x8000,
             irq: int = 0xA000) -> bytes:
    prg = bytearray(0x8000)
    prg[0:len(code)] = code
    prg[0x7FFA] = nmi & 0xFF
    prg[0x7FFB] = nmi >> 8
    prg[0x7FFC] = reset & 0xFF
    prg[0x7FFD] = reset >> 8
    prg[0x7FFE] = irq & 0xFF
    prg[0x7FFF] = irq >> 8
    return bytes(prg)


class OpcodeTable(unittest.TestCase):

    def test_every_opcode_is_implemented(self):
        self.assertEqual(unimplemented_opcodes(), [])

    def test_no_zero_cycle_instruction(self):
        self.assertEqual([op for op, c in enumerate(NMOS2A03.cycletime)
                          if c == 0], [])

    def test_jam_raises_rather_than_fetching_on(self):
        mpu = NMOS2A03(memory=Flat(), pc=0x200)
        for opcode in sorted(JAM_OPCODES):
            mpu.memory[0x200] = opcode
            mpu.pc = 0x200
            with self.assertRaises(Jam):
                mpu.step()


class DecimalMode(unittest.TestCase):
    """The 2A03's adder ignores D; the flag bit still exists."""

    def adc(self, a, operand, decimal, carry=False):
        mpu = NMOS2A03(memory=Flat(), pc=0x200)
        mpu.memory[0x200] = 0x69          # ADC #imm
        mpu.memory[0x201] = operand
        mpu.pc = 0x200
        mpu.a = a
        mpu.p = 0x20 | (0x08 if decimal else 0) | (0x01 if carry else 0)
        mpu.step()
        return mpu.a, mpu.p

    def test_adc_is_binary_with_decimal_set(self):
        binary, _ = self.adc(0x09, 0x01, decimal=False)
        decimal, _ = self.adc(0x09, 0x01, decimal=True)
        self.assertEqual(binary, 0x0A)
        self.assertEqual(decimal, 0x0A, "the 2A03 has no decimal correction")

    def test_decimal_bit_survives_the_adder(self):
        _, status = self.adc(0x09, 0x01, decimal=True)
        self.assertTrue(status & 0x08, "D must still be readable by PHP")

    def test_sbc_is_binary_with_decimal_set(self):
        mpu = NMOS2A03(memory=Flat(), pc=0x200)
        mpu.memory[0x200] = 0xE9          # SBC #imm
        mpu.memory[0x201] = 0x01
        mpu.pc = 0x200
        mpu.a = 0x10
        mpu.p = 0x29                      # D set, C set
        mpu.step()
        self.assertEqual(mpu.a, 0x0F)
        self.assertTrue(mpu.p & 0x08)

    def test_php_pushes_the_decimal_bit(self):
        mpu = NMOS2A03(memory=Flat(), pc=0x200)
        mpu.memory[0x200] = 0x08          # PHP
        mpu.pc = 0x200
        mpu.sp = 0xFF
        mpu.p = 0x28
        mpu.step()
        self.assertTrue(mpu.memory[0x1FF] & 0x08)


class AddressDecode(unittest.TestCase):

    def setUp(self):
        self.tracer = Tracer(tiny_prg(b"\xEA"), cycle_model="ntsc")

    def test_ram_is_mirrored_to_1fff(self):
        bus = self.tracer.bus
        bus[0x0005] = 0x5A
        for mirror in (0x0805, 0x1005, 0x1805):
            self.assertEqual(bus[mirror], 0x5A)
        bus[0x1805] = 0xA5
        self.assertEqual(bus[0x0005], 0xA5)

    def test_prg_is_read_only(self):
        bus = self.tracer.bus
        before = bus[0x8000]
        bus[0x8000] = before ^ 0xFF
        self.assertEqual(bus[0x8000], before)

    def test_unmapped_reads_are_zero(self):
        self.assertEqual(self.tracer.bus[0x4015], 0)
        self.assertEqual(self.tracer.bus[0x6000], 0)

    def test_ppu_control_mirrors_every_eight_bytes(self):
        self.tracer.bus[0x3FF8] = 0x80
        self.assertTrue(self.tracer.ppu.nmi_enabled)


class StatusRegister(unittest.TestCase):

    def ppu(self):
        return PPUStub(PPUMemory(b"", True))

    def test_vblank_sets_at_scanline_241_dot_1(self):
        ppu = self.ppu()
        ppu.nmi_enabled = True
        # Dots are processed at `cycles` = 1..341 in every line, so a line is
        # 341 dots, except the first pre-render line after reset, which starts
        # at `cycles` = 0 and so is 342.  The vblank flag goes up on the dot
        # where `cycles` == 1 on scanline 241, i.e. that line's first dot.
        before = 342 + DOTS_PER_SCANLINE * (240 + 1) + 1
        ppu.advance(before - 1)
        self.assertFalse(ppu.vblank)
        ppu.advance(1)
        self.assertTrue(ppu.vblank)
        self.assertTrue(ppu.nmi_pending)
        self.assertEqual(ppu.scanline, VBLANK_SCANLINE)

    def test_reading_the_status_clears_vblank_only(self):
        ppu = self.ppu()
        ppu.vblank = True
        ppu.sprite0 = True
        self.assertEqual(ppu.read_status(), 0xC0)
        self.assertEqual(ppu.read_status(), 0x40)

    def test_no_nmi_while_disabled(self):
        ppu = self.ppu()
        ppu.advance(DOTS_PER_SCANLINE * 262)
        self.assertTrue(ppu.vblank)
        self.assertFalse(ppu.nmi_pending)

    def test_enabling_during_vblank_raises_an_edge(self):
        ppu = self.ppu()
        ppu.vblank = True
        ppu.write_control(0x80)
        self.assertTrue(ppu.nmi_pending)
        self.assertEqual(ppu.enable_edge_nmis, 1)

    def test_enabling_outside_vblank_does_not(self):
        ppu = self.ppu()
        ppu.vblank = False
        ppu.write_control(0x80)
        self.assertFalse(ppu.nmi_pending)

    def test_sprite_zero_needs_rendering_enabled(self):
        ppu = self.ppu()
        ppu.publish_sprite_zero(24, 88)
        ppu.write_mask(0x00)
        ppu.advance(DOTS_PER_SCANLINE * 262)
        self.assertFalse(ppu.sprite0)
        ppu.write_mask(0x18)
        ppu.advance(DOTS_PER_SCANLINE * 262)
        self.assertTrue(ppu.sprite0)

    def test_the_flags_clear_at_pre_render(self):
        ppu = self.ppu()
        ppu.vblank = ppu.sprite0 = True
        ppu.advance(DOTS_PER_SCANLINE * 262)   # through to the next pre-render
        ppu.advance(2)
        self.assertFalse(ppu.sprite0)


class Pad(unittest.TestCase):

    def test_strobe_latches_and_reads_shift_out_lsb_first(self):
        pad = Controller()
        pad.buttons = 0x81                 # RIGHT and A
        pad.write(1)
        pad.write(0)
        bits = [pad.read() for _ in range(8)]
        self.assertTrue(all(value & 0x40 for value in bits),
                        "the upper bits of an unloaded bus read as $40")
        self.assertEqual([value & 1 for value in bits],
                         [1, 0, 0, 0, 0, 0, 0, 1])

    def test_reading_while_strobed_returns_bit_zero_without_shifting(self):
        pad = Controller()
        pad.buttons = 0x01
        pad.write(1)
        self.assertEqual(pad.read() & 1, 1)
        self.assertEqual(pad.read() & 1, 1)


class PPUMemoryTests(unittest.TestCase):

    def test_vertical_mirroring_aliases_the_name_tables(self):
        memory = PPUMemory(bytes(0x2000), True)
        memory.write(0x2000, 0x11)
        self.assertEqual(memory.read(0x2800), 0x11)
        memory.write(0x2400, 0x22)
        self.assertEqual(memory.read(0x2C00), 0x22)

    def test_data_reads_go_through_the_one_byte_buffer(self):
        memory = PPUMemory(bytes(0x2000), True)
        memory.write(0x2000, 0xAB)
        memory.write_address(0x20)
        memory.write_address(0x00)
        self.assertEqual(memory.read_data(), 0x00)      # the stale buffer
        memory.write_address(0x20)
        memory.write_address(0x00)
        memory.read_data()
        self.assertEqual(memory.read_data(), 0xAB)

    def test_control_selects_the_increment(self):
        memory = PPUMemory(bytes(0x2000), True)
        memory.write_control(0x04)
        self.assertEqual(memory.increment, 0x20)
        memory.write_control(0x00)
        self.assertEqual(memory.increment, 1)


class InterruptEntry(unittest.TestCase):

    def test_nmi_pushes_pch_pcl_and_status_with_b_clear(self):
        tracer = Tracer(tiny_prg(b"\xEA\xEA\xEA", nmi=0x9ABC),
                        cycle_model="ntsc")
        tracer.mpu.pc = 0x8123
        tracer.mpu.sp = 0xFF
        tracer.mpu.p = 0xB5                 # B set, I clear
        tracer._enter_nmi()
        self.assertEqual(tracer.mpu.pc, 0x9ABC)
        self.assertEqual(tracer.bus[0x01FF], 0x81)
        self.assertEqual(tracer.bus[0x01FE], 0x23)
        pushed = tracer.bus[0x01FD]
        self.assertFalse(pushed & 0x10, "B must be clear in a hardware NMI")
        self.assertTrue(pushed & 0x20)
        self.assertTrue(tracer.mpu.p & 0x04, "I must be set on entry")
        self.assertEqual(tracer.mpu.sp, 0xFC)

    def test_entry_costs_seven_cycles_and_three_bytes(self):
        code = b"\xA9\x80\x8D\x00\x20" + b"\xEA" * 64     # enable NMI, then NOPs
        tracer = Tracer(tiny_prg(code, nmi=0x9000), cycle_model="ntsc")
        tracer.run_until(40)
        self.assertTrue(tracer.ppu.nmi_enabled)
        start = tracer.cycle
        before = tracer.mpu.sp
        tracer.ppu.nmi_pending = True
        tracer.run_until(start + 1)
        self.assertEqual((before - tracer.mpu.sp) & 0xFF, 3)
        self.assertEqual(tracer.cycle - start, 7)


class WholeImage(unittest.TestCase):
    """End-to-end sanity, skipped when the image is not configured."""

    def setUp(self):
        if not os.environ.get("SMB1_ROM"):
            self.skipTest("SMB1_ROM is not set")
        from .tracer import from_rom
        self.tracer = from_rom()

    def test_one_nmi_per_frame_once_the_game_is_running(self):
        for frame in range(120):
            self.tracer.run_frame(0x08 if frame % 16 < 2 else 0)
        # the reset path enables NMI a few frames in, so allow a small deficit
        self.assertGreater(self.tracer.nmi_count, 110)
        self.assertLessEqual(self.tracer.nmi_count, 120)

    def test_no_nmi_re_enters_the_handler(self):
        for frame in range(120):
            self.tracer.run_frame(0x08 if frame % 16 < 2 else 0)
        self.assertEqual(self.tracer.nmi_during_handler, 0)

    def test_the_main_loop_is_the_idle_jump(self):
        """Outside the handler the image parks on `JMP $8057` with S = $FF."""
        for frame in range(120):
            self.tracer.run_frame(0)
        for _ in range(60_000):
            if self.tracer.mpu.pc == 0x8057:
                self.assertEqual(self.tracer.mpu.sp, 0xFF,
                                 "the idle loop runs with an empty stack")
                return
            self.tracer.run_until(self.tracer.cycle + 1)
        self.fail("the idle loop was never reached in 60,000 instructions")


if __name__ == "__main__":
    unittest.main()


class NegativeTwins(unittest.TestCase):
    """The two headline checks are negative results, so prove they can fail.

    `observe.summarise` reported no fetched program counter outside the graph
    and no out-of-range dispatch index.  A check that cannot report a positive
    is worthless, so here it is fed a doctored observation and must report one.
    """

    def setUp(self):
        if not os.environ.get("SMB1_ROM"):
            self.skipTest("SMB1_ROM is not set")
        from . import observe
        self.observe = observe
        self.cfg = observe.graph()
        self.state = observe.Observation(observe.dispatch_tables(self.cfg))

    def test_a_fetch_outside_the_graph_is_reported(self):
        clean = self.observe.summarise(self.state, self.cfg)
        self.assertEqual(
            clean["fetched_program_counters"]
            ["fetched_but_not_an_instruction_start"], [])
        # $8058 is the operand byte of the idle loop's `JMP $8057`
        self.assertNotIn(0x8058, self.cfg.instruction_starts)
        self.state.pc_seen[0x8058] = 1
        doctored = self.observe.summarise(self.state, self.cfg)
        self.assertEqual(
            doctored["fetched_program_counters"]
            ["fetched_but_not_an_instruction_start"], ["0x8058"])

    def test_an_overlap_outside_the_graph_is_reported(self):
        # $8057 is `JMP $8057`, three bytes; executing both it and $8058 is a
        # misaligned stream, and the graph does not record that pair
        self.state.pc_seen[0x8057] = 1
        self.state.pc_seen[0x8058] = 1
        doctored = self.observe.summarise(self.state, self.cfg)
        self.assertIn(
            ["0x8057", "0x8058"],
            doctored["fetched_program_counters"]
            ["overlapping_pairs_the_graph_does_not_already_record"])

    def test_an_out_of_range_dispatch_index_is_reported(self):
        site = 0x9743                      # three entries
        entries = self.state.sites[site]
        self.assertEqual(entries, 3)
        self.state.dispatch_a[site][entries] = 1
        doctored = self.observe.summarise(self.state, self.cfg)
        self.assertEqual(doctored["dispatch_out_of_range"],
                         [{"site": "0x9743", "table_entries": 3,
                           "indices": [3]}])

    def test_the_high_bit_of_the_accumulator_is_masked_off(self):
        site = 0x9743
        self.state.dispatch_a[site][0x82] = 1      # index 2, in range
        doctored = self.observe.summarise(self.state, self.cfg)
        self.assertEqual(doctored["dispatch_out_of_range"], [])
        entry = [row for row in doctored["dispatch_sites"]
                 if row["site"] == "0x9743"][0]
        self.assertEqual(entry["index_max"], 2)
