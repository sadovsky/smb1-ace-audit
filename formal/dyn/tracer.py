"""An instruction-level NES tracer: py65's 6502 core behind a minimal device stub.

What this is
------------
A concrete interpreter for the cartridge of `formal/README.md`'s scope M0,
instrumented at instruction granularity.  It exists because nes-py exposes only
per-frame RAM, so the site-specific questions (which accumulator value reaches
*which* dispatch, which program counter is ever fetched, which instruction
writes into the stack page) cannot be answered from frame samples.

What it is not
--------------
It is not a console and not a second opinion on the PPU.  Everything outside
the CPU, the 2 KiB of RAM and the cartridge is a *stub*, listed below.  Results
produced with it are observations over the inputs that were run.

The device stub
---------------
=========================  ====================================================
`$0000-$1FFF`              2 KiB RAM, mirrored every 2 KiB (`address & $07FF`)
`$8000-$FFFF`              32 KiB PRG, writes ignored (NROM has no registers)
`$2002` bit 7              vblank: set at scanline 241 dot 1, cleared by a read
                           of `$2002` and at pre-render dot 1
`$2002` bit 6              sprite-0 hit: set once per frame at scanline
                           `OAM[0].y + 1 + line_offset`, dot
                           `OAM[0].x + 1 + dot_offset`, from the page the last
                           DMA wrote, and cleared at pre-render dot 1.
                           Rendering must be enabled (`$2001` bits 3 and 4).
                           The two offsets are *calibrated*, not computed from
                           pixels: the stub does not render, so it cannot know
                           on which of sprite 0's eight rows an opaque sprite
                           pixel first meets opaque background.  They were
                           swept over 40 combinations against nes-py: no
                           combination changed how many frame boundaries agree
                           on RAM, and none produced a control-flow difference,
                           so the calibration carries no weight in any result;
                           `line_offset = 1` is used because it also makes the
                           accumulator agree at the four instructions that read
                           `$2002` inside a wait loop
`$2000` write              bit 7 is the NMI enable; the ghost copy the abstract
                           model calls `nmi_enable`
`$2001` write              bits 3 and 4 gate the sprite-0 hit and the odd-frame
                           dot skip
`$2007`, `$2004` read      return 0.  There are no pattern or name tables, so a
                           routine that reads VRAM back reads a stub.  The
                           observation run counts every fetch of such a read
`$4014` write              OAM DMA: costs 513 or 514 cycles and republishes the
                           sprite-0 parameters from the written page.  No OAM
`$4016` write              controller strobe, both ports (as nes-py does)
`$4016`/`$4017` read       serial controller read, `bit | $40`.  Port 2 is
                           always "no buttons".  The shift register reloads on
                           any write with bit 0 clear
everything else            reads 0, writes ignored
=========================  ====================================================

Timing.  The PPU is a dot counter, three dots per CPU cycle, over the NTSC
frame of 262 scanlines of 341 dots (89,342 dots, 29,780.67 CPU cycles), with
the pre-render line one dot shorter on odd frames while rendering is enabled.
Instructions are atomic: every bus access of an instruction sees the device
state as of the instruction's first cycle, and the dots of its remaining cycles
are advanced afterwards.  An NMI whose vblank dot falls inside an instruction's
cycle window is therefore delivered *after* that instruction, which is also
what nes-py does, so the two agree on interrupt placement to the instruction.

`cycle_model` selects where instruction lengths come from:

`"ntsc"`   py65's cycle table plus its page-crossing and branch penalties, the
           counts `formal.dyn.validate_cpu` checks against the recorded bus
           cycles of the SingleStepTests vectors (73,200 instructions, no
           mismatch).  Frame boundaries fall every 29,780.5 cycles.
`"nespy"`  nes-py's own `OPERATION_CYCLES` table plus one cycle for a taken
           branch, and frames of exactly 29,781 cycles, which is what
           `nes_py.NESEnv.step` executes.  This exists so that cross-validation
           compares the *device model* rather than two different cycle tables;
           it is the wrong model of a console (it drops page-crossing
           penalties) and must not be used for anything but comparison.

NMI entry is implemented here because py65 has no interrupt API: push PCH, push
PCL, push P with the B bit clear and bit 5 set, set I, load PC from `$FFFA`,
charge 7 cycles.  An NMI is taken when the vblank flag is set while enable is
on, and, if `nmi_on_enable_write` is set, also when a write to `$2000` raises
enable from 0 to 1 while the flag is already set.  That second edge is real
hardware behaviour which nes-py does not implement; the observation run reports
how often it fired.
"""
from __future__ import annotations

from .cpu6502 import Jam, NMOS2A03

DOTS_PER_SCANLINE = 341
SCANLINES_PER_FRAME = 262
#: dots per NTSC frame; 3 dots per CPU cycle
DOTS_PER_FRAME = DOTS_PER_SCANLINE * SCANLINES_PER_FRAME        # 89,342
CPU_CYCLES_PER_FRAME = DOTS_PER_FRAME / 3.0                     # 29,780.67
#: what `nes_py.NESEnv.step` runs, exactly
NESPY_CYCLES_PER_FRAME = 29781
#: the frame length the task's protocol samples at, for `cycle_model="ntsc"`
NTSC_SAMPLE_FRAME = 29780.5

VISIBLE_SCANLINES = 240
VBLANK_SCANLINE = 241
FRAME_END_SCANLINE = 261

PRE_RENDER, RENDER, POST_RENDER, VERTICAL_BLANK = 0, 1, 2, 3

NMI_VECTOR = 0xFFFA
RESET_VECTOR = 0xFFFC

#: a sentinel `cur_pc` for the writes the interrupt sequence itself makes
NMI_PUSH_PC = -1

BRANCH_OPCODES = frozenset({0x10, 0x30, 0x50, 0x70, 0x90, 0xB0, 0xD0, 0xF0})

#: nes-py's `OPERATION_CYCLES`, verbatim; 0 means "nes-py does not execute it"
NESPY_OPERATION_CYCLES = (
    7, 6, 0, 0, 0, 3, 5, 0, 3, 2, 2, 0, 0, 4, 6, 0,
    2, 5, 0, 0, 0, 4, 6, 0, 2, 4, 0, 0, 0, 4, 7, 0,
    6, 6, 0, 0, 3, 3, 5, 0, 4, 2, 2, 0, 4, 4, 6, 0,
    2, 5, 0, 0, 0, 4, 6, 0, 2, 4, 0, 0, 0, 4, 7, 0,
    6, 6, 0, 0, 0, 3, 5, 0, 3, 2, 2, 0, 3, 4, 6, 0,
    2, 5, 0, 0, 0, 4, 6, 0, 2, 4, 0, 0, 0, 4, 7, 0,
    6, 6, 0, 0, 0, 3, 5, 0, 4, 2, 2, 0, 5, 4, 6, 0,
    2, 5, 0, 0, 0, 4, 6, 0, 2, 4, 0, 0, 0, 4, 7, 0,
    0, 6, 0, 0, 3, 3, 3, 0, 2, 0, 2, 0, 4, 4, 4, 0,
    2, 6, 0, 0, 4, 4, 4, 0, 2, 5, 2, 0, 0, 5, 0, 0,
    2, 6, 2, 0, 3, 3, 3, 0, 2, 2, 2, 0, 4, 4, 4, 0,
    2, 5, 0, 0, 4, 4, 4, 0, 2, 4, 2, 0, 4, 4, 4, 0,
    2, 6, 0, 0, 3, 3, 5, 0, 2, 2, 2, 0, 4, 4, 6, 0,
    2, 5, 0, 0, 0, 4, 6, 0, 2, 4, 0, 0, 0, 4, 7, 0,
    2, 6, 0, 0, 3, 3, 5, 0, 2, 2, 2, 2, 4, 4, 6, 0,
    2, 5, 0, 0, 0, 4, 6, 0, 2, 4, 0, 0, 0, 4, 7, 0,
)


class Controller:
    """The standard pad's shift register, modelled as nes-py models it."""

    __slots__ = ("buttons", "bits", "strobe")

    def __init__(self):
        self.buttons = 0
        self.bits = 0
        self.strobe = True

    def write(self, value: int) -> None:
        self.strobe = bool(value & 1)
        if not self.strobe:
            self.bits = self.buttons

    def read(self) -> int:
        if self.strobe:
            return (self.buttons & 1) | 0x40
        value = (self.bits & 1) | 0x40
        self.bits >>= 1
        return value


class PPUMemory:
    """The PPU's own address space, enough to answer a `$2007` read.

    The image reads VRAM back (`$8716`, `$8719`), so a stub that returns zero
    there feeds the program bytes a console would not.  Modelled: the 2 KiB of
    name-table RAM with the cartridge's mirroring, the 8 KiB of CHR as a
    read-only pattern table, the 32 palette bytes, the address latch written
    through `$2006` (and `$2005`, and the name-table bits of `$2000`), the
    1- or 32-byte increment, and the one-byte read buffer.  The latch's
    behaviour matches nes-py's, including its two departures from hardware:
    the read buffer is bypassed according to the *incremented* address, and
    the latch is reset by a `$2002` read only through `is_first_write`.

    Not modelled: the renderer's own updates to the latch during visible
    scanlines.  A `$2007` access while rendering is enabled therefore sees a
    different address here than on a console or in nes-py.  The observation
    run counts those accesses so the exposure is measurable rather than
    assumed away.
    """

    __slots__ = ("vram", "palette", "chr", "name_tables", "data_address",
                 "temp_address", "first_write", "increment", "buffer",
                 "writes_while_rendering", "reads_while_rendering")

    def __init__(self, chr_rom: bytes, vertical_mirroring: bool):
        self.vram = bytearray(0x800)
        self.palette = bytearray(0x20)
        self.chr = chr_rom or bytes(0x2000)
        # nes-py's PictureBus::update_mirroring
        self.name_tables = ((0, 0x400, 0, 0x400) if vertical_mirroring
                            else (0, 0, 0x400, 0x400))
        self.reset()

    def reset(self) -> None:
        self.vram[:] = bytes(0x800)
        self.palette[:] = bytes(0x20)
        self.data_address = 0
        self.temp_address = 0
        self.first_write = True
        self.increment = 1
        self.buffer = 0
        self.writes_while_rendering = 0
        self.reads_while_rendering = 0

    def _index(self, address: int) -> int:
        return self.name_tables[(address >> 10) & 3] + (address & 0x3FF)

    def read(self, address: int) -> int:
        address &= 0x3FFF
        if address < 0x2000:
            return self.chr[address] if address < len(self.chr) else 0
        if address < 0x3EFF:
            return self.vram[self._index(address)]
        if address < 0x3FFF:
            return self.palette[address & 0x1F]
        return 0

    def write(self, address: int, value: int) -> None:
        address &= 0x3FFF
        if address < 0x2000:
            return                      # NROM CHR is read-only
        if address < 0x3EFF:
            self.vram[self._index(address)] = value
        elif address < 0x3FFF:
            self.palette[0 if address == 0x3F10 else address & 0x1F] = value

    # -- register behaviour ------------------------------------------------

    def read_data(self) -> int:
        value = self.read(self.data_address)
        self.data_address = (self.data_address + self.increment) & 0xFFFF
        if self.data_address < 0x3F00:
            value, self.buffer = self.buffer, value
        return value

    def write_data(self, value: int) -> None:
        self.write(self.data_address, value)
        self.data_address = (self.data_address + self.increment) & 0xFFFF

    def write_address(self, value: int) -> None:
        if self.first_write:
            self.temp_address = (self.temp_address & ~0xFF00) | ((value & 0x3F) << 8)
            self.first_write = False
        else:
            self.temp_address = (self.temp_address & ~0xFF) | value
            self.data_address = self.temp_address
            self.first_write = True

    def write_scroll(self, value: int) -> None:
        if self.first_write:
            self.temp_address = (self.temp_address & ~0x1F) | ((value >> 3) & 0x1F)
            self.first_write = False
        else:
            self.temp_address = ((self.temp_address & ~0x73E0)
                                 | ((value & 0x7) << 12)
                                 | ((value & 0xF8) << 2))
            self.first_write = True

    def write_control(self, value: int) -> None:
        self.increment = 0x20 if value & 0x04 else 1
        self.temp_address = (self.temp_address & ~0xC00) | ((value & 3) << 10)


class PPUStub:
    """`$2002` bits 7 and 6, and the NMI line, from a dot counter.

    Nothing is rendered.  The two flags and the frame geometry are all that the
    image's own code can observe through the stub.
    """

    def __init__(self, memory: PPUMemory, *, sprite0_line_offset: int = 1,
                 sprite0_dot_offset: int = 0,
                 power_on_rendering: bool = True,
                 nmi_on_enable_write: bool = True):
        self.memory = memory
        self.sprite0_line_offset = sprite0_line_offset
        self.sprite0_dot_offset = sprite0_dot_offset
        self.power_on_rendering = power_on_rendering
        self.nmi_on_enable_write = nmi_on_enable_write
        self.reset()

    def reset(self) -> None:
        self.memory.reset()
        self.state = PRE_RENDER
        self.scanline = 0
        self.cycles = 0
        self.vblank = False
        self.sprite0 = False
        self.even_frame = True
        # nes-py's PPU::reset leaves both rendering flags set until the first
        # write to $2001.  A real 2C02 powers up with $2001 = 0.  Only the
        # odd-frame dot skip can tell the difference before that write.
        self.show_bg = self.power_on_rendering
        self.show_spr = self.power_on_rendering
        self.nmi_enabled = False
        self.nmi_pending = False
        self.enable_edge_nmis = 0
        self.ppu_frames = 0
        # OAM is zero at power-on, so sprite 0 sits at y = 0 and its hit is
        # reported on the first visible scanline until the first DMA moves it.
        # nes-py's renderer does the same, because its PPU::reset leaves both
        # rendering flags set.
        self.hit_line = None
        self.hit_dot = None
        self.publish_sprite_zero(0, 0)

    # -- geometry ---------------------------------------------------------

    def line_end(self) -> int:
        if (self.state == PRE_RENDER and not self.even_frame
                and self.show_bg and self.show_spr):
            return DOTS_PER_SCANLINE - 1
        return DOTS_PER_SCANLINE

    def advance(self, dots: int) -> None:
        while dots > 0:
            end = self.line_end()
            first = self.cycles
            room = end - first + 1
            take = dots if dots < room else room
            last = first + take - 1
            if first <= 1 <= last:
                if self.state == PRE_RENDER:
                    self.vblank = False
                    self.sprite0 = False
                elif (self.state == VERTICAL_BLANK
                        and self.scanline == VBLANK_SCANLINE):
                    self.vblank = True
                    if self.nmi_enabled:
                        self.nmi_pending = True
            if (self.state == RENDER and self.hit_line is not None
                    and self.scanline == self.hit_line
                    and first <= self.hit_dot <= last
                    and self.show_bg and self.show_spr):
                self.sprite0 = True
            if last >= end:
                self._end_line()
            else:
                self.cycles = last + 1
            dots -= take

    def _end_line(self) -> None:
        state = self.state
        if state == PRE_RENDER:
            self.state = RENDER
            self.scanline = 0
        elif state == RENDER:
            self.scanline += 1
            if self.scanline >= VISIBLE_SCANLINES:
                self.state = POST_RENDER
        elif state == POST_RENDER:
            self.scanline += 1
            self.state = VERTICAL_BLANK
        else:
            self.scanline += 1
            if self.scanline >= FRAME_END_SCANLINE:
                self.state = PRE_RENDER
                self.scanline = 0
                self.even_frame = not self.even_frame
                self.ppu_frames += 1
        self.cycles = 1

    # -- registers --------------------------------------------------------

    def read_status(self) -> int:
        value = (0x80 if self.vblank else 0) | (0x40 if self.sprite0 else 0)
        self.vblank = False
        self.memory.first_write = True
        return value

    @property
    def rendering(self) -> bool:
        return self.show_bg and self.show_spr

    def write_control(self, value: int) -> None:
        enable = bool(value & 0x80)
        if (enable and not self.nmi_enabled and self.vblank
                and self.nmi_on_enable_write):
            # a rising edge of (vblank AND enable) is an NMI on hardware
            self.nmi_pending = True
            self.enable_edge_nmis += 1
        self.nmi_enabled = enable
        self.memory.write_control(value)

    def write_mask(self, value: int) -> None:
        self.show_bg = bool(value & 0x08)
        self.show_spr = bool(value & 0x10)

    def publish_sprite_zero(self, y: int, x: int) -> None:
        """Set where the sprite-0 hit will be reported for this frame."""
        line = y + 1 + self.sprite0_line_offset
        if 0 <= line < VISIBLE_SCANLINES:
            self.hit_line = line
            self.hit_dot = min(x + 1 + self.sprite0_dot_offset,
                               DOTS_PER_SCANLINE)
        else:
            self.hit_line = None
            self.hit_dot = None


class NESBus:
    """An `ObservableMemory`-style NROM address space with the device stub.

    `py65` only needs `__getitem__`/`__setitem__`, so the subscriber tables of
    `py65.memory.ObservableMemory` are replaced by a hard-coded decode: a
    `defaultdict` lookup per byte is the single hottest cost in a run of 10^9
    instructions.
    """

    __slots__ = ("ram", "prg", "ppu", "pads", "tracer", "cur_pc", "dma_cycles",
                 "track", "written", "stack_writes", "vram_reads", "dma_count",
                 "reg_reads", "read_log", "last_stack_writer")

    def __init__(self, prg: bytes, ppu: PPUStub, tracer):
        self.ram = bytearray(0x800)
        self.prg = prg
        self.ppu = ppu
        self.pads = (Controller(), Controller())
        self.tracer = tracer
        self.cur_pc = 0
        self.dma_cycles = 0
        self.track = False
        #: 2048 x 256 bitmap: `written[(cell << 8) | value]`
        self.written = bytearray(0x800 * 256)
        self.stack_writes: set[tuple[int, int]] = set()
        #: the program counter that last wrote each byte of the stack page
        self.last_stack_writer = [None] * 256
        self.vram_reads = 0
        self.dma_count = 0
        self.reg_reads = 0
        #: when a list, every read of $2000-$7FFF is appended as
        #: (fetching pc, address, value).  Only the register branch of the
        #: decode tests it, so an untracked run pays nothing.
        self.read_log = None

    def __getitem__(self, address):
        address &= 0xFFFF
        if address < 0x2000:
            return self.ram[address & 0x7FF]
        if address >= 0x8000:
            return self.prg[address - 0x8000]
        if address < 0x4000:
            register = address & 7
            if register == 2:
                value = self.ppu.read_status()
            elif register == 7:
                self.vram_reads += 1
                if self.ppu.rendering:
                    self.ppu.memory.reads_while_rendering += 1
                value = self.ppu.memory.read_data()
            else:
                self.reg_reads += 1
                value = 0
        elif address == 0x4016:
            value = self.pads[0].read()
        elif address == 0x4017:
            value = self.pads[1].read()
        else:
            self.reg_reads += 1
            value = 0
        if self.read_log is not None:
            self.read_log.append((self.cur_pc, address, value))
        return value

    def __setitem__(self, address, value):
        address &= 0xFFFF
        if address < 0x2000:
            cell = address & 0x7FF
            self.ram[cell] = value
            if self.track:
                self.written[(cell << 8) | value] = 1
                if 0x100 <= cell < 0x200:
                    self.stack_writes.add((self.cur_pc, cell))
                    self.last_stack_writer[cell & 0xFF] = self.cur_pc
            return
        if address >= 0x8000:
            return                      # NROM: no registers behind the ROM
        if address < 0x4000:
            register = address & 7
            if register == 0:
                self.ppu.write_control(value)
            elif register == 1:
                self.ppu.write_mask(value)
            elif register == 5:
                self.ppu.memory.write_scroll(value)
            elif register == 6:
                self.ppu.memory.write_address(value)
            elif register == 7:
                if self.ppu.rendering:
                    self.ppu.memory.writes_while_rendering += 1
                self.ppu.memory.write_data(value)
            return
        if address == 0x4014:
            self.dma_count += 1
            # nes-py: skip_cycles += 513 + (cycles & 1), where `cycles` has
            # already been incremented for the cycle this store executes in.
            self.dma_cycles = 513 + ((self.tracer.cycle + 1) & 1)
            if value < 0x20:
                base = (value << 8) & 0x7FF
                self.ppu.publish_sprite_zero(self.ram[base],
                                             self.ram[(base + 3) & 0x7FF])
            return
        if address == 0x4016:
            self.pads[0].write(value)
            self.pads[1].write(value)
            return

    # -- convenience -------------------------------------------------------

    def read_word(self, address: int) -> int:
        return self[address] | (self[address + 1] << 8)


class Tracer:
    """The machine: CPU, RAM, cartridge and the device stub, stepped by hand."""

    def __init__(self, prg: bytes, *, chr_rom: bytes = b"",
                 vertical_mirroring: bool = True,
                 cycle_model: str = "nespy",
                 nmi_on_enable_write: bool = True,
                 sprite0_line_offset: int = 1, sprite0_dot_offset: int = 0,
                 power_on_rendering: bool = True,
                 power_on_ram: bytes | None = None,
                 power_on_status: int = 0x34,
                 track_writes: bool = False):
        if cycle_model not in ("ntsc", "nespy"):
            raise ValueError(f"unknown cycle model {cycle_model!r}")
        self.prg = prg
        self.cycle_model = cycle_model
        self.power_on_ram = bytes(power_on_ram) if power_on_ram else None
        self.power_on_status = power_on_status
        self.ppu_memory = PPUMemory(chr_rom, vertical_mirroring)
        self.ppu = PPUStub(self.ppu_memory,
                           sprite0_line_offset=sprite0_line_offset,
                           sprite0_dot_offset=sprite0_dot_offset,
                           power_on_rendering=power_on_rendering,
                           nmi_on_enable_write=nmi_on_enable_write)
        self.bus = NESBus(prg, self.ppu, self)
        self.bus.track = track_writes
        self.mpu = NMOS2A03(memory=self.bus, pc=0)
        self.frame_length = (NESPY_CYCLES_PER_FRAME if cycle_model == "nespy"
                             else NTSC_SAMPLE_FRAME)
        self.reset()

    # -- lifecycle ---------------------------------------------------------

    def reset(self) -> None:
        self.bus.ram[:] = (self.power_on_ram if self.power_on_ram
                           else bytes(0x800))
        self.ppu.reset()
        for pad in self.bus.pads:
            pad.__init__()
        mpu = self.mpu
        mpu.processorCycles = 0
        # The documented power-on state, which is also nes-py's: A=X=Y=0,
        # S=$FD, P=$34 (I set, B and bit 5 set), PC from the reset vector.
        mpu.a = mpu.x = mpu.y = 0
        mpu.sp = 0xFD
        mpu.p = self.power_on_status
        mpu.pc = self.bus.read_word(RESET_VECTOR)
        self.cycle = 0
        self.frame = 0
        self.instructions = 0
        self.nmi_count = 0
        self.nmi_during_handler = 0
        self.jammed = None

    def set_buttons(self, value: int) -> None:
        self.bus.pads[0].buttons = value & 0xFF

    # -- stepping ----------------------------------------------------------

    def _enter_nmi(self, on_nmi=None) -> None:
        mpu = self.mpu
        pc = mpu.pc
        if 0x8082 <= pc <= 0x8181:
            self.nmi_during_handler += 1
        if on_nmi is not None:
            on_nmi(pc, mpu.sp)
        self.bus.cur_pc = NMI_PUSH_PC
        mpu.stPush((pc >> 8) & 0xFF)
        mpu.stPush(pc & 0xFF)
        mpu.stPush((mpu.p & ~mpu.BREAK) | mpu.UNUSED)
        mpu.p |= mpu.INTERRUPT
        mpu.pc = self.bus.read_word(NMI_VECTOR)
        self.nmi_count += 1

    def run_until(self, end_cycle: float, *, on_fetch=None, on_nmi=None,
                  nmi_override=None) -> None:
        """Execute until the CPU cycle counter reaches `end_cycle`.

        `nmi_override(tracer)` is consulted at every instruction boundary when
        given: `True` forces an NMI entry, `False` suppresses a pending one,
        and `None` leaves the stub's own decision alone.  That is how
        `formal.dyn.nmi_storm` realises the abstract model's unconstrained NMI,
        which is not a hardware behaviour.
        """
        mpu = self.mpu
        bus = self.bus
        ppu = self.ppu
        prg = self.prg
        nespy = self.cycle_model == "nespy"
        step = mpu.step
        advance = ppu.advance
        while self.cycle < end_cycle:
            advance(3)
            if nmi_override is not None:
                decision = nmi_override(self)
                if decision is not None:
                    ppu.nmi_pending = bool(decision)
            if ppu.nmi_pending:
                ppu.nmi_pending = False
                self._enter_nmi(on_nmi)
                advance(18)
                self.cycle += 7
                continue
            pc = mpu.pc
            if on_fetch is not None:
                on_fetch(pc)
            bus.cur_pc = pc
            bus.dma_cycles = 0
            before = mpu.processorCycles
            try:
                step()
            except Jam as jam:
                self.jammed = (jam.pc, jam.opcode)
                return
            if nespy:
                opcode = (prg[pc - 0x8000] if pc >= 0x8000 else bus[pc])
                length = NESPY_OPERATION_CYCLES[opcode]
                if not length:
                    # nes-py cannot execute this opcode at all; fall back to
                    # the validated count so the clock keeps moving.
                    length = mpu.processorCycles - before
                elif opcode in BRANCH_OPCODES and mpu.pc != (pc + 2) & 0xFFFF:
                    length += 1
            else:
                length = mpu.processorCycles - before
            length += bus.dma_cycles
            self.instructions += 1
            if length > 1:
                advance(3 * (length - 1))
            self.cycle += length

    def run_frame(self, buttons: int = 0, **hooks) -> None:
        """Run one frame boundary's worth of cycles, as `NESEnv.step` does."""
        self.set_buttons(buttons)
        self.frame += 1
        self.run_until(self.frame * self.frame_length, **hooks)

    # -- state -------------------------------------------------------------

    @property
    def ram(self) -> bytearray:
        return self.bus.ram

    def snapshot(self) -> dict:
        mpu = self.mpu
        return {"pc": mpu.pc, "a": mpu.a, "x": mpu.x, "y": mpu.y,
                "sp": mpu.sp, "p": mpu.p, "cycle": self.cycle,
                "frame": self.frame, "instructions": self.instructions,
                "nmi_count": self.nmi_count}

    def stub_description(self) -> dict:
        return {
            "cycle_model": self.cycle_model,
            "frame_length_cycles": self.frame_length,
            "nmi_on_enable_write": self.ppu.nmi_on_enable_write,
            "sprite0_line_offset": self.ppu.sprite0_line_offset,
            "sprite0_dot_offset": self.ppu.sprite0_dot_offset,
            "power_on_rendering": self.ppu.power_on_rendering,
            "power_on_ram": ("zeros" if not self.power_on_ram
                             else "supplied"),
            "power_on_status": f"0x{self.power_on_status:02X}",
            "ppu_memory": ("name tables, CHR and palette modelled; "
                           "vertical mirroring"
                           if self.ppu_memory.chr != bytes(0x2000)
                           else "no CHR supplied: pattern reads return 0"),
            "vram_accesses_while_rendering_enabled": (
                self.ppu_memory.reads_while_rendering
                + self.ppu_memory.writes_while_rendering),
            "unmodelled": [
                "the renderer does not update the $2006 latch, so a $2007 "
                "access while rendering is enabled sees a different address "
                "than a console would",
                "no OAM read-back: $2004 reads return 0",
                "no OAM: $4014 costs cycles and republishes sprite 0 only",
                "no APU: $4015 reads 0, so the frame counter and DMC are absent",
                "sprite-0 hit position is calibrated, not rendered",
                "no open-bus decay; unmapped reads are 0 as in nes-py",
            ],
        }


def load_prg(path: str | None = None) -> bytes:
    from rom import load_rom
    return load_rom(path).prg


def from_rom(path: str | None = None, **kwargs) -> Tracer:
    """A tracer for the validated image, with its CHR and mirroring."""
    from pathlib import Path

    from rom import default_rom_path, load_rom
    image = load_rom(path)
    raw = Path(path or default_rom_path()).read_bytes()
    vertical = bool(raw[6] & 1)
    return Tracer(image.prg, chr_rom=image.chr, vertical_mirroring=vertical,
                  **kwargs)
