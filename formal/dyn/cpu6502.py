"""py65's NMOS 6502 core, adjusted for the 2A03 and completed for all 256 opcodes.

Two changes to `py65.devices.mpu6502.MPU`:

**Decimal mode.**  The 2A03's adder has no decimal correction; the D flag still
exists as a bit and is still pushed and pulled by `PHP`/`PLP`.  `opADC` and
`opSBC` are therefore wrapped so that the *flag bit is preserved* but the
*adder never sees it*: the wrapper clears D in `self.p`, calls py65's binary
path, and restores the bit afterwards.  Clearing the bit before the call is
what selects the binary branch inside py65; restoring it afterwards is safe
because neither path writes D.  `SED`/`CLD` keep working, `PHP` pushes the real
bit, and `ADC`/`SBC` are always binary.  This is checked by
`formal.dyn.validate_cpu` against the SingleStepTests `nes6502` vectors, which
were recorded on a 2A03 and therefore contain no BCD results.

**The 105 undocumented opcodes.**  py65 maps every opcode it does not
implement to `inst_not_implemented`, which advances PC by one and costs zero
cycles.  Zero-cycle instructions stall a cycle-driven run and a wrong length
mis-aligns the instruction stream, which is exactly what a derailment
experiment must get right, so all of them are implemented here: the stable
combined operations (`SLO RLA SRE RRA SAX LAX DCP ISB`), the immediate group
(`ANC ALR ARR SBX LAS`), the multi-byte `NOP`s, the six unstable instructions
(`XAA LXA TAS SHA SHX SHY`, with the usual magic-constant conventions) and the
twelve `JAM` encodings, which raise `Jam` instead of fetching further.

The unstable six do not have a single hardware behaviour; `formal/model/cpu.py`
models them as havoc for that reason.  Any trace that executes one is flagged
in the report, and `validate_cpu` reports them separately rather than counting
them as agreement.
"""
from __future__ import annotations

from py65.devices.mpu6502 import MPU
from py65.utils.devices import make_instruction_decorator


class Jam(Exception):
    """A `JAM`/`KIL` encoding was executed: the processor stops fetching."""

    def __init__(self, pc: int, opcode: int):
        super().__init__(f"JAM ${opcode:02X} at ${pc:04X}")
        self.pc = pc
        self.opcode = opcode


#: `XAA`/`LXA` fold a hardware-dependent constant into the operand.  $EE is the
#: value most often reported for a cold 2A03; it is a *choice*, not a fact.
MAGIC = 0xEE

UNSTABLE_OPCODES = frozenset({
    0x8B,                     # XAA / ANE
    0xAB,                     # LXA / LAX #imm
    0x9B,                     # TAS / SHS
    0x93, 0x9F,               # SHA / AHX
    0x9E,                     # SHX
    0x9C,                     # SHY
    0x6B,                     # ARR (stable in binary mode; havoc in the model)
})

JAM_OPCODES = frozenset({0x02, 0x12, 0x22, 0x32, 0x42, 0x52,
                         0x62, 0x72, 0x92, 0xB2, 0xD2, 0xF2})


class NMOS2A03(MPU):
    """An NMOS 6502 with no decimal adder and every opcode implemented."""

    # The decorator mutates class-level tables; copy py65's so the base class
    # is left alone (other code in the repository uses it for validation).
    instruct = list(MPU.instruct)
    cycletime = list(MPU.cycletime)
    extracycles = list(MPU.extracycles)
    disassemble = list(MPU.disassemble)
    instruction = make_instruction_decorator(instruct, disassemble,
                                             cycletime, extracycles)

    #: py65 1.2.0 gives `DEC $nnnn` three cycles instead of six.  The vectors
    #: in `formal.dyn.validate_cpu` catch it; the image executes `DEC abs` in
    #: the NMI handler, so the error would shift every frame's timing.
    cycletime[0xCE] = 6

    def __init__(self, memory=None, pc=0x0000):
        super().__init__(memory=memory, pc=pc)
        self.name = '2A03'

    # -- decimal mode is ignored by the adder -----------------------------

    def opADC(self, x):
        decimal = self.p & 8
        if decimal:
            self.p &= ~8
            MPU.opADC(self, x)
            self.p |= 8
        else:
            MPU.opADC(self, x)

    def opSBC(self, x):
        decimal = self.p & 8
        if decimal:
            self.p &= ~8
            MPU.opSBC(self, x)
            self.p |= 8
        else:
            MPU.opSBC(self, x)

    # -- helpers for the undocumented operations --------------------------

    def _rmw(self, addr, value):
        self.memory[addr] = value & 0xFF

    def _cmp(self, register, value):
        self.p &= ~(self.CARRY | self.ZERO | self.NEGATIVE)
        if register == value:
            self.p |= self.CARRY | self.ZERO
        elif register > value:
            self.p |= self.CARRY
        self.p |= (register - value) & self.NEGATIVE

    def _slo(self, addr):
        value = self.ByteAt(addr)
        self.p &= ~self.CARRY
        if value & 0x80:
            self.p |= self.CARRY
        value = (value << 1) & 0xFF
        self._rmw(addr, value)
        self.a |= value
        self.FlagsNZ(self.a)

    def _rla(self, addr):
        value = self.ByteAt(addr)
        carry = self.p & self.CARRY
        self.p &= ~self.CARRY
        if value & 0x80:
            self.p |= self.CARRY
        value = ((value << 1) | (1 if carry else 0)) & 0xFF
        self._rmw(addr, value)
        self.a &= value
        self.FlagsNZ(self.a)

    def _sre(self, addr):
        value = self.ByteAt(addr)
        self.p &= ~self.CARRY
        if value & 1:
            self.p |= self.CARRY
        value >>= 1
        self._rmw(addr, value)
        self.a ^= value
        self.FlagsNZ(self.a)

    def _rra(self, addr):
        value = self.ByteAt(addr)
        carry = self.p & self.CARRY
        self.p &= ~self.CARRY
        if value & 1:
            self.p |= self.CARRY
        value = (value >> 1) | (0x80 if carry else 0)
        self._rmw(addr, value)
        self._adc_value(value)

    def _adc_value(self, data):
        """Binary ADC of `data` into A (the 2A03 adder, D ignored)."""
        carry = 1 if self.p & self.CARRY else 0
        result = self.a + data + carry
        self.p &= ~(self.CARRY | self.OVERFLOW | self.NEGATIVE | self.ZERO)
        if (~(self.a ^ data) & (self.a ^ result)) & self.NEGATIVE:
            self.p |= self.OVERFLOW
        if result > 0xFF:
            self.p |= self.CARRY
        result &= 0xFF
        if result == 0:
            self.p |= self.ZERO
        else:
            self.p |= result & self.NEGATIVE
        self.a = result

    def _sbc_value(self, data):
        """Binary SBC of `data` from A."""
        carry = 1 if self.p & self.CARRY else 0
        result = self.a + (~data & 0xFF) + carry
        self.p &= ~(self.CARRY | self.ZERO | self.OVERFLOW | self.NEGATIVE)
        if ((self.a ^ data) & (self.a ^ result)) & self.NEGATIVE:
            self.p |= self.OVERFLOW
        if result > 0xFF:
            self.p |= self.CARRY
        result &= 0xFF
        if result == 0:
            self.p |= self.ZERO
        else:
            self.p |= result & self.NEGATIVE
        self.a = result

    def _dcp(self, addr):
        value = (self.ByteAt(addr) - 1) & 0xFF
        self._rmw(addr, value)
        self._cmp(self.a, value)

    def _isb(self, addr):
        value = (self.ByteAt(addr) + 1) & 0xFF
        self._rmw(addr, value)
        self._sbc_value(value)

    def _lax(self, addr):
        value = self.ByteAt(addr)
        self.a = value
        self.x = value
        self.FlagsNZ(value)

    def _sax(self, addr):
        self._rmw(addr, self.a & self.x)

    def _unstable_store(self, base, index, value):
        """`SHA`/`SHX`/`SHY`/`TAS`.

        The byte written is `value & (high(base) + 1)`, where `base` is the
        address *before* indexing, and when the index carries into the high
        byte the address's own high byte is replaced by that byte.  Both halves
        are checked against the recorded vectors in `validate_cpu`; what is
        *not* modelled is that on real silicon the AND is a floating-bus
        effect that can fail to happen at all, which is why these six stay in
        the unstable set.
        """
        written = value & (((base >> 8) + 1) & 0xFF)
        addr = (base + index) & 0xFFFF
        if (base & 0xFF00) != (addr & 0xFF00):
            addr = (written << 8) | (addr & 0xFF)
        self._rmw(addr, written)

    # -- undocumented: SLO -------------------------------------------------

    @instruction(name="SLO", mode="zpg", cycles=5)
    def inst_0x07(self):
        self._slo(self.ZeroPageAddr())
        self.pc += 1

    @instruction(name="SLO", mode="zpx", cycles=6)
    def inst_0x17(self):
        self._slo(self.ZeroPageXAddr())
        self.pc += 1

    @instruction(name="SLO", mode="izx", cycles=8)
    def inst_0x03(self):
        self._slo(self.IndirectXAddr())
        self.pc += 1

    @instruction(name="SLO", mode="izy", cycles=8)
    def inst_0x13(self):
        self._slo(self.IndirectYAddr())
        self.pc += 1

    @instruction(name="SLO", mode="abs", cycles=6)
    def inst_0x0f(self):
        self._slo(self.AbsoluteAddr())
        self.pc += 2

    @instruction(name="SLO", mode="abx", cycles=7)
    def inst_0x1f(self):
        self._slo(self.AbsoluteXAddr())
        self.pc += 2

    @instruction(name="SLO", mode="aby", cycles=7)
    def inst_0x1b(self):
        self._slo(self.AbsoluteYAddr())
        self.pc += 2

    # -- undocumented: RLA -------------------------------------------------

    @instruction(name="RLA", mode="zpg", cycles=5)
    def inst_0x27(self):
        self._rla(self.ZeroPageAddr())
        self.pc += 1

    @instruction(name="RLA", mode="zpx", cycles=6)
    def inst_0x37(self):
        self._rla(self.ZeroPageXAddr())
        self.pc += 1

    @instruction(name="RLA", mode="izx", cycles=8)
    def inst_0x23(self):
        self._rla(self.IndirectXAddr())
        self.pc += 1

    @instruction(name="RLA", mode="izy", cycles=8)
    def inst_0x33(self):
        self._rla(self.IndirectYAddr())
        self.pc += 1

    @instruction(name="RLA", mode="abs", cycles=6)
    def inst_0x2f(self):
        self._rla(self.AbsoluteAddr())
        self.pc += 2

    @instruction(name="RLA", mode="abx", cycles=7)
    def inst_0x3f(self):
        self._rla(self.AbsoluteXAddr())
        self.pc += 2

    @instruction(name="RLA", mode="aby", cycles=7)
    def inst_0x3b(self):
        self._rla(self.AbsoluteYAddr())
        self.pc += 2

    # -- undocumented: SRE -------------------------------------------------

    @instruction(name="SRE", mode="zpg", cycles=5)
    def inst_0x47(self):
        self._sre(self.ZeroPageAddr())
        self.pc += 1

    @instruction(name="SRE", mode="zpx", cycles=6)
    def inst_0x57(self):
        self._sre(self.ZeroPageXAddr())
        self.pc += 1

    @instruction(name="SRE", mode="izx", cycles=8)
    def inst_0x43(self):
        self._sre(self.IndirectXAddr())
        self.pc += 1

    @instruction(name="SRE", mode="izy", cycles=8)
    def inst_0x53(self):
        self._sre(self.IndirectYAddr())
        self.pc += 1

    @instruction(name="SRE", mode="abs", cycles=6)
    def inst_0x4f(self):
        self._sre(self.AbsoluteAddr())
        self.pc += 2

    @instruction(name="SRE", mode="abx", cycles=7)
    def inst_0x5f(self):
        self._sre(self.AbsoluteXAddr())
        self.pc += 2

    @instruction(name="SRE", mode="aby", cycles=7)
    def inst_0x5b(self):
        self._sre(self.AbsoluteYAddr())
        self.pc += 2

    # -- undocumented: RRA -------------------------------------------------

    @instruction(name="RRA", mode="zpg", cycles=5)
    def inst_0x67(self):
        self._rra(self.ZeroPageAddr())
        self.pc += 1

    @instruction(name="RRA", mode="zpx", cycles=6)
    def inst_0x77(self):
        self._rra(self.ZeroPageXAddr())
        self.pc += 1

    @instruction(name="RRA", mode="izx", cycles=8)
    def inst_0x63(self):
        self._rra(self.IndirectXAddr())
        self.pc += 1

    @instruction(name="RRA", mode="izy", cycles=8)
    def inst_0x73(self):
        self._rra(self.IndirectYAddr())
        self.pc += 1

    @instruction(name="RRA", mode="abs", cycles=6)
    def inst_0x6f(self):
        self._rra(self.AbsoluteAddr())
        self.pc += 2

    @instruction(name="RRA", mode="abx", cycles=7)
    def inst_0x7f(self):
        self._rra(self.AbsoluteXAddr())
        self.pc += 2

    @instruction(name="RRA", mode="aby", cycles=7)
    def inst_0x7b(self):
        self._rra(self.AbsoluteYAddr())
        self.pc += 2

    # -- undocumented: SAX -------------------------------------------------

    @instruction(name="SAX", mode="zpg", cycles=3)
    def inst_0x87(self):
        self._sax(self.ZeroPageAddr())
        self.pc += 1

    @instruction(name="SAX", mode="zpy", cycles=4)
    def inst_0x97(self):
        self._sax(self.ZeroPageYAddr())
        self.pc += 1

    @instruction(name="SAX", mode="izx", cycles=6)
    def inst_0x83(self):
        self._sax(self.IndirectXAddr())
        self.pc += 1

    @instruction(name="SAX", mode="abs", cycles=4)
    def inst_0x8f(self):
        self._sax(self.AbsoluteAddr())
        self.pc += 2

    # -- undocumented: LAX -------------------------------------------------

    @instruction(name="LAX", mode="zpg", cycles=3)
    def inst_0xa7(self):
        self._lax(self.ZeroPageAddr())
        self.pc += 1

    @instruction(name="LAX", mode="zpy", cycles=4)
    def inst_0xb7(self):
        self._lax(self.ZeroPageYAddr())
        self.pc += 1

    @instruction(name="LAX", mode="izx", cycles=6)
    def inst_0xa3(self):
        self._lax(self.IndirectXAddr())
        self.pc += 1

    @instruction(name="LAX", mode="izy", cycles=5, extracycles=1)
    def inst_0xb3(self):
        self._lax(self.IndirectYAddr())
        self.pc += 1

    @instruction(name="LAX", mode="abs", cycles=4)
    def inst_0xaf(self):
        self._lax(self.AbsoluteAddr())
        self.pc += 2

    @instruction(name="LAX", mode="aby", cycles=4, extracycles=1)
    def inst_0xbf(self):
        self._lax(self.AbsoluteYAddr())
        self.pc += 2

    # -- undocumented: DCP -------------------------------------------------

    @instruction(name="DCP", mode="zpg", cycles=5)
    def inst_0xc7(self):
        self._dcp(self.ZeroPageAddr())
        self.pc += 1

    @instruction(name="DCP", mode="zpx", cycles=6)
    def inst_0xd7(self):
        self._dcp(self.ZeroPageXAddr())
        self.pc += 1

    @instruction(name="DCP", mode="izx", cycles=8)
    def inst_0xc3(self):
        self._dcp(self.IndirectXAddr())
        self.pc += 1

    @instruction(name="DCP", mode="izy", cycles=8)
    def inst_0xd3(self):
        self._dcp(self.IndirectYAddr())
        self.pc += 1

    @instruction(name="DCP", mode="abs", cycles=6)
    def inst_0xcf(self):
        self._dcp(self.AbsoluteAddr())
        self.pc += 2

    @instruction(name="DCP", mode="abx", cycles=7)
    def inst_0xdf(self):
        self._dcp(self.AbsoluteXAddr())
        self.pc += 2

    @instruction(name="DCP", mode="aby", cycles=7)
    def inst_0xdb(self):
        self._dcp(self.AbsoluteYAddr())
        self.pc += 2

    # -- undocumented: ISB -------------------------------------------------

    @instruction(name="ISB", mode="zpg", cycles=5)
    def inst_0xe7(self):
        self._isb(self.ZeroPageAddr())
        self.pc += 1

    @instruction(name="ISB", mode="zpx", cycles=6)
    def inst_0xf7(self):
        self._isb(self.ZeroPageXAddr())
        self.pc += 1

    @instruction(name="ISB", mode="izx", cycles=8)
    def inst_0xe3(self):
        self._isb(self.IndirectXAddr())
        self.pc += 1

    @instruction(name="ISB", mode="izy", cycles=8)
    def inst_0xf3(self):
        self._isb(self.IndirectYAddr())
        self.pc += 1

    @instruction(name="ISB", mode="abs", cycles=6)
    def inst_0xef(self):
        self._isb(self.AbsoluteAddr())
        self.pc += 2

    @instruction(name="ISB", mode="abx", cycles=7)
    def inst_0xff(self):
        self._isb(self.AbsoluteXAddr())
        self.pc += 2

    @instruction(name="ISB", mode="aby", cycles=7)
    def inst_0xfb(self):
        self._isb(self.AbsoluteYAddr())
        self.pc += 2

    # -- undocumented: immediate group ------------------------------------

    @instruction(name="ANC", mode="imm", cycles=2)
    def inst_0x0b(self):
        self.a &= self.ImmediateByte()
        self.FlagsNZ(self.a)
        self.p &= ~self.CARRY
        if self.a & 0x80:
            self.p |= self.CARRY
        self.pc += 1

    @instruction(name="ANC", mode="imm", cycles=2)
    def inst_0x2b(self):
        self.inst_0x0b()

    @instruction(name="ALR", mode="imm", cycles=2)
    def inst_0x4b(self):
        value = self.a & self.ImmediateByte()
        self.p &= ~self.CARRY
        if value & 1:
            self.p |= self.CARRY
        self.a = value >> 1
        self.FlagsNZ(self.a)
        self.pc += 1

    @instruction(name="ARR", mode="imm", cycles=2)
    def inst_0x6b(self):
        value = self.a & self.ImmediateByte()
        carry = 1 if self.p & self.CARRY else 0
        result = (value >> 1) | (carry << 7)
        self.p &= ~(self.CARRY | self.OVERFLOW | self.ZERO | self.NEGATIVE)
        # carry is bit 6 of the result, i.e. bit 7 of the AND, not bit 0 of it
        if value & 0x80:
            self.p |= self.CARRY
        if (result ^ (result << 1)) & 0x40:
            self.p |= self.OVERFLOW
        self.a = result
        self.FlagsNZ(result)
        self.pc += 1

    @instruction(name="XAA", mode="imm", cycles=2)
    def inst_0x8b(self):
        self.a = (self.a | MAGIC) & self.x & self.ImmediateByte()
        self.FlagsNZ(self.a)
        self.pc += 1

    @instruction(name="LXA", mode="imm", cycles=2)
    def inst_0xab(self):
        self.a = (self.a | MAGIC) & self.ImmediateByte()
        self.x = self.a
        self.FlagsNZ(self.a)
        self.pc += 1

    @instruction(name="SBX", mode="imm", cycles=2)
    def inst_0xcb(self):
        value = self.ImmediateByte()
        base = self.a & self.x
        self.x = (base - value) & 0xFF
        self._cmp(base, value)
        self.pc += 1

    @instruction(name="SBC", mode="imm", cycles=2)
    def inst_0xeb(self):
        self._sbc_value(self.ImmediateByte())
        self.pc += 1

    @instruction(name="LAS", mode="aby", cycles=4, extracycles=1)
    def inst_0xbb(self):
        value = self.ByteAt(self.AbsoluteYAddr()) & self.sp
        self.a = value
        self.x = value
        self.sp = value
        self.FlagsNZ(value)
        self.pc += 2

    # -- undocumented: unstable stores ------------------------------------

    @instruction(name="SHA", mode="izy", cycles=6)
    def inst_0x93(self):
        self._unstable_store(self.WrapAt(self.ByteAt(self.pc)), self.y,
                             self.a & self.x)
        self.pc += 1

    @instruction(name="SHA", mode="aby", cycles=5)
    def inst_0x9f(self):
        self._unstable_store(self.WordAt(self.pc), self.y, self.a & self.x)
        self.pc += 2

    @instruction(name="SHX", mode="aby", cycles=5)
    def inst_0x9e(self):
        self._unstable_store(self.WordAt(self.pc), self.y, self.x)
        self.pc += 2

    @instruction(name="SHY", mode="abx", cycles=5)
    def inst_0x9c(self):
        self._unstable_store(self.WordAt(self.pc), self.x, self.y)
        self.pc += 2

    @instruction(name="TAS", mode="aby", cycles=5)
    def inst_0x9b(self):
        self.sp = self.a & self.x
        self._unstable_store(self.WordAt(self.pc), self.y, self.sp)
        self.pc += 2

    # -- undocumented: NOPs ------------------------------------------------

    @instruction(name="NOP", mode="imp", cycles=2)
    def inst_0x1a(self):
        pass

    @instruction(name="NOP", mode="imp", cycles=2)
    def inst_0x3a(self):
        pass

    @instruction(name="NOP", mode="imp", cycles=2)
    def inst_0x5a(self):
        pass

    @instruction(name="NOP", mode="imp", cycles=2)
    def inst_0x7a(self):
        pass

    @instruction(name="NOP", mode="imp", cycles=2)
    def inst_0xda(self):
        pass

    @instruction(name="NOP", mode="imp", cycles=2)
    def inst_0xfa(self):
        pass

    @instruction(name="NOP", mode="imm", cycles=2)
    def inst_0x80(self):
        self.pc += 1

    @instruction(name="NOP", mode="imm", cycles=2)
    def inst_0x82(self):
        self.pc += 1

    @instruction(name="NOP", mode="imm", cycles=2)
    def inst_0x89(self):
        self.pc += 1

    @instruction(name="NOP", mode="imm", cycles=2)
    def inst_0xc2(self):
        self.pc += 1

    @instruction(name="NOP", mode="imm", cycles=2)
    def inst_0xe2(self):
        self.pc += 1

    @instruction(name="NOP", mode="zpg", cycles=3)
    def inst_0x04(self):
        self.ByteAt(self.ZeroPageAddr())
        self.pc += 1

    @instruction(name="NOP", mode="zpg", cycles=3)
    def inst_0x44(self):
        self.inst_0x04()

    @instruction(name="NOP", mode="zpg", cycles=3)
    def inst_0x64(self):
        self.inst_0x04()

    @instruction(name="NOP", mode="zpx", cycles=4)
    def inst_0x14(self):
        self.ByteAt(self.ZeroPageXAddr())
        self.pc += 1

    @instruction(name="NOP", mode="zpx", cycles=4)
    def inst_0x34(self):
        self.inst_0x14()

    @instruction(name="NOP", mode="zpx", cycles=4)
    def inst_0x54(self):
        self.inst_0x14()

    @instruction(name="NOP", mode="zpx", cycles=4)
    def inst_0x74(self):
        self.inst_0x14()

    @instruction(name="NOP", mode="zpx", cycles=4)
    def inst_0xd4(self):
        self.inst_0x14()

    @instruction(name="NOP", mode="zpx", cycles=4)
    def inst_0xf4(self):
        self.inst_0x14()

    @instruction(name="NOP", mode="abs", cycles=4)
    def inst_0x0c(self):
        self.ByteAt(self.AbsoluteAddr())
        self.pc += 2

    @instruction(name="NOP", mode="abx", cycles=4, extracycles=1)
    def inst_0x1c(self):
        self.ByteAt(self.AbsoluteXAddr())
        self.pc += 2

    @instruction(name="NOP", mode="abx", cycles=4, extracycles=1)
    def inst_0x3c(self):
        self.inst_0x1c()

    @instruction(name="NOP", mode="abx", cycles=4, extracycles=1)
    def inst_0x5c(self):
        self.inst_0x1c()

    @instruction(name="NOP", mode="abx", cycles=4, extracycles=1)
    def inst_0x7c(self):
        self.inst_0x1c()

    @instruction(name="NOP", mode="abx", cycles=4, extracycles=1)
    def inst_0xdc(self):
        self.inst_0x1c()

    @instruction(name="NOP", mode="abx", cycles=4, extracycles=1)
    def inst_0xfc(self):
        self.inst_0x1c()

    # -- undocumented: JAM -------------------------------------------------

    def _jam(self):
        opcode = self.memory[(self.pc - 1) & 0xFFFF]
        raise Jam((self.pc - 1) & 0xFFFF, opcode)

    @instruction(name="JAM", mode="imp", cycles=2)
    def inst_0x02(self):
        self._jam()

    @instruction(name="JAM", mode="imp", cycles=2)
    def inst_0x12(self):
        self._jam()

    @instruction(name="JAM", mode="imp", cycles=2)
    def inst_0x22(self):
        self._jam()

    @instruction(name="JAM", mode="imp", cycles=2)
    def inst_0x32(self):
        self._jam()

    @instruction(name="JAM", mode="imp", cycles=2)
    def inst_0x42(self):
        self._jam()

    @instruction(name="JAM", mode="imp", cycles=2)
    def inst_0x52(self):
        self._jam()

    @instruction(name="JAM", mode="imp", cycles=2)
    def inst_0x62(self):
        self._jam()

    @instruction(name="JAM", mode="imp", cycles=2)
    def inst_0x72(self):
        self._jam()

    @instruction(name="JAM", mode="imp", cycles=2)
    def inst_0x92(self):
        self._jam()

    @instruction(name="JAM", mode="imp", cycles=2)
    def inst_0xb2(self):
        self._jam()

    @instruction(name="JAM", mode="imp", cycles=2)
    def inst_0xd2(self):
        self._jam()

    @instruction(name="JAM", mode="imp", cycles=2)
    def inst_0xf2(self):
        self._jam()


def unimplemented_opcodes() -> list[int]:
    """Opcodes still mapped to py65's placeholder (should be empty)."""
    placeholder = MPU.inst_not_implemented
    return [op for op, fn in enumerate(NMOS2A03.instruct)
            if fn is placeholder]
