"""Complete NMOS 6502 instruction decoder (plan section 5).

`d65.py` knows only the 151 documented opcodes, and `trace.py` stops a trace
when it meets anything else ("hit data").  That is unsound in both directions:

  * An undocumented opcode is **not** proof that the bytes are data.  On the
    NMOS 6502 every one of the 256 encodings does something.  105 of them are
    undocumented, and they are not all NOPs: `SLO`, `RLA`, `SRE`, `RRA`, `DCP`
    and `ISC` are read-modify-write instructions, `SAX`/`SHA`/`SHX`/`SHY`
    store, `LAX` loads, and twelve encodings jam the processor.
  * Treating an undocumented opcode as a one-byte stop also mis-aligns
    everything after it, because most of them are two or three bytes long.

This module therefore decodes all 256 encodings with their real length and
control-flow behaviour, and records whether each is documented, so the audit
can say "this path runs an undocumented RMW instruction" instead of silently
dropping the path.

Hardware details modelled here:

  * Relative branches: the displacement is signed and added to the address of
    the *next* instruction, with 16-bit wrap.
  * `JMP (abs)`: the NMOS page-crossing bug.  `JMP ($10FF)` reads the low byte
    from `$10FF` and the high byte from `$1000`, not `$1100`.
  * Zero-page indexed addressing wraps inside page zero.
  * `JAM` encodings halt the processor; they are a distinct control-flow kind,
    not a NOP and not a return.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

# --------------------------------------------------------------------------
# addressing modes
# --------------------------------------------------------------------------

#: mode -> instruction length in bytes
MODE_LENGTH = {
    "imp": 1, "acc": 1,
    "imm": 2, "zp": 2, "zpx": 2, "zpy": 2, "izx": 2, "izy": 2, "rel": 2,
    "abs": 3, "abx": 3, "aby": 3, "ind": 3,
}


class Flow(str, Enum):
    """How an instruction moves the program counter."""

    NORMAL = "normal"          # falls through
    BRANCH = "branch"          # conditional: falls through or takes the target
    JUMP = "jump"              # unconditional direct jump
    INDIRECT_JUMP = "indirect_jump"   # JMP (abs): target is data-derived
    CALL = "call"              # JSR
    RETURN = "return"          # RTS / RTI
    BREAK = "break"            # BRK: pushes a frame and vectors through $FFFE
    HALT = "halt"              # JAM / KIL: the CPU stops fetching


@dataclass(frozen=True)
class OpcodeInfo:
    opcode: int
    mnemonic: str
    mode: str
    documented: bool
    flow: Flow
    #: undocumented instructions whose result depends on analogue behaviour
    unstable: bool = False

    @property
    def length(self) -> int:
        return MODE_LENGTH[self.mode]


def _table() -> dict[int, OpcodeInfo]:
    #: (opcode, mnemonic, mode) for the 151 documented encodings
    documented = """
    00 BRK imp|01 ORA izx|05 ORA zp|06 ASL zp|08 PHP imp|09 ORA imm|0a ASL acc|
    0d ORA abs|0e ASL abs|10 BPL rel|11 ORA izy|15 ORA zpx|16 ASL zpx|18 CLC imp|
    19 ORA aby|1d ORA abx|1e ASL abx|20 JSR abs|21 AND izx|24 BIT zp|25 AND zp|
    26 ROL zp|28 PLP imp|29 AND imm|2a ROL acc|2c BIT abs|2d AND abs|2e ROL abs|
    30 BMI rel|31 AND izy|35 AND zpx|36 ROL zpx|38 SEC imp|39 AND aby|3d AND abx|
    3e ROL abx|40 RTI imp|41 EOR izx|45 EOR zp|46 LSR zp|48 PHA imp|49 EOR imm|
    4a LSR acc|4c JMP abs|4d EOR abs|4e LSR abs|50 BVC rel|51 EOR izy|55 EOR zpx|
    56 LSR zpx|58 CLI imp|59 EOR aby|5d EOR abx|5e LSR abx|60 RTS imp|61 ADC izx|
    65 ADC zp|66 ROR zp|68 PLA imp|69 ADC imm|6a ROR acc|6c JMP ind|6d ADC abs|
    6e ROR abs|70 BVS rel|71 ADC izy|75 ADC zpx|76 ROR zpx|78 SEI imp|79 ADC aby|
    7d ADC abx|7e ROR abx|81 STA izx|84 STY zp|85 STA zp|86 STX zp|88 DEY imp|
    8a TXA imp|8c STY abs|8d STA abs|8e STX abs|90 BCC rel|91 STA izy|94 STY zpx|
    95 STA zpx|96 STX zpy|98 TYA imp|99 STA aby|9a TXS imp|9d STA abx|a0 LDY imm|
    a1 LDA izx|a2 LDX imm|a4 LDY zp|a5 LDA zp|a6 LDX zp|a8 TAY imp|a9 LDA imm|
    aa TAX imp|ac LDY abs|ad LDA abs|ae LDX abs|b0 BCS rel|b1 LDA izy|b4 LDY zpx|
    b5 LDA zpx|b6 LDX zpy|b8 CLV imp|b9 LDA aby|ba TSX imp|bc LDY abx|bd LDA abx|
    be LDX aby|c0 CPY imm|c1 CMP izx|c4 CPY zp|c5 CMP zp|c6 DEC zp|c8 INY imp|
    c9 CMP imm|ca DEX imp|cc CPY abs|cd CMP abs|ce DEC abs|d0 BNE rel|d1 CMP izy|
    d5 CMP zpx|d6 DEC zpx|d8 CLD imp|d9 CMP aby|dd CMP abx|de DEC abx|e0 CPX imm|
    e1 SBC izx|e4 CPX zp|e5 SBC zp|e6 INC zp|e8 INX imp|e9 SBC imm|ea NOP imp|
    ec CPX abs|ed SBC abs|ee INC abs|f0 BEQ rel|f1 SBC izy|f5 SBC zpx|f6 INC zpx|
    f8 SED imp|f9 SBC aby|fd SBC abx|fe INC abx
    """

    #: the 105 undocumented encodings
    undocumented = """
    03 SLO izx|07 SLO zp|0f SLO abs|13 SLO izy|17 SLO zpx|1b SLO aby|1f SLO abx|
    23 RLA izx|27 RLA zp|2f RLA abs|33 RLA izy|37 RLA zpx|3b RLA aby|3f RLA abx|
    43 SRE izx|47 SRE zp|4f SRE abs|53 SRE izy|57 SRE zpx|5b SRE aby|5f SRE abx|
    63 RRA izx|67 RRA zp|6f RRA abs|73 RRA izy|77 RRA zpx|7b RRA aby|7f RRA abx|
    83 SAX izx|87 SAX zp|8f SAX abs|97 SAX zpy|
    a3 LAX izx|a7 LAX zp|af LAX abs|b3 LAX izy|b7 LAX zpy|bf LAX aby|
    c3 DCP izx|c7 DCP zp|cf DCP abs|d3 DCP izy|d7 DCP zpx|db DCP aby|df DCP abx|
    e3 ISC izx|e7 ISC zp|ef ISC abs|f3 ISC izy|f7 ISC zpx|fb ISC aby|ff ISC abx|
    0b ANC imm|2b ANC imm|4b ALR imm|6b ARR imm|cb SBX imm|eb USBC imm|
    8b XAA imm|ab LXA imm|93 SHA izy|9f SHA aby|9b TAS aby|9c SHY abx|9e SHX aby|
    bb LAS aby|
    1a NOP imp|3a NOP imp|5a NOP imp|7a NOP imp|da NOP imp|fa NOP imp|
    80 NOP imm|82 NOP imm|89 NOP imm|c2 NOP imm|e2 NOP imm|
    04 NOP zp|44 NOP zp|64 NOP zp|
    14 NOP zpx|34 NOP zpx|54 NOP zpx|74 NOP zpx|d4 NOP zpx|f4 NOP zpx|
    0c NOP abs|
    1c NOP abx|3c NOP abx|5c NOP abx|7c NOP abx|dc NOP abx|fc NOP abx|
    02 JAM imp|12 JAM imp|22 JAM imp|32 JAM imp|42 JAM imp|52 JAM imp|
    62 JAM imp|72 JAM imp|92 JAM imp|b2 JAM imp|d2 JAM imp|f2 JAM imp
    """

    #: undocumented instructions whose behaviour depends on analogue effects
    #: (the "magic constant" group); modelled, but flagged.
    UNSTABLE = {"XAA", "LXA", "TAS", "SHA", "SHX", "SHY", "ARR"}

    flows = {
        "JSR": Flow.CALL,
        "RTS": Flow.RETURN,
        "RTI": Flow.RETURN,
        "BRK": Flow.BREAK,
        "JAM": Flow.HALT,
    }
    branches = {"BPL", "BMI", "BVC", "BVS", "BCC", "BCS", "BNE", "BEQ"}

    table: dict[int, OpcodeInfo] = {}
    for text, is_documented in ((documented, True), (undocumented, False)):
        for entry in text.replace("\n", "").split("|"):
            entry = entry.strip()
            if not entry:
                continue
            code, mnemonic, mode = entry.split()
            opcode = int(code, 16)
            if mnemonic in branches:
                flow = Flow.BRANCH
            elif mnemonic == "JMP":
                flow = Flow.JUMP if mode == "abs" else Flow.INDIRECT_JUMP
            else:
                flow = flows.get(mnemonic, Flow.NORMAL)
            if opcode in table:
                raise AssertionError(f"opcode ${opcode:02X} listed twice")
            table[opcode] = OpcodeInfo(opcode, mnemonic, mode, is_documented,
                                       flow, mnemonic in UNSTABLE)
    missing = sorted(set(range(256)) - set(table))
    if missing:
        raise AssertionError(
            "opcode table incomplete: " + ", ".join(f"${m:02X}" for m in missing)
        )
    return table


OPCODES: dict[int, OpcodeInfo] = _table()

DOCUMENTED_COUNT = sum(1 for info in OPCODES.values() if info.documented)


@dataclass(frozen=True)
class Instruction:
    address: int
    info: OpcodeInfo
    operands: tuple[int, ...]

    @property
    def length(self) -> int:
        return self.info.length

    @property
    def end(self) -> int:
        """Address just past this instruction, with 16-bit wrap."""
        return (self.address + self.length) & 0xFFFF

    @property
    def bytes(self) -> bytes:
        return bytes((self.info.opcode, *self.operands))

    @property
    def operand16(self) -> int:
        if len(self.operands) < 2:
            raise ValueError(f"{self.info.mnemonic} has no 16-bit operand")
        return self.operands[0] | self.operands[1] << 8

    @property
    def branch_target(self) -> int:
        """Signed displacement from the *next* instruction, 16-bit wrap."""
        if self.info.mode != "rel":
            raise ValueError(f"{self.info.mnemonic} is not a relative branch")
        displacement = self.operands[0]
        if displacement > 0x7F:
            displacement -= 0x100
        return (self.end + displacement) & 0xFFFF

    def successors(self) -> list[tuple[int, str]]:
        """(address, edge kind) pairs, excluding data-derived destinations."""
        flow = self.info.flow
        if flow is Flow.NORMAL:
            return [(self.end, "fallthrough")]
        if flow is Flow.BRANCH:
            return [(self.end, "fallthrough"), (self.branch_target, "branch")]
        if flow is Flow.JUMP:
            return [(self.operand16, "jump")]
        if flow is Flow.CALL:
            # the call target, plus the return point which the callee may or
            # may not honour (JumpEngine does not); the CFG decides.
            return [(self.operand16, "call")]
        return []        # RETURN / BREAK / HALT / INDIRECT_JUMP: not direct

    def __str__(self) -> str:
        mode, info = self.info.mode, self.info
        a8 = self.operands[0] if self.operands else 0
        text = {
            "imp": "", "acc": "A", "imm": f"#${a8:02X}", "zp": f"${a8:02X}",
            "zpx": f"${a8:02X},X", "zpy": f"${a8:02X},Y",
            "izx": f"(${a8:02X},X)", "izy": f"(${a8:02X}),Y",
            "rel": f"${self.branch_target:04X}" if mode == "rel" else "",
            "abs": f"${self.operand16:04X}" if len(self.operands) > 1 else "",
            "abx": f"${self.operand16:04X},X" if len(self.operands) > 1 else "",
            "aby": f"${self.operand16:04X},Y" if len(self.operands) > 1 else "",
            "ind": f"(${self.operand16:04X})" if len(self.operands) > 1 else "",
        }[mode]
        mark = "" if info.documented else "*"
        return f"{info.mnemonic}{mark} {text}".strip()


def decode(read_byte, address: int) -> Instruction:
    """Decode the instruction at `address`.  Never fails: all 256 encodings."""
    address &= 0xFFFF
    info = OPCODES[read_byte(address) & 0xFF]
    operands = tuple(read_byte((address + 1 + i) & 0xFFFF) & 0xFF
                     for i in range(info.length - 1))
    return Instruction(address, info, operands)


def indirect_jump_pointer(address: int) -> tuple[int, int]:
    """The two addresses `JMP ($nnnn)` actually reads (NMOS page-wrap bug)."""
    address &= 0xFFFF
    low = address
    high = (address & 0xFF00) | ((address + 1) & 0x00FF)
    return low, high


def zero_page_indexed(base: int, index: int) -> int:
    """`zp,X` / `zp,Y`: the sum wraps inside page zero."""
    return (base + index) & 0xFF
