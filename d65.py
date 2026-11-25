"""Minimal 6502 linear disassembler.  usage: dis.py START [END]  (hex CPU addrs)"""
import sys
from rom import b
M = {}
def op(code, name, mode): M[code] = (name, mode)
T = """00 BRK imp|01 ORA izx|05 ORA zp|06 ASL zp|08 PHP imp|09 ORA imm|0a ASL acc|0d ORA abs|0e ASL abs|10 BPL rel|11 ORA izy|15 ORA zpx|16 ASL zpx|18 CLC imp|19 ORA aby|1d ORA abx|1e ASL abx|20 JSR abs|21 AND izx|24 BIT zp|25 AND zp|26 ROL zp|28 PLP imp|29 AND imm|2a ROL acc|2c BIT abs|2d AND abs|2e ROL abs|30 BMI rel|31 AND izy|35 AND zpx|36 ROL zpx|38 SEC imp|39 AND aby|3d AND abx|3e ROL abx|40 RTI imp|41 EOR izx|45 EOR zp|46 LSR zp|48 PHA imp|49 EOR imm|4a LSR acc|4c JMP abs|4d EOR abs|4e LSR abs|50 BVC rel|51 EOR izy|55 EOR zpx|56 LSR zpx|58 CLI imp|59 EOR aby|5d EOR abx|5e LSR abx|60 RTS imp|61 ADC izx|65 ADC zp|66 ROR zp|68 PLA imp|69 ADC imm|6a ROR acc|6c JMP ind|6d ADC abs|6e ROR abs|70 BVS rel|71 ADC izy|75 ADC zpx|76 ROR zpx|78 SEI imp|79 ADC aby|7d ADC abx|7e ROR abx|81 STA izx|84 STY zp|85 STA zp|86 STX zp|88 DEY imp|8a TXA imp|8c STY abs|8d STA abs|8e STX abs|90 BCC rel|91 STA izy|94 STY zpx|95 STA zpx|96 STX zpy|98 TYA imp|99 STA aby|9a TXS imp|9d STA abx|a0 LDY imm|a1 LDA izx|a2 LDX imm|a4 LDY zp|a5 LDA zp|a6 LDX zp|a8 TAY imp|a9 LDA imm|aa TAX imp|ac LDY abs|ad LDA abs|ae LDX abs|b0 BCS rel|b1 LDA izy|b4 LDY zpx|b5 LDA zpx|b6 LDX zpy|b8 CLV imp|b9 LDA aby|ba TSX imp|bc LDY abx|bd LDA abx|be LDX aby|c0 CPY imm|c1 CMP izx|c4 CPY zp|c5 CMP zp|c6 DEC zp|c8 INY imp|c9 CMP imm|ca DEX imp|cc CPY abs|cd CMP abs|ce DEC abs|d0 BNE rel|d1 CMP izy|d5 CMP zpx|d6 DEC zpx|d8 CLD imp|d9 CMP aby|dd CMP abx|de DEC abx|e0 CPX imm|e1 SBC izx|e4 CPX zp|e5 SBC zp|e6 INC zp|e8 INX imp|e9 SBC imm|ea NOP imp|ec CPX abs|ed SBC abs|ee INC abs|f0 BEQ rel|f1 SBC izy|f5 SBC zpx|f6 INC zpx|f8 SED imp|f9 SBC aby|fd SBC abx|fe INC abx"""
for e in T.split("|"):
    c, n, m = e.split(); op(int(c, 16), n, m)
LEN = dict(imp=1, acc=1, imm=2, zp=2, zpx=2, zpy=2, izx=2, izy=2, rel=2, abs=3, abx=3, aby=3, ind=3)
def dis(pc, end):
    while pc < end:
        o = b(pc)
        if o not in M:
            print(f"{pc:04X}  {o:02x}        .db ${o:02x}"); pc += 1; continue
        n, m = M[o]; L = LEN[m]
        raw = " ".join(f"{b(pc+i):02x}" for i in range(L))
        a8 = b(pc+1) if L > 1 else 0
        a16 = a8 | (b(pc+2) << 8) if L == 3 else 0
        arg = {"imp": "", "acc": "A", "imm": f"#${a8:02X}", "zp": f"${a8:02X}", "zpx": f"${a8:02X},X",
               "zpy": f"${a8:02X},Y", "izx": f"(${a8:02X},X)", "izy": f"(${a8:02X}),Y",
               "rel": f"${pc+2+(a8-256 if a8>127 else a8):04X}", "abs": f"${a16:04X}",
               "abx": f"${a16:04X},X", "aby": f"${a16:04X},Y", "ind": f"(${a16:04X})"}[m]
        print(f"{pc:04X}  {raw:<9} {n} {arg}"); pc += L
if __name__ == "__main__":
    s = int(sys.argv[1], 16); e = int(sys.argv[2], 16) if len(sys.argv) > 2 else s + 0x40
    dis(s, e)
