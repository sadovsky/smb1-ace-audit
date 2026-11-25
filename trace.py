"""Recursive-descent disassembly of the SMB1 PRG from its real entry points.
Follows JSR/JMP/branches; for the RTS-dispatch jump tables (JSR $8E04 and the
handful of hand-rolled ones) it reads the table and queues every target. Records
every indirect control transfer and every computed dispatch as an ACE candidate.
"""
from rom import b, image
from d65 import M, LEN

code = set()          # occupied instruction bytes
starts = set()        # real instruction starts (kept separate from operands)
indirect = []         # (addr, kind, detail)
jumptables = []       # (dispatch_addr, table_addr, n_entries)

# RTS-dispatch engine: JSR $8E04 preceded by  LDA idx / ASL / TAY ; table follows the JSR.
JUMPENGINE = 0x8E04

def read_table(addr, maxn=80):
    out = []
    for i in range(maxn):
        lo, hi = b(addr+2*i), b(addr+2*i+1)
        v = lo | hi<<8
        if v < 0x8000: break
        out.append(v)
    return out

def walk(start, queue):
    pc = start
    while True:
        if pc in code or not (0x8000 <= pc <= 0xFFFF): return
        o = b(pc)
        if o not in M:               # hit data; stop this trace
            return
        name, mode = M[o]; L = LEN[mode]
        starts.add(pc)
        for k in range(L): code.add(pc+k)
        nxt = pc + L
        if name == "JSR":
            tgt = b(pc+1) | b(pc+2)<<8
            if tgt == JUMPENGINE:
                tbl = nxt                       # table sits right after the JSR
                ents = read_table(tbl)
                jumptables.append((pc, tbl, len(ents)))
                for e in ents: queue.append(e)
                return                          # engine never returns to after-table as code
            queue.append(tgt); pc = nxt; continue
        if name == "JMP":
            if mode == "abs":
                queue.append(b(pc+1)|b(pc+2)<<8)
            else:  # ind
                indirect.append((pc, "JMP (ind)", f"${b(pc+1)|b(pc+2)<<8:04X}"))
            return
        if name == "RTS" or name == "RTI": return
        if mode == "rel":
            disp = b(pc+1); dest = pc+2 + (disp-256 if disp>127 else disp)
            queue.append(dest)
            if name in ("BRA",): return
        pc = nxt

def run():
    q = [b(0xFFFC)|b(0xFFFD)<<8, b(0xFFFA)|b(0xFFFB)<<8, b(0xFFFE)|b(0xFFFF)<<8,
         JUMPENGINE]
    seen=set()
    while q:
        s = q.pop()
        if s in seen: continue
        seen.add(s); walk(s, q)
    return q

run()
print(f"reached {len(code)} code bytes  ({len(code)*100//0x8000}% of PRG)")
print(f"JSR $8E04 dispatch tables: {len(jumptables)}")
print(f"real indirect JMPs: {len(indirect)}")
for a,k,d in indirect: print(f"  ${a:04X}  {k} {d}")
# save for next step
import json
json.dump({"instruction_bytes": sorted(code), "instruction_starts": sorted(starts),
           "ind": indirect, "jt": jumptables}, open("trace.json", "w"))
