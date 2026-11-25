"""LEGACY recursive-descent disassembly of the SMB1 PRG from its entry points.

Superseded by `analysis/cfg.py`.  Kept so its output can be compared against
the corrected analysis (see `results/baseline/`), but it has three known
defects, all of which the replacement fixes:

  * `if pc in code: return` guards on occupied *bytes*, so an instruction whose
    start is an operand byte of an already-decoded one is discarded.  That
    throws away SMB1's own `$2C` filler idiom, used at $8220, $996A, $BDD4 and
    elsewhere to give a routine two entry points.
  * an opcode outside the documented 151 ends the trace as "data", but all 256
    NMOS encodings act and most undocumented ones are two or three bytes long.
  * `read_table` stops at the first word below $8000, which over-read the
    tables at $9746 (3 entries, read as 5) and $C7AB (6, read as 8).  The
    second over-read manufactured a phantom dispatch target at $A060.

Use `python3 -m analysis.cfg` for the corrected graph.
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
print("NOTE: legacy tracer; see the docstring for three known defects and "
      "use `python3 -m analysis.cfg` for the corrected graph.")
print(f"reached {len(code)} code bytes  ({len(code)*100//0x8000}% of PRG)")
print(f"JSR $8E04 dispatch tables: {len(jumptables)}")
print(f"real indirect JMPs: {len(indirect)}")
for a,k,d in indirect: print(f"  ${a:04X}  {k} {d}")
# save for next step
import json
json.dump({"instruction_bytes": sorted(code), "instruction_starts": sorted(starts),
           "ind": indirect, "jt": jumptables}, open("trace.json", "w"))
