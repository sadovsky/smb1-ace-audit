# smb1-ace-audit

A static audit of **arbitrary code execution (ACE) from controller input** in
the NES game *Super Mario Bros.* (NTSC / World, NROM / mapper 0).

**Result in one line:** no controller-only ACE vector was found, and the game's
one *direct* computed jump (`JMP ($0006)` at `$8E16`) always reads its target
from fixed ROM tables — but the stronger claim that **every** one of the 18
dispatch sites provably keeps its index in range does not hold, and this
revision withdraws it.

What the ROM actually supports, all derived rather than asserted
(`results/dispatch_bounds.json`):

| | sites |
|---|---|
| bounded at the dispatch, no assumption about RAM | **2** (`$BDBD`, `$D2E5`) |
| bounded only under an invariant that is observed or derived, not proved | **14** |
| not bounded by the invariant the earlier revision asserted | **2** (`$9664`, `$9743`) |

Also note that "exactly one computed jump" counts only direct indirect jumps:
336 `RTS` instructions and one `RTI` likewise take their destinations from
memory, and return-frame integrity is **not** established here
(`results/proof_obligations.json`, obligation D).

Classified over all 18 × 256 resolutions with nothing skipped: 505 destinations
excluded unconditionally, 1252 excluded only conditionally, 1633 not
ACE-capable, and **724 in controllable RAM that no proven bound excludes**.
None has a known input sequence, so no ACE is demonstrated — but neither is it
excluded.

Every correction, with the ROM evidence and a regression test for each, is
listed at the top of **[ACE_AUDIT.md](ACE_AUDIT.md)**. The superseded outputs
are preserved under `results/baseline/`, and the remediation plan this revision
follows is **[AUDIT_REMEDIATION.md](AUDIT_REMEDIATION.md)**.

Full writeup: **[ACE_AUDIT.md](ACE_AUDIT.md)** (and `paper/` for the PDF).

## The ROM is not included

`smb1.nes` is copyrighted and is **not** distributed here. Supply your own dump
of NTSC *Super Mario Bros.* (World), iNES format, SHA-1
`ea343f4e445a9050d4b4fbac2c77d0693b1d0922`. Point the tools at it with either:

```bash
export SMB1_ROM=/path/to/smb1.nes      # or
cp /path/to/smb1.nes ./smb1.nes        # next to the scripts
```

## Running it

```bash
# the corrected pipeline (each writes a JSON artifact under results/)
python3 -m analysis.cfg               # CFG: typed edges, overlapping decodings,
                                      # unresolved transfers
python3 -m analysis.dispatch_tables   # table boundaries from independent evidence
python3 -m analysis.index_derivation  # per-site index sets, derived not asserted
python3 -m analysis.enemy_routing     # routed enemy-ID sets (reproduces reach.py)
python3 -m analysis.destinations      # the complete 18 x 256 destination matrix
python3 -m analysis.interrupts        # vectors and interrupt masking
python3 -m tools.proof_obligations    # what is and is not established
python3 audit.py                      # per-site summary over the above
python3 classify.py --json            # exploitability with separated provenance
python3 -m unittest discover          # 128 regression tests

# legacy entry points, kept for comparison with results/baseline/
python3 trace.py          # original recursive-descent tracer -> trace.json
python3 reach.py          # original enemy-ID derivation
python3 controlflow.py    # byte classification + stack control flow
```

Ad-hoc inspection:

```bash
python3 rom.py "20 04 8e"   # find a byte pattern, with context
python3 d65.py 8E04 8E19    # disassemble a CPU address range
```

## Files

| file | what it is |
|------|-----------|
| `analysis/decoder.py` | all 256 NMOS 6502 encodings, branch/indirect/zero-page wrap semantics |
| `analysis/cfg.py` | CFG keyed on instruction *starts*, so overlapping decodings survive; typed edges; unresolved transfers recorded |
| `analysis/valueset.py` | exact 8-bit value-set domain with flag knowledge |
| `analysis/interpret.py` | instruction semantics, branch feasibility, comparison refinement |
| `analysis/index_derivation.py` | derives each dispatch's index set from backward slices, intersected across depths |
| `analysis/dispatch_tables.py` | table boundaries from independent evidence, not one heuristic |
| `analysis/enemy_routing.py` | routed enemy-ID sets, derived independently of `reach.py` |
| `analysis/destinations.py` | the complete destination matrix, including unexpected-ROM roles |
| `analysis/write_census.py` | conservative writer manifest per RAM address |
| `analysis/effective_address.py` | effective-address sets per addressing mode |
| `analysis/interrupts.py` | vector targets and whether an IRQ can ever be serviced |
| `analysis/provenance.py` | bound provenance / reachability / execution outcome, kept separate |
| `tools/proof_obligations.py` | assembles `results/proof_obligations.json` from the live analysis |
| `rom.py` | ROM loader + byte/pattern helpers (resolves `$SMB1_ROM` / `./smb1.nes`) |
| `d65.py` | minimal 6502 linear disassembler (opcode + length tables) |
| `trace.py` | *legacy* recursive-descent disassembler; discards overlapping decodings and stops at undocumented opcodes (see the corrections list) |
| `controlflow.py` | byte classification (starts/operands/data) and stack-based control flow: RTS-trick, `TXS`, `RTI` |
| `classify.py` | exploitability classification with provenance separated from verdict; `--json` writes the full record set |
| `reach.py` | **derives** the enemy-ID -> dispatch bounds from the routing tables instead of assuming them |
| `audit.py` | per-site summary: derived bounds, established boundaries, both kinds of computed transfer |
| `trace_jsonl.py` | writes native CPU instruction events as reproducible JSONL records |
| `test_audit.py` | regression tests: ROM validation, 6502/JumpEngine semantics, memory mirroring, derived bounds |
| `native_dispatch.py` | instruction-level dispatch census + derailment detector (needs the tracer-patched `nes-py`) |
| `stack_depth.py` | measures the stack-pointer band (condition C3) using the native tracer |
| `search_oob.py` | evolutionary controller-only search for an out-of-bounds dispatch index |
| `fuzz.py` | emulator search: controller-input fuzz watching the index variables and enemy-ID slots (needs the patched `nes-py`) |
| `inject.py` | focused probe: inject out-of-range enemy IDs into a live slot and watch for derailment (needs the patched `nes-py`) |
| `ACE_AUDIT.md` | the writeup (incl. the emulator-search results, section 6) |
| `paper/` | academic-paper-style PDF of the writeup |

`fuzz.py` and `inject.py` need a Game-Genie-patched `nes-py` exposing
`CheatNESEnv` / `TraceNESEnv` (point at it with `$CHEAT_ENV_DIR`); the static analysis
(`trace.py`, `audit.py`) needs only the ROM.

The companion patch now exposes optional native instruction tracing. Set
`SMB1_TRACE_DISPATCH=1` when running `fuzz.py` to capture only JumpEngine entry
and indirect-jump events, keeping controller-only and assisted records separate.

## Method, briefly

On NROM the code is in read-only ROM, so the player controls no code bytes.
ACE therefore requires driving the program counter **into RAM** (`$0000–$07FF`
and its mirrors). The instructions that can move the PC to a data-derived
address are the JumpEngine's `JMP ($0006)` and every `RTS`/`RTI`. For the
JumpEngine the destination comes from a fixed ROM table indexed by the caller,
so for any in-range index the PC stays in ROM, and the audit reduces to: **is
every dispatch's index in range, and on what evidence?**

That second clause is the substance of this revision. Bounds are now *derived*
from the ROM by value-set analysis over the CFG rather than written down by
hand, because hand-reading produced wrong bounds at three sites and a wrong
mechanism at a fourth. Table sizes are established from independent evidence
rather than one heuristic, because the heuristic over-read two tables — and one
of those over-reads was what made a site look safe.

## License

Code and writeup are released under the MIT License (`LICENSE`). This project
contains only original analysis and tooling; it includes no Nintendo code or
assets.
