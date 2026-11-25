# smb1-ace-audit

A static audit of **arbitrary code execution (ACE) from controller input** in
the NES game *Super Mario Bros.* (NTSC / World, NROM / mapper 0).

**Result in one line:** the whole game has exactly **one** computed jump
(`JMP ($0006)` at `$8E16`), it always reads its target from fixed ROM tables,
and every one of the 18 dispatch sites keeps its index in range — so no
controller-only ACE vector was found. This is strong structural evidence, not a
formal impossibility proof; the residual questions are stated precisely in the
writeup.

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
python3 trace.py     # recursive-descent disassembly from the reset/NMI/IRQ
                     # vectors -> trace.json (reached code, the sole indirect
                     # jump, the 18 JSR $8E04 dispatch tables)
python3 audit.py     # per-site index/bound/target analysis (ACE_AUDIT.md 3-4)
```

Ad-hoc inspection:

```bash
python3 rom.py "20 04 8e"   # find a byte pattern, with context
python3 d65.py 8E04 8E19    # disassemble a CPU address range
```

## Files

| file | what it is |
|------|-----------|
| `rom.py` | ROM loader + byte/pattern helpers (resolves `$SMB1_ROM` / `./smb1.nes`) |
| `d65.py` | minimal 6502 linear disassembler (opcode + length tables) |
| `trace.py` | recursive-descent disassembler from the CPU vectors; writes `trace.json` |
| `audit.py` | the ACE analysis over `trace.json`: index source, bound, and `JMP ($0006)` target per dispatch |
| `fuzz.py` | emulator search: controller-input fuzz watching the index variables and enemy-ID slots (needs the patched `nes-py`) |
| `inject.py` | focused probe: inject out-of-range enemy IDs into a live slot and watch for derailment (needs the patched `nes-py`) |
| `ACE_AUDIT.md` | the writeup (incl. the emulator-search results, section 6) |
| `paper/` | academic-paper-style PDF of the writeup |

`fuzz.py` and `inject.py` need a Game-Genie-patched `nes-py` exposing
`CheatNESEnv` (point at it with `$CHEAT_ENV_DIR`); the static analysis
(`trace.py`, `audit.py`) needs only the ROM.

## Method, briefly

On NROM the code is in read-only ROM, so the player controls no code bytes.
ACE therefore requires driving the program counter **into RAM** (`$0000–$07FF`).
The only instruction that can move the PC to a data-derived address is the
JumpEngine's `JMP ($0006)`. Its destination comes from a fixed ROM table indexed
by the caller; for any in-range index the PC stays in ROM. So the audit reduces
to: **is every dispatch's index provably in range?** `trace.py` finds the sites;
`audit.py` checks the bounds and computes, for each, whether any out-of-range
index would land in controllable RAM.

## License

Code and writeup are released under the MIT License (`LICENSE`). This project
contains only original analysis and tooling; it includes no Nintendo code or
assets.
