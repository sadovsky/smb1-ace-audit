# Can Super Mario Bros. (NES) do controller-only ACE?

**Short answer: I did not find one, and the ROM's structure explains why none is
known — but this is strong structural evidence, not a formal impossibility
proof.** The question is reduced to three concrete, falsifiable residual
conditions (see the end).

- ROM: `smb1.nes`, NROM / mapper 0, PRG `$8000–$FFFF`, SHA-1
  `ea343f4e445a9050d4b4fbac2c77d0693b1d0922`.
- Scope: **arbitrary code execution from controller input on the unmodified
  ROM** (the speedrun/TAS sense). This is a different question from Game Genie
  patches, which inject fixed bytes and are a different threat model.
- "ACE" here means: force the 6502 program counter into memory whose bytes the
  player controls, then have it execute a chosen payload.

---

## 1. The entire attack surface is one instruction

On NROM the program lives in **read-only** ROM. The player controls no code
bytes directly, so ACE is only possible if the program counter can be driven
**into RAM** (`$0000–$07FF`, which the game and controller state fill with
mutable values).

Recursive-descent disassembly from the three CPU vectors —

| vector | address |
|--------|---------|
| RESET  | `$8000` |
| NMI    | `$8082` |
| IRQ    | `$FFF0` (points at data; **IRQ never fires** — no mapper IRQ on NROM, APU frame IRQ disabled) |

— reaches **22,762 of 32,768 PRG bytes (69%)** as executable code, following
every `JSR`/`JMP`/branch and reading every RTS-dispatch jump table. In all of
that code there is **exactly one computed/indirect jump**:

```
8E04  JumpEngine:
8E04  0A        ASL A          ; A = index * 2
8E05  A8        TAY
8E06  68        PLA            ; pull caller return addr -> $04/$05
8E07  85 04     STA $04        ;   (= address of the table minus 1)
8E09  68        PLA
8E0A  85 05     STA $05
8E0C  C8        INY
8E0D  B1 04     LDA ($04),Y    ; $06 = ROM[table + 2*index]
8E0F  85 06     STA $06
8E11  C8        INY
8E12  B1 04     LDA ($04),Y    ; $07 = ROM[table + 2*index + 1]
8E14  85 07     STA $07
8E16  6C 06 00  JMP ($0006)    ; <-- the only computed jump in the game
```

There are **no** `JMP (ptr)` through a RAM pointer anywhere in reachable code,
and the NMOS 6502 has no indexed-indirect jump. Every dynamic branch in Super
Mario Bros. — 18 call sites — funnels through `$8E16`.

So the whole ACE question is: **can `$8E16` ever land the PC in controllable
RAM?**

---

## 2. The target always comes from a fixed ROM table

`JMP ($0006)` reads its destination from `$06/$07`, which the engine fetches
from a table in ROM (the bytes right after each `JSR $8E04`), indexed by the
value the caller passes in `A`. For every **in-range** index it reads a valid
in-ROM routine address, so the PC stays in ROM.

To reach RAM you must drive a dispatch's index **past the end of its table**,
onto whatever ROM bytes follow, and have those bytes form a `<$0800` value.

A scan of all 18 tables shows the uncomfortable part: **the ROM bytes just past
almost every table already look like RAM pointers.** The game is therefore
**not** protected by its table contents. It is protected **entirely by each
dispatch keeping its index within bounds.** Security reduces to 18 bounds
questions.

---

## 3. The 18 dispatch sites

`N` = valid entries in the table. "Index source" is the value in `A`/`Y` at the
`JSR $8E04`. "Bound" is the check that keeps it in range.

| dispatch | table | N | index source | bound | verdict |
|----------|-------|---|--------------|-------|---------|
| `$8215` | `$8218` | 4 | `$0770` OperMode | game-state counter, set only to 0–3 by code | in-range in normal play |
| `$8234` | `$8237` | 4 | `$0772` OperMode_Task | task counter stepped by code | in-range in normal play |
| `$83A3` | `$83A6` | 5 | `$0772` | task counter | in-range in normal play |
| `$856A` | `$856D` | 15 | `$073C`-family screen task | screen-routine counter | in-range in normal play |
| `$921B` | `$921E` | 3 | `$0772` | task counter | in-range in normal play |
| `$92C8` | `$92CB` | 8 | `$071F` forced to 1..8 → 0..7 | **structural** (`LDY`/`BNE`/`LDY #$08`/`DEY`) | **provably safe** |
| `$9664` | `$9667` | 47 | GameEngine area (`$0E`-driven) | game-engine state | in-range in normal play |
| `$9743` | `$9746` | 5 | `$0733` | state counter | in-range in normal play |
| `$AEDF` | `$AEE2` | 4 | `$0772` | task counter | in-range in normal play |
| `$B04C` | `$B04F` | 13 | `$0E` player/game state | state value | in-range in normal play |
| `$B34E` | `$B351` | 4 | `$1D` (`CMP #$03`) | player state, checked | in-range in normal play |
| `$BDBD` | `$BDC0` | 9 | `$05` via `$BDF6` | **`CMP #$09 / BCC`** | **bounded at dispatch** |
| `$C27F` | `$C282` | 55 | `$16,x` enemy ID | **table sized to ID space 0–`$36`** | **no legal ID out of range** |
| `$C7A8` | `$C7AB` | 8 | `$16,x − $12` | routed sub-handler (IDs `$12`–`$19`) | in-range given routing |
| `$C88F` | `$C892` | 34 | `$16,x` (`CPY #$15`, `SBC #$14`) | worst case index 34 → `$2060` (I/O crash, **not** RAM) | no RAM target |
| `$C907` | `$C90A` | 21 | `$16,x` **raw, no local bound** | upstream routing only | **the one site that can reach RAM — see §4** |
| `$C987` | `$C98A` | 7 | `$16,x − $24` | routed sub-handler (IDs `$24`–`$2A`) | in-range given routing |
| `$D2E5` | `$D2E8` | 5 | `$0746` (`CMP #$05 / BCS`) | **explicit clamp** | **bounded at dispatch** |

Three sites are bounded right at the dispatch (`$92C8`, `$BDBD`, `$D2E5`). The
enemy-ID master `$C27F` has a table sized exactly to the enemy-ID space, so no
legal ID is out of range. The rest are indexed by **mode / task / engine-state
counters** that the game only ever sets to small in-range values during normal
play — which is also *why the game never crashes* at these dispatches.

---

## 4. The one site that can reach RAM: `$C907`

`$C907` (enemy graphics) is the only dispatch whose table (21 entries) is
smaller than the index domain it is fed (raw enemy ID `$16,x`, up to `$36`) with
**no bounds check at the dispatch**:

```
C905  A5 16     LDA $16,X      ; raw enemy ID, no CMP
C907  20 04 8E  JSR $8E04      ; 21-entry table at $C90A
```

Mapping every enemy ID through this dispatch, two of them land in controllable
RAM:

| enemy ID | index | `JMP ($0006)` target | region |
|----------|-------|----------------------|--------|
| `$34` | 52 | **`$0747`** | controllable RAM |
| `$35` | 53 | **`$03D0`** | controllable RAM |

Every other out-of-range ID lands in ROM (jump to unintended code) or in
`$2000–$7FFF` I/O space (instant crash on open-bus / PPU read) — not
controllable RAM.

**Why this is not reachable in practice.** The enemy *behavior* master dispatch
`$C27F` routes those exact IDs to inert stubs:

```
ID $34 -> $C2F0:  60           RTS                         (no-op)
ID $35 -> $C307:  A9 B8        LDA #$B8
                  95 CF        STA $CF,X                    (set Y-position)
                  60           RTS
```

No master-dispatch handler points into the `$C8D7–$C905` block at all, and
`$C905` has exactly one caller (`$C8FF`), inside the enemy-graphics routine,
which is gated to low IDs. This gate is *empirically proven* by normal play:
Bowser's ID is `$2D` (> `$14`, the table limit) and he renders every time you
reach `8-4` without the game crashing. So high IDs never enter the `$C905` path.

---

## 5. Verdict

**No controller-only ACE was found**, and the architecture is the reason one has
never been found: a single jump engine (`$8E16`) reading **fixed ROM tables**,
with every index held in range by explicit checks, exact table sizing, or
state-counter invariants. This matches the known state of the art — NTSC
SMB1 any% TAS relies on the flagpole/framerule glitches, not ACE; ACE is known
in SMB2J, SMB3 and SMW, but not in NTSC SMB1.

This is **structural evidence, not a machine-checked proof.** The question is
reduced to three precise, falsifiable residual conditions. Finding ACE means
satisfying one of them; proving impossibility means ruling out all three:

1. **Out-of-range index injection.** Can any glitch push one of the 18 index
   variables (`$0770`, `$0772`, `$0733`, `$073C`, `$0746`, `$0E`, `$1D`, the
   `$BDF6` result, or enemy ID `$16,x`) outside its table under a *glitched*
   state the static bounds don't cover? No controller-only route was found, but
   the mode/task counters were not exhaustively bounded against corrupted state.

2. **Enemy ID `$34`/`$35` into the graphics path.** Can a glitch place ID
   `$34` or `$35` in a slot that reaches `$C905` while bypassing the `$C27F`
   stub routing? This is the single place the lone jump vector reaches RAM
   (`$0747` / `$03D0`).

3. **Stack corruption of the JumpEngine.** `$8E04` does `PLA/PLA` to fetch the
   *table pointer itself* from the return address. If stack depth can be
   corrupted (overflow/underflow) so that read returns a RAM pointer, the
   "table" the engine indexes could be made to point at controllable memory —
   an independent vector. Stack-depth invariants were **not** audited here.

**Coverage caveats.** Static descent reached 69% of PRG; code reached only via
computed dispatch tables is included, but anything reached by paths the descent
missed is unaudited. PPU/APU writes cannot execute code, so they are not an ACE
path (though they are how the visual Game Genie glitches work).

---

## 6. Reproducing this

Tooling lives in `../gamegenie/`:

- `rom.py` — loads the PRG, byte/pattern helpers.
- `d65.py` — minimal 6502 linear disassembler (opcode/length tables).
- `trace.py` — recursive-descent disassembly from the vectors; emits
  `trace.json` with the reached code set, indirect jumps, and the 18 dispatch
  tables.

The per-site enumeration (index → `JMP ($0006)` target → region) and the
table-bounds scan are short scripts over `trace.json` and the ROM; the numbers
in §3–§4 come directly from them.

```bash
cd ../gamegenie
python3 trace.py          # -> trace.json, lists the single JMP(ind) and 18 tables
```

The key invariant to re-derive: for each dispatch, `index <= N-1` ⇒ target is a
fixed ROM routine ⇒ PC stays in ROM. ACE requires breaking that inequality at a
site whose out-of-range bytes form a `<$0800` pointer **and** reaching it from
controller input.
