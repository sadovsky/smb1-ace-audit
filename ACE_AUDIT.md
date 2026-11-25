# Can Super Mario Bros. (NES) do controller-only ACE?

**Short answer: no controller-only ACE has been demonstrated here. The ROM's
indirect control flow is highly constrained, but this revision withdraws the
claim that every dispatch index is provably in range.** Of the eighteen
dispatch sites, **two** are bounded by instructions at the dispatch with no
assumption about RAM; **thirteen** are bounded only under an invariant that is
observed or derived rather than proved; and **three** do not keep the index
inside the table even under the invariant asserted for them (`$9664` and
`$9743`, both new, plus `$C88F`, whose single escaping index was already
published).

Current interim conclusion:

> Static analysis of this ROM identifies a highly constrained indirect
> control-flow architecture centred on the JumpEngine at `$8E04`. No
> controller-only arbitrary code execution has been demonstrated in the
> experiments reported here. Some dispatch invariants can be established
> locally or conditionally; others remain empirical. A definitive negative
> result requires establishing control-flow completeness, state invariants,
> return-address integrity, and the relevant hardware execution semantics
> across all states the controller-input model permits.

`results/proof_obligations.json` tracks what remains; all six obligations are
open or only partially established, so impossibility is not claimed.

## Corrections in this revision

Each item below was asserted by an earlier revision of this document and is
contradicted by the ROM. Every correction is machine-checked by a regression
test, and the superseded outputs are preserved in `results/baseline/`.

| claim as published | what the ROM shows | artifact |
|---|---|---|
| `$92C8`: `$071F` "forced to 1..8 → 0..7", **structural, provably safe** | `LDY $071F / BNE / LDY #$08 / STY $071F / DEY / TYA` substitutes 8 for zero and never clamps. The index is `((v or 8) - 1) & 0xFF`, derived as `{0..254}`; `$071F = 9` gives index 8 → `$26EE`. In range only while `RAM[$071F] <= 8`. | `analysis/dispatch_index.py` |
| `$B34E`: `$1D` "player state, **checked**" by `CMP #$03` | `BEQ $B34E` only decides whether `STY $0789` runs. Both paths dispatch with `A = $1D` unchanged; derived index set is all 256 values over a 4-entry table. | `results/dispatch_bounds.json` |
| `$BDBD`: bounded by `CMP #$09 / BCC` | Genuinely bounded (0..8 over 9 entries), but by `$BDF6` returning `Y <= 13`. The cited comparison alone does not bound it: the other path runs `SBC #$05`. Right conclusion, wrong mechanism. | `analysis/index_derivation.py` |
| `$9664`: indexed by "GameEngine (`$0E`)", bound 46 | The index is formed at `$965F-$9662` as `LDA $00 / CLC / ADC $07`. `$0E` is not the index source. Bounding it needs a relational invariant over two scratch bytes with dozens of writers, over the game's largest table (47 entries). Recorded **unproved**. | `results/dispatch_bounds.json` |
| `$9743`: table has 5 entries, bound `$0733 <= 4` | The table at `$9746` has **3** entries: its entry 0 points at `$974C`, which holds `JSR $9BBB`. The heuristic read that instruction's bytes as entries 3 and 4. Under the *asserted* bound of 4, indices 3 and 4 dispatch outside the table, to `$BB20` and `$BD9B`. | `data/dispatch_tables.json` |
| `$C7A8`: table has 8 entries | 6 entries. Entry 1 points at `$C7B7`, which holds `RTS`. The over-read also manufactured a phantom dispatch target at `$A060`, from which the old tracer decoded data as `JAM`. Routed indices 0..5 exactly saturate the real table. | `data/dispatch_tables.json` |
| "**exactly one** computed/indirect jump in the whole game" | One *direct* indirect jump (`JMP ($0006)` at `$8E16`), plus **336 `RTS` and one `RTI`**, each of which takes its destination from memory. The claim counted only the first kind. | `results/cfg.json` |
| "every RTS in reached code returns to a JSR frame", from a 24-instruction scan in address order | The **conclusion holds**, but that scan could not establish it: it does not follow execution paths. A per-routine abstract stack analysis with a fixpoint over callee summaries now verifies all 627 reachable `RTS` sites against their routine's entry frame. The one unverified return is the NMI's `RTI`, which the per-routine method does not model. | `results/stack_analysis.json` |
| "2181 of 2182 non-ROM destinations are **excluded**, 0 unknown" | Every PRG-ROM destination was skipped before classifying, and an *observed* bound was allowed to exclude an index outright. Over all 18 × 256 resolutions: 505 excluded unconditionally, 1252 excluded only conditionally, 1633 not ACE-capable, **724 in controllable RAM and not excluded**. | `exploitability_classification.json` |
| ROM destinations are safe because they are ROM | 1932 resolutions are unexpected-ROM destinations; **390 land on an operand byte** of another instruction and 874 on bytes the CFG never reaches. Landing mid-instruction is not a safe outcome. | `results/destination_matrix.json` |
| I/O destinations are an "instant crash" | An instruction fetch from a register region is a bus transaction, not a defined crash. `$2060` is classified `io_dependent` pending hardware verification. | `memory.py`, `analysis/destinations.py` |
| Undocumented opcodes stop a trace ("hit data") | All 256 NMOS encodings do something; 105 are undocumented and most are two or three bytes, so stopping mis-aligns the stream. Six families write memory and twelve encodings jam the CPU. | `analysis/decoder.py` |
| IRQs dismissed because "NROM has no mapper IRQ" | The 2A03 has its own two IRQ sources, and SMB1's IRQ vector points at `$FFF0`, which is **table data**. The real reason no IRQ fires is stronger: `SEI` at reset and **no reachable `CLI` or `PLP`**, so `RTI` can only restore a status byte that already had I set. | `results/interrupts.json` |

Two further method errors, with no single headline claim attached:

- The recursive tracer guarded its walk with `if pc in code: return`, where
  `code` held every *byte* already decoded. That discards an instruction whose
  start is an operand byte of another — which is exactly SMB1's own `$2C`
  filler idiom, used at `$8220`, `$996A`, `$BDD4`, `$BFB6`, `$DC20`, `$E3EB`
  and `$F349` to give a routine two entry points. Ten such decodings were
  being thrown away.
- Branch feasibility was never considered, so the tracer followed the
  fallthrough of always-taken branches (`LDA #$0B / BNE` cannot fall through)
  into data and decoded it as instructions.

The question is reduced to concrete, falsifiable residual conditions (see the
end).

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
that code there is exactly one *direct* indirect jump — but note that 336 `RTS`
instructions and one `RTI` also take their destinations from memory, and the
original claim counted only the first kind:

```
8E04  JumpEngine:
8E04  0A        ASL A          ; 8-bit shift; bit 7 is discarded
8E05  A8        TAY
8E06  68        PLA            ; pull caller return addr -> $04/$05
8E07  85 04     STA $04        ;   (= address of the table minus 1)
8E09  68        PLA
8E0A  85 05     STA $05
8E0C  C8        INY
8E0D  B1 04     LDA ($04),Y    ; $06 = CPU[($04/$05) + wrapped Y]
8E0F  85 06     STA $06
8E11  C8        INY
8E12  B1 04     LDA ($04),Y    ; $07 = CPU[($04/$05) + wrapped Y]
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

The audit models these instructions directly for all 256 accumulator values.
This matters: `ASL A` aliases `$80–$FF` to `$00–$7F`, and at index `$7F` the
second `INY` wraps `$FF → $00`, making the high byte come from the caller's
return-address base rather than the next linear byte. The historical shortcut
`table + 2*index` is valid only for indices `$00–$7E`; it is not used for the
current results.

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
| `$92C8` | `$92CB` | 8 | `$071F`, zero substituted by 8, **not clamped** | conditional on `RAM[$071F] <= 8` | derived `{0..254}`; in range only under that invariant |
| `$9664` | `$9667` | 47 | **`$00 + $07`** formed at `$965F-$9662`, not `$0E` | needs a relational invariant | **unproved** |
| `$9743` | `$9746` | **3** (not 5) | `$0733` | asserted bound 4 exceeds the real table | **indices 3-4 dispatch outside the table** → `$BB20`, `$BD9B` |
| `$AEDF` | `$AEE2` | 4 | `$0772` | task counter | in-range in normal play |
| `$B04C` | `$B04F` | 13 | `$0E` player/game state | state value | in-range in normal play |
| `$B34E` | `$B351` | 4 | `$1D` raw; the `CMP #$03` does **not** clamp | conditional on `RAM[$1D] <= 3` (observed) | derived 0..255 unconditionally |
| `$BDBD` | `$BDC0` | 9 | `$05` via `$BDF6` | **`$BDF6` returns `Y <= 13`** (not the `CMP` alone) | **bounded, no RAM assumption** |
| `$C27F` | `$C282` | 55 | `$16,x` enemy ID | **table sized to ID space 0–`$36`** | **no legal ID out of range** |
| `$C7A8` | `$C7AB` | **6** (not 8) | `$16,x − $12` | routed sub-handler (IDs `$12`–`$19`) | routed indices 0-5 exactly saturate the table |
| `$C88F` | `$C892` | 34 | `$16,x` (`CPY #$15`, `SBC #$14`) | index 34 → `$2060`, a PPU register mirror (**hardware dependent**, not a defined crash) | out of range by one index; no RAM target |
| `$C907` | `$C90A` | 21 | `$16,x` **raw, no local bound** | routed IDs only (derived, assumes preservation) | routed indices 0-20 in range; see §4 |
| `$C987` | `$C98A` | 7 | `$16,x − $24` | routed sub-handler (IDs `$24`–`$2A`) | in-range given routing |
| `$D2E5` | `$D2E8` | 5 | `$0746` (`CMP #$05 / BCS`) | **explicit clamp** | **bounded at dispatch** |

**Two** sites are bounded right at the dispatch with no assumption about RAM:
`$BDBD` (via `$BDF6` returning `Y <= 13`) and `$D2E5` (`CMP #$05 / BCS`, a real
clamp). `$92C8` was previously counted here and does not belong: its `BNE` only
substitutes for zero. The enemy-ID master `$C27F` has a table sized exactly to
the identifier space, conditional on that space being `$00..$36`, which is
itself a table-boundary claim. The rest are indexed by **mode / task /
engine-state counters** that the game is only *observed* to set to small
in-range values — which is why the game does not crash in practice, but is not
the same as a bound.

---

## 4. The one site that can reach RAM: `$C907`

`$C907` (enemy graphics) is the only dispatch whose table (21 entries) is
smaller than the index domain it is fed (raw enemy ID `$16,x`, up to `$36`) with
**no bounds check at the dispatch**:

```
C905  B5 16     LDA $16,X      ; raw enemy ID, no CMP
C907  20 04 8E  JSR $8E04      ; 21-entry table at $C90A
```

Mapping every enemy ID through this dispatch, two of them land in controllable
RAM:

| enemy ID | index | `JMP ($0006)` target | region |
|----------|-------|----------------------|--------|
| `$34` | 52 | **`$0747`** | controllable RAM |
| `$35` | 53 | **`$03D0`** | controllable RAM |

Every other out-of-range ID lands in ROM (an unintended entry, which may be
an operand byte rather than an instruction start — see
`results/destination_matrix.json`) or in the `$2000–$7FFF` register and
unmapped space. A fetch from that space is a bus transaction whose result
depends on the hardware; it is classified `io_dependent` or
`open_bus_dependent`, not as a defined crash.

The exact 6502 model also reproduces the previously reported *static* candidate
`$3C → $16B5`. `$16B5` is an internal-RAM mirror and normalizes to physical RAM
`$06B5`. It is outside the legal `$00–$36` enemy-ID range. At the upstream
`$C27F` master dispatch, a hypothetical `$3C` instead resolves to `$95B6`; it
does not reach `$C905`. This is a static control-flow observation, not a
controller-only demonstration.

**Why this is not reachable in practice.** The enemy *behavior* master dispatch
`$C27F` routes those exact IDs to inert stubs:

```
ID $34 -> $C2F0:  60           RTS                         (no-op)
ID $35 -> $C307:  A9 B8        LDA #$B8
                  95 CF        STA $CF,X                    (set Y-position)
                  60           RTS
```

No master-dispatch handler points into the `$C8D7–$C905` block at all, and
`$C905` has exactly one caller (`$C8FF`), inside the enemy-graphics routine.

**The gate itself, derived rather than inferred.** An earlier version argued the
gate must exist because Bowser (ID `$2D`, far past the 21-entry table) renders
without crashing. That is evidence, not a proof. The gate is in fact readable
straight out of the collision dispatch:

```
$C882  LDX $08 / LDA #$00 / LDY $16,X
$C888  CPY #$15
$C88A  BCC $C88F        ; ID <  $15 -> dispatch with index 0
$C88C  TYA / SBC #$14   ; ID >= $15 -> index = ID - $14
$C88F  JSR $8E04        ; 34-entry collision table

   collision entry 0        -> $C8E0 -> ... -> $C8FF JSR $C905 -> $C907
   collision entries 16..22 -> $C965 -> ... -> $C976 JSR $C982 -> $C987
```

The only route into the `$C8E0` block is **collision-table entry 0**, which
`CPY #$15 / BCC` selects *only for identifiers below `$15`*. So `$C907` receives
identifiers `$00`–`$14`, giving indices 0–20 — exactly its 21 entries. The table
is not under-sized; it is sized precisely to the identifier set that can arrive,
and `$34`, `$35` and `$3C` are all `>= $15`.

`reach.py` derives this mechanically for every enemy dispatch, using the exact
JumpEngine model and the mirroring-aware classifier:

| dispatch | N | identifiers that arrive | index range | verdict |
|---|---|---|---|---|
| `$C27F` behavior | 55 | `$00`–`$36` | 0–54 | exact fit |
| `$C88F` collision | 34 | all (0 if `< $15`, else ID−`$14`) | 0–34 | **ID `$36` → idx 34, out of bounds** |
| `$C907` graphics | 21 | `$00`–`$14` | 0–20 | exact fit |
| `$C987` sub | 7 | `$24`–`$2A` | 0–6 | exact fit |
| `$C7A8` sub | 8 | `$12`,`$14`–`$17` | 0–5 | within bounds |

Two results follow. First, **every in-bounds index at all 18 dispatches resolves
to PRG ROM** (asserted by `test_every_in_bounds_target_stays_in_rom`). Second,
exactly one legal identifier indexes past its table anywhere in the game:
**ID `$36` at `$C88F`**, index 34 against 34 entries, resolving to `$2060` —
PPU register space. That can hang the machine but cannot execute controllable
bytes, so it is **not** an ACE vector.

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

## 6. Empirical validation (emulator search)

Two experiments on the real game (patched `nes-py`) complement the static audit.
See `fuzz.py` and `inject.py`.

**Input fuzz &mdash; condition C1, controller-only.** 48 episodes x 3000 frames
(144k frames) of structured plus fully random controller input, two thirds on
`1-1` and one third across varied start areas for dispatch coverage. Each frame
reads the eight state-counter index variables and the five enemy-ID slots.
Result: **OperMode never left `{0,1,2,3}` (zero derailments)**; every index
variable stayed within the table it indexes at the relevant site; and **enemy
IDs `$34`/`$35` never appeared in any slot.** Two raw variables briefly exceed
the *tightest* table they ever index, both already explained statically: `$071F`
reaches 8 but the engine's `DEY` makes the real index 7 (the "structural"
`$92C8` case), and `$0772` reaches 3 only while indexing its larger 4/5-entry
tables, not the 3-entry one at `$921B`.

**ID injection &mdash; condition C2 downstream.** Overwriting a live enemy
slot's ID every frame (the realistic shape of a glitch depositing a byte) shows
that **every in-range identifier `$00`&ndash;`$36`, including the two dangerous
values `$34`/`$35`, is absorbed without derailment**: the behavior master
`$C27F` routes them to the `RTS` stubs and the graphics gate keeps them out of
`$C905`. Only identifiers **beyond the legal maximum** (`$3F`, `$7F`) derail the
CPU immediately (around frame 5), by overrunning the 55-entry master table
itself.

This confirms both halves of the static picture: the game is safe precisely
because (a) enemy IDs never exceed `$36`, and (b) within that range the routing
keeps `$34`/`$35` away from `$C905`. The search found **no controller-only route
to an out-of-range index**. (Caveat: `nes-py`'s CPU core aborts on undocumented
opcodes, so "derail" here means the PC left normal code; on real hardware those
opcodes execute as NOPs and the run would continue into whatever follows.)

---

### 6b. Instruction-level validation (native tracer)

The fuzz above samples RAM once per frame, which cannot see transient state.
That gap is now closed: the emulator carries an optional instruction tracer
(`rommage/nes-py-fork/nes-py-tracer.patch`), and `native_dispatch.py` uses it to
observe **every** instruction rather than a per-frame snapshot.

Two filters are armed. The first watches `$8E04`, where the accumulator still
holds the dispatch index, giving a census of every index the game actually
takes. The second is the **derailment detector**: it records any instruction
executed below `$8000`. On NROM all code is in ROM, so an instruction running
outside `$8000-$FFFF` means the program counter has entered RAM or I/O — the
precondition for ACE, observed directly instead of inferred.

Six controller-only episodes of 4000 frames:

| measure | value |
|---|---|
| dispatch invocations | 67,675 |
| distinct indices taken | 17 |
| **max index observed** | **23** (largest table has 55 entries) |
| events dropped | 0 |
| **instructions executed outside PRG ROM** | **0** |

The program counter never left PRG ROM, and no dispatch index came close to
overrunning its table. This is a stronger statement than the frame-granular
result: it is a per-instruction observation, not a sample.

It remains a *search*, not a proof — it covers the states these inputs reached.

---

## 6c. Stack and alternate control flow (review items 4.4, 4.5)

The claim "exactly one computed jump" is only as good as the search behind it.
A 6502 program can transfer control without a `JMP`, so `controlflow.py`
enumerates the alternatives.

**The RTS trick.** The classic 6502 dispatch pushes a computed address and
`RTS`es into it. If SMB1 did that anywhere, it would be a computed transfer the
audit never counted. Scanning every reached instruction stream for
`PHA` … `PHA` … `RTS` with no intervening `JSR`: **none exists.** Every `RTS`
in reached code returns to a genuine `JSR` frame.

**Direct stack-pointer writes.** `TXS` appears exactly once, at `$8009` in
reset initialisation. Gameplay therefore cannot reposition the stack; it moves
only through `JSR`/`RTS`, `PHA`/`PLA`, `PHP`/`PLP` and the NMI's push/`RTI`.

**`RTI`.** One site, `$8181`, ending the NMI handler. IRQ is never taken on
NROM.

**Byte classification.** `trace.py` now separates instruction starts (10,693)
from operand bytes (12,090) and dispatch-table data (502), leaving 9,985 bytes
(30% of PRG) unreached. Sweeping the unreached remainder finds 15 byte
positions that would decode as `JMP (indirect)`. They are byte coincidences in
data: no traced path decodes them as instruction starts, and the only way to
begin executing at a misaligned address is a computed transfer, which is the
bounds-checked engine. They are listed rather than dismissed.

### Stack depth, measured

Condition C3 asks whether the stack can be driven far enough that the engine's
`PLA/PLA` pulls something other than a return address. `stack_depth.py` samples
the `sp` field the tracer records, over four controller-only episodes of 3000
frames:

| measure | value |
|---|---|
| SP range observed | **`$EF`–`$FC`** |
| deepest use | 16 bytes of the 256-byte stack page |
| headroom before wrap | 239 bytes |

Overflow needs roughly 128 nested frames. Combined with the single reset-only
`TXS` and the absence of any RTS trick, C3 is now tightly bounded — though
still by measurement over reached states, not by proof.

---

## 6d. Exploitability classification (review item 8)

`classify.py` emits one record per (dispatch site, index) pair whose
destination is not PRG ROM, with the review's fields plus an explicit
**provenance** label on the bound that excludes it. Provenance is the point: a
bound derived from the ROM is a different claim from one inferred from play.

| provenance | meaning | sites |
|---|---|---|
| `proven` | enforced at the dispatch, no RAM assumption | **2** |
| `structural_conditional` | instructions constrain it, given an upstream invariant | 1 |
| `derived_conditional` | computed from the routing tables, given preservation | 4 |
| `observed` | consistent with every state reached, not proved | 9 |
| `unproved` | no bound keeping the index in range | **2** |

Only `proven` excludes an index unconditionally; `analysis/provenance.py`
enforces that, and a conditional bound cannot be constructed without listing
its assumptions.

Of 4114 non-expected destinations across all 256 indices at all 18 sites (the
earlier count of 2182 omitted every PRG-ROM destination):

- **505 are excluded unconditionally** — the index lies outside the set derived
  while assuming nothing about RAM.
- **1252 are excluded only conditionally**, each carrying its assumptions.
- **1633 are `not_ace`** — reachable index, destination holds no
  player-influenced bytes.
- **724 are `unknown`**: destinations in controllable RAM that no proven bound
  excludes. None is `demonstrated`; no input sequence is known for any of them.

The earlier "2181 excluded, 0 unknown" result came from skipping ROM
destinations and from letting an observed bound exclude an index outright.

The nine `observed` sites are condition C1 and are the honest soft spot.

---

## 6e. Targeted search for an out-of-bounds index (review item 7)

`search_oob.py` attacks those nine sites directly. Watching each dispatch
address makes the quantity measurable: the instruction there is `JSR $8E04`,
so the accumulator at that moment *is* the index. The search is evolutionary
over controller-input programs, scored by how far past a table's last valid
index it can push, then by coverage of distinct (site, index) pairs.

Result over 10 generations: **47–49 distinct (site, index) pairs, best margin
`+0`** — several sites reach their *last valid* index (`$856A` 14 of 15,
`$92C8` 7 of 8, `$8234` 3 of 4) and **none exceeds it**. Zero instructions
executed outside PRG ROM along the way.

Counters saturating exactly at the table limit is what one expects if the
tables were sized to the state space, which is the same pattern the derived
enemy bounds show.

---

## 7. Reproducing this

Tooling lives in `../gamegenie/`:

- `rom.py` — loads the PRG, byte/pattern helpers.
- `d65.py` — minimal 6502 linear disassembler (opcode/length tables).
- `trace.py` — recursive-descent disassembly from the vectors; emits
  `trace.json` with the reached code set, indirect jumps, and the 18 dispatch
  tables.

The loader now verifies the complete iNES layout before analysis: magic,
mapper 0, 32 KiB PRG, 8 KiB CHR, interrupt vectors, and the expected complete
file SHA-1. Alternate builds require an explicit programmatic override. The
memory classifier recognizes NES internal-RAM mirrors (`$0800–$1FFF`), so
`$16B5` is reported as mirrored internal RAM rather than an unrelated region.

The per-site enumeration (index → `JMP ($0006)` target → region) and the
table-bounds scan are short scripts over `trace.json` and the ROM; the numbers
in §3–§4 come directly from them. Run `python3 -m unittest -v` for the loader,
memory-map, and 6502 wrapping regressions.

```bash
cd ../gamegenie
python3 trace.py          # -> trace.json, lists the single JMP(ind) and 18 tables
```

The key invariant to re-derive: for each dispatch, `index <= N-1` ⇒ target is a
fixed ROM routine ⇒ PC stays in ROM. ACE requires breaking that inequality at a
site whose out-of-range bytes form a `<$0800` pointer **and** reaching it from
controller input.
