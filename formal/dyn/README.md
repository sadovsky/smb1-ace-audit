# Dynamic track (`formal/dyn`)

Instruction-level execution of the image, for the questions frame sampling
cannot answer. Nothing here proves anything: every number is an observation
over the inputs that were run, and the reports say so in their own manifests.

What it is for:

- **refuting** proposed invariants. A proposed domain for a RAM cell that
  excludes an observed value is wrong. `dyn_cell_domains.json` exists to be
  read that way, as `formal/verify/JOINT_INVARIANT.md` section 6 asks.
- **positive findings**. A fetched program counter that is not an instruction
  start of `analysis.cfg`, or a dispatch index past the end of its table,
  would be direct evidence against `J-LOCATION`. Both were looked for.
- **following the model's counterexamples concretely**. The unconstrained-NMI
  behaviour that `JOINT_INVARIANT.md` section 1 describes in prose now has a
  trace.

## Modules

| | |
|---|---|
| `cpu6502.py` | py65's NMOS core with the 2A03's decimal behaviour and all 256 opcodes |
| `tracer.py` | the machine: CPU, RAM, cartridge, and a documented device stub |
| `nespy.py` | ctypes bindings for nes-py's native instruction tracer |
| `validate_cpu.py` | the core against the SingleStepTests `nes6502` vectors |
| `crossvalidate.py` | the tracer against nes-py, per frame and per instruction |
| `inputs.py` | controller-input models, open loop and closed loop |
| `search_inputs.py` | a greedy search for inputs that get past world 1-1 |
| `observe.py` | the five observations, on either engine |
| `nmi_storm.py` | the counterexample search for the model variant `T` |
| `test_dyn.py` | unit tests for the decisions, not the measurements |

## The CPU

`cpu6502.NMOS2A03` is `py65.devices.mpu6502.MPU` with two changes.

**Decimal mode.** The 2A03 adder ignores D; the flag bit still exists and is
still pushed by `PHP`. `opADC` and `opSBC` are wrapped so that the bit is
preserved but the adder never sees it: the wrapper clears D in `self.p`, calls
py65's binary path (clearing the bit is what selects that path inside py65),
and restores the bit afterwards. Neither path writes D, so this is safe.

**The 105 undocumented opcodes.** py65 maps every opcode it does not implement
to a placeholder that advances PC by one and costs zero cycles, which
mis-aligns an instruction stream and stalls a cycle-driven run. All of them are
implemented here, including the twelve `JAM` encodings, which raise instead of
fetching on. py65's `DEC $nnnn` cycle count (3 instead of 6) is also corrected.

`python3 -m formal.dyn.validate_cpu` compares the result with the
SingleStepTests `nes6502` vectors, 300 per opcode:

| | |
|---|---|
| opcodes compared | 244 (the twelve `JAM` encodings are not comparable) |
| instructions compared | 73,200 |
| state mismatches | 0 |
| cycle-count mismatches | 0 (the vector's bus-cycle count) |

That includes the eight the model treats as havoc (`ARR XAA LXA TAS SHA SHX
SHY`): they agree on this sample with the magic constant `$EE` and with the
page-crossing address corruption modelled, but they have no single hardware
behaviour and are reported separately, never as agreement.

## The device stub

`tracer.py`'s docstring is the specification. In short: RAM mirrored through
`$1FFF`; PRG at `$8000-$FFFF` with writes ignored; `$2002` bits 7 and 6 driven
by a dot counter over the NTSC frame of 262 x 341 dots at three dots per CPU
cycle; NMI at vblank when enable is set, and also on a 0 -> 1 enable write
while the flag is set; name-table RAM, CHR and palette behind `$2006`/`$2007`
with the one-byte read buffer; `$4014` DMA charged 513 or 514 cycles;
controller 1 as a shift register with strobe. Everything else reads zero.

Not modelled, and therefore not claimed: rendering, OAM contents, the APU, open
bus, and the renderer's updates to the `$2006` latch. The sprite-0 hit position
is **calibrated**, not rendered: the stub puts it at `OAM[0].y + 2`,
`OAM[0].x + 1`. Forty combinations of the two offsets were swept against
nes-py; none changed how many frame boundaries agree on RAM and none produced a
control-flow difference, so no result rests on the calibration.

## Cross-validation against nes-py

`python3 -m formal.dyn.crossvalidate --frames 1200 --inputs
mixed,run,explore,random,title,menu` -> `../results/reports/dyn_crossvalidation.json`.

Both emulators run from power-on on the same controller bytes. nes-py's RAM is
all zeros at power-on and the tracer is given the same. nes-py's
processor-status byte has its bits in the reverse order (`CPU_Flags` in
`nes_py/nes/include/cpu_opcodes.hpp` declares `N V ONE B D I Z C`), which is
internally consistent and invisible to the image but has to be translated
before comparison.

Measured over six input models (`mixed`, `advance`, `replay:4`, `explore`,
`random`, `title`), 1,200 frames each:

| | |
|---|---|
| frame boundaries with byte-identical RAM | 6,410 of 7,200 |
| largest difference at any one boundary | 2 bytes of 2,048 |
| fetches compared outside the timing loops | 21,811,986 |
| program-counter differences | 0 |
| differences in A, X, Y, S or the six real status bits | 0 |

A frame boundary is 29,781 CPU cycles, which is what `NESEnv.step` executes,
and it falls about 2,300 cycles after the NMI, i.e. *inside* the handler. A
cell the handler is in the middle of rewriting at that instant differs whenever
the two emulators are not cycle-identical; that is why 790 boundaries differ,
always by one or two bytes, and the differing addresses are the ones the
handler updates every frame (`$07A7-$07AD`, the pseudo-random register; `$0000`
and `$0009`, scratch) or stack bytes the two have at different call depths.

The instruction comparison removes from both streams the six loops whose
iteration count is a function of exact timing -- the two `$2002` vblank waits
at reset, the two sprite-0 waits in the handler, the `DEY` delay, and the
`JMP $8057` idle loop -- because one extra iteration shifts every later index.
What remains is compared index by index. The only loops whose totals differ are
the sprite-0-set wait and the idle loop, which compensate each other.

The two halves of the result constrain each other. Because the instruction
streams agree *everywhere* outside those loops, the RAM differences at frame
boundaries cannot be divergence of state: if they were, a later fetch would
differ too. They are the snapshot landing on a different instruction of the
same execution.

**The corroboration is therefore: outside six timing-dependent wait loops, the
tracer and nes-py execute the same instructions in the same order with the same
register contents, for 21.8 million fetches across six input models, and they
agree on all 2,048 RAM bytes at 89% of frame boundaries, differing by at most
two bytes at the rest.** It is not a claim that either matches a console.

## What was observed

`python3 -m formal.dyn.observe` -> `../results/reports/dyn_observations.json`,
`dyn_observations_nespy.json`, `dyn_cell_domains.json`. Status of every number:
**observed**.

| | tracer engine | nes-py engine |
|---|---|---|
| frames | 140,000 (14 runs) | 400,000 (10 runs) |
| instructions | 1,353,946,027 | 3,863,810,573 |
| fetches at an address that is not an instruction start | 0 | 0 |
| fetches outside `$8000-$FFFF` | 0 | 0 |
| graph nodes executed | 6,322 of 10,708 (59.0%) | 6,430 (60.0%) |
| executed instructions that overlap | 5 pairs, all 5 already recorded by the graph | the same |
| dispatch landings checked against their table | 633,547, all correct | not available |
| dispatch indices past the end of a table | 0 | 0 |
| stack pointer at any fetch | `$E6-$FF` (depth 25) | `$E6-$FF` |
| stack pointer at NMI entry | always `$FF` | always `$FF` |
| NMI delivered while `$8082-$8181` was running | 0 | 0 |
| NMI delivered by a 0 -> 1 enable write during vblank | 0 | n/a |

The overlapping executed instructions are the image's own trick: `$8222`,
`$996A`, `$BDD4`, `$BDD7` and `$E3EB` are each a `BIT $nnnn` whose operand byte
is the entry point of an immediate load reached by a different `JSR`. All five
pairs are among the ten `overlapping_starts` that `analysis.cfg` records, and
the check that found them decodes the executed addresses directly rather than
following the graph's edges, so it is independent corroboration that the
stream never ran misaligned.

The dispatch-landing check arms at each fetch of a `JSR $8E04` and verifies
that the first fetch after the JumpEngine's `JMP ($0006)` is the table entry
`(A and $7F)` selects. It is the dynamic counterpart of the
`D-xxxx-CONTRACT` lemmas. Three of the eighteen sites (`$83A3`, `$9743`,
`$C987`) were never fetched, so nothing at all is observed about them.

Three single-cell questions, which are the preconditions other obligations
rest on:

- `RAM[$0778]` at the fetch of `$8168`: `{$10, $11, $14, $15}`. Bit 7 was
  never set, which is what `JOINT_INVARIANT.md` needs for game logic to run
  with NMI disabled. Over 140,000 frames; still an observation.
- `RAM[$071F]` at the fetch of `$92B0`: `0..7`, and the cell was never written
  above 8 anywhere. This is the domain `P6-071F-PP` asserts.
- `RAM[$0733]` at the fetch of `$9740`: nothing, because `$9740` was never
  fetched. The cell was only ever written the value 0.

Writes into the stack page by instructions that are not pushes: 170 distinct
(program counter, address) pairs from 28 program counters. One of them,
`$90DC`, is the power-on RAM clear and covers `$0100-$015F`. The other 27 write
only into **`$0109-$0139`**, while the stack pointer never went below `$E6`,
i.e. the stack never reached below `$01E6`. So in these runs the stack and the
data the image keeps in page one are separated by 166 unused bytes. That is
exactly the hazard `LOC-RETURN` is open about, measured but not bounded.

`dyn_cell_domains.json` has, for each of the 2,048 cells, the set of values it
held at an NMI entry and the set it was ever written, as sorted integers and
`[lo, hi]` runs. 752 cells held a single value at every NMI entry; 67 spanned
all 256; 1,913 were written at all. A proposed invariant that excludes a value
in there is refuted by it; a proposed invariant that agrees with it has only
not been refuted.

## The unconstrained-NMI counterexample

`python3 -m formal.dyn.nmi_storm` -> `../results/reports/dyn_nmi_storm.json`.
**Not a hardware claim**: NMIs are delivered at boundaries the experiment
chooses, which no NES can do. It is a witness for the model variant `T` of
`JOINT_INVARIANT.md` section 1, and therefore evidence that `MA-NMI-EDGE` and
`MA-NMI-LATENCY` are load-bearing.

42 variants (14 entry counts x 3 warmups). 23 of them ended with the program
counter off the graph: 21 fetched from outside `$8000-$FFFF` and 2 fetched
inside PRG at an address that is not an instruction start. The other 19
survived the 200,000-instruction budget. The shape of the result, with 86 forced entries:

1. From the idle loop `JMP $8057` with `S = $FF`, 86 entries push 258 bytes,
   so `S` walks `$FF, $FC, ... , $00, $FD` and the whole page is overwritten;
   afterwards it holds exactly 85 `$80`, 85 `$82` and 86 `$A5` bytes -- the
   high and low halves of `$8082` and the pushed status byte.
2. The handler then runs, and its `RTI` pulls `($A5, $82, $80)` and returns to
   `$8082`, its own entry point, three times in a row, `S` climbing by three
   each time (`$FD`, `$00`, `$03`).
3. The next `RTI`, with `S = $06`, pulls `($A5, $82, $00)` and jumps to
   **`$0082`**, which is not an instruction start and not in PRG. The `$00`
   was not pushed by anything: `STA $0109` at **`$E88D`** wrote it.
4. Past that the fetch at `$0082` reads RAM, runs into a `$00` byte, `BRK`s
   through `$FFFE` to `$FFF0`, executes the vector table itself as
   instructions (`$FFFA` decodes as an undocumented two-byte `NOP`, `$FFFC` as
   `BRK`) and loops there, walking the stack pointer down three bytes a time.

With 256 forced entries the stack pointer comes all the way back to `$FF` and
the failure is the other kind: an `RTS` at `$AF92` pulls a misaligned frame and
lands at **`$8101`**, inside PRG but in the middle of `LDX #$14`. Seven
instructions execute off the graph -- `$8101`, `$8103`, `$8106`, `$8108`,
`$810A`, `$810D`, `$810F`, all seven of them undocumented opcodes -- and then the
stream resynchronises at `$8111`, which is an instruction start again.

With 1, 2, 3 or 42 entries nothing derails within the 200,000-instruction
budget, and 129, 171 and 172 also survive it. 85 entries, which bring `S` to
exactly `$00` without wrapping, already derail.

## Running

    export SMB1_ROM=/path/to/verified/image
    export PYTHONPATH=/path/to/nes-py:.
    python3 -m formal.dyn.validate_cpu                 # ~3 s
    python3 -m unittest formal.dyn.test_dyn            # ~10 s
    python3 -m formal.dyn.crossvalidate --frames 1200 \
        --inputs mixed,advance,replay:4,explore,random,title \
        --out formal/results/reports/dyn_crossvalidation.json
    python3 -m formal.dyn.search_inputs --seeds 12 --frames 16000
    python3 -m formal.dyn.observe --engine nespy  --frames 30000 --workers 10 \
        --models mixed,advance,explore,random,title,menu \
        --out formal/results/reports/dyn_observations_nespy.json
    python3 -m formal.dyn.observe --engine tracer --frames 12000 --workers 14 \
        --models mixed,advance,replay:3,replay:10,explore,random,title,menu \
        --out formal/results/reports/dyn_observations.json \
        --domains-out formal/results/reports/dyn_cell_domains.json
    python3 -m formal.dyn.nmi_storm --workers 7 \
        --out formal/results/reports/dyn_nmi_storm.json

The tracer runs about 37 frames a second per process (roughly 350,000
instructions a second) with every observation hook active; nes-py's native
tracer runs about 700 frames a second with every instruction recorded, but
reports registers only, so it can answer three of the five questions and does
so over twenty times as many frames.

## Artifacts

In `../results/reports/`:

| file | what it is |
|---|---|
| `dyn_crossvalidation.json` | the tracer against nes-py, per frame and per instruction |
| `dyn_observations.json` | the five observations, tracer engine |
| `dyn_observations_nespy.json` | observations 1-3, nes-py engine, more frames |
| `dyn_cell_domains.json` | per-cell value sets, for checking proposed invariants |
| `dyn_nmi_storm.json` | the `T` counterexample traces, 42 variants |

None of them contains a byte of the image. The traces record addresses,
`in_graph` and register contents, not opcode bytes; where an instruction has to
be named, the mnemonic and addressing mode are written out, as
`formal/README.md` and `JOINT_INVARIANT.md` already do. The replay files
`search_inputs.py` writes are controller bytes and live under
`~/big/smb1-formal/replays`, outside the repository.

## Coverage, and the honest limit on it

Graph coverage is the fraction of the 10,708 instruction starts in
`analysis.cfg.build_from_vectors` that were executed. It is bounded by how far
the inputs get into the game, and scripted inputs are bad at Super Mario Bros.
`search_inputs.py` exists because every open-loop model, and the one in
`experiments/observe_indices.py`, dies in world 1-1; the replays it records get
further. Everything not covered is simply unobserved: no conclusion of any kind
follows from a dispatch site that was never fetched.
