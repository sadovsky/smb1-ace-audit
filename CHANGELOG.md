# Changelog

## Formal track, second pass (2026-11-25)

P1 is still `unknown`. What changed is how precisely the open part is known.
Manifest: 211 obligations (70 proved, 47 conditional, 2 bounded, 68 abstract
counterexample, 15 unknown, 8 refuted, 1 observed).

- **Model validation**: every published vector (2,370,000 instructions) and
  5,915,520 exhaustive-per-dimension comparisons against a second
  implementation, 0 mismatches. Recorded differences: `JAM` leaves PC in
  place; interrupt hijacking is not expressible.
- **Trusted base**: slice queries hashed and re-asked of cvc5 and Bitwuzla;
  the control-flow graph's edges checked against the model (`GRAPH-EDGES`).
- **Initial memory**: the partition of RAM at the first NMI-enabling write is
  proved; 156 cells are never initialised, 40 survive a warm boot.
- **Bounded**: P1 from cold boot to the first NMI-enabling write, complete for
  that phase, and 4,000 steps beyond with one NMI.
- **Return frames**: stack depth bounded under named premises; 37 of 71
  non-push writers bounded; combined separation `unknown`. Refuted: the call
  graph is acyclic; warm resets do not drift the stack pointer.
- **Interrupt timing**: a cycle-level model derives the two NMI assumptions,
  one part proved, two conditional (one on a program premise).
- **Refuted in a model variant**: with NMIs allowed at any boundary, the
  program counter leaves the graph (concrete runs; not a hardware claim).
- **Lean**: the certificate soundness argument is mechanised for an abstract
  machine; it showed the conditions as designed did not imply safety and
  identified five omissions.
- **Certificate checker and proposer**: committed as work in progress, opt-in,
  no verdicts recorded.
- **Observation**: two full play-throughs replayed; 98.0% of instruction
  starts executed, all 18 dispatch sites reached, no check fired.
- **Replication** from a fresh clone: all statuses match; three slice query
  digests differ for a reason not yet identified.
- **Report**: `formal/paper/smb1_formal_report.pdf`.

Withdrawn or corrected along the way: saved-query hashes in `56ff998` did not
match their manifest (fixed); the report draft said the dispatch contract
covered the stack pointer and write set (it covers only the next fetch);
`MA-PPU-RESET` was described as unconditional hardware behaviour (it is
console-dependent).

## Formal track (2026-11-25)

Follows `FORMAL_VERIFICATION_PLAN.md`; details and limits in `formal/README.md`.
The primary theorem (every instruction fetch is in PRG ROM, for all inputs) is
**neither proved nor refuted**.

- Added a Z3 instruction-level model of the 2A03 and the NROM address map
  (`formal/model`). Validated against 71,100 recorded single-instruction
  vectors (237 opcodes) and 6,040 py65 comparisons with no mismatch; unstable
  undocumented instructions are modelled as havoc and not compared.
- Proved, with Z3 and cvc5 agreeing: the `$92C8` arithmetic lemma, the same
  lemma derived from the image's bytes, and a dispatch contract for each of
  the 18 sites. Each has a negative twin that is refuted.
- Proved by exhaustive model execution: every statically determined successor
  of the 10,370 non-computed instruction starts is in the graph.
- Conditional on the joint invariant: `$D2E5` and `$BDBD` indices in range
  from the code alone (independently matching `analysis/`), and 22 of the 45
  possible writers of `RAM[$071F]` preserve `<= 8`.
- Open: 16 site indices, the `$071F` invariant (initialisation and 23
  writers), return-frame integrity, and the two interrupt invariants. The
  model also found three writers of `$071F` the census did not list (`SHA*` at
  `$F3B1`/`$F3BD`, shown unreachable, and `ASL $1F1E,X` at `$FFF7` on the IRQ
  path).

## Remediation revision (2026-11-25)

Follows `AUDIT_REMEDIATION.md`. Outcome-neutral: the corrections below both
weaken and strengthen parts of the earlier result. No controller-only ACE was
demonstrated, and impossibility is not claimed.

ROM: SHA-1 `ea343f4e445a9050d4b4fbac2c77d0693b1d0922`, verified before every
run. Pre-correction outputs preserved in `results/baseline/`.

### Corrected (claims that were wrong about the ROM)

- **`$92C8` was not clamped.** `LDY $071F / BNE / LDY #$08 / STY $071F / DEY /
  TYA` substitutes 8 for zero and never bounds the upper end. Index is
  `((v or 8) - 1) & 0xFF`, derived as `{0..254}`. In range only while
  `RAM[$071F] <= 8`, which is an upstream invariant, not a structural fact.
  Previously published as "structural, provably safe".
- **`$B34E` had no local bound.** The `CMP #$03 / BEQ $B34E` at `$B345` only
  decides whether `STY $0789` runs; both paths dispatch with `A = $1D`
  unchanged. Previously published as "player state, checked".
- **`$9664`'s index source was misidentified.** The index is formed at
  `$965F-$9662` as `LDA $00 / CLC / ADC $07`, not from `$0E`. Over the game's
  largest table (47 entries), with dozens of writers to both scratch bytes.
  Recorded `unproved`.
- **`$9743`'s table has 3 entries, not 5.** Entry 0 points at `$974C`, which
  holds `JSR $9BBB`; the boundary heuristic read that instruction's bytes as
  entries 3 and 4. Under the bound the earlier revision asserted
  (`$0733 <= 4`), indices 3 and 4 dispatch outside the table to `$BB20` and
  `$BD9B`, both genuine instruction starts.
- **`$C7A8`'s table has 6 entries, not 8.** Entry 1 points at `$C7B7`, which
  holds `RTS`. The over-read also manufactured a phantom dispatch target at
  `$A060`, from which the old tracer decoded data as `JAM` instructions.
- **"Exactly one computed jump" counted only direct indirect jumps.** There are
  also 336 `RTS` and one `RTI`, each taking its destination from memory.
- **"2181 excluded, 0 unknown" overstated the evidence.** Every PRG-ROM
  destination was skipped before classification, and an *observed* bound was
  allowed to exclude an index outright. Corrected: 505 excluded
  unconditionally, 1252 conditionally, 1633 not ACE-capable, 724 unknown.
- **ROM destinations are not safe by virtue of being ROM.** 1932 resolutions
  are unexpected-ROM destinations; 390 land on an operand byte of another
  instruction, 874 on bytes the CFG never reaches.
- **I/O destinations are not a defined crash.** An instruction fetch from a
  register region is a bus transaction. `$2060` is `io_dependent` pending
  hardware verification.
- **Undocumented opcodes are not NOPs and do not mark data.** All 256 NMOS
  encodings act; 105 are undocumented, most are two or three bytes, six
  families write memory, twelve jam the CPU.
- **Overlapping instruction decodings were being discarded.** `trace.py`
  guarded on occupied *bytes*, which throws away SMB1's own `$2C` filler idiom
  (`$8220`, `$996A`, `$BDD4`, `$BFB6`, `$DC20`, `$E3EB`, `$F349`).
- **Branch feasibility was not modelled**, so the tracer followed the
  fallthrough of always-taken branches into data.

### Confirmed (claims that held, sometimes for a different reason)

- `$D2E5` is bounded at the dispatch: `CMP #$05 / BCS` is a real clamp,
  0..4 over 5 entries, no RAM assumption. As published.
- `$BDBD` is bounded, 0..8 over 9 entries — but by `$BDF6` returning
  `Y <= 13`, not by the `CMP #$09 / BCC` cited in the paper.
- The enemy-ID routing derivation reproduces independently from the CFG:
  identical arriving identifier sets, index spans, and the single
  out-of-range case `ID $36 -> index 34 -> $2060`.
- `$C907`'s routed indices (0..20) stay inside its 21-entry table.
- The sole direct indirect jump is `JMP ($0006)` at `$8E16`.

### Strengthened

- **IRQ entry is closed off more firmly than before.** The old argument was
  "NROM has no mapper IRQ", which ignores the 2A03's own two IRQ sources. The
  IRQ vector in fact points at `$FFF0`, which is table data, so a serviced IRQ
  would execute data. It cannot be serviced: `SEI` runs at reset and no
  reachable instruction is `CLI` or `PLP`, so `RTI` can only restore a status
  byte that already had I set. Caveat recorded: 101 PRG bytes hold `$58`, and
  the induction covers reachable instruction starts only.
- **Return-frame integrity now has evidence behind it.** `controlflow.py`
  concluded "every RTS in reached code returns to a JSR frame" from a
  24-instruction window in address order, which cannot establish it.
  `analysis/stack.py` replaces that with per-routine abstract stack semantics
  over the CFG and a fixpoint over callee summaries: 457 of 460 routines are
  balanced, all 627 reachable `RTS` sites consume exactly their entry frame,
  and `$8E04` is identified as the one routine that deliberately consumes its
  caller's frame. The two unresolved routines are reset (whose `TXS`
  initialises the stack pointer) and the NMI handler (whose `RTI` frame this
  method does not model). Still not a proof: 29 indexed stores could reach
  `$0100-$01FF` without a stack instruction. Obligation D moves from open to
  partially established.
- **`ASL` aliasing bounds how far any overrun can read.** The JumpEngine
  discards bit 7, so only 128 of 256 indices are distinct and a table overrun
  can never read beyond 256 bytes past the `JSR`.
- **The `$7F` wrap is explicit.** At effective index 127 the pointer's high
  byte comes from the return address itself, because `INY` wraps.
- Table boundaries now rest on independent evidence; 17 of 18 have at least
  one source beyond the heuristic (`$8234` does not).

### Observed

`experiments/observe_indices.py` samples the index variables once per frame
over 120,000 frames of mixed input (manifest in
`results/observed_indices.json`: ROM hash, both repository commits, seed,
initial-state hash, frames executed, dropped steps, input model).

- `RAM[$071F]` takes every value 0..8. Eight maps to index 7, the last entry
  of the 8-entry table, so play reaches the exact edge of the range the
  `$92C8` invariant must hold — it has no slack.
- `RAM[$0733]` was never observed non-zero, so the `$9743` overrun was not
  reproduced. This does not settle it: `$0733` is written at `$9CA3` and read
  at `$9740` within one frame, which frame sampling can miss entirely.
- No value was observed out of range at every site it feeds.
- `$0772` reaching 3 exceeds `$921B`'s 3-entry table while staying in range at
  the other three sites it indexes. The first version of this experiment
  reported that as a finding, which is precisely the error the plan warns
  about; it is now reported as undecidable from frame sampling, and
  `tests/test_observation.py` keeps it that way.

### Added

`analysis/` (decoder, CFG, value-set interpreter, index derivation, dispatch
tables, enemy routing, destinations, write census, effective addresses,
interrupts, provenance), `tools/proof_obligations.py`, `tests/` (128
regression tests, ROM-dependent ones skip when the verified ROM is absent),
`data/dispatch_tables.json`, and `results/` artifacts that the documentation's
numbers are taken from.

### Still open

All six proof obligations (`results/proof_obligations.json`): four are
partially established (A, B, D, E) and two are open (C, F). In particular: no
critical variable has a fully resolved writer set, so no state invariant is
established inductively; the stores that could rewrite a stack frame have not
had their index ranges bounded; no emulator fidelity comparison was run in this
revision; and no input sequence is known for any out-of-range index.
