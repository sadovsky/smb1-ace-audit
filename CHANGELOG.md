# Changelog

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
- **`ASL` aliasing bounds how far any overrun can read.** The JumpEngine
  discards bit 7, so only 128 of 256 indices are distinct and a table overrun
  can never read beyond 256 bytes past the `JSR`.
- **The `$7F` wrap is explicit.** At effective index 127 the pointer's high
  byte comes from the return address itself, because `INY` wraps.
- Table boundaries now rest on independent evidence; 17 of 18 have at least
  one source beyond the heuristic (`$8234` does not).

### Added

`analysis/` (decoder, CFG, value-set interpreter, index derivation, dispatch
tables, enemy routing, destinations, write census, effective addresses,
interrupts, provenance), `tools/proof_obligations.py`, `tests/` (128
regression tests, ROM-dependent ones skip when the verified ROM is absent),
`data/dispatch_tables.json`, and `results/` artifacts that the documentation's
numbers are taken from.

### Still open

All six proof obligations (`results/proof_obligations.json`). In particular:
no critical variable has a fully resolved writer set, so no state invariant is
established inductively; return-frame integrity is not analysed (the RTS
pattern scan is not a substitute); no emulator fidelity comparison was run in
this revision; and no input sequence is known for any out-of-range index.
