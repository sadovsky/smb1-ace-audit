# Joint invariant and certificate design (plan sections 8, 9, 10; M4, M6)

This is the design the certificate checker and the invariant proposer are
built to. It is a specification, not a result. If the implementation has to
deviate, the deviation and its reason are recorded at the bottom of this file.

## 1. The model variant the certificate is about

`T_V2` is `formal/model/transitions.py` plus two timing assumptions. Both
*remove* behaviours, so everything proved is conditional on them.

- **MA-NMI-EDGE**: after an NMI is taken, no further NMI is taken until the
  handler has executed its disabling write (`$8082`-`$808C`). Rationale: NMI
  is edge-triggered and a second edge needs a new vertical blank, tens of
  thousands of cycles later.
- **MA-NMI-LATENCY**: no NMI is taken between the handler's enabling write
  (`STA $2000` at `$817E`) and the completion of the `RTI` at `$8181`.
  Rationale: the 6502 polls interrupt lines before the last cycle of an
  instruction, and the enabling write happens on the last cycle of the `STA`,
  so the earliest an NMI caused by it can be taken is after the next
  instruction. This rationale needs a citation and is not modelled.

Without them the theorem is believed false *in the model*: `T` as written lets
NMI re-enter at `$8082` 86 times, the stack pointer wraps (256 is not a
multiple of 3), and an `RTI` then pulls a misaligned frame. That is an
abstract counterexample to `J_location` for the unconstrained variant and must
be reported as such, with a concrete trace if one can be produced.

Facts read from the image that the design relies on (each must be re-checked
by the checker, not trusted from here):

- reset `$8000`: `SEI / CLD / LDA #$10 / STA $2000 / LDX #$FF / TXS`, then
  initialisation, then `ORA #$80 / JSR $8EED` (enables NMI), then the idle
  loop `JMP $8057` at `$8057`. Reset never returns.
- NMI `$8082`: clears bit 7 of the mirror `$0778` and writes PPU control with
  bit 7 clear at `$808C`. At `$8168` it pushes the mirror and writes it to
  PPU control again, runs game logic (`JSR $8212` at `$8175`), then
  `LDA $2002 / PLA / ORA #$80 / STA $2000 / RTI`.
- So game logic runs inside the NMI handler with NMI disabled, **provided**
  bit 7 of `RAM[$0778]` is clear at `$8168`. That is itself an invariant to
  prove.

## 2. Structure

`N` is the set of instruction starts. Routines are the entries reported by
`analysis.stack.routine_entries`; a node may belong to several routines
(shared tails). Three roots: reset `R`, NMI handler `H`, and (never entered,
see `J-IRQ`) the IRQ target `$FFF0`.

The certificate assigns:

- to every reachable node `pc` (and ghost NMI-enable value `en`) an abstract
  state `Inv[pc, en]`;
- to every routine `r` a contract `(Mod[r], Post[r], use[r])`;
- one frame-boundary invariant `I_frame` on RAM, the state in which an NMI
  may begin.

## 3. Abstract state language

A state is a conjunction of:

- value sets (subsets of 0..255) for `A`, `X`, `Y`, `S`;
- three-valued flags `C Z N V` (`I` is always set, `D` is unconstrained);
- `depth`: `S = S0 - depth`, where `S0` is the stack pointer on entry to the
  routine (a ghost);
- the entry frame is intact: `RAM[$0100+S0+1..2]` equals the ghost return
  address (three bytes for `H`);
- value sets for individual RAM cells (mirror-normalised; absent means
  unconstrained);
- pair sets for declared pairs of cells: a set of `(a, b)` values, used for
  correlations that must survive the frame boundary such as
  (`$0770`, `$0772`);
- copy facts `reg == RAM[c]`;
- `en`, the ghost NMI-enable bit: 0, 1, or either.

Unreachable is `false`. A node without an invariant is treated as `false`,
and reaching it from a reachable node is a failed check.

## 4. Verification conditions

All are quantifier-free bit-vector/array queries built from `cpu.step` on a
symbolic state constrained by the invariant. Each gets an id, goes to the
ledger, and is checked by the code in `formal/verify/certificate.py`, which
shares no code with the proposer.

**VC-STEP(pc)**, ordinary instruction: for every successor `pc'`,
`Inv[pc] and guard => Inv[pc']` on the successor state. This includes the
frame-intact conjunct, so a store that could hit the entry frame fails here.

**VC-MOD(pc, r)**: every write the step makes targets a cell in `Mod[r]`, or
the routine's own stack area `[$0100+S0-use[r]+1, $0100+S0]`.

**VC-CALL(pc)**, `JSR q` with `q` not the JumpEngine:
1. the state after the `JSR` satisfies `Inv[q.entry]`;
2. `depth + 2 + use[q] <= use[r]`;
3. let the return state be the pre-call state with registers and flags
   replaced by fresh values satisfying `Post[q]`, cells in `Mod[q]` replaced
   by fresh values satisfying `Post[q]`, the bytes
   `[$0100+S-use[q]-1, $0100+S]` unconstrained, `S` unchanged; then
   `Inv[return point]` holds;
4. `Mod[q]` is a subset of `Mod[r]`.

**VC-RET(pc)**, `RTS`: `depth = 0` and the post-`RTS` state satisfies
`Post[r]`. Nothing is checked about the destination: the caller's VC-CALL
already assumed it.

**VC-DISPATCH(site)**, `JSR $8E04`: `Inv[site] => (A and $7F) < n`; and for
each entry `e_i`, the state after executing the JumpEngine with `PC = e_i`
satisfies `Inv[e_i]` with the same `depth`. The targets are part of the
calling routine's body.

**VC-NMI-ENTRY(pc)**, for each `pc` whose `en` may be 1, excluding the two
windows removed by the timing assumptions: the RAM part of `Inv[pc]` implies
`I_frame`; and `Inv[$8082]` holds of the state after interrupt entry.

**VC-NMI-RESUME(pc)**, same set: `Inv[pc]` holds of a state whose registers
and flags are unconstrained, whose RAM is any state satisfying `Post[H]`
except that bytes above `S` in the stack page are unchanged.

**VC-NMI-EXIT**: at `RTI`, `depth = 0`, the pulled status has I set, and the
RAM part of the state implies `I_frame` and `Post[H]`.

**VC-RESET(pc, en)**: for every reachable point, the reset state (registers
unconstrained, I set, RAM unchanged, `en` unchanged) satisfies
`Inv[$8000, en]`.

**VC-COLD**: the cold-boot state satisfies `Inv[$8000, 0]`.

**VC-FORBIDDEN(pc)**: `Inv[pc]` is `false` for `BRK`, `JAM`, the unstable
undocumented instructions, `CLI`, `PLP`, and any `RTI` other than the
handler's.

**VC-SAFETY**: every node is in ROM (trivial, recorded for completeness).

## 5. What acceptance would mean

If every VC holds, then on paper: `J := PC in N and Inv[PC, en] and the stack
is a chain of intact frames` is inductive for `T_V2`, by the standard
soundness argument for procedure contracts with a frame rule. That argument
is **not machine-checked** and is part of the trusted base. The conclusion
would be P1 for `T_V2`, conditional on MA-CPU, MA-PPU-POWERON,
MA-PPU-WARMUP, MA-NMI-EDGE, MA-NMI-LATENCY.

Partial acceptance is the expected outcome. Each failed VC is recorded with
the instruction, the invariant it could not establish, and a satisfying
assignment; P1 stays `unknown` and lists them.

## 6. Proposer

Anything that emits a certificate in this format. The intended one is an
interprocedural abstract interpreter over the same domains: flow-sensitive
registers and cells, the frame rule at calls using may-modify sets, the
handler analysed as a loop whose entry state is `I_frame`. Its output is
untrusted; only the checker's verdict counts. Observed values from the tracer
(`formal/dyn`) may be used to sanity-check proposals (a proposed domain that
excludes an observed value is wrong) but never as evidence for a VC.

## 7. Deviations

Written while implementing `formal/verify/certificate.py` (the checker) and
`formal/analysis/` (the proposer).  Each entry says what the implementation
does instead of what sections 1-6 say, and why.

### 7.0 Fixes forced by the Lean mechanisation

`formal/lean/` states the section 5 meta-argument in Lean 4 and proves it over
an abstract machine.  Doing that turned up five hypotheses the proof needs
that neither section 4 nor the first version of the checker supplied
(`formal/lean/FINDINGS.md`).  All five are fixed here.  F1 came with a
machine-checked certificate for which every other verification condition held
and safety was false, so it was a real unsoundness rather than a gap in the
proof.

* **F1, the timing windows were trusted from the certificate.**  `vc_nmi`
  asks the solver nothing inside `nmi_windows`, so a certificate that
  declared a wide window hid the handler from every obligation.  The checker
  now *derives* the window set itself from the image -- the handler's
  prologue up to and including its first PPU-control write that clears bit 7,
  and the `RTI` that follows its last write that sets bit 7 -- and
  `VC-NMI-WINDOWS` fails for any declared instruction start outside the
  derived set.  MA-NMI-EDGE and MA-NMI-LATENCY remain assumptions, but they
  are now assumptions about *those* boundaries and no others.
* **F2, an interrupt inside a callee was not charged to its callers.**
  `VC-CALL-RETURN` now havocs `Mod[q]` together with `Mod[H]` whenever an NMI
  may be taken anywhere inside `q`, transitively (`Checker.interruptible`).
  As the finding predicts, that is a much weaker hypothesis and it is
  expected to fail where it used to hold: `Mod[H]` is the whole handler's
  footprint.
* **F3, `Post[H]` was checked before the `RTI` and assumed after it.**  It is
  now checked on the post-`RTI` state, as `VC-RET` always did.  The proposer
  therefore no longer puts flag clauses in `Post[H]`, since the `RTI` restores
  the flags from the frame; `I` survives, because the saved status byte has it
  set (the `status_i` conjunct).
* **F4, the `relevant` narrowing could make a query vacuous.**  The callee's
  own `Post` cells are now part of `relevant`, and `VC-CALL-RETURN` and
  `VC-NMI-RESUME` additionally probe their hypotheses for satisfiability and
  fail when they are unsatisfiable.  A vacuous obligation is a failure, not a
  `holds`.
* **F5, nothing ordered `S` against `s0` and nothing bounded the stack.**
  `depth` entries must now lie in `0..255` at parse time, the invariant emits
  `S <= s0` explicitly (the bit-vector equation `S = s0 - depth` is modulo 256
  and orders nothing), and `VC-CAPACITY` checks
  `use[root] + 3 + use[H] <= 256` together with the handler having no live
  context whose enable bit is set outside a window -- which is also what makes
  the bound finite.

### 7.1 Soundness fixes to section 4

These are places where the verification conditions as written do **not**
establish what the section 5 meta-argument needs.  The spec is wrong here and
the checker is stricter than it.

* **VC-RET needs the frame conjunct.**  Section 4 says only `depth = 0` and
  `Post[r]`.  But the caller's VC-CALL assumes control resumes at the
  instruction after its `JSR`, and that holds only if the `RTS` pulls the
  entry frame.  A certificate whose `Inv` at an `RTS` omits `frame` would be
  accepted while the return address could be anything.  `vc_ret` therefore
  requires `depth = {0}` **and** `frame` to be asserted.  Same for
  VC-NMI-EXIT and the three-byte interrupt frame.
* **VC-NMI-EXIT needs the saved status byte.**  Inside the handler the pushed
  status is a ghost, so nothing made it have `I` set, and the `RTI` could
  restore a cleared `I`.  The abstract state gained a `status_i` conjunct
  (`bit 2 of the ghost status byte is 1`); VC-NMI-ENTRY establishes it from
  the interrupted context and VC-NMI-EXIT consumes it.
* **There is no VC-IRQ.**  `transitions.py` offers an IRQ entry at every
  boundary where `I` is clear, and section 4 never excludes it; without an
  explicit check a certificate could leave `I` unconstrained and say nothing
  about `$FFF0`.  `vc_irq` checks that every live context asserts `I`.
  Preservation is part of VC-STEP and the base cases are VC-COLD and
  VC-RESET.
* **TXS is forbidden outside a root routine.**  It moves the frame base, which
  invalidates `depth = s0 - S` and so the frame conjunct, and section 4 does
  not mention it.  `check_context` reports it as a failed VC-FORBIDDEN.
* **VC-DISPATCH also checks the JumpEngine's own writes.**  The engine writes
  `$0004-$0007` and pops two bytes.  Section 4 charges nothing for that; the
  checker charges it to the calling routine through the same `VC-MOD` claim.
* **VC-DISPATCH needs one unconditional condition.**  Section 4's per-entry
  conditions are each conditional on the engine landing on that entry, so on
  their own they say nothing if it could land somewhere else.
  `VC-DISPATCH-TARGET` asks for the unconditional disjunction: the address the
  engine computes is one of the table's entries.

### 7.2 Extensions to the abstract-state language of section 3

Each of these was added because without it a necessary fact is not
*checkable*, not merely not inferable.  All are quantifier-free and exact.

* **`rel`: flag-register relations.**  Section 3 has three-valued flags and
  value sets but no comparison context, so after `CMP #k` the certificate can
  record `C` but not *why*, and the following branch cannot narrow the
  register.  Every comparison-derived bound - including the two dispatch
  indices the earlier value-set work found bounded - is unavailable without
  it.  An entry is `[flag, op, register, k]` with `op` one of `uge`, `eq`,
  `bit7sub`, meaning `flag <=> op(register, k)`.
* **`zero_runs` and `zero_pages`: parametric zero regions.**  The
  RAM-clearing loop at `$90CC` has an invariant parametric in the index
  register (`every cell above Y in page X is zero`), which no finite set of
  per-cell value sets can express.  Without it no RAM cell has any domain
  after a reset, because `transitions.py` admits a warm reset at every
  boundary and reset is the only place RAM is established.  `zero_pages`
  compares pages to the counter *signed*, because the counter ends at `$FF`
  and that is exactly the iteration in which every page is clear.
* **`copies`: `register == RAM[cell]`.**  Named in section 3 and kept; it is
  what makes the dispatch refinement work, and the proposer now also records
  it after a store, not only after a load.
* **`keeps`, `preserves` and `en_bit`: input/output relations.**  Plan
  section 8 asks for "relationships among registers, flags and memory
  values", and one is unavoidable here.  `$8EED` is three instructions --
  write `A` to PPU control, write `A` to its RAM mirror, return -- and it is
  called both to *enable* NMI (from reset) and to leave it alone (from
  `$8E19`, where bit 7 of `A` comes from the mirror and is clear).  A contract
  with a flat exit set for the enable bit models it as possibly enabling at
  every call site, and the bit then leaks into every context in the program,
  which is where the first attempt at this certificate ended up.  So a
  contract may declare `preserves` (registers it leaves untouched, checked at
  the `RTS` against a per-routine entry ghost that the invariant names with
  `keeps`) and `en_bit` (the exit enable bit is a named bit of a named
  register).  Together they let a caller's knowledge of `A` decide the enable
  bit after the call.
* **`no_ppu` on a routine contract.**  Section 4 has no account of the ghost
  enable bit across a call, and extending `Post[q]` with a flat set of
  possible exit values is useless: a routine called once with the bit set is
  then modelled as possibly setting it at every other call site, and the bit
  leaks into every context in the program.  A routine may instead declare
  that no write in it or its callees reaches PPU control, which makes the
  enable bit the identity across the call.  `VC-MOD` checks the routine's own
  writes and `VC-CALL-PPU` checks that its callees declare it too.

### 7.3 Structural choices

* **Contexts are `(pc, routine, en)`, not `Inv[pc, en]` plus a separate
  routine map.**  Section 2 allows a node to belong to several routines
  (shared tails, the `BIT abs` overlap idiom); making the routine part of the
  key gives such a node one invariant per owning routine instead of a join,
  and it is what lets `depth` and the entry frame mean anything there.  On the
  real image this turns 10,708 instruction starts into about 16,000
  routine-qualified nodes.
* **`depth` is a *set* of small integers, and the stack pointer carries an
  absolute value set.**  A routine can reach the same instruction at two
  depths (a join after a `PHA`), and the absolute value set is what pins the
  ghost `s0` and so the address of the entry frame; without it no store can be
  shown to miss the frame.
* **`Post` gained an `en` component.**  Needed for any call whose callee
  changes the enable bit; `no_ppu` above covers the common case.
* **`VC-RESET` for `en = 0` is one query, not one per context.**  Its
  hypothesis leaves RAM and the registers completely unconstrained, which is
  weaker than any context's invariant, so the single query covers them all.
  The `en = 1` contexts are few and each gets its own query.
* **The JumpEngine has no contexts.**  `VC-DISPATCH` executes its
  instructions inside the query, so its fetches are accounted for there;
  `VC-COVERAGE` checks that nothing else enters it and that the certificate
  claims no context inside it.
* **`$FFF0` and the IRQ cluster have no contexts at all**, so they are
  `false`.  What closes them is `VC-IRQ` (above) plus the `BRK` at `$FFFC`
  being reachable only from inside the cluster.
* **The proposer must not model an NMI inside the two windows.**  The windows
  are where MA-NMI-EDGE and MA-NMI-LATENCY say no NMI is taken, so a proposer
  that models one there contradicts the assumption its own certificate
  declares -- and in particular makes the handler re-enter itself at
  `$8085`, which widens its entry state to nothing useful.  The windows are
  derived structurally (the handler's prologue up to and including its first
  PPU-control write that clears bit 7, and the `RTI` that follows its last
  write that sets bit 7) rather than taken from a list, so the certificate's
  claim about them is auditable.

### 7.4 A new model assumption: MA-PPU-RESET

`transitions.py` carries the ghost enable bit across a warm reset unchanged.
That is the conservative choice, and it has a consequence the design did not
anticipate: a reset taken while the bit is set leaves it set through the first
instructions of the reset handler, and `$8002/$8004` (`LDA #$10` /
`STA $2000`) is the only thing that clears it.  An NMI taken at the boundary
*between* those two instructions returns with `A` equal to
`RAM[$0778] | $80` - bit 7 **set** - because that is what the handler's own
`$817C/$817E` leaves in `A`.  The `STA $2000` then re-enables NMI, and the
rest of the initialisation, including the RAM-clearing loop, runs with NMI
enabled and RAM half-cleared.

Rather than carry that through the certificate, the proposer declares

> **MA-PPU-RESET**: the reset line clears PPU control, so the ghost
> NMI-enable bit is 0 at `$8000`.

which NESdev documents as true of the front-loading NES (NES-001), whose
reset button resets both CPU and PPU, and as **false** of the Famicom and the
top-loading NES-101, where only the CPU is reset.  It is the same kind of
assumption as `MA-PPU-POWERON`, but unlike that one it is known not to hold on
some consoles; on those, the warm-reset scenario above is not excluded by
anything proved here and is an open obligation.  It *removes* behaviours, so it is an assumption and not a
result: the checker records it as a `VC-RESET` verdict naming it, and
`properties/joint.py` lists it among the assumptions of `P1-JOINT`.  The
underlying model is unchanged, so this does not make anything else in the
repository conditional.

### 7.5 Hints

The proposer accepts hand-written hints (`formal/analysis/hints.py`) that add
conjuncts at named program points.  All of the present ones are for the
`$90CC` clearing loop.  A hint is a suggestion, not evidence: the checker
decides, and a wrong hint becomes a failed verification condition.  The
proposer is untrusted either way, so this changes nothing about what a
`holds` verdict means.
