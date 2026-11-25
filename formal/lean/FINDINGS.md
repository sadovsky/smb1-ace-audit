# Findings from mechanising the section 5 meta-argument

What was done: the paper argument of `formal/verify/JOINT_INVARIANT.md`
section 5 -- "if every verification condition holds then the joint invariant
is inductive, hence the safety property holds of every reachable state" -- is
stated and proved in Lean 4 over an abstract machine (`formal/lean/`). The
certificate objects and every verification condition of section 4 are
`Prop`s; the transition relation is the parameterised union of step / call /
return / async-entry / async-return / reset. `lake build` succeeds with no
`sorry`, `axiom` or `admit` (see README.md for the build output).

A **finding** is a hypothesis the proof needs that nothing in section 4 or in
`formal/verify/certificate.py` supplies. Each one is a named field of
`Extra` in `AceAudit/Spec.lean`, or an explicit discrepancy between the
`Prop` in `AceAudit/Spec.lean`'s `VC` and what the checker actually asks the
solver. The proof was written by following the invariant through the
transition relation and recording what was missing; the four gaps a review
had already found were not used to steer it, and are compared at the bottom.

---

## F1. The timing windows are trusted from the certificate (soundness hole)

**Needed hypothesis** (`Extra.window`):

```lean
window : ∀ c g σ σ', X.C.Inv c g σ → X.C.window c.pc → ¬ X.M.aent σ σ'
```

`VC-NMI-ENTRY` and `VC-NMI-RESUME` are required only for contexts outside
`nmi_windows` (section 4; `Checker.vc_nmi` returns `HOLDS` with
`excluded_by: MA-NMI-EDGE / MA-NMI-LATENCY` and asks the solver nothing).
`self.windows` is read from the certificate JSON, so the only thing standing
between the certificate and the handler is a claim the certificate makes about
itself. Section 7.3 says the windows are "derived structurally ... so the
certificate's claim about them is auditable" -- that is a statement about the
*proposer*, and audit by a human is what the mechanisation is meant to
replace.

**This is not a proof artefact.** `AceAudit/GapWindow.lean` builds a concrete
instance of the framework -- two program counters, one live context -- in which

* every verification condition holds (`GapWindow.gapVC : VC X`), and
* `GapWindow.bad` is reachable (`reach_bad`) with a program counter outside the
  safe set (`bad_unsafe`),

and therefore `no_extra (E : Extra X) : False`: for that certificate the
verification conditions of section 4 are satisfied and the safety property is
false. The gap is a genuine unsoundness in the verification-condition set,
not a weakness of this particular proof.

**Fix.** The windows have to be discharged against the transition relation,
not declared. Either (a) derive them in the checker from the image (the
handler's prologue up to its first PPU-control write clearing bit 7, and the
`RTI` after its last write setting bit 7) and check that derivation against
the CFG, with `MA-NMI-EDGE`/`MA-NMI-LATENCY` appearing as the only assumptions
used; or (b) keep them in the certificate and add a verification condition
that the declared set equals the derived one. Today neither exists.

---

## F2. An interrupt inside a callee is not charged to the suspended callers

**Needed hypothesis** (`Extra.handlerMod`):

```lean
handlerMod : ∀ c g σ, X.C.Inv c g σ → c.en = true → ¬ X.C.window c.pc →
  Sub (X.C.mod X.P.handler) (X.C.mod c.rtn)
```

The global invariant has to say, for every suspended activation, that the
current state differs from the state at which it was suspended only inside the
junk region of what is running on top of it (`ChainStep`, last conjunct), and
the junk regions have to nest down the chain (`junk_mono`). `VC-CALL` (4)
gives the nesting for calls (`Mod[q] ⊆ Mod[r]`). For an interrupt there is
no such condition: `Checker.vc_nmi` re-establishes `Inv` only for **the
interrupted context itself** (`VC-NMI-RESUME`), and says nothing about the
activations below it on the stack. Their invariants were last established by
their own `VC-CALL-RETURN`, whose havoc covers `Mod[q]` and not `Mod[H]`.

So a handler write to a cell in `Mod[H] \ Mod[q]` that some suspended caller's
invariant constrains is unaccounted for, and the caller resumes with an
invariant that no longer holds.

**Fix.** Either add `Mod[H] ⊆ Mod[r]` as a verification condition for every
routine `r` that has a live context with `en = 1` outside a window -- the
form stated above -- or widen the havoc in `VC-CALL-RETURN` to
`Mod[q] ∪ Mod[H]` whenever the callee, or anything it calls, is interruptible.
The second is the cheaper check and the weaker requirement. Note the first is
likely to be *false* on the real image: `Mod[H]` is the whole handler's
footprint, including the game logic at `$8212`, while an interrupted leaf
routine's `Mod` set is small. That is worth knowing before the certificate is
re-run, because it means the present `holds` verdicts for `VC-CALL-RETURN` do
not have the meaning section 5 gives them.

---

## F3. `Post[H]` is checked before the `RTI` and assumed after it

**Needed hypothesis** (`Extra.postAret`):

```lean
postAret : ∀ e σ σ', X.M.aret σ σ' →
  X.C.post X.P.handler e σ → X.C.post X.P.handler e σ'
```

`Checker.vc_nmi_exit` asks `VC-NMI-EXIT-IFRAME` of `state`, the state **at**
the `RTI`:

```python
out.append(self._ask(f"VC-NMI-EXIT-IFRAME:{context.key}", "VC-NMI-EXIT",
                     hypotheses,
                     z3.And(self.i_frame.formula(state, ghosts),
                            routine.post.formula(state)), ...))
```

while `Checker.vc_nmi` *assumes* `handler.post.formula(resumed)` of the state
on resumption. The two states are not the same: the `RTI` pulls the status
byte, so every flag clause of `Post[H]` (`Post.c/.z/.n/.v/.i`) is restored
from the interrupt frame -- that is, to the interrupted context's flags -- and
the register clauses (`Post.a/.x/.y`) are evaluated on `havoc_state`'s fresh
registers in the resume query but on the handler's registers in the exit
query. Nothing justifies carrying either across the transition.

For comparison, `VC-RET` has this right: `Checker.vc_ret` evaluates
`routine.post.formula(returned.state)` on the post-`RTS` state.

**Fix.** Check `Post[H]` on the post-`RTI` state, as `VC-RET` does, or
restrict `Post[H]` to clauses the `RTI` cannot disturb (RAM cells and the
ghost enable bit) and check the flag and register clauses separately against
what the `RTI` actually restores.

---

## F4. The `relevant` narrowing of the callee havoc

**Discrepancy, not an added hypothesis.** `VC.callReturn` and
`VC.aentResume` quantify over *every* state that agrees with the pre-call
state outside the callee's junk region:

```lean
callReturn : ∀ c g σ σe σ' q, X.C.Inv c g σ → X.P.isCallSite c.pc q →
  X.M.call σ σe q →
  AgreeOutside (junk X q σ.sp) σ σ' → σ'.sp = σ.sp → X.C.post q σe σ' →
  X.C.Inv ⟨X.P.retPc c.pc, c.rtn, σ'.en⟩ g σ'
```

That universal quantification is what the pop half of the frame rule
(`chain_pop`) instantiates, and it is the obligation the soundness proof
needs. `Checker._havoc_callee` discharges a weaker one: it havocs
`callee.mod & relevant` rather than `callee.mod`, where

```python
relevant = Inv[return point].mentioned_cells ∪ frame_cells ∪ Post[caller].cells
```

(`Checker._relevant(return_pc, context.routine)` -- note `context.routine` is
the *caller*). The docstring's justification is that a cell outside the
claim's footprint cannot change whether the claim holds. That is true of the
**claim** and false of the **hypothesis**: the query also asserts
`callee.post.formula(after)`, and `Post[q]`'s own cells are not in `relevant`.
So for a cell `x ∈ Mod[q] ∩ cells(Post[q])` that `Inv[return point]` does not
mention, `after[x]` keeps its *pre-call* value, `Post[q]` is asserted of that
value, and if `Inv[call site]` pins `x` to a different value the hypothesis
set is unsatisfiable and `VC-CALL-RETURN` is reported `holds` vacuously. The
same applies to `Checker.vc_nmi`'s resume query with `Post[H]`.

**Fix.** Add `callee.post.cells` (and, for the resume query,
`handler.post.cells`) to `relevant`; or drop the optimisation. A cheap
independent check: for each `VC-CALL-RETURN` query, assert the hypotheses
alone and require `sat`. A vacuous query is always a bug, whatever its cause.

---

## F5. Nothing bounds the stack, and the depth relation is modulo 256

**Needed hypothesis** (`VC.depth`), which the checker does *not* establish:

```lean
depth : ∀ c g σ, X.C.Inv c g σ → σ.sp ≤ g.s0
```

This is the one `VC` field whose justification does not survive inspection, so
it is a finding rather than a verification condition. Two separate problems.

1. **`depth` is not constrained to be non-negative, and the relation it states
   wraps.** `Invariant.formula` emits
   `Or(*[state.s == ghosts.s0 - d for d in self.depth])` over 8-bit bitvectors.
   Nothing in `Invariant.parse` requires `d >= 0`, and the subtraction is
   modulo 256, so the conjunct places no ordering constraint between `S` and
   `s0` at all. The frame-nesting argument needs that ordering: it is what
   makes a callee's scratch area a subset of its caller's
   (`stackAtOrBelow_mono`, `junk_mono`), and hence what keeps a callee away
   from the frames of the activations suspended below it.

2. **No verification condition bounds total stack depth.** `VC-CALL-USE`
   (`depth + 2 + use[q] <= use[r]`) makes `use` nest down a call chain, but
   nothing checks the base case -- that `use[root]` plus the interrupt frame
   and the handler's own usage fit in the 256-byte stack page:

   > `use[root] + 3 + use[H] <= 256`, and the handler is not itself
   > interruptible (otherwise the bound is not finite).

   Section 1 already knows the consequence of getting this wrong -- "the stack
   pointer wraps (256 is not a multiple of 3), and an `RTI` then pulls a
   misaligned frame" -- and names `MA-NMI-EDGE` as what rules it out. But
   `MA-NMI-EDGE` is about *when* a second NMI may be taken, and the capacity
   condition above is an arithmetic fact about the contracts that no verdict
   in the ledger covers.

The mechanisation makes this assumption visible rather than discharging it:
`St.sp` is an `Int` and `Layout.stackAddr : Int → Addr`, so the model has no
wraparound by construction, and `Machine.callSp`/`aentSp` (`σ'.sp = σ.sp - 2`,
`σ'.sp = σ.sp - 3`) are therefore unbounded-integer facts. **This is the one
place where the mechanisation assumes something the checker should be made to
check**, and it is recorded here rather than silently relied on.

**Fix.** Require `depth` entries to be non-negative at parse time and add the
`S <= s0` conjunct explicitly (it is not implied by the bitvector equation);
add the capacity verification condition above, computed from the contracts;
and add a verification condition that the handler has no live context with
`en = 1` outside a window, which is also what makes the depth bound finite.

---

## What the mechanisation did *not* need

Worth recording, because each is a place where the checker is stricter than
the soundness argument requires, and relaxing it would be safe:

* **The frame conjunct is needed only at `RTS` and `RTI`**, exactly as section
  7.1 has it (`VC.retFrame`, `VC.aretFrame`). The proof does not need it
  maintained at intermediate contexts: the return address is read from memory
  at the return instruction, and the invariant there asserts it. Carrying it
  through the body is how the certificate *gets* it, but it is not a separate
  obligation.
* **`use[r]` plays no role** in the frame-separation argument, only in the
  capacity argument of F5. The junk region the proof uses is "the `Mod` set,
  plus the whole stack at or below the activation's base, plus registers and
  flags", which is coarser than the checker's `[s0-use+1, s0]` window and is
  what makes the regions nest for an interrupt (whose stack usage is not
  inside any caller's `use` budget). Consequently the checker's
  `VC-CALL-RETURN` havocs a *narrower* stack window than `VC.callReturn`
  states; the gap matters only for a certificate whose invariants constrain
  stack cells strictly below the callee's declared area.

---

## Comparison with the four gaps the review had already found

| Review gap | Independently forced by the proof? |
|---|---|
| NMI windows trusted from the certificate | **Yes** -- `Extra.window` (F1), and machine-checked to be a real unsoundness, not an artefact (`GapWindow.no_extra`) |
| NMI inside a callee not charged to the callee's contract | **Yes** -- `Extra.handlerMod` (F2); the proof also says precisely which weaker condition suffices |
| A postcondition checked before `RTI` but assumed after | **Yes** -- `Extra.postAret` (F3) |
| A havoc optimisation that could make hypotheses vacuous | **Partly** (F4). The proof states the quantification the frame rule needs and so localises the discrepancy, but the vacuity itself is a property of the z3 encoding, which is outside the mechanisation. The specific hole found by reading `_relevant` against `VC.callReturn` -- the callee's `Post` cells are missing from `relevant` -- is new. |

**Revealed in addition:** F5, in two parts: the certificate's `depth`
conjunct is modulo 256 and so implies no ordering between `S` and `s0`, and no
verification condition bounds total stack depth against the size of the stack
page. Neither was in the review's list.

---

## Unproved statements

Nothing in `formal/lean/` is left open: there is no `sorry`, `axiom` or
`admit`, and `#print axioms` (`AceAudit/Check.lean`) reports only `propext`
and `Quot.sound` for every exported theorem. The following were deliberately
**not attempted**, and are not claimed anywhere:

1. A stack-capacity theorem. F5's condition is stated in prose above; it is
   not a Lean theorem. Proving it would need the depth bound threaded through
   the chain and a hypothesis that the handler is not interruptible.
2. Counter-models for F2, F3 and F4 of the kind built for F1. Each needs a
   longer trace (a call, a nested interrupt and a return, and a step whose
   successor depends on the clobbered cell), and only F1's was built.
3. Everything listed under "What this does not cover" in README.md: the 6502
   semantics, the SMT encoding of each verification condition, and the
   checker's Python.
