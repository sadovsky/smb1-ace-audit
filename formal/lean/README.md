# `formal/lean/` -- the section 5 meta-argument, machine-checked

The checker in `formal/verify/certificate.py` discharges the verification
conditions of `formal/verify/JOINT_INVARIANT.md` section 4 with an SMT solver.
The step from "every verification condition holds" to "the joint invariant is
inductive, hence the safety property holds for all reachable states" was a
paper argument (section 5) and part of the trusted base. This directory
replaces that argument with a Lean 4 proof.

The point is not to re-verify the image. It is that a missing or too-weak
verification condition now shows up as a proof that does not close, instead of
as something a reviewer has to notice. Five such gaps are recorded in
[FINDINGS.md](FINDINGS.md); one of them is additionally shown to be a real
unsoundness by a machine-checked counter-model.

## Building

```
$ elan --version
elan 4.4.0 (3cc76985a 2026-11-18)
$ lean --version
Lean (version 4.36.0, x86_64-unknown-linux-gnu, commit 611c117bfaf7b7a, Release)

$ cd formal/lean && taskset -c 0-3 lake build
✔ [2/14] Built AceAudit.Basic (459ms)
✔ [4/14] Built AceAudit.Spec (854ms)
✔ [6/14] Built AceAudit.Soundness (620ms)
✔ [8/14] Built AceAudit.GapWindow (445ms)
ℹ [10/14] Built AceAudit.Check (290ms)
info: AceAudit/Check.lean:11:0: 'AceAudit.chain_step_preserve' depends on axioms: [propext, Quot.sound]
info: AceAudit/Check.lean:12:0: 'AceAudit.chain_pop' depends on axioms: [propext, Quot.sound]
info: AceAudit/Check.lean:13:0: 'AceAudit.reach_J' depends on axioms: [propext, Quot.sound]
info: AceAudit/Check.lean:14:0: 'AceAudit.reach_live' depends on axioms: [propext, Quot.sound]
info: AceAudit/Check.lean:15:0: 'AceAudit.reach_safe' depends on axioms: [propext, Quot.sound]
info: AceAudit/Check.lean:16:0: 'AceAudit.GapWindow.gapVC' depends on axioms: [propext, Quot.sound]
info: AceAudit/Check.lean:17:0: 'AceAudit.GapWindow.init_good' does not depend on any axioms
info: AceAudit/Check.lean:18:0: 'AceAudit.GapWindow.aent_good_bad' does not depend on any axioms
info: AceAudit/Check.lean:19:0: 'AceAudit.GapWindow.reach_bad' does not depend on any axioms
info: AceAudit/Check.lean:20:0: 'AceAudit.GapWindow.bad_unsafe' does not depend on any axioms
info: AceAudit/Check.lean:21:0: 'AceAudit.GapWindow.no_extra' depends on axioms: [propext, Quot.sound]
✔ [12/14] Built AceAudit (314ms)
Build completed successfully (14 jobs).
```

No Mathlib: the development uses Lean core only, so the toolchain is the
single `elan` download and nothing is cached outside `~/.elan`. There is no
`sorry`, `axiom` or `admit` anywhere; `AceAudit/Check.lean` prints the axiom
dependencies of every theorem named in this file and in FINDINGS.md on each
build, which is the mechanical version of that claim. `propext` and `Quot.sound` come from `omega`'s
internals; neither is an assumption about the subject matter.

## What is proved

`AceAudit/Soundness.lean`, verbatim:

```lean
/-- **The joint invariant is inductive.**  Every reachable state of `T_V2`
satisfies `J`: its program counter is a live context whose invariant holds, and
the stack is a chain of intact frames. -/
theorem reach_J (V : VC X) (E : Extra X) {σ : St X.S}
    (h : Reach X σ) : J X σ

/-- Every reachable program counter is a live context. -/
theorem reach_live (V : VC X) (E : Extra X) {σ : St X.S} (h : Reach X σ) :
    ∃ r : X.S.Rtn, Live X ⟨σ.pc, r, σ.en⟩

/-- **The safety property.**  Every reachable program counter is in the safe
set.  (Conclusion of spec section 5, for `T_V2`.) -/
theorem reach_safe (V : VC X) (E : Extra X) {σ : St X.S} (h : Reach X σ) :
    X.C.safe σ.pc
```

`X : Setup` bundles the parameters (signature, layout, program, machine,
certificate); `V : VC X` is the conjunction of the verification conditions;
`E : Extra X` is the conjunction of the three hypotheses that no verification
condition supplies (F1, F2, F3 of FINDINGS.md). The two structural lemmas
that carry the argument are `chain_step_preserve` and `chain_pop`, the two
halves of the frame rule.

### The global invariant, stated explicitly

This is the choice the paper argument leaves implicit, and the real content of
the mechanisation. From `AceAudit/Spec.lean`:

```lean
def ChainStep (X : Setup) (σ : St X.S) (cur : X.S.Rtn) (g : Ghosts X.S)
    (f : Frame X.S) : Prop :=
  f.inner = cur
  ∧ f.innerG = g
  ∧ g.s0 ≤ f.saved.sp
  ∧ Sub (X.C.mod cur) (X.C.mod f.rtn)
  ∧ X.C.Inv ⟨f.saved.pc, f.rtn, f.saved.en⟩ f.g f.saved
  ∧ AgreeOutside (junk X cur f.saved.sp) f.saved σ
  ∧ Resumes X f

def Chain (X : Setup) :
    St X.S → X.S.Rtn → Ghosts X.S → List (Frame X.S) → Prop
  | _, cur, _, [] => cur = X.P.root
  | σ, cur, g, f :: fs => ChainStep X σ cur g f ∧ Chain X f.saved f.rtn f.g fs

def J (X : Setup) (σ : St X.S) : Prop :=
  ∃ (cur : X.S.Rtn) (g : Ghosts X.S) (fs : List (Frame X.S)),
    X.C.Inv ⟨σ.pc, cur, σ.en⟩ g σ ∧ Chain X σ cur g fs
```

In words. The state is running activation `cur` with ghosts `g`, whose
context invariant holds. Below it is a list of suspended activations. Each
`Frame` remembers the suspended routine, its ghosts, **the state at the moment
it was suspended**, and which routine it is suspended inside. The chain says,
for each of them: its invariant held of its saved state, and the state now
differs from that saved state only inside the junk region of what is running
on top of it -- `junk r s = Mod[r] ∪ (the stack at or below s) ∪ registers and
flags`. The remaining conjuncts are what makes the junk regions nest down the
chain (`Mod` containment, and the bases decreasing), which is what lets the
frame rule be applied at an arbitrary depth.

The same frame mechanism serves calls and interrupts: a `Frame` is pushed by
`JSR` and by interrupt entry alike, with `viaCall` recording which, and
`Resumes` recording the premise the corresponding resume condition will need.
Unifying them is what makes F2 visible -- the interrupt case is missing the
`Mod` containment that `VC-CALL` (4) supplies for calls.

## Map: Lean definition -> spec section -> checker

| Lean | `JOINT_INVARIANT.md` | `formal/verify/certificate.py` |
|---|---|---|
| `Sig`, `St`, `Ghosts` | §3 (abstract state, `depth`, ghosts) | `symexec.State`, `Ghosts` |
| `Ctx` | §7.3 (contexts are `(pc, routine, en)`) | `Context`, `parse_context` |
| `Layout.stackAddr`, `scratch` | §3 (entry frame, stack area) | `_stack_cell` |
| `Layout.decodeRet` | §3 (the entry frame is intact) | `_frame_terms` |
| `Layout.volatile` | §3 (registers, flags) | `State.a/x/y/c/z/n/v/i` |
| `AgreeOutside` | §4 `VC-CALL` (3) ("replaced by fresh values") | `_havoc_callee` |
| `Prog` | §2 (routines, roots, `N`) | `CFG`, `Flow`, `analysis.stack` |
| `Machine` | §1 (`T_V2`), §4 (successors) | `formal/model/transitions.py`, `cpu.step`, `cpu.enter_interrupt`, `cpu.reset` |
| `Cert.Inv` | §2, §3 | `Invariant`, `Checker.invariant` |
| `Cert.mod` / `use` / `post` | §2 (`Mod[r]`, `use[r]`, `Post[r]`) | `Routine.mod/use/post`, `Post` |
| `Cert.window` | §1 `MA-NMI-EDGE`/`MA-NMI-LATENCY`, §7.3 | `Checker.windows` |
| `Cert.safe` | §4 `VC-SAFETY` | `Checker.vc_safety` |
| `VC.cold` | §4 `VC-COLD` | `Checker.vc_cold` |
| `VC.stepInv` | §4 `VC-STEP` | `Checker.check_context` |
| `VC.stepMod` | §4 `VC-MOD` | `Checker._mod_claim` |
| `VC.depth` | §3 (`depth`, `S = S0 - depth`) | `Invariant.formula` (**see F5: not implied**) |
| `VC.callEntry` | §4 `VC-CALL` (1) | `Checker.vc_call`, `VC-CALL-ENTRY` |
| `VC.callMod` | §4 `VC-CALL` (4) | `Checker.vc_call`, `VC-CALL-MOD` |
| `VC.callReturn` | §4 `VC-CALL` (3) | `Checker.vc_call`, `VC-CALL-RETURN`, `_havoc_callee` |
| `VC.callNormal` | §7 (a call target must have a contract) | `Checker.vc_call` kind check |
| `VC.retFrame` | §4 `VC-RET` as fixed by §7.1 | `Checker.vc_ret`, `VC-RET-FRAME` |
| `VC.retPost` | §4 `VC-RET` | `Checker.vc_ret`, `VC-RET-POST` |
| `VC.retNormal` | §7.1 | `Checker.vc_ret` kind check |
| `VC.aentInv` | §4 `VC-NMI-ENTRY` | `Checker.vc_nmi`, `VC-NMI-ENTRY` |
| `VC.aentResume` | §4 `VC-NMI-RESUME` | `Checker.vc_nmi`, `VC-NMI-RESUME` |
| `VC.aretFrame` | §4 `VC-NMI-EXIT` as fixed by §7.1 | `Checker.vc_nmi_exit` |
| `VC.aretPost` | §4 `VC-NMI-EXIT` | `Checker.vc_nmi_exit`, `VC-NMI-EXIT-IFRAME` |
| `VC.aretHandler` | §7.1 (`RTI` only in the handler) | `Checker.vc_nmi_exit` kind check |
| `VC.reset` | §4 `VC-RESET` | `Checker.vc_reset` |
| `VC.safety` | §4 `VC-SAFETY` | `Checker.vc_safety` |
| `Extra.window` | **nothing** (F1) | `Checker.vc_nmi` window short-circuit |
| `Extra.handlerMod` | **nothing** (F2) | -- |
| `Extra.postAret` | **nothing** (F3) | -- |
| `ChainStep`, `Chain`, `J` | §5 ("the stack is a chain of intact frames") | -- (was the paper argument) |
| `reach_safe` | §5 (the conclusion) | -- (was the paper argument) |

`VC-DISPATCH` has no row of its own: its conclusion is the invariant at each
table entry in the *same* routine at the *same* depth (§4: "the targets are
part of the calling routine's body"), so it is an instance of `VC.stepInv` and
`VC.stepMod`, with `Machine.step` understood to include the
`JSR`-to-JumpEngine composite transition. `VC-DISPATCH-TARGET`,
`VC-DISPATCH-INDEX` and the engine's own writes are then exactly what makes
that instance true, and they are checked in Python.

## What this mechanisation does NOT cover

Plainly, because the theorem above is only as strong as this list is honest.

1. **The 6502.** `Machine` is seven opaque relations (the six transition
   relations and the set of cold-boot states) plus nineteen constraints
   linking control flow to the stack (`callSp`, `retTarget`, `aentAgree`,
   ...). Nothing checks that `formal/model/transitions.py` and
   `cpu.step` satisfy them. In particular the mechanisation never decodes an
   instruction, and `Layout.decodeRet` is an opaque function rather than a
   little-endian read of two bytes.
2. **The SMT encoding of each verification condition.** `VC` says what each
   condition must mean; `certificate.py` builds a z3 query it believes has
   that meaning. The correspondence is by inspection -- that inspection is
   how F3, F4 and F5 were found -- and is not itself checked. Specifically
   unchecked: `Invariant.formula`, `Post.formula`, `_mod_claim`,
   `_frame_terms`, `_zero_run_terms`, `_engine_target`, and every z3 `sat`/
   `unsat` verdict.
3. **The checker's Python.** Context parsing, the CFG, the routine-entry
   analysis, the `rom_axiom_cap` and solver-timeout cutoffs (an `unknown`
   verdict is not `holds`, and nothing here knows the difference), and the
   proposer in `formal/analysis/`.
4. **The model assumptions.** `MA-CPU`, `MA-PPU-POWERON`, `MA-PPU-WARMUP`,
   `MA-NMI-EDGE`, `MA-NMI-LATENCY`, `MA-PPU-RESET`. These are about the
   hardware, and they are what `Cert.window` and the `Machine` fields stand in
   for.
5. **Stack-pointer wraparound.** `St.sp : Int`, so the model cannot wrap.
   See F5: this is the one place where the mechanisation assumes something a
   verification condition ought to check.
6. **The extensions of §7.2** (`rel`, `zero_runs`, `zero_pages`, `copies`,
   `keeps`, `preserves`, `en_bit`, `no_ppu`) and the §7.1 additions `VC-IRQ`,
   `VC-FORBIDDEN`, `VC-COVERAGE`, `VC-DISPATCH-TARGET` and the `TXS`
   restriction. `Cert.Inv`, `Cert.post` and `Cert.safe` are abstract
   predicates, so everything in §7.2 is inside them, and the §7.1 additions
   are what make `Prog`'s classification of program points (`isCallSite`,
   `isRetSite`, `isRtiSite`) exhaustive and the IRQ transition absent from
   `Machine`. Both are assumptions here.

## Files

| File | Contents |
|---|---|
| `AceAudit/Basic.lean` | regions and `Sub`; `Sig`, `St`, `Ghosts`, `Ctx`; `AgreeOutside`; `Layout`, `stackAtOrBelow`, `scratch` |
| `AceAudit/Spec.lean` | `Prog`, `Machine`, `Cert`, `Setup`, `junk` and `junk_mono`; `VC`; `Extra`; `Frame`, `Resumes`, `ChainStep`, `Chain`, `J`; `Reach` |
| `AceAudit/Soundness.lean` | `chain_step_preserve`, `chain_pop`, `reach_J`, `reach_live`, `reach_safe` |
| `AceAudit/GapWindow.lean` | a concrete certificate satisfying every verification condition whose safety property is false (F1) |
| `AceAudit/Check.lean` | `#print axioms` on every exported theorem, on every build |
| `FINDINGS.md` | the five findings, with the fix for each |
