/-
# The program, the machine, the certificate and the verification conditions

This file states, as `Prop`s over the abstract model of `Basic.lean`:

* `Prog`   -- the structural facts the checker reads from the image (spec §2);
* `Machine`-- the transition relation as a union of step / call / return /
              async-entry / async-return / reset, with the *minimum* linkage
              between control flow and the stack that the proof needs (§1, §4);
* `Cert`   -- the certificate objects: context invariants, `Mod`, `use`,
              `Post`, the NMI windows and the safe set (§2, §3);
* `VC`     -- one field per verification condition of §4 (plus the §7.1 fixes);
* `Extra`  -- the hypotheses the soundness proof needs that **no** verification
              condition supplies.  Each is a finding; see FINDINGS.md.
-/
import AceAudit.Basic

namespace AceAudit

/-! ## The program -/

/-- Structural data about the image.  The checker computes all of this from
the CFG (`formal/analysis`, `graph.nodes`, `Flow`); here it is a parameter and
the `Machine` fields below say how it must agree with the semantics. -/
structure Prog (S : Sig) where
  /-- The first instruction of a routine. -/
  entryPc : S.Rtn → S.PC
  /-- The instruction after a call site (`instruction.end`). -/
  retPc : S.PC → S.PC
  /-- The reset routine and the NMI handler (spec §2: two of the three roots;
  the IRQ root is excluded by `VC-IRQ`, which is outside this mechanisation). -/
  root : S.Rtn
  handler : S.Rtn
  /-- `Routine.kind = "normal"`: a routine that may be called and returns. -/
  isNormal : S.Rtn → Prop
  /-- `pc` is a `JSR q` (`Flow.CALL`, resolved callee `q`). -/
  isCallSite : S.PC → S.Rtn → Prop
  /-- `pc` is an `RTS`. -/
  isRetSite : S.PC → Prop
  /-- `pc` is an `RTI`. -/
  isRtiSite : S.PC → Prop
  rootNotNormal : ¬ isNormal root
  handlerNotNormal : ¬ isNormal handler
  rootNeHandler : root ≠ handler

/-! ## The machine -/

/-- The transition relation of `T_V2`, as a union of six relations, together
with the facts about them that the soundness proof uses.  Everything here is
discharged outside this mechanisation, by `formal/model/transitions.py` and
`cpu.step` (see README.md, "What this does not cover").

The `*Agree` fields are the honest statement of "this transition writes only
to the scratch area": the pushed frame lies in the stack at or below the
current pointer, and registers and flags are `volatile`. -/
structure Machine (S : Sig) (L : Layout S) (P : Prog S) where
  /-- The cold-boot states. -/
  init : St S → Prop
  /-- An ordinary instruction, including the `JSR`-to-JumpEngine composite
  transition that `VC-DISPATCH` discharges (its targets belong to the calling
  routine, spec §4). -/
  step : St S → St S → Prop
  /-- `JSR q`. -/
  call : St S → St S → S.Rtn → Prop
  /-- `RTS`. -/
  ret : St S → St S → Prop
  /-- Interrupt entry. -/
  aent : St S → St S → Prop
  /-- `RTI`. -/
  aret : St S → St S → Prop
  /-- Warm reset, available at every instruction boundary. -/
  rst : St S → St S → Prop
  -- control-flow classification
  stepSite : ∀ σ σ', step σ σ' →
    (∀ q, ¬ P.isCallSite σ.pc q) ∧ ¬ P.isRetSite σ.pc ∧ ¬ P.isRtiSite σ.pc
  callSite : ∀ σ σ' q, call σ σ' q → P.isCallSite σ.pc q
  callPc : ∀ σ σ' q, call σ σ' q → σ'.pc = P.entryPc q
  retSite : ∀ σ σ', ret σ σ' → P.isRetSite σ.pc
  aretSite : ∀ σ σ', aret σ σ' → P.isRtiSite σ.pc
  aentPc : ∀ σ σ', aent σ σ' → σ'.pc = P.entryPc P.handler
  rstPc : ∀ σ σ', rst σ σ' → σ'.pc = P.entryPc P.root
  initPc : ∀ σ, init σ → σ.pc = P.entryPc P.root
  -- stack discipline
  callSp : ∀ σ σ' q, call σ σ' q → σ'.sp = σ.sp - 2
  retSp : ∀ σ σ', ret σ σ' → σ'.sp = σ.sp + 2
  aentSp : ∀ σ σ', aent σ σ' → σ'.sp = σ.sp - 3
  aretSp : ∀ σ σ', aret σ σ' → σ'.sp = σ.sp + 3
  -- the return address comes out of the frame the entry pushed
  retTarget : ∀ σ σ', ret σ σ' → σ'.pc = L.decodeRet 2 σ.mem σ.sp
  aretTarget : ∀ σ σ', aret σ σ' → σ'.pc = L.decodeRet 3 σ.mem σ.sp
  -- footprints
  callAgree : ∀ σ σ' q, call σ σ' q → AgreeOutside (scratch L σ.sp) σ σ'
  aentAgree : ∀ σ σ', aent σ σ' → AgreeOutside (scratch L σ.sp) σ σ'
  retAgree : ∀ σ σ', ret σ σ' → AgreeOutside L.volatile σ σ'
  aretAgree : ∀ σ σ', aret σ σ' → AgreeOutside L.volatile σ σ'
  /-- An interrupt is taken only with the ghost enable bit set. -/
  aentEnabled : ∀ σ σ', aent σ σ' → σ.en = true

/-! ## The certificate -/

/-- The certificate objects of spec §2 and §3, as the checker parses them
(`certificate.Invariant`, `certificate.Routine`, `certificate.Post`).

A context the certificate does not mention has `Inv` false, so there is no
separate liveness map: `Live c` below is `∃ g σ, Inv c g σ`. -/
structure Cert (S : Sig) where
  /-- `Inv[(pc, routine, en)]`, as a predicate on the ghosts and the state. -/
  Inv : Ctx S → Ghosts S → St S → Prop
  /-- `Mod[r]`. -/
  mod : S.Rtn → S.Addr → Prop
  /-- `use[r]`: bytes of stack below `s0` the routine may use.  Recorded
  because the spec has it; the soundness proof does **not** use it (F5). -/
  use : S.Rtn → Int
  /-- `Post[r]`, as a relation between the entry state and the exit state, so
  that `preserves`/`keeps` are expressible. -/
  post : S.Rtn → St S → St S → Prop
  /-- The program points at which `MA-NMI-EDGE` / `MA-NMI-LATENCY` say no
  interrupt is taken (`certificate.nmi_windows`). -/
  window : S.PC → Prop
  /-- The safety property's set of allowed program counters (`VC-SAFETY`). -/
  safe : S.PC → Prop

/-- Everything the soundness theorem is parameterised by. -/
structure Setup where
  S : Sig
  L : Layout S
  P : Prog S
  M : Machine S L P
  C : Cert S

/-- A context is live when its invariant is satisfiable. -/
def Live (X : Setup) (c : Ctx X.S) : Prop := ∃ g σ, X.C.Inv c g σ

/-- The region a routine `r` based at stack pointer `s` may change: its `Mod`
set, the stack at or below its base, and the registers and flags.

This is the junk region of the frame rule.  It is deliberately *coarser* than
the checker's `[s0-use+1, s0]` stack window: coarser makes the frame rule's
hypothesis stronger and therefore the obligation harder, and it is what makes
the region nest down the call chain (see FINDINGS.md F4). -/
def junk (X : Setup) (r : X.S.Rtn) (s : Int) : X.S.Addr → Prop :=
  fun a => X.C.mod r a ∨ scratch X.L s a

theorem scratch_sub_junk (X : Setup) (r : X.S.Rtn) (s : Int) :
    Sub (scratch X.L s) (junk X r s) := fun _ h => Or.inr h

theorem volatile_sub_junk (X : Setup) (r : X.S.Rtn) (s : Int) :
    Sub X.L.volatile (junk X r s) := fun _ h => Or.inr (Or.inr h)

/-- The junk regions nest: a callee with a smaller `Mod` set and a lower base
can only disturb what its caller was already allowed to disturb. -/
theorem junk_mono (X : Setup) {r r' : X.S.Rtn} {s s' : Int}
    (hm : Sub (X.C.mod r) (X.C.mod r')) (hs : s ≤ s') :
    Sub (junk X r s) (junk X r' s') := by
  intro a ha
  rcases ha with ha | ha
  · exact Or.inl (hm a ha)
  · exact Or.inr (scratch_mono X.L hs a ha)

/-! ## Verification conditions

One field per verification condition of spec §4, in the form the checker
`formal/verify/certificate.py` asks z3 for.  Where §7.1 strengthens §4, the
field states the strengthened version and says so. -/
structure VC (X : Setup) where
  /-- `VC-COLD` (`Checker.vc_cold`). -/
  cold : ∀ σ, X.M.init σ →
    X.C.Inv ⟨σ.pc, X.P.root, σ.en⟩ ⟨σ.sp, σ.pc, σ⟩ σ
  /-- `VC-STEP` (`Checker.check_context`): every successor satisfies the
  invariant of its context, in the same routine with the same ghosts. -/
  stepInv : ∀ c g σ σ', X.C.Inv c g σ → X.M.step σ σ' →
    X.C.Inv ⟨σ'.pc, c.rtn, σ'.en⟩ g σ'
  /-- `VC-MOD` (`Checker._mod_claim`): every write targets `Mod[r]` or the
  routine's own stack area.  Stated as agreement outside the junk region. -/
  stepMod : ∀ c g σ σ', X.C.Inv c g σ → X.M.step σ σ' →
    AgreeOutside (junk X c.rtn g.s0) σ σ'
  /-- `depth` is a set of non-negative integers with `S = s0 - depth`
  (spec §3), so the stack pointer never rises above the entry pointer. -/
  depth : ∀ c g σ, X.C.Inv c g σ → σ.sp ≤ g.s0
  /-- `VC-CALL` (1) (`VC-CALL-ENTRY`): the state after the `JSR` satisfies the
  callee's entry invariant, with the callee's ghosts fixed here. -/
  callEntry : ∀ c g σ σ' q, X.C.Inv c g σ → X.P.isCallSite c.pc q →
    X.M.call σ σ' q →
    X.C.Inv ⟨σ'.pc, q, σ'.en⟩ ⟨σ'.sp, X.P.retPc c.pc, σ'⟩ σ'
  /-- `VC-CALL` (4) (`VC-CALL-MOD`): `Mod[q] ⊆ Mod[r]`. -/
  callMod : ∀ c g σ q, X.C.Inv c g σ → X.P.isCallSite c.pc q →
    Sub (X.C.mod q) (X.C.mod c.rtn)
  /-- `Checker.vc_call`: a call target must be a `normal` routine. -/
  callNormal : ∀ c g σ q, X.C.Inv c g σ → X.P.isCallSite c.pc q →
    X.P.isNormal q
  /-- `VC-CALL` (3) (`VC-CALL-RETURN`), the frame rule: for *every* state that
  agrees with the pre-call state outside the callee's junk region, restores the
  stack pointer, and satisfies `Post[q]`, the return point's invariant holds. -/
  callReturn : ∀ c g σ σe σ' q, X.C.Inv c g σ → X.P.isCallSite c.pc q →
    X.M.call σ σe q →
    AgreeOutside (junk X q σ.sp) σ σ' → σ'.sp = σ.sp → X.C.post q σe σ' →
    X.C.Inv ⟨X.P.retPc c.pc, c.rtn, σ'.en⟩ g σ'
  /-- `VC-RET` as strengthened in spec §7.1 (`Checker.vc_ret`,
  `VC-RET-FRAME`): depth `0` **and** the entry frame asserted intact. -/
  retFrame : ∀ c g σ, X.C.Inv c g σ → X.P.isRetSite c.pc →
    σ.sp = g.s0 ∧ X.L.decodeRet 2 σ.mem g.s0 = g.ret
  /-- `Checker.vc_ret`: an `RTS` only in a `normal` routine. -/
  retNormal : ∀ c g σ, X.C.Inv c g σ → X.P.isRetSite c.pc → X.P.isNormal c.rtn
  /-- `VC-RET` (`VC-RET-POST`): the post-`RTS` state satisfies `Post[r]`. -/
  retPost : ∀ c g σ σ', X.C.Inv c g σ → X.P.isRetSite c.pc → X.M.ret σ σ' →
    X.C.post c.rtn g.entry σ'
  /-- `VC-NMI-ENTRY` (`Checker.vc_nmi`): for a context whose enable bit may be
  set and which is not in a timing window, the state after interrupt entry
  satisfies the handler's entry invariant.  The handler's ghost return address
  is the interrupted program counter. -/
  aentInv : ∀ c g σ σ', X.C.Inv c g σ → c.en = true → ¬ X.C.window c.pc →
    X.M.aent σ σ' →
    X.C.Inv ⟨σ'.pc, X.P.handler, σ'.en⟩ ⟨σ'.sp, c.pc, σ'⟩ σ'
  /-- `VC-NMI-RESUME` (`Checker.vc_nmi`): the interrupted context's invariant
  holds again of any state that agrees with it outside the handler's junk
  region, restores the stack pointer and satisfies `Post[H]`. -/
  aentResume : ∀ c g σ σe σ', X.C.Inv c g σ → c.en = true →
    ¬ X.C.window c.pc → X.M.aent σ σe →
    AgreeOutside (junk X X.P.handler σ.sp) σ σ' → σ'.sp = σ.sp →
    X.C.post X.P.handler σe σ' →
    X.C.Inv ⟨c.pc, c.rtn, σ'.en⟩ g σ'
  /-- `VC-NMI-EXIT` as strengthened in spec §7.1 (`Checker.vc_nmi_exit`):
  depth `0` and the three-byte interrupt frame asserted intact. -/
  aretFrame : ∀ c g σ, X.C.Inv c g σ → X.P.isRtiSite c.pc →
    σ.sp = g.s0 ∧ X.L.decodeRet 3 σ.mem g.s0 = g.ret
  /-- `Checker.vc_nmi_exit`: an `RTI` only in the handler. -/
  aretHandler : ∀ c g σ, X.C.Inv c g σ → X.P.isRtiSite c.pc →
    c.rtn = X.P.handler
  /-- `VC-NMI-EXIT` (`VC-NMI-EXIT-IFRAME`): `Post[H]` holds of the state **at**
  the `RTI`, before the return transition.  This is what the checker asks;
  compare `Extra.postAret` (F3). -/
  aretPost : ∀ c g σ, X.C.Inv c g σ → X.P.isRtiSite c.pc →
    X.C.post X.P.handler g.entry σ
  /-- `VC-RESET` (`Checker.vc_reset`): the state after a warm reset satisfies
  the root's entry invariant. -/
  reset : ∀ σ σ', X.M.rst σ σ' →
    X.C.Inv ⟨σ'.pc, X.P.root, σ'.en⟩ ⟨σ'.sp, σ'.pc, σ'⟩ σ'
  /-- `VC-SAFETY` (`Checker.vc_safety`): every live context is safe. -/
  safety : ∀ c g σ, X.C.Inv c g σ → X.C.safe c.pc

/-! ## The hypotheses no verification condition supplies

Each field here is a gap: the soundness proof below needs it and nothing in
spec §4 or in `certificate.py` establishes it.  See FINDINGS.md. -/
structure Extra (X : Setup) where
  /-- **F1** The timing windows are trusted from the certificate.  Spec §4
  excludes the windows from `VC-NMI-ENTRY`/`VC-NMI-RESUME` and
  `Checker.vc_nmi` returns `HOLDS` for them without any query, so nothing
  connects `C.window` to the transition relation. -/
  window : ∀ c g σ σ', X.C.Inv c g σ → X.C.window c.pc → ¬ X.M.aent σ σ'
  /-- **F2** An interrupt taken inside a callee is not charged to the
  contracts of the routines suspended further down the stack.  The proof needs
  the handler's `Mod` set to be contained in the `Mod` set of every
  interruptible routine. -/
  handlerMod : ∀ c g σ, X.C.Inv c g σ → c.en = true → ¬ X.C.window c.pc →
    Sub (X.C.mod X.P.handler) (X.C.mod c.rtn)
  /-- **F3** `VC-NMI-EXIT` checks `Post[H]` of the pre-`RTI` state while
  `VC-NMI-RESUME` assumes it of the post-`RTI` state.  The proof needs
  `Post[H]` to survive the `RTI`. -/
  postAret : ∀ e σ σ', X.M.aret σ σ' →
    X.C.post X.P.handler e σ → X.C.post X.P.handler e σ'

/-! ## The global invariant

The stack is a chain of intact frames.  One `Frame` records a suspended
activation: the routine, its ghosts, the state at the moment it was suspended,
and which routine it is suspended inside, with that routine's ghosts.  A frame
is pushed by a call and by an interrupt entry alike; `viaCall` says which. -/
structure Frame (S : Sig) where
  /-- The suspended routine. -/
  rtn : S.Rtn
  /-- Its ghosts. -/
  g : Ghosts S
  /-- The state at the moment of suspension; `saved.pc` is the call site, or
  the interrupted instruction. -/
  saved : St S
  /-- The routine it is suspended inside. -/
  inner : S.Rtn
  /-- That routine's ghosts. -/
  innerG : Ghosts S
  /-- `true` for a call, `false` for an interrupt entry. -/
  viaCall : Bool

/-- How the frame came to be, and the link between the suspended activation's
ghosts and the inner activation's ghosts.  This is the premise the resume
verification condition needs when control comes back. -/
def Resumes (X : Setup) (f : Frame X.S) : Prop :=
  (f.viaCall = true ∧ X.P.isCallSite f.saved.pc f.inner
      ∧ X.M.call f.saved f.innerG.entry f.inner
      ∧ f.innerG.s0 = f.innerG.entry.sp
      ∧ f.innerG.ret = X.P.retPc f.saved.pc)
  ∨ (f.viaCall = false ∧ f.inner = X.P.handler
      ∧ f.saved.en = true ∧ ¬ X.C.window f.saved.pc
      ∧ X.M.aent f.saved f.innerG.entry
      ∧ f.innerG.s0 = f.innerG.entry.sp
      ∧ f.innerG.ret = f.saved.pc)

/-- One link of the chain: the frame `f` is immediately below the activation
`(cur, g)`, running in state `σ`.

The crucial conjunct is the last agreement: **the suspended caller's invariant
holds of its saved state, and the current state differs from that saved state
only inside the junk region of what is running on top of it**.  That is the
frame rule's hypothesis, carried across arbitrarily many transitions. -/
def ChainStep (X : Setup) (σ : St X.S) (cur : X.S.Rtn) (g : Ghosts X.S)
    (f : Frame X.S) : Prop :=
  f.inner = cur
  ∧ f.innerG = g
  ∧ g.s0 ≤ f.saved.sp
  ∧ Sub (X.C.mod cur) (X.C.mod f.rtn)
  ∧ X.C.Inv ⟨f.saved.pc, f.rtn, f.saved.en⟩ f.g f.saved
  ∧ AgreeOutside (junk X cur f.saved.sp) f.saved σ
  ∧ Resumes X f

/-- The stack is a chain of intact frames.  The empty chain is the root
routine, which is never returned from. -/
def Chain (X : Setup) :
    St X.S → X.S.Rtn → Ghosts X.S → List (Frame X.S) → Prop
  | _, cur, _, [] => cur = X.P.root
  | σ, cur, g, f :: fs => ChainStep X σ cur g f ∧ Chain X f.saved f.rtn f.g fs

/-- **The joint invariant** (spec §5): the program counter is a live context
whose invariant holds of the current state, and the stack is a chain of intact
frames, each suspended caller's invariant holding modulo its callee's `Mod` set
and stack range. -/
def J (X : Setup) (σ : St X.S) : Prop :=
  ∃ (cur : X.S.Rtn) (g : Ghosts X.S) (fs : List (Frame X.S)),
    X.C.Inv ⟨σ.pc, cur, σ.en⟩ g σ ∧ Chain X σ cur g fs

/-! ## Reachability -/

/-- The reachable states of `T_V2`: the transition relation is the union of
the six relations of `Machine`. -/
inductive Reach (X : Setup) : St X.S → Prop
  | init (σ) : X.M.init σ → Reach X σ
  | viaStep (σ σ') : Reach X σ → X.M.step σ σ' → Reach X σ'
  | viaCall (σ σ' q) : Reach X σ → X.M.call σ σ' q → Reach X σ'
  | viaRet (σ σ') : Reach X σ → X.M.ret σ σ' → Reach X σ'
  | viaAent (σ σ') : Reach X σ → X.M.aent σ σ' → Reach X σ'
  | viaAret (σ σ') : Reach X σ → X.M.aret σ σ' → Reach X σ'
  | viaReset (σ σ') : Reach X σ → X.M.rst σ σ' → Reach X σ'

end AceAudit
