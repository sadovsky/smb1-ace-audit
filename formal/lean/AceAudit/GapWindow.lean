/-
# F1 is a real soundness hole, not an artefact of this proof

`Extra.window` is the hypothesis that the certificate's `nmi_windows` really
are points at which the transition relation takes no interrupt.  Nothing in
spec section 4 establishes it, and `Checker.vc_nmi` returns `HOLDS` for a
windowed context without asking the solver anything.

This file builds a concrete instance of the whole framework in which

* every verification condition of `VC` holds (`gapVC`), and
* a reachable state's program counter is outside the safe set
  (`reach_bad`, `bad_unsafe`),

so by `reach_safe` there can be no `Extra` for it (`no_extra`).  That is: the
verification conditions as specified do **not** imply the safety property.  It
also shows `VC` is satisfiable, so the soundness theorem is not vacuous.

The instance is the smallest one that exhibits the hole: one ordinary
instruction `p` which the certificate declares to be inside a timing window,
one handler entry `h` outside the safe set, and a machine that takes an
interrupt at `p` anyway.
-/
import AceAudit.Soundness

namespace AceAudit
namespace GapWindow

/-- Two program counters and two routine names, both `Bool`: `false` is the
ordinary instruction `p` / the root routine, `true` is the handler entry `h` /
the handler. -/
def sg : Sig := { Addr := Unit, Val := Unit, PC := Bool, Rtn := Bool }

def lay : Layout sg :=
  { stackAddr := fun _ => ()
    volatile := fun _ => True
    decodeRet := fun _ _ _ => false }

def prg : Prog sg :=
  { entryPc := fun r => r
    retPc := fun _ => false
    root := false
    handler := true
    isNormal := fun _ => False
    isCallSite := fun _ _ => False
    isRetSite := fun _ => False
    isRtiSite := fun _ => False
    rootNotNormal := fun h => h
    handlerNotNormal := fun h => h
    rootNeHandler := fun h => Bool.noConfusion h }

/-- The reachable state inside the window: the enable bit is set. -/
def good : St sg := { pc := false, sp := 0, mem := fun _ => (), en := true }

/-- Where the interrupt lands: the handler entry, outside the safe set. -/
def bad : St sg := { pc := true, sp := -3, mem := fun _ => (), en := true }

def mach : Machine sg lay prg :=
  { init := fun σ => σ = good
    step := fun _ _ => False
    call := fun _ _ _ => False
    ret := fun _ _ => False
    aent := fun σ σ' => σ = good ∧ σ' = bad
    aret := fun _ _ => False
    rst := fun _ _ => False
    stepSite := fun _ _ h => h.elim
    callSite := fun _ _ _ h => h.elim
    callPc := fun _ _ _ h => h.elim
    retSite := fun _ _ h => h.elim
    aretSite := fun _ _ h => h.elim
    aentPc := fun _ _ h => by obtain ⟨_, h2⟩ := h; subst h2; rfl
    rstPc := fun _ _ h => h.elim
    initPc := fun _ h => by subst h; rfl
    callSp := fun _ _ _ h => h.elim
    retSp := fun _ _ h => h.elim
    aentSp := fun _ _ h => by obtain ⟨h1, h2⟩ := h; subst h1; subst h2; decide
    aretSp := fun _ _ h => h.elim
    retTarget := fun _ _ h => h.elim
    aretTarget := fun _ _ h => h.elim
    callAgree := fun _ _ _ h => h.elim
    aentAgree := fun _ _ _ _ _ => rfl
    retAgree := fun _ _ h => h.elim
    aretAgree := fun _ _ h => h.elim
    aentEnabled := fun _ _ h => by obtain ⟨h1, _⟩ := h; subst h1; rfl }

/-- The certificate: one live context, at `p`, in the root routine.  It
declares `p` to be inside a timing window, which is exactly the claim the
checker takes on trust. -/
def cert : Cert sg :=
  { Inv := fun c g σ => c.pc = false ∧ c.rtn = false ∧ σ.pc = false ∧ σ.sp ≤ g.s0
    mod := fun _ _ => False
    use := fun _ => 0
    post := fun _ _ _ => True
    window := fun pc => pc = false
    safe := fun pc => pc = false }

def X : Setup := { S := sg, L := lay, P := prg, M := mach, C := cert }

/-- Every verification condition of spec section 4 holds of this certificate. -/
theorem gapVC : VC X :=
  { cold := fun σ h => by
      subst h
      refine ⟨rfl, rfl, rfl, ?_⟩
      show (0 : Int) ≤ 0
      omega
    stepInv := fun _ _ _ _ _ h => h.elim
    stepMod := fun _ _ _ _ _ h => h.elim
    depth := fun _ _ _ h => h.2.2.2
    callEntry := fun _ _ _ _ _ _ h _ => h.elim
    callMod := fun _ _ _ _ _ h => h.elim
    callNormal := fun _ _ _ _ _ h => h.elim
    callReturn := fun _ _ _ _ _ _ _ h _ _ _ _ => h.elim
    retFrame := fun _ _ _ _ h => h.elim
    retNormal := fun _ _ _ _ h => h.elim
    retPost := fun _ _ _ _ _ h _ => h.elim
    aentInv := fun _ _ _ _ hInv _ hnw _ => absurd hInv.1 hnw
    aentResume := fun _ _ _ _ _ hInv _ hnw _ _ _ _ => absurd hInv.1 hnw
    aretFrame := fun _ _ _ _ h => h.elim
    aretHandler := fun _ _ _ _ h => h.elim
    aretPost := fun _ _ _ _ h => h.elim
    reset := fun _ _ h => h.elim
    safety := fun _ _ _ h => h.1 }

/-- The machine takes an interrupt at `p`, which the certificate says is
inside a timing window. -/
theorem aent_good_bad : X.M.aent good bad := by
  show good = good ∧ bad = bad
  exact ⟨rfl, rfl⟩

/-- The bad state is reachable: cold boot, then an interrupt taken at `p`. -/
theorem init_good : X.M.init good := by
  show good = good
  rfl

theorem reach_bad : Reach X bad :=
  Reach.viaAent (X := X) good bad (Reach.init (X := X) good init_good) aent_good_bad

/-- ... and its program counter is not in the safe set. -/
theorem bad_unsafe : ¬ X.C.safe bad.pc := by
  intro h
  have h' : (true : Bool) = false := h
  exact Bool.noConfusion h'

/-- Therefore no `Extra X` exists: the verification conditions of spec
section 4 do not imply the safety property, and the missing hypothesis is the
one `Extra.window` names. -/
theorem no_extra (E : Extra X) : False :=
  bad_unsafe (reach_safe X gapVC E reach_bad)

end GapWindow
end AceAudit
