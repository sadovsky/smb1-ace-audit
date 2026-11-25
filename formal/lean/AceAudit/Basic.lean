/-
# Abstract state space, regions and layout

Mechanises the parts of `formal/verify/JOINT_INVARIANT.md` sections 2 and 3
that the soundness argument of section 5 actually uses.  Nothing here knows
about the 6502: addresses, values, program counters and routine names are
opaque types, and the only concrete type is `Int`, used for the stack pointer.
-/

namespace AceAudit

/-! ## Regions

A region is a predicate on a type.  `Sub` is containment.  (Lean core has no
`Set`, and this development deliberately does not depend on Mathlib.) -/

/-- `Sub U V`: every element of the region `U` is an element of `V`. -/
def Sub {α : Type} (U V : α → Prop) : Prop := ∀ a, U a → V a

theorem sub_refl {α : Type} (U : α → Prop) : Sub U U := fun _ h => h

theorem sub_trans {α : Type} {U V W : α → Prop}
    (h₁ : Sub U V) (h₂ : Sub V W) : Sub U W := fun a h => h₂ a (h₁ a h)

/-! ## Signature and states -/

/-- The opaque types the whole development is parameterised by.  `Rtn` is the
set of routine names: the entries of `analysis.stack.routine_entries`
(spec section 2). -/
structure Sig where
  Addr : Type
  Val : Type
  PC : Type
  Rtn : Type

/-- A machine state: program counter, stack pointer, memory and the ghost
NMI-enable bit `en` (spec section 3, last bullet).

`mem` is the whole observable store.  Registers and processor flags are
modelled as addresses too -- the ones in `Layout.volatile` -- so that a
routine contract's `Post` can speak about them and so that every transition
that scribbles on them is accounted for by one region. -/
structure St (S : Sig) where
  pc : S.PC
  sp : Int
  mem : S.Addr → S.Val
  en : Bool

/-- The ghosts of one activation of a routine (spec section 3):
`s0` is the stack pointer on entry, `ret` the return address, and `entry` the
state on entry, which is what `Post`'s `preserves`/`keeps` clauses compare
against. -/
structure Ghosts (S : Sig) where
  s0 : Int
  ret : S.PC
  entry : St S

/-- A certificate context: `(pc, routine, en)` (spec section 7.3). -/
structure Ctx (S : Sig) where
  pc : S.PC
  rtn : S.Rtn
  en : Bool

/-! ## Agreement -/

/-- `AgreeOutside U σ σ'`: the two states have the same memory everywhere
outside the region `U`.  This is the semantic content of the checker's
havoc-based verification conditions: "the post-state is the pre-state with
`U` replaced by fresh values". -/
def AgreeOutside {S : Sig} (U : S.Addr → Prop) (σ σ' : St S) : Prop :=
  ∀ a, ¬ U a → σ'.mem a = σ.mem a

/-- Agreement outside a smaller region implies agreement outside a larger one. -/
theorem AgreeOutside.weaken {S : Sig} {U V : S.Addr → Prop} {σ σ' : St S}
    (hs : Sub V U) (h : AgreeOutside V σ σ') : AgreeOutside U σ σ' :=
  fun a ha => h a (fun hv => ha (hs a hv))

theorem AgreeOutside.trans {S : Sig} {U : S.Addr → Prop} {σ₁ σ₂ σ₃ : St S}
    (h₁ : AgreeOutside U σ₁ σ₂) (h₂ : AgreeOutside U σ₂ σ₃) :
    AgreeOutside U σ₁ σ₃ := fun a ha => (h₂ a ha).trans (h₁ a ha)

/-! ## Layout -/

/-- The stack layout and the decoding of return frames.  This is the only
interface to the hardware that the proof uses.

* `stackAddr i` is the address of stack slot `i`.  Slots are indexed by `Int`,
  so the model has **no stack-pointer wraparound**; see FINDINGS.md (F5).
* `volatile` are the addresses that are not memory in the architectural sense:
  registers and flags.  Every transition may change them freely.
* `decodeRet k m s0` is the return address held in the `k`-byte frame saved
  just above slot `s0` in memory `m` (`k = 2` for `JSR`/`RTS`, `k = 3` for an
  interrupt frame, matching `Routine.frame_bytes`). -/
structure Layout (S : Sig) where
  stackAddr : Int → S.Addr
  volatile : S.Addr → Prop
  decodeRet : Nat → (S.Addr → S.Val) → Int → S.PC

/-- The stack slots at or below `s`: the scratch area that anything running
below stack pointer `s` may use. -/
def stackAtOrBelow {S : Sig} (L : Layout S) (s : Int) : S.Addr → Prop :=
  fun a => ∃ i : Int, i ≤ s ∧ a = L.stackAddr i

/-- What any transition may change without being charged to a `Mod` set: the
stack below the current pointer, and the registers and flags. -/
def scratch {S : Sig} (L : Layout S) (s : Int) : S.Addr → Prop :=
  fun a => stackAtOrBelow L s a ∨ L.volatile a

theorem stackAtOrBelow_mono {S : Sig} (L : Layout S) {s s' : Int} (h : s ≤ s') :
    Sub (stackAtOrBelow L s) (stackAtOrBelow L s') := by
  intro a ha
  obtain ⟨i, hi, he⟩ := ha
  exact ⟨i, by omega, he⟩

theorem scratch_mono {S : Sig} (L : Layout S) {s s' : Int} (h : s ≤ s') :
    Sub (scratch L s) (scratch L s') := by
  intro a ha
  rcases ha with ha | ha
  · exact Or.inl (stackAtOrBelow_mono L h a ha)
  · exact Or.inr ha

end AceAudit
