/-
# Soundness of the certificate: the joint invariant is inductive

The theorem of spec section 5, mechanised: if every verification condition
holds (`VC`) and the hypotheses that no verification condition supplies hold
(`Extra`, each one a finding), then the joint invariant `J` holds of every
reachable state, and therefore every reachable program counter is a live
context and lies in the safe set.
-/
import AceAudit.Spec

namespace AceAudit

variable (X : Setup)

/-! ## Unfolding the chain -/

theorem chain_nil {σ : St X.S} {cur : X.S.Rtn} {g : Ghosts X.S} :
    Chain X σ cur g [] ↔ cur = X.P.root := Iff.rfl

theorem chain_cons {σ : St X.S} {cur : X.S.Rtn} {g : Ghosts X.S}
    {f : Frame X.S} {fs : List (Frame X.S)} :
    Chain X σ cur g (f :: fs) ↔
      (ChainStep X σ cur g f ∧ Chain X f.saved f.rtn f.g fs) := Iff.rfl

/-! ## The two structural lemmas about the chain -/

/-- **The frame rule, preservation half.**  A transition of the innermost
activation that stays inside its own junk region leaves the chain of
suspended frames intact.  This is where `VC-MOD` is consumed, and it is the
reason the junk regions have to nest (`junk_mono`). -/
theorem chain_step_preserve {σ σ' : St X.S} {cur : X.S.Rtn} {g : Ghosts X.S}
    {fs : List (Frame X.S)} (hc : Chain X σ cur g fs)
    (ha : AgreeOutside (junk X cur g.s0) σ σ') : Chain X σ' cur g fs := by
  cases fs with
  | nil => exact hc
  | cons f fs =>
      obtain ⟨⟨h1, h2, h3, h4, h5, h6, h7⟩, hrest⟩ := (chain_cons X).1 hc
      refine (chain_cons X).2 ⟨⟨h1, h2, h3, h4, h5, ?_, h7⟩, hrest⟩
      exact AgreeOutside.trans h6
        (AgreeOutside.weaken (junk_mono X (sub_refl _) h3) ha)

/-- **The frame rule, pop half.**  When the innermost activation finishes, the
frame below it becomes the innermost one, and the agreement that its own
suspended caller needs follows by transitivity from the nesting of the junk
regions.  This is where `depth ≥ 0` (`VC.depth`) is consumed. -/
theorem chain_pop (V : VC X) {σ σ' : St X.S} {cur : X.S.Rtn} {g : Ghosts X.S}
    {f : Frame X.S} {fs : List (Frame X.S)}
    (hc : Chain X σ cur g (f :: fs))
    (ha : AgreeOutside X.L.volatile σ σ') :
    Chain X σ' f.rtn f.g fs := by
  obtain ⟨⟨h1, h2, h3, h4, h5, h6, h7⟩, hrest⟩ := (chain_cons X).1 hc
  cases fs with
  | nil => exact hrest
  | cons f1 fs1 =>
      obtain ⟨⟨g1, g2, g3, g4, g5, g6, g7⟩, grest⟩ := (chain_cons X).1 hrest
      refine (chain_cons X).2 ⟨⟨g1, g2, g3, g4, g5, ?_, g7⟩, grest⟩
      have hd : f.saved.sp ≤ f.g.s0 :=
        V.depth ⟨f.saved.pc, f.rtn, f.saved.en⟩ f.g f.saved h5
      have hsp : f.saved.sp ≤ f1.saved.sp := by omega
      exact AgreeOutside.trans g6
        (AgreeOutside.trans
          (AgreeOutside.weaken (junk_mono X h4 hsp) h6)
          (AgreeOutside.weaken (volatile_sub_junk X f.rtn f1.saved.sp) ha))

/-! ## The soundness theorem -/

/-- **The joint invariant is inductive.**  Every reachable state of `T_V2`
satisfies `J`: its program counter is a live context whose invariant holds, and
the stack is a chain of intact frames. -/
theorem reach_J (V : VC X) (E : Extra X) {σ : St X.S}
    (h : Reach X σ) : J X σ := by
  induction h with
  | init σ hi =>
      exact ⟨X.P.root, ⟨σ.sp, σ.pc, σ⟩, [], V.cold σ hi, (chain_nil X).2 rfl⟩
  | viaStep σ σ' _ ht ih =>
      obtain ⟨cur, g, fs, hInv, hChain⟩ := ih
      exact ⟨cur, g, fs, V.stepInv ⟨σ.pc, cur, σ.en⟩ g σ σ' hInv ht,
        chain_step_preserve X hChain
          (V.stepMod ⟨σ.pc, cur, σ.en⟩ g σ σ' hInv ht)⟩
  | viaCall σ σ' q _ ht ih =>
      obtain ⟨cur, g, fs, hInv, hChain⟩ := ih
      have hsite := X.M.callSite σ σ' q ht
      have hentry := V.callEntry ⟨σ.pc, cur, σ.en⟩ g σ σ' q hInv hsite ht
      have hmodq := V.callMod ⟨σ.pc, cur, σ.en⟩ g σ q hInv hsite
      have hsp := X.M.callSp σ σ' q ht
      refine ⟨q, ⟨σ'.sp, X.P.retPc σ.pc, σ'⟩,
        { rtn := cur, g := g, saved := σ, inner := q,
          innerG := ⟨σ'.sp, X.P.retPc σ.pc, σ'⟩, viaCall := true } :: fs,
        hentry, (chain_cons X).2 ⟨⟨rfl, rfl, by show σ'.sp ≤ σ.sp; omega, hmodq, hInv, ?_, ?_⟩,
          hChain⟩⟩
      · exact AgreeOutside.weaken (scratch_sub_junk X q σ.sp)
          (X.M.callAgree σ σ' q ht)
      · exact Or.inl ⟨rfl, hsite, ht, rfl, rfl⟩
  | viaRet σ σ' _ ht ih =>
      obtain ⟨cur, g, fs, hInv, hChain⟩ := ih
      have hsite := X.M.retSite σ σ' ht
      have hnorm := V.retNormal ⟨σ.pc, cur, σ.en⟩ g σ hInv hsite
      cases fs with
      | nil =>
          have heq : cur = X.P.root := (chain_nil X).1 hChain
          subst heq
          exact absurd hnorm X.P.rootNotNormal
      | cons f fs =>
          obtain ⟨⟨h1, h2, h3, h4, h5, h6, h7⟩, -⟩ := (chain_cons X).1 hChain
          subst h1
          subst h2
          rcases h7 with ⟨_, hcs, hcall, hs0, hret⟩ | ⟨_, hinner, _, _, _, _, _⟩
          · obtain ⟨hf1, hf2⟩ :=
              V.retFrame ⟨σ.pc, f.inner, σ.en⟩ f.innerG σ hInv hsite
            have hcsp := X.M.callSp f.saved f.innerG.entry f.inner hcall
            have hrsp := X.M.retSp σ σ' ht
            have hspeq : σ'.sp = f.saved.sp := by omega
            have hpc : σ'.pc = X.P.retPc f.saved.pc := by
              rw [X.M.retTarget σ σ' ht, hf1, hf2]; exact hret
            have hpost :=
              V.retPost ⟨σ.pc, f.inner, σ.en⟩ f.innerG σ σ' hInv hsite ht
            have hag : AgreeOutside (junk X f.inner f.saved.sp) f.saved σ' :=
              AgreeOutside.trans h6
                (AgreeOutside.weaken
                  (volatile_sub_junk X f.inner f.saved.sp)
                  (X.M.retAgree σ σ' ht))
            have hinv' := V.callReturn ⟨f.saved.pc, f.rtn, f.saved.en⟩ f.g
              f.saved f.innerG.entry σ' f.inner h5 hcs hcall hag hspeq hpost
            refine ⟨f.rtn, f.g, fs, ?_,
              chain_pop X V hChain (X.M.retAgree σ σ' ht)⟩
            rw [hpc]; exact hinv'
          · rw [hinner] at hnorm
            exact absurd hnorm X.P.handlerNotNormal
  | viaAent σ σ' _ ht ih =>
      obtain ⟨cur, g, fs, hInv, hChain⟩ := ih
      have hen : σ.en = true := X.M.aentEnabled σ σ' ht
      have hnw : ¬ X.C.window σ.pc :=
        fun hw => E.window ⟨σ.pc, cur, σ.en⟩ g σ σ' hInv hw ht
      have hentry := V.aentInv ⟨σ.pc, cur, σ.en⟩ g σ σ' hInv hen hnw ht
      have hmodh := E.handlerMod ⟨σ.pc, cur, σ.en⟩ g σ hInv hen hnw
      have hsp := X.M.aentSp σ σ' ht
      refine ⟨X.P.handler, ⟨σ'.sp, σ.pc, σ'⟩,
        { rtn := cur, g := g, saved := σ, inner := X.P.handler,
          innerG := ⟨σ'.sp, σ.pc, σ'⟩, viaCall := false } :: fs,
        hentry, (chain_cons X).2 ⟨⟨rfl, rfl, by show σ'.sp ≤ σ.sp; omega, hmodh, hInv, ?_, ?_⟩,
          hChain⟩⟩
      · exact AgreeOutside.weaken (scratch_sub_junk X X.P.handler σ.sp)
          (X.M.aentAgree σ σ' ht)
      · exact Or.inr ⟨rfl, rfl, hen, hnw, ht, rfl, rfl⟩
  | viaAret σ σ' _ ht ih =>
      obtain ⟨cur, g, fs, hInv, hChain⟩ := ih
      have hsite := X.M.aretSite σ σ' ht
      have hhand := V.aretHandler ⟨σ.pc, cur, σ.en⟩ g σ hInv hsite
      cases fs with
      | nil =>
          have heq : cur = X.P.root := (chain_nil X).1 hChain
          subst heq
          exact absurd hhand X.P.rootNeHandler
      | cons f fs =>
          obtain ⟨⟨h1, h2, h3, h4, h5, h6, h7⟩, -⟩ := (chain_cons X).1 hChain
          subst h1
          subst h2
          rcases h7 with ⟨_, hcs, _, _, _⟩ | ⟨_, hinner, hen, hnw, haent, hs0, hret⟩
          · have hn := V.callNormal ⟨f.saved.pc, f.rtn, f.saved.en⟩ f.g
              f.saved f.inner h5 hcs
            have hh : f.inner = X.P.handler := hhand
            rw [hh] at hn
            exact absurd hn X.P.handlerNotNormal
          · obtain ⟨hf1, hf2⟩ :=
              V.aretFrame ⟨σ.pc, f.inner, σ.en⟩ f.innerG σ hInv hsite
            have hpost := V.aretPost ⟨σ.pc, f.inner, σ.en⟩ f.innerG σ hInv hsite
            have hpost' := E.postAret f.innerG.entry σ σ' ht hpost
            have hasp := X.M.aentSp f.saved f.innerG.entry haent
            have hrsp := X.M.aretSp σ σ' ht
            have hspeq : σ'.sp = f.saved.sp := by omega
            have hpc : σ'.pc = f.saved.pc := by
              rw [X.M.aretTarget σ σ' ht, hf1, hf2]; exact hret
            have hag : AgreeOutside (junk X X.P.handler f.saved.sp) f.saved σ' := by
              rw [← hinner]
              exact AgreeOutside.trans h6
                (AgreeOutside.weaken
                  (volatile_sub_junk X f.inner f.saved.sp)
                  (X.M.aretAgree σ σ' ht))
            have hinv' := V.aentResume ⟨f.saved.pc, f.rtn, f.saved.en⟩ f.g
              f.saved f.innerG.entry σ' h5 hen hnw haent hag hspeq hpost'
            refine ⟨f.rtn, f.g, fs, ?_,
              chain_pop X V hChain (X.M.aretAgree σ σ' ht)⟩
            rw [hpc]; exact hinv'
  | viaReset σ σ' _ ht ih =>
      exact ⟨X.P.root, ⟨σ'.sp, σ'.pc, σ'⟩, [], V.reset σ σ' ht,
        (chain_nil X).2 rfl⟩

/-- Every reachable program counter is a live context. -/
theorem reach_live (V : VC X) (E : Extra X) {σ : St X.S} (h : Reach X σ) :
    ∃ r : X.S.Rtn, Live X ⟨σ.pc, r, σ.en⟩ := by
  obtain ⟨cur, g, _, hInv, _⟩ := reach_J X V E h
  exact ⟨cur, g, σ, hInv⟩

/-- **The safety property.**  Every reachable program counter is in the safe
set.  (Conclusion of spec section 5, for `T_V2`.) -/
theorem reach_safe (V : VC X) (E : Extra X) {σ : St X.S} (h : Reach X σ) :
    X.C.safe σ.pc := by
  obtain ⟨cur, g, _, hInv, _⟩ := reach_J X V E h
  exact V.safety ⟨σ.pc, cur, σ.en⟩ g σ hInv

end AceAudit
