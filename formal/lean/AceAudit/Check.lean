/-
Build-time audit: no `sorry`, no `axiom`, no `admit`.

`#print axioms` on each exported theorem lists every axiom its proof term
depends on.  An empty list means the proof is closed under the kernel's own
rules alone; `sorryAx` would appear here if anything were left open.
-/
import AceAudit.Soundness
import AceAudit.GapWindow

#print axioms AceAudit.chain_step_preserve
#print axioms AceAudit.chain_pop
#print axioms AceAudit.reach_J
#print axioms AceAudit.reach_live
#print axioms AceAudit.reach_safe
#print axioms AceAudit.GapWindow.gapVC
#print axioms AceAudit.GapWindow.init_good
#print axioms AceAudit.GapWindow.aent_good_bad
#print axioms AceAudit.GapWindow.reach_bad
#print axioms AceAudit.GapWindow.bad_unsafe
#print axioms AceAudit.GapWindow.no_extra
