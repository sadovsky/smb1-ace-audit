(declare-fun v!0 () (_ BitVec 8))
(assert (not (= (bvadd #xfd v!0) v!0)))
(check-sat)
