(declare-fun v!0 () (_ BitVec 8))
(assert (let ((a!1 (bvule (bvsub (ite (= v!0 #x00) #x08 v!0) #x01) #x07)))
  (not a!1)))
(check-sat)
