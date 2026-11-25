(declare-fun v () (_ BitVec 8))
(assert (let ((a!1 (bvule (bvsub (ite (= v #x00) #x08 v) #x01) #x07)))
  (not a!1)))
(check-sat)
