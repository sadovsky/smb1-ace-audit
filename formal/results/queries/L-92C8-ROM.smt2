(declare-fun v!0 () (Array (_ BitVec 11) (_ BitVec 8)))
(assert (bvule (select v!0 #b11100011111) #x08))
(assert (let ((a!1 (and true (not (= (select v!0 #b11100011111) #x00)) true true true))
      (a!3 (=> (and true
                    (= (select v!0 #b11100011111) #x00)
                    true
                    true
                    true
                    true
                    true)
               (bvule #x07 #x07))))
(let ((a!2 (=> a!1 (bvule (bvadd #xff (select v!0 #b11100011111)) #x07))))
  (not (and a!2 a!3)))))
(check-sat)
