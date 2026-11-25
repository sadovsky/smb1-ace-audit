(declare-fun RAM () (Array (_ BitVec 11) (_ BitVec 8)))
(assert (let ((a!1 (and true (not (= (select RAM #b11100011111) #x00)) true true true))
      (a!2 (bvsub (ite (= (select RAM #b11100011111) #x00)
                       #x08
                       (select RAM #b11100011111))
                  #x01)))
(let ((a!3 (=> a!1 (= (bvadd #xff (select RAM #b11100011111)) a!2)))
      (a!4 (=> (and true
                    (= (select RAM #b11100011111) #x00)
                    true
                    true
                    true
                    true
                    true)
               (= #x07 a!2))))
  (not (and a!3 a!4)))))
(check-sat)
