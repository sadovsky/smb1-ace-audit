(declare-fun h61848_S () (_ BitVec 8))
(assert (not (= (bvadd #xfd h61848_S) h61848_S)))
(check-sat)
