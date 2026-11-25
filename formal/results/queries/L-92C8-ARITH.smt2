; benchmark generated from python API
(set-info :status unknown)
(declare-fun v () (_ BitVec 8))
(assert
 (bvule v (_ bv8 8)))
(assert
 (let (($x75 (= v (_ bv0 8))))
(let ((?x153 (ite $x75 (_ bv8 8) v)))
(let ((?x146 (bvsub ?x153 (_ bv1 8))))
(let (($x131 (bvule ?x146 (_ bv7 8))))
(not $x131))))))
(check-sat)
