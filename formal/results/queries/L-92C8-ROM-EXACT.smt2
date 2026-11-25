; benchmark generated from python API
(set-info :status unknown)
(declare-fun RAM () (Array (_ BitVec 11) (_ BitVec 8)))
(assert
 (let ((?x17 (select RAM (_ bv1823 11))))
(let (($x6 (= ?x17 (_ bv0 8))))
(let ((?x9 (ite $x6 (_ bv8 8) ?x17)))
(let ((?x8 (bvsub ?x9 (_ bv1 8))))
(let (($x14 (and true $x6 true true true true true)))
(let (($x65 (not $x6)))
(let (($x30 (and true $x65 true true true)))
(let (($x64 (and (=> $x30 (= (bvadd (_ bv255 8) ?x17) ?x8)) (=> $x14 (= (_ bv7 8) ?x8)))))
(not $x64))))))))))
(check-sat)
