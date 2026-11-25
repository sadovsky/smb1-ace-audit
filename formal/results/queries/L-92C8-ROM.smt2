; benchmark generated from python API
(set-info :status unknown)
(declare-fun RAM () (Array (_ BitVec 11) (_ BitVec 8)))
(assert
 (let ((?x17 (select RAM (_ bv1823 11))))
 (bvule ?x17 (_ bv8 8))))
(assert
 (let ((?x17 (select RAM (_ bv1823 11))))
(let (($x6 (= ?x17 (_ bv0 8))))
(let (($x14 (and true $x6 true true true true true)))
(let (($x65 (not $x6)))
(let (($x30 (and true $x65 true true true)))
(let (($x36 (and (=> $x30 (bvule (bvadd (_ bv255 8) ?x17) (_ bv7 8))) (=> $x14 (bvule (_ bv7 8) (_ bv7 8))))))
(not $x36))))))))
(check-sat)
