"""Proof obligations, their statuses, and the ledger they are recorded in.

Statuses follow the plan's taxonomy exactly.  Two rules are enforced here
rather than left to convention:

* `proved` requires that the obligation carries no assumptions and that every
  dependency is itself `proved`.  Anything else is at most `conditional`.
* a solver answer is only recorded if the solver actually ran; the ledger
  stores the query's SHA-256 so the answer can be tied to the exact text.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field

import z3

STATUSES = ("proved", "conditional", "bounded", "refuted",
            "abstract_counterexample", "unknown", "timeout", "observed")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QUERIES = os.path.join(ROOT, "results", "queries")


#: Query files are written only when this is set, which `formal.run` does.
#: Tests and ad-hoc callers must not overwrite the artifacts the manifest's
#: hashes refer to.
SAVE_QUERIES = False


def smtlib(assertions) -> str:
    """Deterministic SMT-LIB 2 text for a list of assertions.

    `Solver.to_smt2` names shared subterms after internal AST ids, and fresh
    symbols carry a process-wide counter (`h61848_S`), so neither the solver's
    own rendering nor the raw names can be hashed reproducibly: the first
    replication run found the same query hashing differently in two runs for
    exactly that reason.  Constants are therefore renamed in order of first
    appearance, as for the slice queries.
    """
    from .crosscheck import canonical_smtlib
    return canonical_smtlib(list(assertions))


@dataclass
class Check:
    """One validity query: is `hypotheses => claim` valid?"""
    z3_result: str
    cvc5_result: str | None
    query_sha256: str
    query_artifact: str | None
    model: dict | None = None

    @property
    def valid(self) -> bool:
        return self.z3_result == "unsat" and self.cvc5_result in ("unsat", None)

    @property
    def agreed(self) -> bool:
        return self.cvc5_result is None or self.cvc5_result == self.z3_result


def _cvc5(text: str, timeout_ms: int) -> str:
    try:
        import cvc5
    except ImportError:
        return "unavailable"
    manager = cvc5.TermManager()
    solver = cvc5.Solver(manager)
    solver.setOption("tlimit-per", str(timeout_ms))
    parser = cvc5.InputParser(solver)
    parser.setStringInput(cvc5.InputLanguage.SMT_LIB_2_6,
                          "(set-logic ALL)\n" + text, "query")
    symbols = parser.getSymbolManager()
    answer = "unknown"
    while True:
        command = parser.nextCommand()
        if command.isNull():
            break
        output = command.invoke(solver, symbols).strip()
        if output in ("sat", "unsat", "unknown"):
            answer = output
    return answer


def check_valid(name: str, claim, hypotheses=(), *, timeout_ms: int = 60000,
                second_solver: bool = True, save: bool = True,
                rom_derived: bool = False) -> Check:
    """Ask both solvers whether `Not(hypotheses => claim)` is unsatisfiable.

    `rom_derived` queries embed bytes of the program image.  They are written
    with a `.rom.smt2` suffix, which the repository ignores, so the image is
    not redistributed; the ledger keeps their hash.
    """
    solver = z3.Solver()
    solver.set("timeout", timeout_ms)
    solver.add(*hypotheses)
    solver.add(z3.Not(claim))
    text = smtlib(solver.assertions())
    digest = hashlib.sha256(text.encode()).hexdigest()
    artifact = None
    if save and SAVE_QUERIES:
        os.makedirs(QUERIES, exist_ok=True)
        suffix = ".rom.smt2" if rom_derived else ".smt2"
        path = os.path.join(QUERIES, name + suffix)
        with open(path, "w") as handle:
            handle.write(text)
        artifact = os.path.relpath(path, os.path.dirname(ROOT))
    result = str(solver.check())
    model = None
    if result == "sat":
        found = solver.model()
        model = {str(d): str(found[d]) for d in found.decls()
                 if z3.is_bv_value(found[d]) or z3.is_bool(found[d])}
    other = _cvc5(text, timeout_ms) if second_solver else None
    return Check(result, other, digest, artifact, model)


@dataclass
class Obligation:
    id: str
    statement: str
    scope: str
    status: str
    assumptions: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    solver: str | None = None
    solver_version: str | None = None
    query_artifact: str | None = None
    query_sha256: str | None = None
    result_artifact: str | None = None
    independent_check: str | None = None
    detail: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.status not in STATUSES:
            raise ValueError(f"{self.id}: unknown status {self.status!r}")
        if self.status == "proved" and self.assumptions:
            raise ValueError(
                f"{self.id}: 'proved' cannot carry assumptions; "
                "use 'conditional'")


class Ledger:
    def __init__(self):
        self.items: dict[str, Obligation] = {}

    def add(self, obligation: Obligation) -> Obligation:
        if obligation.id in self.items:
            raise ValueError(f"duplicate obligation {obligation.id}")
        self.items[obligation.id] = obligation
        return obligation

    def record(self, id: str, statement: str, scope: str, check: Check | None,
               *, assumptions=(), dependencies=(), status: str | None = None,
               detail: dict | None = None) -> Obligation:
        """Record a solver-backed obligation; status is derived, not chosen.

        A valid check gives `proved` when there are no assumptions and no
        dependencies, otherwise `conditional`.  Solvers disagreeing, or either
        failing to answer, gives `unknown`.
        """
        if check is not None and status is None:
            if not check.agreed:
                status = "unknown"
            elif check.valid:
                status = ("conditional" if assumptions or dependencies
                          else "proved")
            elif check.z3_result == "sat":
                status = "refuted"
            else:
                status = "timeout" if check.z3_result == "unknown" else "unknown"
        detail = dict(detail or {})
        if check is not None and check.model:
            detail["counterexample"] = check.model
        return self.add(Obligation(
            id, statement, scope, status, list(assumptions),
            list(dependencies),
            solver="z3" if check else None,
            solver_version=z3.get_version_string() if check else None,
            query_artifact=check.query_artifact if check else None,
            query_sha256=check.query_sha256 if check else None,
            independent_check=(f"cvc5: {check.cvc5_result}"
                               if check and check.cvc5_result else None),
            detail=detail))

    def settle(self) -> None:
        """Demote `proved` items whose dependencies are not all `proved`.

        Dependencies on ids that are not in the ledger count as unproved.
        Cycles are handled by iterating to a fixpoint from the pessimistic
        side: nothing in a cycle can be `proved` through the cycle alone.
        """
        proved = {k for k, o in self.items.items() if o.status == "proved"}
        changed = True
        while changed:
            changed = False
            for key in sorted(proved):
                if any(d not in proved for d in self.items[key].dependencies):
                    proved.discard(key)
                    self.items[key].status = "conditional"
                    changed = True

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for obligation in self.items.values():
            out[obligation.status] = out.get(obligation.status, 0) + 1
        return dict(sorted(out.items()))

    def to_json(self) -> dict:
        return {"counts": self.counts(),
                "obligations": [asdict(o) for o in self.items.values()]}

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as handle:
            json.dump(self.to_json(), handle, indent=2, sort_keys=True)
