"""Hash, count and independently re-check the answers the slicer relies on.

`verify/obligations.check_valid` already hashes its query, writes it out and
asks cvc5 the same question.  The slice machinery in `verify/symexec.py` did
none of that: it called Z3 directly, thousands of times per run, and a wrong
`unsat` from any one of those calls would have become a `conditional` status
with nothing to check it against.  Closing that was the point of this module.

Every definite answer the slicer relies on now goes through `record`, which

* renders the query as SMT-LIB 2 with its symbols renamed canonically, so the
  text -- and therefore its SHA-256 -- depends only on the query's structure
  and not on how many havoc states happened to be built before it.  Raw Z3
  names carry a global counter (`h17_A`, `bus!204`), which would make the
  hash of the same question differ between a full run and a single module;
* counts it and remembers its hash in whichever `collect` block is active, so
  an obligation can state exactly which queries carry it;
* re-asks it of cvc5 and Bitwuzla in a worker pool and tallies the verdicts.

Nothing here can improve a status.  Agreement is reported, a disagreement or
a second-solver timeout is reported in the same place, and `outcome_fields`
demotes an obligation whose queries disagree to `unknown`.

Identical query texts are re-checked once: the trivial queries dominate by
count (most instructions cannot write the cell under examination at all, so
the bad condition is literally `false`), and a hash is exactly the right
thing to deduplicate on.  Both the total and the distinct count are reported.
"""
from __future__ import annotations

import hashlib
import multiprocessing as mp
import os
import re
import time
from contextlib import contextmanager
from dataclasses import dataclass, field

import z3

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QUERIES = os.path.join(ROOT, "results", "queries")

#: solvers asked to confirm Z3, in report order
SECOND_SOLVERS = ("cvc5", "bitwuzla")
#: per-query limit handed to each second solver
TIMEOUT_MS = int(os.environ.get("SMB1_CROSSCHECK_TIMEOUT_MS", "20000"))
#: worker processes for the re-check.  The machine is shared; keep this small.
WORKERS = int(os.environ.get("SMB1_CROSSCHECK_WORKERS", "4"))
#: re-check in batches, bounded by count and by the memory the texts take
BATCH = 256
BATCH_BYTES = 64 << 20
#: set to False to hash and count without asking a second solver
CROSS_CHECK = os.environ.get("SMB1_CROSSCHECK", "1") != "0"
#: Slice queries embed image bytes.  They are written only on request, and
#: only with the `.rom.smt2` suffix the repository ignores, so the image is
#: never redistributed; set SMB1_SLICE_QUERY_DIR to keep them out of the tree
#: altogether.  The hashes in the manifest identify them either way.
SAVE_QUERIES = os.environ.get("SMB1_SAVE_SLICE_QUERIES", "") == "1"
QUERY_DIR = os.environ.get("SMB1_SLICE_QUERY_DIR", QUERIES)


# -- deterministic, counter-independent SMT-LIB ------------------------------

#: a quoted symbol, or a plain one.  Operator names match too and are left
#: alone, because only declared constants are in the renaming map.
_TOKEN = re.compile(r"\|[^|]*\||[A-Za-z_][A-Za-z0-9_!]*")


def declarations(assertions) -> dict:
    """Name -> declaration for every uninterpreted constant in `assertions`."""
    seen: set[int] = set()
    decls: dict[str, object] = {}
    pending = list(assertions)
    while pending:
        term = pending.pop()
        key = term.get_id()
        if key in seen:
            continue
        seen.add(key)
        if z3.is_const(term) and term.decl().kind() == z3.Z3_OP_UNINTERPRETED:
            name = term.decl().name()
            previous = decls.get(name)
            if previous is not None and not previous.range().eq(
                    term.decl().range()):
                raise ValueError(
                    f"two constants named {name!r} with different sorts; the "
                    "SMT-LIB text would be ambiguous")
            decls[name] = term.decl()
        pending.extend(term.children())
    return decls


def canonical_smtlib(assertions) -> str:
    """SMT-LIB 2 for `assertions` with constants renamed `v!0`, `v!1`, ...

    Names are assigned in order of first appearance in the assertion text, so
    two structurally equal queries built at different points of a run produce
    the same string.  The renaming is a bijection on symbols, so the query it
    denotes is the same question up to the names of its variables.
    """
    assertions = [_unwrap(a) for a in assertions]
    decls = declarations(assertions)
    renaming: dict[str, str] = {}

    def rename(match: re.Match) -> str:
        token = match.group(0)
        name = token[1:-1] if token.startswith("|") else token
        if name not in decls:
            return token
        if name not in renaming:
            renaming[name] = f"v!{len(renaming)}"
        return renaming[name]

    body = [_TOKEN.sub(rename, f"(assert {a.sexpr()})") for a in assertions]
    header = [f"(declare-fun {new} () {decls[old].range().sexpr()})"
              for old, new in renaming.items()]
    return "\n".join(header + body + ["(check-sat)"]) + "\n"


def disjunction(terms) -> z3.BoolRef:
    """`Or` of `terms`, never a one-argument `or`.

    `z3.Or(z3.BoolVal(False), *terms)` with an empty `terms` renders as
    `(or false)`, and SMT-LIB 2.6 declares `or` left-associative with at least
    two arguments: Z3 and cvc5 accept the unary form, Bitwuzla refuses to
    parse it, so a query built that way quietly loses one of its two second
    opinions.
    """
    terms = list(terms)
    if not terms:
        return z3.BoolVal(False)
    if len(terms) == 1:
        return terms[0]
    return z3.Or(*terms)


def _unwrap(term):
    """Strip one-argument `and`/`or` wrappers from the top of a term."""
    while (z3.is_and(term) or z3.is_or(term)) and term.num_args() == 1:
        term = term.arg(0)
    return term


def query_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def digest_of(hashes) -> str | None:
    """One hash committing to a set of query hashes, order-independent."""
    if not hashes:
        return None
    joined = "\n".join(sorted(hashes)) + "\n"
    return hashlib.sha256(joined.encode()).hexdigest()


# -- second solvers ----------------------------------------------------------

def _cvc5_answer(text: str, timeout_ms: int) -> str:
    from .obligations import _cvc5
    return _cvc5(text, timeout_ms)


def _bitwuzla_answer(text: str, timeout_ms: int) -> str:
    try:
        import bitwuzla
    except ImportError:
        return "unavailable"
    options = bitwuzla.Options()
    options.set(bitwuzla.Option.TIME_LIMIT_PER, timeout_ms)
    parser = bitwuzla.Parser(bitwuzla.TermManager(), options, "smt2")
    # QF_ABV: the queries are quantifier-free bit-vectors and RAM/PRG arrays.
    parser.parse("(set-logic QF_ABV)\n" + text, True, False)
    return str(parser.bitwuzla().check_sat())


_RUNNERS = {"cvc5": _cvc5_answer, "bitwuzla": _bitwuzla_answer}


def second_opinions(job) -> tuple[str, dict]:
    """Worker entry point: one query text, every second solver's answer."""
    digest, text, timeout_ms, solvers = job
    answers = {}
    for name in solvers:
        try:
            answers[name] = _RUNNERS[name](text, timeout_ms)
        except Exception as exc:                      # pragma: no cover
            # keep the message: an unexplained "error" in the tally is the
            # one thing this module exists to prevent
            answers[name] = f"error: {type(exc).__name__}: {exc}"[:200]
    return digest, answers


# -- the worker pool ---------------------------------------------------------

_POOL = None
_PENDING: dict[str, str] = {}
_PENDING_BYTES = 0
#: query hash -> {solver: answer}; one re-check per distinct text per run
_ANSWERS: dict[str, dict] = {}


def _pool():
    global _POOL
    if _POOL is None:
        # fork, not forkserver/spawn: those re-import __main__ in the child,
        # which under `python3 -m unittest` would re-run the test suite.
        _POOL = mp.get_context("fork").Pool(max(1, WORKERS))
    return _POOL


def _drop_pool() -> None:
    global _POOL
    if _POOL is not None:
        _POOL.terminate()
        _POOL = None


def flush() -> None:
    """Re-check every queued query and record what the second solvers said."""
    global _PENDING, _PENDING_BYTES
    pending, _PENDING, _PENDING_BYTES = _PENDING, {}, 0
    if not pending:
        return
    jobs = [(h, t, TIMEOUT_MS, SECOND_SOLVERS) for h, t in pending.items()]
    if WORKERS <= 1:
        for job in jobs:
            digest, answers = second_opinions(job)
            _ANSWERS[digest] = answers
        return
    pool = _pool()
    waiting = [(job[0], pool.apply_async(second_opinions, (job,)))
               for job in jobs]
    # Both solvers are given a per-query limit of their own; this deadline is
    # only a backstop for a solver that ignores it.  Work is spread over the
    # workers, so allow one full limit per batch slot plus slack.
    rounds = 1 + (len(jobs) - 1) // max(1, WORKERS)
    deadline = (time.time() + rounds * len(SECOND_SOLVERS)
                * TIMEOUT_MS / 1000.0 + 60.0)
    stalled = False
    for digest, result in waiting:
        if stalled:
            _ANSWERS[digest] = {s: "timeout" for s in SECOND_SOLVERS}
            continue
        try:
            _, answers = result.get(timeout=max(1.0, deadline - time.time()))
        except mp.TimeoutError:
            stalled = True
            _drop_pool()
            _ANSWERS[digest] = {s: "timeout" for s in SECOND_SOLVERS}
        except Exception as exc:                      # pragma: no cover
            _ANSWERS[digest] = {s: f"error: {type(exc).__name__}"
                                for s in SECOND_SOLVERS}
        else:
            _ANSWERS[digest] = answers


def _enqueue(digest: str, text: str) -> None:
    global _PENDING_BYTES
    if digest in _ANSWERS or digest in _PENDING:
        return
    _PENDING[digest] = text
    _PENDING_BYTES += len(text)
    if len(_PENDING) >= BATCH or _PENDING_BYTES >= BATCH_BYTES:
        flush()


# -- collections -------------------------------------------------------------

def _classify(z3_result: str, other: str) -> str:
    if other.startswith("error"):
        return "error"
    if other == "unavailable":
        return "unavailable"
    if other in ("unknown", "timeout"):
        return "timeout"
    if z3_result == "unknown":
        # Z3 did not answer, so there is nothing to contradict.  Such a query
        # is not queued for a second opinion; this guards the case where the
        # same text was asked twice and Z3 timed out on only one of them.
        return "timeout"
    return "agree" if other == z3_result else "disagree"


@dataclass
class Collection:
    """The queries one obligation rests on."""

    label: str
    #: z3 answer -> how many times it was recorded
    results: dict = field(default_factory=dict)
    #: query kind -> count
    kinds: dict = field(default_factory=dict)
    #: distinct query hash -> the z3 answer recorded for it
    answers: dict = field(default_factory=dict)
    #: hashes that were queued for a second opinion
    rechecked: set = field(default_factory=set)

    def note(self, digest: str, z3_result: str, kind: str,
             recheck: bool) -> None:
        self.results[z3_result] = self.results.get(z3_result, 0) + 1
        self.kinds[kind] = self.kinds.get(kind, 0) + 1
        previous = self.answers.get(digest)
        if previous is None or (previous == "unknown"
                                and z3_result != "unknown"):
            self.answers[digest] = z3_result
        if recheck:
            self.rechecked.add(digest)

    @property
    def total(self) -> int:
        return sum(self.results.values())

    def tally(self) -> dict:
        """Per second solver, how its answers compared with Z3's."""
        out = {}
        for solver in SECOND_SOLVERS:
            counts = {"agree": 0, "disagree": 0, "timeout": 0,
                      "unavailable": 0, "error": 0}
            disagreements, errors = [], []
            for digest in sorted(self.rechecked):
                answers = _ANSWERS.get(digest)
                if answers is None:
                    counts["error"] += 1
                    if len(errors) < 8:
                        errors.append({"query_sha256": digest,
                                       "reason": "never re-checked"})
                    continue
                said = answers.get(solver, "unavailable")
                verdict = _classify(self.answers[digest], said)
                counts[verdict] += 1
                if verdict == "disagree" and len(disagreements) < 8:
                    disagreements.append(
                        {"query_sha256": digest,
                         "z3": self.answers[digest], solver: said})
                if verdict == "error" and len(errors) < 8:
                    errors.append({"query_sha256": digest, "reason": said})
            entry = {k: v for k, v in counts.items() if v}
            if disagreements:
                entry["disagreements"] = disagreements
            if errors:
                entry["errors"] = errors
            out[solver] = entry or {"agree": 0}
        return out

    def summary(self) -> dict:
        """The record an obligation carries about its slice queries."""
        flush()
        tally = self.tally()
        disagreements = sum(t.get("disagree", 0) for t in tally.values())
        timeouts = sum(t.get("timeout", 0) for t in tally.values())
        unavailable = [s for s, t in tally.items() if t.get("unavailable")]
        notes = []
        if disagreements:
            notes.append(f"{disagreements} disagreement(s) with Z3")
        if timeouts:
            notes.append(f"{timeouts} second-solver timeout(s)")
        if unavailable:
            notes.append("not installed: " + ", ".join(sorted(unavailable)))
        failed = sum(t.get("error", 0) for t in tally.values())
        if failed:
            notes.append(f"{failed} second-solver error(s)")
        if not CROSS_CHECK:
            notes.append("re-check disabled (SMB1_CROSSCHECK=0)")
        return {
            "solver_queries": self.total,
            "relied_on_unsat": self.results.get("unsat", 0),
            "z3_sat": self.results.get("sat", 0),
            "z3_no_answer": self.results.get("unknown", 0),
            "by_kind": dict(sorted(self.kinds.items())),
            "distinct_queries": len(self.answers),
            "distinct_rechecked": len(self.rechecked),
            "query_digest": digest_of(self.answers),
            "hash_scheme": "each query hash is the sha256 of its canonical "
                           "SMT-LIB text; the digest is the sha256 of the "
                           "sorted distinct hashes, one per line",
            "second_solver": tally,
            "cross_check": "; ".join(notes) if notes else "clean",
        }

    @property
    def clean(self) -> bool:
        """True when no second solver contradicted Z3."""
        return not any(t.get("disagree") for t in self.tally().values())


#: queries recorded with no `collect` block active.  Still hashed, counted and
#: re-checked, so an unwrapped call site cannot hide a disagreement; it just
#: has no obligation to report it on.
UNATTRIBUTED = Collection("unattributed")
_STACK: list[Collection] = []
_SAVED = 0


@contextmanager
def collect(label: str):
    """Attribute every query recorded in the block to one collection."""
    collection = Collection(label)
    _STACK.append(collection)
    try:
        yield collection
    finally:
        _STACK.pop()
        flush()


def active() -> list:
    """Every collection a query should be filed under.

    Nested blocks all see the query, so an aggregate obligation can wrap the
    per-item proofs it summarises and still report the total.
    """
    return list(_STACK) if _STACK else [UNATTRIBUTED]


def record(assertions, z3_result: str, kind: str, *,
           recheck: bool | None = None) -> str:
    """Hash one solver answer, file it, and queue the second opinion.

    `recheck` defaults to true for definite answers.  A Z3 `unknown` is left
    alone: it is already reported as a timeout and nothing rests on it.
    Returns the query's SHA-256.
    """
    text = canonical_smtlib(list(assertions))
    digest = query_hash(text)
    if recheck is None:
        recheck = z3_result in ("sat", "unsat")
    recheck = recheck and CROSS_CHECK
    for collection in active():
        collection.note(digest, z3_result, kind, recheck)
    if SAVE_QUERIES:
        _save(digest, text)
    if recheck:
        _enqueue(digest, text)
    return digest


def _save(digest: str, text: str) -> None:
    global _SAVED
    os.makedirs(QUERY_DIR, exist_ok=True)
    # Always `.rom.smt2`: a slice query carries the instruction bytes it
    # executed, so it is image-derived whatever its subject.
    path = os.path.join(QUERY_DIR, f"slice-{digest[:16]}.rom.smt2")
    if not os.path.exists(path):
        with open(path, "w") as handle:
            handle.write(text)
        _SAVED += 1


def obligation_fields(collection: Collection) -> dict:
    """`query_sha256` and `independent_check` for an obligation's queries.

    The plan's certificate schema has one slot for a query hash and one for
    an independent check.  A slice-based obligation rests on many queries, so
    the digest over their hashes goes in the first and the per-solver tally in
    the second; the full record stays in `detail.slice_queries`.
    """
    summary = collection.summary()
    if not summary["distinct_queries"]:
        return {}
    parts = []
    for solver, tally in summary["second_solver"].items():
        counts = ", ".join(f"{k} {v}" for k, v in tally.items()
                           if isinstance(v, int))
        parts.append(f"{solver}: {counts}")
    return {"query_sha256": summary["query_digest"],
            "independent_check": "; ".join(parts)}


def totals() -> dict:
    """Run-level counts, including anything recorded outside a block."""
    return {"unattributed": UNATTRIBUTED.summary(),
            "distinct_queries_rechecked": len(_ANSWERS),
            "queries_written": _SAVED,
            "second_solvers": list(SECOND_SOLVERS),
            "second_solver_timeout_ms": TIMEOUT_MS,
            "workers": WORKERS}


def reset() -> None:
    """Forget every recorded query (tests)."""
    global UNATTRIBUTED, _PENDING, _PENDING_BYTES
    UNATTRIBUTED = Collection("unattributed")
    _STACK.clear()
    _PENDING, _PENDING_BYTES = {}, 0
    _ANSWERS.clear()
