"""The joint inductive invariant (plan section 10; milestones M4 and M6).

This module runs the *proposer* (`formal/analysis`), hands its certificate to
the *checker* (`formal/verify/certificate.py`), and records one aggregate
obligation per verification-condition kind.  The two sides share no code, so a
`holds` verdict is a statement about the certificate and the machine model,
not about the analysis that guessed it.

Statuses follow the plan's taxonomy:

* a kind every one of whose conditions holds is `conditional`, on the model
  assumptions listed in `ASSUMPTIONS` -- never `proved`, because the section 5
  soundness argument that turns the conditions into an inductive invariant is
  on paper and is part of the trusted base;
* a kind with a failed condition is `unknown`: a failed condition says this
  candidate invariant is not inductive, which is not a counterexample to the
  property;
* a kind whose only non-holding conditions are solver timeouts is `timeout`.

`P1-JOINT` is derived from those and nothing else.
"""
from __future__ import annotations

import json
import multiprocessing
import os
import time

from ..analysis.hints import HINTS
from ..analysis.invariants import propose
from ..verify import certificate as cert
from ..verify.obligations import Ledger, Obligation
from .common import MODEL_SCOPE, Context

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERTIFICATE = os.path.join(HERE, "results", "certificates", "joint.json")
VERDICTS = os.path.join(HERE, "results", "reports", "joint_verdicts.json")

#: the model assumptions every joint result is conditional on
ASSUMPTIONS = (
    "MA-CPU: formal/model/cpu.py matches the 2A03 at instruction granularity",
    "MA-PPU-POWERON: PPU control is zero at cold boot",
    "MA-PPU-WARMUP: writes to PPU control take effect",
    "MA-NMI-EDGE: after an NMI is taken, no further NMI is taken until the "
    "handler's disabling write",
    "MA-NMI-LATENCY: no NMI is taken between the handler's enabling write "
    "and the completion of its RTI",
    "META-SOUNDNESS: the section 5 argument that the verification conditions "
    "make the joint invariant inductive is on paper, not machine-checked",
)

KINDS = ("VC-STEP", "VC-MOD", "VC-CALL", "VC-RET", "VC-DISPATCH",
         "VC-NMI-ENTRY", "VC-NMI-RESUME", "VC-NMI-EXIT", "VC-RESET",
         "VC-COLD", "VC-FORBIDDEN", "VC-IRQ", "VC-CAPACITY", "VC-SAFETY",
         "VC-COVERAGE", "VC-NODE")

#: how many times the proposer re-runs with the contracts it derived.  The
#: contracts and the invariants depend on each other, so this is a fixpoint
#: iteration with a budget; a budget that is too small shows up as failed
#: verification conditions, never as a wrong conclusion.
ROUNDS = 6

#: how many worker processes check contexts in parallel
WORKERS = min(8, max(1, (os.cpu_count() or 2) - 2))

#: set in the parent before the pool is created; `fork` gives every worker a
#: copy, so all of them check against exactly the same `Checker` object.  A
#: `Checker` holds no Z3 state -- the certificate is parsed into plain Python
#: and the queries are built per call -- so forking it is safe.
_CHECKER: cert.Checker | None = None


def _check(keys: list[str]) -> list[tuple]:            # pragma: no cover
    assert _CHECKER is not None
    return [(v.id, v.kind, v.status, v.detail) for v in
            _CHECKER.check_contexts([cert.parse_context(k) for k in keys])]


def check_certificate(certificate: dict, ctx: Context, *,
                      workers: int = WORKERS) -> list[cert.Verdict]:
    """Every verification condition, with the per-context ones in parallel."""
    global _CHECKER
    _CHECKER = cert.Checker(certificate, ctx.graph, ctx.prg)
    checker = _CHECKER
    keys = [c.key for c in checker.live()]
    verdicts = list(checker.check_globals())
    if workers <= 1 or len(keys) < 64:
        return verdicts + checker.check_contexts(checker.live())
    chunks = [keys[i::workers * 8] for i in range(workers * 8)]
    pool = multiprocessing.get_context("fork").Pool(workers)
    try:
        for batch in pool.imap_unordered(_check, [c for c in chunks if c]):
            verdicts.extend(cert.Verdict(*row) for row in batch)
    finally:
        pool.terminate()
        pool.join()
    return verdicts


def _ordered(verdicts) -> list:
    """Failing verdicts, most informative kinds first."""
    rank = {k: i for i, k in enumerate(KINDS)}
    return sorted((v for v in verdicts if v.status != cert.HOLDS),
                  key=lambda v: (rank.get(v.kind, 99), v.id))


def _status(entry: dict) -> str:
    if entry[cert.FAILS] == 0 and entry[cert.UNKNOWN] == 0:
        return "conditional"
    if entry[cert.FAILS] == 0:
        return "timeout"
    return "unknown"


def run(ledger: Ledger, ctx: Context) -> None:
    started = time.time()
    if os.environ.get("SMB1_JOINT_REUSE") == "1":
        # Re-check the committed certificate instead of proposing a new one.
        # The certificate is an artifact, so checking it on its own is what an
        # independent replication does; it also makes a run that was
        # interrupted restartable without the proposer's quarter of an hour.
        certificate = cert.load(CERTIFICATE)
        if certificate.get("rom_sha1") != ctx.sha1:
            raise ValueError("the saved certificate is for another image")
    else:
        certificate, _proposer = propose(ctx.graph, ctx.prg, ctx.sha1,
                                         hints=HINTS, max_rounds=ROUNDS)
        os.makedirs(os.path.dirname(CERTIFICATE), exist_ok=True)
        with open(CERTIFICATE, "w") as handle:
            # compact: one entry per routine-qualified instruction start, so
            # an indented form would be tens of megabytes
            json.dump(certificate, handle, separators=(",", ":"),
                      sort_keys=True)
    proposed = time.time() - started

    verdicts = check_certificate(certificate, ctx)
    summary = cert.summarise(verdicts)
    os.makedirs(os.path.dirname(VERDICTS), exist_ok=True)
    with open(VERDICTS, "w") as handle:
        json.dump({"summary": summary,
                   "seconds": {"propose": round(proposed, 1),
                               "check": round(time.time() - started
                                              - proposed, 1)},
                   "failures": [
                       {"id": v.id, "kind": v.kind, "status": v.status,
                        **v.detail} for v in _ordered(verdicts)[:400]],
                   "other_failing_ids": [v.id for v in
                                         _ordered(verdicts)[400:8000]]},
                  handle, indent=1, sort_keys=True)

    missing = sorted(set(summary) - set(KINDS))
    if missing:
        # A kind the ledger does not know about would be a verification
        # condition whose verdict is silently discarded, and `P1-JOINT` could
        # then be `conditional` while it fails.
        raise AssertionError(f"verdict kinds not recorded in the ledger: "
                             f"{missing}")
    ids = []
    for kind in KINDS:
        entry = summary.get(kind)
        if entry is None:
            continue
        total = entry[cert.HOLDS] + entry[cert.FAILS] + entry[cert.UNKNOWN]
        status = _status(entry)
        ids.append(f"JOINT-{kind}")
        ledger.add(Obligation(
            ids[-1],
            f"every {kind} condition of the joint certificate holds "
            f"({entry[cert.HOLDS]} of {total})",
            "joint inductive invariant, one verification-condition kind",
            status,
            list(ASSUMPTIONS) if status == "conditional" else [],
            solver="z3",
            detail={"scope": MODEL_SCOPE, "conditions": total,
                    "holds": entry[cert.HOLDS], "fails": entry[cert.FAILS],
                    "solver_unknown": entry[cert.UNKNOWN],
                    "first_failing_ids": entry["failing"],
                    "certificate": os.path.relpath(
                        CERTIFICATE, os.path.dirname(HERE)),
                    "verdicts": os.path.relpath(VERDICTS,
                                                os.path.dirname(HERE))}))

    all_hold = bool(ids) and all(
        ledger.items[i].status == "conditional" for i in ids)
    ledger.add(Obligation(
        "JOINT-CERTIFICATE",
        "the proposed certificate is an inductive invariant of T_V2",
        "joint inductive invariant (plan section 10)",
        "conditional" if all_hold else "unknown",
        list(ASSUMPTIONS) if all_hold else [],
        dependencies=ids,
        detail={
            "contexts": len(certificate["contexts"]),
            "live_contexts": sum(
                1 for v in certificate["contexts"].values()
                if not v.get("false")),
            "routines": len(certificate["routines"]),
            "tracked_cells": len(certificate["tracked_cells"]),
            "nmi_windows": certificate["nmi_windows"],
            "proposer_notes": certificate["notes"],
            "unmodelled_instructions":
                certificate["unmodelled_instructions"],
            "reset_assumption": certificate[
                "reset_clears_enable_assumption"],
            "seconds": {"propose": round(proposed, 1),
                        "check": round(time.time() - started - proposed, 1)},
            "why_unknown": None if all_hold else
                "at least one verification condition does not hold; see the "
                "JOINT-* items and results/reports/joint_verdicts.json",
        }))

    ledger.add(Obligation(
        "P1-JOINT",
        "P1 (every instruction fetch is inside PRG ROM) for T_V2, via the "
        "joint inductive invariant",
        "primary theorem by certificate",
        "conditional" if all_hold else "unknown",
        (list(ASSUMPTIONS)
         + [certificate["reset_clears_enable_assumption"]]) if all_hold
        else [],
        dependencies=["JOINT-CERTIFICATE"],
        detail={
            "argument": "every live context is an instruction start inside "
                        "PRG ROM (VC-SAFETY), the certificate is inductive "
                        "for T_V2 (JOINT-CERTIFICATE), and the initial "
                        "states satisfy it (VC-COLD, VC-RESET), so every "
                        "reachable fetch is at a live context",
            "not_machine_checked": "the step from 'every verification "
                                   "condition holds' to 'the conjunction is "
                                   "inductive' is the section 5 argument and "
                                   "is on paper",
        }))
