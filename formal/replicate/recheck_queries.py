"""Independent re-check of the saved SMT-LIB queries (plan M8).

Deliberately imports nothing from this project: it reads the manifest, finds
each query file, confirms its SHA-256 is the one the manifest recorded, and
asks Z3 and cvc5 afresh.  A query "replicates" when both solvers return the
answer the recorded status requires (`unsat` for proved/conditional, `sat` for
refuted).

Queries that embed bytes of the program image (`*.rom.smt2`) are not in the
repository.  They exist only after `python3 -m formal.run` has been run
against a local image, and are reported as "absent" otherwise, never as
passing.

    python3 formal/replicate/recheck_queries.py [repository root]
"""
import hashlib
import json
import os
import sys

EXPECTED = {"proved": "unsat", "conditional": "unsat", "refuted": "sat"}


def z3_answer(text):
    import z3
    solver = z3.Solver()
    solver.set("timeout", 120000)
    solver.from_string(text)
    return str(solver.check())


def cvc5_answer(text):
    import cvc5
    solver = cvc5.Solver(cvc5.TermManager())
    solver.setOption("tlimit-per", "120000")
    parser = cvc5.InputParser(solver)
    parser.setStringInput(cvc5.InputLanguage.SMT_LIB_2_6,
                          "(set-logic ALL)\n" + text, "query")
    symbols = parser.getSymbolManager()
    answer = "unknown"
    while True:
        command = parser.nextCommand()
        if command.isNull():
            return answer
        output = command.invoke(solver, symbols).strip()
        if output in ("sat", "unsat", "unknown"):
            answer = output


def main(root):
    with open(os.path.join(root, "formal", "results", "manifests",
                           "obligations.json")) as handle:
        manifest = json.load(handle)
    rows, failures, absent = [], 0, 0
    for item in manifest["obligations"]:
        if not item.get("query_artifact"):
            continue
        path = os.path.join(root, item["query_artifact"])
        if not os.path.exists(path):
            absent += 1
            rows.append((item["id"], "absent (regenerate with formal.run)"))
            continue
        with open(path) as handle:
            text = handle.read()
        digest = hashlib.sha256(text.encode()).hexdigest()
        want = EXPECTED.get(item["status"])
        got = (z3_answer(text), cvc5_answer(text))
        ok = (digest == item["query_sha256"] and want is not None
              and got == (want, want))
        failures += not ok
        rows.append((item["id"],
                     f"{'ok' if ok else 'MISMATCH'}: hash "
                     f"{'matches' if digest == item['query_sha256'] else 'DIFFERS'}"
                     f", z3 {got[0]}, cvc5 {got[1]}, expected {want}"))
    for name, verdict in rows:
        print(f"{name:28} {verdict}")
    checked = len(rows) - absent
    print(f"\n{checked} queries re-checked, {failures} mismatches, "
          f"{absent} absent")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else
                  os.path.dirname(os.path.dirname(os.path.dirname(
                      os.path.abspath(__file__))))))
