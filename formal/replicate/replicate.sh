#!/usr/bin/env bash
# Clean-environment replication (plan M8).
#
# Clones the committed HEAD into a temporary directory (so nothing untracked
# can be depended on), builds a fresh virtual environment from the pinned
# requirements, regenerates the manifest from the local image, and compares
# the regenerated statuses and query hashes with the committed ones.
#
#   SMB1_ROM=/path/to/image formal/replicate/replicate.sh [output.json]
#
# Optional: NES6502_VECTORS=/path/to/vectors also re-runs model validation.
set -euo pipefail
: "${SMB1_ROM:?set SMB1_ROM to the verified image}"
root="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
out="${1:-$root/formal/results/reports/replication.json}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

git clone --quiet "$root" "$work/repo"
commit="$(git -C "$work/repo" rev-parse HEAD)"
# `python3 -m venv` needs a system package on Debian/Ubuntu; fall back to uv.
if python3 -m venv "$work/venv" >/dev/null 2>&1; then
  "$work/venv/bin/pip" install --quiet -r "$work/repo/formal/replicate/requirements.txt"
elif command -v uv >/dev/null 2>&1; then
  rm -rf "$work/venv"
  uv venv --quiet "$work/venv"
  uv pip install --quiet --python "$work/venv/bin/python" \
     -r "$work/repo/formal/replicate/requirements.txt"
else
  echo "need either the python3-venv package or uv" >&2; exit 1
fi
py="$work/venv/bin/python"
cd "$work/repo"
cp formal/results/manifests/obligations.json "$work/committed.json"

validation="skipped (NES6502_VECTORS not set)"
if [ -n "${NES6502_VECTORS:-}" ] && [ -d "$NES6502_VECTORS" ]; then
  "$py" -m formal.validate_model --vectors "$NES6502_VECTORS" > "$work/validate.out"
  validation="$(tr '\n' ';' < "$work/validate.out")"
fi
"$py" -m formal.run > "$work/run.out"
tests="$("$py" -m unittest discover -s formal/tests -t . 2>&1 | tail -3 | tr '\n' ' ')"
recheck="$("$py" formal/replicate/recheck_queries.py . | tail -1)"

"$py" - "$work/committed.json" formal/results/manifests/obligations.json \
      "$out" "$commit" "$validation" "$tests" "$recheck" <<'PY'
import json, platform, sys
committed, fresh, out, commit, validation, tests, recheck = sys.argv[1:]
a, b = (json.load(open(p)) for p in (committed, fresh))
key = lambda m: {o["id"]: (o["status"], o.get("query_sha256")) for o in m["obligations"]}
ka, kb = key(a), key(b)
differences = {k: {"committed": ka.get(k), "regenerated": kb.get(k)}
               for k in sorted(set(ka) | set(kb)) if ka.get(k) != kb.get(k)}
report = {
    "what": "fresh clone of the committed HEAD, fresh virtual environment, "
            "manifest regenerated from the local image",
    "commit": commit, "python": platform.python_version(),
    "rom_sha1": b["rom_sha1"], "solver": b["solver"],
    "obligations": len(kb), "counts": b["counts"],
    "differences_from_committed_manifest": differences,
    "replicates": not differences,
    "model_validation": validation, "tests": tests,
    "saved_query_recheck": recheck,
    "limits": "same machine, same operating system and same solver builds as "
              "the original run; this shows the result does not depend on "
              "untracked state, not that it is independent of the toolchain",
}
json.dump(report, open(out, "w"), indent=2, sort_keys=True)
print(json.dumps({k: report[k] for k in ("replicates", "counts", "tests",
                                         "saved_query_recheck")}, indent=2))
PY
