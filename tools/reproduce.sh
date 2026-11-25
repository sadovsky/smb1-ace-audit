#!/usr/bin/env bash
# Regenerate every artifact the documentation quotes.
# Requires $SMB1_ROM (or ./smb1.nes) with SHA-1 ea343f4e445a9050d4b4fbac2c77d0693b1d0922.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p results/revised
run() { echo "--- $*"; "$@"; }
run python3 -m analysis.cfg                > results/revised/cfg.out
run python3 -m analysis.dispatch_tables    > results/revised/dispatch_tables.out
run python3 -m analysis.index_derivation   > results/revised/index_derivation.out
run python3 -m analysis.enemy_routing      > results/revised/enemy_routing.out
run python3 -m analysis.destinations       > results/revised/destinations.out
run python3 -m analysis.interrupts         > results/revised/interrupts.out
run python3 -m analysis.write_census       > results/revised/write_census.out
run python3 -m analysis.stack              > results/revised/stack.out
run python3 -m tools.proof_obligations     > results/revised/proof_obligations.out
run python3 audit.py                       > results/revised/audit.out
run python3 classify.py --json             > results/revised/classify.out
run python3 trace.py                       > results/revised/trace_legacy.out
run python3 reach.py                       > results/revised/reach_legacy.out
run python3 controlflow.py                 > results/revised/controlflow_legacy.out
run python3 -m unittest discover          2> results/revised/unittest.out
run python3 paper/build_paper.py           > results/revised/paper.out
echo "all artifacts regenerated under results/revised/"
