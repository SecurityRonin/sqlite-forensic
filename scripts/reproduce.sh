#!/usr/bin/env bash
#
# One-command reproduction of the deleted-record head-to-head (roadmap §5).
#
# Prerequisites (built once at their pinned versions — see the per-tool recipes):
#   - undark        tools/undark/SETUP.md      -> tools/undark/undark
#   - fqlite        tools/fqlite/SETUP.md       -> tools/fqlite/run-tap.sh  (+ a JDK)
#   - bring2lite    tools/bring2lite/SETUP.md   -> scripts/run-bring2lite.sh
#   - sqlite_dissect  pip install sqlite-dissect -> scripts/run-sqlite-dissect.sh
#
# Any gate left unset is simply skipped by the harness, so this reproduces one
# column at a time. With every gate set it rewrites docs/img/comparison_metrics.csv
# from the live run; the chart is then regenerated from that CSV.
#
# Override any path via the matching environment variable, e.g.
#   FQLITE_JAVA=/opt/homebrew/opt/openjdk@25/bin/java scripts/reproduce.sh
set -euo pipefail

W="$(cd "$(dirname "$0")/.." && pwd)"
cd "$W"

UNDARK_BIN="${UNDARK_BIN:-$W/tools/undark/undark}" \
FQLITE_TAP="${FQLITE_TAP:-$W/tools/fqlite/run-tap.sh}" \
FQLITE_JAVA="${FQLITE_JAVA:-$(command -v java || true)}" \
BRING2LITE_CMD="${BRING2LITE_CMD:-$W/scripts/run-bring2lite.sh}" \
SQLITE_DISSECT_CMD="${SQLITE_DISSECT_CMD:-$W/scripts/run-sqlite-dissect.sh}" \
  cargo test -p sqlite-forensic --test nemetz_tool_comparison -- --nocapture

# Regenerate the chart from the (possibly rewritten) metrics CSV.
python3 docs/plot_comparison.py

echo "Reproduced: docs/img/comparison_metrics.csv + docs/img/recovery-comparison.png"
