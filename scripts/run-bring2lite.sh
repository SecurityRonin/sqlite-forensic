#!/usr/bin/env bash
# Normalized oracle wrapper for bring2lite (Nyeste/Bring2lite, Python 3).
#
# Usage:   run-bring2lite.sh <database.db>
# Emits:   one recovered DELETED record per line on stdout, as
#              col0,col1,col2,col3,...
#          where col0 is the rowid/first column and col1/col2 are the two
#          format-stable identity columns the head-to-head scores. This is the
#          SAME row shape undark emits, so the Rust harness reads identity columns
#          at CSV fields 1 and 2 (see forensic/tests/nemetz_tool_comparison.rs).
#
# What is emitted vs. suppressed (documented, not a special case):
#   bring2lite writes per-page .log files under <out>/<db>/<dir>/. It separates
#   the carved/recovered-deleted content from the intact live b-tree:
#     * freeblocks/        in-page free-block deletions   -> RECOVERED (emit)
#     * freelists/         freelist leaf/trunk page carve -> RECOVERED (emit)
#     * unalloc-parsing/   unallocated-area carve         -> RECOVERED (emit)
#     * regular-page-parsing/  the live b-tree dump       -> LIVE (suppress)
#   Only the first three are deleted-record recovery; regular-page-parsing is a
#   re-dump of the still-live table and is NOT a recovery claim (undark/fqlite do
#   not re-emit the live b-tree either), so including it would unfairly inflate
#   bring2lite's live-re-read count. The schema-header first line of each report
#   ("INT,INT,..." / "No schema found,") and the "++++"/"####" separators are
#   dropped; every remaining non-empty line is a recovered record.
#
# Environment (override to point at a non-default checkout):
#   BRING2LITE_DIR   directory containing main.py (default: tools/bring2lite/pkg
#                    relative to this script)
#   PYTHON           python interpreter (default: python3)
#
# The wrapper is deterministic and self-contained: it makes its own temp out-dir,
# adds the headless PyQt5 shim to PYTHONPATH only when a real PyQt5 is absent, and
# cleans up on exit.
set -euo pipefail

db="${1:?usage: run-bring2lite.sh <database.db>}"
# Resolve to an absolute path before any `cd` (bring2lite runs from its pkg dir).
db="$(cd "$(dirname "$db")" && pwd)/$(basename "$db")"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pkg="${BRING2LITE_DIR:-$here/../tools/bring2lite/pkg}"
shim="$here/../tools/bring2lite/shim"
py="${PYTHON:-python3}"

if [ ! -f "$pkg/main.py" ]; then
  echo "run-bring2lite.sh: bring2lite main.py not found at $pkg/main.py" >&2
  echo "  set BRING2LITE_DIR to the checkout (see tools/README.md provenance)" >&2
  exit 2
fi

# Use the headless PyQt5 stub only when a real PyQt5 is unavailable.
if ! "$py" -c 'import PyQt5' >/dev/null 2>&1; then
  export PYTHONPATH="${shim}${PYTHONPATH:+:$PYTHONPATH}"
fi

out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT

# bring2lite resolves its own classes relative to CWD, so run from the package dir.
( cd "$pkg" && "$py" main.py --filename "$db" --out "$out" --format CSV ) \
  >/dev/null 2>&1 || true

# Emit the carved-deleted records (freeblocks + freelists + unalloc), normalized.
# Content-based filtering (line number is unreliable: freeblock files have no
# header, generateReport files do):
#   * drop "++++"/"####" separators and blank lines
#   * drop the schema-header line whose first field is a type token
#     (INT/TEXT/REAL/BLOB/NULL) or "No schema found"
#   * drop the raw-tuple fallback dump lines that begin with "[" (the same record
#     re-emitted un-decoded as [['8bit', N], ...] — no format-stable identity)
# every remaining non-empty line is a recovered record "col0,col1,col2,...".
find "$out" \( -path '*/freeblocks/*' -o -path '*/freelists/*' -o -path '*/unalloc-parsing/*' \) \
     -name '*.log' -print0 2>/dev/null \
| while IFS= read -r -d '' f; do
    awk '
      /^\+\+\+\+/ { next }
      /^#####/ { next }
      /^[[:space:]]*$/ { next }
      /^\[/ { next }
      /^No schema found,/ { next }
      /^(INT|TEXT|REAL|BLOB|NULL)[, ]/ { next }
      { print }
    ' "$f"
  done
