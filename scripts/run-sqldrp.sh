#!/usr/bin/env bash
# Normalized oracle wrapper for the SQLite Deleted Records Parser
# (Mari DeGrazia, "sqlparse" v1.3), ported to Python 3.
#
# Usage:   run-sqldrp.sh <database.db>
# Emits:   the tool's TSV recovery report on stdout, one record per line:
#              Type<TAB>Offset<TAB>Length<TAB>Data
#          The header line ("Type\tOffset\tLength\tData") is preserved as the
#          tool emits it so the Rust harness can detect and skip it.
#
# IMPORTANT — capability boundary (measured, not assumed): sqlparse is a printable
# STRING carver, not a per-column record parser. Its `Data` field is a single
# space-joined printable-ASCII blob extracted from each freeblock / unallocated
# region (see remove_ascii_non_printable in the source), NOT a "col0,col1,col2"
# tuple. It therefore has no format-stable (col1,col2) cross-tool identity of the
# kind the Nemetz head-to-head scores, and it recovers nothing at all from the
# integer-valued tables (0C/0D) because integers are not printable strings. The
# head-to-head harness records this as a documented boundary rather than scoring a
# confounded key (the same discipline that excludes the 0C-06/0C-07 FLOAT tables).
#
# Environment (override to point at a non-default checkout):
#   SQLDRP_SCRIPT   path to the Py3-ported sqlparse script
#                   (default: tools/sqldrp/sqlparse_v1.3.py relative to here)
#   PYTHON          python interpreter (default: python3)
set -euo pipefail

db="${1:?usage: run-sqldrp.sh <database.db>}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
script="${SQLDRP_SCRIPT:-$here/../tools/sqldrp/sqlparse_v1.3.py}"
py="${PYTHON:-python3}"

if [ ! -f "$script" ]; then
  echo "run-sqldrp.sh: sqlparse script not found at $script" >&2
  echo "  set SQLDRP_SCRIPT to the Py3-ported script (see tools/README.md)" >&2
  exit 2
fi

out="$(mktemp)"
trap 'rm -f "$out"' EXIT

"$py" "$script" -f "$db" -o "$out" >/dev/null 2>&1 || true
cat "$out"
