#!/usr/bin/env bash
# Normalized oracle wrapper for DC3 SQLite Dissect (sqlite_dissect).
#
# Usage:   run-sqlite-dissect.sh <database.db>
# Emits:   one recovered record per line on stdout as:   rowid,col1,col2,...
#          (the same normalized shape run-bring2lite.sh emits; the Rust harness
#          projects fields[1],fields[2] as the cross-tool (col1,col2) identity.)
#
# SQLite Dissect (DoD Cyber Crime Center) parses the database together with its
# rollback journal and WAL and exports recovered cells -- including carved/deleted
# records -- to CSV. This wrapper runs a CSV export and projects each carved record
# to `rowid,<data columns>`.
#
# Environment:
#   SQLITE_DISSECT   the sqlite_dissect entrypoint (default: `sqlite_dissect` on
#                    PATH; e.g. "python -m sqlite_dissect" for a pip install)
#   PYTHON           python interpreter for the normalizer (default: python3)
#
# VALIDATE ON FIRST RUN: SQLite Dissect's CSV prepends a block of metadata columns
# (File Source ... Operation, File Offset) before the table's own columns, and an
# "Operation" column marking carved vs live rows. The exact metadata set is
# version-dependent; the normalizer below locates the data columns from the CSV
# header and keeps rows whose Operation is not "Added" (i.e. carved/deleted).
# Confirm the header names against your sqlite_dissect version once and adjust META
# / the live marker if they differ. This leg is env-gated: the head-to-head skips
# it unless SQLITE_DISSECT_CMD points at this script (see tools/README.md).
set -euo pipefail

db="${1:?usage: run-sqlite-dissect.sh <database.db>}"
sd="${SQLITE_DISSECT:-sqlite_dissect}"
py="${PYTHON:-python3}"

outdir="$(mktemp -d)"
trap 'rm -rf "$outdir"' EXIT

# Export recovered cells to CSV (one file per table), with carving + freelist
# carving enabled (SQLite Dissect does NOT carve by default). Errors are tolerated
# so a partially-parseable database still yields what it can.
# shellcheck disable=SC2086
$sd "$db" -c -f -e csv -d "$outdir" >/dev/null 2>&1 || true

# Normalize every per-table CSV to one record per line in column order
# (`col0,col1,col2,...`) for carved records only, so the harness projection of
# fields[1],fields[2] is the answer key's (col1,col2) identity. SQLite Dissect's
# CSV prepends these metadata columns before the table's own columns:
"$py" - "$outdir" <<'PY'
import csv, glob, os, sys

outdir = sys.argv[1]
META = {
    "file source", "version", "page version", "cell source", "page number",
    "location", "operation", "file offset", "row id",
}
for path in sorted(glob.glob(os.path.join(outdir, "*.csv"))):
    with open(path, newline="") as fh:
        reader = csv.reader(fh)
        try:
            header = next(reader)
        except StopIteration:
            continue
        low = [h.strip().lower() for h in header]
        op_i = low.index("operation") if "operation" in low else None
        data_i = [i for i, h in enumerate(low) if h not in META]
        for row in reader:
            # Keep recovered deletions only -- skip live ("Added") rows.
            if op_i is not None and op_i < len(row) and row[op_i].strip().lower() == "added":
                continue
            cols = [row[i] for i in data_i if i < len(row)]
            if cols:
                print(",".join(cols))
PY
