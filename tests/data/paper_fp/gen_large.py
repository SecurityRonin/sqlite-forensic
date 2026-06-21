#!/usr/bin/env python3
"""Generate a ~100 MB messages-like SQLite database with a known deleted subset,
for the throughput benchmark that sits alongside the survey's reported timings
(Undark 2.94 s, SQLite-DRP 3.97 s, FQLite 13.62 s, Bring2Lite 21.89 s on its own
100 MB DB; see docs/competitive-landscape.md "Throughput").

The file is LARGE and is gitignored — like the other large/manual artifacts in
the corpus catalog, it is documented but never committed. Regenerate it locally
when you want to run the throughput perf-smoke; the perf test is env-gated
(SQLITE_FORENSIC_PERF_DB) and skips cleanly when the file is absent.

Construction (real sqlite3 engine via stdlib):
  - one `messages` table, hundreds of thousands of rows;
  - each body is id-tagged `MSG-<id>-...` so a recovered deleted row is
    identifiable by content alone (the rowid alias is an INTEGER PRIMARY KEY);
  - secure_delete=OFF and auto_vacuum=NONE so DELETEd payload stays on freed
    pages as recoverable residue;
  - a known contiguous subset is DELETEd, leaving real carvable residue.

The deleted id range is written to a sidecar manifest `<db>.deleted.json` so the
perf test knows the ground-truth subset without hardcoding it.

Run:  python3 gen_large.py [output_path]
Default output: $SQLITE_FORENSIC_PERF_DB or ./large_messages.db beside this file.
Re-running reproduces a byte-identical file on the same engine.
"""

import json
import os
import sqlite3
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# Sizing: ~512-byte bodies; rows are tuned so the file lands near 100 MB after
# the DELETE leaves freed pages in place (auto_vacuum=NONE never shrinks).
TARGET_BYTES = 100 * 1024 * 1024
BODY_FILLER = 480  # bytes of filler after the id tag -> ~512-byte rows
TOTAL_ROWS = 178_000  # ~512 B/row -> ~100 MB on disk (auto_vacuum=NONE keeps freed pages)
# Delete a known contiguous middle subset (leaves live rows on both sides so a
# carver must exclude live rowids, matching the false-positive discipline).
DELETE_LO = 40_001
DELETE_HI = 120_000


def _fresh(path):
    for suffix in ("", "-wal", "-shm", "-journal"):
        p = path + suffix
        if os.path.exists(p):
            os.remove(p)


def _body_for(i):
    tag = "MSG-%d-" % i
    return tag + "x" * BODY_FILLER


def generate(path):
    _fresh(path)
    con = sqlite3.connect(path)
    con.execute("PRAGMA page_size=4096")
    con.execute("PRAGMA auto_vacuum=NONE")
    con.execute("PRAGMA secure_delete=OFF")
    con.execute("PRAGMA journal_mode=DELETE")
    con.execute(
        "CREATE TABLE messages("
        "id INTEGER PRIMARY KEY, ts INTEGER, sender TEXT, body TEXT)"
    )
    batch = []
    for i in range(1, TOTAL_ROWS + 1):
        batch.append((i, 1_700_000_000 + i, "sender-%d" % (i % 1000), _body_for(i)))
        if len(batch) >= 5000:
            con.executemany(
                "INSERT INTO messages(id, ts, sender, body) VALUES (?, ?, ?, ?)",
                batch,
            )
            batch.clear()
    if batch:
        con.executemany(
            "INSERT INTO messages(id, ts, sender, body) VALUES (?, ?, ?, ?)",
            batch,
        )
    con.commit()
    con.execute(
        "DELETE FROM messages WHERE id BETWEEN ? AND ?", (DELETE_LO, DELETE_HI)
    )
    con.commit()
    con.close()

    manifest = path + ".deleted.json"
    with open(manifest, "w", encoding="utf-8") as fh:
        json.dump(
            {
                "deleted_lo": DELETE_LO,
                "deleted_hi": DELETE_HI,
                "total_rows": TOTAL_ROWS,
                "body_tag": "MSG-<id>-",
            },
            fh,
        )
    return path, manifest


def main():
    if len(sys.argv) > 1:
        path = os.path.abspath(sys.argv[1])
    else:
        path = os.environ.get(
            "SQLITE_FORENSIC_PERF_DB", os.path.join(HERE, "large_messages.db")
        )
    path, manifest = generate(path)
    size = os.path.getsize(path)
    print("wrote %s  (%d bytes, %.1f MB)" % (path, size, size / 1024 / 1024))
    print("deleted ids %d..%d  manifest %s" % (DELETE_LO, DELETE_HI, manifest))


if __name__ == "__main__":
    main()
