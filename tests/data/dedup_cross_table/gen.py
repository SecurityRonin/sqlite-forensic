#!/usr/bin/env python3
"""Generate cross_table_identity.db — a regression fixture for dedup collapsing
genuinely-distinct deleted records that two tables share (docs/improvement-roadmap.md
§1.2).

Two live tables `a` and `b` each hold rows (1,'DUP-1') and (2,'DUP-2') with
IDENTICAL (rowid, values), plus a distinct keeper row so each table stays live
(its pages remain allocated, so the deleted rows are recovered as in-page residue
attributable to their owning table). Both tables then DELETE ids 1 and 2.

The carver recovers (1,'DUP-1') and (2,'DUP-2') from BOTH a's and b's free space —
four physically-distinct deleted records. A dedup keyed only on (rowid, values)
collapses each identity to one, dropping two genuinely-distinct deleted rows. The
fix keys attributed records by (table, rowid, values), keeping all four.
"""
import os
import sqlite3

HERE = os.path.dirname(os.path.abspath(__file__))
PATH = os.path.join(HERE, "cross_table_identity.db")


def main():
    for suffix in ("", "-wal", "-journal"):
        try:
            os.remove(PATH + suffix)
        except FileNotFoundError:
            pass
    con = sqlite3.connect(PATH)
    con.execute("PRAGMA page_size=4096")
    con.execute("PRAGMA auto_vacuum=NONE")
    con.execute("PRAGMA secure_delete=OFF")
    con.execute("CREATE TABLE a(id INTEGER PRIMARY KEY, v TEXT)")
    con.execute("CREATE TABLE b(id INTEGER PRIMARY KEY, v TEXT)")
    for t in ("a", "b"):
        con.executemany(
            f"INSERT INTO {t}(id, v) VALUES (?, ?)",
            [(1, "DUP-1"), (2, "DUP-2"), (3, f"KEEP-{t}")],
        )
    con.commit()
    con.execute("DELETE FROM a WHERE id IN (1, 2)")
    con.execute("DELETE FROM b WHERE id IN (1, 2)")
    con.commit()
    con.close()
    print("wrote", PATH, os.path.getsize(PATH), "bytes")


if __name__ == "__main__":
    main()
