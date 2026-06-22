#!/usr/bin/env python3
"""Generate cross_table_rowid.db — a regression fixture for the exclusion-invariant
hole where live-row identity is keyed by a GLOBAL rowid with no table dimension
(docs/improvement-roadmap.md §1.1).

Construction (real sqlite3 engine, secure_delete=OFF so freed pages keep payload):
  * Table `t` (created FIRST): the paper 0F B-tree-rebalancing scenario — 80 rows
    of ~420-byte id-tagged TEXT, then DELETE ids 1..50. The range delete triggers
    interior-node merges that free pages still holding some still-LIVE rows
    (ids 51..80), exactly the Choi Type-** substrate.
  * Table `z` (created SECOND, so it wins Database::live_rows()'s rowid-keyed
    collapse): rows at the SAME rowids 51..80 as t's survivors, with DIFFERENT
    values. Because live_rows() is keyed by rowid alone, z's rows overwrite t's in
    the collapsed map.

Effect: when the carver surfaces one of t's live rows (51..80) from a freed page
(intact rowid), the exclusion filter does live.get(rowid) and gets z's row — whose
values differ — so it fails to recognise t's live row and re-surfaces it as a
deleted "prior version". That is a breach of the exclusion invariant (never report
a live row as deleted), latent because no single-table corpus exercises it.

Ground truth: t live ids 51..80 (v = "ROW-<id>-XXXX…"); t deleted ids 1..50;
z live ids 51..80 (v = "ZZZ-<id>-QQQ…"). NO carved record's values may equal any
currently-live row of either table.
"""
import os
import sqlite3

HERE = os.path.dirname(os.path.abspath(__file__))
PATH = os.path.join(HERE, "cross_table_rowid.db")


def t_value(i):
    tag = "ROW-%d-" % i
    return tag + "X" * (420 - len(tag))


def z_value(i):
    tag = "ZZZ-%d-" % i
    return tag + "Q" * (40 - len(tag))


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
    con.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)")  # first -> loses collapse
    con.execute("CREATE TABLE z(id INTEGER PRIMARY KEY, v TEXT)")  # second -> wins collapse
    con.executemany(
        "INSERT INTO t(id, v) VALUES (?, ?)", [(i, t_value(i)) for i in range(1, 81)]
    )
    con.executemany(
        "INSERT INTO z(id, v) VALUES (?, ?)", [(i, z_value(i)) for i in range(51, 81)]
    )
    con.commit()
    con.execute("DELETE FROM t WHERE id BETWEEN 1 AND 50")
    con.commit()
    con.close()
    print("wrote", PATH, os.path.getsize(PATH), "bytes")


if __name__ == "__main__":
    main()
