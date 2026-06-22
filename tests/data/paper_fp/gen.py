#!/usr/bin/env python3
"""Generate the three replicated false-positive scenarios from Lee, Park, Lee &
Choi, "A study on the false positives of existing tools for recovering deleted
records in SQLite databases", FSI:DI 55 (2025), art. 302031
(DOI 10.1016/j.fsidi.2025.302031), Table 5.

These are REPLICATIONS of the paper's scenario *construction*, built with the
real sqlite3 engine via Python's stdlib `sqlite3` module. They are NOT the
paper's official corpus (that corpus + code is "released upon publication" and
is not yet public). The construction parameters follow Table 5; the exact bytes
differ from the authors' artifacts. See README.md for ground truth + provenance.

Run from anywhere:  python3 gen.py
Writes f.db, b.db, wcase.db (+ wcase.db-wal) beside this script.
Deterministic: re-running reproduces byte-identical files on the same engine.
"""

import os
import sqlite3

HERE = os.path.dirname(os.path.abspath(__file__))


def _fresh(path):
    """Remove a db and any sidecars so each run starts clean."""
    for suffix in ("", "-wal", "-shm", "-journal"):
        p = path + suffix
        if os.path.exists(p):
            os.remove(p)


def gen_0f_rebalancing():
    """Scenario 0F — B-tree rebalancing (paper Type ** false positive).

    A range DELETE triggers interior-node merges; freed pages keep their
    payload. A carver that does not exclude *live* rowids can mis-attribute the
    still-live rows that a rebalance shuffled onto a freed page.

    Construction: 80 rows with a ~420-byte TEXT value, delete ids 1..50. Each
    value embeds its id (`ROW-<id>-XXXX…`) so a content-keyed tool whose output
    drops the rowid (bring2lite emits a NULL rowid-alias cell) can still
    be scored against the live/deleted sets — this distinguishes a Type-** false
    positive (a *live* 51..80 row surfaced from a freed page) from a true deleted
    recovery, which an all-identical payload would make impossible to tell apart.
    Ground truth: live ids 51..80 (30 rows), deleted ids 1..50.
    """
    path = os.path.join(HERE, "f.db")
    _fresh(path)
    con = sqlite3.connect(path)
    con.execute("PRAGMA page_size=4096")
    con.execute("PRAGMA auto_vacuum=NONE")
    con.execute("PRAGMA secure_delete=OFF")
    con.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)")

    def value_for(i):
        # ~420 bytes total, id-tagged so the row is identifiable by content alone.
        tag = "ROW-%d-" % i
        return tag + "X" * (420 - len(tag))

    con.executemany(
        "INSERT INTO t(id, v) VALUES (?, ?)",
        [(i, value_for(i)) for i in range(1, 81)],
    )
    con.commit()
    con.execute("DELETE FROM t WHERE id BETWEEN 1 AND 50")
    con.commit()
    con.close()
    return path


def gen_0b_overwritten_table():
    """Scenario 0B — overwritten table, same schema (paper Type * false positive).

    A table is DROPped and re-CREATEd with the SAME schema, then repopulated.
    Residual rows from the dropped table can be mis-attributed to the recreated
    same-name table by ownership heuristics.

    Construction: 10 OLD rows, DROP, recreate same schema, 5 NEW rows.
    Ground truth: live ids 1..5 (NEW-NAME), dropped residue = 10 OLD-NAME rows.
    """
    path = os.path.join(HERE, "b.db")
    _fresh(path)
    con = sqlite3.connect(path)
    con.execute("PRAGMA page_size=4096")
    con.execute("PRAGMA auto_vacuum=NONE")
    con.execute("PRAGMA secure_delete=OFF")
    con.execute(
        "CREATE TABLE students(id INTEGER PRIMARY KEY, name TEXT, affil TEXT)"
    )
    con.executemany(
        "INSERT INTO students(id, name, affil) VALUES (?, ?, ?)",
        [(i, "OLD-NAME-%d" % i, "OLD-AFFIL-%d" % i) for i in range(1, 11)],
    )
    con.commit()
    con.execute("DROP TABLE students")
    con.commit()
    con.execute(
        "CREATE TABLE students(id INTEGER PRIMARY KEY, name TEXT, affil TEXT)"
    )
    con.executemany(
        "INSERT INTO students(id, name, affil) VALUES (?, ?, ?)",
        [(i, "NEW-NAME-%d" % i, "NEW-AFFIL-%d" % i) for i in range(1, 6)],
    )
    con.commit()
    con.close()
    return path


def gen_10_wal_secure_delete():
    """Scenario 10 — WAL + secure_delete=ON (paper: WAL-only recovery).

    With secure_delete=ON the deleted payload is zeroed wherever it is rewritten;
    by never checkpointing, the inserted rows live only as WAL frames, so the
    only residue is in the uncheckpointed -wal and the main image carries none of
    the message bodies. A second reader holds a snapshot open to pin the WAL, then
    db + -wal are COPIED while connections are open — SQLite checkpoints the WAL
    on last-connection close, so the live db/-wal pair must be snapshotted before
    that close (the copies are never reopened with sqlite3 here, which would also
    checkpoint them away).

    Construction: 20 rows inserted into the WAL (NOT checkpointed), all 20
    deleted, copy db + -wal while a reader pins the WAL.
    Ground truth: live 0, deleted ids 1..20 — residue ONLY in -wal, main image
    holds zero message bodies.
    """
    import shutil

    work = os.path.join(HERE, "_wal_work.db")
    _fresh(work)
    path = os.path.join(HERE, "wcase.db")
    _fresh(path)

    writer = sqlite3.connect(work)
    writer.execute("PRAGMA page_size=4096")
    writer.execute("PRAGMA auto_vacuum=NONE")
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("PRAGMA wal_autocheckpoint=0")
    writer.execute("PRAGMA secure_delete=ON")
    writer.execute("CREATE TABLE msg(id INTEGER PRIMARY KEY, body TEXT)")
    writer.executemany(
        "INSERT INTO msg(id, body) VALUES (?, ?)",
        [(i, "SECRET-MESSAGE-%d" % i) for i in range(1, 21)],
    )
    writer.commit()

    # A second connection opens a read snapshot and holds it: this pins the WAL
    # so neither a checkpoint nor a close can reclaim the frames while we copy.
    reader = sqlite3.connect(work)
    reader.execute("BEGIN")
    reader.execute("SELECT count(*) FROM msg").fetchall()

    writer.execute("DELETE FROM msg WHERE id BETWEEN 1 AND 20")
    writer.commit()  # delete frames land in -wal (never checkpointed)

    if not os.path.exists(work + "-wal"):
        raise RuntimeError("-wal must exist (uncheckpointed insert+delete)")

    # Snapshot the OPEN db + -wal to the final names before any close-checkpoint.
    shutil.copyfile(work, path)
    shutil.copyfile(work + "-wal", path + "-wal")

    reader.close()
    writer.close()
    _fresh(work)  # drop the working db + its (now checkpointed) sidecars
    return path


def md5(path):
    import hashlib

    h = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    f = gen_0f_rebalancing()
    b = gen_0b_overwritten_table()
    w = gen_10_wal_secure_delete()
    for label, p in (("0F f.db", f), ("0B b.db", b), ("10 wcase.db", w)):
        print("%-14s %s  %d bytes" % (label, md5(p), os.path.getsize(p)))
    wal = w + "-wal"
    if os.path.exists(wal):
        print("%-14s %s  %d bytes" % ("10 wcase.db-wal", md5(wal), os.path.getsize(wal)))


if __name__ == "__main__":
    main()
