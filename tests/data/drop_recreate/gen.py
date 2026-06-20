#!/usr/bin/env python3
"""Generate the drop-recreate residue fixtures for the AUTOINCREMENT high-water
diagnostic (Detector A), per `docs/design/drop-recreate-attribution.md`.

These are SYNTHETIC, built with the real sqlite3 engine via Python's stdlib
`sqlite3` module. They exercise the `table_instance_risk` HINT flag, which fires
only when a residue record attributed to an AUTOINCREMENT table has a
`rowid > sqlite_sequence` high-water mark — and which the design deliberately
frames as a hint, NOT a per-row predecessor assertion.

Run from anywhere:  python3 gen.py
Writes b_autoinc.db, b_plainpk.db, upd_autoinc.db beside this script.
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


def _connect(path):
    _fresh(path)
    con = sqlite3.connect(path)
    con.execute("PRAGMA page_size=4096")
    con.execute("PRAGMA auto_vacuum=NONE")
    con.execute("PRAGMA secure_delete=OFF")
    return con


def gen_b_autoinc():
    """`b_autoinc.db` — AUTOINCREMENT drop-recreate (Detector A FIRES).

    AUTOINCREMENT `students`: INSERT 10, DROP, CREATE same schema, INSERT 5.
    sqlite_sequence is RESET to 5 on the recreate (the DROP deleted its row).
    Residue rowids 6..10 survive in the reused pages and exceed seq=5, so the
    flag fires on the recovered 6..10. Ground truth: live ids 1..5 (NEW), residue
    ids 6..10 (OLD) genuinely predate the current instance.
    """
    path = os.path.join(HERE, "b_autoinc.db")
    con = _connect(path)
    schema = (
        "CREATE TABLE students("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, affil TEXT)"
    )
    con.execute(schema)
    con.executemany(
        "INSERT INTO students(name, affil) VALUES (?, ?)",
        [("OLD-NAME-%d" % i, "OLD-AFFIL-%d" % i) for i in range(1, 11)],
    )
    con.commit()
    con.execute("DROP TABLE students")
    con.commit()
    con.execute(schema)
    con.executemany(
        "INSERT INTO students(name, affil) VALUES (?, ?)",
        [("NEW-NAME-%d" % i, "NEW-AFFIL-%d" % i) for i in range(1, 6)],
    )
    con.commit()
    con.close()
    return path


def gen_b_plainpk():
    """`b_plainpk.db` — plain INTEGER PRIMARY KEY drop-recreate (flag NEVER fires).

    Identical construction to b_autoinc but with a plain `INTEGER PRIMARY KEY`
    (no AUTOINCREMENT). No sqlite_sequence row exists, so Detector A has no
    high-water mark to compare against and the flag never fires — the honest
    limit the design documents (the survey's exact undecidable 0B case).
    Ground truth: live ids 1..5 (NEW), residue ids 6..10 (OLD).
    """
    path = os.path.join(HERE, "b_plainpk.db")
    con = _connect(path)
    schema = "CREATE TABLE students(id INTEGER PRIMARY KEY, name TEXT, affil TEXT)"
    con.execute(schema)
    con.executemany(
        "INSERT INTO students(id, name, affil) VALUES (?, ?, ?)",
        [(i, "OLD-NAME-%d" % i, "OLD-AFFIL-%d" % i) for i in range(1, 11)],
    )
    con.commit()
    con.execute("DROP TABLE students")
    con.commit()
    con.execute(schema)
    con.executemany(
        "INSERT INTO students(id, name, affil) VALUES (?, ?, ?)",
        [(i, "NEW-NAME-%d" % i, "NEW-AFFIL-%d" % i) for i in range(1, 6)],
    )
    con.commit()
    con.close()
    return path


def gen_upd_autoinc():
    """`upd_autoinc.db` — Codex BLOCKER-1 case (flag FIRES on a CURRENT row).

    AUTOINCREMENT `t`: INSERT one row (id=5), UPDATE its id to 1000, then DELETE
    it. sqlite_sequence stays at 5 (UPDATE of the rowid does not advance the
    INSERT high-water mark), so the residue rowid 1000 > seq 5 trips the flag —
    yet the row was a CURRENT-instance row that an UPDATE moved, NOT a dropped
    predecessor. This fixture is the proof the flag is a HINT, not an assertion:
    `r > seq` is reachable without any drop-recreate.
    Ground truth: live 0, residue rowid 1000 (a moved-then-deleted current row).
    """
    path = os.path.join(HERE, "upd_autoinc.db")
    con = _connect(path)
    con.execute("CREATE TABLE t(id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT)")
    con.execute("INSERT INTO t(id, v) VALUES (5, 'MOVED-ROW')")
    con.commit()
    con.execute("UPDATE t SET id=1000 WHERE id=5")
    con.commit()
    con.execute("DELETE FROM t WHERE id=1000")
    con.commit()
    con.close()
    return path


def md5(path):
    import hashlib

    h = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    a = gen_b_autoinc()
    p = gen_b_plainpk()
    u = gen_upd_autoinc()
    for label, path in (
        ("b_autoinc.db", a),
        ("b_plainpk.db", p),
        ("upd_autoinc.db", u),
    ):
        print("%-16s %s  %d bytes" % (label, md5(path), os.path.getsize(path)))


if __name__ == "__main__":
    main()
