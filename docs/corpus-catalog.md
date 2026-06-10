# `sqlite-forensic` Test Corpus Catalog

This is the per-repo record of the SQLite test fixtures under `core/tests/data/`
and `forensic/tests/data/`. It mirrors the fleet-wide catalog discipline
(`issen/docs/corpus-catalog.md`); the verbatim generator for each synthetic
fixture is recorded here so the corpus is reproducible. Unlike most fleet repos,
these fixtures **are committed** (only `/target` is gitignored), but the
generators are kept here regardless so anyone can rebuild or vary them.

All fixtures were built with the system `sqlite3` CLI / Python `sqlite3` module:
`SQLite 3.45.3 2024-04-15` (CLI version string above).

> Follow-up (flagged, NOT done this round): promote these entries into the
> fleet-wide `issen/docs/corpus-catalog.md` and add the missing
> `forensicnomicon::sqlite` constants (B-tree page-type bytes, serial-type rules,
> reserved-space offset 20, in-header DB-size offset 28, freelist-count offset 36,
> WAL salt/checksum offsets). Both are owned by other live repos this round.

## Classification

`SYNTHETIC` — all built locally with the real `sqlite3` engine (REAL engine,
synthetic data). Confidence `✓` (confirmed: each generator below was run and the
resulting file inspected, not just named).

## §A `core/tests/data/places.db`  (pre-existing, WS-C spike)

Single-table `moz_places` DB exercising every storage class + the rowid-alias
rule. Generator is documented in `docs/ws-c-sqlite-core-spike.md` §generator.

- md5 `f07a69d05358f227e2120080370bbb6b`, 8192 bytes (2 pages, 4096-byte page).

## §B `core/tests/data/overflow.db`  (overflow-page chain)

One `notes` row whose ~12 KB TEXT body spills onto an overflow-page chain, plus
one small row that fits on the leaf. Drives `core/tests/overflow.rs`.

```sh
python3 - <<'PY'
import sqlite3
con = sqlite3.connect('overflow.db')
con.executescript("PRAGMA page_size=4096; PRAGMA auto_vacuum=NONE;")
con.execute("CREATE TABLE notes(id INTEGER PRIMARY KEY, body TEXT)")
big = "OVERFLOW_PAYLOAD_" + ("ABCDEFGHIJ" * 1200)  # 12017 chars
con.execute("INSERT INTO notes VALUES (1, ?)", (big,))
con.execute("INSERT INTO notes VALUES (2, 'small row')")
con.commit(); con.close()
PY
```

- `notes` root page = 2; row id=1 body length = 12017; 4 pages total.
- md5 `1c17320320a173fb5968c598f9df7373`, 16384 bytes.

## §C `forensic/tests/data/deleted_places.db`  (deleted-record carving)

`moz_places` with 400 rows inserted, ids 201..=400 `DELETE`d **without VACUUM**,
under `secure_delete=OFF` so the freed leaf pages retain the deleted records.
This is the carving fixture (`forensic/tests/carve.rs`,
`forensic/tests/audit_realdb.rs`) and the freelist fixture
(`core/tests/freelist.rs`).

```sh
python3 - <<'PY'
import sqlite3
con = sqlite3.connect('deleted_places.db')
con.executescript("""
PRAGMA page_size=4096; PRAGMA auto_vacuum=NONE; PRAGMA secure_delete=OFF;
CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT,
  visit_count INTEGER, last_visit_date INTEGER, frecency REAL);
WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n < 400)
INSERT INTO moz_places SELECT n,
  'https://site-'||n||'.example.com/path/page',
  'Title for record number '||n||' SECRETMARKER',
  n%100, 1700000000000000+n, n*1.5 FROM seq;
DELETE FROM moz_places WHERE id > 200;
""")
con.commit(); con.close()
PY
```

- Ground truth: live rows = 200 (ids 1..=200), deleted ids 201..=400;
  `PRAGMA freelist_count` = 5, `PRAGMA page_count` = 13; `moz_places` root = 2.
- md5 `16682d7df99b1e8a89287a508d95eb47`, 53248 bytes.

> Note: `secure_delete` defaults to **ON** on this build; without the explicit
> `PRAGMA secure_delete=OFF` the deleted content is wiped and nothing is
> carvable. Many real-world browser DBs run with secure_delete off, so this is a
> realistic — not contrived — recovery scenario.

## §D `core/tests/data/wal_places.db` + `…-wal`  (read-only WAL overlay)

A main DB + persistent `-wal` sidecar captured **mid-transaction**: a held reader
connection blocks the checkpoint so the WAL survives on disk with one committed
COMMIT frame (page 2) that the main file does not yet reflect. Drives
`core/tests/wal.rs` and the WAL branch of `forensic/tests/audit_realdb.rs`.

```sh
python3 - <<'PY'
import sqlite3, shutil
con = sqlite3.connect('wal.db')
con.executescript("""
PRAGMA page_size=4096; PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;
CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT,
  visit_count INTEGER, last_visit_date INTEGER, frecency REAL);
INSERT INTO moz_places VALUES (1,'https://www.rust-lang.org/','Rust',5,1700000000000000,2000.5);
INSERT INTO moz_places VALUES (2,'https://github.com/','GitHub',12,1700000100000000,5500.0);
""")
con.commit()
con.execute("PRAGMA wal_checkpoint(TRUNCATE)"); con.commit()  # baseline → main file
reader = sqlite3.connect('wal.db')                            # hold a read txn
reader.execute("BEGIN"); reader.execute("SELECT count(*) FROM moz_places").fetchone()
con.execute("PRAGMA wal_autocheckpoint=0")
con.execute("UPDATE moz_places SET title='Rust (EDITED IN WAL)', visit_count=777 WHERE id=1")
con.execute("INSERT INTO moz_places VALUES (3,'https://wal-only-row.example/','WAL-ONLY ROW',1,1700000200000000,100.0)")
con.commit()
shutil.copy('wal.db','wal_places.db')          # snapshot while WAL is live
shutil.copy('wal.db-wal','wal_places.db-wal')
PY
```

- Ground truth: main-only view = id=1 title `Rust`, visit_count 5, 2 rows;
  WAL-applied view = id=1 title `Rust (EDITED IN WAL)`, visit_count 777, plus
  id=3 `WAL-ONLY ROW`, 3 rows. WAL = 1 COMMIT frame for page 2.
- md5 `wal_places.db` = `bad96eb068359bcb142533696b6515fc`, 8192 bytes.
- md5 `wal_places.db-wal` = `84b08a77d90914c917d92e60a6c8eeab`, 4152 bytes.

## §E MD5 manifest

| file | md5 | bytes |
|---|---|---|
| `core/tests/data/places.db` | `f07a69d05358f227e2120080370bbb6b` | 8192 |
| `core/tests/data/overflow.db` | `1c17320320a173fb5968c598f9df7373` | 16384 |
| `core/tests/data/wal_places.db` | `bad96eb068359bcb142533696b6515fc` | 8192 |
| `core/tests/data/wal_places.db-wal` | `84b08a77d90914c917d92e60a6c8eeab` | 4152 |
| `forensic/tests/data/deleted_places.db` | `16682d7df99b1e8a89287a508d95eb47` | 53248 |
