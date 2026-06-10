# Test Data — `tests/data/`

Committed SQLite fixtures shared by both workspace members. `core/tests/*.rs` and
`forensic/tests/*.rs` reach them with the symmetric relative path
`include_bytes!("../../tests/data/<file>")`.

For the per-repo index (classification + oracle methodology) see
[`../../docs/corpus-catalog.md`](../../docs/corpus-catalog.md); for the
deleted-record carving validation see
[`../../docs/validation.md`](../../docs/validation.md). The gitignored
independent-oracle corpus is documented separately in
[`../../tests-fqlite-corpus/README.md`](../../tests-fqlite-corpus/README.md).

All files here are **SYNTHETIC** — built locally with the real `sqlite3` engine
(`SQLite 3.45.3 2024-04-15`, REAL engine / synthetic data). The generator command
IS the provenance; there is no download URL.

#### places.db

- **Source:** SYNTHETIC — system `sqlite3` CLI.
- **Identity:** single-table `moz_places` DB exercising every SQLite storage class
  (Integer/Real/Text/Blob/Null) and the `INTEGER PRIMARY KEY` rowid-alias rule.
  Pre-existing WS-C spike fixture (also documented in
  `docs/ws-c-sqlite-core-spike.md`).
- **Generator:**

  ```sh
  sqlite3 tests/data/places.db <<'SQL'
  CREATE TABLE moz_places (
    id INTEGER PRIMARY KEY,
    url TEXT NOT NULL,
    title TEXT,
    visit_count INTEGER DEFAULT 0,
    last_visit_date INTEGER,
    frecency REAL
  );
  INSERT INTO moz_places (url, title, visit_count, last_visit_date, frecency) VALUES
   ('https://www.rust-lang.org/', 'Rust Programming Language', 5, 1700000000000000, 2000.5),
   ('https://github.com/', 'GitHub', 12, 1700000100000000, 5500.0),
   ('https://news.ycombinator.com/', 'Hacker News', 3, NULL, -1.0),
   ('https://en.wikipedia.org/wiki/SQLite', 'SQLite - Wikipedia', 1, 1700000200000000, NULL),
   ('https://example.com/', NULL, 0, 1700000300000000, 0.0);
  SQL
  ```

- **md5:** `f07a69d05358f227e2120080370bbb6b` — 8192 bytes (2 pages, 4096-byte page).
- **Notable contents:** `frecency` as Real; one NULL `title`, one NULL
  `last_visit_date`, one negative `frecency`. `moz_places` root page = 2. Used by
  `core/tests/real_db.rs`, `core/tests/freelist.rs`, `forensic/tests/audit_realdb.rs`.

#### overflow.db

- **Source:** SYNTHETIC — Python `sqlite3` module.
- **Identity:** one `notes` row whose ~12 KB TEXT body spills onto an
  overflow-page chain, plus one small inline row. Used by `core/tests/overflow.rs`.
- **Generator:**

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

- **md5:** `1c17320320a173fb5968c598f9df7373` — 16384 bytes (4 pages).
- **Notable contents:** `notes` root page = 2; row id=1 body length = 12017
  (overflow chain); row id=2 inline.

#### deleted_places.db

- **Source:** SYNTHETIC — Python `sqlite3` module.
- **Identity:** `moz_places` with 400 rows inserted, ids 201..=400 `DELETE`d
  **without VACUUM** under `secure_delete=OFF`, freeing whole leaf pages onto the
  freelist whose old cell content survives. The deleted-record carving fixture
  (`forensic/tests/carve.rs`, `forensic/tests/fqlite_oracle.rs`,
  `forensic/tests/audit_realdb.rs`) and the freelist fixture
  (`core/tests/freelist.rs`).
- **Generator:**

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

- **md5:** `16682d7df99b1e8a89287a508d95eb47` — 53248 bytes.
- **Notable contents:** live rows = 200 (ids 1..=200), deleted ids 201..=400;
  `PRAGMA freelist_count` = 5, `PRAGMA page_count` = 13; `moz_places` root = 2.
  Freelist = trunk page 9 + leaf pages 10–13. Note: `secure_delete` defaults to
  **ON** on this build — without the explicit `PRAGMA secure_delete=OFF` the
  deleted content is wiped and nothing is carvable. (Many real browser DBs run
  with `secure_delete` off, so this is realistic.)

#### wal_places.db + wal_places.db-wal

- **Source:** SYNTHETIC — Python `sqlite3` module, snapshotted mid-transaction.
- **Identity:** a main DB + persistent `-wal` sidecar captured
  **mid-transaction** — a held reader connection blocks the checkpoint so the WAL
  survives on disk with one committed COMMIT frame (page 2) the main file does not
  yet reflect. Used by `core/tests/wal.rs` and the WAL branch of
  `forensic/tests/audit_realdb.rs`.
- **Generator:**

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
  con.execute("PRAGMA wal_checkpoint(TRUNCATE)"); con.commit()  # baseline -> main file
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

- **md5:** `wal_places.db` = `bad96eb068359bcb142533696b6515fc` (8192 bytes);
  `wal_places.db-wal` = `84b08a77d90914c917d92e60a6c8eeab` (4152 bytes).
- **Notable contents:** main-only view = id=1 title `Rust`, visit_count 5, 2 rows;
  WAL-applied view = id=1 title `Rust (EDITED IN WAL)`, visit_count 777, plus id=3
  `WAL-ONLY ROW`, 3 rows. WAL = 1 COMMIT frame for page 2.
