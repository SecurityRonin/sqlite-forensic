# `sqlite-forensic` Test Corpus Catalog

This is the per-repo record of the SQLite test fixtures under the repo-root
`tests/data/` (shared by both workspace members; co-located detail in
`tests/data/README.md`). It mirrors the fleet-wide catalog discipline
(`issen/docs/corpus-catalog.md`); the verbatim generator for each synthetic
fixture is recorded here so the corpus is reproducible. The committed fixtures
**are** in git (only `/target`, `/tools`, and `/tests-oracle-corpus` are
gitignored), but the generators are kept here regardless so anyone can rebuild or
vary them.

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

## §A `tests/data/places.db`  (pre-existing, WS-C spike)

Single-table `moz_places` DB exercising every storage class + the rowid-alias
rule. The verbatim generator is in `tests/data/README.md` (§`places.db`).

- md5 `f07a69d05358f227e2120080370bbb6b`, 8192 bytes (2 pages, 4096-byte page).

## §B `tests/data/overflow.db`  (overflow-page chain)

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

## §C `tests/data/deleted_places.db`  (deleted-record carving)

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

## §D `tests/data/wal_places.db` + `…-wal`  (read-only WAL overlay)

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

## §E `tests/data/updated_messages.db`  (prior-version / version-aware carving)

A `messages` table where row 7's `body` is **`UPDATE`d twice** (grow then shrink)
under `secure_delete=OFF`, so the intermediate pre-edit version survives in freed
slack with **the same rowid as the live row but different values** — the
edited-message / changed-amount evidence. Drives `forensic/tests/prior_version.rs`
and the prior-version leg of `forensic/tests/oracle_differential.rs`.

```sh
python3 - <<'PY'
import sqlite3
con = sqlite3.connect('updated_messages.db')
con.executescript("""
PRAGMA page_size=4096; PRAGMA auto_vacuum=NONE; PRAGMA secure_delete=OFF;
CREATE TABLE messages(id INTEGER PRIMARY KEY, sender TEXT, body TEXT, amount INTEGER);
""")
con.executemany("INSERT INTO messages VALUES(?,?,?,?)",
                [(n, f"user{n}", f"ORIGINAL message body number {n} ZZZ", 707) for n in range(1, 51)])
con.commit()
# Edit row 7's body twice: grow forces the cell to relocate (freeing the old slot),
# then shrink leaves the intermediate version recoverable in freed space.
con.execute("UPDATE messages SET body=? WHERE id=7",
            ("PRIORVERSION secret message body that was later edited " + ("Q" * 120),))
con.execute("UPDATE messages SET body='EDITED final body' WHERE id=7")
con.commit(); con.close()
PY
```

- Ground truth: 50 live rows (ids 1..=50); live row 7 body = `EDITED final body`.
  The recoverable prior version is rowid 7, body `PRIORVERSION secret …`, amount 707
  — a genuine deleted record whose rowid is still live with different values. The
  full original body (`ORIGINAL message body number 7 ZZZ`) survives nowhere (it was
  overwritten); only the intermediate `PRIORVERSION` version is cleanly carvable.
- md5 `e1edbb56bf37efa6a7c1e738040f1360`, 8192 bytes.

> Note: a same-size in-place `UPDATE` overwrites the cell without freeing the old
> version, so no prior version survives. The grow-then-shrink edit forces a
> relocation (freed old cell) whose prefix survives intact in slack — the realistic
> shape of an edited message in a chat/SQLite store.

## §F Independent oracle tools (VENDORED, not committed)

Two independent reference carvers validate `carve_deleted_records` (differential
methodology in `docs/validation.md`; harness in
`forensic/tests/oracle_differential.rs`). `tools/` is gitignored — neither tool is
**committed**; these entries are their provenance record.

### §F.1 `undark` (C) — test gate `UNDARK_BIN`

- Classification: `VENDORED` (third-party tool), confidence `✓` (built and run).
- Tool: `undark` 0.7.1, Paul L. Daniels.
- Upstream: <https://github.com/inflex/undark>
- Source tarball (master): <https://github.com/inflex/undark/archive/refs/heads/master.tar.gz>
- Source tarball sha256 `c0a9ee7ebd180727deef52fbafe0ef0e2b7c9b43c5604761bfeb86bc9306912a`.
- Build (macOS/clang): hoist the nested `swap64`/`ntohll` out of `decode_row` to
  file scope and rename `ntohll` → `u_ntohll` (collides with the macOS
  `<sys/_endian.h>` macro), then `make`. Patched source kept at
  `tools/undark.c.patched` (gitignored). See `docs/validation.md` for the exact
  recipe.
- CLI: `undark -i <db>` dumps all reconstructable records as CSV
  (`rowid,id,col1,col2,…`); deleted rows = recovered rowids absent from the live
  b-tree.

### §F.2 `fqlite` (Java) — test gate `FQLITE_TAP`

fqlite's CLI was removed at v2.0, but its carving engine (`fqlite.base.Job`) is
plain Java that populates a result list the GUI merely reads. A headless
source-instrumentation tap drives it with no JavaFX UI — so fqlite IS usable as
an oracle, the CLI cancellation was the only blocker.

- Classification: `VENDORED` (third-party tool, source-instrumented), confidence
  `✓` (built and run).
- Tool: `fqlite` 4.22, Dirk Pawlaszczyk.
- Upstream: <https://github.com/pawlaszczyk/fqlite>
- Commit: `26922bd9e3cdc60c93b72dfb1fb2f5972a0af6a6`.
- Build: clone at the commit, null-guard the unguarded `gui.add_table(...)` calls
  in `Job.java`, stub the `rag`/`erm` LLM packages, compile the engine + the
  `HeadlessTap` driver against JavaFX 22 + commons-codec/jspecify/antlr/sqlite-jdbc
  (JDK 25, `--release 21`). Full recipe in `tools/fqlite/README.md`; engine API
  map + the JavaFX-coupling findings (relevant to a future upstream CLI revival)
  in `tools/fqlite/ENGINE_NOTES.md`. Both gitignored.
- Invocation: `tools/fqlite/run-tap.sh <db>` → CSV `rowid,col1,col2,…` of
  recovered DELETED rows (rowid `-1` when fqlite cannot recover it; the fqlite
  comparison is keyed by url content).

> `sqlite_dissect` was also evaluated as an oracle but its free-block carver
> produced misaligned/garbled columns on these fixtures, so it was rejected as a
> yardstick; its DC3-authored databases are still used as independent input (§G).

## §G `tests-oracle-corpus/dc3-sqlite-dissect/`  (REAL-ext, not committed)

Independent third-party SQLite databases authored by the Department of Defense
Cyber Crime Center (DC3) as the `sqlite_dissect` project's test corpus. Used as
**independent input** for the differential carving validation: neither the input
DB nor the oracle (`undark`) is ours. `tests-oracle-corpus/` is gitignored — the
DBs are **not committed**; this entry + `tests-oracle-corpus/README.md` are their
provenance record.

- Classification: `REAL-ext` (externally-authored real artifacts), confidence `✓`
  (downloaded and inspected; SQLite magic + schema confirmed per file).
- Source: <https://github.com/dod-cyber-crime-center/sqlite-dissect> →
  `sqlite_dissect/tests/test_files/` (raw base
  <https://raw.githubusercontent.com/dod-cyber-crime-center/sqlite-dissect/master/sqlite_dissect/tests/test_files/>).
- Forensic cases exercised (the load-bearing point — these reach scenarios our
  whole-freed-page fixture cannot): `corpus_01-01.db`/`corpus_01-02.db`,
  `corpus_03-02.db`, `corpus_07-01.db` are **in-page free-block deletions**
  (`freelist_count = 0` — deleted rows live inside still-allocated b-tree pages);
  `corpus_0A-01.db`/`corpus_0A-02.db` are **dropped tables** (no table in
  `sqlite_master`). Our freelist-only carver recovers 0 from all of these — the
  documented scope boundary in `docs/validation.md`.

sha256 (full list in `tests-oracle-corpus/README.md`); the six DBs wired into the
differential test:

| file | sha256 | md5 | bytes |
|---|---|---|---|
| `corpus_01-01.db` | `8438a5533586e7e0f38628330d615aeaa057ebb9698c1103424d8128e417875e` | `4ac52776c7d21f0beb38d456452ca2f6` | 8192 |
| `corpus_01-02.db` | `508fb80ce083bc6ad79d2921b1d35d998724e808a72d05476671010b1265043b` | `57f88570e289df9919bd900f24b7a026` | 8192 |
| `corpus_03-02.db` | `7ea933d7082d3ec0cdc9f5ca3e39624d80c0da495a365d520424a69a1937f138` | `9c0a90eeb78cd24d5b4004c157d8618f` | 12288 |
| `corpus_07-01.db` | `6e110c0663be9500e817ab0d6153f0f1aaa7d8831e7e17a05e2565abbbf9e4da` | `7f8f9e9b4d6aa971b9f0c5d16b6c2419` | 81920 |
| `corpus_0A-01.db` | `c640727d2fe3e269d196e64c25cf896e9fa21c2626d4f6b88398274c4e1691d1` | `a174174a3f98fe7733e4a32e7aab86b7` | 8192 |
| `corpus_0A-02.db` | `030fd0a82fa37707f448e90a21bc178f120b018b009999daaefdc61d04b24d24` | `c1be2eb3388bc294ec0deecb334180b9` | 8192 |

## §I `tests/data/nemetz/`  (REAL-ext, CC0, **committed**)

The **SQLite Forensic Corpus** (Nemetz, Schmitt & Freiling, DFRWS-EU 2018) — a
third-party dataset that ships, per database, an `.xml` answer key tagging every
deleted row with its full decoded content. This is independent deleted-record
**ground truth**: unlike our `deleted_places.db` fixture (we authored both the
deleter and the carver), here a third party authored the deletions *and* the
answer key, so a recall/precision number against it is real. It drives
`forensic/tests/nemetz_metrics.rs` (the per-DB confusion matrix) and is the basis
of `docs/recovery-comparison.md`.

- Classification: `REAL-ext` (externally-authored real artifacts), confidence `✓`
  (downloaded, extracted, SQLite magic + schema + answer-key parse confirmed per
  file). **Committed** (CC0 public domain — redistribution unrestricted).
- Authors: Sebastian Nemetz, Sven Schmitt, Felix Freiling (FAU Erlangen-Nuremberg).
- Paper: <https://doi.org/10.1016/j.diin.2018.01.015>.
- Download (v2.0): <https://downloads.digitalcorpora.org/corpora/sql/sqlite_forensic_corpus_v2.0.zip>
  (302 → `digitalcorpora.s3.amazonaws.com`; `curl -L`). Zip md5
  `02aa205efa80757602a2911156db79a6`.
- Vendored subset (32 databases): deleted/overwritten categories `0A`,`0B`,`0C`,
  `0D`,`0E` (per-row deleted ground truth) plus anti-forensic category `11`
  (`*_antifor.db` — manipulated page/cell pointers, a no-phantom robustness test
  with no deleted ground truth). Per-file md5 manifest, the category table, and
  the `gen_ground_truth.py` regeneration recipe live in
  `tests/data/nemetz/README.md` — the single detailed index for this dataset
  (cross-referenced, not duplicated here).
- Ground-truth manifest `tests/data/nemetz/nemetz_ground_truth.json` is generated
  from the `.xml` answer keys by the committed
  `tests/data/nemetz/gen_ground_truth.py`; the harness reads the manifest, never
  the `.xml` at test time.

## §H MD5 manifest

Committed fixtures (under `tests/data/`, `tests/data/`):

| file | md5 | bytes |
|---|---|---|
| `tests/data/places.db` | `f07a69d05358f227e2120080370bbb6b` | 8192 |
| `tests/data/overflow.db` | `1c17320320a173fb5968c598f9df7373` | 16384 |
| `tests/data/wal_places.db` | `bad96eb068359bcb142533696b6515fc` | 8192 |
| `tests/data/wal_places.db-wal` | `84b08a77d90914c917d92e60a6c8eeab` | 4152 |
| `tests/data/deleted_places.db` | `16682d7df99b1e8a89287a508d95eb47` | 53248 |
| `tests/data/updated_messages.db` | `e1edbb56bf37efa6a7c1e738040f1360` | 8192 |

The 32 committed Nemetz databases under `tests/data/nemetz/` (CC0, §I) have their
own md5 manifest in `tests/data/nemetz/README.md` to avoid duplicating it here.

Not committed (provenance only — see §F, §G and the per-directory READMEs):
`tools/undark`, the fqlite tap under `tools/fqlite/` (source, jars, built classes
— recipe in `tools/fqlite/README.md`), and the DC3 corpus under
`tests-oracle-corpus/dc3-sqlite-dissect/` (full sha256/md5 list in
`tests-oracle-corpus/README.md`).
