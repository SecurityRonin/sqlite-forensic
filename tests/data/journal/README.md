# `tests/data/journal/` — real sqlite3-engine rollback-journal scenarios

**Tier: real-engine artifact / minted input.** Every file here is produced by the
**real SQLite engine** (not hand-encoded bytes), driving a minted scenario chosen
to exercise one rollback-`-journal` anomaly arm. The *recipe* is deterministic;
the *journal nonce* is engine-random, so the committed artifact is the bytes the
engine actually wrote — reproduce the scenario to get an equivalent (not
byte-identical) journal.

These fixtures back `forensic/tests/hot_journal_anomaly.rs`, which validates the
`audit_journal` anomaly arms (HOT, CHECKSUM-MISMATCH, DUPLICATE-PAGE,
DBSIZE-DELTA, and the cookie-based SCHEMA-CHANGE) against real engine output
rather than self-encoded bytes. Negative-derived variants (a flipped checksum
byte, an appended duplicate record, an edited `mx_page`) are produced **in-test
on owned `Vec<u8>` copies** — the committed corpus is never mutated.

## Files

| File | md5 | size | role |
|---|---|---|---|
| `hot.db` | `6dfd120f216ff997b819bdc755ea6431` | 20480 | main db beside the hot journal |
| `hot.db-journal` | `d428e2fcf8e6f3d9c71a58b18c6f4dcc` | 22016 | Tier-A hot journal (valid magic, n_rec=5, DML only) |
| `ddl_persist.db` | `0271673fb35215d80f313e5f549dbbaf` | 16384 | main db after a committed `ALTER TABLE` |
| `ddl_persist.db-journal` | `fe785dd18b5eb58b6dd4176ae5864130` | 8720 | Tier-B PERSIST journal (zeroed header) with the prior page-1 image |

## Ground truth (verified against the bytes)

- **`hot.db-journal`** — valid journal magic `d9d505f920a163d7`, `n_rec=5`,
  `mx_page=5`, `page_size=4096`, sector 512. All 5 page images
  (pgnos 3, 2, 4, 5, 1) are checksum-valid (5/5). Page 1 **is** journaled, but
  the prior page-1 image's schema cookie (`bytes[40..44]` BE = **1**) **equals**
  the live db's cookie (`hot.db` offset 40 = **1**): the held transaction was
  DML only, so SCHEMA-CHANGE must **not** fire. HOT fires.
- **`ddl_persist.db-journal`** — Tier-B (header zeroed on PERSIST commit). The
  prior page-1 image's schema cookie is **1**; the live `ddl_persist.db` cookie
  is **2** — the `ALTER TABLE` advanced it. SCHEMA-CHANGE must fire, with both
  cookie values shown.

## Recipes

Engine: SQLite **3.45.3** (`sqlite3` CLI) / **3.50.4** (Python `sqlite3` module)
on macOS. The hot-journal scenario needs an open transaction whose journal is
flushed to disk mid-flight, so it is driven from Python (which can hold a
transaction open and copy the files); the DDL scenario is a plain `sqlite3`
script.

### `hot.db` + `hot.db-journal` (Tier-A hot journal, DML only)

```python
import sqlite3, os, shutil
con = sqlite3.connect("hot.db")
con.execute("PRAGMA page_size=4096")
con.execute("PRAGMA journal_mode=DELETE")
con.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)")
con.executemany("INSERT INTO t(id,v) VALUES(?,?)",
                [(i, f"row-{i:04d}-"+"x"*40) for i in range(1, 201)])
con.commit()
# cache_size=1 forces the page cache to spill, writing the journal to disk
# mid-transaction:
con.execute("PRAGMA cache_size=1")
con.execute("BEGIN IMMEDIATE")
con.execute("DELETE FROM t WHERE id <= 50")
con.executemany("INSERT INTO t(id,v) VALUES(?,?)",
                [(i, f"new-{i:04d}-"+"y"*60) for i in range(300, 360)])
# WHILE the transaction is open, copy the db and its journal:
shutil.copyfile("hot.db", "<dest>/hot.db")
shutil.copyfile("hot.db-journal", "<dest>/hot.db-journal")
con.rollback(); con.close()
```

### `ddl_persist.db` + `ddl_persist.db-journal` (committed-DDL PERSIST journal)

```sql
-- sqlite3 ddl_persist.db < recipe.sql
PRAGMA page_size=4096;
PRAGMA journal_mode=PERSIST;
CREATE TABLE u(id INTEGER PRIMARY KEY, name TEXT);
INSERT INTO u(id,name) SELECT value, 'name-'||value FROM generate_series(1,300);
ALTER TABLE u ADD COLUMN extra TEXT DEFAULT 'd';
```

PERSIST leaves the `-journal` on disk after the clean commit (header zeroed,
bodies intact), carrying the prior page-1 image whose cookie pre-dates the
`ALTER`.

## License / redistribution

Minted by this project with the open-source SQLite engine (public domain). The
artifacts carry no third-party content and are released under this repository's
license; safe to commit and redistribute.
