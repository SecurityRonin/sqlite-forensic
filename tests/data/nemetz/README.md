# Nemetz SQLite Forensic Corpus — vendored subset (`tests/data/nemetz/`)

Independent, third-party deleted-record **ground truth** for the carving metrics
harness (`forensic/tests/nemetz_metrics.rs`). Unlike our own
`deleted_places.db` fixture (where we authored both the deleter and the carver —
Doer-Checker-weak), every database here was built and deleted-from by a third
party who *also* shipped the answer key, so a recall/precision number computed
against it is real ground truth.

This is the co-located human-facing detail; the single machine index is
[`../../../docs/corpus-catalog.md`](../../../docs/corpus-catalog.md) §I — cross-reference, do not duplicate.

## Source

- **Dataset:** SQLite Forensic Corpus, version 2.0 (141 databases).
- **Authors:** Sebastian Nemetz, Sven Schmitt, Felix Freiling — Chair for IT
  Security Infrastructures, Friedrich-Alexander-University Erlangen-Nuremberg.
- **Publication:** *A Standardized Corpus for SQLite Database Forensics*,
  DFRWS-EU 2018 (Digital Investigation 24, S121–S130).
  <https://doi.org/10.1016/j.diin.2018.01.015>
- **Landing page:** <https://faui1-files.cs.fau.de/public/sqlite-forensic-corpus/>
  (mirrored on Digital Corpora).
- **Download URL (v2.0, used here):**
  <https://downloads.digitalcorpora.org/corpora/sql/sqlite_forensic_corpus_v2.0.zip>
  (HTTP 302 → `digitalcorpora.s3.amazonaws.com`; fetch with `curl -L`).
- **Downloaded zip md5:** `02aa205efa80757602a2911156db79a6` (5.1 MB).
- **Licence:** CC0 1.0 (public domain dedication — the authors disclaim
  copyright; see each `.xml`'s `<dc:rights>`). Redistribution of this vendored
  subset is therefore unrestricted.

## What is vendored, and why this subset

The full corpus has 141 databases across 14 categories. We vendor the
**deleted/overwritten-content** categories (real per-row deleted ground truth) plus
one **anti-forensic** category for false-positive resistance:

| Category | What it exercises | Ground truth |
|---|---|---|
| `0A` | Deleted *tables* (`DROP TABLE`, sometimes after row `DELETE`s) | row-level for the DELETE'd rows |
| `0B` | Overwritten tables (`DROP` then a new `CREATE` reusing the pages) | dropped-table recovery (no row-level deleted set) |
| `0C` | **Deleted records** (in-page free block, `secure_delete=0`, no overwrite) | exact deleted-row set — the cleanest recall test |
| `0D` | Deleted **then overwritten** records (later `INSERT`s reclaim slack) | deleted set, partitioned recoverable vs destroyed |
| `0E` | Deleted records spanning **overflow** pages (long text) | deleted set incl. overflow rows |
| `11` | Anti-forensic: manipulated page/cell pointers (`*_antifor.db`) | **none** — robustness / no-phantom test only |

Each `NN/NN-MM` database ships three files (and category 11 adds `.log` +
`.db_recovery` artifacts, vendored verbatim):

- `NN-MM.db` (or `NN-MM_antifor.db` for category 11) — the database.
- `NN-MM.sql` — the build + `DELETE`/`DROP` provenance script. The
  `PRAGMA secure_delete` state and whether later `INSERT`s overwrote freed slack
  determine which deletes are *physically* recoverable.
- `NN-MM.xml` — the **answer key**: every row tagged `deleted="1"` carries its
  full decoded column content, plus per-table `rowsTotal`/`rowsAlive`/`rowsDeleted`.

## Ground-truth manifest (machine-checkable)

`nemetz_ground_truth.json` is generated from the `.xml` answer keys by the
committed `gen_ground_truth.py` (re-run after re-vendoring):

```sh
python3 tests/data/nemetz/gen_ground_truth.py
```

For each table it records the schema column order, the deleted rows (recall
ground truth), the alive rows (used to tell a live-re-read from a phantom FP),
and per deleted row `substrate_recoverable` — whether a distinctive column's
bytes still physically survive in the `.db` (computed independently of our
carver, partitioning `D_recoverable` from `D_destroyed` for the two-denominator
recall). The harness reads this manifest, never the `.xml` at test time.

## MD5 manifest (vendored databases)

| file (under `tests/data/nemetz/`) | md5 | bytes |
|---|---|---|
| `0A/0A-01.db` | `a174174a3f98fe7733e4a32e7aab86b7` | 8192 |
| `0A/0A-02.db` | `c1be2eb3388bc294ec0deecb334180b9` | 8192 |
| `0A/0A-03.db` | `9565362072244d68631a0ba01bdf94d0` | 12288 |
| `0A/0A-04.db` | `ef9ad3652da810fe1090b63bf2bc5127` | 12288 |
| `0A/0A-05.db` | `c2846f857ecffafe0a42ef07f5a648d9` | 12288 |
| `0B/0B-01.db` | `ab8e7922647bbd6a7a398cc56800a584` | 8192 |
| `0B/0B-02.db` | `88daa0f36fb22327d7e5fba23eb62f99` | 16384 |
| `0C/0C-01.db` | `d34bc762b6cba175bae170fa7a606480` | 8192 |
| `0C/0C-02.db` | `164fac034c32308727cfd153e6f94620` | 12288 |
| `0C/0C-03.db` | `65d73454d6a09f6c448536b62ccbae35` | 8192 |
| `0C/0C-04.db` | `24dfdd07e36c415015f33f7f5b2deefc` | 12288 |
| `0C/0C-05.db` | `401317f6b02233952a27ee6c80dc954b` | 12288 |
| `0C/0C-06.db` | `ab323dbc2b07e1167adffc5a63142f18` | 8192 |
| `0C/0C-07.db` | `121ef02e980b85ac97d2beb8c209c211` | 12288 |
| `0C/0C-08.db` | `ceebbbe67a0d9d01d0271a919be01026` | 12288 |
| `0C/0C-09.db` | `35e93ae449d67327ee39855dcd91036e` | 8192 |
| `0C/0C-10.db` | `1604a028d1dad945caf341499d5b6ba2` | 12288 |
| `0D/0D-01.db` | `18bc00dafdea993310bee8941983f042` | 8192 |
| `0D/0D-02.db` | `0d469da01f6e716bfb7719c0ad8cfc9b` | 8192 |
| `0D/0D-03.db` | `7b7ae92bbd991404d67f37716492a16d` | 8192 |
| `0D/0D-04.db` | `d9f9b890ee943a8b6eb0d0747278a36f` | 8192 |
| `0D/0D-05.db` | `b095e7b237b4cbb883fe971dab996b86` | 8192 |
| `0D/0D-06.db` | `66702224c003f92a6815078414abc904` | 8192 |
| `0D/0D-07.db` | `897dd2e67ee25d2fdff3360160a9e375` | 12288 |
| `0D/0D-08.db` | `5201d14ff657e94256736211c54678a4` | 12288 |
| `0E/0E-01.db` | `3153d8a4062d2ddf34fd64ea6e0a0841` | 77824 |
| `0E/0E-02.db` | `2abda844f3f6844022ca628f91b6edcc` | 90112 |
| `11/11-01_antifor.db` | `2413516fa09f5203e94ab2dcc52b4976` | 20480 |
| `11/11-02_antifor.db` | `1186e5d9156ad557848b6d67735396bc` | 20480 |
| `11/11-03_antifor.db` | `fd268bf1647dc9cebb6073f0f90a4ac1` | 20480 |
| `11/11-04_antifor.db` | `7d1d58827bbb60b290c0512717d2a213` | 12288 |
| `11/11-05_antifor.db` | `1ee39cc8de2efbf080557f723c5bf703` | 86016 |

(The co-located `.sql`/`.xml`/`.log`/`.db_recovery` files are vendored verbatim
from the same zip; their integrity is implied by the zip md5 above.)
