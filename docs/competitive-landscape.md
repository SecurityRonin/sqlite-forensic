# Competitive Landscape — the 2025 SQLite false-positive survey, and where we sit

## Executive summary

A 2025 survey (Lee, Park, Lee & Choi, *FSI:DI* 55, art. 302031) shows that the
common SQLite deleted-record recovery tools emit **false positives**: they report
rows as deleted that are in fact still live. The survey isolates two structural
causes — **B-tree rebalancing** (a merge shuffles a *live* row onto a freed page,
which freed-page carvers misread as deleted) and **table reinsertion with the same
schema** (residue from a dropped table mis-attributed to a recreated same-name
table).

We replicated the survey's scenario *construction* with the real `sqlite3` engine
and measured our carver against four of the survey's tools on **identical bytes**:
`bring2lite`, `Undark` (v0.7.1), the SQLite Deleted Records Parser (SQL-DRP,
Mari DeGrazia), and `FQLite` (4.22, driven headlessly via a source tap). FQLite's
in-page/freelist carve ran on the two non-WAL scenarios (0F/0B); its WAL recovery
path is GUI-coupled in the current source and was not reachable headlessly, so
scenario 10 has no FQLite number (the blocker is documented below — no figure is
fabricated).

- **On the B-tree rebalancing scenario, `bring2lite` produced 13 false positives
  (live rows reported as deleted; precision 0.705); our carver produced 0
  (precision 1.000).** This reproduces the survey's Type-\*\* finding on our
  replication. The difference is structural: we exclude live rowids by
  construction, so a row on a freed page that is still reachable from the live
  b-tree is never re-surfaced. `FQLite` likewise produced **0** live false
  positives here (precision 1.000) — its freelist carve recovers fewer of the
  truly-deleted rows (11/50) but does not re-surface a live one.
- **On WAL + `secure_delete=ON`, we recover all 20 deleted rows from the `-wal`**;
  SQL-DRP (a main-image-only carver) recovers 0 because it does not read the
  `-wal`. This matches the survey's observation that only WAL-aware tools recover
  this case.
- **On the overwritten-same-schema scenario we are honest-but-imperfect.** We
  recover the dropped-table residue, flag it deleted, and keep it disjoint from
  the live set — but we attribute it by page ownership to the recreated same-name
  table rather than detecting the drop-recreate explicitly.

> **Scope discipline.** The survey's own corpus + code is "released upon
> publication" and is not yet public, so we did **not** reproduce its bytes. Every
> figure below is labelled by source: **measured (this repo, identical bytes)** —
> our carver and the oracles run on the *same* replicated files — versus
> **reported by the paper** — the survey's numbers on *its* corpus, which we cite
> but did not re-measure. We make **no** head-to-head claim on absolute recall
> across the two corpora; only the identical-bytes column is apples-to-apples.

## The survey's three-technique framework

The survey classifies SQLite deleted-record recovery into three techniques, and
evaluates tools for false positives within each:

| Technique | What it reads | Survey's tool examples |
|---|---|---|
| **Metadata-based** | freeblocks + freelist via the page/b-tree structure | SQLite Deleted Records Parser |
| **Carving-based** | pattern/serial-type scan of unallocated space | Undark, bring2lite, FQLite |
| **WAL / journal** | the `-wal` and rollback `-journal` sidecars | bring2lite, FQLite |

`sqlite4n6` spans all three: metadata-aware freeblock + freelist reconstruction, a
serial-type carve of unallocated space, and WAL + rollback-journal recovery — with
a 0-false-positive discipline on the in-page tier (live rowids are excluded by
construction).

The three techniques trade off along three axes — qualitative characterizations,
not measured values:

| Technique | Throughput | Coverage | Anti-forensic resilience |
|---|---|---|---|
| Metadata-based | High | High | Low |
| Carving-based | Medium | High | Medium |
| WAL-based | Low | Low | High |

This is the survey's qualitative read of the three *approaches* — not a scorecard
for any tool, and we don't add a self-graded `sqlite4n6` row to it (the axes have
no defined cutoffs and we'd be grading ourselves). `sqlite4n6` implements all three
plus the rollback journal (stated above); where it actually lands is shown by the
**measured** evidence below — the false-positive comparison on identical bytes and
the throughput figures (~15.6 s on a 100 MB database).

## Measured false-positive / recall table (identical bytes)

Three scenarios were built with the real `sqlite3` engine following the survey's
Table 5 construction (fixtures + generator in
[`tests/data/paper_fp/`](https://github.com/SecurityRonin/sqlite-forensic/blob/main/tests/data/paper_fp/README.md)). Each tool was run
on the **same** files; recovered records were scored by content against the
ground-truth live/deleted sets. `precision = TP / (TP + FP)`,
`recall = TP / deleted`.

### 0F — B-tree rebalancing (deleted denom = 50; 30 live rows present)

| Tool | TP | FP (live) | Precision | Recall | Source |
|---|---:|---:|---:|---:|---|
| **sqlite4n6 (ours)** | 33 | **0** | **1.000** | 0.660 | measured (this repo, identical bytes) |
| bring2lite | 31 | **13** | 0.705 | 0.620 | measured (this repo, identical bytes) |
| FQLite | 11 | **0** | 1.000 | 0.220 | measured (this repo, identical bytes) |
| Undark | 0 | **1** | 0.000 | 0.000 | measured (this repo, identical bytes) |
| SQL-DRP | 5 | 0 | 1.000 | 0.100 | measured (this repo, identical bytes) |
| Bring2Lite | — | ~10 | — | — | reported by the paper (its corpus) |
| SQLite Deleted Record Parser | — | 0 | — | (lower) | reported by the paper (its corpus) |

The headline: on identical bytes, the freed-page carver (`bring2lite`) re-surfaces
**13 live rows** as deleted; our live-rowid exclusion yields **0**. SQL-DRP, a
metadata-only freeblock scanner, also avoids the live-row false positives but
recovers far fewer truly-deleted rows (it does not chase whole freed pages).
**FQLite** recovers 11 of the 50 truly-deleted freelist rows (ids 1–9, 18, 27,
content-scored by the embedded `ROW-<id>-…` tag) with **0** live false positives
(its 15 output lines also include 1 `sqlite_master` schema row and 2 untagged
freespace fragments, neither scorable as a live/deleted data row). **Undark**
recovers nothing truly-deleted from the freelist pages here and emits a
single freespace fragment — whose id-tag (`ROW-56-…`) is a **live** row (id 56,
range 51..80) surfaced as recovered: **1 false positive, 0 true positives**.
Undark dumps a flat CSV with no live/deleted bucketing, so its lone recovery is a
live-row fragment, exactly the survey's Type-\*\* weakness.

### 0B — overwritten table, same schema (residue denom = 10 OLD rows; 5 live NEW rows)

| Tool | TP (OLD residue) | FP (live NEW) | Precision | Recall (/10) | Source |
|---|---:|---:|---:|---:|---|
| **sqlite4n6 (ours)** | 5 | 0 | 1.000 | 0.500 | measured (this repo, identical bytes) |
| bring2lite | 5 | 0 | 1.000 | 0.500 | measured (this repo, identical bytes) |
| FQLite | 5 | 0 | 1.000 | 0.500 | measured (this repo, identical bytes) |
| SQL-DRP | 5 | 0 | 1.000 | 0.500 | measured (this repo, identical bytes) |

All four recover the 5 surviving OLD residue rows (rowids 6..=10; the other 5 OLD
rows lost their cells to same-rowid reuse by the NEW rows) and none re-surface a
live NEW row, so the *content* false-positive count is 0 for all four on this
replication. `FQLite` carves the OLD residue as a flat list under the recreated
`students` table (its output is the 5 `OLD-NAME-6..10` rows, plus the
`sqlite_master` schema row and one malformed fragment, neither a live NEW row), so
it shares the others' clean 0-false-positive result on this replication. **Our nuance (the Type-\* caveat):** we attribute the OLD residue by
page ownership to the recreated `recovered_students` table; we do not reroute or
re-tier it. Where the recreated table is `AUTOINCREMENT`, we now ALSO surface a
`table_instance_risk` provenance flag on each residue row whose `rowid` exceeds the
table's `sqlite_sequence` high-water mark — a **hint**, not a predecessor proof
(the same `rowid > seq` is reachable by an `UPDATE` of the rowid or a
`sqlite_sequence` edit), carrying its evidence (the rowid, the seq) so the examiner
can cross-check. For a plain `INTEGER PRIMARY KEY` recreate the flag stays silent —
the survey's genuinely-undecidable case. `bring2lite`/SQL-DRP sidestep the
attribution question entirely by emitting the residue as schema-less unallocated
blobs.

### 10 — WAL + secure_delete=ON (deleted denom = 20; residue only in `-wal`)

| Tool | TP | FP | Precision | Recall | Source |
|---|---:|---:|---:|---:|---|
| **sqlite4n6 (ours)** | 20 | 0 | 1.000 | 1.000 | measured (this repo, identical bytes) |
| bring2lite | 20 | 0 | 1.000 | 1.000 | measured (this repo, identical bytes) |
| Undark | 0 | 0 | n/a | 0.000 | measured (this repo, identical bytes) |
| SQL-DRP | 0 | 0 | n/a | 0.000 | measured (this repo, identical bytes) |
| FQLite | — | — | — | recover | cited (paper) — WAL path not reachable headlessly (see provenance) |
| SQLite-DRP | — | — | — | do not recover | reported by the paper (its corpus) |

With `secure_delete=ON` the main image holds none of the message bodies; the only
residue is in the uncheckpointed `-wal`. We and `bring2lite` (both WAL-aware)
recover all 20; SQL-DRP and **Undark** (both main-image only — Undark has no `-wal`
awareness) recover none, confirming the survey's main-image-vs-WAL split on
identical bytes. **FQLite** is WAL-aware in its GUI, and the paper reports it
recovering this case, but its WAL recovery is structurally GUI-coupled in the
current source (the `-wal` reader is instantiated by a JavaFX `ImportDBTask`, and
the WAL table wiring in `Job.processDB()` sits entirely inside `if (gui != null)`
blocks). The headless tap drives the in-page/freelist engine (`Job.run`), which on
this file leaves `job.wal == null` and recovers nothing — so scenario 10 keeps
FQLite's **cited** figure rather than a fabricated measured one (blocker detailed
in the provenance note).

> **One honest WAL artifact.** Our carve of `wcase.db` emits 21 records for 20
> distinct deleted rowids: rowid 14 also appears once as a lower-confidence
> (0.48) all-NULL record carved from a *different* WAL commit generation. It is
> not a false positive (14 is genuinely deleted), but it shows the multi-snapshot
> WAL view can surface the same rowid across commit generations. The 20 clean
> full-content rows recover at confidence 0.90.

## Oracle provenance — which oracles ran, which were cited

- **`bring2lite`** (Python 3) — **RAN** on all three files.
  [Repo](https://github.com/bring2lite/bring2lite). Its CLI path imports PyQt5 at
  module load (only used on the `--gui` path); a minimal import shim let the
  headless run proceed. It buckets recovered records into per-page logs
  (`unalloc-parsing/`, `freelists/`, `WALs/` vs live `regular-page-parsing/`),
  which is how live-vs-deleted attribution was scored. It emits `is`-with-literal
  `SyntaxWarning`s under 3.11 but runs.
- **SQLite Deleted Records Parser (SQL-DRP, v1.3, Mari DeGrazia)** — **RAN** on all
  three files. [Repo](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser).
  It is Python 2; converted with `2to3` plus two minor bytes-vs-str fixes (the
  `b"SQLite"` header check and a bytes-aware `remove_ascii_non_printable`). TSV
  (`-f`/`-o`) mode; it reads the main image only and does not consult a `-wal`.
- **Undark** (v0.7.1, Paul L. Daniels, C) — **RAN** on all three files.
  [Repo](https://github.com/inflex/undark). Built from the master tarball (sha256
  `c0a9ee7ebd180727deef52fbafe0ef0e2b7c9b43c5604761bfeb86bc9306912a`) with two
  behavior-preserving clang/macOS patches (hoist the nested `swap64`/`ntohll` out
  of `decode_row`; rename `ntohll` → `u_ntohll` to dodge the macOS
  `<sys/_endian.h>` macro), then `make`. Gated on `UNDARK_BIN`; recipe in
  `docs/validation.md` and `docs/corpus-catalog.md` §F.1. Undark emits a flat CSV
  (`rowid,cols…`) with **no live/deleted bucketing** — it dumps every record it can
  decode, including live b-tree rows — so on 0B it surfaces the 5 live NEW rows as
  recovered, and on 0F its lone freespace fragment is a live row (id 56). It reads
  the main image only (no `-wal`), so it recovers nothing from scenario 10 —
  confirmed (0 records).
- **FQLite** (4.22, Dirk Pawlaszczyk, Java) — **RAN on 0F and 0B**; its WAL path on
  scenario 10 was **not reachable headlessly** (genuine blocker, no number
  fabricated). [Repo](https://github.com/pawlaszczyk/fqlite). FQLite's command-line
  mode was removed at v2.0 (the GUI installer ships no runnable CLI), so it is
  driven through a headless source-instrumentation tap of its carving engine
  (`fqlite.base.Job`). Build recipe (gitignored under `tools/fqlite/`, gated on
  `FQLITE_TAP`):
    - clone `pawlaszczyk/fqlite` at commit
      `26922bd9e3cdc60c93b72dfb1fb2f5972a0af6a6`;
    - null-guard the unguarded `gui.add_table(...)` calls in `Job.java` so
      `processDB()` runs to completion with `gui == null`;
    - stub the `rag`/`erm` LLM packages so the build does not pull
      langchain4j/llama;
    - compile the engine + `tap/HeadlessTap.java` with OpenJDK 25, `--release 21`,
      against **OpenJFX 22.0.2** SDK (`--module-path javafx-sdk-22.0.2/lib
      --add-modules javafx.base,javafx.graphics,javafx.controls`) plus
      `commons-codec-1.17.1`, `jspecify-1.0.0`, `antlr4-runtime-4.8`,
      `sqlite-jdbc-3.51.1.0`;
    - run: `FQLITE_JAVA=<jdk-25>/bin/java tools/fqlite/run-tap.sh <db>` → CSV
      `rowid,col1,col2,…` of recovered DELETED records (rowid `-1` when the
      header rowid is unrecoverable; scored by content). The tap boots the JavaFX
      *toolkit* headlessly (no window) because the engine's `AppLog` static init
      and `processDB` cleanup fence still touch JavaFX.

  On 0F it recovers 11 of 50 deleted freelist rows with 0 live false positives; on
  0B it recovers the 5 surviving OLD residue rows with 0 false positives. **The
  WAL blocker (scenario 10):** the `-wal` reader (`WALReader`) is instantiated by a
  JavaFX `ImportDBTask` Task, and the WAL table registration in `Job.processDB()`
  is entirely inside `if (gui != null)` blocks (`gui.add_table(...).thenAccept(...)`
  → `setWALPath`/`guiwaltab`). Driving `Job.run()` headlessly therefore never
  builds the WAL reader (`job.wal == null` after the run), and WAL-recovered rows
  would in any case land in `WALReader`'s own `resultlist`, not `job.resultlist`.
  The tap was extended to (a) set `readWAL`/`walpath` and (b) drain
  `job.wal.resultlist`, but the GUI-coupled instantiation cannot be reached without
  reconstructing the `ImportDBTask` flow or refactoring `processDB`'s WAL wiring out
  of its `if (gui != null)` guards — out of scope for this pass. So scenario 10
  keeps FQLite's **cited** figure; **no FQLite number is fabricated.** Full recipe +
  engine API map in `tools/fqlite/README.md` and `tools/fqlite/ENGINE_NOTES.md`
  (both gitignored); also in `docs/validation.md` and `docs/corpus-catalog.md`
  §F.2.

> **Companion comparison — the Nemetz head-to-head.** `bring2lite` and SQL-DRP are
> also wired as standing, env-gated oracles into the repo's third-party-ground-truth
> head-to-head (`forensic/tests/nemetz_tool_comparison.rs`, written up in
> [`recovery-comparison.md`](recovery-comparison.md)), through the **same** committed
> wrappers used here — `scripts/run-bring2lite.sh` (`BRING2LITE_CMD`) and
> `scripts/run-sqldrp.sh` (`SQLDRP_CMD`). That table scores precision/recall against
> the Nemetz answer key on the `(col1,col2)` matcher (where SQL-DRP's string-carver
> nature surfaces as a documented 0-identity boundary); this page scores the
> survey's **false-positive** scenarios. Read the two together for the full picture.

## Capabilities the surveyed tools don't have

The survey scores deleted-record carving. Beyond that axis, this tool recovers
substrates and structures none of the four surveyed tools address — and is
validated for them against independent ground truth:

- **Freeblock-clobbered rows the others drop.** When SQLite overwrites a freed
  cell's first four bytes, we rebuild the record from its surviving serial-type
  tail plus a same-page schema template — including deletions with a **2-byte
  rowid** (any rowid ≥ 128, i.e. most real tables) and **coalesced** runs of
  adjacent deletions (accepted only when they tile the freed slot exactly, so a
  misaligned read is rejected, never emitted as a phantom).
- **Dropped-table schema recovery.** A deleted `sqlite_master` row is recovered
  from page-1 free space, surfacing a dropped table/index/view/trigger's name and
  `CREATE` statement (`audit` reports `SQLITE-DROPPED-SCHEMA-RECOVERED`).
- **Rollback-journal + WAL recovery** of the last transaction's deletes **and**
  edits — the default `DELETE`/`PERSIST` mode the freed-page carvers don't read.
- **Confirmed on a real case.** On the **NIST CFReDS *Data Leakage Case***, the
  Google Drive `snapshot.db` carved from a Volume Shadow Copy yields both deleted
  `cloud_entry` records NIST documents — including the freeblock-clobbered one —
  with the live row never re-surfaced. The independent **`sqlite-unhide`** corpus
  (third-party answer keys) and **NIST SFT-05** (native types + a variety of BLOB
  image formats) are exercised the same way. See [`validation.md`](validation.md).

## Limits of this comparison

- **Replicated corpus, not the survey's bytes.** The survey's official corpus is
  not yet public; these are real-engine replications of its construction. When the
  corpus is released, swap it in and re-measure (tracked in the fixtures README).
- **Throughput is now measured apples-to-apples (see "Throughput" below).** Every
  tool was timed on the **same** machine (Apple M4 Pro) and the **same**
  locally-generated ~100 MB image; our `carve -f jsonl -o -` runs in a median
  **15.6 s** (release). The survey's numbers are on *its own* 100 MB DB on a
  *different* machine and are not directly comparable — they are kept only as a
  historical anchor, not read against the measured table.
- **Recall is not the headline.** The identical-bytes recall numbers differ by
  scenario and tool, but the survey's contribution — and ours here — is about
  **false positives** and **substrate coverage** (WAL vs main-image), not a recall
  leaderboard across different corpora.

## Throughput

**Throughput is not the headline — false positives and substrate coverage are.**
Lower wall-clock time only means "faster at the same job" when the tools are doing
the same job; they are not (see the *recovery discipline* column). A flat b-tree
dump that emits ~178k undifferentiated rows in 1.5 s is not "10× faster" than a
deleted-only carve that emits 79,904 attributed rows in 15 s — it is doing
different, lesser work. The table below records times **as facts in their
work-done context**, not as a leaderboard.

Every tool was run on the **same machine** and the **same** locally-generated
~100 MB messages-like image (210k → 178k rows, an 80k-row contiguous middle subset
DELETEd, `secure_delete=OFF`, `auto_vacuum=NONE`; generator
`tests/data/paper_fp/gen_large.py`, gitignored DB). **Methodology:** wall-clock,
warm cache, **median of 5 runs** per tool, release build; harness
`scripts/throughput-bench.sh`. Our carve recovers 79,904 of the 80,000 deleted
rows (recall 0.9988) with **0** live false positives — correctness holds at scale,
pinned by the env-gated perf-smoke `forensic/tests/perf_large_carve.rs`
(`SQLITE_FORENSIC_PERF_DB`).

**Measured here — same machine (Apple M4 Pro, macOS 15.7.8), same ~100 MB db:**

| Tool / mode | Median wall-clock | Records emitted | Recovery discipline |
|---|---:|---:|---|
| `sqlite4n6 carve -f jsonl -o -` | 15.6 s | 79,904 deleted | **deleted-only**, live-rowid excluded, 0 live FP; every row content-confirmed in the deleted range |
| `sqlite4n6 carve` (workbook) + `-f db` | 44.8 s | 79,904 deleted | as above, **plus** it rebuilds a 45 MB queryable `.carved.db` + an 8.7 MB `.xlsx` |
| `undark -i` | 1.5 s | 177,906 | **flat-dump**: whole b-tree (live + freespace), no live/deleted split — ~178k rows are almost all *live* |
| `fqlite` (headless tap) | 2.4 s | 2,935 | **deleted-only** bucket (status flag `D`), but mostly freelist-page fragments — only 31 rows carry an `MSG-` tag, 6 of them in the true deleted range |
| `sqldrp` (sqlparse v1.3) | 0.2 s | 5 | **metadata/string carve**: printable-ASCII blobs from a handful of freeblock/unallocated regions; no per-column record, no live/deleted split |
| `bring2lite` | — (did not complete) | 0 | crashes mid-run (`struct.error: unpack requires a buffer of 1 bytes` in `_extract_trunk_page_content` while parsing a freelist trunk page) before producing any recovered record |

Notes on the measurements:

- **`bring2lite` did not complete a recovery on this db** — it parses the live
  b-tree, then aborts in the freelist trunk-page parser with a truncated-buffer
  `struct.error`. The ~10 s it spends before crashing is **not** a recovery time,
  so no figure is entered for it. (It runs to completion on the small
  identical-bytes fixtures elsewhere in this doc; the failure is specific to the
  larger image's freelist structure.)
- **`undark` emits all 177,906 rows then SIGSEGVs at exit** when its stdout is a
  regular file or `/dev/null` (it exits cleanly to a pipe); the timing pipes its
  output, and the row count is complete regardless of the exit-time crash.
- **`sqldrp`** is a printable-string carver: on this db it surfaces 5 freeblock /
  unallocated string blobs, not 80k records — it does not chase freed pages.
- **Flags shown are the current `-f`/`-o` form.** These figures were measured
  before the output-flag redesign, when a single `--db` run materialized the
  workbook *and* the carved db together (the 44.8 s row); the carve work itself is
  unchanged.

**Reported by the paper (its own 100 MB db, a *different* machine — NOT comparable
with the table above; kept only as a historical order-of-magnitude anchor):**

| Tool | Reported time |
|---|---:|
| Undark | 2.94 s |
| SQLite-DRP | 3.97 s |
| FQLite | 13.62 s |
| Bring2Lite | 21.89 s |

These survey numbers were measured on a different machine and a different corpus;
they are **explicitly not** an apples-to-apples comparison with the measured table
and must not be read against it. The apples-to-apples evidence is the first table:
same machine, same bytes, with the *records-emitted* and *recovery-discipline*
columns making clear that a smaller time often buys a smaller — or
undifferentiated — result.
