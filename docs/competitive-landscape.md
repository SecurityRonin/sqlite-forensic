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
and measured our carver against three of the survey's tools on **identical bytes**:
`bring2lite`, `Undark` (v0.7.1), and the SQLite Deleted Records Parser (SQL-DRP,
Mari DeGrazia). FQLite is cited from the paper (its headless tap was not set up in
this run).

- **On the B-tree rebalancing scenario, `bring2lite` produced 13 false positives
  (live rows reported as deleted; precision 0.705); our carver produced 0
  (precision 1.000).** This reproduces the survey's Type-\*\* finding on our
  replication. The difference is structural: we exclude live rowids by
  construction, so a row on a freed page that is still reachable from the live
  b-tree is never re-surfaced.
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
> our carver and the two oracles run on the *same* replicated files — versus
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
| Undark | 0 | **1** | 0.000 | 0.000 | measured (this repo, identical bytes) |
| SQL-DRP | 5 | 0 | 1.000 | 0.100 | measured (this repo, identical bytes) |
| Bring2Lite / FQLite | — | ~10 each | — | — | reported by the paper (its corpus) |
| SQLite Deleted Record Parser | — | 0 | — | (lower) | reported by the paper (its corpus) |

The headline: on identical bytes, the freed-page carver (`bring2lite`) re-surfaces
**13 live rows** as deleted; our live-rowid exclusion yields **0**. SQL-DRP, a
metadata-only freeblock scanner, also avoids the live-row false positives but
recovers far fewer truly-deleted rows (it does not chase whole freed pages).
**Undark** recovers nothing truly-deleted from the freelist pages here and emits a
single freespace fragment — whose id-tag (`ROW-56-…`) is a **live** row (id 56,
range 51..80) surfaced as recovered: **1 false positive, 0 true positives**.
Undark dumps a flat CSV with no live/deleted bucketing, so its lone recovery is a
live-row fragment, exactly the survey's Type-\*\* weakness.

### 0B — overwritten table, same schema (residue denom = 10 OLD rows; 5 live NEW rows)

| Tool | TP (OLD residue) | FP (live NEW) | Precision | Recall (/10) | Source |
|---|---:|---:|---:|---:|---|
| **sqlite4n6 (ours)** | 5 | 0 | 1.000 | 0.500 | measured (this repo, identical bytes) |
| bring2lite | 5 | 0 | 1.000 | 0.500 | measured (this repo, identical bytes) |
| SQL-DRP | 5 | 0 | 1.000 | 0.500 | measured (this repo, identical bytes) |

All three recover the 5 surviving OLD residue rows (rowids 6..=10; the other 5 OLD
rows lost their cells to same-rowid reuse by the NEW rows) and none re-surface a
live NEW row, so the *content* false-positive count is 0 for all three on this
replication. **Our nuance (the Type-\* caveat):** we attribute the OLD residue by
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
| Bring2Lite / FQLite | — | — | — | recover | reported by the paper (its corpus) |
| SQLite-DRP | — | — | — | do not recover | reported by the paper (its corpus) |

With `secure_delete=ON` the main image holds none of the message bodies; the only
residue is in the uncheckpointed `-wal`. We and `bring2lite` (both WAL-aware)
recover all 20; SQL-DRP and **Undark** (both main-image only — Undark has no `-wal`
awareness) recover none, confirming the survey's main-image-vs-WAL split on
identical bytes.

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
- **FQLite** — **CITED, not run** in this pass. The tap is **not set up** here: this
  worktree has no `tools/fqlite/` source-instrumentation tap, and FQLite's GUI
  installer ships no runnable CLI (its command-line mode was removed at v2.0), so
  driving it headlessly needs the source tap (clone at commit
  `26922bd…`, null-guard the JavaFX `gui.add_table` calls in `Job.java`, stub the
  `rag`/`erm` LLM packages, and compile the engine + `HeadlessTap.java` against
  JavaFX 22 + commons-codec/jspecify/antlr/sqlite-jdbc). That build was out of
  scope for this run, so **no FQLite number is fabricated** — its false-positive
  figures here remain the survey's reported numbers on its corpus. The tap recipe
  (gated on `FQLITE_TAP`) is documented in `docs/validation.md` and
  `docs/corpus-catalog.md` §F.2 for a future run.

> **Companion comparison — the Nemetz head-to-head.** `bring2lite` and SQL-DRP are
> also wired as standing, env-gated oracles into the repo's third-party-ground-truth
> head-to-head (`forensic/tests/nemetz_tool_comparison.rs`, written up in
> [`recovery-comparison.md`](recovery-comparison.md)), through the **same** committed
> wrappers used here — `scripts/run-bring2lite.sh` (`BRING2LITE_CMD`) and
> `scripts/run-sqldrp.sh` (`SQLDRP_CMD`). That table scores precision/recall against
> the Nemetz answer key on the `(col1,col2)` matcher (where SQL-DRP's string-carver
> nature surfaces as a documented 0-identity boundary); this page scores the
> survey's **false-positive** scenarios. Read the two together for the full picture.

## Limits of this comparison

- **Replicated corpus, not the survey's bytes.** The survey's official corpus is
  not yet public; these are real-engine replications of its construction. When the
  corpus is released, swap it in and re-measure (tracked in the fixtures README).
- **Throughput is now measured (see "Throughput" below).** On a locally-generated
  ~100 MB image our `carve --format jsonl` runs in a median **15.3 s** (release,
  Apple M4 Pro); the survey's numbers are on *its own* 100 MB DB on a *different*
  machine and are not directly comparable, but anchor the order of magnitude.
- **Recall is not the headline.** The identical-bytes recall numbers differ by
  scenario and tool, but the survey's contribution — and ours here — is about
  **false positives** and **substrate coverage** (WAL vs main-image), not a recall
  leaderboard across different corpora.

## Throughput

The survey reports execution time on a 100 MB database. We measured our carver on
a **locally-generated ~100 MB** messages-like image (210k → 178k rows, an 80k-row
contiguous middle subset DELETEd, `secure_delete=OFF`, `auto_vacuum=NONE`;
generator `tests/data/paper_fp/gen_large.py`, gitignored DB). Methodology:
**wall-clock over 5 runs, median reported**, release build, on the local machine
noted below. The carve recovers 79,904 of the 80,000 deleted rows (0.9988) with
**0** live false positives — correctness holds at scale, pinned by the env-gated
perf-smoke `forensic/tests/perf_large_carve.rs` (`SQLITE_FORENSIC_PERF_DB`).

**Measured here (this repo, local machine — Apple M4 Pro, macOS):**

| Tool / mode | Median wall-clock | Records emitted | Notes |
|---|---:|---:|---|
| `sqlite4n6 carve --format jsonl` | **15.3 s** | 79,904 deleted | streams JSONL; deleted-only, 0 live FP |
| `sqlite4n6 carve --db` | **39.7 s** | 79,904 deleted | also rebuilds a 45 MB carved `.db` + 8.5 MB `.xlsx` |
| Undark (`-i`) | **1.45 s** | 177,906 (flat dump) | dumps the **whole b-tree** (live + freespace), no live/deleted split |

**Reported by the paper (its own 100 MB DB, a different machine — NOT directly
comparable; an order-of-magnitude anchor only):**

| Tool | Reported time |
|---|---:|
| Undark | 2.94 s |
| SQLite-DRP | 3.97 s |
| FQLite | 13.62 s |
| Bring2Lite | 21.89 s |

The two tables measure different things. Our `jsonl` figure is the cost of
recovering **only deleted** records with live-rowid exclusion and per-record
attribution; Undark's 1.45 s is a single linear b-tree dump with no live/deleted
separation (it emits ~178k rows, almost all live). The cross-machine paper numbers
are not an apples-to-apples leaderboard — the apples-to-apples cell is the
local Undark row, run on the **same** bytes as our carve. As with recall,
throughput is not the headline: the survey's contribution and ours is **false
positives** and **substrate coverage**, not raw speed.

## Ideas to steal (survey → our backlog)

- **Throughput benchmark.** Add a large-DB (≈100 MB) timing harness so we can
  report execution time alongside the survey's tools on comparable input.
- **rowid → table inference for drop-recreate (the 0B nuance).** *Shipped (Detector
  A):* residue attributed to an `AUTOINCREMENT` table carries a `table_instance_risk`
  flag when its `rowid` exceeds the table's `sqlite_sequence` high-water mark —
  surfaced as a non-overclaiming **hint** (consistent with prior-incarnation
  residue, but also explainable by an `UPDATE`/`sqlite_sequence` edit/current-instance
  deletion), AUTOINCREMENT-only, never a predecessor assertion, never a reroute or
  tier change. The plain-`INTEGER PRIMARY KEY` case stays unflagged (genuinely
  undecidable from a bare snapshot). *Backlog (Detector B):* a sidecar `-wal`/`-journal`
  DDL-boundary signal (`sidecar_schema_changed_for_table`) reusing the prior-schema
  machinery — a table-level boundary, still not row-level provenance.
- **WAL-checkpoint acquisition warning.** A `-wal` that a checkpoint would have
  reclaimed is forensically load-bearing; surface a warning when an evidence WAL
  is uncheckpointed (residue present) so an examiner copies the `-wal` before any
  tool checkpoints it away.
