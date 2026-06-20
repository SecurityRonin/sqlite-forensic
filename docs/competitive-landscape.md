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
and measured our carver against two of the survey's tools on **identical bytes**:
`bring2lite` and the SQLite Deleted Records Parser (SQL-DRP, Mari DeGrazia).

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
| SQL-DRP | 5 | 0 | 1.000 | 0.100 | measured (this repo, identical bytes) |
| Undark / Bring2Lite / FQLite | — | ~10 each | — | — | reported by the paper (its corpus) |
| SQLite Deleted Record Parser | — | 0 | — | (lower) | reported by the paper (its corpus) |

The headline: on identical bytes, the freed-page carver (`bring2lite`) re-surfaces
**13 live rows** as deleted; our live-rowid exclusion yields **0**. SQL-DRP, a
metadata-only freeblock scanner, also avoids the live-row false positives but
recovers far fewer truly-deleted rows (it does not chase whole freed pages).

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
page ownership to the recreated `recovered_students` table; we do not explicitly
detect the drop-recreate. A reader of `recovered_students` could mistake an
OLD-NAME residue row for a prior state of the *new* students table.
`bring2lite`/SQL-DRP sidestep this by attributing nothing — they emit the residue
as schema-less unallocated blobs. (See "Ideas to steal" → rowid→table inference.)

### 10 — WAL + secure_delete=ON (deleted denom = 20; residue only in `-wal`)

| Tool | TP | FP | Precision | Recall | Source |
|---|---:|---:|---:|---:|---|
| **sqlite4n6 (ours)** | 20 | 0 | 1.000 | 1.000 | measured (this repo, identical bytes) |
| bring2lite | 20 | 0 | 1.000 | 1.000 | measured (this repo, identical bytes) |
| SQL-DRP | 0 | 0 | n/a | 0.000 | measured (this repo, identical bytes) |
| Bring2Lite / FQLite | — | — | — | recover | reported by the paper (its corpus) |
| Undark / SQLite-DRP | — | — | — | do not recover | reported by the paper (its corpus) |

With `secure_delete=ON` the main image holds none of the message bodies; the only
residue is in the uncheckpointed `-wal`. We and `bring2lite` (both WAL-aware)
recover all 20; SQL-DRP (main-image only) recovers none — matching the survey.

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
- **Undark** and **FQLite** — **CITED, not run** here (no `UNDARK_BIN` / `FQLITE_TAP`
  available in this run). Their false-positive figures here are the survey's reported
  numbers on its corpus.

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
- **Throughput unmeasured here.** The survey reports execution time on a 100 MB DB
  (Undark 2.94 s, SQLite-DRP 3.97 s, FQLite 13.62 s, Bring2Lite 21.89 s,
  reported by the paper). Our fixtures are small; we report no throughput number
  rather than an apples-to-oranges one.
- **Recall is not the headline.** The identical-bytes recall numbers differ by
  scenario and tool, but the survey's contribution — and ours here — is about
  **false positives** and **substrate coverage** (WAL vs main-image), not a recall
  leaderboard across different corpora.

## Ideas to steal (survey → our backlog)

- **Throughput benchmark.** Add a large-DB (≈100 MB) timing harness so we can
  report execution time alongside the survey's tools on comparable input.
- **rowid → table inference for drop-recreate (the 0B nuance).** When residue is
  attributed to a recreated same-name table, distinguish *prior states of the
  current table* from *a previous dropped table with the same schema* — e.g. by
  reconciling recovered rowids against the live table's rowid range and the
  freelist-trunk history, and labelling drop-recreate residue distinctly rather
  than folding it into `recovered_<table>`.
- **WAL-checkpoint acquisition warning.** A `-wal` that a checkpoint would have
  reclaimed is forensically load-bearing; surface a warning when an evidence WAL
  is uncheckpointed (residue present) so an examiner copies the `-wal` before any
  tool checkpoints it away.
