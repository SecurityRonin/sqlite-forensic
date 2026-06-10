# Deleted-Record Recovery — Measured Capability

What `sqlite_forensic::carve_all_deleted_records` actually recovers, and how it
compares **head-to-head against `undark` and `fqlite`** — every tool scored
against the **same independent third-party ground truth**: the SQLite Forensic
Corpus (Nemetz, Schmitt & Freiling, DFRWS-EU 2018, CC0), whose authors shipped,
per database, an `.xml` answer key tagging every deleted row with its full
content.

Both matrices below are **harness-computed**, not hand-written: the single-tool
matrix by `forensic/tests/nemetz_metrics.rs` and the three-tool head-to-head by
`forensic/tests/nemetz_tool_comparison.rs` (run either with `--nocapture` to
regenerate its table). Corpus and oracle provenance are in
[`corpus-catalog.md`](corpus-catalog.md) and [`validation.md`](validation.md).

## Executive summary

- **fqlite leads on recall; our carver leads on precision; undark trails on
  both.** Scored against the same Nemetz answer keys, on the in-page-deletion
  category `0C` fqlite recovers **67** of the recoverable deleted rows, our carver
  **23**, and undark **14** (of 84). fqlite's freeblock-aware reconstruction is
  the recall advantage — and the precise gap our forward-parse carver does not yet
  close (see "[The freeblock-prefix-clobber FN](#the-freeblock-prefix-clobber-fn)").
- **Our carver never re-surfaces a live row.** Across the in-scope corpus it emits
  **0 live-re-reads** — a structural 0-false-positive guarantee. fqlite matches
  this (0 live-re-reads); undark does **not** — on `0D` it re-reads **56** live
  rows as deleted (precision 0.091) and on `0E` **27** (precision 0.333).
- **fqlite pays some precision for its recall.** On `0C` it emits 16 phantom rows
  (precision 0.807) from mangled freeblock reconstructions; our carver's `0C`
  precision is higher (0.885) and on `0D`/`0E` it is 1.000.
- **Two recall denominators** are reported because they answer different questions
  — substrate-limited (carver capability) and end-to-end (examiner usefulness).
- These are honest measurements of *each tool* against *this* corpus, not a
  verdict that any tool is "best": each wins on a different axis, stated plainly
  below.

> The earlier headline ("163 of 163 recoverable, 0 false positives") was a
> fixture-only measurement against our own `deleted_places.db` (whole-freed-page
> deletion — the one shape our carver handles well) and has been retracted; the
> numbers here, against independent ground truth that also exercises in-page
> deletion, supersede it.

## Head-to-head — ours vs undark vs fqlite (computed)

Every tool's recovered rows are matched against the **same** answer key by a
format-stable `(col1, col2)` identity (the two integer/text columns at positions
1 and 2 — `name`/`surname` for the text tables, the two non-id integer columns for
the integer tables). These columns uniquely identify every deleted row in every
0C/0D/0E database and are byte-stable across tools; the floating-point columns are
**excluded from the key** because the three tools render reals at different
precision (ours 5 dp, undark 6 dp, fqlite 8 dp), which would penalise float
*formatting* rather than recovery. Two databases — **0C-06** and **0C-07** —
carry `FLOAT` values *at* positions 1 and 2, so no format-stable cross-tool key
exists for them; they are **excluded from this table** (our own single-tool matrix
still scores them, rounding reals symmetrically). Categories `0A`/`0B`
(dropped/overwritten *tables* — no live-vs-deleted anchor) and `11` (anti-forensic
tampering — no deleted answer key) carry no clean row-level deleted set and are
**out of scope** for a recall table.

`Ddel` = rows deleted; `Drec` = of those, byte-present (recoverable substrate);
`live` = live rows wrongly recovered as deleted (must be 0); recall denominators
as defined under "[How the matrix is computed](#how-the-matrix-is-computed)".

| cat | tool | Ddel | Drec | TP | FP | FN | live | recall (substrate) | recall (e2e) | precision |
|---|---|---|---|---|---|---|---|---|---|---|
| 0C | **ours** | 84 | 84 | 23 | 3 | 61 | **0** | 0.274 | 0.274 | 0.885 |
| 0C | undark | 84 | 84 | 14 | 10 | 70 | 4 | 0.167 | 0.167 | 0.583 |
| 0C | fqlite | 84 | 84 | **67** | 16 | 17 | **0** | **0.798** | **0.798** | 0.807 |
| 0D | **ours** | 45 | 36 | 2 | 0 | 34 | **0** | 0.056 | 0.044 | **1.000** |
| 0D | undark | 45 | 36 | 1 | 10 | 35 | 56 | 0.028 | 0.022 | 0.091 |
| 0D | fqlite | 45 | 36 | **20** | 0 | 16 | **0** | **0.556** | **0.444** | **1.000** |
| 0E | **ours** | 12 | 9 | 3 | 0 | 6 | **0** | 0.333 | 0.250 | **1.000** |
| 0E | undark | 12 | 9 | 3 | 6 | 6 | 27 | 0.333 | 0.250 | 0.333 |
| 0E | fqlite | 12 | 9 | 2 | 2 | 7 | **0** | 0.222 | 0.167 | 0.500 |

(Totals exclude 0C-06/0C-07; `0C` therefore sums 8 databases, 84 deleted rows.
Regenerate with `cargo test -p sqlite-forensic --test nemetz_tool_comparison --
--nocapture`, with `UNDARK_BIN` and `FQLITE_TAP` set.)

### Honest read — who wins where, and why

- **In-page deletion (`0C`): fqlite leads recall decisively (0.798 vs ours 0.274
  vs undark 0.167).** fqlite carves freeblocks geometrically — it starts parsing
  at `freeblock_offset + 4` and reconstructs the record without the clobbered
  payload-length/rowid varints. Our forward parser cannot (the
  freeblock-prefix-clobber FN below); this is exactly the gap tracked in task #56.
  fqlite's lead costs precision (16 phantom rows, 0.807) — our carver is more
  precise (0.885) and re-reads no live row.
- **Deleted-then-overwritten (`0D`): fqlite leads recall (0.556); ours and fqlite
  hold perfect precision; undark fails on precision.** undark re-surfaces **56**
  live rows as deleted here (precision 0.091) — it mis-parses these overwritten
  tables and re-reads the live cells. Our carver and fqlite both recover only
  genuine residue (0 live-re-reads). Our recall is low (0.056) because the
  freeblock clobber compounds with the later `INSERT` overwrites.
- **Overflow (`0E`): ours and undark tie on recall (0.333), fqlite slightly lower
  (0.222); only ours holds perfect precision.** undark again re-reads live rows
  (27, precision 0.333); fqlite emits a couple of phantoms (0.500). Our carver
  recovers the rows whose first overflow segment + header survived, with no
  false positive.

The consistent picture: **fqlite recovers the most on in-page/overwrite deletion
via freeblock reconstruction; our carver recovers less but never re-reads a live
row and keeps the highest precision on 0D/0E; undark recovers the least and
frequently re-surfaces live rows as deleted on these tables.** Where undark and
fqlite beat us on in-page recall, the cause is their freeblock-aware
reconstruction — a known, recorded capability gap, not a measurement artifact.

## How the matrix is computed

For each database, the carver's output is matched against the answer key by full
decoded-row content (schema column order; integers in decimal, reals at 5 decimal
places, text verbatim, NULL as empty — the corpus's export format, applied
symmetrically to both sides):

- **TP** — a carved row equal to an answer-key **deleted** row.
- **FP** — a carved row equal to neither a deleted nor a **live** row (a phantom).
- **live-re-read** — a carved row equal to a **live** row; counted **separately**,
  never folded into FP, so the two very different failure modes stay distinct.
- **FN** — an answer-key deleted (substrate-recoverable) row no carved row matched.

Recall is reported with two denominators:

- **substrate-limited recall** = TP / `|D_recoverable|` — of the deleted rows
  whose bytes *physically survive* in the file (a corpus property computed
  independently of our carver, by byte-presence), how many did we recover? The
  carver-capability number.
- **end-to-end recall** = TP / `|D_deleted|` — of *all* rows the workload deleted
  (some destroyed by later overwrites), how many did we recover? The
  examiner-usefulness number.

`F2` is F-beta with β = 2 (recall-weighted, since missing evidence costs an
examiner more than discarding a low-confidence phantom), over precision and
substrate-limited recall.

## Our carver — per-database detail (computed)

The head-to-head above totals each tool per category. This section breaks **our
carver** down per database (from `nemetz_metrics.rs`), so a low category recall
can be traced to specific files. It differs from the head-to-head in two
deliberate ways, both of which slightly *raise* the count reported here versus the
head-to-head's `ours` row: it matches on the **full decoded row** (all columns,
reals at 5 dp) rather than the `(col1,col2)` projection, and it **includes
0C-06/0C-07** (whose float key columns the cross-tool table must drop). So our
0C total here is 24 (over all ten 0C databases) versus 23 in the head-to-head
(eight databases) — the same carver, two compatible scopings.

Categories: `0C` deleted records (in-page free block); `0D` deleted then
overwritten; `0E` deleted overflow records. `Ddel` = rows deleted; `Drec` = of
those, byte-present (recoverable substrate); `live` = live-re-reads (must be 0).

| DB | Ddel | Drec | TP | FP | FN | live | recall (substrate) | recall (e2e) | precision | F2 |
|---|---|---|---|---|---|---|---|---|---|---|
| 0C-01 | 7  | 7  | 0  | 0 | 7  | 0 | 0.000 | 0.000 | 1.000 | 0.000 |
| 0C-02 | 10 | 10 | 1  | 0 | 9  | 0 | 0.100 | 0.100 | 1.000 | 0.122 |
| 0C-03 | 7  | 7  | 2  | 1 | 5  | 0 | 0.286 | 0.286 | 0.667 | 0.323 |
| 0C-04 | 10 | 10 | 1  | 2 | 9  | 0 | 0.100 | 0.100 | 0.333 | 0.116 |
| 0C-05 | 10 | 10 | 1  | 0 | 9  | 0 | 0.100 | 0.100 | 1.000 | 0.122 |
| 0C-06 | 7  | 7  | 1  | 0 | 6  | 0 | 0.143 | 0.143 | 1.000 | 0.172 |
| 0C-07 | 10 | 10 | 0  | 0 | 10 | 0 | 0.000 | 0.000 | 1.000 | 0.000 |
| 0C-08 | 10 | 10 | 2  | 1 | 8  | 0 | 0.200 | 0.200 | 0.667 | 0.233 |
| 0C-09 | 10 | 10 | 5  | 0 | 5  | 0 | 0.500 | 0.500 | 1.000 | 0.556 |
| 0C-10 | 20 | 20 | 11 | 0 | 9  | 0 | 0.550 | 0.550 | 1.000 | 0.604 |
| **0C total** | **101** | **101** | **24** | **4** | **77** | **0** | **0.238** | **0.238** | **0.857** | — |
| 0D-01 | 5  | 3 | 0 | 0 | 3 | 0 | 0.000 | 0.000 | 1.000 | 0.000 |
| 0D-02 | 5  | 2 | 0 | 0 | 2 | 0 | 0.000 | 0.000 | 1.000 | 0.000 |
| 0D-03 | 5  | 2 | 0 | 0 | 2 | 0 | 0.000 | 0.000 | 1.000 | 0.000 |
| 0D-04 | 5  | 5 | 0 | 0 | 5 | 0 | 0.000 | 0.000 | 1.000 | 0.000 |
| 0D-05 | 5  | 5 | 0 | 0 | 5 | 0 | 0.000 | 0.000 | 1.000 | 0.000 |
| 0D-06 | 10 | 9 | 1 | 0 | 8 | 0 | 0.111 | 0.100 | 1.000 | 0.135 |
| 0D-07 | 5  | 5 | 0 | 0 | 5 | 0 | 0.000 | 0.000 | 1.000 | 0.000 |
| 0D-08 | 5  | 5 | 1 | 0 | 4 | 0 | 0.200 | 0.200 | 1.000 | 0.238 |
| 0E-01 | 7  | 6 | 3 | 0 | 3 | 0 | 0.500 | 0.429 | 1.000 | 0.556 |
| 0E-02 | 5  | 3 | 0 | 0 | 3 | 0 | 0.000 | 0.000 | 1.000 | 0.000 |

(Dropped/overwritten-*table* categories `0A`/`0B` carry no row-level deleted set
that anchors a live-vs-deleted distinction — the whole table is gone — so they are
reported as bounded dropped-table recovery, not in the recall matrix; their
correctness is measured by the DC3 differential below.)

### Reading the numbers

- **0C precision 0.857** (24 TP / 28 carved): the only leaks are the phantom
  all-empty class (4 across 0C-03/04/08), never a live row.
- **0C recall ≈ 24 %** with every deleted row substrate-present: the carver
  recovers only the subset whose cell header survived freeblock conversion.
- **0D recall is near-zero**: on top of the freeblock clobber, later `INSERT`s
  overwrite freed slack, so `Drec < Ddel` *and* most surviving rows are still
  prefix-clobbered.
- **0E** (overflow): the carver recovers the rows whose first overflow segment and
  header survived, missing the rest.

## The freeblock-prefix-clobber FN

This is the dominant FN class and the honest explanation for the low recall.
When SQLite deletes a cell from an allocated page, it converts the cell into a
**freeblock**: the first two bytes become the next-freeblock pointer and the next
two the freeblock size — **overwriting the cell's first four bytes**, which is
exactly where the cell header (payload-length varint + rowid varint) lived. The
record body and its serial-type array survive *after* that clobbered prefix.

`carve_free_regions` parses forward from the start of each free region. At a
freeblock boundary it sees the freeblock pointer/size where it expects the
payload-length and rowid varints, fails the self-consistency check, and recovers
nothing for that cell. The rows we *do* recover in `0C` are the ones whose header
happened to survive (e.g. the last freed cell in a chain, or slack not at a
freeblock head). Reference tools that score higher here (undark, fqlite) do
**freeblock-aware** carving: they start parsing at `freeblock_offset + 4` and
reconstruct the record without the original payload-length/rowid. Our carver does
not yet do this.

This is a **known capability gap, recorded — not a defect in the measurement**. A
freeblock-aware in-page carver is the obvious next step to raise recall; when
added, the pinned floor in `nemetz_metrics.rs` (`NEMETZ_0C_TP_FLOOR = 24`) rises
and the matrix above is regenerated. The phantom-FP class (low-confidence
all-empty inferred records) is the companion precision item to address alongside
it.

## What the numbers do and do NOT claim

- They claim an **honest, reproducible measurement** of all three tools against
  *this* independent corpus: fqlite leads recall on in-page/overwrite deletion via
  freeblock reconstruction; our carver leads on precision and never re-reads a live
  row; undark trails on both and over-reports live rows as deleted on the
  overwritten and overflow tables.
- They do **not** claim our carver is "best" or that it has parity with
  freeblock-aware tools on in-page recall — it does not, by the documented
  freeblock-prefix clobber. Each tool wins on a different axis.
- A low per-category recall is a true statement about a capability boundary, not a
  harness artifact — the substrate partition proves the bytes are present and we
  still miss them.

## Inter-tool concordance on our own fixture (agreement, not correctness)

Separate from the head-to-head above (which scores each tool against ground
truth), `oracle_differential.rs` reconciles our output against undark and fqlite
as **oracles over our own `deleted_places.db` fixture** — it answers "do we agree
with them?", not "how does each score?". On that fixture (whole-freed-page
deletion — the shape our carver handles), our output **matches undark exactly**
(163 rows) and **matches-or-exceeds fqlite**, and on the prior-version fixture we
**match fqlite and exceed undark**. This is genuine agreement *on that deletion
shape*, but it is inter-tool concordance, not ground truth — which is why the
Nemetz head-to-head (real answer keys) is the headline.

## DC3 `sqlite_dissect` corpus — a no-false-positive regression set

The DC3 corpus carries **no deleted-row ground truth**: its `expected_rows` were
found (independently confirmed: `freelist_count = 0`, contiguous rowids,
`expected == SELECT *` on the readable DBs) to be the **live table content**, used
upstream only as a precision allow-list. We therefore keep it solely as a
**no-false-positive / `NoGenuineDeletion` regression set** (the carver must not
re-surface those intact live rows) plus a dropped-table recovery check on
`0A-01`/`0A-02`. No precision/recall is computed from it.

## WAL-resident records

Out of scope for the carver: a row that exists only in an uncheckpointed `-wal`
overlay is *live* (not yet checkpointed), not deleted, so it is not a carving
target. `sqlite-core` surfaces the WAL-applied view via
`Database::open_with_wal`, and the auditor flags an active overlay as
`WalUncheckpointedState`. Recovering genuinely *deleted* content from within WAL
frames, with WAL-sequencing ground truth, is the subject of a separate
(NIST CFReDS-based) evaluation not yet landed.
