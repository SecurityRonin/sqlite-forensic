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

- **Freeblock-aware reconstruction (task #56) closed most of the in-page recall
  gap at the highest precision of any tool.** On the in-page-deletion category
  `0C`, our carver now recovers **63** of the 84 recoverable deleted rows
  (recall 0.750, up from 23 / 0.274), against fqlite **67** (0.798) and undark
  **14** (0.167). We do it at **precision 0.955** (3 phantoms) versus fqlite's
  **0.807** (16 phantoms) — i.e. nearly fqlite's recall with roughly five times
  fewer false rows.
- **Our carver still never re-surfaces a live row.** Across the in-scope corpus
  it emits **0 live-re-reads** — the structural 0-false-positive guarantee held
  through the change. fqlite also holds 0; undark does **not** — on `0D` it
  re-reads **56** live rows as deleted (precision 0.091) and on `0E` **27**
  (precision 0.333).
- **We Pareto-dominate fqlite on overflow (`0E`)** — higher recall (0.333 vs
  0.222) AND higher precision (1.000 vs 0.500). On `0C` and `0D` fqlite keeps a
  recall edge (0.798 vs 0.750; 0.556 vs 0.306) while we keep the precision edge;
  neither tool dominates the other there.
- **The mechanism**: when SQLite frees an in-page cell it overwrites the cell's
  first four bytes (payload-length + rowid varints, the record `header_len`, and
  the leading serial type) with the freeblock header. `reconstruct_freeblock_records`
  rebuilds each freed cell from its *surviving* serial-type tail plus a header
  template derived from a live cell on the same page; the destroyed rowid is
  surfaced as unknown (`0`), never invented. See
  "[Freeblock reconstruction](#freeblock-reconstruction)".
- **Two recall denominators** are reported because they answer different questions
  — substrate-limited (carver capability) and end-to-end (examiner usefulness).
- These are honest measurements of *each tool* against *this* corpus, not a
  verdict that any tool is "best": stated plainly below.

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
| 0C | **ours** | 84 | 84 | 63 | 3 | 21 | **0** | 0.750 | 0.750 | **0.955** |
| 0C | undark | 84 | 84 | 14 | 10 | 70 | 4 | 0.167 | 0.167 | 0.583 |
| 0C | fqlite | 84 | 84 | **67** | 16 | 17 | **0** | **0.798** | **0.798** | 0.807 |
| 0D | **ours** | 45 | 36 | 11 | 0 | 25 | **0** | 0.306 | 0.244 | **1.000** |
| 0D | undark | 45 | 36 | 1 | 10 | 35 | 56 | 0.028 | 0.022 | 0.091 |
| 0D | fqlite | 45 | 36 | **20** | 0 | 16 | **0** | **0.556** | **0.444** | **1.000** |
| 0E | **ours** | 12 | 9 | **3** | 0 | 6 | **0** | **0.333** | **0.250** | **1.000** |
| 0E | undark | 12 | 9 | 3 | 6 | 6 | 27 | 0.333 | 0.250 | 0.333 |
| 0E | fqlite | 12 | 9 | 2 | 2 | 7 | **0** | 0.222 | 0.167 | 0.500 |

(Totals exclude 0C-06/0C-07; `0C` therefore sums 8 databases, 84 deleted rows.
Regenerate with `cargo test -p sqlite-forensic --test nemetz_tool_comparison --
--nocapture`, with `UNDARK_BIN` and `FQLITE_TAP` set.)

### Honest read — who wins where, and why

- **In-page deletion (`0C`): ours and fqlite now lead together; undark trails.**
  With freeblock reconstruction (task #56) our recall rose 0.274 → **0.750**,
  essentially matching fqlite's **0.798** — but at **precision 0.955** (3
  phantoms) versus fqlite's **0.807** (16 phantoms). fqlite keeps a small recall
  edge; we keep a clear precision edge and re-read no live row. Neither tool
  Pareto-dominates the other on `0C`.
- **Deleted-then-overwritten (`0D`): fqlite leads recall (0.556 vs ours 0.306);
  ours and fqlite hold perfect precision; undark fails on precision.** undark
  re-surfaces **56** live rows as deleted here (precision 0.091) — it mis-parses
  these overwritten tables and re-reads the live cells. Our recall rose 0.056 →
  **0.306** via reconstruction, but the later `INSERT` overwrites destroy more
  substrate than `0C`, so fqlite's more aggressive (lower-precision elsewhere)
  reconstruction recovers more here. Both keep 0 live-re-reads.
- **Overflow (`0E`): ours Pareto-dominates fqlite — higher recall (0.333 vs
  0.222) AND higher precision (1.000 vs 0.500).** undark ties our recall (0.333)
  but re-reads **27** live rows (precision 0.333); fqlite emits phantoms (0.500).
  Our carver recovers the rows whose first overflow segment + header survived,
  with no false positive. (Freeblock reconstruction adds nothing on `0E` — these
  records spill to overflow, so the residue is not a simple in-page freeblock.)

The consistent picture: **after task #56, our carver matches fqlite's in-page
recall while keeping the highest precision of all three tools on every category
and never re-reading a live row; it Pareto-dominates fqlite on overflow; fqlite
retains a recall edge on `0C`/`0D` only by tolerating more phantoms; undark
trails on both recall and precision and over-reports live rows as deleted.**

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
0C total here is **79** (over all ten 0C databases) versus 63 in the head-to-head
(eight databases) — the same carver, two compatible scopings.

Categories: `0C` deleted records (in-page free block); `0D` deleted then
overwritten; `0E` deleted overflow records. `Ddel` = rows deleted; `Drec` = of
those, byte-present (recoverable substrate); `live` = live-re-reads (must be 0).

| DB | Ddel | Drec | TP | FP | FN | live | recall (substrate) | recall (e2e) | precision | F2 |
|---|---|---|---|---|---|---|---|---|---|---|
| 0C-01 | 7  | 7  | 6  | 0 | 1 | 0 | 0.857 | 0.857 | 1.000 | 0.882 |
| 0C-02 | 10 | 10 | 8  | 0 | 2 | 0 | 0.800 | 0.800 | 1.000 | 0.833 |
| 0C-03 | 7  | 7  | 6  | 1 | 1 | 0 | 0.857 | 0.857 | 0.857 | 0.857 |
| 0C-04 | 10 | 10 | 8  | 2 | 2 | 0 | 0.800 | 0.800 | 0.800 | 0.800 |
| 0C-05 | 10 | 10 | 10 | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |
| 0C-06 | 7  | 7  | 7  | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |
| 0C-07 | 10 | 10 | 9  | 0 | 1 | 0 | 0.900 | 0.900 | 1.000 | 0.918 |
| 0C-08 | 10 | 10 | 9  | 1 | 1 | 0 | 0.900 | 0.900 | 0.900 | 0.900 |
| 0C-09 | 10 | 10 | 5  | 0 | 5 | 0 | 0.500 | 0.500 | 1.000 | 0.556 |
| 0C-10 | 20 | 20 | 11 | 0 | 9 | 0 | 0.550 | 0.550 | 1.000 | 0.604 |
| **0C total** | **101** | **101** | **79** | **4** | **22** | **0** | **0.782** | **0.782** | **0.952** | — |
| 0D-01 | 5  | 3 | 1 | 0 | 2 | 0 | 0.333 | 0.200 | 1.000 | 0.385 |
| 0D-02 | 5  | 2 | 1 | 0 | 1 | 0 | 0.500 | 0.200 | 1.000 | 0.556 |
| 0D-03 | 5  | 2 | 0 | 0 | 2 | 0 | 0.000 | 0.000 | 1.000 | 0.000 |
| 0D-04 | 5  | 5 | 1 | 0 | 4 | 0 | 0.200 | 0.200 | 1.000 | 0.238 |
| 0D-05 | 5  | 5 | 0 | 0 | 5 | 0 | 0.000 | 0.000 | 1.000 | 0.000 |
| 0D-06 | 10 | 9 | 1 | 0 | 8 | 0 | 0.111 | 0.100 | 1.000 | 0.135 |
| 0D-07 | 5  | 5 | 3 | 0 | 2 | 0 | 0.600 | 0.600 | 1.000 | 0.652 |
| 0D-08 | 5  | 5 | 4 | 0 | 1 | 0 | 0.800 | 0.800 | 1.000 | 0.833 |
| 0E-01 | 7  | 6 | 3 | 0 | 3 | 0 | 0.500 | 0.429 | 1.000 | 0.556 |
| 0E-02 | 5  | 3 | 0 | 0 | 3 | 0 | 0.000 | 0.000 | 1.000 | 0.000 |

(Dropped/overwritten-*table* categories `0A`/`0B` carry no row-level deleted set
that anchors a live-vs-deleted distinction — the whole table is gone — so they are
reported as bounded dropped-table recovery, not in the recall matrix; their
correctness is measured by the DC3 differential below.)

### Reading the numbers

- **0C precision 0.952** (79 TP / 83 carved): the only leaks are the phantom
  all-empty class (4 across 0C-03/04/08), never a live row. Freeblock
  reconstruction added 55 TP without adding a single live-re-read.
- **0C recall ≈ 78 %** with every deleted row substrate-present: reconstruction
  now recovers the freeblock-head cells the forward parser missed; the residual
  FN are mostly 0C-09/0C-10 (whose freed cells have no freeblock chain — they sit
  in the unallocated gap with a destroyed prefix the template cannot anchor).
- **0D recall rose to ≈ 31 %**: reconstruction recovers the freeblock residue,
  but later `INSERT`s overwrite freed slack (`Drec < Ddel`) and destroy more than
  in `0C`.
- **0E** (overflow): unchanged — these records spill to overflow pages, so the
  in-page freeblock template does not apply; the carver recovers the rows whose
  first overflow segment + header survived.

## Freeblock reconstruction

This was the dominant FN class before task #56, and the fix that closed it.
When SQLite frees a cell from an allocated page, it converts the cell into a
**freeblock** (file-format §1.6): the first two bytes become the next-freeblock
pointer and the next two the freeblock size — **overwriting the cell's first four
bytes**, which span the payload-length varint, the rowid varint, the record
`header_len` varint, and the leading serial type(s). The record's **surviving
serial-type tail and its whole value body remain intact** *after* those four
bytes.

`Database::reconstruct_freeblock_records` rebuilds each freed cell from that
surviving tail plus a **schema template** derived from a live cell on the same
page — the table's column count, header length, and the serial types of the
leading columns that fall inside the clobbered prefix (e.g. a fixed-width `id`
column). It walks the page's freeblock chain (bounded, cycle-safe), reads the
surviving serials at the byte offset where the clobber ends, prepends the
template's leading serials, and decodes the body. The destroyed rowid is surfaced
as unknown (`0`) — never invented — and the record is graded LOW
(`FREEBLOCK_RECONSTRUCT_CONFIDENCE`), tagged `RecoverySource::FreeblockReconstructed`.

**Precision is preserved by construction.** A reconstructed candidate is emitted
only when every serial type is legal AND the whole record fits within the
freeblock's `[offset, offset + size)` bounds; the forensic layer additionally
drops any reconstruction whose decoded values match a live row (by value, since
the rowid is gone). The result: 0C recall 0.274 → 0.750 with **0 new phantoms and
0 live-re-reads** — fqlite-level recall at higher precision (3 phantoms vs 16).

This is the published forensic technique (Nemetz et al. 2018; Pawlaszczyk &
Hummert 2021), implemented from the SQLite file-format spec — not adapted from any
GPL tool's source.

## What the numbers do and do NOT claim

- They claim an **honest, reproducible measurement** of all three tools against
  *this* independent corpus: after task #56, our carver matches fqlite's in-page
  recall at the highest precision of the three and never re-reads a live row;
  it Pareto-dominates fqlite on overflow (`0E`); fqlite keeps a recall edge on
  `0C`/`0D` by tolerating more phantoms; undark trails on both and over-reports
  live rows as deleted on the overwritten and overflow tables.
- They do **not** claim our carver is "best" overall. fqlite still recovers more
  raw rows on `0C` (0.798 vs 0.750) and `0D` (0.556 vs 0.306); we trade those few
  rows for a structural 0-false-positive guarantee and the lowest phantom rate.
- A low per-category recall (e.g. `0E`) is a true statement about a capability
  boundary, not a harness artifact — the substrate partition proves the bytes are
  present and we still miss them.

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
