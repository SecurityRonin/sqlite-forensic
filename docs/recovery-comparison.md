# Deleted-Record Recovery — Measured Capability

What `sqlite_forensic::carve_all_deleted_records` actually recovers, measured
against **independent third-party ground truth** — the SQLite Forensic Corpus
(Nemetz, Schmitt & Freiling, DFRWS-EU 2018, CC0), whose authors shipped, per
database, an `.xml` answer key tagging every deleted row with its full content.

This replaces the earlier prose ("163 of 163 recoverable, 0 false positives"),
which was measured only against our *own* `deleted_places.db` fixture — a
Doer-Checker-weak setup where we authored both the deleter and the carver, and
whose particular deletion shape (whole leaf pages freed onto the freelist)
happens to be the one case our carver handles well. Against independent ground
truth that also exercises the common **in-page free-block** deletion, the honest
recall is **much lower**, and this document reports the true per-database numbers.

The matrix is **computed reproducibly** by `forensic/tests/nemetz_metrics.rs`
(run it with `--nocapture` to regenerate the table), not hand-written. Corpus and
oracle provenance are in [`corpus-catalog.md`](corpus-catalog.md) and
[`validation.md`](validation.md).

## Executive summary

- **Precision is high.** Across the recall corpus the carver emits **0
  live-re-reads** (a live row is never structurally re-surfaced as deleted) and
  only a small, low-confidence **phantom** class (all-empty/NULL records the
  inferred carver matches on a run of zero bytes). This is the carver's real
  strength and it is confirmed against independent ground truth.
- **Recall is low on in-page deletion, by a documented mechanism.** On the
  cleanest category — `0C`, records deleted in place with `secure_delete=0` and no
  later overwrite, so **every** deleted row's bytes physically survive — the
  carver recovers only **24 of 101** deleted rows (substrate-limited recall ≈
  24 %). The cause is structural and is *not* a harness artifact: see
  "[The freeblock-prefix-clobber FN](#the-freeblock-prefix-clobber-fn)".
- **Two recall denominators** are reported per database because they answer
  different questions — substrate-limited (capability) and end-to-end
  (usefulness).
- The independent-oracle differential (undark, fqlite) and the DC3 corpus remain
  as **secondary** checks (inter-tool concordance and a no-false-positive
  regression set), explicitly labelled *agreement, not correctness*.

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

## Per-database confusion matrix (computed)

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

- They claim an **honest, reproducible measurement** of *this* carver against
  *this* independent corpus: high precision (no live-re-read; a small phantom
  class), low recall on in-page/overflow deletion driven by the documented
  freeblock-prefix clobber.
- They do **not** claim parity with freeblock-aware tools on in-page deletion, and
  they retract the earlier "163/163, 0 FP" framing as fixture-specific.
- A low per-category recall is a true statement about a capability boundary, not a
  harness artifact — the substrate partition proves the bytes are present and we
  still miss them.

## Secondary checks (agreement, not correctness)

These corroborate behaviour but are **not** a correctness oracle; the two
reference tools disagree with each other, so there is no gold standard among them.

### Inter-tool concordance — undark & fqlite (`oracle_differential.rs`)

On our own `deleted_places.db` fixture (whole-freed-page deletion — the shape our
carver handles), our output **matches undark exactly** (163 rows) and
**matches-or-exceeds fqlite**, and on the prior-version fixture we **match fqlite
and exceed undark**. This is genuine evidence of agreement *on that deletion
shape*, but it is explicitly inter-tool concordance, not ground truth — which is
precisely why the Nemetz matrix above (real answer keys) is now the headline.

### DC3 `sqlite_dissect` corpus — a no-false-positive regression set

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
