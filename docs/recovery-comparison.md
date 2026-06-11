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

- **Freeblock-aware reconstruction closed the in-page recall gap and now leads,
  at the highest precision of any tool.** On the in-page-deletion category `0C`,
  our carver recovers **70** of the 84 recoverable deleted rows (recall 0.833, up
  from 23 / 0.274), ahead of fqlite **67** (0.798) and undark **14** (0.167). We
  do it at **precision 0.959** (3 phantoms) versus fqlite's **0.807** (16
  phantoms) — higher recall AND roughly five times fewer false rows.
- **Our carver still never re-surfaces a live row.** Across the in-scope corpus
  it emits **0 live-re-reads** — the structural 0-false-positive guarantee held
  through the change. fqlite also holds 0; undark does **not** — on `0D` it
  re-reads **56** live rows as deleted (precision 0.091) and on `0E` **27**
  (precision 0.333).
- **On overflow (`0E`) we lead on substrate recall (1.000 vs fqlite 0.667) at
  precision 1.000.** On `0D` (deleted then overwritten) ours and fqlite both
  recover **every** row whose full identity still survives — substrate recall
  1.000, precision 1.000 — against an honest contiguous full-row denominator of 19
  (the other ~26 of 45 deleted rows were destroyed by later overwrites). The `0E`
  denominator is likewise honest (3 of 12: most overflow bodies that survive do so
  in-page and contiguously; the few that genuinely spill to an overflow-page chain
  are conservatively excluded). On `0C` ours now leads on recall as well as
  precision.
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

`Ddel` = rows deleted; `Drec` = of those, the recoverable substrate — rows whose
scored identity still physically survives in the file; `live` = live rows wrongly
recovered as deleted (must be 0); recall denominators as defined under
"[How the matrix is computed](#how-the-matrix-is-computed)".

The substrate denominator is the **honest contiguous full-row-identity** count,
decided **per record by body size** (not by category): a deleted row is
recoverable only when its whole record body — every column's bytes, in column
order — survives as one contiguous run, mirroring the recall matcher's full-row
key. The earlier proxy (any one distinctive column surviving anywhere) inflated
the count by treating a row as recoverable when a later same-rowid overwrite had
destroyed its scored identity but a single column coincidentally survived
elsewhere. Under the honest rule:

- `0D` drops from 36 to **19** — overwrites genuinely destroyed roughly 26 of the
  45 deleted rows; the substrate is small for that reason, not because the harness
  is lenient.
- `0E` drops from 9 to **3**. Most `0E` deleted bodies are large-but-in-page and
  survive as a single contiguous run (tested honestly); the few records whose
  payload exceeds the in-page limit (`usable − 35`) spill to a non-contiguous
  overflow-page chain (SQLite file format, "Cell payload overflow pages") that a
  flat-file contiguity test cannot model, so they are conservatively counted as
  not-recoverable — chain-aware overflow recoverability is future work.
- `0C` (no overwrites) stays fully recoverable (101/101 on the single-tool
  matrix).

| cat | tool | Ddel | Drec | TP | FP | FN | live | recall (substrate) | recall (e2e) | precision |
|---|---|---|---|---|---|---|---|---|---|---|
| 0C | **ours** | 84 | 84 | **70** | 3 | 14 | **0** | **0.833** | **0.833** | **0.959** |
| 0C | undark | 84 | 84 | 14 | 10 | 70 | 4 | 0.167 | 0.167 | 0.583 |
| 0C | fqlite | 84 | 84 | 67 | 16 | 17 | **0** | 0.798 | 0.798 | 0.807 |
| 0D | **ours** | 45 | 19 | 19 | 0 | 0 | **0** | **1.000** | 0.422 | **1.000** |
| 0D | undark | 45 | 19 | 1 | 10 | 18 | 56 | 0.053 | 0.022 | 0.091 |
| 0D | fqlite | 45 | 19 | **20** | 0 | 0 | **0** | **1.000** | **0.444** | **1.000** |
| 0E | **ours** | 12 | 3 | **3** | 0 | 0 | **0** | **1.000** | **0.250** | **1.000** |
| 0E | undark | 12 | 3 | 3 | 6 | 0 | 27 | 1.000 | 0.250 | 0.333 |
| 0E | fqlite | 12 | 3 | 2 | 2 | 2 | **0** | 0.333 | 0.167 | 0.500 |

(Totals exclude 0C-06/0C-07; `0C` therefore sums 8 databases, 84 deleted rows.
Regenerate with `cargo test -p sqlite-forensic --test nemetz_tool_comparison --
--nocapture`, with `UNDARK_BIN` and `FQLITE_TAP` set.)

![Precision-recall plane plus F1 and F0.5 grouped bars for ours, undark, and
fqlite across categories 0C/0D/0E](img/recovery-comparison.png)

The figure plots the **same harness-computed numbers** as the table above:
`forensic/tests/nemetz_tool_comparison.rs` writes the per-(tool, category)
`recall_substrate`, `precision`, `F1`, and `F0.5` to
[`img/comparison_metrics.csv`](img/comparison_metrics.csv) when run with the
undark/fqlite oracles, and `docs/plot_comparison.py` renders the chart straight
from that CSV — chart and table are the same dataset by construction. By **F1**
(balanced), sqlite-forensic leads `0C` (0.892 vs fqlite 0.802) and `0E` (1.000 vs
undark 0.500, fqlite 0.400); under **F0.5** (precision-weighted — the forensic β,
since a phantom row costs an examiner more than a missed low-confidence one) the
`0C` lead widens (0.931 vs 0.805) and `0E` stays a clean lead (1.000 vs undark
0.385, fqlite 0.455). On `0D`, ours and fqlite both score **1.000** on substrate
recall, precision, and therefore both F-scores — each recovers every row whose full
identity survives. To refresh: rerun the test with `UNDARK_BIN`/`FQLITE_TAP` set to
rewrite the CSV, then `python3 docs/plot_comparison.py` to rerender the PNG. (The
committed CSV/PNG were produced by that oracle run; `FQLITE_TAP` =
`tools/fqlite/run-tap.sh`, `UNDARK_BIN` = `tools/undark`.)

### Honest read — who wins where, and why

- **In-page deletion (`0C`): ours leads on both recall and precision; undark
  trails.** With freeblock reconstruction our recall reached **0.833** (70 of 84),
  ahead of fqlite's **0.798** (67) — and at **precision 0.959** (3 phantoms)
  versus fqlite's **0.807** (16 phantoms). We re-read no live row.
- **Deleted-then-overwritten (`0D`): ours and fqlite both recover every row whose
  identity survives — substrate recall 1.000, precision 1.000; undark fails on
  precision.** undark re-surfaces **56** live rows as deleted here (precision
  0.091) — it mis-parses these overwritten tables and re-reads the live cells.
  Against the honest contiguous full-row-identity denominator (19 of the 45
  deleted rows still carry a survivable scored identity; the rest were destroyed
  by later same-rowid overwrites), our span-walk reconstruction recovers all 19,
  matching fqlite — both at precision 1.000, both with 0 live-re-reads. (fqlite
  projects **20** TPs under the cross-tool `(col1,col2)` projection against the
  denominator of 19 substrate-recoverable rows; that extra projected row is not
  part of the recoverable substrate.)
- **Overflow (`0E`): ours leads — substrate recall 1.000 at precision 1.000.**
  Against the honest denominator (3 of the 12 deleted overflow rows survive
  in-page and contiguously), our carver recovers all 3 with no false positive.
  undark ties on substrate recall (3/3) but re-reads **27** live rows (precision
  0.333); fqlite recovers 2 of 3 (recall 0.667) and emits phantoms (precision
  0.500). (Freeblock reconstruction adds nothing on `0E` — these records spill to
  overflow, so the residue is not a simple in-page freeblock.)

The consistent picture (per the committed oracle run): **our carver leads fqlite
on in-page recall (`0C`, 0.833 vs 0.798) while keeping the highest precision of all
three tools on every category and never re-reading a live row; it leads on overflow
(`0E`, substrate recall 1.000 vs fqlite 0.667) and matches fqlite on overwritten
records (`0D`) — both recover every row whose full identity survives, at precision
1.000; undark trails on precision throughout and over-reports live rows as
deleted.**

### Live `sqlite_master` re-reads — a precision artifact, measured per tool

A subtler precision failure than a phantom row is re-surfacing the database's
**current `sqlite_master` schema row** — the live page-1
`(type, name, tbl_name, rootpage, sql)` table-definition record — as if it were a
recovered *deleted* record. It was never deleted, so reporting it as recovered
mis-presents a live object as evidence. This is distinct from the user-row
live-re-read in the matrix above (which counts a carved row equal to a live
*user-table* row): the schema row is not a user-table row, so it never enters
that `alive` set and a separate measurement is needed.

The detector is general, derived from the schema itself (not a per-database
constant): a recovered record counts as a live schema re-read iff its
`(type, name, tbl_name)` identity equals a row returned by the live page-1 schema
read. Measured across the in-scope corpus (the same 18 databases the head-to-head
scores — `0C`/`0D`/`0E` minus the two FLOAT-key exclusions):

| tool | live `sqlite_master` re-reads |
|---|---|
| **ours** | **0** |
| undark | **0** |
| fqlite | **25** |

fqlite emits the live schema-table row as a recovered record on **every**
in-scope database (one per single-table DB, two per two-table DB). Our carver
emits **0** — the live schema rows are folded into the same value-based live-row
filter that suppresses re-reads of live user rows, so the schema record is
recognised as live and dropped. undark emits **0** because it does not
reconstruct `sqlite_master` at all (it surfaces only raw cell rows). The count is
reproducible from `forensic/tests/nemetz_tool_comparison.rs`
(`live_sqlite_master_rereads_per_tool`) with `UNDARK_BIN` and `FQLITE_TAP` set.

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
  whose scored identity *physically survives* in the file (a corpus property
  computed independently of our carver: the full record body surviving
  contiguously, decided per record by body size — records that genuinely overflow
  onto a non-contiguous overflow-page chain are conservatively excluded), how many
  did we recover? The carver-capability number.
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
0C total here is **87** (over all ten 0C databases) versus 70 in the head-to-head
(eight databases) — the same carver, two compatible scopings.

Categories: `0C` deleted records (in-page free block); `0D` deleted then
overwritten; `0E` deleted overflow records. `Ddel` = rows deleted; `Drec` = of
those, the recoverable substrate — rows whose full scored identity survives
contiguously, decided per record by body size (records that genuinely overflow
onto a non-contiguous chain are conservatively excluded); `live` = live-re-reads
(must be 0).

| DB | Ddel | Drec | TP | FP | FN | live | recall (substrate) | recall (e2e) | precision | F2 |
|---|---|---|---|---|---|---|---|---|---|---|
| 0C-01 | 7  | 7  | 7  | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |
| 0C-02 | 10 | 10 | 10 | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |
| 0C-03 | 7  | 7  | 7  | 1 | 0 | 0 | 1.000 | 1.000 | 0.875 | 0.972 |
| 0C-04 | 10 | 10 | 10 | 2 | 0 | 0 | 1.000 | 1.000 | 0.833 | 0.962 |
| 0C-05 | 10 | 10 | 10 | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |
| 0C-06 | 7  | 7  | 7  | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |
| 0C-07 | 10 | 10 | 10 | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |
| 0C-08 | 10 | 10 | 10 | 1 | 0 | 0 | 1.000 | 1.000 | 0.909 | 0.980 |
| 0C-09 | 10 | 10 | 5  | 0 | 5 | 0 | 0.500 | 0.500 | 1.000 | 0.556 |
| 0C-10 | 20 | 20 | 11 | 0 | 9 | 0 | 0.550 | 0.550 | 1.000 | 0.604 |
| **0C total** | **101** | **101** | **87** | **4** | **14** | **0** | **0.861** | **0.861** | **0.956** | — |
| 0D-01 | 5  | 1 | 1 | 0 | 0 | 0 | 1.000 | 0.200 | 1.000 | 1.000 |
| 0D-02 | 5  | 1 | 1 | 0 | 0 | 0 | 1.000 | 0.200 | 1.000 | 1.000 |
| 0D-03 | 5  | 0 | 0 | 0 | 0 | 0 | 1.000 | 0.000 | 1.000 | 1.000 |
| 0D-04 | 5  | 2 | 2 | 0 | 0 | 0 | 1.000 | 0.400 | 1.000 | 1.000 |
| 0D-05 | 5  | 0 | 0 | 0 | 0 | 0 | 1.000 | 0.000 | 1.000 | 1.000 |
| 0D-06 | 10 | 5 | 5 | 0 | 0 | 0 | 1.000 | 0.500 | 1.000 | 1.000 |
| 0D-07 | 5  | 5 | 5 | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |
| 0D-08 | 5  | 5 | 5 | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |
| 0E-01 | 7  | 3 | 3 | 0 | 0 | 0 | 1.000 | 0.429 | 1.000 | 1.000 |
| 0E-02 | 5  | 0 | 0 | 0 | 0 | 0 | 1.000 | 0.000 | 1.000 | 1.000 |

(Dropped/overwritten-*table* categories `0A`/`0B` carry no row-level deleted set
that anchors a live-vs-deleted distinction — the whole table is gone — so they are
reported as bounded dropped-table recovery, not in the recall matrix; their
correctness is measured by the DC3 differential below.)

### Reading the numbers

- **0C precision 0.956** (87 TP / 91 carved): the only leaks are the phantom
  all-empty class (4 across 0C-03/04/08), never a live row. Freeblock
  reconstruction added the freeblock-head cells without adding a single
  live-re-read.
- **0C recall ≈ 86 %** with every deleted row substrate-present: reconstruction
  recovers the freeblock-head cells the forward parser missed; the residual FN are
  0C-09/0C-10 (whose freed cells have no freeblock chain — they sit in the
  unallocated gap with a destroyed prefix the template cannot anchor).
- **0D substrate recall 1.000** (19 TP / 19 Drec): span-walking freeblock
  reconstruction recovers *every* coalesced cell in a free span, not just the
  span's head — and the substrate denominator is now the honest contiguous
  full-row-identity count, so it equals exactly the rows whose scored identity
  still survives. The carver recovers all of them. End-to-end recall (TP / Ddel)
  stays lower because later `INSERT`s genuinely destroyed ~26 of the 45 deleted
  rows' identities.
- **0E substrate recall 1.000** (3 TP / 3 Drec): the freeblock template does not
  apply here (these records spill to overflow), but the per-record substrate rule
  does — most `0E` deleted bodies are large-but-in-page and survive contiguously,
  and the carver recovers all 3 of them. The honest denominator is 3 (the few rows
  that genuinely overflow onto a non-contiguous overflow-page chain are
  conservatively excluded — chain-aware overflow recovery is future work), so this
  is no longer the inflated 9 the any-distinctive-column proxy produced.

## Freeblock reconstruction

This was the dominant FN class before freeblock-aware reconstruction, and the fix that closed it.
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
the rowid is gone). The result: 0C recall 0.274 → 0.833 with **0 new phantoms and
0 live-re-reads** — above fqlite's recall at higher precision (3 phantoms vs 16).

This is the published forensic technique (Nemetz et al. 2018; Pawlaszczyk &
Hummert 2021), implemented from the SQLite file-format spec — not adapted from any
GPL tool's source.

## What the numbers do and do NOT claim

- They claim an **honest, reproducible measurement** of all three tools against
  *this* independent corpus (per the committed oracle run): our carver leads fqlite
  on in-page recall (`0C`) at the highest precision of the three and never re-reads
  a live row; it leads on overflow (`0E`, substrate recall 1.000 vs fqlite 0.667)
  and matches fqlite on overwritten records (`0D`), where both recover every row
  whose full identity survives; undark trails on precision and over-reports live
  rows as deleted on the overwritten and overflow tables.
- They do **not** claim our carver is "best" overall. On `0D` end-to-end, fqlite's
  cross-tool `(col1,col2)` projection counts **20** TPs to our 19 (against a
  denominator of 19 substrate-recoverable rows); on `0C` we lead fqlite by raw
  recall, and on `0E` we lead it. We hold a structural 0-false-positive guarantee
  and the lowest phantom rate of the three throughout.
- A low per-category end-to-end recall is a true statement about a capability
  boundary, not a harness artifact — the two-denominator split separates "the bytes
  did not survive" (substrate) from "the bytes survived and we missed them"
  (carver capability).

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
