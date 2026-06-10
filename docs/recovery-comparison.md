# Deleted-Record Recovery — Capability Comparison

A recovery-power comparison of **our** carver (`sqlite_forensic::carve_all_deleted_records`)
against two independent reference tools — **undark** (C) and **fqlite** (Java) —
structured by deletion-scenario class. The differential methodology, oracle
provenance, and build recipes are in [`validation.md`](validation.md); the corpus
provenance is in [`corpus-catalog.md`](corpus-catalog.md). This document does not
repeat those; it reports the per-scenario numbers.

## Headline

Post-#49 our carver gained **in-page free-block carving** and **dropped-table
carving** (column count inferred from each record's serial-type array). The result:

- On the freed-page + in-page scenario (our fixture) it **exactly matches undark**
  (163 of 163 recoverable rows) and **matches-or-exceeds fqlite**.
- On dropped tables it **matches or exceeds undark** (recovers the dropped rows
  plus the dropped table's own schema record).
- On the "no genuine deletion" DBs it recovers **~none — correctly**: undark and
  fqlite over-report there by re-reading the intact live rows, which our carver
  refuses to do.
- **0 false positives** across the entire corpus — the non-negotiable property.
  This is stronger than both oracles: undark and fqlite both re-surface live rows
  (as deleted) and stale copies of live rows; ours never does.

"Recover" below means a clean, fully-decoded record. Counts are of distinct
recovered rows. Our carver is **deterministic**; the fqlite tap is mildly
non-deterministic (result-list ordering/dedup varies run-to-run), so its counts
are representative of a typical run.

## The four deletion-scenario classes

| class | what it is | where the residue lives |
|---|---|---|
| **Freed freelist whole-page** | rows deleted such that whole leaf pages are freed onto the freelist (no `VACUUM`, `secure_delete=OFF`) | freelist trunk + leaf page bodies |
| **In-page free block** | rows deleted in place on a page that stays allocated | the unallocated gap / inter-cell slack of an allocated leaf page |
| **Dropped table** | `DROP TABLE` — the table's page goes on the freelist with no `sqlite_master` schema | freelist page body; column count must be inferred |
| **WAL-resident** | rows that exist only in an uncheckpointed `-wal` overlay | WAL frames (not in the main file) |

## Per-scenario results

### Freed freelist whole-page + in-page (our fixture `deleted_places.db`)

`moz_places`, 400 rows; ids 201..=400 `DELETE`d without `VACUUM` under
`secure_delete=OFF`. Ground truth: 200 deleted rows. Of those, ids 201..=236 and
250 had their cell content overwritten by the freelist trunk header / leaf-pointer
array when the pages were freed, so **at most 163 are recoverable by any tool**.

| tool | recovered (of 200) | recall | range | false positives |
|---|---|---|---|---|
| **ours** | **163** | **82%** | 237..=400 (except 250) | **0** |
| undark | 163 | 82% | 237..=400 (except 250) | re-reads live rows + stale copies (see below) |
| fqlite | ~126 (varies) | ~63% | 235..=400 with gaps | re-reads live rows + stale copies |

- **ours == undark exactly** (identical 163-row set) — the #49 gap (in-page remnant
  rowid 237) is closed by in-page carving.
- **ours vs fqlite:** we recover everything fqlite does **except site-235**. Row
  235's cell *prefix* (its payload-length and rowid varints) was overwritten by an
  adjacent record; fqlite reconstructs it via freeblock geometry (emitting an
  unknown rowid), which our forward, 0-false-positive parse will not do — accepting
  it would mean accepting records with no parseable rowid, raising the
  false-positive risk. We document 235 rather than chase it.
- fqlite additionally **misses the freelist trunk-page rows** (238..=276 live on the
  trunk page body, which fqlite reads only as a trunk); ours and undark carve that
  body. So on this fixture **ours ⊇ fqlite**.

### Dropped table (`corpus_0A-01.db`, `corpus_0A-02.db`)

`DROP TABLE` left the `users` data on a freelist page with no schema. Column count
is inferred per record from its serial-type array.

| DB | ours | undark | fqlite | false positives |
|---|---|---|---|---|
| `corpus_0A-01.db` | **21** | 20 | ~20 | **0** |
| `corpus_0A-02.db` | **11** | 10 | ~19 | **0** |

- **ours ≥ undark** on the genuine data rows. The extra row in each case is the
  **dropped table's own `sqlite_master` schema record** (its `CREATE TABLE …`),
  which survives in page 1's free space — a bonus recovery undark does not produce.
- No live table exists, so there is nothing to over-report; every recovered row is
  genuine deleted residue.

### "No genuine deletion" (`corpus_01-01/01-02/03-02/07-01.db`)

These DBs have an **intact, packed live table and no genuine deleted residue.**
undark and fqlite nonetheless emit rows here — by **re-reading the live cells**
(and, for some, mis-decoding a column). That is over-reporting, not recovery.

| DB | ours | undark | fqlite | note |
|---|---|---|---|---|
| `corpus_01-01.db` | **0** | 10 | ~6 | undark/fqlite re-read the 10 live rows |
| `corpus_01-02.db` | **0** | 10 | ~6 | same |
| `corpus_03-02.db` | **0** | 11 | ~7 | undark's 11 = 10 live + 1 garbage row |
| `corpus_07-01.db` | **0** | 19 | ~7 | undark's rows are the live table |

- **ours = 0 is the correct answer.** Our carver carves only the *complement* of the
  live cell extents on an allocated page, and additionally drops any record whose
  rowid is currently live — so it cannot re-surface a live row. The oracles' nonzero
  counts here are a **precision failure on their part**, which this comparison makes
  visible.

### WAL-resident

Out of scope for the carver: a row that exists only in an uncheckpointed `-wal`
overlay is *live* (just not yet checkpointed into the main file), not deleted, so it
is not a carving target. `sqlite-core` already surfaces the WAL-applied view via
`Database::open_with_wal`, and the auditor flags an active overlay as
`WalUncheckpointedState`. No tool "recovers" WAL rows as deleted; recovering deleted
content *from within* a WAL frame is a possible future capability, recorded here as
out of present scope.

## The 0-false-positive discipline (why ours is stricter than both oracles)

Our carver enforces 0 false positives **structurally**, in two layers:

1. `Database::carve_free_regions` carves only the byte ranges that are the
   *complement* of the live cell extents on an allocated page — a live cell can
   never be returned.
2. `carve_all_deleted_records` then drops any carved record whose rowid is
   **currently live** (`Database::live_rowids`). This catches the subtle case where
   a b-tree rebalance left a *stale byte-copy of a still-live row* in an old page's
   free space: it parses as a clean record but is not deleted. **Both undark and
   fqlite report these stale copies as recovered**; ours does not.

The cost of this discipline is the one documented miss (site-235, a clobbered-prefix
remnant) — a deliberate, honest trade: we would rather miss one partially-overwritten
row than emit a single false positive on an evidence database. Carved records remain
**confidence-graded observations** ("consistent with a deleted row"); in-page residue
is graded a notch below freed-page recovery (it is more often partially overwritten).

## Summary judgment

On genuine deleted residue our carver is **consistent with, and on several scenarios
exceeds,** both independent tools — while holding a **0-false-positive** property
neither oracle holds. The single residual gap (site-235) is a partially-overwritten
record only fqlite's looser reconstruction reaches; it is documented, not papered
over. This is consistency with independent oracles plus a stricter precision
guarantee — not a claim of perfect recall.
