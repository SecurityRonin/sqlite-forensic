# Differential Validation — Deleted-Record Carving

This document is the Doer-Checker evidence for `sqlite_forensic`'s deleted-record
carving. It records how our carver's output was reconciled against an **independent
reference tool** so that correctness is not asserted only by tests we wrote against a
fixture we generated. The machine-checkable form of this evidence is
`forensic/tests/oracle_differential.rs`.

> **This document is the historical *differential* record; the current capability
> matrix lives in [`recovery-comparison.md`](recovery-comparison.md).** The page-level
> findings below remain accurate as the record of how each tool draws the
> freelist/allocated boundary, but several carver *scope boundaries* they describe are
> now closed — so read the per-scenario **numbers and the "Summary" section below as
> the pre-fix snapshot** and defer to `recovery-comparison.md` for current numbers:
>
> - `carve_all_deleted_records` added **in-page free-block carving** and
>   **dropped-table carving**, so on the fixture it recovers the in-page remnant
>   (rowid 237) and **exactly matches undark**, and it recovers the DC3 dropped-table
>   rows. Where this doc says "our freelist-only carver recovers none" of those cases,
>   that is the *pre-fix* state.
> - It then added **value-aware prior-version recovery**: an `UPDATE`'s freed old
>   version (same rowid, *different* values) is recovered (tagged `PriorVersion`), not
>   dropped. The differential test (`oracle_differential.rs`) asserts agreement now,
>   plus a prior-version reconciliation, rather than the former exemptions.
>
> The Summary's "consistent with / agree exactly" statements describe the
> **freelist-page differential** specifically and still hold for that scenario; they
> are not the whole-corpus capability claim — for that, see `recovery-comparison.md`.

## Summary

- **Conclusion:** on the freelist-page deletion scenario our carver is designed for,
  its output is **consistent with** TWO independent reference carvers — `undark` (C)
  and `fqlite` (Java) — with **100% content agreement on every overlapping row** and no
  false positives. Where all three tools overlap on our fixture, they agree exactly.
- **Two independent oracles, two corpora.** `undark` and a headless source-instrumented
  tap of `fqlite`'s recovery engine are both used as oracles; our `deleted_places.db`
  fixture and the third-party DC3 `sqlite_dissect` corpus are both used as input.
- **Divergences are diagnosed at the page level, not papered over.** Each tool draws the
  freelist-vs-allocated and trunk-vs-leaf boundaries slightly differently; every
  ours-vs-oracle difference is explained by *which page* a row lives on and *which pages
  each tool scans*. None is a defect in our freelist-carving path.
- We make no claim that our carver is "proven correct". The evidence supports only that
  its freelist-page recovery is **consistent with** two independent tools' recovery.

## The two oracles

### Oracle 1 — `undark` (C)

| | |
|---|---|
| Tool | `undark` |
| Version | 0.7.1 (Paul L. Daniels) |
| Upstream | <https://github.com/inflex/undark> |
| Source tarball (master) | <https://github.com/inflex/undark/archive/refs/heads/master.tar.gz> |
| Source tarball sha256 | `c0a9ee7ebd180727deef52fbafe0ef0e2b7c9b43c5604761bfeb86bc9306912a` |
| Local binary | `tools/undark` (gitignored, not committed) |
| Test gate | `UNDARK_BIN` |

### Oracle 2 — `fqlite` (Java), via a headless source-instrumentation tap

fqlite was the originally-named oracle. Its command-line mode was removed in v2.0
(README: *"With version 2.0, the support for the command line mode was cancelled"*),
releases ship only ~440 MB `JavaFX` `jpackage` installers (no runnable CLI jar), it is
**not on Maven Central**, and its repo ships no test databases. So it cannot be used as
a packaged CLI oracle.

**But fqlite IS usable as an oracle via source instrumentation** — the CLI cancellation
was the only blocker, not the engine. fqlite's carving engine (`fqlite.base.Job`) is
plain Java that populates a result list the GUI merely reads. A small headless tap
(`tools/fqlite/HeadlessTap.java`) constructs `Job`, runs `Job.run(path)`, and emits the
recovered DELETED records as CSV — never launching the JavaFX UI. The engine is not
cleanly decoupled from JavaFX in the current source (its logger's static init builds a
JavaFX `TextArea`, `processDB()` posts a `Platform.runLater` cleanup fence and calls
`gui.add_table` unguarded), so the tap (a) null-guards those `add_table` calls, (b) sets
`GUI.baseDir`, and (c) boots the JavaFX *toolkit* headlessly (no window). The full engine
API map, the JavaFX-coupling findings, and the minimal changes a clean
`fqlite.base.MAIN` revival would need are in `tools/fqlite/ENGINE_NOTES.md`.

| | |
|---|---|
| Tool | `fqlite` (recovery engine) |
| Version | 4.22 |
| Commit | `26922bd9e3cdc60c93b72dfb1fb2f5972a0af6a6` |
| Upstream | <https://github.com/pawlaszczyk/fqlite> |
| Driver | `tools/fqlite/HeadlessTap.java` + `run-tap.sh` (gitignored; recipe in `tools/fqlite/README.md`) |
| Test gate | `FQLITE_TAP` |

(`sqlite_dissect` was also evaluated as an oracle but its free-block carver produced
misaligned/garbled column boundaries on these fixtures — recovering corrupt `title`
values and surfacing live rows — so it was rejected as a yardstick. Its *test databases*,
authored by DC3, are still used as independent *input*; see below.)

### `undark` build recipe (macOS / clang)

### Build recipe (macOS / clang)

Upstream undark uses two GCC nested-function definitions and a function named `ntohll`
that collides with the macOS `<sys/_endian.h>` `ntohll` macro, so it does not compile
with clang out of the box. Two minimal, behavior-preserving patches make it build:

1. Hoist the nested `swap64` / `ntohll` helpers out of `decode_row` to file scope.
2. Rename undark's `ntohll` to `u_ntohll` to avoid the macOS macro collision.

```sh
curl -sL https://github.com/inflex/undark/archive/refs/heads/master.tar.gz | tar xz
cd undark-master
# patch 1+2 (see tools/undark.c.patched for the exact patched source)
make                     # produces ./undark
./undark -V              # => undark version 0.7.1, by Paul L Daniels
```

The exact patched source is kept at `tools/undark.c.patched` (gitignored) for
reproducibility.

### CLI invocation

undark dumps every record it can reconstruct (live + recovered-deleted) to stdout as CSV,
one record per line: `rowid,id,col1,col2,…`. The command used by the test is simply:

```sh
undark -i <database.db>
```

Deleted rows are identified by rowid: any recovered rowid that is **not** present in the
live b-tree (read via `sqlite3`) is a recovered-deleted record. (`--freespace` scans free
*blocks within allocated pages*; it returns nothing on these fixtures because the deleted
content there is on freed whole pages, not in allocated-page free blocks.)

### `fqlite` tap invocation

```sh
FQLITE_TAP=tools/fqlite/run-tap.sh
"$FQLITE_TAP" <database.db>   # -> CSV: rowid,col1,col2,...  (recovered DELETED rows)
```

fqlite often cannot recover a carved row's rowid (emits `-1`), so the fqlite comparison
is keyed by the row's text content (url), not rowid. Build recipe in
`tools/fqlite/README.md`; engine API map in `tools/fqlite/ENGINE_NOTES.md`.

## Comparison projection

Each tool's output is reduced to the same identity per row: the `url`/`title`
(moz_places) or `name`/`surname` (DC3 `users`) text columns at record positions 1 and 2.
The undark comparison keys by rowid; the fqlite comparison keys by url (fqlite does not
always recover the rowid). Agreement is defined on this projection.

## Results

### Corpus 1 — our fixture (undark AND fqlite as oracles over our input)

`forensic/tests/data/deleted_places.db` — `moz_places`, 400 rows inserted, ids 201..=400
`DELETE`d without `VACUUM` under `secure_delete=OFF`; freed whole leaf pages onto the
freelist. Ground truth: 200 live (1..=200), 200 deleted (201..=400). Freelist =
trunk page 9 + leaf pages 10,11,12,13.

Three-way recovery over the deleted range (ids 201..=400):

| tool | recovers | which rows |
|---|---|---|
| our carver | **162** | 238..=400 (except 250) |
| undark | **163** | 237..=400 (except 250) |
| fqlite | **126** | 235, 237, and 277..=400 (except none) |

Agreement:

| comparison | result |
|---|---|
| content agreement (url + title) on every overlapping row | **100%, 0 mismatches** (all three tools) |
| our false positives (rows we carve no oracle corroborates) | **0** |
| ours vs undark | ours ⊇ undark minus 1 row (237); **162/163 = 99.4%** |
| ours vs fqlite | ours adds 238..=276; fqlite adds 235, 237 — all explained below |

**Why the three tools draw the freelist boundary differently — page-level diagnosis:**

- **Rows 277..=400 live on freelist *leaf* pages 10–13.** All three tools carve these. ✓
- **Rows 238..=276 live on page 9, the freelist *trunk* page.** Our carver and undark
  scan the trunk page body (below its small 8-byte trunk header + leaf-pointer array) and
  recover them. **fqlite reads page 9 only as a trunk** (next-pointer + leaf-pointer
  array) and does **not** carve record content from its body — so fqlite misses 238..=276.
  This is a genuine fqlite-specific behaviour, not a defect in either carver.
- **Rows 235, 237 live on page 8, a still-*allocated* leaf page** (in-page free blocks
  from rows deleted in place). undark (byte-by-byte) and fqlite (in-page free-block carver)
  reach them; our carver scans only freelist pages by design, so it skips them — the same
  safety property (never re-surface content from an allocated page) seen in the DC3 corpus.
- **Rows 201..=236 and 250** are recovered by no tool: their cells were overwritten by the
  freelist trunk header / leaf-pointer array when the pages were freed.

Both divergence sets are encoded as explicit, asserted exemptions in the test
(`FIXTURE_IN_PAGE_DIVERGENCES` / `FQLITE_IN_PAGE_DIVERGENCES` for the allocated-page rows;
`FQLITE_TRUNK_PAGE_DIVERGENCES` for the trunk-page rows). Each is asserted to be a *real*
disagreement, so a future carver change that closes a gap fails the test and forces the
exemption to be re-derived rather than silently passing.

### Corpus 2 — DC3 `sqlite_dissect` test corpus (independent input *and* independent oracle)

The Department of Defense Cyber Crime Center (DC3) `sqlite_dissect` test databases were
authored by neither us nor undark's author, so for these cases **neither the input DB nor
the oracle is ours** — the strongest Doer-Checker form. Provenance + hashes are in
`tests-oracle-corpus/README.md` and `docs/corpus-catalog.md`. The DBs with carvable
deleted records:

| DB | table cols | freelist_count | undark recovers | fqlite recovers | our carver recovers | agreement |
|---|---|---|---|---|---|---|
| `corpus_01-01.db` | 4 | 0 | 10 | 6 | 0 | documented gap |
| `corpus_01-02.db` | 4 | 0 | 10 | 6 | 0 | documented gap |
| `corpus_03-02.db` | 4 | 0 | 11 | 7 | 0 | documented gap |
| `corpus_07-01.db` | 4 | 0 | 19 | 7 | 0 | documented gap |
| `corpus_0A-01.db` | 6 | 1 | 20 | 20 | 0 | documented gap |
| `corpus_0A-02.db` | 6 | 1 | 10 | 19 | 0 | documented gap |

Both independent oracles (undark and fqlite) recover deleted rows from these in-page /
dropped-table DBs; our freelist-only carver recovers none — the same documented scope
boundary, now corroborated by two tools rather than one.

**Divergence — our carver recovers 0 from every DC3 case (documented scope boundary).**
This is the load-bearing independent finding. These DBs delete records **without freeing
whole pages onto the freelist** (`freelist_count = 0` for the in-page cases) or **drop a
table entirely** (`0A-01`/`0A-02` have no table in `sqlite_master`; the dropped table's
page went on the freelist). The deleted content therefore lives in **free blocks inside
still-allocated b-tree pages** or in **dropped-table pages**, neither of which our
freelist-page scan covers. undark, scanning byte-by-byte, recovers them.

We did **not** "fix" this by bolting on in-page free-block carving: that is a new
capability (a feature), not a bug in the freelist path, and adding it under a validation
task would exceed scope. It is recorded here honestly as the carver's current boundary and
asserted explicitly in the test (each DC3 case asserts our carver recovers **0** here — if
a future in-page carver lands, the assertion fires and forces a re-reconciliation against
undark rather than passing silently). On the cases where undark and ours overlap, content
agreement is required and holds (vacuously, since our set is empty); our carver produces
**no false positives** on any DC3 DB.

## What this validates, and what it does not

- **Validates:** the freelist-page carving path — the scenario our carver targets — is
  consistent with **two** independent tools' recovery (100% content agreement, no false
  positives; 99.4% recall vs undark, and full agreement vs fqlite outside the trunk-page
  rows fqlite structurally skips).
- **Does not validate / out of scope:** in-page free-block recovery and dropped-table
  recovery. Both undark and fqlite recover these; our carver does not — surfaced here as
  the documented divergence and the candidate next feature, not claimed as working.
- **Epistemic stance:** carved records remain confidence-graded observations
  ("consistent with a deleted row"); this validation likewise establishes *consistency
  with* two independent oracles, not proof of correctness.
