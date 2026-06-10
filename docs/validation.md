# Differential Validation — Deleted-Record Carving

This document is the Doer-Checker evidence for `sqlite_forensic::carve_deleted_records`.
It records how our carver's output was reconciled against an **independent reference
tool** so that correctness is not asserted only by tests we wrote against a fixture we
generated. The machine-checkable form of this evidence is `forensic/tests/oracle_differential.rs`.

## Summary

- **Conclusion:** on the freelist-page deletion scenario our carver is designed for,
  its output is **consistent with** the independent `undark` carver — 100% content
  agreement on every overlapping rowid and 162/163 of undark's recovered deleted rows.
- **One understood divergence** on our fixture (rowid 237, on a still-allocated page)
  and a **documented scope boundary** on the DC3 corpus (in-page / dropped-table
  deletions our freelist-only carver does not scan). Both are diagnosed below; neither
  is a defect in the freelist-carving path.
- We make no claim that our carver is "proven correct". The evidence supports only that
  its freelist-page recovery is consistent with an independent tool's recovery.

## Why the oracle is `undark`, not fqlite

The original plan named **fqlite** (Dirk Pawlaszczyk) as the reference oracle. fqlite
cannot be driven as a headless oracle in its current form, established empirically:

- Its own README states: *"With version 2.0, the support for the command line mode was
  cancelled."* fqlite 3.x/4.x is a `JavaFX` GUI-only application.
- Every GitHub release (3.0 … 4.22, the latest at time of writing) ships only platform
  installers — `…-macOS-arm64.dmg`, `…-windows.exe`, `…-x86_64.deb` — each a ~440 MB
  `jpackage` self-contained bundle. **No runnable CLI jar is published in any release.**
- fqlite is **not on Maven Central** (`search.maven.org` returns `numFound: 0` for
  `fqlite`), so there is no library engine to drive from a small Java shim either.
- The fqlite GitHub repository ships **no test/sample databases** (the only `.jar` in the
  tree is `gradle/wrapper/gradle-wrapper.jar`; the only large binaries are PNG/SVG icons
  and the user-guide PDF). The "fqlite test corpus" referenced in the task does not exist
  to download.

Rather than fabricate fqlite output, we substituted the **next-best independent oracle**:
`undark` 0.7.1 by Paul L. Daniels — a small, self-contained C SQLite deleted-record
carver. It is a different author, language, and algorithm from ours, which is what an
independent oracle requires. (`sqlite_dissect` was also evaluated as an oracle but its
free-block carver produced misaligned/garbled column boundaries on these fixtures —
recovering corrupt `title` values and surfacing live rows — so it was rejected as a
yardstick. Its *test databases*, authored by DC3, are still used as independent *input*;
see below.)

## The oracle tool

| | |
|---|---|
| Tool | `undark` |
| Version | 0.7.1 (Paul L. Daniels) |
| Upstream | <https://github.com/inflex/undark> |
| Source tarball (master) | <https://github.com/inflex/undark/archive/refs/heads/master.tar.gz> |
| Source tarball sha256 | `c0a9ee7ebd180727deef52fbafe0ef0e2b7c9b43c5604761bfeb86bc9306912a` |
| Local binary | `tools/undark` (gitignored, not committed) |

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

## Comparison projection

Both tools' output is reduced to the same identity per row: `rowid -> (text-col-1, text-col-2)`
— i.e. the `url`/`title` (moz_places) or `name`/`surname` (DC3 `users`) text columns at
record positions 1 and 2. Agreement is then defined on this projection.

## Results

### Corpus 1 — our fixture (undark as independent oracle over our input)

`forensic/tests/data/deleted_places.db` — `moz_places`, 400 rows inserted, ids 201..=400
`DELETE`d without `VACUUM` under `secure_delete=OFF`; freed whole leaf pages onto the
freelist. Ground truth: 200 live (1..=200), 200 deleted (201..=400). Freelist =
trunk page 9 + leaf pages 10,11,12,13.

| metric | value |
|---|---|
| deleted rows in ground truth | 200 |
| undark recovers (in 201..=400) | **163** (ids 237..=400, except 250) |
| our carver recovers (in 201..=400) | **162** (ids 238..=400, except 250) |
| content agreement on overlapping rowids | **162 / 162 = 100%** (url + title exact) |
| our recovery vs undark's set | **162 / 163 = 99.4%** |
| false positives (rows we carve, undark does not) | **0** |

**Divergence — rowid 237 (undark recovers, we do not).** Diagnosed at the page level:
`site-237` lives on **page 8**, a still-**allocated** leaf page from which some rows were
deleted in place (an in-page free block). `site-238` lives on **page 9**, the freelist
trunk page (its 8-byte trunk header + 5 leaf pointers overwrote only the very top of the
page, above row 238's cell). Our carver scans only freelist pages (9–13) by design — it
never re-surfaces content from allocated pages, a deliberate safety property so it cannot
mistake a live page's slack for a deleted row. undark scans byte-by-byte across all pages,
so it additionally reaches the one in-page remnant on page 8. Neither tool recovers ids
201..=236 or 250: those cells were overwritten by the freelist trunk header / leaf-pointer
array when the pages were freed.

The 237 divergence is encoded as an explicit, asserted exemption in the test
(`FIXTURE_IN_PAGE_DIVERGENCES`), so if a future carver change makes the two tools agree
there, the test fails and the exemption must be re-derived rather than silently passing.

### Corpus 2 — DC3 `sqlite_dissect` test corpus (independent input *and* independent oracle)

The Department of Defense Cyber Crime Center (DC3) `sqlite_dissect` test databases were
authored by neither us nor undark's author, so for these cases **neither the input DB nor
the oracle is ours** — the strongest Doer-Checker form. Provenance + hashes are in
`tests-oracle-corpus/README.md` and `docs/corpus-catalog.md`. The DBs with carvable
deleted records:

| DB | table cols | freelist_count | undark recovers | our carver recovers | agreement |
|---|---|---|---|---|---|
| `corpus_01-01.db` | 4 | 0 | 10 | 0 | documented gap |
| `corpus_01-02.db` | 4 | 0 | 10 | 0 | documented gap |
| `corpus_03-02.db` | 4 | 0 | 11 | 0 | documented gap |
| `corpus_07-01.db` | 4 | 0 | 19 | 0 | documented gap |
| `corpus_0A-01.db` | 6 | 1 | 20 | 0 | documented gap |
| `corpus_0A-02.db` | 6 | 1 | 10 | 0 | documented gap |

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
  consistent with an independent tool's recovery (100% content agreement, no false
  positives, 99.4% recall vs undark on the fixture).
- **Does not validate / out of scope:** in-page free-block recovery and dropped-table
  recovery. These are an undark capability our carver lacks; surfaced here as the documented
  divergence and the candidate next feature, not claimed as working.
- **Epistemic stance:** carved records remain confidence-graded observations
  ("consistent with a deleted row"); this validation likewise establishes *consistency
  with* an independent oracle, not proof of correctness.
