# sqlite-forensic — Product Requirements (`sqlite4n6`)

*A reverse-written intent document. Every current-state claim below is grounded in
a same-session read of the repo (`README.md`, the member `Cargo.toml`s, and the
`core/`, `forensic/`, and `cli/` sources, 2026-07-24); the load-bearing decisions
live as ADRs [0001](decisions/0001-reader-analyzer-split.md)–[0009](decisions/0009-batteries-included-decode.md)
under [`docs/decisions/`](decisions/). Empirical claims (precision/recall figures,
SFT-03 counts) are reproduced from the committed test harness and
[`docs/validation.md`](validation.md) / [`docs/recovery-comparison.md`](recovery-comparison.md),
not re-measured here.*

## Executive Summary

**The deleted rows are the evidence — and `sqlite3` can't see them.** `sqlite4n6`
is a read-only SQLite forensic CLI that carves deleted and superseded records back
out of any SQLite database — browser history, chat apps, mobile artifacts — and
grades forensically-notable anomalies into severity-ranked findings. The zero-config
path (`sqlite4n6 carve History.db`) writes a review-ready `History.recovered.xlsx`
workbook: each table as a per-rowid **version history**, live rows interleaved with
the prior (changed) and deleted versions recovered from the uncheckpointed WAL, the
rollback journal, and free space.

Four properties define the product:

1. **Read-only by construction.** The evidence file and its `-wal`/`-shm`/`-journal`
   sidecars are never written; every output is a separate new file, guarded so it
   can never resolve to the evidence db or a sidecar ([ADR 0006](decisions/0006-default-xlsx-workbook-and-rebuild-writer.md)).
2. **Precision over recall, enforced structurally** — carve only the complement of
   the live cell extents, then drop any carved record whose rowid is live, so a
   live row is never re-surfaced as "deleted" ([ADR 0005](decisions/0005-precision-first-carving.md)).
3. **Full temporal recovery** — the WAL's after-images (per-commit timeline) and
   the rollback journal's before-images, the two halves of the deleted-row
   evidence the live engine hides ([ADR 0007](decisions/0007-wal-and-rollback-journal-temporal-recovery.md)).
4. **Safe to run on evidence** — `forbid(unsafe)`, panic-free by lint, fuzzed, and
   measured against independent third-party ground truth ([ADR 0003](decisions/0003-unsafe-panic-free-posture.md)).

## Problem & Users

The live `sqlite3`/rusqlite path reads the live b-tree and stops: it cannot see
freelist pages, in-page free blocks, dropped-table pages, an uncheckpointed WAL
overlay, or a rollback journal — exactly where deleted-row evidence survives. A
forensic analyst needs those rows back, attributed to their source table, with
enough provenance and honesty to stand up under review.

Primary users:

- **DFIR / forensic analysts** examining browser, messaging, and mobile-app SQLite
  artifacts who need deleted and prior-version rows, not just the live table.
- **Examiners preparing evidence** who need recovered rows framed as observations
  ("consistent with a deleted row"), with provenance columns and a confidence
  grade, never as verdicts.
- **Python-first DFIR workflows** — thin pyo3 bindings expose `carve` / `audit` /
  `timeline` over a database path (`python/`).

## What It Does

- **`carve <db>`** — recovers deleted/superseded records and writes, by default,
  the combined per-rowid version-history workbook `<stem>.recovered.xlsx` (image
  BLOBs as in-cell thumbnails). `-f {db,jsonl,csv,table,case}` selects one
  alternate output; `-o <FILE>` sets an exact path; `-o -` streams to stdout.
  Recovery sources: freelist pages, in-page free blocks, dropped-table pages,
  freeblock-clobbered cells (reconstructed from the surviving serial-type tail),
  intact overflow-page chains, the uncheckpointed WAL, and the rollback journal.
- **`audit <db>`** — grades header, freelist, WAL, page-count, encryption/checksum,
  and rollback-journal observations into severity-ranked
  `forensicnomicon::report::Finding`s under stable, scheme-prefixed `SQLITE-*`
  codes (README "Anomaly codes").
- **Attribution in three honest tiers** — CERTAIN (`recovered_<table>`, page still
  part of a live b-tree), INFERRED (`recovered_inferred`, shape-matched against
  surviving tables), UNKNOWN (`recovered_unattributed`); Tier-2 fragments stay in
  their own set, never merged with full rows ([ADR 0005](decisions/0005-precision-first-carving.md)).
- **Enrichment, always on** — SHA-256 hash + media-type for every recovered BLOB,
  decode of encoded values (plist/gzip/JSON/UTF-16), CASE/UCO export
  ([ADR 0009](decisions/0009-batteries-included-decode.md)).

## Architecture

One workspace, the fleet reader/analyzer split plus the CLI ([ADR 0001](decisions/0001-reader-analyzer-split.md),
[ADR 0002](decisions/0002-crate-naming-sqlite-collision.md)):

| Crate | Role |
|---|---|
| `sqlite-core` (lib `sqlite_core`) | Raw, read-only, panic-free-by-lint file-format reader: header parse, b-tree walk, freelist + overflow chains, read-only WAL overlay, rollback-journal parser, and a pure-Rust `rebuild` writer. |
| `sqlite-forensic` | Anomaly auditor + deleted-record carver; grades observations into `forensicnomicon::report::Finding` and satisfies the fleet `forensic-carve::Carver` contract. Depends on `sqlite-core`. |
| `sqlite4n6` | The read-only CLI (Humble-Object shell: parse args, read bytes, drive the libraries, emit one output). |
| `sqlite4n6-py` | pyo3 bindings, a standalone workspace outside `forbid(unsafe)`, `publish = false`. |

Format constants and the report vocabulary come from the `forensicnomicon`
KNOWLEDGE leaf ([ADR 0004](decisions/0004-forensicnomicon-knowledge-leaf.md)); the
WAL temporal model maps onto `forensicnomicon::history`.

## Scope

- Read-only recovery from a SQLite database file and its `-wal` / `-journal`
  sidecars: live rows (incl. WITHOUT ROWID via the index b-tree), deleted and
  superseded rows, dropped-table rows and schema, the full per-commit WAL timeline,
  and the rollback journal's last-transaction deletes and edits.
- Graded anomaly findings, three-tier attribution, BLOB typing/hashing/decoding,
  and CASE/UCO export.
- Single static binary distributed via Homebrew / apt (Cloudsmith) / winget, plus
  crates.io libraries and a Python wheel.

## Non-Goals

- **No writes to the evidence.** The tool never modifies the database or its
  sidecars; all output is separate new files ([ADR 0006](decisions/0006-default-xlsx-workbook-and-rebuild-writer.md)).
- **No decryption.** Encrypted databases (SQLCipher / SEE) are detected and named
  from the header, but decryption needs the key/VFS and is out of scope
  ([ADR 0009](decisions/0009-batteries-included-decode.md)).
- **No same-schema drop+recreate claim.** Undecidable from a single snapshot or a
  sidecar (indistinguishable from a benign `VACUUM` page move); `table_instance_risk`
  flags only `AUTOINCREMENT` rowid-overflow and unambiguous sidecar schema changes.
- **No recovery from DELETE-mode (unlinked) or TRUNCATE-mode (zeroed) rollback
  journals** — no in-band residue survives; that is a disk-carving-layer concern.
- **No full overflow-chain recovery** — reassembly is bounded to chains whose every
  page survives as a freelist leaf, graded below the in-page tier.
- **Precision over recall** — the tool refuses to over-report; a documented in-page
  recall gap is accepted rather than manufacture phantom rows.

## Artifact Family

Any SQLite database (`SQLite format 3\0`): browser history/cache, messaging app
stores (`ChatStorage.sqlite`), mobile-app artifacts, OS artifact stores, WebKit
Local Storage `ItemTable`, and their `-wal`/`-shm`/`-journal` sidecars.

## Validation Approach

Correctness is proven against independent third-party ground truth, not only
self-authored fixtures (README "Validated against real cases";
[`docs/validation.md`](validation.md), [`docs/recovery-comparison.md`](recovery-comparison.md)):

- **Nemetz *SQLite Forensic Corpus*** (141 databases, DFRWS-EU 2018, CC0) — scored
  per-row against the authors' answer key; highest precision in the comparison,
  0 live-row re-reads (`forensic/tests/nemetz_metrics.rs`).
- **NIST CFReDS *Data Leakage Case*** — the Google Drive `snapshot.db` carved from
  a Volume Shadow Copy, both documented deleted `cloud_entry` files recovered
  (`forensic/tests/nist_dlc_snapshot.rs`).
- **NIST CFReDS / CFTT SFT-03 PERSIST** — 100/100 documented deletions and 100/100
  modifications recovered.
- **`sqlite-unhide`** (nine author-keyed databases) — surfaced and fixed two real
  defects our own fixtures could not.
- **Josh Hickman iOS-17** real-device databases — a no-panic robustness sweep.
- **Cross-checked** against `undark`, `fqlite`, and the live `sqlite3` engine as
  independent oracles; the rebuild writer's output is re-read by both the crate's
  own reader and the real `sqlite3` engine.
- **Fuzzed** — libFuzzer targets over `database_open`, `carve`, `audit`, and
  `render` ([ADR 0003](decisions/0003-unsafe-panic-free-posture.md)).

Every figure is reproducible from the committed harness; recovered rows stay
observations, never verdicts.
