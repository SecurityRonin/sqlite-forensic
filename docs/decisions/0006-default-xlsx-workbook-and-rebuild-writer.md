# 6. Default output = per-rowid version-history XLSX workbook; pure-Rust rebuild writer

Date: 2026-07-24
Status: Accepted

## Context

An examiner wants a review-ready view in seconds, not a schema to reconstruct by
hand. Raw carved records in a stream are hard to read; a queryable database is
useful for scripting but not for a first pass. The tool ships a single static
binary an analyst runs, so the zero-config path must produce the most useful
artifact for the common case (Design-for-the-human / Secure-by-default, fleet
constitution).

## Decision

- **`carve`'s default output is a combined review workbook**
  `<stem>.recovered.xlsx` (`cli/src/main.rs` module docs; `combined_xlsx_bytes`).
  The source database is dumped one sheet per live table, and each sheet is that
  table's **per-rowid version history** — live rows interleaved with the prior
  (changed) and deleted versions recovered from the uncheckpointed WAL, the
  rollback journal, and free space, ordered by `commit_seq` and tinted by state.
  Image BLOBs render as in-cell thumbnails. The XLSX and image codecs are pure
  Rust (`cli/Cargo.toml`: `rust_xlsxwriter`, `image` with
  `default-features = false` + the detected codecs), preserving the single
  static-binary / no-C-deps property.
- **`-f {db,jsonl,csv,table,case}`** each pick one alternate output; one output
  per run. `-f db` writes `<stem>.carved.db` via a **pure-Rust `rebuild` writer**
  (`core/src/rebuild.rs` `build_recovered_db*`) that bulk-loads the carved rows
  into a fresh SQLite file, each cell in its **native** storage class so a
  recovered BLOB is byte-preserved and large cells spill onto overflow chains.
- **Read-only-safe reconstruction.** Every output is a *separate, new* file,
  guarded so it can never resolve to the evidence db or a `-wal`/`-shm`/`-journal`
  sidecar (`cli/src/main.rs` module docs); `-o <FILE>` overrides the path,
  `-o -` streams. The evidence bytes are owned by the `Database` and never
  flushed back.

## Consequences

- The zero-config `sqlite4n6 carve <db>` yields a spreadsheet an analyst can open
  immediately; power users reach for `-f db`/`-f jsonl` when they need a queryable
  store or a pipe.
- The rebuild writer has two independent oracles (`core/src/rebuild.rs` docs): the
  output re-opens with the crate's own reader *and* is read identically by the
  real `sqlite3` engine — so a rebuild bug surfaces against an external tool, not
  only self-consistency.
- Blob fidelity differs by format and is documented (`db`/`jsonl` lossless; `csv`/
  `table` show a `<blob:N bytes>` placeholder) so an examiner never silently loses
  recovered image content.
