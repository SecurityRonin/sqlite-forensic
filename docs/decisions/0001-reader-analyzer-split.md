# 1. Reader/analyzer split — `sqlite-core` reader + `sqlite-forensic` analyzer

Date: 2026-07-24
Status: Accepted

## Context

A SQLite database is evidence, and two jobs pull the code in opposite directions.
One job is to read the file format correctly and robustly — the 100-byte header,
b-tree pages, overflow chains, the freelist. The other is to *audit* the file:
grade forensically-notable observations and recover the deleted rows a normal
reader deliberately hides. A reader is built to read *valid* data and normalize
away exactly the byte-level detail (slack, freeblocks, malformed records) that a
forensic auditor must see.

The fleet's crate-structure standard (`~/src/ronin-issen/CLAUDE.md`, "Crate-structure
standard — reader/analyzer split") makes this split binding for every format: one
workspace `<x>-forensic` with a `core/` reader crate and a `forensic/` analyzer
crate. `ntfs-forensic` is the reference implementation.

## Decision

Ship one Cargo workspace with two library members plus a CLI
(`Cargo.toml` members = `["core", "forensic", "cli"]`):

- **`sqlite-core`** (`core/`) — the raw, read-only file-format reader:
  `Database::open`, b-tree walk, `freelist_pages`, overflow-chain reassembly, a
  read-only WAL overlay, a rollback-journal parser, and a pure-Rust `rebuild`
  writer. It emits no findings (`core/src/lib.rs` module docs).
- **`sqlite-forensic`** (`forensic/`) — the anomaly auditor + deleted-record
  carver: grades observations into `forensicnomicon::report::Finding` and carves
  deleted rows. It depends on `sqlite-core` (`forensic/Cargo.toml` →
  `sqlite-core = { workspace = true }`).

`sqlite-forensic` accepts an in-memory `Database` built from `&[u8]`, so it is
medium-agnostic and imports no container/filesystem layer (README "Drive the
library directly").

## Consequences

- The reader is reusable by third parties as a plain SQLite parser; the analyzer
  earns its keep as the forensic differentiator.
- The analyzer currently consumes the reader's public API. Where a future audit
  needs byte-level structure the happy-path reader normalizes away, the standard
  permits `sqlite-forensic` to parse lower-level structure directly rather than
  contort the audit through the reader — the split does not forbid it.
- Both crates publish independently to crates.io via release-plz, versioned in
  lockstep through `[workspace.package]`.
