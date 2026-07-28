# 9. Batteries-included, capable-by-default decode and enrichment

Date: 2026-07-24
Status: Accepted

## Context

An examiner staring at an opaque recovered SQLite BLOB must get "binary plist →
{…}" / "PNG · 42 KB" from the zero-config path, not a rebuild with a feature flag
they had to know to enable. The fleet Batteries-Included rule
(`~/src/ronin-issen/CLAUDE.md`) makes decode/enrichment capability always-on in
the analysis layer, never behind a Cargo feature — a capability that is not
compiled in is not there when it matters on an evidence workstation.

## Decision

The analysis layer hard-depends on its decode/enrichment stack, always on:

- **BLOB decoding** — the CLI hard-deps `blob-decoder = "0.1"` (`cli/Cargo.toml`)
  and chains it after the built-in interpreters so a recovered binary-plist / gzip
  / JSON / base64 value is decoded in `-f jsonl` output (commits `90b99cf`→
  `a81acd8`, the four-step `BlobInterpreter` seam). A narrow WebKit/Chrome
  `.localstorage` UTF-16-LE interpreter is built in (`core/src/lib.rs`, commit
  `f21cf49`) as a known-artifact convenience alongside — not instead of — the
  general decoder.
- **Content addressing** — every carved BLOB carries a SHA-256 content hash via
  the audited `sha2` crate (`Cargo.toml` `[workspace.dependencies] sha2`, never
  hand-rolled), plus a magic-signature `media_type` when recognized (commits
  `6d304ef`→`902c523`).
- **CASE/UCO export** — `-f case` emits a JSON-LD bundle where each recovered BLOB
  is a `uco-observable:ObservableObject` (`forensic/src/case_uco.rs`, commit
  `471749c`) for case-management interop.
- **Encryption/checksum naming** — the reserved-space anomaly names the likely
  scheme from the header (SQLCipher / SEE / checksum VFS) with the raw value,
  detection-only (commit `d7dd22c`; README anomaly `SQLITE-RESERVED-SPACE-NONZERO`).

## Consequences

- The default `carve`/`audit` path enriches recovered evidence with no flags; the
  decode stack is a compiled-in capability of every shipped binary.
- Decode output stays honest: an `interpreted` object carries `lossy` /
  `confidence` and sits *alongside* the raw base64 so the original bytes still
  round-trip (README "What you get").
- Decryption of a keyed database is now in scope — see ADR 0010: given a key,
  `Database::open_encrypted` decrypts SQLCipher pages into the plaintext stream the
  reader consumes. The reserved-space *naming* here stays the detection front door.
