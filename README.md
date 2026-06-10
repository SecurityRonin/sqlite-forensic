[![Docs](https://img.shields.io/badge/docs-securityronin.github.io-blue.svg)](https://securityronin.github.io/sqlite-forensic/)
[![Rust edition 2021](https://img.shields.io/badge/rust-edition%202021-orange.svg)](https://doc.rust-lang.org/edition-guide/rust-2021/index.html)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](#trust-but-verify)
[![security: cargo-deny](https://img.shields.io/badge/security-cargo--deny-success.svg)](deny.toml)

# sqlite-forensic

**Carve deleted rows out of a SQLite database without trusting it, without writing to it, and without re-surfacing a single live row.**

> Measured against **independent third-party ground truth** — the SQLite Forensic Corpus (Nemetz, Schmitt & Freiling, DFRWS-EU 2018, CC0), whose authors shipped a per-row deleted answer key — and reported as a reproducible per-database confusion matrix ([`docs/recovery-comparison.md`](docs/recovery-comparison.md)). The honest headline: **precision is high** (it never re-surfaces a live row as "deleted", and emits only a small low-confidence phantom class), but **recall on in-page deletion is low** — about **24 % on the cleanest category** — because SQLite overwrites a freed cell's first four bytes (its header) with the freeblock pointer, which our forward parser cannot yet reconstruct. We report the true numbers, not the fixture-flattering ones.

Every browser history, every chat app, every mobile artifact is a SQLite file — and the forensically interesting rows are usually the *deleted* ones. The standard `sqlite3`/rusqlite path cannot see them: it reads the live b-tree and stops. `sqlite-forensic` reads the raw file format itself — freelist pages, in-page free blocks, dropped-table pages, and an uncheckpointed WAL overlay — and recovers what the live query cannot, as severity-graded, confidence-scored observations.

This is a Rust library workspace (two crates, no CLI yet). Point the analyzer at the file bytes and get graded findings plus carved deleted records:

```rust
use sqlite_core::Database;
use sqlite_forensic::{audit, carve_all_deleted_records};

let db = Database::open(std::fs::read("History")?)?; // read-only, owns the bytes

// 1. Graded header / freelist / WAL anomalies
for anomaly in audit(&db) {
    println!("[{:?}] {} — {}", anomaly.severity, anomaly.code, anomaly.kind.note());
}

// 2. Deleted rows carved from free space — column count inferred per record
for rec in carve_all_deleted_records(&db) {
    println!("recovered rowid {} from page {} (allocated: {})",
             rec.rowid, rec.page, rec.allocated);
}
```

The reader (`sqlite-core`) answers *"what does this file actually contain?"*; the analyzer (`sqlite-forensic`) grades the forensically notable parts and recovers the deleted ones.

---

## What you get

| | sqlite-forensic | rusqlite / `sqlite3` |
|---|:-:|:-:|
| Read live rows | ✅ | ✅ |
| Read-only on the evidence file | ✅ | ✅ (with care) |
| Recover deleted rows from freelist pages | ✅ | — |
| Recover deleted rows from in-page free blocks | ✅ | — |
| Recover dropped-table rows (column count inferred) | ✅ | — |
| Read uncheckpointed WAL overlay as a separate view | ✅ | applied silently |
| Graded, confidence-scored anomaly findings | ✅ | — |
| Refuses to ever re-surface a live row as "deleted" | ✅ | n/a |
| `forbid(unsafe)`, panic-free on hostile input | ✅ | C / FFI |

---

## The two crates

This is one workspace (`sqlite-forensic`) with two members, following the fleet reader/analyzer split:

| Crate | Role | Entry points |
|---|---|---|
| [`sqlite-core`](core) | The raw, read-only, panic-free file-format reader: header parse, b-tree walk, freelist + overflow chains, and a read-only WAL overlay. No findings. | `Database::open`, `Database::open_with_wal`, `freelist_pages`, `read_table`, `carve_free_regions`, `live_rowids` |
| [`sqlite-forensic`](forensic) | The anomaly auditor + deleted-record carver: grades observations into `forensicnomicon::report::Finding`s and recovers deleted rows. Depends on `sqlite-core`. | `audit`, `audit_findings`, `carve_all_deleted_records`, `carve_deleted_records` |

`sqlite-forensic` accepts an in-memory `Database` (built from `&[u8]`) — it is medium-agnostic and has no dependency on any image format or container layer. Findings flow into the shared `forensicnomicon::report` model, so a SQLite database's anomalies aggregate uniformly with the partition / container / filesystem layers in a triage report.

---

## Anomaly codes

`audit()` emits stable, scheme-prefixed codes (a published contract — never re-spelled). Each is an **observation** ("consistent with …"), graded for severity; the examiner draws the conclusion.

| Code | Severity | What it observes |
|---|:-:|---|
| `SQLITE-DELETED-RECORD-RECOVERED` | Medium | A record-shaped cell recovered from unallocated space — consistent with a deleted row not yet overwritten. Carries page / offset / rowid provenance. |
| `SQLITE-FREELIST-NONEMPTY` | Low | The database holds free pages — consistent with prior deletions (`DELETE` without `VACUUM`); those pages may retain recoverable rows. |
| `SQLITE-WAL-UNCHECKPOINTED` | Medium | A `-wal` sidecar carries committed page versions the main file does not reflect — the main file alone under-reports the true state. |
| `SQLITE-PAGECOUNT-MISMATCH` | High | The in-header page count disagrees with the count implied by file length — consistent with truncation, carving, or out-of-band modification. |
| `SQLITE-RESERVED-SPACE-NONZERO` | Low | The header reserves bytes per page — non-standard; consistent with a page-level extension such as encryption (SQLCipher/SEE) or a checksum VFS. |

The `AnomalyKind` enum is `#[non_exhaustive]`: new codes can be added without a breaking change, so downstream `match` arms must carry a `_` arm.

---

## Trust but verify

A carver that *over*-reports is worse than useless on an evidence database — it manufactures rows that were never deleted. The design goal of this carver is therefore precision over recall, enforced structurally rather than by inspection:

- **Read-only, panic-free, `forbid(unsafe)`** — `Database::open` owns a `Vec<u8>` and never writes back to the artifact; the whole workspace denies `unsafe` at compile time and reads every length/offset through bounds-checked helpers, so a malformed, attacker-controlled database cannot reach a raw-pointer path or panic.
- **Measured against independent third-party ground truth.** Recall and precision are computed per database against the **SQLite Forensic Corpus** (Nemetz, Schmitt & Freiling, DFRWS-EU 2018, CC0), whose authors shipped a per-row deleted-record answer key — so the truth set is theirs, not ours. The harness (`forensic/tests/nemetz_metrics.rs`) emits a reproducible confusion matrix; the full table is in [`docs/recovery-comparison.md`](docs/recovery-comparison.md).
- **High precision, structurally — never a live-row re-read.** Our carver carves only the *complement* of the live cell extents on a page, then drops any carved record whose rowid is currently live. Across the Nemetz recall corpus it produces **0 live-re-reads** (verified against the answer key's live rows), with only a small, low-confidence **phantom** class (all-empty/NULL records the inferred carver matches on a run of zero bytes). The two over-reporting failure modes the reference oracles exhibit on no-deletion databases — re-reading live cells, and re-surfacing a stale byte-copy of a live row — our carver does not.
- **Low recall on in-page deletion — reported honestly, not hidden.** On the cleanest category (`0C`: records deleted in place, `secure_delete=0`, no overwrite, so **every** deleted row's bytes survive) the carver recovers only **24 of 101** rows (~24 %). SQLite overwrites a freed cell's first four bytes (its payload-length + rowid header) with the freeblock pointer, and our forward parser cannot yet reconstruct those rows; freeblock-aware tools (undark, fqlite) can. This is a tracked capability gap, not a measurement artifact — the corpus proves the bytes are present and we still miss them. The earlier "163 of 163, 0 false positives" claim was specific to our own whole-freed-page fixture and is **retracted** as not representative.
- **Secondary checks stay labelled as such.** The undark/fqlite differential ([`docs/validation.md`](docs/validation.md)) is **inter-tool concordance** (the oracles disagree with each other — agreement, not correctness), and the DC3 `sqlite_dissect` corpus is a **no-false-positive regression set** (its `expected_rows` are live content, not a deleted set), never a recall oracle.

Carved records remain **confidence-graded observations** ("consistent with a deleted row"), never a verdict. The honest summary: a strict precision discipline confirmed against independent ground truth, and a documented in-page recall gap — not a claim of perfect recall or proof of correctness.

**Honest gaps (tracked, not hidden):** there is **no CI workflow** and **no line-coverage gate** in this repo yet, and the carver is **not yet fuzzed** — all three are planned to bring it level with the Paranoid-Gatekeeper bar the rest of the fleet enforces. The safety lints (`unsafe_code = forbid`, `unwrap_used`/`expect_used = deny`) and the `cargo-deny` supply-chain gate *are* enforced today.

---

## Documentation

- [`docs/validation.md`](docs/validation.md) — the Doer-Checker differential: how the carver was reconciled against undark and fqlite, page-level divergence diagnosis, build recipes.
- [`docs/recovery-comparison.md`](docs/recovery-comparison.md) — the measured per-database recall/precision confusion matrix against independent Nemetz ground truth, with the undark/fqlite concordance and DC3 no-FP regression set as secondary checks.
- [`docs/corpus-catalog.md`](docs/corpus-catalog.md) — every test fixture with its verbatim generator command and MD5.
- [`tests/data/README.md`](tests/data/README.md) — the committed synthetic fixtures, co-located.

---

## RapidTriage ecosystem

sqlite-forensic is the SQLite file-format parser in the [RapidTriage](https://github.com/SecurityRonin/rapidtriage) DFIR toolkit:

| Crate | Artifact family |
|---|---|
| [sqlite-forensic](https://github.com/SecurityRonin/sqlite-forensic) | SQLite databases (b-tree, freelist, WAL, deleted-record carving) |
| [browser-forensic](https://github.com/SecurityRonin/browser-forensic) | Chrome / Firefox / Safari |
| [winevt-forensic](https://github.com/SecurityRonin/winevt-forensic) | Windows Event Logs (EVTX) |
| [srum-forensic](https://github.com/SecurityRonin/srum-forensic) | Windows SRUM / ESE |
| [memory-forensic](https://github.com/SecurityRonin/memory-forensic) | Process memory, page tables |
| [forensicnomicon](https://github.com/SecurityRonin/forensicnomicon) | Artifact catalog, format constants, report model |

---

[Privacy Policy](https://securityronin.github.io/sqlite-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/sqlite-forensic/terms/) · © 2026 Security Ronin Ltd
