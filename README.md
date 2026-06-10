[![Docs](https://img.shields.io/badge/docs-securityronin.github.io-blue.svg)](https://securityronin.github.io/sqlite-forensic/)
[![Rust edition 2021](https://img.shields.io/badge/rust-edition%202021-orange.svg)](https://doc.rust-lang.org/edition-guide/rust-2021/index.html)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](#trust-but-verify)
[![security: cargo-deny](https://img.shields.io/badge/security-cargo--deny-success.svg)](deny.toml)

# sqlite-forensic

**Carve deleted rows out of a SQLite database without trusting it, without writing to it, and without re-surfacing a single live row.**

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
- **Validated against two independent oracles** — the carver's output was reconciled against **undark** (C) and a headless source-instrumentation tap of **fqlite** (Java) — neither written by us — over our own fixture *and* the third-party DC3 `sqlite_dissect` corpus. Full methodology, oracle provenance, and build recipes in [`docs/validation.md`](docs/validation.md); the per-scenario capability matrix is in [`docs/recovery-comparison.md`](docs/recovery-comparison.md).
- **Zero false positives of the two classes that matter most — structurally, not by inspection.** Our carver carves only the *complement* of the live cell extents on a page, then drops any carved record whose rowid is currently live (`Database::live_rowids`). So it never re-surfaces a live row, and never re-surfaces a *stale byte-copy* of one left in old free space by a b-tree rebalance — the two over-reporting failure modes **observed in both undark and fqlite on the no-deletion databases** (on the four DC3 "no genuine deletion" cases the oracles emit 6–19 rows each by re-reading live cells; ours emits **0 — the correct answer**).
- **On the synthetic fixtures, every recovered record is a genuine, correctly-decoded deleted row.** Where ground truth is known (the rowid set we deleted), each carved rowid is checked against it — no phantom parses. We do **not** claim a blanket "0 false positives" on the real-world DC3 databases: we have not adjudicated every emitted record there, so that stronger claim is unproven and we do not make it.
- **Matches undark, exceeds on dropped tables — with the recoverable-ceiling caveat.** On the freed-page + in-page fixture our carver recovers **163 of 163 *recoverable* rows** (exactly undark's set) — about **81% of all 200 deleted rows**; the other ~37 (ids 201–236 and 250) had their cell content physically overwritten when the pages were freed and are **unrecoverable by any tool**. On dropped tables it recovers the dropped rows *plus* the dropped table's own schema record (21 vs undark's 20; 11 vs 10). A rigorous per-scenario precision/recall treatment is being designed separately and will land in [`docs/recovery-comparison.md`](docs/recovery-comparison.md); this README does not commit to a single global precision/recall number.
- **The one documented miss is not papered over.** Site-235 — a record whose payload-length/rowid prefix was clobbered by an adjacent cell — is reachable only by fqlite's looser freeblock reconstruction (which emits an unknown rowid). Accepting it would mean accepting records with no parseable rowid, raising false-positive risk, so we document it rather than chase it.

Carved records remain **confidence-graded observations** ("consistent with a deleted row"), never a verdict. This is consistency with two independent oracles plus a stricter precision discipline — not a claim of perfect recall or proof of correctness.

**Honest gaps (tracked, not hidden):** there is **no CI workflow** and **no line-coverage gate** in this repo yet, and the carver is **not yet fuzzed** — all three are planned to bring it level with the Paranoid-Gatekeeper bar the rest of the fleet enforces. The safety lints (`unsafe_code = forbid`, `unwrap_used`/`expect_used = deny`) and the `cargo-deny` supply-chain gate *are* enforced today.

---

## Documentation

- [`docs/validation.md`](docs/validation.md) — the Doer-Checker differential: how the carver was reconciled against undark and fqlite, page-level divergence diagnosis, build recipes.
- [`docs/recovery-comparison.md`](docs/recovery-comparison.md) — per-deletion-scenario capability matrix (freed-page / in-page / dropped-table / WAL) against both oracles.
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
