[![Docs](https://img.shields.io/badge/docs-securityronin.github.io-blue.svg)](https://securityronin.github.io/sqlite-forensic/)
[![Rust edition 2021](https://img.shields.io/badge/rust-edition%202021-orange.svg)](https://doc.rust-lang.org/edition-guide/rust-2021/index.html)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

[![CI](https://github.com/SecurityRonin/sqlite-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/sqlite-forensic/actions/workflows/ci.yml)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](#trust-but-verify)
[![security: cargo-deny](https://img.shields.io/badge/security-cargo--deny-success.svg)](deny.toml)

# sqlite-forensic

**Carve deleted rows out of a SQLite database without trusting it, without writing to it, and without re-surfacing a single live row.**

> Measured against **independent third-party ground truth** — the SQLite Forensic Corpus (Nemetz, Schmitt & Freiling, DFRWS-EU 2018, CC0), whose authors shipped a per-row deleted answer key — and reported as a reproducible per-database confusion matrix ([`docs/recovery-comparison.md`](docs/recovery-comparison.md)). The headline: **precision is the highest of any tool measured** (it never re-surfaces a live row as "deleted", and emits only a small low-confidence phantom class), and **freeblock-aware reconstruction leads in-page recall** — **0.833** on the cleanest category (`0C`: 70 of 84 recoverable rows), ahead of `fqlite`'s **0.798**, at roughly five times fewer false rows. Every number here is the harness-measured value against that independent corpus.

Every browser history, every chat app, every mobile artifact is a SQLite file — and the forensically interesting rows are usually the *deleted* ones. The standard `sqlite3`/rusqlite path cannot see them: it reads the live b-tree and stops. `sqlite-forensic` reads the raw file format itself — freelist pages, in-page free blocks, dropped-table pages, and an uncheckpointed WAL overlay — and recovers what the live query cannot, as severity-graded, confidence-scored observations.

This is a Rust library workspace with a CLI (`sqlite4n6`). The fastest path — point it at a database and read the deleted rows straight out of free space. It opens the evidence **read-only** and never writes the file or its sidecars:

```console
$ sqlite4n6 carve ChatStorage.sqlite                         # deleted rows, table view
$ sqlite4n6 carve ChatStorage.sqlite --format jsonl          # one JSON object per record
$ sqlite4n6 carve ChatStorage.sqlite --min-confidence medium # drop low-confidence carves
$ sqlite4n6 carve ChatStorage.sqlite --no-fragments          # full rows only (fragments shown by default)
$ sqlite4n6 audit ChatStorage.sqlite                         # graded anomaly findings
```

## Install

Pick the channel for your platform — each lands the `sqlite4n6` binary on your `PATH`.

**macOS / Linux (Homebrew):**

```console
$ brew install securityronin/tap/sqlite4n6
```

**Debian / Ubuntu (apt):**

```console
$ curl -1sLf 'https://dl.cloudsmith.io/public/securityronin/sqlite-forensic/setup.deb.sh' | sudo -E bash
$ sudo apt install sqlite4n6
```

**Windows (winget):**

```console
> winget install SecurityRonin.sqlite4n6
```

**Prebuilt binaries** — grab a `.tar.gz` (macOS/Linux), `.msi` (Windows), or `.deb` (Debian/Ubuntu) for your architecture from the [latest release](https://github.com/SecurityRonin/sqlite-forensic/releases/latest); every asset is listed in `checksums.txt` for verification.

**From source (Rust toolchain):**

```console
$ cargo install --git https://github.com/SecurityRonin/sqlite-forensic sqlite4n6
```

When a `-wal` sidecar is present, `carve` auto-detects it and carves the **full per-commit WAL timeline** — every materializable state, each labelled with its log-sequence coordinate: the on-disk base image, **each commit snapshot** of the WAL, and the uncheckpointed WAL-frame residue. A row deleted late in a transaction history is still a live cell in an *earlier* commit's page image, so the snapshot column tells you the exact committed state a deleted row was last alive in. This is the real N-snapshot temporal model — not a two-point on-disk-vs-latest approximation.

```console
$ sqlite4n6 carve chat.db                            # auto-detects chat.db-wal
  page    offset     rowid  recovery_source   conf  snapshot                            values
     2      1581       130  commit-snapshot   0.90  commit:(3131615003,3836839008,0)    130 | bob | secret body 130
     2      1261         ?  commit-snapshot   0.40  commit:(3131615003,3836839008,1)    NULL | NULL | ...

$ sqlite4n6 carve chat.db --wal /path/to/chat.db-wal  # point at an explicit sidecar
$ sqlite4n6 carve chat.db --no-wal                     # on-disk image only, no snapshot column
```

The `snapshot` column carries the salt-qualified LSN — `commit:(salt1,salt2,commit_frame_index)` for a committed snapshot, `wal-frame:(salt1,salt2,frame_index)` for raw frame residue, `on-disk` for the base image. A record identical across views is collapsed to its earliest committed coordinate. `--no-wal` carves the on-disk image alone (single view, no snapshot column). The evidence file and its sidecars are **never** written.

## Two recovery sets: full rows and fragments

`carve` returns **two structurally separate result sets** — never merged, so a partial salvage can never be mistaken for a recovered row. The separation *is* the precision discipline.

**Set 1 — full rows (high precision).** Complete records, every cell intact, carrying page / offset / rowid provenance and a confidence score. These are carved from freelist pages, in-page free blocks, and dropped-table pages; extended by **freeblock reconstruction**, which rebuilds a record from its surviving serial-type tail plus a same-page schema template when SQLite overwrote only the cell's first four bytes (surfacing the destroyed rowid as unknown). A bounded sub-tier reaches rows whose payload outgrew the page (`> usable − 35` bytes) and spilled onto an **overflow-page chain** — reassembled to a full record **only when every chain page survives as a freelist leaf** (content-preserving), and graded below the in-page tier because a chain page reallocated as the freelist *trunk* destroys the record.

**Set 2 — fragments (Tier-2, shown by default).** When a row's full identity is destroyed but a single distinctive cell survives contiguously (a `TEXT` of `≥ 4` bytes, or a `REAL`), that lone value is salvaged as a **fragment**. A fragment has no rowid and is *not a row* — it is the partial evidence one surviving cell can still anchor ("this value was here"), never the stronger claim a full row makes ("this row was here").

The two sets stay apart by construction: fragments render in their own section, suppressed with `--no-fragments`, and excluded from `--rowid-only` (a fragment carries no rowid). Set 1 is the precision-first surface; Set 2 is the recall safety net that refuses to overclaim.

Or drive the library directly — point the analyzer at the file bytes and get graded findings plus carved deleted records:

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
| Reassemble deleted rows whose payload spilled to overflow-page chains | ✅ partial | — |
| Salvage partial rows as a separate Tier-2 fragment tier (a distinctive cell survives) | ✅ default | — |
| Read uncheckpointed WAL overlay as a separate view | ✅ | applied silently |
| Carve every WAL commit snapshot, LSN-labelled (per-commit timeline) | ✅ | — |
| Graded, confidence-scored anomaly findings | ✅ | — |
| Refuses to ever re-surface a live row as "deleted" | ✅ | n/a |
| `forbid(unsafe)`, panic-free on hostile input | ✅ | C / FFI |

---

## The two crates

This is one workspace (`sqlite-forensic`): two library crates following the fleet reader/analyzer split, plus the `sqlite4n6` CLI that consumes them:

| Crate | Role | Entry points |
|---|---|---|
| [`sqlite-core`](core) | The raw, read-only, panic-free file-format reader: header parse, b-tree walk, freelist + overflow chains, and a read-only WAL overlay that maps onto the canonical `forensicnomicon::history` temporal cohort (each commit a salt-qualified `[H]` state). No findings. | `Database::open`, `Database::open_with_wal`, `freelist_pages`, `read_table`, `carve_free_regions`, `live_rowids`, `wal_timeline`, `WalTimeline::to_temporal_cohort` |
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
- **Strong in-page recall via freeblock reconstruction — reported honestly.** On the cleanest category (`0C`: records deleted in place, `secure_delete=0`, no overwrite, so **every** deleted row's bytes survive) the carver recovers **70 of the 84** cross-tool-scored rows (recall **0.833**), ahead of `fqlite`'s 0.798. SQLite overwrites a freed cell's first four bytes (payload-length + rowid varints, `header_len`, leading serial) with the freeblock pointer; `reconstruct_freeblock_records` rebuilds each record from its surviving serial-type tail plus a schema template derived from a live cell on the same page, with the destroyed rowid surfaced as unknown. It does so at higher precision than `fqlite` and **0 live-re-reads**.
- **Overflow-page chains: partial recovery, honestly bounded.** A deleted row whose payload spilled onto a freed overflow chain is reassembled to a full row **only when every chain page survives as a freelist leaf**; a chain page reallocated as the freelist trunk destroys the record, which is then refused from the full tier and surfaces only as a Tier-2 fragment. On the Nemetz `0E` category this reassembles the one byte-perfectly-recoverable spilled chain (verified `assert_eq!` against the answer key, substrate recall **1.000**) for an **end-to-end `0E` recall of 0.333** — a deliberately bounded capability, graded below the in-page tier, never claimed as full overflow recovery.
- **Secondary checks stay labelled as such.** The undark/fqlite differential ([`docs/validation.md`](docs/validation.md)) is **inter-tool concordance** (the oracles disagree with each other — agreement, not correctness), and the DC3 `sqlite_dissect` corpus is a **no-false-positive regression set** (its `expected_rows` are live content, not a deleted set), never a recall oracle.

Carved records remain **confidence-graded observations** ("consistent with a deleted row"), never a verdict. The honest summary: a strict precision discipline confirmed against independent ground truth, and a documented in-page recall gap — not a claim of perfect recall or proof of correctness.

**Enforced in CI (the fleet's Paranoid-Gatekeeper bar):** every push and PR runs `rustfmt`, Clippy (`-D warnings`), the full test suite on Linux/macOS/Windows, a **100%-function-coverage** gate (`cargo llvm-cov --fail-under-functions 100`), `cargo-deny` (licenses + advisories + sources), an MSRV build (1.96), a `gitleaks` secret scan, and docs-as-error. The safety lints (`unsafe_code = forbid`, `unwrap_used`/`expect_used = deny`) hold at compile time. Three **libFuzzer harnesses** — over `Database::open`, the carver, and the auditor — are built and checked in CI; run a campaign with `cargo +nightly fuzz run <target>`. The one substantive limitation remains the **documented in-page recall gap** above — not a coverage or tooling gap.

---

## Documentation

- [`docs/validation.md`](docs/validation.md) — the Doer-Checker differential: how the carver was reconciled against undark and fqlite, page-level divergence diagnosis, build recipes.
- [`docs/recovery-comparison.md`](docs/recovery-comparison.md) — the measured per-database recall/precision confusion matrix against independent Nemetz ground truth, with the undark/fqlite concordance and DC3 no-FP regression set as secondary checks.
- [`docs/corpus-catalog.md`](docs/corpus-catalog.md) — every test fixture with its verbatim generator command and MD5.
- [`tests/data/README.md`](tests/data/README.md) — the committed synthetic fixtures, co-located.

---

## Issen ecosystem

sqlite-forensic is the SQLite file-format parser in the [Issen](https://github.com/SecurityRonin/issen) DFIR toolkit:

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
