[![Docs](https://img.shields.io/badge/docs-securityronin.github.io-blue.svg)](https://securityronin.github.io/sqlite-forensic/)
[![CI](https://github.com/SecurityRonin/sqlite-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/sqlite-forensic/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](#trust-but-verify)
[![security: cargo-deny](https://img.shields.io/badge/security-cargo--deny-success.svg)](deny.toml)

# sqlite-forensic

**The deleted rows are the evidence — and `sqlite3` can't see them.** `sqlite4n6` carves deleted records back out of any SQLite database — browser history, chat apps, mobile artifacts — into a **review-ready spreadsheet you can open in seconds**: each table as a per-rowid **version history** (live, prior-changed, and deleted versions interleaved in WAL commit order) recovered from the uncheckpointed WAL, the **rollback journal** (the default `DELETE`/`PERSIST` mode the WAL path doesn't cover), and free space. It opens the evidence read-only, never writes it, and never re-surfaces a live row as "deleted".

```bash
brew install securityronin/tap/sqlite4n6
sqlite4n6 carve History.db          # → History.recovered.xlsx
```

**[Full documentation →](https://securityronin.github.io/sqlite-forensic/)**

---

## See it in 30 seconds

```console
$ sqlite4n6 carve History.db
wrote 412 record(s) and 9 fragment(s) to History.recovered.xlsx
```

Open `History.recovered.xlsx` and each table is its own **version history** — live rows interleaved with the **prior (changed) and deleted versions** recovered from the uncheckpointed WAL, the rollback journal, and free space, ordered by the WAL's logical commit sequence and tinted by state (current / superseded / deleted / guessed / rowid-reused), with `wal_commit` / `commit_seq` / `view_state` / `is_deleted` columns. A review-ready view, no schema to reconstruct by hand. **Image BLOBs come back as in-cell thumbnails; every cell is recovered natively and losslessly.** Prefer a queryable database? Add `--db` and you also get `History.carved.db`:

```console
$ sqlite4n6 carve History.db --db
wrote 412 record(s) and 9 fragment(s) to History.recovered.xlsx (+ History.carved.db)

$ sqlite3 History.carved.db 'SELECT _rowid, url FROM recovered_moz_places LIMIT 3'
588|https://mail.example.com/inbox
587|https://news.example.com/the-story-they-deleted
586|https://example.com/account/settings
```

Deleted rows, in tools already on your box. The evidence database and its `-wal`/`-shm`/`-journal` sidecars are **never** touched.

Precision-first, and **measured against independent ground truth** (the Nemetz *SQLite Forensic Corpus*, DFRWS-EU 2018): the **highest precision of any tool in the comparison**, **0 live-row re-reads**, and freeblock-aware recall of **0.833** on the cleanest category — ahead of `fqlite`'s 0.798. [How it's measured →](#trust-but-verify)

---

## Install

Every channel drops the `sqlite4n6` binary on your `PATH`.

**macOS / Linux — Homebrew**
```bash
brew install securityronin/tap/sqlite4n6
```

**Debian / Ubuntu / Kali — apt**
```bash
curl -1sLf 'https://dl.cloudsmith.io/public/securityronin/sqlite-forensic/setup.deb.sh' | sudo -E bash
sudo apt install sqlite4n6
```

**Windows** — download the signed `.msi` from the [latest release](https://github.com/SecurityRonin/sqlite-forensic/releases/latest) (every asset is listed in `checksums.txt`).

**From source** — needs a Rust toolchain
```bash
cargo install --git https://github.com/SecurityRonin/sqlite-forensic sqlite4n6
```

---

## What you get

By default `carve` writes a **combined review workbook** — `<name>.recovered.xlsx` — so there is nothing to parse and nothing to reconstruct by hand. The source database is dumped **one sheet per live table**, and each sheet is that table's **per-rowid VERSION HISTORY**: its live rows interleaved with the **prior (changed) and deleted versions** recovered from the uncheckpointed `-wal`, the **rollback `-journal`**, and free space. When no WAL is in play and a `<db>-journal` sits beside the database, `carve` folds in the **last transaction's deletes and edits** recovered from it — the deleted rows (red) and the pre-edit values of modified rows (blue) — the temporal inverse of the WAL: where the WAL holds *after*-images, the journal holds the *before*-image of the last transaction. The versions of one rowid are ordered by `commit_seq` — the WAL's **logical commit order**; there is **no wall-clock timestamp in a SQLite WAL**, only this commit sequence. Each version row carries, after the real columns:

- `_rowid` — the rowid (blank when destroyed);
- `wal_commit` — `live` for the current view, `commit:(salt1,salt2,frame_index)` for a WAL commit version, `residue` for order-unknown carved residue;
- `commit_seq` — the logical commit sequence (blank for the live view / residue);
- `view_state` — `present` (the current row), `changed_later` (a prior value a later commit replaced), `absent_final` (deleted), or `carved_residue`;
- `is_deleted`, `is_guessed`, `rowid_reused`, `attribution_uncertain` — 0/1 evidence flags.

Rows are tinted by a five-level precedence so the state reads at a glance: **current = no fill, superseded (changed-later) = blue, deleted / carved = red, guessed (shape-inferred) = yellow, rowid-reused = purple** (a reused rowid — delete-then-reinsert — overrides the others, since the two versions may be different entities). Residue attributed to no live table, and partial fragments, stay in their own `recovered_unattributed` / `recovered_fragments` tabs. **Image BLOBs — live, historical, or carved — are shown as in-cell thumbnails** (PNG/JPEG/GIF/BMP/WebP/TIFF); a video BLOB shows a typed `video/<ext> · <size>` placeholder (first-frame extraction is deferred). A sheet exceeding Excel's 1,048,576-row limit is truncated with a warning naming the table and dropped count.

The version history covers **only the uncheckpointed WAL window** (the `-wal` present at capture) plus free-space residue; once a checkpoint folds the WAL into the main file, that prior-version evidence is gone. **WITHOUT ROWID tables have no rowid to track**, so their sheet carries a single "WITHOUT ROWID — not version-tracked" note instead of versions. Every version is an observation — a value the rowid is *consistent with having held at that commit* — never a wall-clock claim.

Need a queryable database too? Add `--db` to also write `<name>.carved.db` (same stem, `--out`'s stem honored) — the raw carved records as a SQLite file, **attributed back to their source table in three honest tiers** — observed fact, forensic inference, and unknown — each in its own table, all carrying the provenance columns (`_page`, `_offset`, `_rowid`, `_source`, `_confidence`) and the carved cells in their **native types** (a recovered `BLOB` is stored byte-for-byte):

- **`recovered_<table>` — CERTAIN (observed fact).** The row was carved from a page still part of a live table's b-tree, so the owning table is known for sure; the columns are that table's **real names** (parsed from its `CREATE TABLE`). If the names cannot be parsed with confidence, the table keeps its real name but falls back to generic `c0..cN` columns — never wrong names.
- **`recovered_inferred` — INFERRED (consistent with).** The whole page was freed, so the hard table linkage is cut. The row's **shape** (column count + per-column affinity) is matched against every surviving table; a `_table_guess` column names the candidate and `_table_match_ambiguous` (0/1) flags when more than one table is equally consistent. This is a forensic inference, never asserted as fact.
- **`recovered_unattributed` — UNKNOWN.** Dropped-table residue, or a shape matching no surviving table — recovered in full, attributed to nothing.
- **`recovered_fragments`** — the **separate** Tier-2 partial-salvage table (a distinctive cell survived but the row's identity did not), kept distinct so a fragment is never mistaken for a full row. `--no-fragments` drops it.

Want a queryable database, the files elsewhere, or a stream instead? Pick the option:

```console
$ sqlite4n6 carve ChatStorage.sqlite --db               # also write a queryable <name>.carved.db
$ sqlite4n6 carve ChatStorage.sqlite --out /cases/2026-001/case  # set the output stem (→ case.recovered.xlsx)
$ sqlite4n6 carve ChatStorage.sqlite --format table     # recovered rows to stdout (or: csv, jsonl)
$ sqlite4n6 carve ChatStorage.sqlite --format jsonl     # one JSON object per record (BLOBs as base64)
$ sqlite4n6 carve ChatStorage.sqlite --min-confidence medium  # drop low-confidence carves
$ sqlite4n6 carve ChatStorage.sqlite --rowid-only       # just the recovered rowids
$ sqlite4n6 audit ChatStorage.sqlite                    # severity-graded anomaly findings
```

Under the hood `sqlite4n6` reads the raw file format itself — freelist pages, in-page free blocks, dropped-table pages, an uncheckpointed WAL overlay, and the **rollback journal** — recovering what the live `sqlite3`/rusqlite path cannot, because that path reads the live b-tree and stops.

| | sqlite-forensic | rusqlite / `sqlite3` |
|---|:-:|:-:|
| Read live rows | ✅ | ✅ |
| Read-only on the evidence file | ✅ | ✅ (with care) |
| Recover deleted rows from freelist pages | ✅ | — |
| Recover deleted rows from in-page free blocks | ✅ | — |
| Recover dropped-table rows (column count inferred) | ✅ | — |
| Reassemble deleted rows whose payload spilled to overflow-page chains | ✅ intact chains | — |
| Salvage partial rows as a separate Tier-2 fragment tier (a distinctive cell survives) | ✅ | — |
| Rebuild recovered rows into a queryable SQLite db (native types, lossless BLOBs) | ✅ | — |
| Read uncheckpointed WAL overlay as a separate view | ✅ | applied silently |
| Carve every WAL commit snapshot, LSN-labelled (per-commit timeline) | ✅ | — |
| Recover the last transaction's deletes **and edits** from the rollback `-journal` (default `DELETE`/`PERSIST` mode) | ✅ | — |
| Graded, confidence-scored anomaly findings | ✅ | — |
| Refuses to ever re-surface a live row as "deleted" | ✅ | n/a |
| `forbid(unsafe)`, panic-free on hostile input | ✅ | C / FFI |

---

## Time-travel: the full WAL timeline

When a `-wal` sidecar is present, `carve` auto-detects it and carves the **full per-commit WAL timeline** — every materializable state, each labelled with its log-sequence coordinate: the on-disk base image, **each commit snapshot** of the WAL, and the uncheckpointed WAL-frame residue. A row deleted late in a transaction history is still a live cell in an *earlier* commit's page image, so the snapshot column tells you the exact committed state a deleted row was last alive in. This is the real N-snapshot temporal model — not a two-point on-disk-vs-latest approximation.

```console
$ sqlite4n6 carve chat.db --format table             # auto-detects chat.db-wal
  page    offset     rowid  recovery_source   conf  snapshot                            values
     2      1581       130  commit-snapshot   0.90  commit:(3131615003,3836839008,0)    130 | bob | secret body 130
     2      1261         ?  commit-snapshot   0.40  commit:(3131615003,3836839008,1)    NULL | NULL | ...

$ sqlite4n6 carve chat.db --wal /path/to/chat.db-wal  # point at an explicit sidecar
$ sqlite4n6 carve chat.db --no-wal                     # on-disk image only, no snapshot column
```

The `snapshot` column carries the salt-qualified LSN — `commit:(salt1,salt2,commit_frame_index)` for a committed snapshot, `wal-frame:(salt1,salt2,frame_index)` for raw frame residue, `on-disk` for the base image. A record identical across views is collapsed to its earliest committed coordinate. `--no-wal` carves the on-disk image alone (single view, no snapshot column). The evidence file and its sidecars are **never** written.

---

## The rollback journal: the last transaction's deletes and edits

`DELETE` (the default) and `PERSIST` are SQLite's *rollback-journal* modes — the
common case the WAL feature doesn't cover. Before a transaction modifies a page,
SQLite copies that page's **original** bytes into a `<db>-journal` sidecar; in
`PERSIST` mode the header is zeroed on commit but those page images remain. That
makes the journal the **temporal inverse of the WAL**: the WAL holds *after*-images
(roll forward to the present), the journal holds the *before*-image of the **last
transaction** (roll back to the state just before it). When `carve` finds a
`<db>-journal` (and no WAL takes precedence), it diffs that prior state against the
live database and recovers:

- **deletions** — a rowid present in the prior state but gone now → the full
  deleted row (tinted **red**), and
- **modifications** — a rowid present in both with changed values → the **pre-edit
  value** (tinted **blue**), with the live row kept as current.

```console
$ sqlite4n6 carve case.sqlite                  # auto-detects case.sqlite-journal
wrote 1 record(s) and 0 fragment(s) to case.recovered.xlsx
recovered 100 deleted + 100 modified row(s) from the rollback journal

$ sqlite4n6 carve case.sqlite --no-journal     # ignore the -journal sidecar
```

Validated end-to-end against the **NIST CFReDS** SFT-03 PERSIST set (NIST-authored
ground truth): **100/100** documented deletions and **100/100** modifications
recovered. Two-tier parser — a valid (hot/crash) journal header, or a `PERSIST`
zeroed header reconstructed from the database's own page size; journal-header
offsets verified against SQLite's `pager.c`. The journal also drives a set of
`audit` observations (see *Anomaly codes*). Limits: only the *last* transaction's
state survives in a rollback journal; `DELETE`-mode (file unlinked) and
`TRUNCATE`-mode (file zeroed) leave no in-band residue.

---

## Two recovery sets: full rows and fragments

`carve` returns **two structurally separate result sets** — never merged, so a partial salvage can never be mistaken for a recovered row. The separation *is* the precision discipline.

**Set 1 — full rows (high precision).** Complete records, every cell intact, carrying page / offset / rowid provenance and a confidence score. These are carved from freelist pages, in-page free blocks, and dropped-table pages; extended by **freeblock reconstruction**, which rebuilds a record from its surviving serial-type tail plus a same-page schema template when SQLite overwrote only the cell's first four bytes (surfacing the destroyed rowid as unknown). A bounded sub-tier reaches rows whose payload outgrew the page (`> usable − 35` bytes) and spilled onto an **overflow-page chain** — reassembled to a full record **only when every chain page survives as a freelist leaf** (content-preserving), and graded below the in-page tier because a chain page reallocated as the freelist *trunk* destroys the record.

**Set 2 — fragments (Tier-2, shown by default).** When a row's full identity is destroyed but a single distinctive cell survives contiguously (a `TEXT` of `≥ 4` bytes, or a `REAL`), that lone value is salvaged as a **fragment**. A fragment has no rowid and is *not a row* — it is the partial evidence one surviving cell can still anchor ("this value was here"), never the stronger claim a full row makes ("this row was here").

The two sets stay apart by construction: separate tables in the rebuilt db (and separate sections in the text output), suppressed together with `--no-fragments`, and excluded from `--rowid-only` (a fragment carries no rowid). Set 1 is the precision-first surface; Set 2 is the recall safety net that refuses to overclaim.

---

## Drive the library directly

Point the analyzer at the file bytes and get graded findings plus carved deleted records:

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

This is one workspace (`sqlite-forensic`): two library crates following the fleet reader/analyzer split, plus the `sqlite4n6` CLI that consumes them.

| Crate | Role | Entry points |
|---|---|---|
| [`sqlite-core`](core) | The raw, read-only, panic-free file-format reader: header parse, b-tree walk, freelist + overflow chains, a read-only WAL overlay that maps onto the canonical `forensicnomicon::history` temporal cohort, a rollback-journal parser + prior-state snapshot, plus a small pure-Rust writer (`rebuild`) that materializes recovered rows into a fresh database. | `Database::open`, `Database::open_with_wal`, `freelist_pages`, `read_table`, `carve_free_regions`, `live_rowids`, `wal_timeline`, `Database::rollback_prior`, `RollbackJournal::parse`, `rebuild::build_recovered_db` |
| [`sqlite-forensic`](forensic) | The anomaly auditor + deleted-record carver: grades observations into `forensicnomicon::report::Finding`s and recovers deleted rows (free space, WAL frames, and the rollback journal). Depends on `sqlite-core`. | `audit`, `audit_findings`, `audit_journal`, `carve_all_deleted_records`, `carve_with_fragments`, `carve_rollback_journal` |

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
| `SQLITE-JOURNAL-HOT` | High | A `-journal` with a valid header sits beside the database — consistent with an interrupted or in-progress write transaction (the main db may require rollback). |
| `SQLITE-JOURNAL-RECOVERABLE` | Medium | A `PERSIST` rollback journal carries pre-transaction page images — consistent with a committed transaction whose deleted/modified rows remain recoverable. |
| `SQLITE-JOURNAL-CHECKSUM-MISMATCH` | High | A journal page record failed its page checksum — consistent with corruption, a torn page write, or post-write modification. Names the offending page(s). |
| `SQLITE-JOURNAL-SCHEMA-CHANGE` | Medium | The schema page (page 1) is among the journal's images — consistent with a DDL change (CREATE/DROP/ALTER) in the last transaction; the prior schema is recoverable. |
| `SQLITE-JOURNAL-DUPLICATE-PAGE` | Medium | A page number repeats across the journal's records (the spec journals a page at most once) — consistent with corruption, a savepoint/super-journal artifact, or tampering. |
| `SQLITE-JOURNAL-DBSIZE-DELTA` | Low | The journal's transaction-start page count differs from the current size — the last transaction grew (INSERTs) or shrank (auto-vacuum / truncation) the database. |

The journal anomalies are emitted by `audit_journal(&db, &journal_bytes)`; the
`audit` subcommand auto-folds them when a `<db>-journal` is present (`--no-journal`
opts out). The `AnomalyKind` enum is `#[non_exhaustive]`: new codes can be added without a breaking change, so downstream `match` arms must carry a `_` arm.

---

## Trust but verify

A carver that *over*-reports is worse than useless on an evidence database — it manufactures rows that were never deleted. The design goal of this carver is therefore precision over recall, enforced structurally rather than by inspection:

- **Read-only, panic-free, `forbid(unsafe)`** — `Database::open` owns a `Vec<u8>` and never writes back to the artifact; the whole workspace denies `unsafe` at compile time and reads every length/offset through bounds-checked helpers, so a malformed, attacker-controlled database cannot reach a raw-pointer path or panic. (The `*.recovered.xlsx` workbook and the `--db` `*.carved.db` are separate, new output files — the evidence is still never written.)
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
