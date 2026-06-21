# sqlite-forensic

**Carve deleted rows out of a SQLite database without trusting it, without writing to it, and without re-surfacing a live row.**

```rust
use sqlite_core::Database;
use sqlite_forensic::{audit, carve_all_deleted_records};

let db = Database::open(std::fs::read("History")?)?;
for anomaly in audit(&db) { /* graded findings */ }
for rec in carve_all_deleted_records(&db) { /* recovered deleted rows */ }
```

**[GitHub Repository →](https://github.com/SecurityRonin/sqlite-forensic)**

---

## What it does

sqlite-forensic reads the raw SQLite file format — header, b-tree, freelist + overflow chains, a read-only WAL overlay, and the rollback journal — and does two things the live `sqlite3`/rusqlite path cannot:

- **Grades anomalies** (`sqlite-forensic::audit`, `audit_journal`) into severity-ranked, confidence-scored `forensicnomicon::report::Finding`s across three substrates — free space, the uncheckpointed WAL, and the rollback journal: non-empty freelist, uncheckpointed WAL state (with acquisition guidance — acquire the live `-wal` before a checkpoint folds it into the main file and discards the residue), page-count mismatch, non-standard reserved space, and rollback-journal observations (hot journal, recoverable prior state, checksum mismatch, schema-cookie change, duplicate page, db-size delta). Each is an observation ("consistent with …"), never a verdict.
- **Carves deleted records** (`carve_all_deleted_records`) from freelist pages, in-page free blocks, dropped-table pages, and freed overflow-page chains (reassembled when every chain page survives as a freelist leaf) — column count inferred per record — while structurally refusing to re-surface a live row. A separate Tier-2 surface (`carve_with_fragments`; shown by default in the `sqlite4n6 carve` CLI, `--no-fragments` to suppress) salvages partial rows where a distinctive cell survives but full identity is destroyed. The **rollback journal** (`carve_rollback_journal`, `Database::rollback_prior`) adds the last transaction's deletes **and** edits — the default `DELETE`/`PERSIST` mode the WAL path doesn't cover — by diffing the journal's pre-transaction snapshot against the live db. An optional `table_instance_risks` / `…_with_sidecar` pass surfaces a non-overclaiming **hint** (`rowid_exceeds_autoinc_highwater(r=…,seq=…)` or `sidecar_schema_changed(table)`) when residue is consistent with — but not proof of — a prior table incarnation.

By default the `sqlite4n6 carve` CLI writes a **combined review workbook** (`evidence.recovered.xlsx`) — the source database dumped one sheet per live table, where each sheet is that table's **per-rowid version history**: live rows interleaved with the prior-changed and deleted versions recovered from the uncheckpointed WAL, the rollback journal, and free space, ordered by the WAL's logical commit sequence (there is no wall-clock timestamp in a SQLite WAL) and tinted by state, with image BLOBs shown as in-cell thumbnails. Add `--db` to also write a **queryable SQLite database** (`evidence.carved.db`) of the raw carved records — attribution-tiered `recovered_*` tables with carved cells in their native types (a recovered `BLOB` is stored losslessly) — so you can `sqlite3 evidence.carved.db "SELECT …"` immediately. `--format table|csv|jsonl` streams to stdout instead (JSONL carries BLOBs as base64).

---

## The two crates

| Crate | Role |
|---|---|
| `sqlite-core` | Raw, read-only, panic-free file-format reader. No findings. |
| `sqlite-forensic` | Anomaly auditor + deleted-record carver, built on `sqlite-core`. |

---

## Anomaly codes

| Code | Severity | Observes |
|---|:-:|---|
| `SQLITE-DELETED-RECORD-RECOVERED` | Medium | A record-shaped cell recovered from unallocated space. |
| `SQLITE-FREELIST-NONEMPTY` | Low | Free pages present — consistent with prior deletions. |
| `SQLITE-WAL-UNCHECKPOINTED` | Medium | `-wal` overlay the main file does not reflect. |
| `SQLITE-PAGECOUNT-MISMATCH` | High | Header page count disagrees with file length. |
| `SQLITE-RESERVED-SPACE-NONZERO` | Low | Non-standard per-page reserved bytes (e.g. SQLCipher). |
| `SQLITE-JOURNAL-*` | Low–High | Rollback-journal observations (`audit_journal`): `HOT`, `RECOVERABLE`, `CHECKSUM-MISMATCH`, `SCHEMA-CHANGE` (keyed on a change to the schema **cookie** at file-header offset 40, not mere page-1 presence), `DUPLICATE-PAGE`, `DBSIZE-DELTA`. |

---

## Validation

Validation is organized in three trust tiers (the axis is whether the correctness check is independent — see the methodology): **Tier 1** real third-party ground truth / real-device data; **Tier 2** real-engine bytes checked by a derivable answer key or an independent oracle (`sqlite3` / `calamine`), with the scenario chosen by us; **Tier 3** we authored both fixture and answer with no independent check (essentially just the freeblock-clobbered spilled-cell path, flagged `unproven-by-corpus`). The deleted-record carver is reconciled against independent reference tools — **undark** (C) and **fqlite** (Java) — and validated against third-party ground truth: the **Nemetz SQLite Forensic Corpus** (DFRWS-EU 2018, 141 DBs), the **NIST CFReDS / CFTT** SQLite sets (encoding/header reporting; WAL and rollback-journal deleted/modified-record recovery, 100/100 deletes + 100/100 modifications on SFT-03 PERSIST), and a no-panic robustness sweep over genuine **Josh Hickman iOS-17** databases:

- [Validation methodology](https://github.com/SecurityRonin/sqlite-forensic/blob/main/docs/validation.md)
- [Recovery capability comparison](https://github.com/SecurityRonin/sqlite-forensic/blob/main/docs/recovery-comparison.md)
- [Test corpus catalog](https://github.com/SecurityRonin/sqlite-forensic/blob/main/docs/corpus-catalog.md)

---

## RapidTriage ecosystem

sqlite-forensic is the SQLite parser in the [RapidTriage](https://github.com/SecurityRonin/rapidtriage) DFIR toolkit alongside [browser-forensic](https://github.com/SecurityRonin/browser-forensic), [winevt-forensic](https://github.com/SecurityRonin/winevt-forensic), [srum-forensic](https://github.com/SecurityRonin/srum-forensic), [memory-forensic](https://github.com/SecurityRonin/memory-forensic), and [forensicnomicon](https://github.com/SecurityRonin/forensicnomicon).

---

[Privacy Policy](privacy.md) · [Terms of Service](terms.md) · [GitHub](https://github.com/SecurityRonin/sqlite-forensic) · © 2026 Security Ronin Ltd.
