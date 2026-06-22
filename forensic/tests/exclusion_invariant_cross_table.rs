//! Regression: the exclusion invariant (never report a live row as deleted) must
//! hold even when two tables share rowids (docs/improvement-roadmap.md §1.1).
//!
//! `Database::live_rows()` keys live-row identity by a GLOBAL rowid with no table
//! dimension, so a table created later overwrites an earlier table's rows at the
//! same rowid in the collapsed map. When the carver surfaces an earlier table's
//! still-live row from a freed page (a B-tree-rebalance Type-** substrate), the
//! rowid-keyed exclusion check compares it against the *wrong* table's live row
//! and fails to drop it — re-surfacing a live row as a deleted "prior version".
//!
//! Fixture: `tests/data/exclusion_invariant/cross_table_rowid.db` (real `sqlite3`
//! engine; generator + provenance alongside it). Table `t` is the paper 0F
//! rebalance (live ids 51..80, deleted 1..50); table `z`, created second, holds
//! the SAME rowids 51..80 with different values and wins the collapse.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashSet;

use sqlite_core::Database;
use sqlite_forensic::carve_all_deleted_records;

const DB: &[u8] = include_bytes!("../../tests/data/exclusion_invariant/cross_table_rowid.db");

/// Value-tuple identity, keyed exactly as the carve filter keys it.
fn vkey(values: &[sqlite_core::Value]) -> String {
    format!("{values:?}")
}

#[test]
fn no_live_row_is_re_surfaced_across_tables_sharing_rowids() {
    let db = Database::open(DB.to_vec()).expect("fixture opens");

    // The complete set of every currently-live row's value-tuple, across ALL
    // tables, uncollapsed — the ground truth the invariant is defined against.
    let live: HashSet<String> = db
        .live_table_rows()
        .iter()
        .flat_map(|t| t.rows.iter())
        .map(|r| vkey(&r.values))
        .collect();
    assert!(!live.is_empty(), "fixture must have live rows");

    let recovered = carve_all_deleted_records(&db);

    // Sanity: the genuinely-deleted t rows (1..50) must still be recovered, so a
    // later fix cannot trivially pass by dropping everything.
    let recovered_deleted = recovered
        .iter()
        .filter(|r| {
            matches!(r.values.last(), Some(sqlite_core::Value::Text(v)) if v.starts_with("ROW-"))
        })
        .count();
    assert!(
        recovered_deleted > 0,
        "expected to recover some genuinely-deleted t rows"
    );

    // The invariant: NO recovered (deleted) record may equal a currently-live row.
    let leaked: Vec<(i64, &Vec<sqlite_core::Value>)> = recovered
        .iter()
        .filter(|rec| live.contains(&vkey(&rec.values)))
        .map(|rec| (rec.rowid, &rec.values))
        .collect();

    assert!(
        leaked.is_empty(),
        "exclusion invariant breached: {} live row(s) re-surfaced as deleted (rowids {:?})",
        leaked.len(),
        leaked.iter().map(|(rid, _)| *rid).collect::<Vec<_>>()
    );
}
