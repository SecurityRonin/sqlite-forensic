//! Regression: dedup must not collapse genuinely-distinct deleted records that
//! two different tables happen to share by `(rowid, values)`
//! (docs/improvement-roadmap.md §1.2).
//!
//! `dedup_keep_best` keyed identity on `(rowid, values)` alone, with no table
//! dimension, so a deleted row that exists in two tables with the same rowid and
//! the same values was kept only once — silently dropping a genuinely-distinct
//! deleted record (recall / evidence loss).
//!
//! Fixture: `tests/data/dedup_cross_table/cross_table_identity.db` (real `sqlite3`
//! engine). Tables `a` and `b` each hold (1,'DUP-1') and (2,'DUP-2'); both DELETE
//! ids 1 and 2. Each table stays live (a keeper row), so the deleted rows are
//! recovered as in-page residue attributable to their owning table.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use sqlite_core::{Database, Value};
use sqlite_forensic::carve_all_deleted_records;

const DB: &[u8] = include_bytes!("../../tests/data/dedup_cross_table/cross_table_identity.db");

fn count_with_tail(recovered: &[sqlite_forensic::CarvedRecord], tail: &str) -> usize {
    recovered
        .iter()
        .filter(|r| matches!(r.values.last(), Some(Value::Text(v)) if v == tail))
        .count()
}

#[test]
fn cross_table_identical_deleted_rows_are_not_collapsed() {
    let db = Database::open(DB.to_vec()).expect("fixture opens");
    let recovered = carve_all_deleted_records(&db);

    // (1,'DUP-1') and (2,'DUP-2') are each deleted from BOTH a and b — two
    // genuinely-distinct deleted records per identity. Dedup on (rowid, values)
    // alone collapses each to one; the table-aware identity must keep both.
    assert_eq!(
        count_with_tail(&recovered, "DUP-1"),
        2,
        "(1,'DUP-1') deleted from both tables a and b must be recovered twice"
    );
    assert_eq!(
        count_with_tail(&recovered, "DUP-2"),
        2,
        "(2,'DUP-2') deleted from both tables a and b must be recovered twice"
    );
}
