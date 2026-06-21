//! Freeblock reconstruction of deleted rows with a **multi-byte rowid varint**
//! (rowid ≥ 128) — the common case the freeblock-template path silently dropped.
//!
//! When a table-leaf cell is freed, SQLite overwrites its first four bytes with
//! the freeblock header. Those four bytes cover the `payload-length` + `rowid`
//! varints and the record `header_len`. For a **1-byte** rowid the clobber also
//! eats the first serial type, leaving a "known leading serial" the template can
//! supply. For a **2-byte** rowid (any rowid ≥ 128) the prefix is one byte wider,
//! so the clobber stops at `header_len` and **no** serial type is destroyed — the
//! whole serial array survives. The template builder used to reject that case
//! (empty leading-serial list), so every freeblock-clobbered row past rowid 127
//! was lost — and most real tables run well past 127 rows.
//!
//! Fixture (`tests/data/freeblock_2byte_rowid.db`, Tier-2, built with the real
//! `sqlite3` engine; ground truth derivable from the construction):
//! ```sql
//! PRAGMA page_size=4096; PRAGMA secure_delete=0;
//! CREATE TABLE t(id INTEGER PRIMARY KEY, name TEXT, val INTEGER);
//! -- insert id 1..260 as ('name_'||id, id*7), then:
//! DELETE FROM t WHERE id IN (5, 6, 200, 201);
//! ```
//! ids 5/6 have a 1-byte rowid (recovered before and after the fix); ids 200/201
//! have a 2-byte rowid (recovered only after it).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::pedantic)]

use sqlite_core::{Database, Value};
use sqlite_forensic::carve_all_deleted_records;

fn recovered_names(db: &Database) -> Vec<String> {
    carve_all_deleted_records(db)
        .into_iter()
        .flat_map(|r| r.values)
        .filter_map(|v| match v {
            Value::Text(t) => Some(t),
            _ => None,
        })
        .collect()
}

#[test]
fn recovers_deleted_rows_with_two_byte_rowid() {
    let bytes = std::fs::read("../tests/data/freeblock_2byte_rowid.db")
        .or_else(|_| std::fs::read("tests/data/freeblock_2byte_rowid.db"))
        .expect("fixture readable");
    let db = Database::open(bytes).expect("fixture opens");
    let names = recovered_names(&db);

    // 1-byte rowid baseline — must hold before and after the fix.
    assert!(
        names.iter().any(|n| n == "name_5"),
        "1-byte-rowid row name_5 should always recover; got {names:?}"
    );
    assert!(names.iter().any(|n| n == "name_6"));

    // 2-byte rowid (≥ 128) — the regression this test pins.
    assert!(
        names.iter().any(|n| n == "name_200"),
        "2-byte-rowid row name_200 must recover (freeblock-clobbered, all serials \
         survive); got {names:?}"
    );
    assert!(
        names.iter().any(|n| n == "name_201"),
        "2-byte-rowid row name_201 must recover; got {names:?}"
    );
}
