//! In-page free-block / gap carving + schema-less (column-count-inferring)
//! carving, validated against REAL SQLite fixtures (see `docs/corpus-catalog.md`).
//!
//! Two capabilities the freelist-only path could not reach:
//!   1. Allocated table-leaf pages (type 0x0D) keep deleted-cell residue in the
//!      unallocated gap between the cell-pointer array and `cell_content_start`,
//!      and in the freeblock chain. Carving these recovers in-place deletions
//!      WITHOUT ever re-surfacing a live (allocated) cell.
//!   2. Dropped-table / schema-gone records have no declared column count, so the
//!      count must be INFERRED from the record's serial-type array.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use sqlite_core::{Database, Value};

const DELETED: &[u8] = include_bytes!("../../tests/data/deleted_places.db");

/// The deleted-record carver must, on an allocated leaf page, recover records
/// from the free gap WITHOUT returning any live (allocated) cell. On
/// `deleted_places.db`, page 8 is a still-allocated leaf page whose gap holds
/// deleted rows 235 and 237 (verified with a hex inspection); the live rows on
/// that page are ids in 1..=200.
#[test]
fn carves_free_gap_on_allocated_leaf_page() {
    let db = Database::open(DELETED.to_vec()).expect("open");
    let page = db.raw_page(8).expect("page 8 in range");

    // Carve only the unallocated regions of this allocated leaf page.
    let carved = db.carve_free_regions(page, 6);

    let rowids: Vec<i64> = carved.iter().map(|c| c.rowid).collect();
    assert!(
        rowids.contains(&237),
        "must carve deleted row 237 from page 8's free gap; got {rowids:?}"
    );
    assert!(
        rowids.contains(&235),
        "must carve deleted row 235 from page 8's free gap; got {rowids:?}"
    );

    // 0-FALSE-POSITIVE: never re-surface a live (allocated) row. The live rows on
    // page 8 are ids 1..=200; carving free regions must yield none of them.
    assert!(
        carved.iter().all(|c| c.rowid > 200),
        "carving free regions must not return any live (allocated, id<=200) row"
    );

    // Row 237 content must be recovered verbatim.
    let r237 = carved.iter().find(|c| c.rowid == 237).unwrap();
    assert_eq!(
        r237.values.get(1),
        Some(&Value::Text("https://site-237.example.com/path/page".into()))
    );
}
