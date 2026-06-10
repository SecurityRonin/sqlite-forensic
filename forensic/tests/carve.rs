//! Deleted-record carving validation against a REAL browser-style SQLite
//! (`moz_places`, `secure_delete=OFF`; see `docs/corpus-catalog.md`). Rows with
//! id 201..=400 were `DELETE`d without `VACUUM`, freeing whole leaf pages onto
//! the freelist whose old cell content (the deleted records) survives intact.
//!
//! This is the capability rusqlite structurally cannot provide: libsqlite only
//! returns the 200 live rows; the native carver recovers the deleted ones from
//! the freed pages. Recovered rows are confidence-graded observations, never
//! assertions.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use sqlite_core::{Database, Value};
use sqlite_forensic::{carve_deleted_records, AnomalyKind};

const DB: &[u8] = include_bytes!("data/deleted_places.db");
const MOZ_PLACES_COLS: usize = 6;

#[test]
fn recovers_deleted_rows_from_freed_pages() {
    let db = Database::open(DB.to_vec()).expect("open deleted_places.db");
    let carved = carve_deleted_records(&db, MOZ_PLACES_COLS);

    // The 200 deleted rows (ids 201..=400) lived on the freed pages; we should
    // recover a substantial majority of them (allowing for the few bytes the
    // freelist trunk header overwrote at the top of one freed page).
    assert!(
        carved.len() >= 150,
        "expected to carve the bulk of the 200 deleted rows, got {}",
        carved.len()
    );

    // Every carved record is marked unallocated with provenance.
    for rec in &carved {
        assert!(!rec.allocated, "carved record must be flagged unallocated");
        assert!(rec.page >= 1, "carved record carries its source page");
        assert!(
            rec.confidence > 0.0 && rec.confidence <= 1.0,
            "confidence is a probability"
        );
        assert_eq!(rec.values.len(), MOZ_PLACES_COLS);
    }

    // A specific deleted row must be recoverable verbatim. Row id=300:
    //   url   = 'https://site-300.example.com/path/page'
    //   title = 'Title for record number 300 SECRETMARKER'
    let r300 = carved
        .iter()
        .find(|r| r.rowid == 300)
        .expect("deleted row 300 must be carved");
    assert_eq!(
        r300.values[1],
        Value::Text("https://site-300.example.com/path/page".into())
    );
    assert_eq!(
        r300.values[2],
        Value::Text("Title for record number 300 SECRETMARKER".into())
    );

    // No carved rowid should collide with a LIVE row (1..=200): the carver only
    // scans unallocated space, so it must not re-surface allocated records.
    assert!(
        carved.iter().all(|r| r.rowid > 200),
        "carver must not return live (allocated) rows"
    );
}

#[test]
fn carving_is_a_residue_anomaly_finding() {
    let db = Database::open(DB.to_vec()).expect("open");
    let carved = carve_deleted_records(&db, MOZ_PLACES_COLS);
    assert!(!carved.is_empty());
    // Each carved record converts to a Residue-category anomaly.
    let kind = AnomalyKind::DeletedRecordRecovered {
        page: carved[0].page,
        offset: carved[0].offset,
        rowid: carved[0].rowid,
    };
    assert_eq!(kind.code(), "SQLITE-DELETED-RECORD-RECOVERED");
}
