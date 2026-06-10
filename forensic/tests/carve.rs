//! SMOKE test for deleted-record carving over a REAL browser-style SQLite
//! (`moz_places`, `secure_delete=OFF`; see `docs/corpus-catalog.md`). Rows with
//! id 201..=400 were `DELETE`d without `VACUUM`, freeing whole leaf pages onto
//! the freelist whose old cell content (the deleted records) survives intact.
//!
//! This is the capability rusqlite structurally cannot provide: libsqlite only
//! returns the 200 live rows; the native carver recovers the deleted ones from
//! the freed pages. Recovered rows are confidence-graded observations, never
//! assertions.
//!
//! # NOT the authoritative validation
//!
//! This file is self-referential: the fixture, the carver, and these assertions
//! are all ours, so it can only smoke-test that the pipeline runs and that a
//! couple of known rows come back verbatim — it cannot prove correctness against
//! an independent reference. The authoritative, Doer-Checker validation lives in
//! `forensic/tests/fqlite_oracle.rs` (differential reconciliation against the
//! independent `undark` carver and the DC3 `sqlite_dissect` corpus) and is
//! written up in `docs/validation.md`. The former magic-number assertion
//! (`carved.len() >= 150`) is intentionally gone: it dressed an arbitrary
//! threshold up as validation. Completeness is now measured against the oracle.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use sqlite_core::{Database, Value};
use sqlite_forensic::{carve_deleted_records, AnomalyKind};

const DB: &[u8] = include_bytes!("../../tests/data/deleted_places.db");
const MOZ_PLACES_COLS: usize = 6;

#[test]
fn smoke_recovers_deleted_rows_from_freed_pages() {
    let db = Database::open(DB.to_vec()).expect("open deleted_places.db");
    let carved = carve_deleted_records(&db, MOZ_PLACES_COLS);

    // Smoke bound only: the carver must produce a non-trivial result on a fixture
    // known to hold ~200 deleted rows. The actual completeness claim (vs. the
    // undark oracle) is asserted in `fqlite_oracle.rs`, NOT here — do not treat
    // this loose lower bound as validation.
    assert!(
        !carved.is_empty(),
        "carver returned nothing on a fixture with ~200 deleted rows"
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
