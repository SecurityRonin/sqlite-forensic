//! Full-coverage deleted-record recovery: `carve_all_deleted_records` drives
//! every recovery class — freelist whole-page, freelist trunk-page body,
//! in-page free space on an allocated leaf, and dropped-table (schema-gone) —
//! validated against the fixture and the third-party DC3 corpus.
//!
//! RED assertions target the rows the freelist-only path missed that are
//! GENUINELY deleted (not live-cell re-reads): fixture 235/237 (allocated-page
//! in-page remnants) and the DC3 dropped-table records (0A-01/0A-02). The
//! 0-false-positive property — never re-surface a live row — is asserted
//! throughout.
//!
//! NOTE on the DC3 in-page cases (01-01, 01-02, 03-02, 07-01): these have NO
//! genuine deleted residue (their live tables are intact and packed); undark and
//! fqlite "recover" rows there only by re-reading the LIVE cells. Our 0-FP carver
//! deliberately does NOT do that, so it recovers ~0 from them — which is correct,
//! not a gap. See `docs/recovery-comparison.md`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use sqlite_core::{Database, Value};
use sqlite_forensic::carve_all_deleted_records;

const DELETED: &[u8] = include_bytes!("../../tests/data/deleted_places.db");

fn dc3(name: &str) -> Option<Vec<u8>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../tests-oracle-corpus/dc3-sqlite-dissect")
        .join(name);
    std::fs::read(path).ok()
}

/// On our fixture, full carving must now recover the two allocated-page in-page
/// remnants (235, 237) that the freelist-only path missed — closing the gap vs
/// undark — while still recovering the freelist rows and surfacing no live row.
#[test]
fn fixture_full_recovery_includes_in_page_remnants() {
    let db = Database::open(DELETED.to_vec()).expect("open");
    let carved = carve_all_deleted_records(&db);

    let mut ids: Vec<i64> = carved.iter().map(|c| c.rowid).collect();
    ids.sort_unstable();
    ids.dedup();

    for must in [235, 237, 300, 400] {
        assert!(
            ids.contains(&must),
            "full carving must recover deleted row {must}; got {} distinct rows",
            ids.len()
        );
    }
    // 0-FALSE-POSITIVE: live rows are ids 1..=200.
    assert!(
        carved.iter().all(|c| c.rowid > 200),
        "full carving must never re-surface a live (id<=200) row"
    );
}

/// Dropped-table recovery: `corpus_0A-01.db` DROPped its `users` table, leaving
/// its page on the freelist with NO `sqlite_master` schema. The records are
/// 5-column (id, name, surname, zip, frecency); the column count must be
/// inferred from the serial-type array. undark recovers all 20.
#[test]
fn dc3_dropped_table_recovered() {
    let Some(bytes) = dc3("corpus_0A-01.db") else {
        eprintln!("SKIP dc3_dropped_table_recovered: DC3 corpus absent (gitignored)");
        return;
    };
    let db = Database::open(bytes).expect("open 0A-01");
    let carved = carve_all_deleted_records(&db);

    // Must recover a substantial share of the 20 dropped rows by inferring the
    // column count from each record's serial-type array.
    assert!(
        carved.len() >= 18,
        "dropped-table carving must recover the bulk of 20 rows; got {}",
        carved.len()
    );
    // A known dropped row: rowid 20 = ("Erich","Graf",...).
    let r20 = carved
        .iter()
        .find(|c| c.rowid == 20)
        .expect("must recover dropped rowid 20");
    assert_eq!(r20.values.get(1), Some(&Value::Text("Erich".into())));
    assert_eq!(r20.values.get(2), Some(&Value::Text("Graf".into())));
    // Every carved record is flagged unallocated.
    assert!(carved.iter().all(|c| !c.allocated));
}

/// Second dropped-table fixture `corpus_0A-02.db` (heterogeneous-width rows).
#[test]
fn dc3_dropped_table_0a02_recovered() {
    let Some(bytes) = dc3("corpus_0A-02.db") else {
        eprintln!("SKIP dc3_dropped_table_0a02_recovered: DC3 corpus absent (gitignored)");
        return;
    };
    let db = Database::open(bytes).expect("open 0A-02");
    let carved = carve_all_deleted_records(&db);
    // undark recovers ~16 names here; we must recover a substantial share.
    assert!(
        carved.len() >= 10,
        "dropped-table 0A-02 carving must recover the bulk of its rows; got {}",
        carved.len()
    );
}
