//! WAL-overlay validation against a REAL SQLite database + `-wal` sidecar (see
//! `docs/corpus-catalog.md` for the generator). The fixture was captured while
//! a held reader connection blocked checkpointing, so the `-wal` sidecar holds
//! one committed COMMIT frame for page 2 that the main file does not yet reflect.
//!
//! Ground truth (cross-checked with the `sqlite3` CLI):
//! - main-only view:  id=1 title `Rust`, `visit_count` 5; 2 rows.
//! - WAL-applied view: id=1 title `Rust (EDITED IN WAL)`, `visit_count` 777;
//!   plus id=3 `WAL-ONLY ROW`; 3 rows.
//!
//! The reader must overlay the WAL WITHOUT mutating either file (the forensic-safe
//! alternative to libsqlite checkpointing).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use sqlite_core::{Database, Value};

const MAIN: &[u8] = include_bytes!("../../tests/data/wal_places.db");
const WAL: &[u8] = include_bytes!("../../tests/data/wal_places.db-wal");
const MOZ_PLACES_ROOT: u32 = 2;
const MOZ_PLACES_COLS: usize = 6;

#[test]
fn main_only_view_shows_pre_wal_state() {
    let db = Database::open(MAIN.to_vec()).expect("open main");
    let rows = db
        .read_table(MOZ_PLACES_ROOT, MOZ_PLACES_COLS)
        .expect("walk");
    assert_eq!(rows.len(), 2, "main file has 2 committed rows");
    assert_eq!(rows[0].values[2], Value::Text("Rust".into()));
    assert_eq!(rows[0].values[3], Value::Integer(5));
}

#[test]
fn wal_applied_view_overlays_committed_frame() {
    let db = Database::open_with_wal(MAIN.to_vec(), WAL).expect("open with wal");
    assert!(db.wal_applied(), "WAL frames were overlaid");

    let rows = db
        .read_table(MOZ_PLACES_ROOT, MOZ_PLACES_COLS)
        .expect("walk wal-applied");

    // The overlay changed page 2: id=1 title + visit_count updated, and a third
    // row appeared — all from the WAL, none of it written back to the file.
    assert_eq!(rows.len(), 3, "WAL adds a third row");
    assert_eq!(
        rows[0].values[2],
        Value::Text("Rust (EDITED IN WAL)".into()),
        "WAL overlay changed the title"
    );
    assert_eq!(rows[0].values[3], Value::Integer(777));
    assert_eq!(rows[2].values[2], Value::Text("WAL-ONLY ROW".into()));
}

#[test]
fn open_without_wal_does_not_claim_wal_applied() {
    let db = Database::open(MAIN.to_vec()).expect("open");
    assert!(!db.wal_applied());
}

#[test]
fn empty_wal_overlays_nothing() {
    // A WAL with only its 32-byte header (no frames) is a no-op overlay.
    let mut empty_wal = vec![0u8; 32];
    empty_wal[0..4].copy_from_slice(&0x377f_0682u32.to_be_bytes());
    let db = Database::open_with_wal(MAIN.to_vec(), &empty_wal).expect("open empty wal");
    let rows = db
        .read_table(MOZ_PLACES_ROOT, MOZ_PLACES_COLS)
        .expect("walk");
    assert_eq!(rows.len(), 2, "no frames → main-only state");
    assert_eq!(rows[0].values[2], Value::Text("Rust".into()));
}
