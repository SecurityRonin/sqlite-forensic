//! Known-answer + robustness validation against the **NIST CFReDS SQLite**
//! corpus (CFTT SQLite data-recovery test sets), the authoritative,
//! independently-authored ground truth for deleted/modified-record recovery.
//!
//! - **SFT-03 WAL** ("deleted and modified records"): NIST committed 100 deletes
//!   into the write-ahead log of a 2240-row `invoice_items` table without
//!   checkpointing. The main database therefore still holds all 2240 rows
//!   (the pre-delete state) while the `-wal` carries the deletions — our WAL
//!   handling must surface *both* states, with the documented delta of 100.
//! - **Corrupted header** (SharifCTF "crashed db"): a real damaged-header file
//!   must fail to open with a typed error, never a panic.
//! - **No-panic robustness** over every CFReDS database, mirroring the Nemetz
//!   robustness floor.
//!
//! Provenance + per-file NIST MD5s: `tests/data/README.md`.
//!
//! NOTE (documented limitation, see `tests/data/README.md` § known gaps): the
//! SFT-03 *PERSIST* (rollback-journal) deletions are recoverable only from the
//! `-journal` sidecar, which the carver does not yet parse. That recovery
//! substrate is tracked as a pending capability, not asserted here.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::pedantic)]

use std::path::{Path, PathBuf};

use sqlite_core::Database;
use sqlite_forensic::{audit, carve_with_fragments, row_histories_with_residue};

fn cfreds(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../tests/data/cfreds")
        .join(name)
}

fn invoice_items_rows(db: &Database) -> usize {
    db.live_table_rows()
        .iter()
        .find(|d| d.name == "invoice_items")
        .map_or(0, |d| d.rows.len())
}

#[test]
fn sft03_wal_surfaces_uncheckpointed_deletions() {
    // NIST ground truth: 2240 rows live, 100 deleted via an uncheckpointed WAL.
    for platform in ["ios", "android"] {
        let main = std::fs::read(cfreds(&format!("sft-03-WAL_{platform}.sqlite"))).unwrap();
        let wal = std::fs::read(cfreds(&format!("sft-03-WAL_{platform}.sqlite-wal"))).unwrap();

        // Main database alone = the pre-delete state (deletions not checkpointed).
        let main_only = Database::open(main.clone()).expect("open main");
        assert_eq!(
            invoice_items_rows(&main_only),
            2240,
            "{platform}: main db retains all rows until checkpoint"
        );

        // With the WAL applied = the current (post-delete) state.
        let applied = Database::open_with_wal(main, &wal).expect("open_with_wal");
        assert!(applied.wal_applied(), "{platform}: WAL frames were applied");
        assert_eq!(
            invoice_items_rows(&applied),
            2140,
            "{platform}: WAL-applied view reflects the 100 deletions"
        );

        // The WAL timeline must expose at least one materializable commit.
        let timeline = applied
            .wal_timeline()
            .expect("uncheckpointed WAL yields a timeline");
        assert!(
            !timeline.commit_snapshots().is_empty(),
            "{platform}: at least one commit snapshot"
        );
    }
}

#[test]
fn corrupted_header_fails_typed_not_panicking() {
    // SharifCTF "crashed db": the 100-byte SQLite header is overwritten. Opening
    // it must yield a typed Err (graceful), never an abort/panic/wrong output.
    let bytes =
        std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/data/sharifctf/db0.db"))
            .unwrap();
    assert_ne!(
        &bytes[..16],
        b"SQLite format 3\0",
        "fixture must be header-damaged"
    );
    // Any typed error is acceptable; the contract is "no panic, no false-open".
    match Database::open(bytes) {
        Ok(_) => panic!("a damaged-header db must not open as a valid database"),
        Err(e) => {
            let _ = format!("{e:?}");
        }
    }
}

#[test]
fn all_cfreds_databases_survive_the_pipeline_without_panic() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/data/cfreds");
    let mut walked = 0usize;
    for entry in std::fs::read_dir(&dir).expect("cfreds dir") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("sqlite") {
            continue; // skip -wal/-shm/-journal sidecars and the .rtf doc
        }
        let bytes = std::fs::read(&path).unwrap();
        // Attach a -wal sidecar when present so the WAL path is exercised too.
        let wal_path = path.with_extension("sqlite-wal");
        let db = if wal_path.exists() {
            Database::open_with_wal(bytes, &std::fs::read(&wal_path).unwrap())
        } else {
            Database::open(bytes)
        };
        let Ok(db) = db else { continue };
        walked += 1;

        // Full analyzer pipeline: must not panic, must return structurally.
        let tiers = carve_with_fragments(&db);
        for r in &tiers.full {
            assert!(
                !r.values.is_empty(),
                "a carved full row has at least one cell"
            );
        }
        let _ = audit(&db);
        let _ = row_histories_with_residue(&db);
        let _ = db.live_table_rows();
    }
    assert!(
        walked >= 10,
        "exercised the full CFReDS sqlite set, got {walked}"
    );
}
