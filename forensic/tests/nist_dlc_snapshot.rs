//! **Tier-1** real-data validation against the NIST `CFReDS` *Data Leakage Case*.
//!
//! `snapshot.db` is the Google Drive client database recovered from a **Volume
//! Shadow Copy** of the case's PC disk image (`cfreds_2015_data_leakage_pc`,
//! ~20 GB; the 20 KB SQLite file is U.S.-Government public domain). NIST's
//! published answer to question 49 ("What files were deleted from Google Drive?")
//! is: find the deleted records of the `cloud_entry` table inside `snapshot.db`.
//! The live table holds only the Drive `root`; the two deleted file entries are
//! `do_u_wanna_build_a_snow_man.mp3` (a clean freed cell) and `happy_holiday.jpg`
//! (a freeblock-clobbered cell — its first four bytes overwritten).
//!
//! This is the strongest Doer-Checker form: an independent third party authored
//! both the artifact and the answer key. Neither the input nor the ground truth
//! is ours. Provenance + extraction recipe: `tests/data/README.md`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use sqlite_core::{Database, Value};
use sqlite_forensic::carve_all_deleted_records;

const SNAPSHOT: &[u8] = include_bytes!("../../tests/data/nist_dlc_snapshot.db");

fn recovered_texts(db: &Database) -> Vec<String> {
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
fn recovers_both_deleted_cloud_entry_files() {
    let db = Database::open(SNAPSHOT.to_vec()).expect("snapshot.db opens");
    let texts = recovered_texts(&db);

    // The clean freed record (RowID 3) — full filename recovered intact.
    assert!(
        texts.iter().any(|t| t == "do_u_wanna_build_a_snow_man.mp3"),
        "NIST DLC: the clean deleted cloud_entry (do_u_wanna_build_a_snow_man.mp3) \
         must be recovered; got {texts:?}"
    );

    // The freeblock-clobbered record — its first 4 bytes (and so the head of the
    // filename) are destroyed, but the surviving tail of `happy_holiday.jpg`
    // (`…holiday.jpg`) is reconstructed.
    assert!(
        texts.iter().any(|t| t.ends_with("holiday.jpg")),
        "NIST DLC: the freeblock-clobbered deleted cloud_entry (happy_holiday.jpg) \
         must be reconstructed from its surviving tail; got {texts:?}"
    );
}

#[test]
fn never_resurfaces_the_live_root_row() {
    // The only LIVE cloud_entry row is the Drive `root`; a 0-false-positive carve
    // must never emit it as recovered (deleted) content.
    let db = Database::open(SNAPSHOT.to_vec()).expect("snapshot.db opens");
    for rec in carve_all_deleted_records(&db) {
        // The live root row is `(doc_id, 'root', …)` with a NULL filename tail; a
        // recovered record equal to it would be a re-surfaced live row.
        let is_root_shape = rec
            .values
            .iter()
            .any(|v| matches!(v, Value::Text(t) if t == "root"))
            && rec.values.len() >= 11;
        assert!(
            !is_root_shape,
            "0-FP: the live Drive root row must not be re-surfaced as deleted: {:?}",
            rec.values
        );
    }
}
