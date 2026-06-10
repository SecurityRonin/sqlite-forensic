//! Version-aware carving: an `UPDATE` frees the OLD version of a row into slack
//! while the NEW version keeps the SAME rowid. That old version is genuinely
//! deleted content — often THE evidence (an edited message, a changed amount) —
//! so it must be recovered, not dropped.
//!
//! The fixture `updated_messages.db` INSERTs 50 rows then edits row 7's `body`
//! twice (grow, then shrink) under `secure_delete=OFF`, so the intermediate
//! version survives in freed space as a cleanly-carvable prior version whose
//! values differ from the live row. See `docs/corpus-catalog.md`.
//!
//! Before this fix, `carve_all_deleted_records` filtered out ANY carved record
//! whose rowid is currently live (to suppress b-tree-rebalance stale copies) —
//! a blunt filter that also dropped this genuine prior version (a false
//! negative). The fix is value-aware classification: a carved record whose rowid
//! is live but whose VALUES differ from the live row is a deleted prior version
//! and is recovered.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use sqlite_core::{Database, Value};
use sqlite_forensic::{carve_all_deleted_records, RecoverySource};

const UPDATED: &[u8] = include_bytes!("../../tests/data/updated_messages.db");

/// The OLD (pre-update) version of row 7 — body `"PRIORVERSION secret …"` —
/// must be recovered, even though rowid 7 is still live (with a DIFFERENT body,
/// `"EDITED final body"`). This is the false-negative → true-positive conversion.
#[test]
fn recovers_pre_update_prior_version() {
    let db = Database::open(UPDATED.to_vec()).expect("open updated_messages.db");
    let carved = carve_all_deleted_records(&db);

    // The prior version of rowid 7 carries the pre-edit body.
    let prior = carved
        .iter()
        .find(|c| matches!(c.values.get(2), Some(Value::Text(t)) if t.starts_with("PRIORVERSION")));

    assert!(
        prior.is_some(),
        "must recover the pre-update prior version of row 7 (the edited-message evidence); \
         got {} carved records",
        carved.len()
    );
    let prior = prior.unwrap();

    // It is the SAME rowid as the live row, but a DIFFERENT (older) value.
    assert_eq!(prior.rowid, 7, "prior version keeps the original rowid");
    assert!(
        !prior.allocated,
        "a prior version lives in unallocated space"
    );

    // It is classified as a prior-version recovery (distinct from a freed-page or
    // dropped-table recovery), so an examiner can weigh it as an edit history.
    assert_eq!(
        prior.source,
        RecoverySource::PriorVersion,
        "a value-differing same-rowid recovery is a prior version"
    );
}
