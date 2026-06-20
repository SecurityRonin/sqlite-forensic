//! Carved-residue merge into the row VERSION HISTORY (Phase 1, increment 4).
//!
//! [`row_histories_with_residue`] augments the core [`Database::row_histories`]
//! base with free-space carved residue: ORDER-UNKNOWN records (freeblocks persist
//! across commits) emitted as `origin: CarvedResidue`, `view_state: CarvedResidue`,
//! `commit_seq: None`, `is_deleted: true` — never a fabricated commit position —
//! attributed to a table and deduped against any WAL `AbsentInFinalView` version
//! of the same rowid + values.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use sqlite_core::row_history::{VersionOrigin, ViewState};
use sqlite_core::{Database, Value};
use sqlite_forensic::row_histories_with_residue;

/// The `updated_messages.db` fixture holds the genuine PRIOR version of row 7
/// ("PRIORVERSION…") in slack — recoverable ONLY by carving, never a live row.
/// It must surface as an order-unknown CarvedResidue version of `messages`, with
/// no fabricated commit_seq.
#[test]
fn carved_prior_version_is_order_unknown_residue() {
    let db_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/data/updated_messages.db");
    let db = Database::open(std::fs::read(&db_path).unwrap()).unwrap();
    assert!(!db.wal_applied(), "fixture has no -wal");

    let histories = row_histories_with_residue(&db);
    let m = histories
        .iter()
        .find(|h| h.table == "messages")
        .expect("messages table present");

    // The carved prior version of row 7 is present as CarvedResidue.
    let residue: Vec<_> = m
        .versions
        .iter()
        .filter(|v| v.origin == VersionOrigin::CarvedResidue)
        .collect();
    assert!(
        !residue.is_empty(),
        "the carved prior version must surface as residue"
    );
    let prior = residue
        .iter()
        .find(|v| matches!(v.values.get(2), Some(Value::Text(t)) if t.starts_with("PRIORVERSION")))
        .expect("the genuine prior version of row 7 is carved");

    // Order-unknown discipline: no fabricated commit position.
    assert_eq!(prior.view_state, ViewState::CarvedResidue);
    assert_eq!(
        prior.commit_seq, None,
        "carved residue is order-unknown — never a fabricated commit_seq"
    );
    assert!(prior.is_deleted, "carved residue is deleted content");

    // The live row 7 ("EDITED final body") must still be the present current row,
    // never re-surfaced as residue.
    assert!(
        m.versions.iter().any(|v| {
            v.origin == VersionOrigin::Live
                && matches!(v.values.get(2), Some(Value::Text(t)) if t == "EDITED final body")
        }),
        "the live edited row 7 remains PresentInFinalView"
    );
    assert!(
        !m.versions.iter().any(|v| {
            v.origin == VersionOrigin::CarvedResidue
                && matches!(v.values.get(2), Some(Value::Text(t)) if t == "EDITED final body")
        }),
        "the live row is never re-listed as carved residue"
    );
}

/// Without any carvable residue beyond what the WAL already shows, the residue
/// merge adds nothing the base history did not have (no double-listing). The
/// deleted_places fixture's deleted rows are carved residue with no WAL, so they
/// appear exactly once as CarvedResidue.
#[test]
fn residue_is_not_double_listed() {
    let db_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/data/deleted_places.db");
    let db = Database::open(std::fs::read(&db_path).unwrap()).unwrap();

    let histories = row_histories_with_residue(&db);
    // Collect every (rowid, values-debug) pair; no exact duplicate version.
    for h in &histories {
        let mut seen = std::collections::HashSet::new();
        for v in &h.versions {
            let key = format!("{:?}:{:?}:{:?}", v.rowid, v.values, v.origin);
            assert!(
                seen.insert(key.clone()),
                "duplicate version in {}: {key}",
                h.table
            );
        }
    }
}
