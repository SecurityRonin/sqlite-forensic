//! `carve` WAL N-snapshot enumeration (task #63): with a `-wal` sidecar present,
//! `carve` must carve EVERY materializable state — the on-disk base image, EACH
//! commit snapshot, and the WAL-frame residue — and label every recovered record
//! by its snapshot/LSN. `--no-wal` collapses to the on-disk-only view.
//!
//! Driven against the REAL `wal_carve.db` + `-wal` fixture (corpus-catalog §J):
//! ONE salt segment, TWO commit snapshots (INSERT then DELETE), WAL-frame residue
//! for ids 121..=140, and 0 residue tail.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use sqlite4n6::{carve_wal_snapshots, snapshot_label};
use sqlite_core::{Database, Value};
use sqlite_forensic::RecoverySource;

const MAIN: &[u8] = include_bytes!("../../tests/data/wal_carve.db");
const WAL: &[u8] = include_bytes!("../../tests/data/wal_carve.db-wal");

fn body(n: i64) -> Value {
    Value::Text(format!("secret WAL body {n}"))
}

/// The full enumeration carves every materializable state — both commit
/// snapshots (the per-commit temporal model) plus the on-disk base image and the
/// WAL-frame residue — and labels each record by its LSN. The deleted ids
/// 121..=140 surface at the INSERT-commit snapshot, the earliest state in which
/// they are still recoverable as intact rows.
///
/// DEDUP / PRESENTATION (documented): a record identical in `(rowid, values)`
/// across views is collapsed to ONE copy carrying the EARLIEST label (a commit
/// snapshot over the later wal-frame/on-disk view). On `wal_carve.db` the
/// WAL-frame residue for 121..=140 is byte-identical to the INSERT-commit
/// snapshot's cells, so it collapses INTO `commit:(…,0)` rather than appearing
/// twice — the commit LSN is the meaningful temporal coordinate. A wal-frame /
/// on-disk label therefore appears only for residue NO commit snapshot covers.
#[test]
fn carve_enumerates_each_commit_snapshot_and_labels_by_lsn() {
    let db = Database::open_with_wal(MAIN.to_vec(), WAL).expect("open with wal");
    let tl = db.wal_timeline().expect("timeline present");
    let records = carve_wal_snapshots(&db, &tl);
    assert!(!records.is_empty(), "WAL enumeration recovered records");

    let labels: std::collections::HashSet<String> = records.iter().map(snapshot_label).collect();
    let lsn0 = tl.commit_snapshots()[0].lsn();
    let lsn1 = tl.commit_snapshots()[1].lsn();
    let commit0 = format!(
        "commit:({},{},{})",
        lsn0.salt1, lsn0.salt2, lsn0.frame_index
    );
    let commit1 = format!(
        "commit:({},{},{})",
        lsn1.salt1, lsn1.salt2, lsn1.frame_index
    );

    // BOTH commit snapshots are materialized and carved.
    assert!(
        labels.contains(&commit0),
        "first commit label present; saw {labels:?}"
    );
    assert!(
        labels.contains(&commit1),
        "second commit label present; saw {labels:?}"
    );

    // Every label is a valid LSN form (commit:, wal-frame:, or on-disk) — no record
    // is left unlabelled.
    for l in &labels {
        assert!(
            l == "on-disk" || l.starts_with("commit:(") || l.starts_with("wal-frame:("),
            "unexpected snapshot label form: {l}"
        );
    }

    // The deleted ids 121..=140 are recovered at the INSERT-commit snapshot LSN
    // (or, if not collapsed there, as wal-frame residue — both are honest).
    for n in 121..=140 {
        let at_first_commit = records
            .iter()
            .any(|r| r.values.contains(&body(n)) && snapshot_label(r) == commit0);
        let as_wal_frame = records
            .iter()
            .any(|r| r.values.contains(&body(n)) && r.source == RecoverySource::WalFrame);
        assert!(
            at_first_commit || as_wal_frame,
            "deleted id {n} surfaces at the INSERT commit and/or as wal-frame residue"
        );
    }
}

/// 0-FALSE-POSITIVE across the whole enumeration: no view re-surfaces a row that
/// is live in the final WAL-applied view (101..=120, 141..=150, 1..=50 survive).
#[test]
fn full_enumeration_never_resurfaces_a_live_row() {
    let db = Database::open_with_wal(MAIN.to_vec(), WAL).expect("open with wal");
    let tl = db.wal_timeline().expect("timeline present");
    let records = carve_wal_snapshots(&db, &tl);
    let live = db.live_rows();
    for rec in &records {
        let collides = live.values().any(|lv| lv == &rec.values);
        assert!(
            !collides,
            "enumeration re-surfaced a LIVE row {:?} ({})",
            rec.values,
            snapshot_label(rec)
        );
    }
}
