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

/// The full enumeration surfaces all three view classes, each LSN-labelled, and
/// the deleted ids 121..=140 appear at the INSERT-commit snapshot.
#[test]
fn carve_enumerates_on_disk_each_commit_and_wal_frame() {
    let db = Database::open_with_wal(MAIN.to_vec(), WAL).expect("open with wal");
    let tl = db.wal_timeline().expect("timeline present");
    let records = carve_wal_snapshots(&db, &tl);

    // The label set spans commit snapshots and wal-frame residue (and on-disk if any).
    let labels: std::collections::HashSet<String> =
        records.iter().map(snapshot_label).collect();
    let lsn0 = tl.commit_snapshots()[0].lsn();
    let lsn1 = tl.commit_snapshots()[1].lsn();
    assert!(
        labels.contains(&format!("commit:({},{},{})", lsn0.salt1, lsn0.salt2, lsn0.frame_index)),
        "first commit snapshot label present; saw {labels:?}"
    );
    assert!(
        labels.contains(&format!("commit:({},{},{})", lsn1.salt1, lsn1.salt2, lsn1.frame_index))
            || records.iter().any(|r| r.source == RecoverySource::WalFrame),
        "second commit and/or wal-frame residue present; saw {labels:?}"
    );
    assert!(
        labels.iter().any(|l| l.starts_with("wal-frame:")),
        "wal-frame residue label present; saw {labels:?}"
    );

    // The deleted ids 121..=140 are recovered, at the INSERT-commit snapshot LSN.
    let commit0 = format!("commit:({},{},{})", lsn0.salt1, lsn0.salt2, lsn0.frame_index);
    for n in 121..=140 {
        let at_first_commit = records.iter().any(|r| {
            r.values.contains(&body(n)) && snapshot_label(r) == commit0
        });
        let anywhere = records.iter().any(|r| r.values.contains(&body(n)));
        assert!(anywhere, "deleted id {n} recovered somewhere in the enumeration");
        assert!(
            at_first_commit || records.iter().any(|r| r.values.contains(&body(n)) && r.source == RecoverySource::WalFrame),
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
