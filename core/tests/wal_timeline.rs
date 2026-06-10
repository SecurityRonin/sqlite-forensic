//! Bespoke, format-exact WAL temporal model (`WalTimeline`) — task #55.
//!
//! Validated against the REAL `wal_carve.db` + `-wal` fixture (`docs/corpus-catalog.md`
//! §J): a `wal_checkpoint(TRUNCATE)` baseline (rows 1..=50, WAL emptied) then —
//! with a held reader blocking checkpoint — an INSERT commit (rows 101..=150) and a
//! DELETE commit (rows 121..=140), **no checkpoint**. The `-wal` therefore holds ONE
//! salt segment with TWO COMMIT frames (both rewriting page 2). That is exactly two
//! materializable commit snapshots in one segment.
//!
//! These tests pin the bespoke model's public contract: enumerate the commit
//! snapshots (each addressable by `CommitId`), materialize each as a read-only replay
//! overlay, diff base-vs-last-commit, and reject a malformed WAL at the right
//! validation tier (page-size mismatch = hard stop).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use sqlite_core::{
    CohortTopology, Database, MaterializationSafety, WalLsn, WalValidationError,
};

const CARVE_MAIN: &[u8] = include_bytes!("../../tests/data/wal_carve.db");
const CARVE_WAL: &[u8] = include_bytes!("../../tests/data/wal_carve.db-wal");

// --- segment / snapshot enumeration -----------------------------------------

#[test]
fn timeline_enumerates_one_segment_two_commit_snapshots() {
    let db = Database::open_with_wal(CARVE_MAIN.to_vec(), CARVE_WAL).expect("open with wal");
    let tl = db.wal_timeline().expect("timeline present");

    // One salt epoch (no checkpoint reset between the two commits).
    assert_eq!(tl.segments().len(), 1, "single salt segment");
    let seg = &tl.segments()[0];
    assert_eq!(seg.frame_count, 2, "two frames in the segment");
    assert!(seg.salt1 != 0 && seg.salt2 != 0, "segment carries WAL salts");
    assert_eq!(seg.page_size, db.header().page_size);

    // Two COMMIT frames → two materializable commit snapshots.
    let snaps = tl.commit_snapshots();
    assert_eq!(snaps.len(), 2, "two materializable commit snapshots");

    // CommitId = (segment_id, commit_frame_index, db_size_after_commit). Both
    // commits leave a 2-page database; the commit frame indices are the file-order
    // positions of the two COMMIT frames (0 then 1 here).
    assert_eq!(snaps[0].id().commit_frame_index, 0);
    assert_eq!(snaps[1].id().commit_frame_index, 1);
    assert_eq!(snaps[0].id().db_size_after_commit, 2);
    assert_eq!(snaps[1].id().db_size_after_commit, 2);
    // Both snapshots belong to the one segment.
    assert_eq!(snaps[0].id().segment, seg.id);
    assert_eq!(snaps[1].id().segment, seg.id);
}

#[test]
fn single_segment_topology_is_linear() {
    let db = Database::open_with_wal(CARVE_MAIN.to_vec(), CARVE_WAL).expect("open with wal");
    let tl = db.wal_timeline().expect("timeline present");
    assert_eq!(
        tl.topology(),
        CohortTopology::LinearSegment,
        "one salt epoch with no reset is a linear cohort"
    );
}

// --- materialization (replay overlay) ---------------------------------------

#[test]
fn materialize_last_commit_recovers_surviving_rows_not_deleted_ones() {
    let db = Database::open_with_wal(CARVE_MAIN.to_vec(), CARVE_WAL).expect("open with wal");
    let tl = db.wal_timeline().expect("timeline present");
    let snaps = tl.commit_snapshots();

    // db_size_after_commit pins the database page count at each commit.
    assert_eq!(snaps[1].db_size_after_commit(), 2);

    // The newest commit's page-2 image is the post-DELETE state: it still carries the
    // surviving body text (e.g. row 101) but the freed cells for 121..=140 are gone
    // from the live area (their residue survives only as slack — that is the carver's
    // job, not the consistent snapshot's).
    let page2 = snaps[1]
        .page_version(2)
        .expect("page 2 present at last commit");
    assert_eq!(page2.page_no, 2);
    assert_eq!(page2.bytes.len(), db.header().page_size as usize);
    let surviving = b"secret WAL body 101";
    assert!(
        page2.bytes.windows(surviving.len()).any(|w| w == surviving),
        "surviving row 101 present in the materialized last-commit page"
    );
}

#[test]
fn materialize_first_commit_holds_rows_before_the_delete() {
    let db = Database::open_with_wal(CARVE_MAIN.to_vec(), CARVE_WAL).expect("open with wal");
    let tl = db.wal_timeline().expect("timeline present");
    let snaps = tl.commit_snapshots();

    // At the FIRST commit (the INSERT), a row later DELETEd (e.g. 130) is still live
    // in the page image — the earlier snapshot is a genuinely-different db state.
    let page2 = snaps[0]
        .page_version(2)
        .expect("page 2 present at first commit");
    let deleted_later = b"secret WAL body 130";
    assert!(
        page2.bytes.windows(deleted_later.len()).any(|w| w == deleted_later),
        "row 130 is live at the INSERT commit (deleted only at the second commit)"
    );
}

#[test]
fn materialize_by_commit_id_is_stable() {
    let db = Database::open_with_wal(CARVE_MAIN.to_vec(), CARVE_WAL).expect("open with wal");
    let tl = db.wal_timeline().expect("timeline present");
    let snaps = tl.commit_snapshots();
    let id = snaps[0].id();
    // Re-resolving by CommitId yields the same snapshot.
    let resolved = tl.snapshot_at(id).expect("resolve by CommitId");
    assert_eq!(resolved.id(), id);
    assert_eq!(resolved.db_size_after_commit(), snaps[0].db_size_after_commit());
}

// --- diff: base vs last valid commit ----------------------------------------

#[test]
fn diff_base_vs_last_commit_identifies_changed_pages() {
    let db = Database::open_with_wal(CARVE_MAIN.to_vec(), CARVE_WAL).expect("open with wal");
    let tl = db.wal_timeline().expect("timeline present");

    let diff = tl.diff_base_to_last_commit().expect("diff present");
    // The INSERT/DELETE activity rewrote page 2; the base never held those rows.
    assert!(
        diff.changed_pages().contains(&2),
        "page 2 changed between the acquired base and the last WAL commit"
    );
    // Page 1 (schema/header) was untouched by the row edits.
    assert!(
        !diff.changed_pages().contains(&1),
        "page 1 (schema) is unchanged across the segment"
    );
}

// --- validation tiers --------------------------------------------------------

#[test]
fn valid_wal_clears_all_three_validation_tiers() {
    let db = Database::open_with_wal(CARVE_MAIN.to_vec(), CARVE_WAL).expect("open with wal");
    let tl = db.wal_timeline().expect("timeline present");
    assert_eq!(
        tl.safety(),
        MaterializationSafety::ReplaySafe,
        "a well-formed single-segment WAL is replay-safe"
    );
}

#[test]
fn page_size_mismatch_is_a_hard_stop_at_physical_validation() {
    // A WAL header that declares a different page size than the DB header must be
    // rejected at the PhysicalValidation tier — never silently mis-sliced.
    let mut bad_wal = CARVE_WAL.to_vec();
    // WAL header page-size field is at offset 8 (big-endian u32). The DB is 4096;
    // claim 8192 to force the mismatch.
    bad_wal[8..12].copy_from_slice(&8192u32.to_be_bytes());
    let err = Database::wal_timeline_from(CARVE_MAIN, &bad_wal)
        .expect_err("page-size mismatch must be rejected");
    assert_eq!(err, WalValidationError::PageSizeMismatch { db: 4096, wal: 8192 });
}

#[test]
fn checksum_break_in_header_magic_is_rejected_at_physical_validation() {
    // Corrupt the WAL magic so the header fails the format check.
    let mut bad_wal = CARVE_WAL.to_vec();
    bad_wal[0] ^= 0xFF;
    let err = Database::wal_timeline_from(CARVE_MAIN, &bad_wal)
        .expect_err("bad magic must be rejected");
    assert_eq!(err, WalValidationError::BadMagic);
}

#[test]
fn absent_wal_yields_no_timeline_not_an_error() {
    // A main DB opened without a WAL has no timeline (None), never an error.
    let db = Database::open(CARVE_MAIN.to_vec()).expect("open");
    assert!(db.wal_timeline().is_none(), "no WAL → no timeline");
}

// --- [H] adapter seam --------------------------------------------------------

#[test]
fn lsn_seam_exposes_salt_qualified_frame_index() {
    // The future state-history-forensic [H] adapter maps to
    // LsnKind::SqliteWal { salt1, salt2, frame_index } — NEVER a bare frame_index.
    // The bespoke model exposes exactly that triple via WalLsn so the adapter can
    // attach without sqlite-core depending on state-history-forensic.
    let db = Database::open_with_wal(CARVE_MAIN.to_vec(), CARVE_WAL).expect("open with wal");
    let tl = db.wal_timeline().expect("timeline present");
    let snaps = tl.commit_snapshots();

    let lsn: WalLsn = snaps[1].lsn();
    assert_eq!(lsn.frame_index, 1);
    let seg = &tl.segments()[0];
    assert_eq!(lsn.salt1, seg.salt1, "LSN is salt-qualified, not bare");
    assert_eq!(lsn.salt2, seg.salt2);

    // tamper-resistance is LOW: WAL checksums detect corruption, not tampering.
    assert!(
        !tl.checksums_are_tamper_evident(),
        "WAL checksums are non-cryptographic — corruption detection only"
    );
}
