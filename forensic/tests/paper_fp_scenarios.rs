//! CHARACTERIZATION of our carver against the three false-positive scenarios
//! from Lee, Park, Lee & Choi, "A study on the false positives of existing tools
//! for recovering deleted records in SQLite databases", FSI:DI 55 (2025),
//! art. 302031 (DOI 10.1016/j.fsidi.2025.302031), Table 5.
//!
//! These assert CURRENT behavior over the committed `tests/data/paper_fp/`
//! fixtures — REPLICATIONS of the paper's scenario construction built with the
//! real sqlite3 engine, NOT the paper's official corpus (which is not yet
//! public; see `tests/data/paper_fp/README.md`). No new feature is introduced,
//! so there is no RED phase.
//!
//! The cross-tool measurement (our carver vs `bring2lite` vs the SQLite Deleted
//! Records Parser, scored on identical bytes) lives in
//! `docs/competitive-landscape.md`; this file pins the structural facts those
//! numbers rest on:
//!
//! - **0F (B-tree rebalancing, Type \*\*):** the carver surfaces truly-deleted
//!   rows but ZERO live rowids — the structural guarantee that produces 0 false
//!   positives where freed-page carvers that don't exclude live rowids produce
//!   them.
//! - **10 (WAL + `secure_delete=ON`):** all 20 deleted rows are recovered from the
//!   `-wal`, where the on-disk image holds none of them.
//! - **0B (overwritten table, same schema, Type \*):** the OLD dropped-table
//!   residue (rowids 6..=10) is recovered, flagged deleted and disjoint from the
//!   live set 1..=5 — but attributed by page ownership to the recreated
//!   same-name table (we do not explicitly detect the drop-recreate). This test
//!   documents that attribution rather than claiming a clean drop-recreate
//!   detection.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use sqlite_core::{Database, Value};
use sqlite_forensic::carve_all_deleted_records;

const F_DB: &[u8] = include_bytes!("../../tests/data/paper_fp/f.db");
const B_DB: &[u8] = include_bytes!("../../tests/data/paper_fp/b.db");
const W_DB: &[u8] = include_bytes!("../../tests/data/paper_fp/wcase.db");
const W_WAL: &[u8] = include_bytes!("../../tests/data/paper_fp/wcase.db-wal");

/// Distinct recovered rowids, sorted.
fn recovered_rowids(recs: &[sqlite_forensic::CarvedRecord]) -> Vec<i64> {
    let mut ids: Vec<i64> = recs.iter().map(|r| r.rowid).collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

fn text(v: &Value) -> &str {
    match v {
        Value::Text(s) => s.as_str(),
        _ => "",
    }
}

/// 0F — B-tree rebalancing. Ground truth: live ids 51..=80, deleted ids 1..=50.
/// The structural guarantee: the carver recovers truly-deleted rows and NEVER a
/// live rowid (zero Type-\*\* false positives), and every recovered record is
/// flagged unallocated.
#[test]
fn scenario_0f_rebalancing_zero_live_false_positives() {
    let db = Database::open(F_DB.to_vec()).expect("open f.db");
    let recs = carve_all_deleted_records(&db);
    let ids = recovered_rowids(&recs);

    let live_fps: Vec<i64> = ids
        .iter()
        .copied()
        .filter(|i| (51..=80).contains(i))
        .collect();
    let deleted: Vec<i64> = ids
        .iter()
        .copied()
        .filter(|i| (1..=50).contains(i))
        .collect();

    assert!(
        live_fps.is_empty(),
        "0F must surface ZERO live rowids (51..=80); got false positives {live_fps:?}"
    );
    assert!(
        !deleted.is_empty(),
        "0F must recover truly-deleted rows (1..=50); recovered none"
    );

    // Every recovered record carries the unallocated flag and a probability.
    for r in &recs {
        assert!(
            !r.allocated,
            "a carved record is never an allocated/live row"
        );
        assert!(
            r.confidence > 0.0 && r.confidence <= 1.0,
            "confidence is a probability in (0,1]"
        );
    }

    // The id-tagged payload lets us confirm the rowid reconstruction is sound:
    // a recovered row's `v` begins with `ROW-<its rowid>-`.
    for r in &recs {
        let expected = format!("ROW-{}-", r.rowid);
        assert!(
            text(&r.values[1]).starts_with(&expected),
            "row {} content must tag its own id; got {:?}",
            r.rowid,
            &text(&r.values[1])[..expected.len().min(text(&r.values[1]).len())]
        );
    }
}

/// 10 — WAL + `secure_delete=ON`. Ground truth: live 0, deleted ids 1..=20, with
/// residue ONLY in the `-wal`. All 20 deleted rows are recovered from the WAL.
#[test]
fn scenario_10_wal_secure_delete_recovers_all_twenty() {
    let db = Database::open_with_wal(W_DB.to_vec(), W_WAL).expect("open wcase.db + -wal");
    let recs = carve_all_deleted_records(&db);
    let ids = recovered_rowids(&recs);

    let recovered: Vec<i64> = ids
        .iter()
        .copied()
        .filter(|i| (1..=20).contains(i))
        .collect();
    assert_eq!(
        recovered.len(),
        20,
        "10 must recover all 20 deleted msg rows from the -wal; got {recovered:?}"
    );

    // The recovered bodies are the secret messages, keyed by id.
    for id in 1..=20i64 {
        let r = recs
            .iter()
            .find(|r| r.rowid == id && text(&r.values[1]) == format!("SECRET-MESSAGE-{id}"))
            .unwrap_or_else(|| panic!("secret body for id {id} must be recovered verbatim"));
        assert!(!r.allocated, "WAL-recovered record is unallocated");
    }
}

/// 0B — overwritten table, same schema. Ground truth: live ids 1..=5 (NEW-NAME),
/// dropped residue = 10 OLD-NAME rows. We recover the OLD residue rowids 6..=10
/// (the 5 whose cells survive the same-rowid reuse), flagged deleted and DISJOINT
/// from the live set 1..=5. They are attributed by page ownership to the
/// recreated `students` table — this test documents that page-ownership
/// attribution, not a drop-recreate detection.
#[test]
fn scenario_0b_overwritten_residue_disjoint_from_live() {
    let db = Database::open(B_DB.to_vec()).expect("open b.db");
    let recs = carve_all_deleted_records(&db);
    let ids = recovered_rowids(&recs);

    let live: std::collections::HashSet<i64> = (1..=5).collect();
    let intersect_live: Vec<i64> = ids.iter().copied().filter(|i| live.contains(i)).collect();
    assert!(
        intersect_live.is_empty(),
        "0B recovered residue must be DISJOINT from the live set 1..=5; overlap {intersect_live:?}"
    );

    // The OLD-NAME residue rowids 6..=10 are recovered as deleted records.
    for id in 6..=10i64 {
        let r = recs
            .iter()
            .find(|r| r.rowid == id)
            .unwrap_or_else(|| panic!("OLD residue rowid {id} must be recovered"));
        assert_eq!(
            text(&r.values[1]),
            format!("OLD-NAME-{id}"),
            "rowid {id} must carry its OLD-NAME residue content"
        );
        assert!(
            !r.allocated,
            "residue record is flagged deleted/unallocated"
        );
    }

    // No NEW-NAME live row is re-surfaced as a recovered (deleted) record.
    assert!(
        !recs
            .iter()
            .any(|r| text(&r.values[1]).starts_with("NEW-NAME")),
        "no live NEW-NAME row may appear in the recovered (deleted) set"
    );
}
