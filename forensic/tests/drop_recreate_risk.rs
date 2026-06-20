//! Drop-recreate residue DIAGNOSTIC HINT (`table_instance_risk`, Detector A) over
//! the committed `tests/data/drop_recreate/` fixtures.
//!
//! Per `docs/design/drop-recreate-attribution.md` (the Codex soundness
//! correction), this is a non-overclaiming HINT, not a per-row predecessor
//! classifier:
//!
//! - `b_autoinc.db` (AUTOINCREMENT, drop-recreate) → the flag FIRES on residue
//!   rowids 6..=10, which exceed `sqlite_sequence(students)=5`.
//! - `b_plainpk.db` (plain INTEGER PRIMARY KEY) → the flag NEVER fires (no
//!   `sqlite_sequence`), the honest-limit characterization.
//! - `upd_autoinc.db` (Codex BLOCKER-1) → the flag FIRES on residue rowid 1000
//!   even though that row was a CURRENT-instance row an `UPDATE` moved past the
//!   high-water mark — proving the flag is a hint, never a predecessor assertion.
//! - anti-regression: across ordinary Nemetz deleted-row databases the flag
//!   fires on ZERO records (no Nemetz db is a same-name AUTOINCREMENT recreate).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use sqlite_core::Database;
use sqlite_forensic::{
    attribute_records, carve_all_deleted_records, table_instance_risks, TableInstanceRisk,
};

const B_AUTOINC: &[u8] = include_bytes!("../../tests/data/drop_recreate/b_autoinc.db");
const B_PLAINPK: &[u8] = include_bytes!("../../tests/data/drop_recreate/b_plainpk.db");
const UPD_AUTOINC: &[u8] = include_bytes!("../../tests/data/drop_recreate/upd_autoinc.db");

/// The (rowid, seq) pairs the flag fired on, sorted by rowid.
fn fired(recs: &[sqlite_forensic::CarvedRecord], risks: &[TableInstanceRisk]) -> Vec<(i64, i64)> {
    let mut out: Vec<(i64, i64)> = recs
        .iter()
        .zip(risks)
        .filter_map(|(_rec, risk)| match risk {
            TableInstanceRisk::RowidExceedsAutoincHighwater { rowid, seq, .. } => {
                Some((*rowid, *seq))
            }
            _ => None,
        })
        .collect();
    out.sort_unstable();
    out
}

fn risks_for(bytes: &[u8]) -> (Vec<sqlite_forensic::CarvedRecord>, Vec<TableInstanceRisk>) {
    let db = Database::open(bytes.to_vec()).expect("open fixture");
    let recs = carve_all_deleted_records(&db);
    let attrs = attribute_records(&db, &recs);
    let risks = table_instance_risks(&db, &recs, &attrs);
    assert_eq!(risks.len(), recs.len(), "one risk per record");
    (recs, risks)
}

/// `b_autoinc.db`: residue rowids 6..=10 exceed `sqlite_sequence=5` → flag fires on
/// exactly those, each carrying the evidence (rowid, seq=5).
#[test]
fn b_autoinc_flags_residue_above_highwater() {
    let (recs, risks) = risks_for(B_AUTOINC);
    let hits = fired(&recs, &risks);
    let rowids: Vec<i64> = hits.iter().map(|(r, _)| *r).collect();
    assert_eq!(
        rowids,
        vec![6, 7, 8, 9, 10],
        "flag fires on residue rowids 6..=10 only"
    );
    for (_, seq) in &hits {
        assert_eq!(*seq, 5, "evidence seq is the high-water mark 5");
    }
}

/// `b_plainpk.db`: no `sqlite_sequence` ⟹ the flag never fires, even though the
/// same residue rowids 6..=10 are recovered (the honest undecidable limit).
#[test]
fn b_plainpk_never_flags() {
    let (recs, risks) = risks_for(B_PLAINPK);
    assert!(
        !recs.is_empty(),
        "plain-PK residue is still recovered (only the flag is withheld)"
    );
    assert!(
        fired(&recs, &risks).is_empty(),
        "no sqlite_sequence ⟹ the flag must NEVER fire"
    );
}

/// `upd_autoinc.db` — Codex BLOCKER-1: the residue rowid 1000 exceeds
/// `sqlite_sequence=5` and the flag FIRES, yet that row was a CURRENT-instance row
/// an `UPDATE` moved past the high-water mark, then deleted. The flag is a HINT —
/// it correctly does NOT assert this is a dropped predecessor.
#[test]
fn upd_autoinc_flags_a_current_instance_row_proving_hint_not_assertion() {
    let (recs, risks) = risks_for(UPD_AUTOINC);
    let hits = fired(&recs, &risks);
    assert_eq!(
        hits,
        vec![(1000, 5)],
        "flag fires on the moved-then-deleted current row (rowid 1000 > seq 5)"
    );
}

/// Anti-regression: across ordinary Nemetz deleted-row databases the flag fires
/// on ZERO records (none is a same-name AUTOINCREMENT drop-recreate), so the
/// diagnostic never spuriously fires on ordinary deleted rows.
#[test]
fn nemetz_databases_never_spuriously_flag() {
    for rel in ["nemetz/0C/0C-01.db", "nemetz/0D/0D-01.db"] {
        let path = format!("{}/../tests/data/{rel}", env!("CARGO_MANIFEST_DIR"));
        let Ok(bytes) = std::fs::read(&path) else {
            continue; // corpus db absent ⟹ skip cleanly (env-gated provenance)
        };
        let db = Database::open(bytes).expect("open nemetz db");
        let recs = carve_all_deleted_records(&db);
        let attrs = attribute_records(&db, &recs);
        let risks = table_instance_risks(&db, &recs, &attrs);
        assert!(
            risks.iter().all(|r| *r == TableInstanceRisk::None),
            "{rel}: ordinary Nemetz deleted rows must NEVER trip the flag"
        );
    }
}

/// The human note shows its evidence (rowid + seq + table) and uses
/// "consistent with" framing — never the word "predecessor" as an assertion.
#[test]
fn note_is_evidence_bearing_and_non_overclaiming() {
    let risk = TableInstanceRisk::RowidExceedsAutoincHighwater {
        table: "students".to_string(),
        rowid: 10,
        seq: 5,
    };
    let note = risk.note();
    assert!(note.contains("rowid 10"), "note shows the rowid");
    assert!(note.contains("students"), "note shows the table");
    assert!(
        note.contains("sqlite_sequence=5"),
        "note shows the seq evidence"
    );
    assert!(
        note.contains("consistent with"),
        "note uses consistent-with framing"
    );
    assert!(
        !note.to_lowercase().contains("predecessor"),
        "note must never assert 'predecessor'"
    );
    // None carries no note.
    assert!(TableInstanceRisk::None.note().is_empty());
}
