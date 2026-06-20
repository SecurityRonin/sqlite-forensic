//! Detector B — the SOUND, table-level "sidecar schema-changed" diagnostic HINT
//! (`TableInstanceRisk::SidecarSchemaChanged`) over the committed
//! `tests/data/drop_recreate/` `-journal` fixtures.
//!
//! Per `docs/design/drop-recreate-attribution.md` (the Codex soundness
//! correction), Detector B is a TABLE-LEVEL boundary hint, NOT row-level
//! provenance. It fires ONLY on an UNAMBIGUOUS schema change to a table `T`
//! visible in a sidecar prior snapshot: the prior `sqlite_master` shows `T`
//! **absent** OR with a **different CREATE SQL text** than the current schema.
//!
//! - `b_journal_altered.db` + `-journal` (ALTER TABLE ADD COLUMN in the last,
//!   journaled transaction) → Detector B FIRES for `students` (prior CREATE SQL
//!   lacks the added column).
//! - `b_journal_dml.db` + `-journal` (DML-only last transaction) → Detector B
//!   does NOT fire (the anti-FP case: prior CREATE SQL equals current).
//! - anti-regression: a no-sidecar call (empty prior schema) NEVER fires, and the
//!   existing bare Detector-A fixtures NEVER trip B.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use sqlite_core::Database;
use sqlite_forensic::{
    attribute_records, carve_all_deleted_records, table_instance_risks_with_sidecar,
    TableInstanceRisk,
};

const B_ALTERED: &[u8] = include_bytes!("../../tests/data/drop_recreate/b_journal_altered.db");
const B_ALTERED_JRNL: &[u8] =
    include_bytes!("../../tests/data/drop_recreate/b_journal_altered.db-journal");
const B_DML: &[u8] = include_bytes!("../../tests/data/drop_recreate/b_journal_dml.db");
const B_DML_JRNL: &[u8] = include_bytes!("../../tests/data/drop_recreate/b_journal_dml.db-journal");
const B_AUTOINC: &[u8] = include_bytes!("../../tests/data/drop_recreate/b_autoinc.db");
const B_PLAINPK: &[u8] = include_bytes!("../../tests/data/drop_recreate/b_plainpk.db");

/// The set of table names Detector B fired `SidecarSchemaChanged` on.
fn b_fired_tables(risks: &[TableInstanceRisk]) -> std::collections::BTreeSet<String> {
    risks
        .iter()
        .filter_map(|r| match r {
            TableInstanceRisk::SidecarSchemaChanged { table } => Some(table.clone()),
            _ => None,
        })
        .collect()
}

/// Run the sidecar-aware pass: carve, attribute, read the prior schema from the
/// `-journal`, then compute the combined Detector-A+B risks.
fn risks_with_journal(
    main: &[u8],
    journal: &[u8],
) -> (
    Vec<sqlite_forensic::CarvedRecord>,
    Vec<TableInstanceRisk>,
    Database,
) {
    let db = Database::open(main.to_vec()).expect("open fixture");
    let recs = carve_all_deleted_records(&db);
    let attrs = attribute_records(&db, &recs);
    let prior = db
        .rollback_prior(journal)
        .expect("rollback_prior parses the PERSIST journal");
    let prior_schema = prior.schema_sql();
    let risks = table_instance_risks_with_sidecar(&db, &recs, &attrs, &prior_schema);
    assert_eq!(risks.len(), recs.len(), "one risk per record");
    (recs, risks, db)
}

/// `b_journal_altered.db` + `-journal`: the prior schema for `students` differs
/// from the current (the ALTER added a column), so Detector B FIRES for
/// `students` on residue attributed to it.
#[test]
fn altered_schema_fires_detector_b() {
    let (recs, risks, _db) = risks_with_journal(B_ALTERED, B_ALTERED_JRNL);
    assert!(!recs.is_empty(), "the altered fixture yields residue");
    let fired = b_fired_tables(&risks);
    assert!(
        fired.contains("students"),
        "Detector B fires for students on the altered-schema sidecar; got {fired:?}"
    );
}

/// `b_journal_dml.db` + `-journal`: the last transaction is DML only, so the
/// prior CREATE SQL equals the current — Detector B must NOT fire (the anti-FP
/// case the design refuses to mislabel).
#[test]
fn dml_only_does_not_fire_detector_b() {
    let (recs, risks, _db) = risks_with_journal(B_DML, B_DML_JRNL);
    assert!(!recs.is_empty(), "the dml fixture yields residue");
    assert!(
        b_fired_tables(&risks).is_empty(),
        "DML-only ⟹ no schema change ⟹ Detector B must NOT fire"
    );
}

/// With an EMPTY prior schema (no sidecar in play), Detector B never fires — the
/// sidecar-aware pass degrades to exactly Detector A.
#[test]
fn no_sidecar_never_fires_detector_b() {
    let db = Database::open(B_ALTERED.to_vec()).expect("open fixture");
    let recs = carve_all_deleted_records(&db);
    let attrs = attribute_records(&db, &recs);
    let empty: BTreeMap<String, String> = BTreeMap::new();
    let risks = table_instance_risks_with_sidecar(&db, &recs, &attrs, &empty);
    assert!(
        b_fired_tables(&risks).is_empty(),
        "no prior schema ⟹ Detector B silent"
    );
}

/// The bare Detector-A fixtures (no sidecar passed) never trip Detector B, and
/// the sidecar-aware pass still surfaces Detector A on `b_autoinc.db`.
#[test]
fn bare_detector_a_fixtures_never_trip_detector_b() {
    let empty: BTreeMap<String, String> = BTreeMap::new();
    for bytes in [B_AUTOINC, B_PLAINPK] {
        let db = Database::open(bytes.to_vec()).expect("open fixture");
        let recs = carve_all_deleted_records(&db);
        let attrs = attribute_records(&db, &recs);
        let risks = table_instance_risks_with_sidecar(&db, &recs, &attrs, &empty);
        assert!(
            b_fired_tables(&risks).is_empty(),
            "a bare A fixture must never trip Detector B"
        );
    }
    // Detector A still fires under the sidecar-aware pass (no sidecar ⟹ A only).
    let db = Database::open(B_AUTOINC.to_vec()).expect("open b_autoinc.db");
    let recs = carve_all_deleted_records(&db);
    let attrs = attribute_records(&db, &recs);
    let risks = table_instance_risks_with_sidecar(&db, &recs, &attrs, &empty);
    assert!(
        risks
            .iter()
            .any(|r| matches!(r, TableInstanceRisk::RowidExceedsAutoincHighwater { .. })),
        "Detector A still surfaces under the sidecar-aware pass"
    );
}

/// Anti-regression: across ordinary Nemetz deleted-row databases, the
/// sidecar-aware pass with an empty prior schema fires NOTHING (neither A nor B).
#[test]
fn nemetz_databases_never_spuriously_flag() {
    let empty: BTreeMap<String, String> = BTreeMap::new();
    for rel in ["nemetz/0C/0C-01.db", "nemetz/0D/0D-01.db"] {
        let path = format!("{}/../tests/data/{rel}", env!("CARGO_MANIFEST_DIR"));
        let Ok(bytes) = std::fs::read(&path) else {
            continue; // corpus db absent ⟹ skip cleanly (env-gated provenance)
        };
        let db = Database::open(bytes).expect("open nemetz db");
        let recs = carve_all_deleted_records(&db);
        let attrs = attribute_records(&db, &recs);
        let risks = table_instance_risks_with_sidecar(&db, &recs, &attrs, &empty);
        assert!(
            risks.iter().all(|r| *r == TableInstanceRisk::None),
            "{rel}: ordinary Nemetz deleted rows must NEVER trip the flag"
        );
    }
}

/// The `SidecarSchemaChanged` note shows its table + that the signal is
/// sidecar-derived, uses "consistent with" framing, and never asserts
/// "predecessor" or "drop-recreate" as fact; the token names the table.
#[test]
fn detector_b_note_and_token_are_evidence_bearing_and_non_overclaiming() {
    let risk = TableInstanceRisk::SidecarSchemaChanged {
        table: "students".to_string(),
    };
    let note = risk.note();
    assert!(note.contains("students"), "note shows the table");
    assert!(
        note.contains("sidecar") || note.contains("-wal") || note.contains("-journal"),
        "note shows the signal is sidecar-derived"
    );
    assert!(
        note.contains("consistent with"),
        "note uses consistent-with framing"
    );
    let lower = note.to_lowercase();
    assert!(
        !lower.contains("predecessor"),
        "note must never assert 'predecessor'"
    );
    assert_eq!(
        risk.token(),
        "sidecar_schema_changed(students)",
        "token names the table"
    );
}
