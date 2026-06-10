//! End-to-end audit of the new freelist / WAL / page-count findings against the
//! REAL fixtures (see `docs/corpus-catalog.md`), exercising `audit()` and
//! `audit_carved_findings()` through the full reader→analyzer pipeline.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use forensicnomicon::report::{Category, Severity, Source};
use sqlite_core::Database;
use sqlite_forensic::{audit, audit_carved_findings, AnomalyKind};

const DELETED: &[u8] = include_bytes!("data/deleted_places.db");
const WAL_MAIN: &[u8] = include_bytes!("../../core/tests/data/wal_places.db");
const WAL_SIDE: &[u8] = include_bytes!("../../core/tests/data/wal_places.db-wal");
const CLEAN: &[u8] = include_bytes!("../../core/tests/data/places.db");

fn src() -> Source {
    Source {
        analyzer: "sqlite-forensic".to_string(),
        scope: "moz_places".to_string(),
        version: None,
    }
}

#[test]
fn deleted_db_flags_nonempty_freelist() {
    let db = Database::open(DELETED.to_vec()).expect("open");
    let kinds: Vec<_> = audit(&db).into_iter().map(|a| a.kind).collect();
    // The fixture has 5 free pages → a NonEmptyFreelist anomaly.
    assert!(
        kinds.contains(&AnomalyKind::NonEmptyFreelist { free_pages: 5 }),
        "expected NonEmptyFreelist {{ free_pages: 5 }}, got {kinds:?}"
    );
}

#[test]
fn clean_db_has_no_freelist_finding() {
    let db = Database::open(CLEAN.to_vec()).expect("open clean");
    let anomalies = audit(&db);
    assert!(
        anomalies
            .iter()
            .all(|a| !matches!(a.kind, AnomalyKind::NonEmptyFreelist { .. })),
        "a never-deleted DB must not raise a freelist finding"
    );
}

#[test]
fn wal_overlay_flags_uncheckpointed_state() {
    let db = Database::open_with_wal(WAL_MAIN.to_vec(), WAL_SIDE).expect("open with wal");
    let anomalies = audit(&db);
    assert!(
        anomalies
            .iter()
            .any(|a| matches!(a.kind, AnomalyKind::WalUncheckpointedState { .. })),
        "an active WAL overlay must raise an uncheckpointed-state finding"
    );
    // Without the sidecar, no such finding.
    let main_only = Database::open(WAL_MAIN.to_vec()).expect("open main");
    assert!(
        audit(&main_only)
            .iter()
            .all(|a| !matches!(a.kind, AnomalyKind::WalUncheckpointedState { .. })),
        "main-only open must not claim uncheckpointed state"
    );
}

#[test]
fn carved_findings_are_residue_and_confidence_graded() {
    let db = Database::open(DELETED.to_vec()).expect("open");
    let findings = audit_carved_findings(&db, 6, &src());
    assert!(!findings.is_empty(), "carving must yield findings");

    let f = &findings[0];
    assert_eq!(f.code, "SQLITE-DELETED-RECORD-RECOVERED");
    assert_eq!(f.category, Category::Residue);
    assert_eq!(f.severity, Some(Severity::Medium));
    // The per-record confidence is threaded into the finding context.
    assert!(
        f.context.confidence.is_some(),
        "carved finding must carry a confidence"
    );
    // Provenance evidence: rowid, source page, cell offset.
    let fields: Vec<&str> = f.evidence.iter().map(|e| e.field.as_str()).collect();
    assert!(fields.contains(&"rowid"));
    assert!(fields.contains(&"source_page"));
    assert!(fields.contains(&"cell_offset"));
}
