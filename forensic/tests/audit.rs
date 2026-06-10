//! End-to-end audit tests: build raw bytes → `sqlite_core::Database::open`
//! → `sqlite_forensic::audit`, driving the full reader→analyzer pipeline.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use forensicnomicon::report::{Severity, Source};
use sqlite_core::Database;
use sqlite_forensic::{audit, audit_findings, AnomalyKind};

/// A minimal valid 100-byte SQLite file header (page size 4096), with the
/// reserved-space-per-page byte (offset 20) set to `reserved`. One empty 4096
/// byte page so the file is at least one page long.
fn header_with_reserved(reserved: u8) -> Vec<u8> {
    let mut bytes = vec![0u8; 4096];
    bytes[..16].copy_from_slice(b"SQLite format 3\0");
    // page-size field at offset 16: 4096 big-endian.
    bytes[16] = 0x10;
    bytes[17] = 0x00;
    // reserved-space-per-page at offset 20.
    bytes[20] = reserved;
    bytes
}

#[test]
fn nonzero_reserved_space_is_flagged() {
    let db = Database::open(header_with_reserved(32)).unwrap();
    let anomalies = audit(&db);
    assert_eq!(anomalies.len(), 1);
    assert_eq!(
        anomalies[0].kind,
        AnomalyKind::NonZeroReservedSpace { reserved: 32 }
    );
    assert_eq!(anomalies[0].code, "SQLITE-RESERVED-SPACE-NONZERO");
    assert_eq!(anomalies[0].severity, Severity::Low);
}

#[test]
fn zero_reserved_space_is_clean() {
    let db = Database::open(header_with_reserved(0)).unwrap();
    assert!(audit(&db).is_empty());
}

#[test]
fn audit_findings_carry_source_and_code() {
    let db = Database::open(header_with_reserved(32)).unwrap();
    let source = Source {
        analyzer: "sqlite-forensic".to_string(),
        scope: "places.sqlite".to_string(),
        version: None,
    };
    let findings = audit_findings(&db, &source);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, "SQLITE-RESERVED-SPACE-NONZERO");
    assert_eq!(findings[0].source.analyzer, "sqlite-forensic");
    assert_eq!(findings[0].severity, Some(Severity::Low));
}
