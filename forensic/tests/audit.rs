//! End-to-end audit tests: build raw bytes → `sqlite_core::Database::open`
//! → `sqlite_forensic::audit`, driving the full reader→analyzer pipeline.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use forensicnomicon::report::{Location, Severity, Source};
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
fn nonzero_reserved_space_note_states_recovery_needs_the_key() {
    // roadmap §2.3: an encrypted/checksum-VFS database's reserved-space finding
    // must tell the examiner that deleted-record recovery needs the key/VFS, not
    // just that reserved space is non-standard.
    let note = AnomalyKind::NonZeroReservedSpace { reserved: 32 }.note();
    assert!(
        note.to_lowercase().contains("key"),
        "reserved-space note must state recovery needs the encryption key: {note}"
    );
}

#[test]
fn nonzero_reserved_space_finding_carries_raw_evidence() {
    // roadmap §2.2: an "unknown/anomalous" finding must surface the offending
    // value AND where it was found, never report the anomaly with no evidence.
    let db = Database::open(header_with_reserved(32)).unwrap();
    let source = Source {
        analyzer: "sqlite-forensic".to_string(),
        scope: "x.sqlite".to_string(),
        version: None,
    };
    let findings = audit_findings(&db, &source);
    assert_eq!(findings.len(), 1);
    let evidence = &findings[0].evidence;
    assert!(
        !evidence.is_empty(),
        "NonZeroReservedSpace must carry raw evidence (the reserved byte count + header offset)"
    );
    assert!(
        evidence.iter().any(|e| e.value == "32"),
        "evidence must include the reserved-byte value (32): {evidence:?}"
    );
    assert!(
        evidence
            .iter()
            .any(|e| matches!(e.location, Some(Location::ByteOffset(20)))),
        "evidence must point at header byte offset 20: {evidence:?}"
    );
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
