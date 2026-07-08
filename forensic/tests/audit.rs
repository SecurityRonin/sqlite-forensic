//! End-to-end audit tests: build raw bytes → `sqlite_core::Database::open`
//! → `sqlite_forensic::audit`, driving the full reader→analyzer pipeline.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use forensicnomicon::report::{Location, Observation, Severity, Source};
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
fn nonzero_reserved_space_names_sqlcipher4_at_80() {
    // roadmap §2.3: name the SPECIFIC scheme the value matches, not a generic
    // menu. reserved=80 is the measured SQLCipher 4 default (16-byte IV + 64-byte
    // HMAC-SHA512), verified against sqlcipher 4.16.
    let note = AnomalyKind::NonZeroReservedSpace { reserved: 80 }.note();
    assert!(
        note.contains("SQLCipher 4"),
        "reserved=80 note must name SQLCipher 4 specifically: {note}"
    );
}

#[test]
fn nonzero_reserved_space_names_checksum_vfs_at_8() {
    // The SQLite checksum VFS reserves exactly 8 bytes per page (cksumvfs.html).
    // At 8 the matched scheme is the checksum VFS — NOT an encryption cipher.
    let note = AnomalyKind::NonZeroReservedSpace { reserved: 8 }.note();
    assert!(
        note.to_lowercase().contains("checksum vfs"),
        "reserved=8 note must name the checksum VFS: {note}"
    );
    assert!(
        !note.contains("SQLCipher"),
        "reserved=8 is not SQLCipher; the note must not name it: {note}"
    );
}

#[test]
fn nonzero_reserved_space_unknown_value_is_flagged_unrecognized_with_bytes() {
    // An unrecognized reservation must be labelled as such AND still surface the
    // offending value, never a bare "encryption" guess (show-the-value discipline).
    let note = AnomalyKind::NonZeroReservedSpace { reserved: 7 }.note();
    assert!(
        note.contains('7'),
        "an unrecognized reserved value must still be shown: {note}"
    );
    assert!(
        note.to_lowercase().contains("unrecognized")
            || note.to_lowercase().contains("does not match"),
        "an unrecognized value must be labelled unrecognized: {note}"
    );
    assert!(
        !note.contains("SQLCipher") && !note.to_lowercase().contains("checksum vfs"),
        "an unrecognized value must not be misattributed to a named scheme: {note}"
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

/// A `page_count`-page file (page size 4096) whose page-1 header carries the
/// freelist trunk head (offset 32) and free-page count (offset 36) set as given.
/// Extra pages are appended zeroed for the caller to populate. The in-header
/// db-size field (offset 28) is left 0 so `PageCountMismatch` never fires and the
/// freelist anomalies are tested in isolation.
fn db_with_freelist(page_count: u32, head: u32, count: u32) -> Vec<u8> {
    let ps = 4096usize;
    let mut b = vec![0u8; ps * page_count as usize];
    b[..16].copy_from_slice(b"SQLite format 3\0");
    b[16] = 0x10; // page size 4096 (0x1000), big-endian
    b[17] = 0x00;
    b[32..36].copy_from_slice(&head.to_be_bytes());
    b[36..40].copy_from_slice(&count.to_be_bytes());
    b
}

fn src() -> Source {
    Source {
        analyzer: "sqlite-forensic".to_string(),
        scope: "x.sqlite".to_string(),
        version: None,
    }
}

#[test]
fn freelist_count_inconsistency_is_flagged() {
    // roadmap §2.1: distrust the header. Offset 36 declares 5 free pages but the
    // trunk head (offset 32) is 0, so the walked chain yields none — a
    // tamper/corruption signal the silent NonEmptyFreelist count would hide.
    let db = Database::open(db_with_freelist(1, 0, 5)).unwrap();
    let a = audit(&db)
        .into_iter()
        .find(|a| a.code == "SQLITE-FREELIST-COUNT-INCONSISTENT")
        .expect("freelist count/chain inconsistency must be flagged");
    assert_eq!(a.severity, Severity::High);
    let lc = a.note.to_lowercase();
    assert!(
        lc.contains("tamper") || lc.contains("corrupt"),
        "note must frame it as tampering/corruption: {}",
        a.note
    );
    let f = a.to_finding(src());
    assert!(
        f.evidence.iter().any(|e| e.value == "5"),
        "evidence must carry the declared count (5): {:?}",
        f.evidence
    );
    assert!(
        f.evidence
            .iter()
            .any(|e| matches!(e.location, Some(Location::ByteOffset(36)))),
        "evidence must point at the freelist-count header field (offset 36): {:?}",
        f.evidence
    );
}

#[test]
fn malformed_freelist_chain_is_flagged() {
    // A trunk head pointing past the file end makes the walk unwalkable; the
    // header still claims a free page, so surface the inconsistency (walked=None).
    let db = Database::open(db_with_freelist(1, 99, 1)).unwrap();
    let a = audit(&db)
        .into_iter()
        .find(|a| a.code == "SQLITE-FREELIST-COUNT-INCONSISTENT")
        .expect("an unwalkable (malformed) freelist chain must be flagged");
    assert!(
        a.note.to_lowercase().contains("unwalkable"),
        "note must state the chain was unwalkable: {}",
        a.note
    );
    // The walked-count evidence must read "malformed" when the chain could not be
    // walked, rather than a bogus number.
    let f = a.to_finding(src());
    assert!(
        f.evidence
            .iter()
            .any(|e| e.field == "walked_free_pages" && e.value == "malformed"),
        "evidence must mark the walked count as malformed: {:?}",
        f.evidence
    );
}

#[test]
fn zeroed_freed_leaves_flag_residue_destruction() {
    // roadmap §2.1 secure_delete fingerprint: a valid freelist whose freed LEAF
    // pages are entirely zero — residue deliberately destroyed. Trunk page 2 lists
    // leaves 3 and 4, both left zeroed.
    let mut b = db_with_freelist(4, 2, 3); // head=page 2; 3 free pages (trunk + 2 leaves)
    let t = 4096; // page 2 begins at byte 4096
    b[t..t + 4].copy_from_slice(&0u32.to_be_bytes()); // next trunk = 0
    b[t + 4..t + 8].copy_from_slice(&2u32.to_be_bytes()); // leaf count = 2
    b[t + 8..t + 12].copy_from_slice(&3u32.to_be_bytes()); // leaf page 3
    b[t + 12..t + 16].copy_from_slice(&4u32.to_be_bytes()); // leaf page 4
    let db = Database::open(b).unwrap();
    let a = audit(&db)
        .into_iter()
        .find(|a| a.code == "SQLITE-FREELIST-RESIDUE-ZEROED")
        .expect("zeroed freed leaves must raise the residue-destruction fingerprint");
    assert_eq!(a.severity, Severity::Medium);
    assert!(
        a.note.to_lowercase().contains("secure_delete"),
        "note must name secure_delete as a consistent-with cause: {}",
        a.note
    );
    assert!(
        a.note.to_lowercase().contains("consistent with"),
        "note must hedge (consistent with), never claim proof: {}",
        a.note
    );
    let f = a.to_finding(src());
    assert!(
        f.evidence.iter().any(|e| e.value == "2"),
        "evidence must carry the zeroed-page count (2): {:?}",
        f.evidence
    );
}

#[test]
fn freed_leaves_with_residue_raise_no_fingerprint() {
    // The same freelist but the freed leaves retain residue (non-zero) — an
    // ordinary secure_delete=OFF delete, NOT a wipe. No fingerprint.
    let mut b = db_with_freelist(4, 2, 3);
    let t = 4096;
    b[t..t + 4].copy_from_slice(&0u32.to_be_bytes());
    b[t + 4..t + 8].copy_from_slice(&2u32.to_be_bytes());
    b[t + 8..t + 12].copy_from_slice(&3u32.to_be_bytes());
    b[t + 12..t + 16].copy_from_slice(&4u32.to_be_bytes());
    b[4096 * 2 + 10] = 0x41; // residue byte on freed leaf page 3
    b[4096 * 3 + 10] = 0x42; // residue byte on freed leaf page 4
    let db = Database::open(b).unwrap();
    assert!(
        !audit(&db)
            .iter()
            .any(|a| a.code == "SQLITE-FREELIST-RESIDUE-ZEROED"),
        "freed leaves that retain residue must NOT raise the fingerprint"
    );
}

/// Tier-2 oracle: build the two databases with the real `sqlite3` engine and
/// confirm the fingerprint fires on `secure_delete=ON` (zeroed freed leaves) and
/// stays silent on `secure_delete=OFF` (residue retained). Env-gated on a
/// `sqlite3` binary (PATH or `SQLITE3_BIN`); skips cleanly when absent so CI
/// without sqlite3 still passes (the deterministic synthetic tests above cover
/// the code paths).
#[test]
fn real_engine_secure_delete_raises_the_fingerprint() {
    let bin = std::env::var("SQLITE3_BIN").unwrap_or_else(|_| "sqlite3".to_string());
    let dir = std::env::temp_dir().join("sqlite4n6-secure-delete-oracle");
    let _ = std::fs::remove_dir_all(&dir);
    if std::fs::create_dir_all(&dir).is_err() {
        eprintln!("SKIP: cannot create temp dir");
        return;
    }

    // Enough rows that DELETE frees whole pages onto the freelist (in-page
    // freeblocks alone would leave freelist_count=0 and exercise nothing).
    let script = "PRAGMA page_size=4096; CREATE TABLE t(x TEXT);\n\
         WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM c WHERE n<2000)\n\
         INSERT INTO t SELECT 'row-'||n||'-'||hex(randomblob(40)) FROM c;\n\
         DELETE FROM t WHERE rowid>200;";

    let mut fired = std::collections::HashMap::new();
    for mode in ["OFF", "ON"] {
        let db_path = dir.join(format!("sd_{mode}.db"));
        let full = format!("PRAGMA secure_delete={mode}; {script}");
        let status = std::process::Command::new(&bin)
            .arg(&db_path)
            .arg(&full)
            .status();
        match status {
            Ok(s) if s.success() => {}
            _ => {
                eprintln!("SKIP real_engine_secure_delete: no usable sqlite3 (set SQLITE3_BIN)");
                return;
            }
        }
        let bytes = std::fs::read(&db_path).unwrap();
        let db = Database::open(bytes).unwrap();
        let hit = audit(&db)
            .iter()
            .any(|a| a.code == "SQLITE-FREELIST-RESIDUE-ZEROED");
        fired.insert(mode, hit);
    }

    assert_eq!(
        fired.get("ON"),
        Some(&true),
        "secure_delete=ON must raise the residue-destruction fingerprint"
    );
    assert_eq!(
        fired.get("OFF"),
        Some(&false),
        "secure_delete=OFF (residue retained) must NOT raise the fingerprint"
    );
    let _ = std::fs::remove_dir_all(&dir);
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
