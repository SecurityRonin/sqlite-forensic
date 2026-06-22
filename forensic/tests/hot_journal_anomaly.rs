//! Rollback-journal anomaly arms over [`audit_journal`], validated against
//! **real sqlite3-engine artifacts** rather than hand-encoded bytes.
//!
//! Fixtures (`tests/data/journal/`, provenance in that dir's README):
//!   - `hot.db` + `hot.db-journal` — a real **HOT** journal (Tier-A valid magic,
//!     DML only): `page_size=4096`, `journal_mode=DELETE`, a table created+filled
//!     and committed, then `cache_size=1; BEGIN IMMEDIATE; DELETE…; INSERT…` with
//!     the db + `-journal` copied *while the txn was open* (cache_size=1 forces
//!     the journal to disk mid-txn), then rolled back. The engine produced a
//!     valid header (n_rec=5), 5 checksum-valid page images (pgnos 3,2,4,5,1).
//!     Page 1 is journaled but the schema cookie did **not** change (DML only),
//!     so SCHEMA-CHANGE must **not** fire.
//!   - `ddl_persist.db` + `ddl_persist.db-journal` — a real committed-DDL PERSIST
//!     journal: `ALTER TABLE … ADD COLUMN`, clean close. The live db's schema
//!     cookie (2) advanced past the journal's prior page-1 image cookie (1), so
//!     SCHEMA-CHANGE must fire.
//!
//! The real NIST CFReDS SFT-03 PERSIST artifact is the negative oracle for the
//! cookie comparison: its live cookie (9) equals the journal's prior page-1
//! image cookie (9) — DML only, no DDL — so SCHEMA-CHANGE must **not** fire even
//! though page 1 *is* among the images.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::pedantic)]

use std::path::{Path, PathBuf};

use forensicnomicon::report::Source;
use sqlite_core::Database;
use sqlite_forensic::{audit_journal, audit_journal_findings};

fn journal_dir(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../tests/data/journal")
        .join(name)
}

fn cfreds(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../tests/data/cfreds")
        .join(name)
}

fn codes_of(db: &Database, journal: &[u8]) -> Vec<&'static str> {
    audit_journal(db, journal).iter().map(|a| a.code).collect()
}

/// The HOT journal's Tier-A header `mx_page` lives at byte offset 16 (4-byte BE)
/// and is **not** covered by any page checksum — editing it is a realistic
/// "db-size delta" scenario without invalidating a record.
const MX_PAGE_OFFSET: usize = 16;

#[test]
fn real_hot_journal_fires_hot_but_not_schema_change() {
    let db = Database::open(std::fs::read(journal_dir("hot.db")).unwrap()).expect("open hot.db");
    let journal = std::fs::read(journal_dir("hot.db-journal")).unwrap();
    let codes = codes_of(&db, &journal);

    assert!(
        codes.contains(&"SQLITE-JOURNAL-HOT"),
        "real valid-magic journal is a hot journal; got {codes:?}"
    );
    // DML only: page 1 is journaled (header change-counter/freelist updates) but
    // the schema cookie did not advance, so SCHEMA-CHANGE must NOT fire.
    assert!(
        !codes.contains(&"SQLITE-JOURNAL-SCHEMA-CHANGE"),
        "DML-only hot journal must NOT raise SCHEMA-CHANGE (cookie unchanged); got {codes:?}"
    );
}

#[test]
fn real_hot_journal_checksums_all_verify() {
    use sqlite_core::RollbackJournal;
    let db = Database::open(std::fs::read(journal_dir("hot.db")).unwrap()).expect("open hot.db");
    let journal = std::fs::read(journal_dir("hot.db-journal")).unwrap();
    let parsed =
        RollbackJournal::parse(&journal, db.header().page_size).expect("parse hot journal");
    let images = parsed.page_images();

    let good = images
        .iter()
        .filter(|i| i.checksum_valid == Some(true))
        .count();
    let bad = images
        .iter()
        .filter(|i| i.checksum_valid == Some(false))
        .count();
    assert!(
        good >= 1,
        "real hot journal has >=1 checksum-valid page image; good={good}"
    );
    assert_eq!(
        bad, 0,
        "real hot journal has ZERO checksum-invalid page images; bad={bad}"
    );
}

#[test]
fn real_ddl_persist_journal_fires_schema_change() {
    let db = Database::open(std::fs::read(journal_dir("ddl_persist.db")).unwrap())
        .expect("open ddl_persist.db");
    let journal = std::fs::read(journal_dir("ddl_persist.db-journal")).unwrap();
    let anomalies = audit_journal(&db, &journal);
    let codes: Vec<&str> = anomalies.iter().map(|a| a.code).collect();

    assert!(
        codes.contains(&"SQLITE-JOURNAL-SCHEMA-CHANGE"),
        "committed-DDL PERSIST journal: cookie advanced (1 -> 2), SCHEMA-CHANGE must fire; got {codes:?}"
    );
    // The note must SHOW both cookie values.
    let sc = anomalies
        .iter()
        .find(|a| a.code == "SQLITE-JOURNAL-SCHEMA-CHANGE")
        .unwrap();
    assert!(
        sc.note.contains('1') && sc.note.contains('2'),
        "SCHEMA-CHANGE note shows both cookie values; note = {:?}",
        sc.note
    );
}

#[test]
fn nist_persist_does_not_fire_schema_change() {
    // The real NIST artifact does only DELETEs/UPDATEs (no DDL): the journal's
    // prior page-1 image cookie (9) equals the live db cookie (9). SCHEMA-CHANGE
    // must NOT fire even though page 1 is journaled. RECOVERABLE must fire.
    for platform in ["ios", "android"] {
        let db = Database::open(
            std::fs::read(cfreds(&format!("SFT-03_PERSIST_{platform}.sqlite"))).unwrap(),
        )
        .expect("open main");
        let journal =
            std::fs::read(cfreds(&format!("SFT-03_PERSIST_{platform}.sqlite-journal"))).unwrap();
        let codes = codes_of(&db, &journal);

        assert!(
            !codes.contains(&"SQLITE-JOURNAL-SCHEMA-CHANGE"),
            "{platform}: NIST PERSIST is DML-only (cookie unchanged); SCHEMA-CHANGE must NOT fire; got {codes:?}"
        );
        assert!(
            codes.contains(&"SQLITE-JOURNAL-RECOVERABLE"),
            "{platform}: PERSIST post-commit journal carries recoverable images; got {codes:?}"
        );
    }
}

#[test]
fn real_hot_journal_byte_flip_fires_checksum_mismatch() {
    // Derive a torn-write / tamper variant from the committed real journal: flip
    // ONE byte inside a page-record payload (NOT the header sector) on an owned
    // copy, then re-audit. The affected page must be named in CHECKSUM-MISMATCH.
    let db = Database::open(std::fs::read(journal_dir("hot.db")).unwrap()).expect("open hot.db");
    let mut journal = std::fs::read(journal_dir("hot.db-journal")).unwrap();
    let ps = db.header().page_size as usize;
    let sector = 512usize; // Tier-A header sector
                           // First record: [pgno:4][page:ps][cksum:4]. The `pager.c` checksum samples
                           // every 200th byte from the tail (page offsets ps-200, ps-400, …), so flip a
                           // byte the checksum actually covers (page offset ps-200) to guarantee a
                           // mismatch — a realistic torn-write / post-write tamper.
    let flip_at = sector + 4 + (ps - 200);
    journal[flip_at] ^= 0xFF;

    let anomalies = audit_journal(&db, &journal);
    let cksum = anomalies
        .iter()
        .find(|a| a.code == "SQLITE-JOURNAL-CHECKSUM-MISMATCH")
        .expect("a flipped payload byte breaks the page checksum");
    // The first record's pgno is 3 (verified empirically); the note must name it.
    assert!(
        cksum.note.contains('3'),
        "checksum-mismatch note names the affected page; note = {:?}",
        cksum.note
    );
}

#[test]
fn real_hot_journal_appended_duplicate_fires_duplicate_page() {
    // Append a byte-for-byte duplicate of a real page record to the real journal
    // (owned copy) → a pgno appears twice → DUPLICATE-PAGE. The Tier-A header
    // reads exactly `n_rec` records, so bump `n_rec` (offset 8, not checksum
    // covered) to include the appended record.
    let db = Database::open(std::fs::read(journal_dir("hot.db")).unwrap()).expect("open hot.db");
    let original = std::fs::read(journal_dir("hot.db-journal")).unwrap();
    let ps = db.header().page_size as usize;
    let sector = 512usize;
    let rec_len = 4 + ps + 4;
    let first_record = original[sector..sector + rec_len].to_vec();

    // Records are stride-packed from `sector`; place the duplicate at the slot
    // immediately after the last real record (truncating any sub-record trailing
    // bytes) so the walker reads it, and bump `n_rec` (offset 8, not checksum
    // covered) to include it.
    let n_rec = u32::from_be_bytes([original[8], original[9], original[10], original[11]]);
    let next_slot = sector + (n_rec as usize) * rec_len;
    let mut journal = original[..next_slot.min(original.len())].to_vec();
    journal[8..12].copy_from_slice(&(n_rec + 1).to_be_bytes());
    journal.extend_from_slice(&first_record);

    let codes = codes_of(&db, &journal);
    assert!(
        codes.contains(&"SQLITE-JOURNAL-DUPLICATE-PAGE"),
        "an appended duplicate real page record raises DUPLICATE-PAGE; got {codes:?}"
    );
}

#[test]
fn real_hot_journal_duplicate_page_finding_names_the_page() {
    // roadmap §2.2: the DUPLICATE-PAGE finding must surface WHICH page repeated,
    // not report the anomaly with no evidence. Same construction as above; the
    // appended record's pgno (its first 4 bytes, BE) is the offending value.
    let db = Database::open(std::fs::read(journal_dir("hot.db")).unwrap()).expect("open hot.db");
    let original = std::fs::read(journal_dir("hot.db-journal")).unwrap();
    let ps = db.header().page_size as usize;
    let sector = 512usize;
    let rec_len = 4 + ps + 4;
    let first_record = original[sector..sector + rec_len].to_vec();
    let dup_pgno = u32::from_be_bytes([
        first_record[0],
        first_record[1],
        first_record[2],
        first_record[3],
    ]);
    let n_rec = u32::from_be_bytes([original[8], original[9], original[10], original[11]]);
    let next_slot = sector + (n_rec as usize) * rec_len;
    let mut journal = original[..next_slot.min(original.len())].to_vec();
    journal[8..12].copy_from_slice(&(n_rec + 1).to_be_bytes());
    journal.extend_from_slice(&first_record);

    let source = Source {
        analyzer: "sqlite-forensic".to_string(),
        scope: "hot.db".to_string(),
        version: None,
    };
    let findings = audit_journal_findings(&db, &journal, &source);
    let dup = findings
        .iter()
        .find(|f| f.code == "SQLITE-JOURNAL-DUPLICATE-PAGE")
        .expect("DUPLICATE-PAGE finding present");
    assert!(
        !dup.evidence.is_empty(),
        "DUPLICATE-PAGE must carry the offending page number, not be evidence-less"
    );
    assert!(
        dup.evidence.iter().any(|e| e.value == dup_pgno.to_string()),
        "evidence must include the duplicated pgno {dup_pgno}: {:?}",
        dup.evidence
    );
}

#[test]
fn real_hot_journal_finding_carries_scope_evidence() {
    // roadmap §2.2c: the HOT-JOURNAL finding should surface the interrupted
    // transaction's scope (db page count at txn start + number of journaled
    // pre-images), not report the anomaly with no evidence. hot.db's journal
    // carries 5 page images.
    let db = Database::open(std::fs::read(journal_dir("hot.db")).unwrap()).expect("open hot.db");
    let journal = std::fs::read(journal_dir("hot.db-journal")).unwrap();
    let source = Source {
        analyzer: "sqlite-forensic".to_string(),
        scope: "hot.db".to_string(),
        version: None,
    };
    let findings = audit_journal_findings(&db, &journal, &source);
    let hot = findings
        .iter()
        .find(|f| f.code == "SQLITE-JOURNAL-HOT")
        .expect("HOT-JOURNAL finding present");
    assert!(
        !hot.evidence.is_empty(),
        "HOT-JOURNAL must carry the journal's scope as evidence, not be evidence-less"
    );
    assert!(
        hot.evidence
            .iter()
            .any(|e| e.field == "journaled_pages" && e.value == "5"),
        "evidence must include the journaled-page count (5): {:?}",
        hot.evidence
    );
}

#[test]
fn real_hot_journal_edited_mxpage_fires_dbsize_delta() {
    // The real journal's mx_page (5) equals the live page count (5) → no natural
    // delta. Edit mx_page (offset 16, NOT checksum-covered) on an owned copy to a
    // larger value → DBSIZE-DELTA, with both numbers shown.
    let db = Database::open(std::fs::read(journal_dir("hot.db")).unwrap()).expect("open hot.db");
    let mut journal = std::fs::read(journal_dir("hot.db-journal")).unwrap();
    let current = db.page_count();
    let forged = current + 7;
    journal[MX_PAGE_OFFSET..MX_PAGE_OFFSET + 4].copy_from_slice(&forged.to_be_bytes());

    let anomalies = audit_journal(&db, &journal);
    let dbsize = anomalies
        .iter()
        .find(|a| a.code == "SQLITE-JOURNAL-DBSIZE-DELTA")
        .expect("forged mx_page != current page count → DBSIZE-DELTA");
    assert!(
        dbsize.note.contains(&forged.to_string()) && dbsize.note.contains(&current.to_string()),
        "dbsize note shows forged mx_page ({forged}) and current ({current}); note = {:?}",
        dbsize.note
    );
}
