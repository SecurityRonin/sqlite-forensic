//! Rollback-journal anomaly detection (design §6) over [`audit_journal`].
//!
//! The anomaly arms validated against real sqlite3-engine artifacts (HOT,
//! CHECKSUM-MISMATCH, DUPLICATE-PAGE, DBSIZE-DELTA, and the cookie-based
//! SCHEMA-CHANGE) live in `hot_journal_anomaly.rs`. This file retains the
//! hand-built **Tier-A** parser edge cases — `mx_page`-sentinel / growth /
//! shrink direction and the no-fire boundary — and the real NIST PERSIST oracle
//! for RECOVERABLE.
//!
//! Two oracles:
//!   1. The real NIST CFReDS SFT-03 PERSIST artifact + its `-journal` (Tier B,
//!      header zeroed on commit). Verified empirically: 14 page images, page 1
//!      journaled, no checksum verification (nonce gone), no duplicate pgno. So
//!      it triggers RECOVERABLE (>=1 image), and — because the schema cookie did
//!      not advance (DML only) — NOT SCHEMA-CHANGE.
//!   2. A hand-built **Tier A** (valid-magic) journal per `pager.c` offsets,
//!      paired with a tiny real `page_size=512` database, to drive the HOT,
//!      CHECKSUM-MISMATCH, DUPLICATE-PAGE, and DBSIZE-DELTA arms — which only a
//!      valid header can exhibit.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::pedantic)]

use std::path::{Path, PathBuf};

use forensicnomicon::report::{Observation, Source};
use sqlite_core::Database;
use sqlite_forensic::{audit_journal, audit_journal_findings};

fn cfreds(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../tests/data/cfreds")
        .join(name)
}

/// `pager.c` journal magic (offset 0).
const JOURNAL_MAGIC: [u8; 8] = [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7];

/// The `pager.c` per-page checksum: `nonce` plus every-200th byte from the tail,
/// starting at `page_size - 200`, stepping down by 200 while the index is
/// positive, in wrapping u32 arithmetic. Mirrors `core`'s `journal_cksum`.
fn journal_cksum(nonce: u32, page: &[u8]) -> u32 {
    let mut sum = nonce;
    let mut x = page.len() as i64 - 200;
    while x > 0 {
        if let Some(&b) = page.get(x as usize) {
            sum = sum.wrapping_add(u32::from(b));
        }
        x -= 200;
    }
    sum
}

/// Build a Tier-A rollback journal: a valid 512-byte header sector
/// (magic, `n_rec`, `nonce`, `mx_page`, `sector_size`, `page_size`) followed by
/// `records`, each `[pgno:4][page:page_size][cksum:4]`. When a record's flag is
/// `false`, a deliberately wrong checksum is stored.
fn build_tier_a_journal(
    page_size: usize,
    nonce: u32,
    mx_page: u32,
    records: &[(u32, Vec<u8>, bool)],
) -> Vec<u8> {
    let sector_size: u32 = 512;
    let mut j = vec![0u8; sector_size as usize];
    j[0..8].copy_from_slice(&JOURNAL_MAGIC);
    j[8..12].copy_from_slice(&(records.len() as u32).to_be_bytes());
    j[12..16].copy_from_slice(&nonce.to_be_bytes());
    j[16..20].copy_from_slice(&mx_page.to_be_bytes());
    j[20..24].copy_from_slice(&sector_size.to_be_bytes());
    j[24..28].copy_from_slice(&(page_size as u32).to_be_bytes());
    for (pgno, page, good) in records {
        assert_eq!(page.len(), page_size, "page must be page_size bytes");
        j.extend_from_slice(&pgno.to_be_bytes());
        j.extend_from_slice(page);
        let mut ck = journal_cksum(nonce, page);
        if !good {
            ck = ck.wrapping_add(1); // corrupt: torn-page / post-write modification
        }
        j.extend_from_slice(&ck.to_be_bytes());
    }
    j
}

/// A tiny real `page_size=512` database with `pages` pages (>=1). We only need it
/// to open and report a `page_count`, against which `mx_page` is compared. Page 1
/// is an empty table-leaf; any trailing pages are zero-filled (benign unused).
fn tiny_db_512(pages: u32) -> Database {
    let ps = 512usize;
    let mut bytes = vec![0u8; ps * pages as usize];
    bytes[0..16].copy_from_slice(b"SQLite format 3\0");
    bytes[16..18].copy_from_slice(&512u16.to_be_bytes()); // page size
    bytes[18] = 1; // file format write version
    bytes[19] = 1; // file format read version
    bytes[21] = 64; // max embedded payload fraction
    bytes[22] = 32; // min embedded payload fraction
    bytes[23] = 32; // leaf payload fraction
    bytes[28..32].copy_from_slice(&pages.to_be_bytes()); // in-header page count
    bytes[44..48].copy_from_slice(&1u32.to_be_bytes()); // schema format
    bytes[48..52].copy_from_slice(&0u32.to_be_bytes());
    bytes[56..60].copy_from_slice(&1u32.to_be_bytes()); // text encoding UTF-8
    bytes[100] = 0x0d; // page-1 leaf table page
    bytes[103..105].copy_from_slice(&0u16.to_be_bytes()); // 0 cells
    bytes[105..107].copy_from_slice(&512u16.to_be_bytes()); // cell content start
    Database::open(bytes).expect("tiny 512 db opens")
}

fn codes_of(db: &Database, journal: &[u8]) -> Vec<&'static str> {
    audit_journal(db, journal).iter().map(|a| a.code).collect()
}

#[test]
fn persist_artifact_triggers_recoverable_only() {
    for platform in ["ios", "android"] {
        let main = std::fs::read(cfreds(&format!("SFT-03_PERSIST_{platform}.sqlite"))).unwrap();
        let journal =
            std::fs::read(cfreds(&format!("SFT-03_PERSIST_{platform}.sqlite-journal"))).unwrap();
        let db = Database::open(main).expect("open main");

        let anomalies = audit_journal(&db, &journal);
        let codes: Vec<&str> = anomalies.iter().map(|a| a.code).collect();

        assert!(
            codes.contains(&"SQLITE-JOURNAL-RECOVERABLE"),
            "{platform}: PERSIST post-commit journal with page images is recoverable; got {codes:?}"
        );
        // DML only: the journal's prior page-1 image schema cookie equals the live
        // db cookie, so SCHEMA-CHANGE must NOT fire (the cookie-comparison arm is
        // validated end-to-end in `hot_journal_anomaly.rs`).
        assert!(
            !codes.contains(&"SQLITE-JOURNAL-SCHEMA-CHANGE"),
            "{platform}: DML-only PERSIST (cookie unchanged) must NOT raise SCHEMA-CHANGE; got {codes:?}"
        );
        // Tier B has no valid header / checksums / duplicate / mx_page, so none of
        // the Tier-A-only anomalies fire on the real artifact.
        assert!(
            !codes.contains(&"SQLITE-JOURNAL-HOT"),
            "{platform}: zeroed header is NOT a hot journal"
        );
        assert!(!codes.contains(&"SQLITE-JOURNAL-CHECKSUM-MISMATCH"));
        assert!(!codes.contains(&"SQLITE-JOURNAL-DUPLICATE-PAGE"));
        assert!(!codes.contains(&"SQLITE-JOURNAL-DBSIZE-DELTA"));

        // The RECOVERABLE note must SHOW the image count.
        let recoverable = anomalies
            .iter()
            .find(|a| a.code == "SQLITE-JOURNAL-RECOVERABLE")
            .unwrap();
        assert!(
            recoverable.note.contains("14"),
            "{platform}: recoverable note shows image count; note = {:?}",
            recoverable.note
        );
    }
}

#[test]
fn tier_a_journal_triggers_hot_checksum_duplicate_dbsize_shrink() {
    let db = tiny_db_512(1); // page_count = 1
    let ps = 512usize;
    let page = vec![0xABu8; ps];

    // Records: pgno 1 (good cksum), pgno 2 (BAD cksum), pgno 2 again (duplicate).
    let records = vec![
        (1u32, page.clone(), true),
        (2u32, page.clone(), false),
        (2u32, page.clone(), true),
    ];
    // mx_page = 9 while the db has 1 page → db SHRANK (mx_page > current):
    // consistent with auto-vacuum / truncation.
    let journal = build_tier_a_journal(ps, 0x1234_5678, 9, &records);

    let anomalies = audit_journal(&db, &journal);
    let codes: Vec<&str> = anomalies.iter().map(|a| a.code).collect();

    assert!(
        codes.contains(&"SQLITE-JOURNAL-HOT"),
        "valid-magic header is a hot journal; got {codes:?}"
    );
    assert!(
        codes.contains(&"SQLITE-JOURNAL-CHECKSUM-MISMATCH"),
        "one record has a deliberately wrong checksum; got {codes:?}"
    );
    assert!(
        codes.contains(&"SQLITE-JOURNAL-DUPLICATE-PAGE"),
        "pgno 2 appears twice; got {codes:?}"
    );
    // SCHEMA-CHANGE is cookie-driven and validated against real engine artifacts
    // in `hot_journal_anomaly.rs`; this hand-built journal does not assert it.
    assert!(
        codes.contains(&"SQLITE-JOURNAL-DBSIZE-DELTA"),
        "mx_page (9) != db.page_count (1); got {codes:?}"
    );

    // CHECKSUM-MISMATCH note must SHOW the offending pgno and a count.
    let cksum = anomalies
        .iter()
        .find(|a| a.code == "SQLITE-JOURNAL-CHECKSUM-MISMATCH")
        .unwrap();
    assert!(
        cksum.note.contains('2'),
        "checksum note shows offending pgno; note = {:?}",
        cksum.note
    );

    // DBSIZE-DELTA note must SHOW both numbers and name the shrink direction.
    let dbsize = anomalies
        .iter()
        .find(|a| a.code == "SQLITE-JOURNAL-DBSIZE-DELTA")
        .unwrap();
    assert!(
        dbsize.note.contains('9') && dbsize.note.contains('1'),
        "dbsize note shows mx_page and current; note = {:?}",
        dbsize.note
    );
    assert!(
        dbsize.note.contains("vacuum") || dbsize.note.contains("truncation"),
        "shrink (mx_page > current) names vacuum/truncation; note = {:?}",
        dbsize.note
    );

    // The structured Evidence carries the offending pgno(s) + the record count for
    // the checksum mismatch, and both page numbers for the size delta.
    let ck_ev = cksum.evidence();
    assert!(
        ck_ev
            .iter()
            .any(|e| e.field == "checksum_mismatch_pgno" && e.value == "2"),
        "checksum evidence names the offending pgno; evidence = {ck_ev:?}"
    );
    assert!(
        ck_ev.iter().any(|e| e.field == "page_records"),
        "checksum evidence carries the record-count denominator; evidence = {ck_ev:?}"
    );
    let db_ev = dbsize.evidence();
    assert!(
        db_ev.iter().any(|e| e.field == "mx_page" && e.value == "9"),
        "size-delta evidence carries mx_page; evidence = {db_ev:?}"
    );
    assert!(
        db_ev
            .iter()
            .any(|e| e.field == "current_pages" && e.value == "1"),
        "size-delta evidence carries the current page count; evidence = {db_ev:?}"
    );
}

#[test]
fn tier_a_growth_reports_dbsize_delta_growth() {
    // mx_page < current → the txn GREW the db (INSERTs). Use a 3-page db and a
    // journal whose mx_page = 1.
    let db = tiny_db_512(3); // page_count = 3
    let ps = 512usize;
    let page = vec![0u8; ps];
    let journal = build_tier_a_journal(ps, 1, 1, &[(2u32, page, true)]);

    let anomalies = audit_journal(&db, &journal);
    let dbsize = anomalies
        .iter()
        .find(|a| a.code == "SQLITE-JOURNAL-DBSIZE-DELTA")
        .expect("mx_page (1) < page_count (3) → growth delta");
    assert!(
        dbsize.note.contains('1') && dbsize.note.contains('3'),
        "growth note shows both numbers; note = {:?}",
        dbsize.note
    );
    assert!(
        dbsize.note.contains("grew")
            || dbsize.note.contains("growth")
            || dbsize.note.contains("INSERT"),
        "growth (mx_page < current) names growth/INSERT; note = {:?}",
        dbsize.note
    );
}

#[test]
fn tier_a_no_delta_when_size_unchanged_or_unknown() {
    let db = tiny_db_512(1); // page_count = 1
    let ps = 512usize;
    let page = vec![0u8; ps];

    // mx_page == current (1) → no delta.
    let equal = build_tier_a_journal(ps, 1, 1, &[(2u32, page.clone(), true)]);
    assert!(
        !codes_of(&db, &equal).contains(&"SQLITE-JOURNAL-DBSIZE-DELTA"),
        "mx_page == current → no size delta"
    );

    // mx_page == 0 sentinel ("size unknown") → no delta.
    let zero = build_tier_a_journal(ps, 1, 0, &[(2u32, page, true)]);
    assert!(
        !codes_of(&db, &zero).contains(&"SQLITE-JOURNAL-DBSIZE-DELTA"),
        "mx_page == 0 sentinel → no size delta"
    );
}

#[test]
fn journal_findings_carry_source_and_code() {
    let main = std::fs::read(cfreds("SFT-03_PERSIST_ios.sqlite")).unwrap();
    let journal = std::fs::read(cfreds("SFT-03_PERSIST_ios.sqlite-journal")).unwrap();
    let db = Database::open(main).expect("open main");
    let source = Source {
        analyzer: "sqlite-forensic".to_string(),
        scope: "SFT-03_PERSIST_ios.sqlite-journal".to_string(),
        version: None,
    };
    let findings = audit_journal_findings(&db, &journal, &source);
    let codes: Vec<String> = findings.iter().map(|f| f.code.to_string()).collect();
    assert!(codes.iter().any(|c| c == "SQLITE-JOURNAL-RECOVERABLE"));
    assert!(findings
        .iter()
        .all(|f| f.source.analyzer == "sqlite-forensic"));
}

#[test]
fn malformed_journal_yields_no_anomalies() {
    // A short garbage journal decodes no records and no valid header → no Tier-A
    // anomalies, and no page images → no RECOVERABLE. Robust, never panics.
    let db = tiny_db_512(1);
    let anomalies = audit_journal(&db, &[0xFFu8; 16]);
    assert!(
        anomalies.is_empty(),
        "garbage journal yields no anomalies; got {anomalies:?}"
    );
}
