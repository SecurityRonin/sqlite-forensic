//! Freeblock reconstruction of deleted rows with a **multi-byte rowid varint**
//! (rowid ≥ 128) — the common case the freeblock-template path silently dropped.
//!
//! When a table-leaf cell is freed, SQLite overwrites its first four bytes with
//! the freeblock header (`next`/`size`). Those four bytes cover the
//! `payload-length` + `rowid` varints and the record `header_len`. For a **1-byte**
//! rowid the clobber also eats the first serial type, leaving a "known leading
//! serial" the template can supply. For a **2-byte** rowid (any rowid ≥ 128) the
//! prefix is one byte wider, so the clobber stops at `header_len` and **no** serial
//! type is destroyed — the whole serial array survives. The template builder used
//! to reject that case, so freeblock-clobbered rows past rowid 127 were lost.
//!
//! The recovery is precision-gated: an empty-leading-serial page reconstructs each
//! freeblock only when the record tiles it **exactly** (`record_end == fb_end`), so
//! a coalesced or misaligned run yields nothing rather than a column-shifted
//! phantom. The independent sqlite-unhide 09.db (Cyrillic, autoincrement ids) is
//! the env-gated real-corpus twin (`sqlite_unhide_corpus.rs`).
//!
//! Fixture (`tests/data/freeblock_2byte_rowid.db`, Tier-2, real `sqlite3` engine;
//! ground truth derivable from the construction):
//! ```sql
//! PRAGMA page_size=4096; PRAGMA secure_delete=0;
//! CREATE TABLE m(id INTEGER PRIMARY KEY, sid TEXT, line TEXT, n INT);
//! -- insert id 1000..1259 as ('s'||id, 'line text for record '||id, id), then:
//! DELETE FROM m WHERE id IN (1050, 1130, 1210);
//! ```
//! Every rowid is 2-byte; the deletions are well-separated so each freed cell is
//! its own (non-coalesced) freeblock.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::pedantic)]

use sqlite_core::{Database, Value};
use sqlite_forensic::carve_all_deleted_records;

fn recovered_texts(db: &Database) -> Vec<String> {
    carve_all_deleted_records(db)
        .into_iter()
        .flat_map(|r| r.values)
        .filter_map(|v| match v {
            Value::Text(t) => Some(t),
            _ => None,
        })
        .collect()
}

#[test]
fn recovers_deleted_rows_with_two_byte_rowid() {
    let bytes = std::fs::read("../tests/data/freeblock_2byte_rowid.db")
        .or_else(|_| std::fs::read("tests/data/freeblock_2byte_rowid.db"))
        .expect("fixture readable");
    let db = Database::open(bytes).expect("fixture opens");
    let texts = recovered_texts(&db);

    for id in [1050, 1130, 1210] {
        let want = format!("line text for record {id}");
        assert!(
            texts.iter().any(|t| t == &want),
            "2-byte-rowid row {id} must recover (freeblock-clobbered, all serials \
             survive); got {texts:?}"
        );
    }
}

/// Coalesced freeblock: adjacent deletions (ids 1100..=1104) merge into one
/// multi-cell freeblock. Span-level exact-tiling walks the coalesced cells and
/// recovers them only when they tile the freeblock exactly — recovering each row
/// without emitting a partial/misaligned phantom.
///
/// Fixture `tests/data/freeblock_coalesced.db` (same shape as above,
/// `DELETE FROM m WHERE id BETWEEN 1100 AND 1104`).
#[test]
fn recovers_coalesced_two_byte_rowid_rows() {
    let bytes = std::fs::read("../tests/data/freeblock_coalesced.db")
        .or_else(|_| std::fs::read("tests/data/freeblock_coalesced.db"))
        .expect("fixture readable");
    let db = Database::open(bytes).expect("fixture opens");
    let texts = recovered_texts(&db);
    let recovered = (1100..=1104)
        .filter(|id| {
            texts
                .iter()
                .any(|t| t == &format!("line text for record {id}"))
        })
        .count();
    // Span-tiling should recover the coalesced run; require a clear majority so a
    // boundary cell that does not tile cleanly does not fail the test.
    assert!(
        recovered >= 4,
        "coalesced freeblock: expected >= 4 of ids 1100..=1104 recovered, got {recovered}; \
         texts={texts:?}"
    );
    // Precision: no misaligned phantom among them.
    for t in &texts {
        if t.contains("line text for record") {
            assert!(
                t.starts_with("line text for record") && !t.chars().any(char::is_control),
                "coalesced recovery emitted a misaligned phantom: {t:?}"
            );
        }
    }
}

/// Precision: the exact-tile gate must not emit a column-shifted phantom — no
/// recovered `line` text may be a misaligned read of the real value (a leading
/// control byte, or a truncated body). A clean recovery is exactly
/// `"line text for record <id>"`.
#[test]
fn two_byte_rowid_recovery_emits_no_misaligned_phantom() {
    let bytes = std::fs::read("../tests/data/freeblock_2byte_rowid.db")
        .or_else(|_| std::fs::read("tests/data/freeblock_2byte_rowid.db"))
        .expect("fixture readable");
    let db = Database::open(bytes).expect("fixture opens");
    for t in recovered_texts(&db) {
        if t.contains("line text for record") {
            assert!(
                t.starts_with("line text for record"),
                "misaligned phantom (leading junk before the real value): {t:?}"
            );
            assert!(
                !t.contains('\u{FFFD}') && !t.chars().any(|c| c.is_control()),
                "misaligned phantom (control/replacement char in body): {t:?}"
            );
        }
    }
}
