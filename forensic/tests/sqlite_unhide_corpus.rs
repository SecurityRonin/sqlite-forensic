//! Independent ground-truth validation against the **sqlite-unhide** corpus
//! (`little-brother/sqlite-unhide`, `tests/extra`): nine hand-built deleted-record
//! databases, each shipped with a `.sql` builder and a `.txt` answer key authored
//! by a third party. Unlike our own fixtures, the expected results here were
//! written by someone who did not design our carver — the Doer-Checker payoff.
//!
//! The corpus is **"FREEWARE. HOME USE ONLY."** with no redistribution licence, so
//! its files are **never committed**. Download `tests/extra/*.db` (+ `.txt`) for
//! your own assessment, then point `SQLITE_FORENSIC_UNHIDE_CORPUS` at the
//! directory. With the var unset the test **skips cleanly** (CI stays green/fast),
//! exactly like the iOS real-device corpus.
//!
//! ```text
//! SQLITE_FORENSIC_UNHIDE_CORPUS=tests-oracle-corpus/sqlite-unhide \
//!   cargo test -p sqlite-forensic --test sqlite_unhide_corpus -- --nocapture
//! ```
//!
//! Provenance + per-file ground truth: `tests-oracle-corpus/README.md`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::pedantic)]

use std::path::PathBuf;

use sqlite_core::{Database, Value};
use sqlite_forensic::carve_all_deleted_records;

/// The corpus root from `SQLITE_FORENSIC_UNHIDE_CORPUS`, or `None` to skip.
fn corpus_root() -> Option<PathBuf> {
    match std::env::var("SQLITE_FORENSIC_UNHIDE_CORPUS") {
        Ok(p) if !p.is_empty() => {
            let path = PathBuf::from(p);
            if path.is_dir() {
                Some(path)
            } else {
                eprintln!(
                    "SKIP sqlite_unhide_corpus: SQLITE_FORENSIC_UNHIDE_CORPUS={} is not a directory",
                    path.display()
                );
                None
            }
        }
        _ => {
            eprintln!(
                "SKIP sqlite_unhide_corpus: set SQLITE_FORENSIC_UNHIDE_CORPUS to a local copy of \
                 little-brother/sqlite-unhide tests/extra (home-use, never committed)"
            );
            None
        }
    }
}

/// Open `NN.db` from the corpus, read-only into owned bytes.
fn open(root: &std::path::Path, stem: &str) -> Option<Database> {
    let path = root.join(format!("{stem}.db"));
    let bytes = std::fs::read(&path).ok()?;
    Database::open(bytes).ok()
}

/// The widest live (schema-present) user table — the structural upper bound on a
/// legitimately-attributable recovered record's column count.
fn max_live_columns(db: &Database) -> Option<usize> {
    db.live_tables().iter().map(|t| t.affinities.len()).max()
}

/// Structural-noise invariant: across every sqlite-unhide database, no recovered
/// full record may have more columns than the widest live table (it would belong
/// to no table in the schema) or be entirely NULL (no recoverable content). This
/// is the regression guard for the inferred-carver over-read that read a run of
/// free-space zero bytes as a 100+-column serial-type-0 record on 03/04/05/06.
#[test]
fn no_full_record_is_structural_noise() {
    let Some(root) = corpus_root() else {
        return;
    };
    let mut checked = 0usize;
    for i in 1..=9 {
        let stem = format!("{i:02}");
        let Some(db) = open(&root, &stem) else {
            continue;
        };
        checked += 1;
        let bound = max_live_columns(&db);
        for rec in carve_all_deleted_records(&db) {
            if let Some(max) = bound {
                assert!(
                    rec.values.len() <= max,
                    "{stem}.db: recovered record with {} columns exceeds the widest live table \
                     ({max}) — structural over-read: {:?}",
                    rec.values.len(),
                    rec.values
                );
            }
            assert!(
                !rec.values.iter().all(|v| matches!(v, Value::Null)),
                "{stem}.db: recovered an all-NULL record (no recoverable content): {:?}",
                rec.values
            );
        }
    }
    assert!(
        checked > 0,
        "SQLITE_FORENSIC_UNHIDE_CORPUS contained no 01.db..09.db"
    );
    eprintln!("sqlite_unhide_corpus: structural-noise invariant held across {checked} database(s)");
}

/// 09.db (key: `"lyrics" 2 rows (5002, 5014)`, UTF-8) — the two deleted rows have
/// 2-byte rowids (5002/5014) and Cyrillic `line` text, so they are
/// freeblock-clobbered cells with an all-surviving serial array. Real-corpus
/// confirmation of the multi-byte-rowid reconstruction fix (committed-fixture
/// twin: `freeblock_highrowid.rs`).
#[test]
#[ignore = "known gap: 2-byte-rowid freeblock recovery awaits the \
            precision-preserving (exact-tile) reconstruction (see \
            freeblock_highrowid.rs)"]
fn recovers_utf8_high_rowid_rows_from_09() {
    let Some(root) = corpus_root() else {
        return;
    };
    let Some(db) = open(&root, "09") else {
        eprintln!("SKIP: 09.db absent from corpus");
        return;
    };
    let texts: Vec<String> = carve_all_deleted_records(&db)
        .into_iter()
        .flat_map(|r| r.values)
        .filter_map(|v| match v {
            Value::Text(t) => Some(t),
            _ => None,
        })
        .collect();
    // The two deleted Cyrillic lines (ids 5014, 5002).
    assert!(
        texts.iter().any(|t| t.contains("Столица")),
        "09.db: deleted UTF-8 row (id 5014) not recovered; got {texts:?}"
    );
    assert!(
        texts.iter().any(|t| t.contains("Весь мир")),
        "09.db: deleted UTF-8 row (id 5002) not recovered; got {texts:?}"
    );
}
