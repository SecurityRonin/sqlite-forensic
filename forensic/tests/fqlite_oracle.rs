//! Independent-oracle differential validation of [`carve_deleted_records`].
//!
//! # Why this test exists (Doer-Checker)
//!
//! `carve.rs` validates the carver against a fixture WE generated, with a carver
//! WE wrote and assertions WE wrote — self-referential validation that can pass
//! while sharing a blind spot with the generator. This test removes that blind
//! spot by reconciling our output against an **independent reference tool** as
//! the yardstick.
//!
//! ## Oracle: `undark`, not fqlite
//!
//! The original plan named **fqlite** (Pawlaszczyk) as the oracle. fqlite turned
//! out to be unusable as a headless oracle: every release since 2.0 ships a
//! JavaFX GUI-only application (its README states "With version 2.0, the support
//! for the command line mode was cancelled"), the current releases are ~440 MB
//! `jpackage` native bundles with no runnable CLI jar, and fqlite is not
//! published to Maven Central, so there is no engine to drive headlessly. See
//! `docs/validation.md` for the full evidence.
//!
//! The independent oracle is therefore **undark** (Paul L. Daniels), a small
//! C SQLite deleted-record carver. It is a different author, a different
//! language, and a different algorithm from ours, which is exactly what an
//! independent oracle must be.
//!
//! ## Two corpora, two levels of independence
//!
//! 1. `forensic/tests/data/deleted_places.db` — OUR fixture. undark is an
//!    independent *oracle* over our input.
//! 2. `tests-fqlite-corpus/dc3-sqlite-dissect/*.db` — the DC3 (Department of
//!    Defense Cyber Crime Center) `sqlite_dissect` test corpus. Authored by
//!    neither us nor undark's author, so neither the input DB nor the oracle is
//!    ours — the strongest form of Doer-Checker validation. These DBs exercise
//!    in-page free-block deletion and dropped-table cases our whole-freed-page
//!    fixture cannot reach, and they surface a documented carver scope boundary.
//!
//! # Gating
//!
//! Skips (passes) unless `UNDARK_BIN` points at a built `undark` binary, so CI
//! without the tool still passes. The DC3 corpus is gitignored; cases over it
//! also skip if the files are absent. Provenance, hashes, and the exact build
//! recipe for undark are in `docs/validation.md` and `docs/corpus-catalog.md`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use sqlite_core::{Database, Value};
use sqlite_forensic::carve_deleted_records;

/// A row reduced to its forensically-comparable identity: rowid -> (url, title).
/// Both tools are compared on this projection (the moz_places / users-style
/// `url`/`name`-and-`title`/`surname` text columns at positions 1 and 2).
type RowSet = BTreeMap<i64, (String, String)>;

fn undark_bin() -> Option<PathBuf> {
    std::env::var_os("UNDARK_BIN").map(PathBuf::from)
}

/// Run undark on `db` and parse its CSV dump into rowid -> (col1, col2).
///
/// undark emits one CSV line per recovered record: `rowid,id,col1,col2,...`.
/// We key by the integer rowid (field 0) and project the two text columns at
/// CSV fields 2 and 3 (the table's first two non-id text columns).
fn undark_recover(undark: &Path, db: &Path) -> RowSet {
    let out = Command::new(undark)
        .arg("-i")
        .arg(db)
        .output()
        .expect("undark must execute");
    let text = String::from_utf8_lossy(&out.stdout);
    let mut set = RowSet::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let fields = split_csv(line);
        let Some(rowid) = fields.first().and_then(|f| f.parse::<i64>().ok()) else {
            continue;
        };
        let c1 = fields.get(2).cloned().unwrap_or_default();
        let c2 = fields.get(3).cloned().unwrap_or_default();
        set.insert(rowid, (unquote(&c1), unquote(&c2)));
    }
    set
}

/// Minimal CSV field split honoring undark's `"..."` quoting (no embedded
/// escaped quotes appear in this corpus). Sufficient for the oracle projection.
fn split_csv(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut in_q = false;
    for ch in line.chars() {
        match ch {
            '"' => in_q = !in_q,
            ',' if !in_q => {
                fields.push(std::mem::take(&mut cur));
            }
            _ => cur.push(ch),
        }
    }
    fields.push(cur);
    fields
}

fn unquote(s: &str) -> String {
    s.trim().trim_matches('"').to_string()
}

/// Project our carver's output to the same rowid -> (text1, text2) identity.
fn ours_recover(db: &Database, cols: usize) -> RowSet {
    let mut set = RowSet::new();
    for rec in carve_deleted_records(db, cols) {
        let t1 = match rec.values.get(1) {
            Some(Value::Text(s)) => s.clone(),
            _ => String::new(),
        };
        let t2 = match rec.values.get(2) {
            Some(Value::Text(s)) => s.clone(),
            _ => String::new(),
        };
        set.insert(rec.rowid, (t1, t2));
    }
    set
}

fn corpus_db(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../tests-fqlite-corpus/dc3-sqlite-dissect")
        .join(name)
}

/// OUR fixture, reconciled against the undark oracle.
///
/// Strong RED claim: our carver and undark recover the *identical* deleted-row
/// set (same rowids, same content). This is deliberately strict so the harness
/// is proven able to fail before GREEN relaxes it to the honest criterion.
#[test]
fn our_fixture_agrees_with_undark() {
    let Some(undark) = undark_bin() else {
        eprintln!("SKIP our_fixture_agrees_with_undark: set UNDARK_BIN to the undark binary");
        return;
    };
    let db_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/deleted_places.db");
    let bytes = std::fs::read(&db_path).unwrap();
    let db = Database::open(bytes).unwrap();

    let ours = ours_recover(&db, 6);
    let oracle = undark_recover(&undark, &db_path);

    // The deleted ground-truth range for this fixture is ids 201..=400.
    let oracle_deleted: RowSet = oracle
        .iter()
        .filter(|(&k, _)| (201..=400).contains(&k))
        .map(|(k, v)| (*k, v.clone()))
        .collect();
    let ours_deleted: RowSet = ours
        .iter()
        .filter(|(&k, _)| (201..=400).contains(&k))
        .map(|(k, v)| (*k, v.clone()))
        .collect();

    // RED: demand exact set equality on rowids.
    assert_eq!(
        ours_deleted.keys().collect::<Vec<_>>(),
        oracle_deleted.keys().collect::<Vec<_>>(),
        "our carved deleted-row set must equal undark's exactly"
    );
    // Content must match on every overlapping rowid.
    for (rowid, oval) in &oracle_deleted {
        if let Some(ours_val) = ours_deleted.get(rowid) {
            assert_eq!(ours_val, oval, "content mismatch for rowid {rowid}");
        }
    }
}

/// DC3 `sqlite_dissect` corpus, reconciled against the undark oracle.
///
/// Each entry: (file, column_count, deleted-range). RED claim: for every DB
/// undark can carve a deleted record from, our carver recovers the same set.
#[test]
fn dc3_corpus_agrees_with_undark() {
    let Some(undark) = undark_bin() else {
        eprintln!("SKIP dc3_corpus_agrees_with_undark: set UNDARK_BIN to the undark binary");
        return;
    };
    // DBs in the DC3 corpus that contain carvable deleted records, with their
    // single-table column count.
    let cases: &[(&str, usize)] = &[
        ("corpus_01-01.db", 4),
        ("corpus_01-02.db", 4),
        ("corpus_03-02.db", 4),
        ("corpus_07-01.db", 4),
        ("corpus_0A-01.db", 6),
        ("corpus_0A-02.db", 6),
    ];

    let mut ran = 0usize;
    for (name, cols) in cases {
        let path = corpus_db(name);
        if !path.exists() {
            eprintln!("SKIP {name}: DC3 corpus DB absent (gitignored — see tests-fqlite-corpus/README.md)");
            continue;
        }
        ran += 1;
        let db = Database::open(std::fs::read(&path).unwrap()).unwrap();
        let ours = ours_recover(&db, *cols);
        let oracle = undark_recover(&undark, &path);

        // undark recovers records here; RED demands our carver match its set.
        assert!(
            !oracle.is_empty(),
            "{name}: undark must recover at least one record (oracle sanity)"
        );
        assert_eq!(
            ours.keys().collect::<Vec<_>>(),
            oracle.keys().collect::<Vec<_>>(),
            "{name}: our carved set must equal undark's recovered set"
        );
    }
    assert!(ran > 0, "no DC3 corpus DB was available to test");
}
