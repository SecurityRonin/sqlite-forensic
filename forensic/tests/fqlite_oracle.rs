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
//! `JavaFX` GUI-only application (its README states "With version 2.0, the support
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
//! 1. `tests/data/deleted_places.db` — OUR fixture. undark is an
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
/// Both tools are compared on this projection (the `moz_places` / `users`-style
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

/// Deleted rowids undark recovers from our fixture that our carver does NOT,
/// for a documented and understood reason rather than a defect.
///
/// rowid 237 lives on page 8, a still-**allocated** leaf page from which some
/// rows were deleted in place (an in-page free block). Our carver deliberately
/// scans only freelist pages (9 = trunk, 10..=13 = leaves) so it never
/// re-surfaces content from allocated pages — a safety property (it cannot
/// mistake a live page's slack for a deleted row). undark scans byte-by-byte
/// across all pages, so it additionally reaches that one in-page remnant.
/// See `docs/validation.md` for the page-level diagnosis.
const FIXTURE_IN_PAGE_DIVERGENCES: &[i64] = &[237];

/// OUR fixture, reconciled against the undark oracle.
///
/// Honest GREEN criterion (not "identical sets", which would overstate — see
/// the RED commit and `docs/validation.md`):
///   1. No false positives: every rowid we carve, undark also recovers.
///   2. Exact content agreement on every overlapping rowid (url + title).
///   3. Completeness on our scope: we recover every deleted row undark
///      recovers, except the documented in-page divergences on allocated pages.
#[test]
fn our_fixture_agrees_with_undark() {
    let Some(undark) = undark_bin() else {
        eprintln!("SKIP our_fixture_agrees_with_undark: set UNDARK_BIN to the undark binary");
        return;
    };
    let db_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/data/deleted_places.db");
    let bytes = std::fs::read(&db_path).unwrap();
    let db = Database::open(bytes).unwrap();

    let ours = ours_recover(&db, 6);
    let oracle = undark_recover(&undark, &db_path);

    // The deleted ground-truth range for this fixture is ids 201..=400.
    let in_del = |k: &i64| (201..=400).contains(k);
    let oracle_deleted: RowSet = oracle
        .iter()
        .filter(|(k, _)| in_del(k))
        .map(|(k, v)| (*k, v.clone()))
        .collect();
    let ours_deleted: RowSet = ours
        .iter()
        .filter(|(k, _)| in_del(k))
        .map(|(k, v)| (*k, v.clone()))
        .collect();

    // (1) No false positives — never carve a rowid undark cannot corroborate.
    for rowid in ours_deleted.keys() {
        assert!(
            oracle_deleted.contains_key(rowid),
            "carved rowid {rowid} is not corroborated by the undark oracle (possible false positive)"
        );
    }

    // (2) Exact content agreement on every overlapping rowid.
    for (rowid, ours_val) in &ours_deleted {
        let oracle_val = &oracle_deleted[rowid];
        assert_eq!(
            ours_val, oracle_val,
            "content mismatch for rowid {rowid}: ours {ours_val:?} vs undark {oracle_val:?}"
        );
    }

    // (3) Completeness on our scope: every undark-recovered deleted row is
    // either recovered by us or a documented in-page divergence.
    let documented: std::collections::BTreeSet<i64> =
        FIXTURE_IN_PAGE_DIVERGENCES.iter().copied().collect();
    let mut undocumented_misses: Vec<i64> = oracle_deleted
        .keys()
        .filter(|k| !ours_deleted.contains_key(k) && !documented.contains(k))
        .copied()
        .collect();
    undocumented_misses.sort_unstable();
    assert!(
        undocumented_misses.is_empty(),
        "undark recovered deleted rows we miss with no documented reason: {undocumented_misses:?}"
    );

    // And the documented divergence is real, not a stale exemption: each listed
    // rowid must genuinely be recovered by undark yet absent from our output.
    for d in FIXTURE_IN_PAGE_DIVERGENCES {
        assert!(
            oracle_deleted.contains_key(d) && !ours_deleted.contains_key(d),
            "documented in-page divergence {d} is stale (undark/ours no longer disagree here) — re-verify and update the exemption"
        );
    }

    // The row-300 verbatim spot-check, now cross-checked against the oracle too.
    assert_eq!(
        ours_deleted.get(&300),
        Some(&(
            "https://site-300.example.com/path/page".to_string(),
            "Title for record number 300 SECRETMARKER".to_string()
        )),
        "row 300 must be recovered verbatim and agree with undark"
    );
}

/// DC3 `sqlite_dissect` corpus, reconciled against the undark oracle.
///
/// These DBs delete records WITHOUT freeing whole pages onto the freelist
/// (`freelist_count` is 0 for the in-page cases) or drop a table entirely.
/// undark, scanning byte-by-byte, recovers them; our carver, which by design
/// scans only freelist pages, recovers none — a **documented scope boundary**,
/// the load-bearing independent finding of this validation (see
/// `docs/validation.md`). The fully-recoverable-by-freelist scenario is covered
/// by `our_fixture_agrees_with_undark`.
///
/// Honest GREEN criterion per DB:
///   1. Oracle sanity: undark recovers at least one record.
///   2. No false positives: our carved set is a SUBSET of undark's.
///   3. Exact content agreement on any overlapping rowid.
///   4. Whatever undark recovers but we don't is the in-page/dropped-table gap.
#[test]
fn dc3_corpus_agrees_with_undark() {
    let Some(undark) = undark_bin() else {
        eprintln!("SKIP dc3_corpus_agrees_with_undark: set UNDARK_BIN to the undark binary");
        return;
    };
    // DBs in the DC3 corpus that contain carvable deleted records, with their
    // single-table column count. `in_page_only` marks DBs whose deletions never
    // reach the freelist, so our freelist-scoped carver recovers nothing — the
    // documented gap, asserted explicitly so a future in-page carver makes this
    // test tighten rather than silently pass.
    struct Case {
        name: &'static str,
        cols: usize,
        in_page_only: bool,
    }
    let cases = [
        Case {
            name: "corpus_01-01.db",
            cols: 4,
            in_page_only: true,
        },
        Case {
            name: "corpus_01-02.db",
            cols: 4,
            in_page_only: true,
        },
        Case {
            name: "corpus_03-02.db",
            cols: 4,
            in_page_only: true,
        },
        Case {
            name: "corpus_07-01.db",
            cols: 4,
            in_page_only: true,
        },
        Case {
            name: "corpus_0A-01.db",
            cols: 6,
            in_page_only: true,
        },
        Case {
            name: "corpus_0A-02.db",
            cols: 6,
            in_page_only: true,
        },
    ];

    let mut ran = 0usize;
    for case in &cases {
        let path = corpus_db(case.name);
        if !path.exists() {
            eprintln!(
                "SKIP {}: DC3 corpus DB absent (gitignored — see tests-fqlite-corpus/README.md)",
                case.name
            );
            continue;
        }
        ran += 1;
        let name = case.name;
        let db = Database::open(std::fs::read(&path).unwrap()).unwrap();
        let ours = ours_recover(&db, case.cols);
        let oracle = undark_recover(&undark, &path);

        // (1) Oracle sanity.
        assert!(
            !oracle.is_empty(),
            "{name}: undark must recover at least one record (oracle sanity)"
        );

        // (2) No false positives — our set is a subset of undark's, and
        // (3) content agrees on every overlapping rowid.
        for (rowid, ours_val) in &ours {
            let oracle_val = oracle.get(rowid).unwrap_or_else(|| {
                panic!("{name}: carved rowid {rowid} not corroborated by undark (false positive)")
            });
            assert_eq!(
                ours_val, oracle_val,
                "{name}: content mismatch for rowid {rowid}"
            );
        }

        // (4) Documented gap: in-page/dropped-table DBs are outside our
        // freelist-only scope, so we recover nothing here. Assert that boundary
        // explicitly — if a future carver gains in-page recovery this fires and
        // the exemption must be re-derived against undark.
        if case.in_page_only {
            assert!(
                ours.is_empty(),
                "{name}: carver now recovers in-page deletions ({} rows) — \
                 re-reconcile against undark and tighten this case",
                ours.len()
            );
        }
    }
    assert!(ran > 0, "no DC3 corpus DB was available to test");
}
