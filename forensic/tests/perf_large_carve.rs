//! THROUGHPUT perf-smoke over a large (~100 MB) messages-like SQLite database
//! with a known deleted subset. This pins two things a small fixture cannot:
//!
//! 1. **Correctness under scale** — the carver recovers (almost) all of a known
//!    80k-row deleted subset and surfaces ZERO live rows, on a real 100 MB image.
//! 2. **No catastrophic perf regression** — the carve finishes well under a
//!    generous wall-clock ceiling, so a pathological slowdown fails CI loudly.
//!
//! The 100 MB database is LARGE and is **gitignored**, like the other large
//! corpus artifacts (see `docs/corpus-catalog.md`). This test is env-gated on
//! `SQLITE_FORENSIC_PERF_DB` (an absolute path to the generated `.db`, with its
//! `<db>.deleted.json` manifest beside it). When the var is unset, or the file is
//! absent, the test **skips cleanly** so a plain `cargo test` stays green and
//! fast. Generate the DB with `tests/data/paper_fp/gen_large.py`.
//!
//! The measured throughput numbers themselves live in
//! `docs/competitive-landscape.md` ("Throughput"); this test is the regression
//! backstop behind those numbers, not the benchmark itself.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use sqlite_core::{Database, Value};
use sqlite_forensic::carve_all_deleted_records;

/// The ground-truth deleted id range baked into `gen_large.py`. The body of a
/// recovered row is tagged `MSG-<id>-…`, so a record's true id is read from its
/// content rather than trusting the carved rowid alias.
const DELETE_LO: i64 = 40_001;
const DELETE_HI: i64 = 120_000;

/// A generous ceiling: a non-pathological carve of a 100 MB image finishes far
/// under this. The point is to fail loudly on a catastrophic regression (e.g. an
/// accidental O(n^2)), not to police a tight latency budget — the real timings
/// are reported in `docs/competitive-landscape.md`.
const WALL_CLOCK_CEILING: Duration = Duration::from_secs(120);

fn perf_db_path() -> Option<PathBuf> {
    std::env::var_os("SQLITE_FORENSIC_PERF_DB").map(PathBuf::from)
}

fn body_id(values: &[Value]) -> Option<i64> {
    for v in values {
        if let Value::Text(t) = v {
            if let Some(rest) = t.strip_prefix("MSG-") {
                if let Some((num, _)) = rest.split_once('-') {
                    if let Ok(id) = num.parse::<i64>() {
                        return Some(id);
                    }
                }
            }
        }
    }
    None
}

#[test]
fn perf_smoke_carves_large_db_under_ceiling() {
    let Some(path) = perf_db_path() else {
        eprintln!(
            "SKIP perf_smoke_carves_large_db_under_ceiling: set SQLITE_FORENSIC_PERF_DB \
             (generate with tests/data/paper_fp/gen_large.py)"
        );
        return;
    };
    if !path.is_file() {
        eprintln!(
            "SKIP perf_smoke_carves_large_db_under_ceiling: {} not found \
             (generate with tests/data/paper_fp/gen_large.py)",
            path.display()
        );
        return;
    }

    let bytes = std::fs::read(&path).expect("read perf db");
    let db = Database::open(bytes).expect("open perf db");

    // (a) completes without panic, timed.
    let started = Instant::now();
    let recs = carve_all_deleted_records(&db);
    let elapsed = started.elapsed();

    // (b) recovers the known-deleted subset and ZERO live rows, keyed by the
    //     id-tagged body content.
    let total_deleted = DELETE_HI - DELETE_LO + 1;
    let mut recovered = std::collections::HashSet::new();
    let mut live_false_positives = std::collections::HashSet::new();
    for r in &recs {
        if let Some(id) = body_id(&r.values) {
            if (DELETE_LO..=DELETE_HI).contains(&id) {
                recovered.insert(id);
            } else {
                live_false_positives.insert(id);
            }
        }
    }

    // ZERO live rows surface as recovered: the deleted range is contiguous in the
    // middle, with live rows on both sides, so a carver that excludes live rowids
    // must report no id outside DELETE_LO..=DELETE_HI.
    assert!(
        live_false_positives.is_empty(),
        "carve surfaced {} live rows as deleted (false positives): {:?}",
        live_false_positives.len(),
        {
            let mut v: Vec<i64> = live_false_positives.iter().copied().collect();
            v.sort_unstable();
            v.truncate(10);
            v
        }
    );

    // A high recovery fraction (the carve must actually recover the subset, not
    // silently return empty — a few rows may be lost to same-page reuse).
    let recall = recovered.len() as f64 / total_deleted as f64;
    assert!(
        recall >= 0.95,
        "carver must recover >=95% of the {total_deleted} deleted rows; got {} ({:.4})",
        recovered.len(),
        recall
    );

    // (c) under a generous wall-clock ceiling.
    assert!(
        elapsed <= WALL_CLOCK_CEILING,
        "carve of {} took {elapsed:?}, over the {WALL_CLOCK_CEILING:?} ceiling",
        path.display()
    );

    eprintln!(
        "perf: carved {} records, recovered {}/{} deleted ({:.4}), {} live FP, in {elapsed:?}",
        recs.len(),
        recovered.len(),
        total_deleted,
        recall,
        live_false_positives.len()
    );
}
