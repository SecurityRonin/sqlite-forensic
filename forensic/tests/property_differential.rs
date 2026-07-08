//! Property-based differential vs the real `sqlite3` engine (roadmap §5).
//!
//! Instead of one hand-authored fixture, this constructs MANY random databases
//! (deterministic seeds, so failures reproduce), deletes a random subset of rows,
//! carves, and asserts two properties on every run:
//!
//!   1. **No fabrication** — every carved value-tuple was genuinely inserted by the
//!      construction log (the carver never invents a row).
//!   2. **Exclusion invariant** — no carved (deleted) record equals a currently
//!      LIVE row. This is the cross-table/residue hazard a fixed corpus misses:
//!      random layouts exercise page reuse, freeblock coalescing, and mixed
//!      live/deleted cells the author never enumerated.
//!
//! Ground truth comes from the engine itself: the live set is read back with
//! `SELECT`, and the inserted set is the log — a Tier-2 oracle (real engine, truth
//! derivable from the documented construction). Env-gated on a `sqlite3` binary
//! (`SQLITE3_BIN`, else PATH); skips cleanly when absent.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use sqlite_core::{Database, Value};
use sqlite_forensic::carve_all_deleted_records;

fn sqlite3_bin() -> Option<String> {
    let bin = std::env::var("SQLITE3_BIN").unwrap_or_else(|_| "sqlite3".to_string());
    Command::new(&bin)
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|_| bin)
}

/// A deterministic 64-bit LCG (Numerical Recipes constants). No `rand` dependency,
/// no wall-clock seed — same seed reproduces the same database, so a failing
/// property shrinks to an exact, re-runnable case.
fn lcg_next(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

fn run_sql(bin: &str, db: &Path, sql: &str) -> bool {
    Command::new(bin)
        .arg(db)
        .arg(sql)
        .status()
        .is_ok_and(|s| s.success())
}

fn query_lines(bin: &str, db: &Path, sql: &str) -> Vec<String> {
    let out = Command::new(bin).arg(db).arg(sql).output().unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .collect()
}

#[test]
fn carved_records_are_derivable_and_never_live() {
    let Some(bin) = sqlite3_bin() else {
        eprintln!("SKIP property_differential: no sqlite3 (set SQLITE3_BIN)");
        return;
    };
    let dir = std::env::temp_dir().join("sqlite4n6-property-differential");
    let _ = std::fs::remove_dir_all(&dir);
    if std::fs::create_dir_all(&dir).is_err() {
        eprintln!("SKIP: cannot create temp dir");
        return;
    }

    let mut recovered_total = 0usize;
    // Fixed seed list → deterministic, reproducible construction.
    for seed in [1_u64, 7, 42, 1337, 99_991] {
        let mut rng = seed;
        let db_path: PathBuf = dir.join(format!("prop_{seed}.db"));
        let _ = std::fs::remove_file(&db_path);

        // secure_delete=OFF so freed cells keep residue (the recoverable case);
        // a unique payload per (seed,id) makes each tuple its own identity.
        let n: i64 = 80;
        let mut sql = String::from(
            "PRAGMA page_size=4096; PRAGMA secure_delete=OFF; \
             CREATE TABLE t(id INTEGER PRIMARY KEY, payload TEXT);\n",
        );
        let mut inserted: HashSet<String> = HashSet::new();
        for id in 1..=n {
            let payload = format!("s{seed}-r{id}-{:016x}", lcg_next(&mut rng));
            inserted.insert(payload.clone());
            let _ = writeln!(sql, "INSERT INTO t VALUES({id},'{payload}');");
        }
        // Delete a random ~half of the rows.
        let deleted_ids: Vec<i64> = (1..=n).filter(|_| lcg_next(&mut rng) % 2 == 0).collect();
        if !deleted_ids.is_empty() {
            let list = deleted_ids
                .iter()
                .map(i64::to_string)
                .collect::<Vec<_>>()
                .join(",");
            let _ = writeln!(sql, "DELETE FROM t WHERE id IN ({list});");
        }
        assert!(
            run_sql(&bin, &db_path, &sql),
            "sqlite3 construction failed for seed {seed}"
        );

        // Ground truth from the engine: the surviving (live) payloads.
        let live: HashSet<String> = query_lines(&bin, &db_path, "SELECT payload FROM t;")
            .into_iter()
            .collect();

        let bytes = std::fs::read(&db_path).unwrap();
        let db = Database::open(bytes).expect("constructed db opens");
        let recovered = carve_all_deleted_records(&db);

        for rec in &recovered {
            // The payload column is our identity; ignore anything not ours (the
            // carver may surface structural noise, which the tool already grades).
            let Some(payload) = rec.values.iter().find_map(|v| match v {
                Value::Text(t) if t.starts_with(&format!("s{seed}-")) => Some(t.clone()),
                _ => None,
            }) else {
                continue;
            };
            recovered_total += 1;
            assert!(
                inserted.contains(&payload),
                "seed {seed}: carver fabricated a row never inserted: {payload}"
            );
            assert!(
                !live.contains(&payload),
                "seed {seed}: exclusion invariant breached — a LIVE row was surfaced \
                 as deleted: {payload}"
            );
        }
    }

    assert!(
        recovered_total > 0,
        "the property test recovered nothing across all seeds — it would pass vacuously"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
