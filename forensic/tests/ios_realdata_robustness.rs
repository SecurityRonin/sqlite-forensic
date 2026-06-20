//! Real-device robustness over genuine iOS application SQLite databases.
//!
//! Synthetic and standardized-corpus fixtures (Nemetz, NIST CFReDS) prove
//! correctness against *authored* inputs; this harness proves the analyzer
//! survives **real-world device artifacts** it never saw — live WAL sidecars,
//! vendor schemas, Biome/CloudKit internal tables — with no panic and a
//! structurally-sane result. It is the real-data front door of the Doer-Checker
//! discipline for the whole pipeline.
//!
//! The corpus is the gitignored, manually-downloaded **Josh Hickman iOS 17**
//! image (owned by the `issen` repo; ~21 GB, never committed here). The test is
//! **env-gated**: point `SQLITE_FORENSIC_IOS_CORPUS` at the extracted corpus root
//! and it walks every SQLite database under it; with the var unset it **skips
//! cleanly**, so a normal `cargo test` and CI stay green and fast.
//!
//! Evidence hygiene: every database is read into owned bytes and opened
//! read-only — the corpus files are never opened read-write (a WAL-mode db opened
//! read-write would checkpoint and mutate the evidence).
//!
//! ```text
//! SQLITE_FORENSIC_IOS_CORPUS=~/src/issen/tests/data/josh-hickman-ios17-biome-segb \
//!   cargo test -p sqlite-forensic --test ios_realdata_robustness -- --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::pedantic)]

use std::path::{Path, PathBuf};

use sqlite_core::{Database, Value};
use sqlite_forensic::{
    audit, audit_journal, carve_all_deleted_records, carve_rollback_journal, carve_with_fragments,
    row_histories_with_residue,
};

/// The corpus root from `SQLITE_FORENSIC_IOS_CORPUS`, or `None` to skip.
fn corpus_root() -> Option<PathBuf> {
    match std::env::var("SQLITE_FORENSIC_IOS_CORPUS") {
        Ok(p) if !p.is_empty() => {
            let path = PathBuf::from(p);
            if path.is_dir() {
                Some(path)
            } else {
                eprintln!(
                    "SKIP ios_realdata_robustness: SQLITE_FORENSIC_IOS_CORPUS={} is not a directory",
                    path.display()
                );
                None
            }
        }
        _ => {
            eprintln!(
                "SKIP ios_realdata_robustness: set SQLITE_FORENSIC_IOS_CORPUS to the extracted \
                 Josh Hickman iOS corpus root to run this real-device robustness sweep"
            );
            None
        }
    }
}

/// Every SQLite database file under `root` (recursive), excluding the
/// `-wal`/`-shm`/`-journal` sidecars (those are attached to their main db).
fn all_ios_dbs(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            // Skip sidecars; keep main databases. iOS apps use .db / .sqlite /
            // .sqlite3, so key off "looks like a db" minus the sidecar suffixes.
            if name.ends_with("-wal") || name.ends_with("-shm") || name.ends_with("-journal") {
                continue;
            }
            if name.ends_with(".db") || name.ends_with(".sqlite") || name.ends_with(".sqlite3") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// A carved record's decoded values must be structurally coherent (mirrors
/// `nemetz_robustness::assert_record_sane`).
fn assert_record_sane(values: &[Value]) {
    assert!(
        values.len() <= 100_000,
        "carved record has implausible column count {}",
        values.len()
    );
    for v in values {
        if let Value::Blob(b) = v {
            let _ = b.len();
        }
    }
}

/// Append a sidecar suffix to a database path (e.g. `sync.db` -> `sync.db-wal`).
fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

#[test]
fn real_ios_databases_survive_the_pipeline_without_panic() {
    let Some(root) = corpus_root() else {
        return;
    };
    let dbs = all_ios_dbs(&root);
    assert!(
        !dbs.is_empty(),
        "SQLITE_FORENSIC_IOS_CORPUS={} contained no .db/.sqlite/.sqlite3 files",
        root.display()
    );

    let mut opened = 0usize;
    for path in &dbs {
        let bytes = std::fs::read(path).expect("ios db readable");

        // Attach a `-wal` sidecar when present (these are live WAL-mode dbs), so
        // the WAL overlay + timeline path is exercised on real frames. A db that
        // fails to open is a typed Err (graceful), never a panic — skip its pipeline.
        let wal_path = sidecar(path, "-wal");
        let db = if wal_path.exists() {
            let wal = std::fs::read(&wal_path).expect("wal sidecar readable");
            match Database::open_with_wal(bytes, &wal) {
                Ok(db) => db,
                Err(_) => continue,
            }
        } else {
            match Database::open(bytes) {
                Ok(db) => db,
                Err(_) => continue,
            }
        };
        opened += 1;

        // Tier-1 + Tier-2 carving; the documented full-tier equivalence must hold.
        let tiers = carve_with_fragments(&db);
        assert_eq!(
            tiers.full,
            carve_all_deleted_records(&db),
            "{}: carve_with_fragments.full diverged from carve_all_deleted_records",
            path.display()
        );
        for rec in &tiers.full {
            assert_record_sane(&rec.values);
        }

        // Anomaly audit + per-rowid version history + live dump — none may panic.
        let anomalies = audit(&db);
        assert!(
            anomalies.len() <= 1_000_000,
            "{}: implausible anomaly count {}",
            path.display(),
            anomalies.len()
        );
        let _ = row_histories_with_residue(&db);
        let _ = db.live_table_rows();

        // WAL timeline, when a real `-wal` is overlaid.
        let _ = db.wal_timeline();

        // Rollback-journal recovery + anomalies, when a real `-journal` sidecar
        // sits beside the db (rare on iOS WAL-mode dbs, but exercise the path on
        // any that use rollback journaling).
        let journal_path = sidecar(path, "-journal");
        if journal_path.exists() {
            if let Ok(journal) = std::fs::read(&journal_path) {
                let recovery = carve_rollback_journal(&db, &journal);
                for r in &recovery.deleted {
                    assert_record_sane(&r.values);
                }
                let _ = audit_journal(&db, &journal);
            }
        }
    }

    assert!(
        opened > 0,
        "no iOS database under {} opened — the pipeline never ran",
        root.display()
    );
    eprintln!(
        "ios_realdata_robustness: walked {} db file(s), {opened} opened + survived the pipeline",
        dbs.len()
    );
}
