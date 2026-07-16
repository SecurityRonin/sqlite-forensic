//! Real-world robustness over the Belkasoft "SQLite Exercises" messenger corpus.
//!
//! Companion to `ios_realdata_robustness`: where that sweeps a Josh Hickman iOS
//! image, this sweeps genuine **messenger and app** databases (Android/iOS
//! WhatsApp, Viber, Skype, Facebook Messenger, Safari, CarPlay) with live WAL and
//! rollback-journal sidecars. The full `open → audit → carve → history` pipeline
//! must survive every real vendor database with no panic and a structurally-sane
//! result — the real-data front door of the Doer-Checker discipline. It is a
//! **robustness** sweep, not a known-answer recall oracle (no committed deletion
//! key; scored recall lives in the Nemetz/CFReDS corpora).
//!
//! The corpus is **not committed** — Belkasoft's Terms of Use prohibit
//! redistribution (provenance + hashes: `tests/data/belkasoft/README.md`,
//! `docs/corpus-catalog.md` §Q). The test is **env-gated**: point
//! `SQLITE_FORENSIC_BELKASOFT_CORPUS` at the extracted corpus root and it walks
//! every SQLite database under it (detected by file magic, since several vendor
//! dbs are extensionless, e.g. `viber_messages`); with the var unset it **skips
//! cleanly**, so a normal `cargo test` and CI stay green.
//!
//! Evidence hygiene: every database is read into owned bytes and opened
//! read-only — never read-write (a WAL-mode db opened read-write would checkpoint
//! and mutate the evidence).
//!
//! ```text
//! SQLITE_FORENSIC_BELKASOFT_CORPUS=/tmp/belka-ex \
//!   cargo test -p sqlite-forensic --test belkasoft_robustness -- --nocapture
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::pedantic)]

use std::path::{Path, PathBuf};

use sqlite_core::{Database, Value};
use sqlite_forensic::{
    audit, audit_journal, carve_all_deleted_records, carve_rollback_journal, carve_with_fragments,
    row_histories_with_residue,
};

/// The corpus root from `SQLITE_FORENSIC_BELKASOFT_CORPUS`, or `None` to skip.
fn corpus_root() -> Option<PathBuf> {
    match std::env::var("SQLITE_FORENSIC_BELKASOFT_CORPUS") {
        Ok(p) if !p.is_empty() => {
            let path = PathBuf::from(p);
            if path.is_dir() {
                Some(path)
            } else {
                eprintln!(
                    "SKIP belkasoft_robustness: SQLITE_FORENSIC_BELKASOFT_CORPUS={} is not a directory",
                    path.display()
                );
                None
            }
        }
        _ => {
            eprintln!(
                "SKIP belkasoft_robustness: set SQLITE_FORENSIC_BELKASOFT_CORPUS to the extracted \
                 Belkasoft \"SQLite Exercises\" corpus root to run this real-world robustness sweep"
            );
            None
        }
    }
}

/// Whether `path` begins with the SQLite file magic — the robust way to find
/// databases in a corpus where several vendor files are extensionless.
fn is_sqlite(path: &Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 16];
    matches!(f.read_exact(&mut magic), Ok(())) && &magic == b"SQLite format 3\0"
}

/// Every SQLite database under `root` (recursive), by magic. `-wal`/`-shm`/
/// `-journal` sidecars have their own magic and are skipped by suffix.
fn all_dbs(root: &Path) -> Vec<PathBuf> {
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
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.ends_with("-wal") || name.ends_with("-shm") || name.ends_with("-journal") {
                    continue;
                }
            }
            if is_sqlite(&path) {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// A carved record's decoded values must be structurally coherent.
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

/// Append a sidecar suffix to a database path (e.g. `msgstore.db` -> `…-wal`).
fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

#[test]
fn real_messenger_databases_survive_the_pipeline_without_panic() {
    let Some(root) = corpus_root() else {
        return;
    };
    let dbs = all_dbs(&root);
    assert!(
        !dbs.is_empty(),
        "SQLITE_FORENSIC_BELKASOFT_CORPUS={} contained no SQLite databases",
        root.display()
    );

    let mut opened = 0usize;
    for path in &dbs {
        let bytes = std::fs::read(path).expect("db readable");

        // Attach a live `-wal` sidecar when present so the WAL overlay + timeline
        // path runs on real frames. A db that fails to open is a typed Err
        // (graceful), never a panic — skip its pipeline.
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

        // Anomaly audit + per-rowid version history + live dump + WITHOUT ROWID
        // reads + WAL timeline — none may panic.
        let anomalies = audit(&db);
        assert!(
            anomalies.len() <= 1_000_000,
            "{}: implausible anomaly count {}",
            path.display(),
            anomalies.len()
        );
        let _ = row_histories_with_residue(&db);
        let _ = db.live_table_rows();
        let _ = db.without_rowid_table_rows();
        let _ = db.wal_timeline();

        // Rollback-journal recovery + anomalies when a real `-journal` sits beside
        // the db (common in this corpus — Viber/WhatsApp).
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
        "no database under {} opened — the pipeline never ran",
        root.display()
    );
    eprintln!(
        "belkasoft_robustness: walked {} db file(s), {opened} opened + survived the pipeline",
        dbs.len()
    );
}
