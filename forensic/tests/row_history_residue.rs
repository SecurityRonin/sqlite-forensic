//! Carved-residue merge into the row VERSION HISTORY (Phase 1, increment 4).
//!
//! [`row_histories_with_residue`] augments the core [`Database::row_histories`]
//! base with free-space carved residue: ORDER-UNKNOWN records (freeblocks persist
//! across commits) emitted as `origin: CarvedResidue`, `view_state: CarvedResidue`,
//! `commit_seq: None`, `is_deleted: true` — never a fabricated commit position —
//! attributed to a table and deduped against any WAL `AbsentInFinalView` version
//! of the same rowid + values.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use sqlite_core::row_history::{VersionOrigin, ViewState};
use sqlite_core::{Database, Value};
use sqlite_forensic::row_histories_with_residue;

/// Resolve a usable `sqlite3` binary, or `None` (the test then skips).
fn sqlite3_bin() -> Option<String> {
    let bin = std::env::var("SQLITE3_BIN").unwrap_or_else(|_| "sqlite3".to_string());
    Command::new(&bin)
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|_| bin)
}

fn scratch(tag: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut p = std::env::temp_dir();
    p.push(format!("sqlite4n6_rowhistres_{tag}_{nonce}"));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn writer_sql(bin: &str, db: &Path, sql: &str) {
    let out = Command::new(bin).arg(db).arg(sql).output().unwrap();
    assert!(
        out.status.success(),
        "sqlite3 writer failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The `updated_messages.db` fixture holds the genuine PRIOR version of row 7
/// ("PRIORVERSION…") in slack — recoverable ONLY by carving, never a live row.
/// It must surface as an order-unknown CarvedResidue version of `messages`, with
/// no fabricated commit_seq.
#[test]
fn carved_prior_version_is_order_unknown_residue() {
    let db_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/data/updated_messages.db");
    let db = Database::open(std::fs::read(&db_path).unwrap()).unwrap();
    assert!(!db.wal_applied(), "fixture has no -wal");

    let histories = row_histories_with_residue(&db);
    let m = histories
        .iter()
        .find(|h| h.table == "messages")
        .expect("messages table present");

    // The carved prior version of row 7 is present as CarvedResidue.
    let residue: Vec<_> = m
        .versions
        .iter()
        .filter(|v| v.origin == VersionOrigin::CarvedResidue)
        .collect();
    assert!(
        !residue.is_empty(),
        "the carved prior version must surface as residue"
    );
    let prior = residue
        .iter()
        .find(|v| matches!(v.values.get(2), Some(Value::Text(t)) if t.starts_with("PRIORVERSION")))
        .expect("the genuine prior version of row 7 is carved");

    // Order-unknown discipline: no fabricated commit position.
    assert_eq!(prior.view_state, ViewState::CarvedResidue);
    assert_eq!(
        prior.commit_seq, None,
        "carved residue is order-unknown — never a fabricated commit_seq"
    );
    assert!(prior.is_deleted, "carved residue is deleted content");

    // The live row 7 ("EDITED final body") must still be the present current row,
    // never re-surfaced as residue.
    assert!(
        m.versions.iter().any(|v| {
            v.origin == VersionOrigin::Live
                && matches!(v.values.get(2), Some(Value::Text(t)) if t == "EDITED final body")
        }),
        "the live edited row 7 remains PresentInFinalView"
    );
    assert!(
        !m.versions.iter().any(|v| {
            v.origin == VersionOrigin::CarvedResidue
                && matches!(v.values.get(2), Some(Value::Text(t)) if t == "EDITED final body")
        }),
        "the live row is never re-listed as carved residue"
    );
}

/// Without any carvable residue beyond what the WAL already shows, the residue
/// merge adds nothing the base history did not have (no double-listing). The
/// deleted_places fixture's deleted rows are carved residue with no WAL, so they
/// appear exactly once as CarvedResidue.
#[test]
fn residue_is_not_double_listed() {
    let db_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/data/deleted_places.db");
    let db = Database::open(std::fs::read(&db_path).unwrap()).unwrap();

    let histories = row_histories_with_residue(&db);
    // Collect every (rowid, values-debug) pair; no exact duplicate version.
    for h in &histories {
        let mut seen = std::collections::HashSet::new();
        for v in &h.versions {
            let key = format!("{:?}:{:?}:{:?}", v.rowid, v.values, v.origin);
            assert!(
                seen.insert(key.clone()),
                "duplicate version in {}: {key}",
                h.table
            );
        }
    }
}

/// With a real WAL, a deleted row already surfaced as a WAL `AbsentInFinalView`
/// version must NOT be re-listed as a separate CarvedResidue version of the same
/// rowid + values (the WAL holds it at higher fidelity). Mints the C1/C2/C3
/// fixture (rowid 2 'b' and rowid 4 'x' both deleted) and asserts each deleted
/// (rowid, body) pair appears EXACTLY ONCE across the whole history.
#[test]
fn wal_absent_version_is_not_double_listed_as_residue() {
    let Some(bin) = sqlite3_bin() else {
        eprintln!("SKIP wal_absent_version_is_not_double_listed_as_residue: no sqlite3");
        return;
    };
    let dir = scratch("dedup");
    let db_path = dir.join("ev.db");
    let wal_path = dir.join("ev.db-wal");

    // Held reader retains the -wal across the short-lived writer connections.
    let mut reader = Command::new(&bin)
        .arg(&db_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut rin = reader.stdin.take().unwrap();
    writeln!(
        rin,
        "PRAGMA journal_mode=WAL;\nPRAGMA wal_autocheckpoint=0;\nPRAGMA secure_delete=OFF;\n\
         CREATE TABLE t(id INTEGER PRIMARY KEY, name TEXT);"
    )
    .unwrap();
    rin.flush().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(400));
    writeln!(rin, "BEGIN;\nSELECT count(*) FROM t;").unwrap();
    rin.flush().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(400));
    reader.stdin = Some(rin);

    writer_sql(
        &bin,
        &db_path,
        "PRAGMA wal_autocheckpoint=0; \
         INSERT INTO t VALUES(1,'a'); INSERT INTO t VALUES(2,'b'); INSERT INTO t VALUES(4,'x');",
    );
    writer_sql(
        &bin,
        &db_path,
        "PRAGMA wal_autocheckpoint=0; \
         UPDATE t SET name='A' WHERE id=1; DELETE FROM t WHERE id=2; DELETE FROM t WHERE id=4;",
    );
    writer_sql(
        &bin,
        &db_path,
        "PRAGMA wal_autocheckpoint=0; \
         INSERT INTO t VALUES(3,'c'); INSERT INTO t VALUES(4,'y');",
    );

    let main = std::fs::read(&db_path).unwrap();
    let walb = std::fs::read(&wal_path).expect("-wal present");
    assert!(!walb.is_empty(), "the -wal must be RETAINED (non-empty)");
    let db = Database::open_with_wal(main, &walb).unwrap();

    let histories = row_histories_with_residue(&db);
    let t = histories.iter().find(|h| h.table == "t").expect("table t");

    // Every (rowid, name) pair appears exactly once regardless of origin: a WAL
    // AbsentInFinalView for a deleted row de-dups any identical CarvedResidue.
    let mut seen = std::collections::HashSet::new();
    for v in &t.versions {
        let name = match v.values.get(1) {
            Some(Value::Text(s)) => s.clone(),
            _ => String::new(),
        };
        let key = format!("{:?}:{name}", v.rowid);
        assert!(
            seen.insert(key.clone()),
            "deleted row double-listed (WAL + residue): {key}"
        );
    }
    // The deletions are present (as the WAL AbsentInFinalView versions).
    let deleted: Vec<_> = t
        .versions
        .iter()
        .filter(|v| v.is_deleted)
        .filter_map(|v| match v.values.get(1) {
            Some(Value::Text(s)) => Some(s.clone()),
            _ => None,
        })
        .collect();
    assert!(
        deleted.iter().any(|n| n == "b") && deleted.iter().any(|n| n == "x"),
        "both deleted rows (b, x) are present once: {deleted:?}"
    );

    if let Some(mut rin) = reader.stdin.take() {
        let _ = writeln!(rin, "COMMIT;\n.quit");
    }
    let _ = reader.wait();
    let _ = std::fs::remove_dir_all(&dir);
}
