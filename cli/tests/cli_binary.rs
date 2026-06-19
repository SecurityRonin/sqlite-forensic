//! Integration coverage for the `sqlite4n6` binary's I/O shell — the Humble
//! Object that `main`, `run_carve`, `run_audit`, `open_db`, and `resolve_wal_path`
//! make up. These drive the real built binary against real fixture databases so
//! the shell's argument-to-exit-code behavior (including the error paths) is
//! exercised end to end, not just the pure library helpers it calls.
//!
//! The binary path is injected by Cargo as `CARGO_BIN_EXE_sqlite4n6`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sqlite4n6"))
}

fn data_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/data")
}

/// `carve --format table` renders deleted records from a real database with
/// deletions to stdout and exits 0. The table stdout mode keeps the Tier-2
/// fragment section, so this also drives the fragment render + dedup path.
#[test]
fn carve_table_happy_path() {
    let out = bin()
        .args(["carve"])
        .arg(data_dir().join("deleted_places.db"))
        .args(["--format", "table"])
        .output()
        .expect("run carve");
    assert!(out.status.success(), "carve must exit 0");
    assert!(!out.stdout.is_empty(), "carve must emit output");
}

/// The `--format csv` and `--format jsonl` branches each drive a distinct
/// renderer and the `FormatArg -> OutputFormat` conversion.
#[test]
fn carve_csv_and_jsonl_formats() {
    for fmt in ["csv", "jsonl"] {
        let out = bin()
            .args(["carve"])
            .arg(data_dir().join("deleted_places.db"))
            .args(["--format", fmt])
            .output()
            .expect("run carve");
        assert!(out.status.success(), "carve --format {fmt} must exit 0");
        assert!(
            !out.stdout.is_empty(),
            "carve --format {fmt} must emit output"
        );
    }
}

/// `--rowid-only` prints recovered rowids, one per line — every non-empty line is
/// a bare integer, and the fragment section is coherently omitted.
#[test]
fn carve_rowid_only_prints_integers() {
    let out = bin()
        .args(["carve"])
        .arg(data_dir().join("deleted_places.db"))
        .args(["--rowid-only"])
        .output()
        .expect("run carve");
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
        assert!(
            line.trim().parse::<i64>().is_ok(),
            "--rowid-only line must be a bare rowid, got {line:?}"
        );
    }
}

/// `--no-fragments` opts into the high-precision full-row-only stdout output and
/// still exits 0 (a stdout-mode flag, paired here with `--format table`).
#[test]
fn carve_no_fragments() {
    let out = bin()
        .args(["carve"])
        .arg(data_dir().join("deleted_places.db"))
        .args(["--format", "table", "--no-fragments"])
        .output()
        .expect("run carve");
    assert!(out.status.success(), "carve --no-fragments must exit 0");
}

/// A `-wal` sidecar co-located with the database is auto-detected (the
/// `resolve_wal_path` auto-detect branch), so the WAL-applied carve runs and
/// exits 0. Driven in default write-mode with `--out` to a scratch path so the
/// rebuilt db lands in isolation (and the WAL branch of `collect_full_records`
/// is exercised).
#[test]
fn carve_auto_detects_wal_sidecar() {
    let dir = Scratch::new("wal_auto");
    let out = bin()
        .args(["carve"])
        .arg(data_dir().join("wal_places.db"))
        .arg("--out")
        .arg(dir.join("recovered.db"))
        .output()
        .expect("run carve");
    assert!(out.status.success(), "carve over a WAL db must exit 0");
}

/// `--no-wal` collapses a WAL database to the on-disk-only view (the
/// `resolve_wal_path` opt-out branch) and still exits 0.
#[test]
fn carve_no_wal_uses_on_disk_only() {
    let dir = Scratch::new("wal_off");
    let out = bin()
        .args(["carve"])
        .arg(data_dir().join("wal_places.db"))
        .args(["--no-wal"])
        .arg("--out")
        .arg(dir.join("recovered.db"))
        .output()
        .expect("run carve");
    assert!(out.status.success(), "carve --no-wal must exit 0");
}

/// An explicit `--wal` path wins over auto-detection (the `resolve_wal_path`
/// explicit branch).
#[test]
fn carve_explicit_wal_path() {
    let dir = Scratch::new("wal_explicit");
    let out = bin()
        .args(["carve"])
        .arg(data_dir().join("wal_places.db"))
        .arg("--wal")
        .arg(data_dir().join("wal_places.db-wal"))
        .arg("--out")
        .arg(dir.join("recovered.db"))
        .output()
        .expect("run carve");
    assert!(out.status.success(), "carve --wal <path> must exit 0");
}

/// Default `carve` (no `--format`) WRITES a rebuilt recovered database to
/// `<stem>.recovered.db` in the current working directory and prints a one-line
/// summary to stdout — it does not dump records. The produced file must itself be
/// a valid SQLite database our reader re-opens.
#[test]
fn default_carve_writes_rebuilt_db() {
    let dir = Scratch::new("rebuild_default");
    // Copy the evidence into the scratch dir so the recovered db lands beside it
    // in an isolated CWD (never polluting the repo).
    let db = dir.join("deleted_places.db");
    std::fs::copy(data_dir().join("deleted_places.db"), &db).unwrap();

    let out = bin()
        .current_dir(&dir.0)
        .args(["carve", "deleted_places.db"])
        .output()
        .expect("run carve");
    assert!(out.status.success(), "default carve must exit 0");

    let produced = dir.join("deleted_places.recovered.db");
    assert!(
        produced.exists(),
        "default carve must write <stem>.recovered.db in the CWD"
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("recovered record") && stdout.contains("deleted_places.recovered.db"),
        "summary line must report the count and the output path, got: {stdout:?}"
    );
    // The produced file re-opens as a valid SQLite database holding our rows.
    let bytes = std::fs::read(&produced).unwrap();
    let rebuilt = sqlite_core::Database::open(bytes).expect("recovered db must be valid SQLite");
    let schema = rebuilt.read_table(1, 5).unwrap();
    assert!(
        schema.iter().any(|r| matches!(
            r.values.get(1),
            Some(sqlite_core::Value::Text(n)) if n == "recovered_records"
        )),
        "the rebuilt db must contain the recovered_records table"
    );
}

/// `--out <PATH>` overrides the derived path; the rebuilt db lands exactly there.
#[test]
fn carve_out_flag_writes_to_explicit_path() {
    let dir = Scratch::new("rebuild_out");
    let target = dir.join("custom_recovered.db");
    let out = bin()
        .args(["carve"])
        .arg(data_dir().join("deleted_places.db"))
        .arg("--out")
        .arg(&target)
        .output()
        .expect("run carve");
    assert!(out.status.success(), "carve --out must exit 0");
    assert!(target.exists(), "carve --out must write to the given path");
}

/// The safety guard refuses to write the rebuilt db over the evidence database
/// (here via `--out` pointing at the input): nonzero exit, evidence untouched.
#[test]
fn carve_out_equal_to_evidence_is_refused() {
    let dir = Scratch::new("rebuild_guard");
    let db = dir.join("evidence.db");
    std::fs::copy(data_dir().join("deleted_places.db"), &db).unwrap();
    let before = std::fs::read(&db).unwrap();

    let out = bin()
        .args(["carve"])
        .arg(&db)
        .arg("--out")
        .arg(&db)
        .output()
        .expect("run carve");
    assert!(
        !out.status.success(),
        "writing the rebuilt db over the evidence must be refused"
    );
    let after = std::fs::read(&db).unwrap();
    assert_eq!(
        before, after,
        "the evidence file must be left byte-identical"
    );
}

/// `audit` grades anomalies on a real database and exits 0, driving `run_audit`,
/// `open_db`, and the `ConfidenceArg`/`FormatArg` conversions used by the audit
/// path's table renderer.
#[test]
fn audit_happy_path() {
    let out = bin()
        .args(["audit"])
        .arg(data_dir().join("deleted_places.db"))
        .output()
        .expect("run audit");
    assert!(out.status.success(), "audit must exit 0");
}

/// A nonexistent file is a read error: the shell must turn it into a nonzero exit
/// with a diagnostic on stderr — never a silent success.
#[test]
fn missing_file_exits_nonzero() {
    let out = bin()
        .args(["audit", "/no/such/database.db"])
        .output()
        .expect("run audit");
    assert!(
        !out.status.success(),
        "a missing database must fail, not succeed silently"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("error"), "must report the error on stderr");
}

/// A file that exists but is not a valid SQLite database is a parse error: the
/// shell exits nonzero rather than emitting empty success.
#[test]
fn malformed_db_exits_nonzero() {
    let mut path = std::env::temp_dir();
    path.push(format!("sqlite4n6_malformed_{}.db", std::process::id()));
    std::fs::write(&path, b"this is definitely not a sqlite database").unwrap();

    let out = bin()
        .args(["carve"])
        .arg(&path)
        .output()
        .expect("run carve");
    let _ = std::fs::remove_file(&path);

    assert!(
        !out.status.success(),
        "a malformed database must fail to parse, not succeed silently"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("error"), "must report the parse error");
}

/// A malformed database on the `audit` path is a parse error too: `audit` reaches
/// `open_db`, whose parse-failure branch must surface a nonzero exit rather than
/// emit empty success.
#[test]
fn malformed_db_audit_exits_nonzero() {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "sqlite4n6_malformed_audit_{}.db",
        std::process::id()
    ));
    std::fs::write(&path, b"this is definitely not a sqlite database").unwrap();

    let out = bin()
        .args(["audit"])
        .arg(&path)
        .output()
        .expect("run audit");
    let _ = std::fs::remove_file(&path);

    assert!(
        !out.status.success(),
        "a malformed database must fail to parse on the audit path too"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("error"), "must report the parse error");
}

/// A unique scratch directory under the system temp dir, removed on drop, so each
/// WAL-error test controls the `<db>` / `<db>-wal` sidecar pair in isolation.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("sqlite4n6_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Scratch(p)
    }
    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `carve` on a missing database is a read error: the shell exits nonzero with a
/// "cannot read database" diagnostic rather than emitting empty success.
#[test]
fn carve_missing_file_exits_nonzero() {
    let out = bin()
        .args(["carve", "/no/such/database.db"])
        .output()
        .expect("run carve");
    assert!(
        !out.status.success(),
        "a missing database must fail the carve, not succeed silently"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("error"), "must report the read error");
}

/// `carve` when the auto-detected `<db>-wal` exists but cannot be read (here it is
/// a directory) is a WAL read error: the shell surfaces a nonzero exit rather than
/// silently carving the on-disk image.
#[test]
fn carve_unreadable_wal_sidecar_exits_nonzero() {
    let dir = Scratch::new("walread");
    let db = dir.join("evidence.db");
    std::fs::write(&db, b"not a real sqlite database").unwrap();
    // The conventional sidecar path exists but is a directory, so reading it errors.
    std::fs::create_dir(dir.join("evidence.db-wal")).unwrap();

    let out = bin().args(["carve"]).arg(&db).output().expect("run carve");
    assert!(
        !out.status.success(),
        "an unreadable WAL sidecar must fail the carve"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("WAL"), "must report the WAL read error");
}

/// `carve` with a readable `-wal` sidecar but a malformed main database is a parse
/// error on the WAL-applied path (`open_with_wal`): nonzero exit, not empty
/// success.
#[test]
fn carve_malformed_db_with_wal_exits_nonzero() {
    let dir = Scratch::new("walparse");
    let db = dir.join("evidence.db");
    std::fs::write(&db, b"this is not a valid sqlite database header").unwrap();
    // A readable sidecar so the WAL branch is taken and the parse (not the read)
    // is what fails.
    std::fs::write(dir.join("evidence.db-wal"), b"bogus wal bytes").unwrap();

    let out = bin().args(["carve"]).arg(&db).output().expect("run carve");
    assert!(
        !out.status.success(),
        "a malformed database under a WAL must fail to parse"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("error"), "must report the parse error");
}
