//! Integration coverage for the `sqlite4n6` binary's I/O shell — the Humble
//! Object that `main`, `run_carve`, `run_audit`, `open_db`, and `resolve_wal_path`
//! make up. These drive the real built binary against real fixture databases so
//! the shell's argument-to-exit-code behavior (including the error paths) is
//! exercised end to end, not just the pure library helpers it calls.
//!
//! The binary path is injected by Cargo as `CARGO_BIN_EXE_sqlite4n6`.

#![allow(clippy::unwrap_used, clippy::expect_used)]
// Calamine surfaces integer flag cells (is_deleted / is_guessed) as exact f64
// 0.0/1.0; comparing them by equality is correct here, not a precision hazard.
#![allow(clippy::float_cmp)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sqlite4n6"))
}

fn data_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/data")
}

/// Resolve a usable `sqlite3` binary, or `None` (the test then skips). Mirrors the
/// skip-if-absent pattern in `core/tests/rebuild_sqlite3_oracle.rs`.
fn sqlite3_bin() -> Option<String> {
    let bin = std::env::var("SQLITE3_BIN").unwrap_or_else(|_| "sqlite3".to_string());
    Command::new(&bin)
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|_| bin)
}

/// Run `sqlite3 <db> "<sql>"` and return trimmed stdout.
fn sqlite3_query(bin: &str, db: &Path, sql: &str) -> String {
    let out = Command::new(bin)
        .arg(db)
        .arg(sql)
        .output()
        .expect("sqlite3 must execute");
    assert!(
        out.status.success(),
        "sqlite3 failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// The on-disk fixture that surfaces a Tier-2 fragment by default (id 20004
/// "Anja"/"Frank" — the same case the forensic crate's fragment tests assert).
fn fragment_fixture() -> PathBuf {
    data_dir().join("nemetz/0D/0D-01.db")
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
/// exits 0. Driven in default write-mode with `--out` to a scratch stem so the
/// output lands in isolation (and the WAL branch of `collect_for_rebuild` is
/// exercised).
#[test]
fn carve_auto_detects_wal_sidecar() {
    let dir = Scratch::new("wal_auto");
    let out = bin()
        .args(["carve"])
        .arg(data_dir().join("wal_places.db"))
        .arg("--out")
        .arg(dir.join("recovered"))
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
        .arg(dir.join("recovered"))
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
        .arg(dir.join("recovered"))
        .output()
        .expect("run carve");
    assert!(out.status.success(), "carve --wal <path> must exit 0");
}

/// Default `carve` (no `--format`, no `--db`) WRITES the combined
/// `<stem>.recovered.xlsx` workbook in the current working directory and prints a
/// one-line summary to stdout — and does NOT write a `.carved.db`. The produced
/// xlsx is the combined live + recovered workbook (the live table's own sheet).
#[test]
fn default_carve_writes_combined_xlsx_not_db() {
    use calamine::Reader;

    let dir = Scratch::new("default_xlsx");
    let db = dir.join("deleted_places.db");
    std::fs::copy(data_dir().join("deleted_places.db"), &db).unwrap();

    let out = bin()
        .current_dir(&dir.0)
        .args(["carve", "deleted_places.db"])
        .output()
        .expect("run carve");
    assert!(out.status.success(), "default carve must exit 0");

    let xlsx = dir.join("deleted_places.recovered.xlsx");
    assert!(
        xlsx.exists(),
        "default carve must write <stem>.recovered.xlsx in the CWD"
    );
    assert!(
        !dir.join("deleted_places.carved.db").exists(),
        "default carve must NOT write a .carved.db (db is opt-in via --db)"
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("record(s)") && stdout.contains("deleted_places.recovered.xlsx"),
        "summary line must report the count and the xlsx path, got: {stdout:?}"
    );
    // The produced xlsx is the COMBINED workbook: the live table's own sheet with
    // the three trailing flag columns.
    let wb: calamine::Xlsx<_> = calamine::open_workbook(&xlsx).expect("xlsx must open in calamine");
    let names = wb.sheet_names();
    assert!(
        names.iter().any(|n| n == "moz_places"),
        "the live table gets its own combined sheet: {names:?}"
    );
}

/// `carve --db` ADDITIONALLY writes the rebuilt `<stem>.carved.db` alongside the
/// default xlsx. The produced db re-opens as valid SQLite with recovered_* tables;
/// the summary names both files.
#[test]
fn carve_db_flag_writes_xlsx_and_carved_db() {
    let dir = Scratch::new("db_flag");
    let db = dir.join("deleted_places.db");
    std::fs::copy(data_dir().join("deleted_places.db"), &db).unwrap();

    let out = bin()
        .current_dir(&dir.0)
        .args(["carve", "deleted_places.db", "--db"])
        .output()
        .expect("run carve --db");
    assert!(out.status.success(), "carve --db must exit 0");

    let xlsx = dir.join("deleted_places.recovered.xlsx");
    let carved = dir.join("deleted_places.carved.db");
    assert!(xlsx.exists(), "the combined .xlsx must be written");
    assert!(carved.exists(), "--db must additionally write .carved.db");

    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("deleted_places.recovered.xlsx")
            && stdout.contains("deleted_places.carved.db"),
        "summary must mention both files, got: {stdout:?}"
    );

    let bytes = std::fs::read(&carved).unwrap();
    let rebuilt = sqlite_core::Database::open(bytes).expect("carved db must be valid SQLite");
    let schema = rebuilt.read_table(1, 5).unwrap();
    assert!(
        schema.iter().any(|r| matches!(
            r.values.get(1),
            Some(sqlite_core::Value::Text(n)) if n.starts_with("recovered_")
        )),
        "the carved db must contain at least one recovered_* attribution table"
    );
}

/// `--out <STEM>` overrides the derived stem for BOTH outputs; with `--db` the
/// carved db lands at `<stem>.carved.db` and the xlsx at `<stem>.recovered.xlsx`.
#[test]
fn carve_out_flag_sets_stem_for_both_outputs() {
    let dir = Scratch::new("out_stem");
    let stem = dir.join("custom");
    let out = bin()
        .args(["carve"])
        .arg(data_dir().join("deleted_places.db"))
        .args(["--db"])
        .arg("--out")
        .arg(&stem)
        .output()
        .expect("run carve");
    assert!(out.status.success(), "carve --out must exit 0");
    assert!(
        dir.join("custom.recovered.xlsx").exists(),
        "xlsx lands at <stem>.recovered.xlsx"
    );
    assert!(
        dir.join("custom.carved.db").exists(),
        "carved db lands at <stem>.carved.db"
    );
}

/// The safety guard refuses to write an output over the evidence database. Here
/// the evidence is named `case.recovered.xlsx` and `--out` is the stem `case`, so
/// the derived combined workbook would land exactly on the evidence: refused,
/// evidence untouched.
#[test]
fn carve_out_collision_with_evidence_is_refused() {
    let dir = Scratch::new("rebuild_guard");
    let db = dir.join("case.recovered.xlsx");
    std::fs::copy(data_dir().join("deleted_places.db"), &db).unwrap();
    let before = std::fs::read(&db).unwrap();

    let out = bin()
        .args(["carve"])
        .arg(&db)
        .arg("--out")
        .arg(dir.join("case"))
        .output()
        .expect("run carve");
    assert!(
        !out.status.success(),
        "writing the combined xlsx over the evidence must be refused"
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

// ---- default combined workbook + opt-in db (`carve` / `carve --db`) ----------

/// The default `carve` writes the COMBINED TEMPORAL workbook: the source DB dumped
/// one VERSION-HISTORY sheet per live table (here `moz_places`), carrying the eight
/// temporal/flag columns and interleaving live (`present`, `is_deleted`=0) versions
/// with carved-residue (`is_deleted`=1) versions of deleted rows.
#[test]
fn default_carve_combined_workbook_folds_recovered_rows() {
    use calamine::Reader;

    let dir = Scratch::new("xlsx_export");
    let db = dir.join("deleted_places.db");
    std::fs::copy(data_dir().join("deleted_places.db"), &db).unwrap();

    let out = bin()
        .current_dir(&dir.0)
        .args(["carve", "deleted_places.db"])
        .output()
        .expect("run carve");
    assert!(out.status.success(), "default carve must exit 0");

    let recovered_xlsx = dir.join("deleted_places.recovered.xlsx");
    assert!(recovered_xlsx.exists(), "the .xlsx must be written");

    // The combined workbook opens in calamine with the live table's own
    // version-history sheet (`moz_places`), carrying the temporal/flag columns.
    let mut wb: calamine::Xlsx<_> =
        calamine::open_workbook(&recovered_xlsx).expect("xlsx must open in calamine");
    let names = wb.sheet_names();
    assert!(
        names.iter().any(|n| n == "moz_places"),
        "the live table gets its own version-history sheet: {names:?}"
    );
    assert!(
        !names.iter().any(|n| n == "recovered_inferred"),
        "attributed residue folds into the table sheet, not a separate tab: {names:?}"
    );
    let sheet = wb.worksheet_range("moz_places").unwrap();
    let header: Vec<String> = sheet
        .rows()
        .next()
        .unwrap()
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    for flag in [
        "_rowid",
        "wal_commit",
        "commit_seq",
        "view_state",
        "is_deleted",
        "is_guessed",
        "rowid_reused",
        "attribution_uncertain",
    ] {
        assert!(
            header.iter().any(|h| h == flag),
            "temporal/flag column {flag} present: {header:?}"
        );
    }
    // Both live (is_deleted=0) and carved-residue (is_deleted=1) versions appear in
    // the one sheet — the deleted rows are folded into their table's history once.
    let del_col = header.iter().position(|h| h == "is_deleted").unwrap();
    let commit_col = header.iter().position(|h| h == "wal_commit").unwrap();
    let mut saw_live = false;
    let mut saw_deleted = false;
    for row in sheet.rows().skip(1) {
        match &row[del_col] {
            calamine::Data::Float(f) if *f == 0.0 => saw_live = true,
            calamine::Data::Float(f) if *f == 1.0 => saw_deleted = true,
            _ => {}
        }
    }
    assert!(
        saw_live && saw_deleted,
        "version-history sheet carries both live and deleted versions"
    );
    // No WAL here → it degrades to live + carved residue, with NO WAL-historical
    // commit versions (every wal_commit cell is `live` or `residue`, never commit).
    let no_commit = sheet
        .rows()
        .skip(1)
        .all(|r| !matches!(&r[commit_col], calamine::Data::String(s) if s.starts_with("commit:")));
    assert!(
        no_commit,
        "no-WAL carve has no historical commit versions (live + residue only)"
    );
}

/// The default `carve` over a fixture that surfaces a fragment writes the combined
/// workbook with BOTH the live table's own sheet (`users`) and the separate
/// `recovered_fragments` tab.
#[test]
fn default_carve_xlsx_includes_fragment_sheet() {
    use calamine::Reader;

    let dir = Scratch::new("xlsx_frags");
    let db = dir.join("0D-01.db");
    std::fs::copy(fragment_fixture(), &db).unwrap();

    let out = bin()
        .current_dir(&dir.0)
        .args(["carve", "0D-01.db"])
        .output()
        .expect("run carve");
    assert!(out.status.success(), "default carve must exit 0");

    let recovered_xlsx = dir.join("0D-01.recovered.xlsx");
    assert!(recovered_xlsx.exists(), "the .xlsx must be written");
    let wb: calamine::Xlsx<_> = calamine::open_workbook(&recovered_xlsx).expect("xlsx must open");
    let names = wb.sheet_names();
    assert!(
        names.iter().any(|n| n == "users"),
        "the live table's own combined sheet present: {names:?}"
    );
    assert!(
        names.iter().any(|n| n == "recovered_fragments"),
        "fragment sheet present (fragments on by default): {names:?}"
    );
}

/// When the default xlsx cannot be written (its derived path is occupied by a
/// directory) the carve is a write error: nonzero exit with the xlsx diagnostic.
#[test]
fn default_carve_xlsx_write_failure_exits_nonzero() {
    let dir = Scratch::new("xlsx_writefail");
    let db = dir.join("evidence.db");
    std::fs::copy(data_dir().join("deleted_places.db"), &db).unwrap();
    // Occupy the derived xlsx path with a directory so writing the file there fails.
    std::fs::create_dir(dir.join("recovered.recovered.xlsx")).unwrap();

    let out = bin()
        .args(["carve"])
        .arg(&db)
        .arg("--out")
        .arg(dir.join("recovered"))
        .output()
        .expect("run carve");
    assert!(
        !out.status.success(),
        "an unwritable xlsx path must fail the carve"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("recovered xlsx"),
        "must report the xlsx write error, got: {stderr}"
    );
}

/// `--db` is refused in the stdout text modes (`--format`): clap rejects the
/// combination with a nonzero exit rather than silently ignoring the flag.
#[test]
fn carve_db_flag_conflicts_with_format() {
    let out = bin()
        .args(["carve"])
        .arg(data_dir().join("deleted_places.db"))
        .args(["--db", "--format", "csv"])
        .output()
        .expect("run carve");
    assert!(
        !out.status.success(),
        "--db with --format must be refused by clap"
    );
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

// ---- stdout-mode (`--format`) error paths -----------------------------------
// These mirror the default-mode error tests but force the `--format` (stdout)
// branch, so the stdout carve's own read/parse error arms are exercised — the
// default-mode carve and the stdout carve are now separate functions.

/// Stdout-mode carve on a missing file is a read error: nonzero exit, diagnostic.
#[test]
fn carve_format_missing_file_exits_nonzero() {
    let out = bin()
        .args(["carve", "/no/such/database.db", "--format", "jsonl"])
        .output()
        .expect("run carve");
    assert!(
        !out.status.success(),
        "a missing db must fail the stdout carve"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("error"), "must report the read error");
}

/// Stdout-mode carve with a malformed db and no WAL is a parse error on the
/// on-disk path: nonzero exit.
#[test]
fn carve_format_malformed_db_exits_nonzero() {
    let dir = Scratch::new("fmt_malformed");
    let db = dir.join("evidence.db");
    std::fs::write(&db, b"definitely not a sqlite database").unwrap();
    let out = bin()
        .args(["carve"])
        .arg(&db)
        .args(["--format", "table"])
        .output()
        .expect("run carve");
    assert!(
        !out.status.success(),
        "malformed db must fail the stdout carve"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("error"), "must report the parse error");
}

/// Stdout-mode carve when the auto-detected `-wal` cannot be read (it is a
/// directory) is a WAL read error on the stdout path: nonzero exit.
#[test]
fn carve_format_unreadable_wal_exits_nonzero() {
    let dir = Scratch::new("fmt_walread");
    let db = dir.join("evidence.db");
    std::fs::write(&db, b"not a real sqlite database").unwrap();
    std::fs::create_dir(dir.join("evidence.db-wal")).unwrap();

    let out = bin()
        .args(["carve"])
        .arg(&db)
        .args(["--format", "csv"])
        .output()
        .expect("run carve");
    assert!(
        !out.status.success(),
        "unreadable WAL must fail the stdout carve"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("WAL"), "must report the WAL read error");
}

/// Stdout-mode carve with a readable `-wal` but a malformed main db is a parse
/// error on the WAL-applied stdout path (`open_with_wal`): nonzero exit.
#[test]
fn carve_format_malformed_db_with_wal_exits_nonzero() {
    let dir = Scratch::new("fmt_walparse");
    let db = dir.join("evidence.db");
    std::fs::write(&db, b"this is not a valid sqlite database header").unwrap();
    std::fs::write(dir.join("evidence.db-wal"), b"bogus wal bytes").unwrap();

    let out = bin()
        .args(["carve"])
        .arg(&db)
        .args(["--format", "jsonl"])
        .output()
        .expect("run carve");
    assert!(
        !out.status.success(),
        "malformed db under a WAL must fail the stdout carve"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("error"), "must report the parse error");
}

/// `--db` mode when the carved db cannot be written (the `--out` stem's directory
/// does not exist) is a write error: nonzero exit with a diagnostic naming the db.
#[test]
fn carve_db_write_failure_exits_nonzero() {
    let dir = Scratch::new("rebuild_writefail");
    let db = dir.join("evidence.db");
    std::fs::copy(data_dir().join("deleted_places.db"), &db).unwrap();
    // A stem inside a directory that does not exist → std::fs::write fails.
    let target = dir.join("nonexistent_subdir").join("recovered");

    let out = bin()
        .args(["carve"])
        .arg(&db)
        .args(["--db"])
        .arg("--out")
        .arg(&target)
        .output()
        .expect("run carve");
    assert!(
        !out.status.success(),
        "an unwritable output path must fail the carve"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("cannot write carved db"),
        "must report the write error, got: {stderr}"
    );
}

// ---- two-table rebuilt db: recovered_fragments alongside recovered_records ---

/// Default `carve` on a fixture that surfaces a fragment must write a rebuilt db
/// in which the real `sqlite3` engine sees the attributed Tier-1 table
/// (`recovered_users`, the in-page deleted row's owning table) AND
/// `recovered_fragments`, the fragment table holding the surviving evidence (the
/// id-20004 "Anja" fragment). The summary line reports both counts. Skips cleanly
/// when `sqlite3` is unavailable.
#[test]
fn default_carve_writes_attributed_table_and_fragments() {
    let Some(sqlite3) = sqlite3_bin() else {
        eprintln!("SKIP default_carve_writes_attributed_table_and_fragments: no sqlite3");
        return;
    };
    let dir = Scratch::new("rebuild_frags");
    let db = dir.join("0D-01.db");
    std::fs::copy(fragment_fixture(), &db).unwrap();

    let out = bin()
        .current_dir(&dir.0)
        .args(["carve", "0D-01.db", "--db"])
        .output()
        .expect("run carve");
    assert!(out.status.success(), "carve --db must exit 0");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("record(s)") && stdout.contains("fragment(s)"),
        "summary must report both records and fragments, got: {stdout:?}"
    );

    let produced = dir.join("0D-01.carved.db");
    assert!(produced.exists(), "carved db must be written");

    // The external engine lists the attributed Tier-1 table + the fragment table.
    let tables = sqlite3_query(
        &sqlite3,
        &produced,
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;",
    );
    assert!(
        tables.contains("recovered_users"),
        "recovered_users (Tier-1) present: {tables}"
    );
    assert!(
        tables.contains("recovered_fragments"),
        "recovered_fragments present: {tables}"
    );

    // The Tier-1 table carries the source table's REAL column names.
    let cols = sqlite3_query(
        &sqlite3,
        &produced,
        "SELECT group_concat(name) FROM pragma_table_info('recovered_users');",
    );
    assert!(
        cols.contains("name") && cols.contains("surname"),
        "real column names present: {cols}"
    );

    // The fragment table carries the surviving distinctive cell.
    let count = sqlite3_query(
        &sqlite3,
        &produced,
        "SELECT count(*) FROM recovered_fragments WHERE c0 = 20004;",
    );
    assert_eq!(
        count, "1",
        "the id-20004 fragment landed in the fragment table"
    );
}

/// Default `carve` on the NIST `CFReDS` `SFT-03` PERSIST database (with its
/// `-journal` sidecar present) must REPORT the rollback-journal recovery in the
/// summary — not silently fold 200 prior rows into the workbook while the stdout
/// summary counts only the free-space carve ("1 record(s)"). NIST ground truth:
/// 100 deleted + 100 modified `invoice_items` rows live in the `-journal`.
#[test]
fn carve_summary_reports_rollback_journal_recovery() {
    let dir = Scratch::new("journal_summary");
    let db = dir.join("case.sqlite");
    std::fs::copy(data_dir().join("cfreds/SFT-03_PERSIST_ios.sqlite"), &db).unwrap();
    std::fs::copy(
        data_dir().join("cfreds/SFT-03_PERSIST_ios.sqlite-journal"),
        dir.join("case.sqlite-journal"),
    )
    .unwrap();

    let out = bin()
        .current_dir(&dir.0)
        .args(["carve", "case.sqlite"])
        .output()
        .expect("run carve");
    assert!(out.status.success(), "carve must exit 0");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("rollback journal")
            && stdout.contains("100 deleted")
            && stdout.contains("100 modified"),
        "summary must report the rollback-journal recovery counts, got: {stdout:?}"
    );
}

/// `--no-fragments` writes the rebuilt db without the fragment table: `sqlite3`
/// sees the attributed Tier-1 `recovered_users`, never `recovered_fragments`, and
/// the summary reports just the record count. Skips when `sqlite3` is absent.
#[test]
fn no_fragments_omits_the_fragment_table() {
    let Some(sqlite3) = sqlite3_bin() else {
        eprintln!("SKIP no_fragments_omits_the_fragment_table: no sqlite3");
        return;
    };
    let dir = Scratch::new("rebuild_nofrags");
    let db = dir.join("0D-01.db");
    std::fs::copy(fragment_fixture(), &db).unwrap();

    let out = bin()
        .current_dir(&dir.0)
        .args(["carve", "0D-01.db", "--db", "--no-fragments"])
        .output()
        .expect("run carve");
    assert!(
        out.status.success(),
        "carve --db --no-fragments must exit 0"
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("record(s)") && !stdout.contains("fragment(s)"),
        "summary must report records only, got: {stdout:?}"
    );

    let produced = dir.join("0D-01.carved.db");
    let tables = sqlite3_query(
        &sqlite3,
        &produced,
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;",
    );
    assert!(
        tables.contains("recovered_users"),
        "recovered_users present: {tables}"
    );
    assert!(
        !tables.contains("recovered_fragments"),
        "--no-fragments must omit the fragment table: {tables}"
    );
}

// ---- three-tier table attribution end-to-end ------------------------------

/// Mint a fresh db by piping `script` to `sqlite3`. The script sets
/// `secure_delete=OFF` so deleted content is recoverable (this host defaults it
/// ON, which zeroes freed bytes).
fn mint_db(sqlite3: &str, path: &Path, script: &str) {
    let _ = std::fs::remove_file(path);
    let out = Command::new(sqlite3)
        .arg(path)
        .arg(script)
        .output()
        .expect("sqlite3 must execute");
    assert!(
        out.status.success(),
        "sqlite3 mint failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A `secure_delete=OFF` script that produces all three attribution tiers:
/// - `people`: a deleted in-page row → Tier-1 `recovered_people`;
/// - `amounts`: most rows deleted, freeing whole pages → Tier-2 (its own shape);
/// - `secret`: bulk-inserted then `DROP`ped → freed pages whose 4-TEXT shape
///   matches no surviving table → Tier-3 `recovered_unattributed`.
const THREE_TIER_SCRIPT: &str = "\
PRAGMA secure_delete=OFF;\n\
PRAGMA auto_vacuum=0;\n\
PRAGMA page_size=4096;\n\
CREATE TABLE people (id INTEGER, name TEXT);\n\
CREATE TABLE amounts (a REAL, b REAL, c REAL);\n\
CREATE TABLE secret (x TEXT, y TEXT, z TEXT, w TEXT);\n\
INSERT INTO people VALUES (1,'alice'),(2,'bob'),(3,'carol'),(4,'dave'),(5,'eve');\n\
WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM c WHERE i<400)\n\
  INSERT INTO amounts SELECT i*1.5, i*2.5, i*3.5 FROM c;\n\
WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM c WHERE i<200)\n\
  INSERT INTO secret SELECT 'aaaa'||i,'bbbb'||i,'cccc'||i,'dddd'||i FROM c;\n\
DELETE FROM people WHERE id=3;\n\
DELETE FROM amounts WHERE rowid>5;\n\
DROP TABLE secret;\n";

/// The headline end-to-end: a `secure_delete=OFF` db with an in-page deletion
/// (Tier-1), whole freed pages of a surviving table (Tier-2), and a dropped
/// table whose shape matches nothing (Tier-3). The default `carve` rebuilds a db
/// the REAL `sqlite3` engine reads back with `recovered_people` (real column
/// names), `recovered_inferred` (`_table_guess` + `_table_match_ambiguous`), and
/// `recovered_unattributed`. Skips when `sqlite3` is unavailable.
#[test]
fn three_tier_attribution_round_trips_through_sqlite3() {
    let Some(sqlite3) = sqlite3_bin() else {
        eprintln!("SKIP three_tier_attribution_round_trips_through_sqlite3: no sqlite3");
        return;
    };
    let dir = Scratch::new("three_tier");
    let db = dir.join("tier.db");
    mint_db(&sqlite3, &db, THREE_TIER_SCRIPT);

    let out = bin()
        .current_dir(&dir.0)
        .args(["carve", "tier.db", "--db"])
        .output()
        .expect("run carve");
    assert!(out.status.success(), "carve --db must exit 0");

    let produced = dir.join("tier.carved.db");
    let tables = sqlite3_query(
        &sqlite3,
        &produced,
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;",
    );
    for expected in [
        "recovered_people",
        "recovered_inferred",
        "recovered_unattributed",
    ] {
        assert!(tables.contains(expected), "{expected} present in: {tables}");
    }

    // Tier-1: real column names from the people CREATE TABLE.
    let people_cols = sqlite3_query(
        &sqlite3,
        &produced,
        "SELECT group_concat(name) FROM pragma_table_info('recovered_people');",
    );
    assert!(
        people_cols.contains("id") && people_cols.contains("name"),
        "Tier-1 real column names: {people_cols}"
    );

    // Tier-2: the guess columns exist and name a surviving table, unambiguous.
    let guess = sqlite3_query(
        &sqlite3,
        &produced,
        "SELECT DISTINCT _table_guess || ':' || _table_match_ambiguous FROM recovered_inferred;",
    );
    assert_eq!(guess, "amounts:0", "Tier-2 guess + ambiguity flag: {guess}");

    // Tier-3: the dropped secret table's 4-TEXT rows landed here.
    let unattr = sqlite3_query(
        &sqlite3,
        &produced,
        "SELECT count(*) FROM recovered_unattributed WHERE c3 IS NOT NULL;",
    );
    assert!(
        unattr.parse::<i64>().unwrap_or(0) > 0,
        "Tier-3 holds the dropped 4-column rows: {unattr}"
    );

    assert_eq!(
        sqlite3_query(&sqlite3, &produced, "PRAGMA integrity_check;"),
        "ok"
    );
}

/// The headline combined-workbook layout, end to end via calamine. On the
/// three-tier fixture the default `carve` writes the source DB dumped one
/// VERSION-HISTORY sheet per live table:
/// - `people` sheet carries its live (`present`, `is_deleted`=0) versions AND the
///   carved-residue version of the deleted row (id 3 'carol') — appearing EXACTLY
///   once, never double-listed;
/// - `recovered_unattributed` (the dropped `secret` table) and
///   `recovered_fragments` are SEPARATE tabs; there is no `recovered_inferred`.
#[test]
fn xlsx_combined_workbook_folds_recovered_into_live_sheets() {
    use calamine::{Data, Reader};

    let Some(sqlite3) = sqlite3_bin() else {
        eprintln!("SKIP xlsx_combined_workbook_folds_recovered_into_live_sheets: no sqlite3");
        return;
    };
    let dir = Scratch::new("three_tier_xlsx");
    let db = dir.join("tier.db");
    mint_db(&sqlite3, &db, THREE_TIER_SCRIPT);

    let out = bin()
        .current_dir(&dir.0)
        .args(["carve", "tier.db"])
        .output()
        .expect("run carve");
    assert!(out.status.success(), "carve must exit 0");

    let xlsx = dir.join("tier.recovered.xlsx");
    assert!(xlsx.exists(), "xlsx companion must be written");
    let mut wb: calamine::Xlsx<_> =
        calamine::open_workbook(&xlsx).expect("calamine must open the xlsx");
    let names = wb.sheet_names();

    // The live tables get their own version-history sheets; Tier-3 + fragments are
    // separate; no recovered_inferred tab (attributed residue folds into a sheet).
    for live in ["people", "amounts"] {
        assert!(
            names.iter().any(|n| n == live),
            "live table {live} has its own sheet: {names:?}"
        );
    }
    assert!(
        names.iter().any(|n| n == "recovered_unattributed"),
        "Tier-3 in its own tab: {names:?}"
    );
    assert!(
        names.iter().any(|n| n == "recovered_fragments"),
        "fragments in their own tab: {names:?}"
    );
    assert!(
        !names.iter().any(|n| n == "recovered_inferred"),
        "no recovered_inferred tab: {names:?}"
    );

    // people: header carries the real `id`/`name` columns + the temporal/flag cols.
    let people = wb.worksheet_range("people").unwrap();
    let people_hdr: Vec<String> = people
        .rows()
        .next()
        .unwrap()
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    for col in ["id", "name", "_rowid", "view_state", "is_deleted"] {
        assert!(
            people_hdr.iter().any(|h| h == col),
            "people header has {col}: {people_hdr:?}"
        );
    }
    let del_col = people_hdr.iter().position(|h| h == "is_deleted").unwrap();
    let view_col = people_hdr.iter().position(|h| h == "view_state").unwrap();

    // The four surviving live rows are `present` (is_deleted=0); the deleted row's
    // residue folds in as a single `carved_residue` (is_deleted=1) version.
    let live_count = people
        .rows()
        .skip(1)
        .filter(|r| matches!(&r[del_col], Data::Float(d) if *d == 0.0))
        .count();
    let deleted: Vec<_> = people
        .rows()
        .skip(1)
        .filter(|r| matches!(&r[del_col], Data::Float(d) if *d == 1.0))
        .collect();
    assert_eq!(
        live_count, 4,
        "the four surviving live versions (id 3 deleted)"
    );
    assert_eq!(
        deleted.len(),
        1,
        "the deleted row folds in EXACTLY once as a residue version (not double-listed)"
    );
    assert_eq!(
        deleted[0][view_col],
        Data::String("carved_residue".into()),
        "the deleted version is a carved_residue: {:?}",
        deleted[0]
    );

    // amounts: the freed-page rows fold into its history as deleted residue too.
    let amounts = wb.worksheet_range("amounts").unwrap();
    let a_hdr: Vec<String> = amounts
        .rows()
        .next()
        .unwrap()
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    let a_del = a_hdr.iter().position(|h| h == "is_deleted").unwrap();
    let any_deleted = amounts
        .rows()
        .skip(1)
        .any(|r| matches!(&r[a_del], Data::Float(d) if *d == 1.0));
    assert!(
        any_deleted,
        "amounts holds at least one deleted (residue) version"
    );
}

/// The committed `deleted_places.db` (163 carved rows) must attribute every row
/// to a tier — none lost. With `moz_places` the sole table, the rows land in
/// `recovered_moz_places` (Tier-1) and/or `recovered_inferred` (Tier-2), and the
/// summed count equals the carved 163.
#[test]
fn deleted_places_rows_all_attribute_somewhere() {
    let Some(sqlite3) = sqlite3_bin() else {
        eprintln!("SKIP deleted_places_rows_all_attribute_somewhere: no sqlite3");
        return;
    };
    let dir = Scratch::new("deleted_places_attr");
    let db = dir.join("deleted_places.db");
    std::fs::copy(data_dir().join("deleted_places.db"), &db).unwrap();

    let out = bin()
        .current_dir(&dir.0)
        .args(["carve", "deleted_places.db", "--db"])
        .output()
        .expect("run carve");
    assert!(out.status.success(), "carve --db must exit 0");

    let produced = dir.join("deleted_places.carved.db");
    // Sum the row counts across every recovered_* attribution table.
    let table_names = sqlite3_query(
        &sqlite3,
        &produced,
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'recovered_%' \
         AND name <> 'recovered_fragments';",
    );
    let mut total = 0i64;
    for name in table_names.lines() {
        let n = sqlite3_query(
            &sqlite3,
            &produced,
            &format!("SELECT count(*) FROM \"{name}\";"),
        );
        total += n.parse::<i64>().unwrap_or(0);
    }
    assert_eq!(
        total, 163,
        "all 163 carved rows must attribute to a tier table"
    );
}

/// The combined workbook embeds a LIVE image BLOB in-cell: the base dump shows
/// images too, not only recovered rows. A live `photos` row holding a real PNG
/// must surface as embedded media (`xl/media/*.png`) in the produced xlsx.
#[test]
fn xlsx_combined_embeds_live_image_blob() {
    let Some(sqlite3) = sqlite3_bin() else {
        eprintln!("SKIP xlsx_combined_embeds_live_image_blob: no sqlite3");
        return;
    };
    let dir = Scratch::new("xlsx_live_image");

    // Encode a small real PNG and drop it beside the db so sqlite3 readfile() can
    // store it verbatim into a live row (no fragile hex literals in SQL).
    let png_path = dir.join("pic.png");
    let img = image::RgbImage::from_fn(24, 24, |x, y| {
        image::Rgb([(x * 10) as u8, (y * 10) as u8, 128])
    });
    img.save(&png_path).expect("write png fixture");

    let db = dir.join("media.db");
    let script = format!(
        "PRAGMA secure_delete=OFF;\n\
         PRAGMA auto_vacuum=0;\n\
         CREATE TABLE photos (id INTEGER, img BLOB);\n\
         INSERT INTO photos VALUES (1, readfile('{}'));\n",
        png_path.display()
    );
    mint_db(&sqlite3, &db, &script);

    let out = bin()
        .current_dir(&dir.0)
        .args(["carve", "media.db"])
        .output()
        .expect("run carve");
    assert!(out.status.success(), "carve must exit 0");

    let xlsx = dir.join("media.recovered.xlsx");
    assert!(xlsx.exists(), "xlsx companion must be written");
    let bytes = std::fs::read(&xlsx).unwrap();
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    let mut media = false;
    for i in 0..zip.len() {
        let name = zip.by_index(i).unwrap().name().to_string();
        let is_png = std::path::Path::new(&name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("png"));
        if name.starts_with("xl/media/") && is_png {
            media = true;
        }
    }
    assert!(
        media,
        "the live image BLOB must embed under xl/media/*.png in the combined workbook"
    );
}

// ---- temporal (WAL version-history) combined workbook ----------------------

/// Build a held-reader WAL fixture with a KNOWN mutation sequence so the `-wal` is
/// RETAINED (this host's sqlite3 checkpoints-and-deletes the sidecar on a clean
/// close). Returns the live reader (kept alive until `teardown_reader`). The db
/// also holds a live image BLOB so the embed path is exercised.
///
/// Table `t(id INTEGER PRIMARY KEY, name TEXT, pic BLOB)`:
///   C1: insert (1,'a'),(2,'b'),(4,'x')           [pic NULL]
///   C2: update 1->'A'; delete 2; delete 4
///   C3: insert 3->'c' with a real PNG; insert 4->'y'  (rowid 4 REUSED)
fn build_temporal_fixture(
    sqlite3: &str,
    dir: &Path,
    png_path: &Path,
) -> (std::process::Child, PathBuf) {
    use std::io::Write;
    use std::process::Stdio;

    let db = dir.join("ev.db");

    let mut reader = Command::new(sqlite3)
        .arg(&db)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn held reader");
    let mut rin = reader.stdin.take().unwrap();
    writeln!(
        rin,
        "PRAGMA journal_mode=WAL;\nPRAGMA wal_autocheckpoint=0;\nPRAGMA secure_delete=OFF;\n\
         CREATE TABLE t(id INTEGER PRIMARY KEY, name TEXT, pic BLOB);"
    )
    .unwrap();
    rin.flush().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(400));
    writeln!(rin, "BEGIN;\nSELECT count(*) FROM t;").unwrap();
    rin.flush().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(400));
    reader.stdin = Some(rin);

    let writer = |sql: &str| {
        let out = Command::new(sqlite3).arg(&db).arg(sql).output().unwrap();
        assert!(
            out.status.success(),
            "sqlite3 writer failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    writer(
        "PRAGMA wal_autocheckpoint=0; \
         INSERT INTO t VALUES(1,'a',NULL); INSERT INTO t VALUES(2,'b',NULL); \
         INSERT INTO t VALUES(4,'x',NULL);",
    );
    writer(
        "PRAGMA wal_autocheckpoint=0; \
         UPDATE t SET name='A' WHERE id=1; DELETE FROM t WHERE id=2; DELETE FROM t WHERE id=4;",
    );
    writer(&format!(
        "PRAGMA wal_autocheckpoint=0; \
         INSERT INTO t VALUES(3,'c',readfile('{}')); INSERT INTO t VALUES(4,'y',NULL);",
        png_path.display()
    ));

    (reader, db)
}

/// Release the held reader (lets sqlite3 quit cleanly without us caring whether it
/// checkpoints — the carve already ran against the retained `-wal`).
fn teardown_reader(mut reader: std::process::Child) {
    use std::io::Write;
    if let Some(mut rin) = reader.stdin.take() {
        let _ = writeln!(rin, "COMMIT;\n.quit");
    }
    let _ = reader.wait();
}

/// The DEFAULT combined workbook is a TEMPORAL workbook: each live user table's
/// sheet carries that table's per-rowid VERSION HISTORY from the uncheckpointed
/// WAL. On the held-reader fixture the `t` sheet must show, for the same rowid, a
/// historical (`changed_later`) version AND the current (`present`) version; the
/// delete+reinsert of rowid 4 must flag `rowid_reused=1`; the deleted rowid 2 must
/// be `absent_final` / `is_deleted=1`. A live image BLOB still embeds in-cell.
/// Gated on `sqlite3` (skips when absent).
#[test]
fn xlsx_temporal_workbook_has_version_history_from_wal() {
    use calamine::{Data, Reader};

    let Some(sqlite3) = sqlite3_bin() else {
        eprintln!("SKIP xlsx_temporal_workbook_has_version_history_from_wal: no sqlite3");
        return;
    };
    let dir = Scratch::new("temporal_xlsx");

    // A small real PNG for the live image BLOB embed assertion.
    let png_path = dir.join("pic.png");
    let img = image::RgbImage::from_fn(24, 24, |x, y| {
        image::Rgb([(x * 10) as u8, (y * 10) as u8, 64])
    });
    img.save(&png_path).expect("write png fixture");

    let (reader, _db_path) = build_temporal_fixture(&sqlite3, &dir.0, &png_path);

    // Confirm the -wal was retained (non-empty) before carving.
    let wal = dir.join("ev.db-wal");
    let walb = std::fs::read(&wal).expect("snapshot -wal present");
    assert!(!walb.is_empty(), "the -wal must be RETAINED (non-empty)");

    let out = bin()
        .current_dir(&dir.0)
        .args(["carve", "ev.db"])
        .output()
        .expect("run carve");
    assert!(
        out.status.success(),
        "carve must exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let xlsx = dir.join("ev.recovered.xlsx");
    assert!(xlsx.exists(), "xlsx companion must be written");

    let mut wb: calamine::Xlsx<_> =
        calamine::open_workbook(&xlsx).expect("calamine must open the xlsx");
    let names = wb.sheet_names();
    assert!(
        names.iter().any(|n| n == "t"),
        "the live table t has its own version-history sheet: {names:?}"
    );

    let range = wb.worksheet_range("t").unwrap();
    let header: Vec<String> = range
        .rows()
        .next()
        .unwrap()
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    for col in [
        "id",
        "name",
        "_rowid",
        "wal_commit",
        "commit_seq",
        "view_state",
        "is_deleted",
        "rowid_reused",
    ] {
        assert!(
            header.iter().any(|h| h == col),
            "t header has {col}: {header:?}"
        );
    }
    let idx = |name: &str| header.iter().position(|h| h == name).unwrap();
    let (i_rowid, i_name) = (idx("_rowid"), idx("name"));
    let (i_view, i_del, i_reuse) = (idx("view_state"), idx("is_deleted"), idx("rowid_reused"));
    let i_commit = idx("wal_commit");

    // Gather (rowid, name, view_state, is_deleted, rowid_reused, wal_commit) per row.
    let as_i = |d: &Data| -> Option<i64> {
        match d {
            Data::Float(f) => Some(*f as i64),
            Data::Int(i) => Some(*i),
            _ => None,
        }
    };
    let as_s = |d: &Data| -> String { d.to_string() };
    // (rowid, name, view_state, is_deleted, rowid_reused, wal_commit) per data row.
    type VRow = (Option<i64>, String, String, i64, i64, String);
    let body: Vec<VRow> = range
        .rows()
        .skip(1)
        .map(|r| {
            (
                as_i(&r[i_rowid]),
                as_s(&r[i_name]),
                as_s(&r[i_view]),
                as_i(&r[i_del]).unwrap_or(0),
                as_i(&r[i_reuse]).unwrap_or(0),
                as_s(&r[i_commit]),
            )
        })
        .collect();

    // rowid 1: a historical 'a' (changed_later) AND the current 'A' (present).
    let r1: Vec<&VRow> = body.iter().filter(|t| t.0 == Some(1)).collect();
    assert!(
        r1.iter().any(|t| t.1 == "a" && t.2 == "changed_later"),
        "rowid 1 historical 'a' is changed_later: {r1:?}"
    );
    assert!(
        r1.iter().any(|t| t.1 == "A" && t.2 == "present"),
        "rowid 1 current 'A' is present: {r1:?}"
    );
    // The historical version is labelled with a commit:(...) wal_commit token.
    assert!(
        r1.iter()
            .any(|t| t.2 == "changed_later" && t.5.starts_with("commit:(")),
        "historical version carries a commit:(...) label: {r1:?}"
    );

    // rowid 2: deleted → absent_final, is_deleted=1.
    let r2: Vec<_> = body.iter().filter(|t| t.0 == Some(2)).collect();
    assert!(
        r2.iter().any(|t| t.2 == "absent_final" && t.3 == 1),
        "rowid 2 is absent_final / is_deleted: {r2:?}"
    );
    // The deleted rowid-2 version is listed EXACTLY once — the WAL-historical
    // version subsumes the carved residue, never double-listed.
    assert_eq!(
        r2.len(),
        1,
        "rowid 2 has exactly one (deleted) version, not double-listed: {r2:?}"
    );

    // rowid 4: REUSED (delete 'x' then reinsert 'y') → rowid_reused=1 on its rows.
    let r4: Vec<_> = body.iter().filter(|t| t.0 == Some(4)).collect();
    assert!(
        r4.len() >= 2 && r4.iter().all(|t| t.4 == 1),
        "rowid 4 versions flag rowid_reused=1: {r4:?}"
    );

    // The live image BLOB (rowid 3's pic) still embeds as xl/media/*.png.
    let bytes = std::fs::read(&xlsx).unwrap();
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    let mut media = false;
    for i in 0..zip.len() {
        let name = zip.by_index(i).unwrap().name().to_string();
        let is_png = std::path::Path::new(&name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("png"));
        if name.starts_with("xl/media/") && is_png {
            media = true;
        }
    }
    assert!(media, "the live image BLOB must embed under xl/media/*.png");

    teardown_reader(reader);
}

/// The `CFReDS` SFT-03 PERSIST pair: a `-journal` sits beside the main db with the
/// pre-images of the last transaction (100 `invoice_items` deletions + 100
/// modifications). The default `carve` must auto-discover the `<db>-journal`,
/// fold its recovery into the combined workbook, and surface in the
/// `invoice_items` sheet: the 100 deleted prior rows flagged `is_deleted=1`
/// (red), and the 100 modified rows' PRIOR values as `changed_later` superseded
/// (blue) versions — the live rows staying current. Counts are floored at 99 (the
/// recovery target is the full 100/100). The corpus pair is committed, so this
/// test reads it directly (no sqlite3 mint, no env gate); output lands in a
/// scratch copy so the evidence `-journal` is never touched.
#[test]
fn xlsx_combined_folds_rollback_journal_recovery() {
    use calamine::{Data, Reader};

    let dir = Scratch::new("journal_xlsx");
    let src = data_dir().join("cfreds");
    let db = dir.join("SFT-03_PERSIST_ios.sqlite");
    std::fs::copy(src.join("SFT-03_PERSIST_ios.sqlite"), &db).unwrap();
    std::fs::copy(
        src.join("SFT-03_PERSIST_ios.sqlite-journal"),
        dir.join("SFT-03_PERSIST_ios.sqlite-journal"),
    )
    .unwrap();

    let out = bin()
        .current_dir(&dir.0)
        .args(["carve", "SFT-03_PERSIST_ios.sqlite"])
        .output()
        .expect("run carve");
    assert!(
        out.status.success(),
        "carve must exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let xlsx = dir.join("SFT-03_PERSIST_ios.recovered.xlsx");
    assert!(xlsx.exists(), "xlsx companion must be written");
    let mut wb: calamine::Xlsx<_> =
        calamine::open_workbook(&xlsx).expect("calamine must open the xlsx");
    assert!(
        wb.sheet_names().iter().any(|n| n == "invoice_items"),
        "invoice_items has its own sheet: {:?}",
        wb.sheet_names()
    );

    let sheet = wb.worksheet_range("invoice_items").unwrap();
    let header: Vec<String> = sheet
        .rows()
        .next()
        .unwrap()
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    for col in ["_rowid", "view_state", "is_deleted"] {
        assert!(
            header.iter().any(|h| h == col),
            "invoice_items header has {col}: {header:?}"
        );
    }
    let i_del = header.iter().position(|h| h == "is_deleted").unwrap();
    let i_view = header.iter().position(|h| h == "view_state").unwrap();
    let i_rowid = header.iter().position(|h| h == "_rowid").unwrap();

    // The journal's 100 deletions fold in as is_deleted=1 versions under the KNOWN
    // table at their RECOVERED rowid (red tint). Count only the journal's
    // contribution — is_deleted rows carrying a known integer rowid in the original
    // 1..=2240 range — so an additional free-space residue carve (destroyed rowid,
    // blank `_rowid`) does not inflate the count.
    let journal_deleted: std::collections::BTreeSet<i64> = sheet
        .rows()
        .skip(1)
        .filter(|r| matches!(&r[i_del], Data::Float(d) if *d == 1.0))
        .filter_map(|r| match &r[i_rowid] {
            Data::Float(f) if f.fract() == 0.0 => Some(*f as i64),
            Data::Int(i) => Some(*i),
            _ => None,
        })
        .filter(|id| (1..=2240).contains(id))
        .collect();
    assert!(
        journal_deleted.len() >= 99,
        "the journal's 100 deletions fold in as is_deleted=1 versions at their rowid (got {})",
        journal_deleted.len()
    );
    assert_eq!(
        journal_deleted.len(),
        100,
        "target is the full 100/100 deletions"
    );

    // Modified rows: the PRIOR value surfaces as a `changed_later` superseded
    // version (blue), is_deleted=0 (the live row stays current).
    let superseded = sheet
        .rows()
        .skip(1)
        .filter(|r| matches!(&r[i_view], Data::String(s) if s == "changed_later"))
        .filter(|r| matches!(&r[i_del], Data::Float(d) if *d == 0.0))
        .count();
    assert!(
        superseded >= 99,
        "the journal's 100 modifications fold in as changed_later superseded versions (got {superseded})"
    );
    assert_eq!(superseded, 100, "target is the full 100/100 modifications");
}

/// The stdout text surfaces (here `--format jsonl`) also surface the rollback
/// journal's recovered prior rows, tagged `rollback-journal`, when a `<db>-journal`
/// is in play. Drives the stdout journal-records path end to end against the
/// committed `CFReDS` SFT-03 PERSIST pair (copied to a scratch dir).
#[test]
fn stdout_carve_surfaces_rollback_journal_records() {
    let dir = Scratch::new("journal_stdout");
    let src = data_dir().join("cfreds");
    std::fs::copy(
        src.join("SFT-03_PERSIST_ios.sqlite"),
        dir.join("SFT-03_PERSIST_ios.sqlite"),
    )
    .unwrap();
    std::fs::copy(
        src.join("SFT-03_PERSIST_ios.sqlite-journal"),
        dir.join("SFT-03_PERSIST_ios.sqlite-journal"),
    )
    .unwrap();

    let out = bin()
        .current_dir(&dir.0)
        .args(["carve", "SFT-03_PERSIST_ios.sqlite", "--format", "jsonl"])
        .output()
        .expect("run carve");
    assert!(
        out.status.success(),
        "carve --format jsonl must exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let journal_lines = stdout
        .lines()
        .filter(|l| l.contains("rollback-journal"))
        .count();
    assert!(
        journal_lines >= 99,
        "the recovered journal prior rows surface tagged rollback-journal (got {journal_lines})"
    );

    // `--no-journal` suppresses them: no rollback-journal rows in the stdout.
    let out2 = bin()
        .current_dir(&dir.0)
        .args([
            "carve",
            "SFT-03_PERSIST_ios.sqlite",
            "--format",
            "jsonl",
            "--no-journal",
        ])
        .output()
        .expect("run carve --no-journal");
    assert!(out2.status.success(), "carve --no-journal must exit 0");
    let stdout2 = String::from_utf8(out2.stdout).unwrap();
    assert!(
        !stdout2.contains("rollback-journal"),
        "--no-journal omits the rollback-journal rows"
    );
}

/// `carve --db` over the AUTOINCREMENT drop-recreate fixture writes a
/// `_table_instance_risk` provenance column into `recovered_students`, populated
/// (non-NULL) for the residue rowids 6..=10 that exceed `sqlite_sequence=5`. The
/// honesty flag rides as a column alongside the other provenance columns — never
/// a rerouted table. Skips when `sqlite3` is unavailable.
#[test]
fn carved_db_carries_table_instance_risk_column() {
    let Some(sqlite3) = sqlite3_bin() else {
        eprintln!("SKIP carved_db_carries_table_instance_risk_column: no sqlite3");
        return;
    };
    let dir = Scratch::new("tir_db");
    let src = data_dir().join("drop_recreate/b_autoinc.db");
    let db = dir.join("b_autoinc.db");
    std::fs::copy(&src, &db).expect("copy fixture");

    let out = bin()
        .current_dir(&dir.0)
        .args(["carve", "b_autoinc.db", "--db"])
        .output()
        .expect("run carve --db");
    assert!(out.status.success(), "carve --db must exit 0");

    let produced = dir.join("b_autoinc.carved.db");
    let cols = sqlite3_query(
        &sqlite3,
        &produced,
        "SELECT group_concat(name) FROM pragma_table_info('recovered_students');",
    );
    assert!(
        cols.contains("_table_instance_risk"),
        "recovered_students carries the _table_instance_risk column: {cols}"
    );

    // The residue rowids 6..=10 (above the high-water mark) carry a non-NULL,
    // evidence-bearing risk token; nothing reroutes them out of recovered_students.
    let flagged = sqlite3_query(
        &sqlite3,
        &produced,
        "SELECT count(*) FROM recovered_students \
         WHERE _table_instance_risk LIKE 'rowid_exceeds_autoinc_highwater%';",
    );
    assert!(
        flagged.parse::<i64>().unwrap_or(0) >= 5,
        "at least the 5 residue rows 6..=10 are flagged: {flagged}"
    );
}

/// `carve --format jsonl` over the AUTOINCREMENT fixture emits a
/// `table_instance_risk` field on every record: the evidence token for the
/// residue rows above the high-water mark, `null` otherwise.
#[test]
fn carve_jsonl_carries_table_instance_risk_field() {
    let out = bin()
        .args(["carve"])
        .arg(data_dir().join("drop_recreate/b_autoinc.db"))
        .args(["--format", "jsonl"])
        .output()
        .expect("run carve --format jsonl");
    assert!(out.status.success(), "carve --format jsonl must exit 0");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("\"table_instance_risk\""),
        "jsonl records carry a table_instance_risk field"
    );
    assert!(
        stdout.contains("rowid_exceeds_autoinc_highwater"),
        "the residue rows above the high-water mark carry the evidence token"
    );
}
