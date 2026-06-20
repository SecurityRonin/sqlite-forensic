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
    let mut wb: calamine::Xlsx<_> =
        calamine::open_workbook(&xlsx).expect("xlsx must open in calamine");
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

/// The default `carve` writes the COMBINED workbook: the source DB dumped one
/// sheet per live table (here `moz_places`) with recovered rows folded in, each
/// carrying the three trailing flag columns and interleaving live + recovered rows.
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

    // The combined workbook opens in calamine with the live table's own sheet
    // (`moz_places`), carrying the three trailing flag columns.
    let mut wb: calamine::Xlsx<_> =
        calamine::open_workbook(&recovered_xlsx).expect("xlsx must open in calamine");
    let names = wb.sheet_names();
    assert!(
        names.iter().any(|n| n == "moz_places"),
        "the live table gets its own combined sheet: {names:?}"
    );
    assert!(
        !names.iter().any(|n| n == "recovered_inferred"),
        "inferred rows fold into table sheets, not a separate tab: {names:?}"
    );
    let sheet = wb.worksheet_range("moz_places").unwrap();
    let header: Vec<String> = sheet
        .rows()
        .next()
        .unwrap()
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    for flag in ["is_deleted", "is_guessed", "table_match_ambiguous"] {
        assert!(
            header.iter().any(|h| h == flag),
            "trailing flag column {flag} present: {header:?}"
        );
    }
    // Both live (is_deleted=0) and recovered (is_deleted=1) rows are present.
    let del_col = header.iter().position(|h| h == "is_deleted").unwrap();
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
        "combined sheet interleaves live + recovered rows"
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
/// three-tier fixture the default `carve` writes the source DB dumped per live
/// table with recovered rows folded back in:
/// - `people` sheet interleaves its live rows with the Tier-1 deleted row (rowid
///   3) in rowid order, `is_deleted=1` only on the recovered row;
/// - `amounts` sheet folds the Tier-2 freed-page rows in with `is_guessed=1`;
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

    // The two live tables get their own combined sheets; Tier-3 + fragments are
    // separate; no recovered_inferred tab (inferred rows folded into a sheet).
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

    // Helper: read a sheet's header + the index of a named column.
    let header_of = |wb: &mut calamine::Xlsx<_>, sheet: &str| -> Vec<String> {
        wb.worksheet_range(sheet)
            .unwrap()
            .rows()
            .next()
            .unwrap()
            .iter()
            .map(std::string::ToString::to_string)
            .collect()
    };

    // people: header carries the real `id`/`name` columns + the three flags.
    let people_hdr = header_of(&mut wb, "people");
    for col in [
        "id",
        "name",
        "is_deleted",
        "is_guessed",
        "table_match_ambiguous",
    ] {
        assert!(
            people_hdr.iter().any(|h| h == col),
            "people header has {col}: {people_hdr:?}"
        );
    }
    let del_col = people_hdr.iter().position(|h| h == "is_deleted").unwrap();
    let people = wb.worksheet_range("people").unwrap();
    // is_deleted per data row, in sheet order.
    let deleted_flags: Vec<f64> = people
        .rows()
        .skip(1)
        .filter_map(|r| match &r[del_col] {
            Data::Float(d) => Some(*d),
            _ => None,
        })
        .collect();
    // Four live rows survive the id=3 deletion; the carve folds in at least one
    // recovered (deleted) row. Both surfaces are present in the one sheet.
    let live_count = deleted_flags.iter().filter(|&&d| d == 0.0).count();
    let recovered_count = deleted_flags.iter().filter(|&&d| d == 1.0).count();
    assert_eq!(
        live_count, 4,
        "the four surviving live rows: {deleted_flags:?}"
    );
    assert!(
        recovered_count >= 1,
        "at least one recovered row folded into people: {deleted_flags:?}"
    );
    // Every live row precedes the recovered rows whose rowid was destroyed (this
    // fixture's freeblock reconstruction nulls the rowid → bottom of the sheet).
    let last_live = deleted_flags.iter().rposition(|&d| d == 0.0).unwrap();
    let first_recovered = deleted_flags.iter().position(|&d| d == 1.0).unwrap();
    assert!(
        last_live < first_recovered,
        "destroyed-rowid recovered rows sink below the live rows: {deleted_flags:?}"
    );

    // amounts: the Tier-2 freed-page rows folded in with is_guessed=1.
    let amounts_hdr = header_of(&mut wb, "amounts");
    let gcol = amounts_hdr
        .iter()
        .position(|h| h == "is_guessed")
        .expect("is_guessed column");
    let amounts = wb.worksheet_range("amounts").unwrap();
    let any_guessed = amounts
        .rows()
        .skip(1)
        .any(|r| matches!(&r[gcol], Data::Float(f) if *f == 1.0));
    assert!(
        any_guessed,
        "amounts holds at least one inferred (is_guessed=1) recovered row"
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
