//! `sqlite4n6` — read-only SQLite forensic CLI.
//!
//! The binary is the irreducible Humble-Object shell: it parses arguments,
//! reads the evidence file into owned bytes, opens a read-only [`Database`],
//! drives the `sqlite4n6` library's pure decision helpers, and either writes a
//! **rebuilt recovered database** (the default) or renders the records to stdout
//! (`--format` / `--rowid-only`). **The evidence file and its sidecars are never
//! written** — the evidence bytes are owned by the [`Database`] and never flushed
//! back, and the rebuilt db is a *separate* output file (guarded so it can never
//! resolve to the evidence db or a `-wal`/`-shm`/`-journal` sidecar). Every
//! decision (path derivation, projection, filtering, rendering) lives in the
//! unit-tested library; this file owns only I/O.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use sqlite4n6::{
    carve_wal_snapshots, combined_xlsx_bytes, filter_by_confidence, group_attributed_tables,
    recovered_output_path, recovered_xlsx_path, render_audit, render_carve, render_carve_tiered,
    render_carve_with_snapshot, render_fragments, MinConfidence, OutputFormat, EXCEL_MAX_ROWS,
};
use sqlite_core::rebuild::build_recovered_db_tables;
use sqlite_core::Database;
use sqlite_forensic::{
    audit, carve_all_deleted_records, carve_with_fragments, CarvedFragment, CarvedRecord,
};

/// sqlite4n6 — read-only SQLite forensic analysis CLI.
#[derive(Parser, Debug)]
#[command(name = "sqlite4n6", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, Debug, ValueEnum, Default)]
enum FormatArg {
    #[default]
    Table,
    Csv,
    Jsonl,
}

impl From<FormatArg> for OutputFormat {
    fn from(f: FormatArg) -> Self {
        match f {
            FormatArg::Table => OutputFormat::Table,
            FormatArg::Csv => OutputFormat::Csv,
            FormatArg::Jsonl => OutputFormat::Jsonl,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum, Default)]
enum ConfidenceArg {
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl From<ConfidenceArg> for MinConfidence {
    fn from(c: ConfidenceArg) -> Self {
        match c {
            ConfidenceArg::Info => MinConfidence::Info,
            ConfidenceArg::Low => MinConfidence::Low,
            ConfidenceArg::Medium => MinConfidence::Medium,
            ConfidenceArg::High => MinConfidence::High,
            ConfidenceArg::Critical => MinConfidence::Critical,
        }
    }
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Recover deleted records from the database's free (unallocated) space.
    Carve(CarveArgs),
    /// Grade forensically-notable anomalies into severity-ranked findings.
    Audit(AuditArgs),
}

// Each bool is an independent CLI toggle (`--rowid-only`, `--no-wal`,
// `--no-fragments`, `--xlsx`); a bitflags struct would only obscure the clap
// surface, so the >3-bools lint does not apply to an args struct.
#[allow(clippy::struct_excessive_bools)]
#[derive(Parser, Debug)]
struct CarveArgs {
    /// Path to the SQLite database file (opened read-only).
    #[arg(value_name = "DB")]
    db: PathBuf,

    /// Render the recovered records to stdout in this format instead of writing a
    /// rebuilt database. Omit to write a rebuilt `<stem>.recovered.db` (the
    /// default).
    #[arg(long, value_enum)]
    format: Option<FormatArg>,

    /// Output path for the rebuilt recovered database (default-write mode only).
    /// Defaults to `<stem>.recovered.db` in the current directory; refused if it
    /// resolves to the evidence db or a `-wal`/`-shm`/`-journal` sidecar.
    #[arg(long, value_name = "PATH")]
    out: Option<PathBuf>,

    /// Print only recovered rowids, one per line.
    #[arg(long)]
    rowid_only: bool,

    /// Drop records below this confidence level.
    #[arg(long, value_enum, default_value = "info")]
    min_confidence: ConfidenceArg,

    /// Explicit path to the `-wal` sidecar (overrides auto-detection).
    #[arg(long, value_name = "WAL")]
    wal: Option<PathBuf>,

    /// Carve the on-disk image ONLY — ignore any `-wal` sidecar (single view, no
    /// snapshot column).
    #[arg(long, conflicts_with = "wal")]
    no_wal: bool,

    /// Suppress the Tier-2 partial-fragment section, leaving only high-precision
    /// full rows. Fragments — lower-confidence partial rows salvaged where a full
    /// row could not be reconstructed but a distinctive cell survived — are shown
    /// **by default**, kept structurally separate from the full-row tier so they
    /// can never be mistaken for a recovered row. `--rowid-only` also omits them
    /// (a fragment has no rowid). Fragments are sourced from the on-disk image only.
    #[arg(long)]
    no_fragments: bool,

    /// Also write a spreadsheet `<stem>.recovered.xlsx` beside the rebuilt
    /// `<stem>.recovered.db` (honoring `--out`'s stem). Its two sheets mirror the
    /// rebuilt tables; image blobs are shown as in-cell thumbnails, video blobs as
    /// a typed `video/<ext> · <size>` placeholder. A rebuild-mode-only option:
    /// conflicts with the stdout text modes (`--format`, `--rowid-only`).
    #[arg(long, conflicts_with = "format", conflicts_with = "rowid_only")]
    xlsx: bool,
}

impl CarveArgs {
    /// Whether to render the Tier-2 fragment section. On by default; suppressed
    /// by `--no-fragments`, and by `--rowid-only` (fragments carry no rowid, so a
    /// rowid listing coherently excludes them rather than erroring).
    fn wants_fragments(&self) -> bool {
        !self.no_fragments && !self.rowid_only
    }

    /// Whether to write a rebuilt recovered database (the default). True only when
    /// neither a stdout `--format` nor `--rowid-only` was given — both of those
    /// keep the historical stdout behavior exactly.
    fn writes_rebuilt_db(&self) -> bool {
        self.format.is_none() && !self.rowid_only
    }

    /// The stdout format to use when NOT writing a rebuilt db: the explicit
    /// `--format`, or `table` for the bare `--rowid-only` case.
    fn stdout_format(&self) -> OutputFormat {
        self.format.unwrap_or(FormatArg::Table).into()
    }
}

#[derive(Parser, Debug)]
struct AuditArgs {
    /// Path to the SQLite database file (opened read-only).
    #[arg(value_name = "DB")]
    db: PathBuf,

    /// Output format.
    #[arg(long, value_enum, default_value = "table")]
    format: FormatArg,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Carve(args) => run_carve(&args),
        Commands::Audit(args) => run_audit(&args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::FAILURE
        }
    }
}

/// Read a database file into a read-only [`Database`].
///
/// Bytes are owned by the returned `Database` and never written back. Open/parse
/// failures return an actionable message — the caller turns this into a nonzero
/// exit, never an empty success.
fn open_db(db_path: &Path) -> Result<Database, String> {
    let bytes = std::fs::read(db_path)
        .map_err(|e| format!("cannot read database {}: {e}", db_path.display()))?;
    Database::open(bytes).map_err(|e| format!("cannot parse database {}: {e:?}", db_path.display()))
}

/// The `-wal` sidecar to use for `carve`, applying the resolution policy:
/// `--no-wal` disables it; an explicit `--wal` wins; otherwise auto-detect the
/// conventional `<db>-wal` sidecar when it exists on disk. Returns the path only
/// when a WAL is actually in play (and present).
fn resolve_wal_path(args: &CarveArgs) -> Option<PathBuf> {
    if args.no_wal {
        return None;
    }
    if let Some(explicit) = &args.wal {
        return Some(explicit.clone());
    }
    // Auto-detect `<db>-wal` next to the database.
    let mut name = args.db.as_os_str().to_owned();
    name.push("-wal");
    let candidate = PathBuf::from(name);
    candidate.exists().then_some(candidate)
}

fn run_carve(args: &CarveArgs) -> Result<(), String> {
    if args.writes_rebuilt_db() {
        return run_carve_rebuild(args);
    }
    run_carve_stdout(args)
}

/// Default mode: carve the full recovered records and write them as a rebuilt
/// `SQLite` database (never the evidence file). The output path is derived (and
/// guarded against the evidence set) by the pure [`recovered_output_path`]; this
/// shell only performs the I/O.
fn run_carve_rebuild(args: &CarveArgs) -> Result<(), String> {
    // Resolve + guard the destination BEFORE carving, so an evidence-clobbering
    // path fails fast and nothing is read or written under it.
    let out_path = recovered_output_path(&args.db, args.out.as_deref())?;

    // Tier-1 full rows and (when enabled) Tier-2 fragments come from one carve over
    // the same evidence bytes; the two sets land in two SEPARATE tables. With
    // `--no-fragments` the fragment set is `None`, omitting the table (single-table
    // db, as before); when enabled but none are found, an empty table is still
    // created (predictable).
    let (db, records, fragments) = collect_for_rebuild(args)?;
    // Group every carved record into its attribution tier: recovered_<table>
    // (CERTAIN, real column names), recovered_inferred (consistent-with + an
    // ambiguity flag), recovered_unattributed (unknown), plus recovered_fragments
    // (unchanged). The db and the xlsx are built from this same table set.
    let tables = group_attributed_tables(&db, &records, fragments.as_deref());

    let bytes = build_recovered_db_tables(&tables);
    std::fs::write(&out_path, &bytes)
        .map_err(|e| format!("cannot write recovered db {}: {e}", out_path.display()))?;

    // `--xlsx`: additionally write the COMBINED workbook companion beside the db,
    // honoring the db's stem. The source DB is dumped one sheet per live table
    // with the recovered (deleted) rows folded back in by rowid (marked
    // is_deleted / is_guessed, tinted), unattributed rows + fragments in separate
    // tabs. Built to an in-memory buffer by the library; this shell only writes
    // bytes (and the library warns on stderr for any >1M-row sheet truncation).
    let xlsx_path = if args.xlsx {
        let path = recovered_xlsx_path(&out_path);
        let xlsx_bytes =
            combined_xlsx_bytes(&db, &records, fragments.as_deref(), &path, EXCEL_MAX_ROWS)?;
        std::fs::write(&path, &xlsx_bytes)
            .map_err(|e| format!("cannot write recovered xlsx {}: {e}", path.display()))?;
        Some(path)
    } else {
        None
    };

    let xlsx_suffix = xlsx_path
        .as_ref()
        .map(|p| format!(" (+ {})", p.display()))
        .unwrap_or_default();
    match &fragments {
        Some(frags) => println!(
            "wrote {} record(s) and {} fragment(s) to {}{xlsx_suffix}",
            records.len(),
            frags.len(),
            out_path.display()
        ),
        None => println!(
            "wrote {} record(s) to {}{xlsx_suffix}",
            records.len(),
            out_path.display()
        ),
    }
    Ok(())
}

/// The evidence handle plus the carved record/fragment sets a rebuild needs:
/// the open [`Database`] (so attribution can read its live schema), the full
/// Tier-1 records, and the optional Tier-2 fragments.
type RebuildInputs = (Database, Vec<CarvedRecord>, Option<Vec<CarvedFragment>>);

/// Collect the rebuilt db's record sets from the evidence: the open database, the
/// full (Tier-1) rows always, and the Tier-2 fragments when
/// `args.wants_fragments()` (else `None`, which omits the fragment table).
///
/// The evidence bytes are read once. Fragments are sourced from the **on-disk
/// image only** (v1 has no WAL fragment pass), matching the stdout carve; so under
/// a WAL the records use the WAL-applied view while the fragments come from the
/// same bytes opened without the WAL. The confidence filter is a full-row policy
/// and is not applied to fragments.
fn collect_for_rebuild(args: &CarveArgs) -> Result<RebuildInputs, String> {
    let db_bytes = std::fs::read(&args.db)
        .map_err(|e| format!("cannot read database {}: {e}", args.db.display()))?;

    // Open the evidence ONCE (WAL-applied when a sidecar is in play), keeping the
    // stdout path's error ordering: an unreadable WAL, then a main-file parse, are
    // surfaced first. The same `db` backs both the full-record carve and — when
    // enabled — the fragment carve, mirroring the stdout path's single-db reuse.
    let (db, wal_records) = if let Some(wal_path) = resolve_wal_path(args) {
        let wal_bytes = std::fs::read(&wal_path)
            .map_err(|e| format!("cannot read WAL {}: {e}", wal_path.display()))?;
        let db = Database::open_with_wal(db_bytes, &wal_bytes)
            .map_err(|e| format!("cannot parse database {}: {e:?}", args.db.display()))?;
        let records = if let Some(timeline) = db.wal_timeline() {
            carve_wal_snapshots(&db, &timeline)
        } else {
            // A present-but-empty/uncommitted WAL yields no timeline; fall back to
            // the WAL-applied full carve (mirrors the stdout path).
            carve_all_deleted_records(&db)
        };
        (db, records)
    } else {
        let db = Database::open(db_bytes)
            .map_err(|e| format!("cannot parse database {}: {e:?}", args.db.display()))?;
        let records = carve_all_deleted_records(&db);
        (db, records)
    };
    let records = filter_by_confidence(wal_records, args.min_confidence.into());

    // Tier-2 fragments share the already-open `db` (no second read/parse); `None`
    // omits the fragment table. v1 has no WAL fragment pass, so a WAL-applied `db`
    // still yields its on-disk fragment residue here, as on the stdout path.
    let fragments = args
        .wants_fragments()
        .then(|| carve_with_fragments(&db).fragments);
    Ok((db, records, fragments))
}

/// Stdout mode (`--format` / `--rowid-only`): the historical rendering behavior,
/// byte-for-byte unchanged.
fn run_carve_stdout(args: &CarveArgs) -> Result<(), String> {
    let fmt = args.stdout_format();
    // Open the main file's owned bytes (never written back, no sidecar created).
    let db_bytes = std::fs::read(&args.db)
        .map_err(|e| format!("cannot read database {}: {e}", args.db.display()))?;

    // A WAL is in play: open the WAL-applied view, enumerate every materializable
    // state (on-disk base image, each commit snapshot, WAL-frame residue), and
    // render with the snapshot (LSN) column.
    if let Some(wal_path) = resolve_wal_path(args) {
        let wal_bytes = std::fs::read(&wal_path)
            .map_err(|e| format!("cannot read WAL {}: {e}", wal_path.display()))?;
        let db = Database::open_with_wal(db_bytes, &wal_bytes)
            .map_err(|e| format!("cannot parse database {}: {e:?}", args.db.display()))?;
        let records = if let Some(timeline) = db.wal_timeline() {
            carve_wal_snapshots(&db, &timeline)
        } else {
            // A present-but-empty/uncommitted WAL yields no timeline; fall back to
            // the WAL-applied full carve (still LSN-labelled where possible).
            carve_all_deleted_records(&db)
        };
        let records = filter_by_confidence(records, args.min_confidence.into());
        for line in render_carve_with_snapshot(&records, fmt, args.rowid_only) {
            println!("{line}");
        }
        // v1 fragments are sourced from the on-disk image only (no WAL fragment
        // pass yet); print the default section under the WAL-applied view's `db`.
        if args.wants_fragments() {
            let fragments = carve_with_fragments(&db).fragments;
            for line in render_fragments(&fragments, fmt) {
                println!("{line}");
            }
        }
    } else {
        // On-disk-only view: single view, no snapshot column.
        let db = Database::open(db_bytes)
            .map_err(|e| format!("cannot parse database {}: {e:?}", args.db.display()))?;
        if args.wants_fragments() {
            // Tier-1 + Tier-2 in one pass; both sections rendered together.
            let tiers = carve_with_fragments(&db);
            let full = filter_by_confidence(tiers.full, args.min_confidence.into());
            for line in render_carve_tiered(&full, &tiers.fragments, fmt, args.rowid_only) {
                println!("{line}");
            }
        } else {
            let records = carve_all_deleted_records(&db);
            let records = filter_by_confidence(records, args.min_confidence.into());
            for line in render_carve(&records, fmt, args.rowid_only) {
                println!("{line}");
            }
        }
    }
    Ok(())
}

fn run_audit(args: &AuditArgs) -> Result<(), String> {
    let db = open_db(&args.db)?;
    let anomalies = audit(&db);
    for line in render_audit(&anomalies, args.format.into()) {
        println!("{line}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{CarveArgs, Cli, Commands};
    use clap::Parser;

    fn carve_args(argv: &[&str]) -> CarveArgs {
        match Cli::try_parse_from(argv).expect("argv must parse").command {
            Commands::Carve(a) => a,
            Commands::Audit(_) => panic!("expected a carve command"),
        }
    }

    /// Fragments are ON by default: the zero-flag `carve` surfaces the Tier-2
    /// partial-row section alongside full rows (one surviving distinctive cell
    /// can still anchor evidence). The two tiers stay structurally separate in
    /// the output, so a fragment is never mistaken for a recovered full row.
    #[test]
    fn default_carve_includes_fragments() {
        let args = carve_args(&["sqlite4n6", "carve", "db.sqlite"]);
        assert!(args.wants_fragments(), "fragments must be on by default");
    }

    /// `--no-fragments` opts back into the high-precision full-row-only output.
    #[test]
    fn no_fragments_opts_out() {
        let args = carve_args(&["sqlite4n6", "carve", "db.sqlite", "--no-fragments"]);
        assert!(
            !args.wants_fragments(),
            "--no-fragments must suppress the Tier-2 fragment section"
        );
    }

    /// `--rowid-only` is a full-row rowid listing; fragments have no rowid, so it
    /// coherently implies no fragment section — a usage combination, not an error.
    #[test]
    fn rowid_only_suppresses_fragments() {
        let args = carve_args(&["sqlite4n6", "carve", "db.sqlite", "--rowid-only"]);
        assert!(
            !args.wants_fragments(),
            "--rowid-only implies the fragment section is omitted"
        );
    }

    /// The bare default carve writes the combined xlsx and NOT the db: the file
    /// surface is xlsx-only unless `--db` is given.
    #[test]
    fn default_carve_writes_xlsx_not_db() {
        let args = carve_args(&["sqlite4n6", "carve", "db.sqlite"]);
        assert!(
            args.writes_xlsx(),
            "the default carve writes the combined xlsx"
        );
        assert!(!args.db_flag, "the rebuilt db is opt-in (no --db given)");
    }

    /// `--db` ADDITIONALLY writes the rebuilt SQLite database alongside the xlsx:
    /// it parses, sets the flag, and keeps the xlsx-writing default active.
    #[test]
    fn db_flag_adds_the_rebuilt_database() {
        let args = carve_args(&["sqlite4n6", "carve", "db.sqlite", "--db"]);
        assert!(args.db_flag, "--db must set the flag");
        assert!(args.writes_xlsx(), "--db keeps the default xlsx output");
    }

    /// `--db` is a file-output (default) concern; it conflicts with the stdout text
    /// modes so clap rejects the combination rather than silently ignoring it.
    #[test]
    fn db_flag_conflicts_with_stdout_modes() {
        for argv in [
            &["sqlite4n6", "carve", "db.sqlite", "--db", "--format", "csv"][..],
            &["sqlite4n6", "carve", "db.sqlite", "--db", "--rowid-only"][..],
        ] {
            assert!(
                Cli::try_parse_from(argv).is_err(),
                "--db must conflict with {argv:?}"
            );
        }
    }
}
