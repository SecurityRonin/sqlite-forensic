//! `sqlite4n6` — read-only SQLite forensic CLI.
//!
//! The binary is the irreducible Humble-Object shell: it parses arguments,
//! reads the evidence file into owned bytes, opens
//! a read-only [`Database`], drives the `sqlite4n6` library's pure decision
//! helpers, and writes the rendered lines to stdout. **The evidence file is
//! never written** — bytes are owned by the [`Database`] and never flushed back,
//! and no sidecar is created. Every decision (projection, filtering, rendering)
//! lives in the unit-tested library; this file owns only I/O.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use sqlite4n6::{filter_by_confidence, render_audit, render_carve, MinConfidence, OutputFormat};
use sqlite_core::Database;
use sqlite_forensic::{audit, carve_all_deleted_records};

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

#[derive(Parser, Debug)]
struct CarveArgs {
    /// Path to the SQLite database file (opened read-only).
    #[arg(value_name = "DB")]
    db: PathBuf,

    /// Output format.
    #[arg(long, value_enum, default_value = "table")]
    format: FormatArg,

    /// Print only recovered rowids, one per line.
    #[arg(long)]
    rowid_only: bool,

    /// Drop records below this confidence level.
    #[arg(long, value_enum, default_value = "info")]
    min_confidence: ConfidenceArg,
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

fn run_carve(args: &CarveArgs) -> Result<(), String> {
    let db = open_db(&args.db)?;
    let records = carve_all_deleted_records(&db);
    let records = filter_by_confidence(records, args.min_confidence.into());
    for line in render_carve(&records, args.format.into(), args.rowid_only) {
        println!("{line}");
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
