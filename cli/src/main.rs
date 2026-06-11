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
use sqlite4n6::{
    carve_wal_snapshots, filter_by_confidence, render_audit, render_carve, render_carve_tiered,
    render_carve_with_snapshot, render_fragments, MinConfidence, OutputFormat,
};
use sqlite_core::Database;
use sqlite_forensic::{audit, carve_all_deleted_records, carve_with_fragments};

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

    /// Explicit path to the `-wal` sidecar (overrides auto-detection).
    #[arg(long, value_name = "WAL")]
    wal: Option<PathBuf>,

    /// Carve the on-disk image ONLY — ignore any `-wal` sidecar (single view, no
    /// snapshot column).
    #[arg(long, conflicts_with = "wal")]
    no_wal: bool,

    /// Also emit Tier-2 partial fragments — lower-confidence partial rows
    /// salvaged where a full row could not be reconstructed but a distinctive
    /// cell survived. Off by default (the high-precision full-row output is the
    /// zero-config path). Fragments are sourced from the on-disk image only.
    #[arg(long, conflicts_with = "rowid_only")]
    fragments: bool,
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
        for line in render_carve_with_snapshot(&records, args.format.into(), args.rowid_only) {
            println!("{line}");
        }
        // v1 fragments are sourced from the on-disk image only (no WAL fragment
        // pass yet); print the opt-in section under the WAL-applied view's `db`.
        if args.fragments {
            let fragments = carve_with_fragments(&db).fragments;
            for line in render_fragments(&fragments, args.format.into()) {
                println!("{line}");
            }
        }
    } else {
        // On-disk-only view: single view, no snapshot column.
        let db = Database::open(db_bytes)
            .map_err(|e| format!("cannot parse database {}: {e:?}", args.db.display()))?;
        if args.fragments {
            // Tier-1 + Tier-2 in one pass; both sections rendered together.
            let tiers = carve_with_fragments(&db);
            let full = filter_by_confidence(tiers.full, args.min_confidence.into());
            for line in render_carve_tiered(&full, &tiers.fragments, args.format.into(), args.rowid_only)
            {
                println!("{line}");
            }
        } else {
            let records = carve_all_deleted_records(&db);
            let records = filter_by_confidence(records, args.min_confidence.into());
            for line in render_carve(&records, args.format.into(), args.rowid_only) {
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
    use super::Cli;
    use clap::Parser;

    /// `--rowid-only --fragments` is a usage error (fragments have no rowid), so
    /// clap rejects the combination — fail loud, not silently ignore one flag.
    #[test]
    fn rowid_only_and_fragments_conflict() {
        let res = Cli::try_parse_from(["sqlite4n6", "carve", "db.sqlite", "--rowid-only", "--fragments"]);
        assert!(res.is_err(), "--rowid-only --fragments must be rejected");
    }

    /// `--fragments` alone parses cleanly (the opt-in path).
    #[test]
    fn fragments_flag_parses() {
        let res = Cli::try_parse_from(["sqlite4n6", "carve", "db.sqlite", "--fragments"]);
        assert!(res.is_ok(), "--fragments alone must parse");
    }
}
