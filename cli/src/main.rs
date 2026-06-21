//! `sqlite4n6` — read-only SQLite forensic CLI.
//!
//! The binary is the irreducible Humble-Object shell: it parses arguments,
//! reads the evidence file into owned bytes, opens a read-only [`Database`],
//! drives the `sqlite4n6` library's pure decision helpers, and — per the single
//! `-f/--format` choice — writes one output: the **combined recovered workbook**
//! (`-f xlsx`, the default → `<stem>.recovered.xlsx`), the **rebuilt carved
//! database** (`-f db` → `<stem>.carved.db`), or a stdout rendering of the records
//! (`-f table`/`csv`/`jsonl`/`rowids`). **The evidence file and its sidecars are
//! never written** — the evidence bytes are owned by the [`Database`] and never
//! flushed back, and the file output is *separate* (guarded so it can never
//! resolve to the evidence db or a `-wal`/`-shm`/`-journal` sidecar). Every
//! decision (path derivation, projection, filtering, rendering) lives in the
//! unit-tested library; this file owns only I/O.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use sqlite4n6::{
    carve_wal_snapshots, carved_db_path, combined_xlsx_bytes, filter_by_confidence,
    group_attributed_tables, journal_carved_records, recovered_xlsx_path, render_audit,
    render_carve, render_carve_tiered, render_carve_with_snapshot, render_fragments, MinConfidence,
    OutputFormat, EXCEL_MAX_ROWS,
};
use sqlite_core::rebuild::build_recovered_db_tables;
use sqlite_core::Database;
use sqlite_forensic::{
    attribute_records, audit, audit_journal, carve_all_deleted_records, carve_rollback_journal,
    carve_with_fragments, table_instance_risks_with_sidecar, Anomaly, CarvedFragment, CarvedRecord,
    JournalRecovery,
};

/// sqlite4n6 — read-only SQLite forensic analysis CLI.
#[derive(Parser, Debug)]
#[command(name = "sqlite4n6", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// The `carve` output format — one choice selects exactly one destination: a file
/// (`xlsx`, `db`) or a stdout rendering (`table`, `csv`, `jsonl`, `rowids`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, Default)]
enum FormatArg {
    /// The full recovered review workbook (`<stem>.recovered.xlsx`) — a FILE.
    #[default]
    Xlsx,
    /// The carved-records database (`<stem>.carved.db`) — a FILE.
    Db,
    /// Carved records as an aligned text table — STDOUT.
    Table,
    /// Carved records as CSV — STDOUT.
    Csv,
    /// Carved records as JSONL — STDOUT.
    Jsonl,
    /// Just the recovered rowids, one per line — STDOUT.
    Rowids,
}

/// The `audit` output format (stdout rendering only).
#[derive(Clone, Copy, Debug, ValueEnum, Default)]
enum AuditFormatArg {
    #[default]
    Table,
    Csv,
    Jsonl,
}

impl From<AuditFormatArg> for OutputFormat {
    fn from(f: AuditFormatArg) -> Self {
        match f {
            AuditFormatArg::Table => OutputFormat::Table,
            AuditFormatArg::Csv => OutputFormat::Csv,
            AuditFormatArg::Jsonl => OutputFormat::Jsonl,
        }
    }
}

impl FormatArg {
    /// The stdout [`OutputFormat`] for a text rendering. `Rowids` renders over the
    /// `table` layout (the rowid-only projection is selected separately, by
    /// [`CarveArgs::rowid_only`]). Only meaningful for the stdout formats.
    fn stdout_format(self) -> OutputFormat {
        match self {
            FormatArg::Csv => OutputFormat::Csv,
            FormatArg::Jsonl => OutputFormat::Jsonl,
            // Table, Rowids (and the file formats, never reached on the stdout
            // path) all use the aligned table layout.
            _ => OutputFormat::Table,
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

// Each bool is an independent CLI toggle (`--no-wal`, `--no-fragments`,
// `--no-journal`); a bitflags struct would only obscure the clap surface, so the
// >3-bools lint does not apply to an args struct.
#[allow(clippy::struct_excessive_bools)]
#[derive(Parser, Debug)]
struct CarveArgs {
    /// Path to the SQLite database file (opened read-only).
    #[arg(value_name = "DB")]
    db: PathBuf,

    /// Output format — one choice, one destination:
    /// `xlsx` (the full recovered review workbook, a FILE; default),
    /// `db` (the carved-records database, a FILE),
    /// `table`/`csv`/`jsonl` (carved records to STDOUT),
    /// `rowids` (just the recovered rowids, one per line, to STDOUT).
    #[arg(short = 'f', long, value_enum, default_value = "xlsx")]
    format: FormatArg,

    /// Full output path for a file format (`xlsx`/`db`), honored EXACTLY as given
    /// (no extension rewriting). Defaults to `<db-stem>.recovered.xlsx` for `xlsx`
    /// or `<db-stem>.carved.db` for `db`, in the current directory. A path
    /// resolving to the evidence db or a `-wal`/`-shm`/`-journal` sidecar is
    /// refused. Ignored for the stdout formats.
    #[arg(short = 'o', long, value_name = "FILE")]
    out: Option<PathBuf>,

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
    /// can never be mistaken for a recovered row. `-f rowids` also omits them
    /// (a fragment has no rowid). Fragments are sourced from the on-disk image only.
    #[arg(long)]
    no_fragments: bool,

    /// Ignore any `<db>-journal` rollback-journal sidecar — do not recover the
    /// last transaction's deletions/modifications from it. By default, when no WAL
    /// is in play and a `<db>-journal` sits beside the database, its prior-state
    /// rows are folded into the combined workbook (deleted → red, modified → blue).
    /// A WAL always takes precedence (the two journal modes are mutually exclusive).
    #[arg(long)]
    no_journal: bool,
}

impl CarveArgs {
    /// Whether to render the Tier-2 fragment section. On by default; suppressed
    /// by `--no-fragments`, and by `-f rowids` (fragments carry no rowid, so a
    /// rowid listing coherently excludes them rather than erroring).
    fn wants_fragments(&self) -> bool {
        !self.no_fragments && self.format != FormatArg::Rowids
    }

    /// Whether the stdout renderer should project to bare rowids — true exactly for
    /// the `rowids` format.
    fn rowid_only(&self) -> bool {
        self.format == FormatArg::Rowids
    }

    /// The stdout [`OutputFormat`] for a text rendering (`table`/`csv`/`jsonl`, and
    /// `rowids` over the table layout). Only meaningful for the stdout formats.
    fn stdout_format(&self) -> OutputFormat {
        self.format.stdout_format()
    }
}

#[derive(Parser, Debug)]
struct AuditArgs {
    /// Path to the SQLite database file (opened read-only).
    #[arg(value_name = "DB")]
    db: PathBuf,

    /// Output format.
    #[arg(long, value_enum, default_value = "table")]
    format: AuditFormatArg,

    /// Ignore any `<db>-journal` rollback-journal sidecar — do not fold its
    /// design-§6 observations (hot journal, recoverable pre-images, checksum
    /// mismatch, journaled schema page, duplicate page, db-size delta) into the
    /// audit. By default, when no WAL is in play and a `<db>-journal` sits beside
    /// the database, those observations join the main-db anomalies. A WAL always
    /// takes precedence (the two journal modes are mutually exclusive).
    #[arg(long)]
    no_journal: bool,
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

/// The `<db>-journal` rollback-journal sidecar to use for `carve`, applying the
/// resolution policy: `--no-journal` disables it; a WAL (resolved by
/// [`resolve_wal_path`]) ALWAYS takes precedence — the two journal modes are
/// mutually exclusive, so a journal is only consulted when no WAL is in play;
/// otherwise auto-detect the conventional `<db>-journal` sidecar when it exists.
/// Returns the path only when a rollback journal is actually in play (and present).
fn resolve_journal_path(args: &CarveArgs) -> Option<PathBuf> {
    if args.no_journal {
        return None;
    }
    // A WAL wins outright: never recover a rollback journal alongside a WAL view.
    if resolve_wal_path(args).is_some() {
        return None;
    }
    // Auto-detect `<db>-journal` next to the database.
    let mut name = args.db.as_os_str().to_owned();
    name.push("-journal");
    let candidate = PathBuf::from(name);
    candidate.exists().then_some(candidate)
}

/// Recover the last transaction's deletions/modifications from the resolved
/// rollback `-journal` (when one is in play), bound to `db`. Reads the journal as
/// owned bytes (the evidence sidecar is never opened read-write). Returns `None`
/// when no journal applies (`--no-journal`, a WAL is in play, or none on disk); a
/// journal read error surfaces loudly rather than silently degrading to empty.
fn recover_journal(args: &CarveArgs, db: &Database) -> Result<Option<JournalRecovery>, String> {
    let Some(journal_path) = resolve_journal_path(args) else {
        return Ok(None);
    };
    let journal_bytes = std::fs::read(&journal_path)
        .map_err(|e| format!("cannot read journal {}: {e}", journal_path.display()))?;
    Ok(Some(carve_rollback_journal(db, &journal_bytes)))
}

/// The sidecar's PRIOR `sqlite_master` as `name -> CREATE SQL`, for Detector B
/// (`docs/design/drop-recreate-attribution.md`). Resolves whichever sidecar is in
/// play under the same policy as the carve:
///
/// - **`-wal`:** the OLD state is the main db file BEFORE the WAL is applied, so
///   the prior schema is the base bytes opened WITHOUT the WAL ([`Database::open`]
///   → [`Database::schema_sql`]). The WAL-applied current schema is read by the
///   detector from the supplied `db`.
/// - **`-journal`:** the prior snapshot the journal preserves
///   ([`Database::rollback_prior`] → `PriorSnapshot::schema_sql`).
///
/// Returns an EMPTY map when no sidecar applies, so Detector B stays silent (the
/// detector runs A only). Reads the evidence + sidecars as owned bytes; never
/// opens them read-write. A read/parse failure degrades to an empty prior schema
/// (Detector B silent) rather than failing the carve — the sidecar's own
/// loud-error path is the carve/journal recovery above; Detector B is an additive
/// hint and never the reason a carve aborts.
fn sidecar_prior_schema(args: &CarveArgs) -> std::collections::BTreeMap<String, String> {
    let empty = std::collections::BTreeMap::new();
    if let Some(wal_path) = resolve_wal_path(args) {
        // -wal: the prior state is the base db file WITHOUT the WAL overlay.
        let _ = &wal_path; // presence is the signal; the base bytes carry the schema.
        let Ok(base_bytes) = std::fs::read(&args.db) else {
            return empty;
        };
        let Ok(base) = Database::open(base_bytes) else {
            return empty;
        };
        return base.schema_sql();
    }
    if let Some(journal_path) = resolve_journal_path(args) {
        // -journal: the prior snapshot's own sqlite_master.
        let Ok(db_bytes) = std::fs::read(&args.db) else {
            return empty;
        };
        let Ok(db) = Database::open(db_bytes) else {
            return empty;
        };
        let Ok(journal_bytes) = std::fs::read(&journal_path) else {
            return empty;
        };
        let Ok(prior) = db.rollback_prior(&journal_bytes) else {
            return empty;
        };
        return prior.schema_sql();
    }
    empty
}

fn run_carve(args: &CarveArgs) -> Result<(), String> {
    match args.format {
        FormatArg::Xlsx => run_carve_xlsx(args),
        FormatArg::Db => run_carve_db(args),
        // table / csv / jsonl / rowids all render to stdout.
        _ => run_carve_stdout(args),
    }
}

/// `-f xlsx` (the default): carve the full recovered records and write the
/// combined `<stem>.recovered.xlsx` workbook — one sheet per live table with the
/// recovered (deleted) rows folded back in by rowid (marked `is_deleted` /
/// `is_guessed`, tinted), unattributed rows + fragments in separate tabs. The
/// rollback-journal prior rows are folded in too when a `<db>-journal` is in play.
/// The output path is the explicit `-o` (verbatim) or the derived
/// `<stem>.recovered.xlsx`, guarded against the evidence set by the pure
/// [`recovered_xlsx_path`]; this shell only performs the I/O.
fn run_carve_xlsx(args: &CarveArgs) -> Result<(), String> {
    // Resolve + guard the destination BEFORE carving, so an evidence-clobbering
    // path fails fast and nothing is read or written under it.
    let xlsx_path = recovered_xlsx_path(&args.db, args.out.as_deref())?;

    let (db, records, fragments) = collect_for_rebuild(args)?;
    let journal = recover_journal(args, &db)?;
    let prior_schema = sidecar_prior_schema(args);

    // Built to an in-memory buffer by the library; this shell only writes bytes
    // (and the library warns on stderr for any >1M-row sheet truncation).
    let xlsx_bytes = combined_xlsx_bytes(
        &db,
        &records,
        fragments.as_deref(),
        journal.as_ref(),
        &prior_schema,
        &xlsx_path,
        EXCEL_MAX_ROWS,
    )?;
    std::fs::write(&xlsx_path, &xlsx_bytes)
        .map_err(|e| format!("cannot write recovered xlsx {}: {e}", xlsx_path.display()))?;

    print_carve_summary(records.len(), fragments.as_deref(), &xlsx_path);
    print_journal_summary(journal.as_ref());
    Ok(())
}

/// `-f db`: carve the full recovered records and write the rebuilt
/// `<stem>.carved.db` — every carved record grouped into its attribution tier:
/// `recovered_<table>` (CERTAIN, real column names), `recovered_inferred`
/// (consistent-with + an ambiguity flag), `recovered_unattributed` (unknown), plus
/// `recovered_fragments`. The output path is the explicit `-o` (verbatim) or the
/// derived `<stem>.carved.db`, guarded against the evidence set by the pure
/// [`carved_db_path`]; this shell only performs the I/O.
fn run_carve_db(args: &CarveArgs) -> Result<(), String> {
    let db_path = carved_db_path(&args.db, args.out.as_deref())?;

    let (db, records, fragments) = collect_for_rebuild(args)?;
    let prior_schema = sidecar_prior_schema(args);

    let tables = group_attributed_tables(&db, &records, fragments.as_deref(), &prior_schema);
    let bytes = build_recovered_db_tables(&tables);
    std::fs::write(&db_path, &bytes)
        .map_err(|e| format!("cannot write carved db {}: {e}", db_path.display()))?;

    print_carve_summary(records.len(), fragments.as_deref(), &db_path);
    Ok(())
}

/// The one-line carve summary naming the written file and the record (and, when
/// fragments were carved, fragment) counts.
fn print_carve_summary(records: usize, fragments: Option<&[CarvedFragment]>, path: &Path) {
    match fragments {
        Some(frags) => println!(
            "wrote {records} record(s) and {} fragment(s) to {}",
            frags.len(),
            path.display()
        ),
        None => println!("wrote {records} record(s) to {}", path.display()),
    }
}

/// When a rollback `-journal` was folded in, report its recovery counts so the
/// summary reflects the prior rows in the workbook rather than only the free-space
/// carve (the journal's deleted/modified rows are tinted red/blue in each table
/// sheet, not counted among the records).
fn print_journal_summary(journal: Option<&JournalRecovery>) {
    if let Some(j) = journal {
        if j.counts.deleted > 0 || j.counts.modified > 0 {
            println!(
                "recovered {} deleted + {} modified row(s) from the rollback journal",
                j.counts.deleted, j.counts.modified
            );
        }
    }
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

/// Stdout mode (`-f table`/`csv`/`jsonl`/`rowids`): the historical rendering
/// behavior, byte-for-byte unchanged.
fn run_carve_stdout(args: &CarveArgs) -> Result<(), String> {
    let fmt = args.stdout_format();
    // Open the main file's owned bytes (never written back, no sidecar created).
    let db_bytes = std::fs::read(&args.db)
        .map_err(|e| format!("cannot read database {}: {e}", args.db.display()))?;

    // The sidecar PRIOR schema for Detector B's `_table_instance_risk` token;
    // empty when no `-wal`/`-journal` applies (Detector A only).
    let prior_schema = sidecar_prior_schema(args);

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
        let attrs = attribute_records(&db, &records);
        let risks = table_instance_risks_with_sidecar(&db, &records, &attrs, &prior_schema);
        for line in render_carve_with_snapshot(&records, &risks, fmt, args.rowid_only()) {
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
        // On-disk-only view: single view, no snapshot column. With no WAL in play, a
        // `<db>-journal` may apply — its recovered prior rows (deleted + modified)
        // join the carved records, tagged `rollback-journal`.
        let db = Database::open(db_bytes)
            .map_err(|e| format!("cannot parse database {}: {e:?}", args.db.display()))?;
        let journal_records = recover_journal(args, &db)?
            .as_ref()
            .map(journal_carved_records)
            .unwrap_or_default();
        if args.wants_fragments() {
            // Tier-1 + Tier-2 in one pass; both sections rendered together.
            let tiers = carve_with_fragments(&db);
            let mut full = filter_by_confidence(tiers.full, args.min_confidence.into());
            full.extend(journal_records);
            let attrs = attribute_records(&db, &full);
            let risks = table_instance_risks_with_sidecar(&db, &full, &attrs, &prior_schema);
            for line in render_carve_tiered(&full, &risks, &tiers.fragments, fmt, args.rowid_only())
            {
                println!("{line}");
            }
        } else {
            let mut records =
                filter_by_confidence(carve_all_deleted_records(&db), args.min_confidence.into());
            records.extend(journal_records);
            let attrs = attribute_records(&db, &records);
            let risks = table_instance_risks_with_sidecar(&db, &records, &attrs, &prior_schema);
            for line in render_carve(&records, &risks, fmt, args.rowid_only()) {
                println!("{line}");
            }
        }
    }
    Ok(())
}

/// The `<db>-journal` rollback-journal sidecar to fold into an `audit`, applying
/// the same resolution policy as `carve`: `--no-journal` disables it; a `<db>-wal`
/// on disk ALWAYS takes precedence (the two journal modes are mutually exclusive,
/// so a journal is only consulted when no WAL is in play); otherwise auto-detect
/// the conventional `<db>-journal` sidecar when it exists. Returns the path only
/// when a rollback journal is actually in play (and present).
fn resolve_audit_journal_path(db: &Path, no_journal: bool) -> Option<PathBuf> {
    if no_journal {
        return None;
    }
    // A WAL wins outright: never consult a rollback journal alongside a WAL view.
    let mut wal = db.as_os_str().to_owned();
    wal.push("-wal");
    if PathBuf::from(wal).exists() {
        return None;
    }
    let mut name = db.as_os_str().to_owned();
    name.push("-journal");
    let candidate = PathBuf::from(name);
    candidate.exists().then_some(candidate)
}

/// The design-§6 rollback-journal observations to fold into `audit` (when a
/// `<db>-journal` is in play and no WAL takes precedence), bound to `db`. Reads
/// the journal as owned bytes (the evidence sidecar is never opened read-write).
/// Returns an empty vector when no journal applies (`--no-journal`, a WAL is in
/// play, or none on disk); a journal read error surfaces loudly rather than
/// silently degrading to empty.
fn audit_journal_for(args: &AuditArgs, db: &Database) -> Result<Vec<Anomaly>, String> {
    let Some(journal_path) = resolve_audit_journal_path(&args.db, args.no_journal) else {
        return Ok(Vec::new());
    };
    let journal_bytes = std::fs::read(&journal_path)
        .map_err(|e| format!("cannot read journal {}: {e}", journal_path.display()))?;
    Ok(audit_journal(db, &journal_bytes))
}

fn run_audit(args: &AuditArgs) -> Result<(), String> {
    let db = open_db(&args.db)?;
    let mut anomalies = audit(&db);
    // Fold in the rollback-journal §6 observations when a `<db>-journal` applies.
    anomalies.extend(audit_journal_for(args, &db)?);
    for line in render_audit(&anomalies, args.format.into()) {
        println!("{line}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        audit_journal_for, open_db, recover_journal, resolve_journal_path, AuditArgs, CarveArgs,
        Cli, Commands, FormatArg, OutputFormat,
    };
    use clap::Parser;
    use std::path::{Path, PathBuf};

    fn carve_args(argv: &[&str]) -> CarveArgs {
        match Cli::try_parse_from(argv).expect("argv must parse").command {
            Commands::Carve(a) => a,
            Commands::Audit(_) => panic!("expected a carve command"),
        }
    }

    fn audit_args(argv: &[&str]) -> AuditArgs {
        match Cli::try_parse_from(argv).expect("argv must parse").command {
            Commands::Audit(a) => a,
            Commands::Carve(_) => panic!("expected an audit command"),
        }
    }

    /// A scratch directory holding a minimal db + chosen sidecars, for the
    /// journal-resolution policy tests. Removed on drop.
    struct JournalScratch(PathBuf);

    impl JournalScratch {
        /// Create `<dir>/ev.db` plus each named sidecar (e.g. `"-journal"`).
        fn new(tag: &str, sidecars: &[&str]) -> Self {
            let mut p = std::env::temp_dir();
            p.push(format!("sqlite4n6_jrnl_{tag}_{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            let db = p.join("ev.db");
            std::fs::write(&db, b"main").unwrap();
            for sc in sidecars {
                let mut name = db.as_os_str().to_owned();
                name.push(sc);
                std::fs::write(PathBuf::from(name), b"side").unwrap();
            }
            JournalScratch(p)
        }
        fn db(&self) -> PathBuf {
            self.0.join("ev.db")
        }
    }

    impl Drop for JournalScratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn carve_args_for(db: &std::path::Path, extra: &[&str]) -> CarveArgs {
        let mut argv: Vec<String> =
            vec!["sqlite4n6".into(), "carve".into(), db.display().to_string()];
        argv.extend(extra.iter().map(|s| (*s).to_string()));
        let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        carve_args(&refs)
    }

    /// With a `<db>-journal` beside the database and no WAL, the journal is in play
    /// and resolves to the conventional `<db>-journal` path.
    #[test]
    fn resolve_journal_auto_detects_sidecar() {
        let s = JournalScratch::new("auto", &["-journal"]);
        let args = carve_args_for(&s.db(), &[]);
        let resolved = resolve_journal_path(&args).expect("journal in play");
        let mut expected = s.db().into_os_string();
        expected.push("-journal");
        assert_eq!(resolved, PathBuf::from(expected));
    }

    /// `--no-journal` opts out even when the sidecar exists.
    #[test]
    fn resolve_journal_respects_no_journal_optout() {
        let s = JournalScratch::new("optout", &["-journal"]);
        let args = carve_args_for(&s.db(), &["--no-journal"]);
        assert!(
            resolve_journal_path(&args).is_none(),
            "--no-journal disables journal recovery"
        );
    }

    /// A WAL always takes precedence: with both a `-wal` and a `-journal` present,
    /// the journal is NOT consulted (the two modes are mutually exclusive).
    #[test]
    fn resolve_journal_yields_to_wal_precedence() {
        let s = JournalScratch::new("walwins", &["-wal", "-journal"]);
        let args = carve_args_for(&s.db(), &[]);
        assert!(
            resolve_journal_path(&args).is_none(),
            "a WAL in play suppresses the rollback journal"
        );
    }

    /// No sidecar on disk → no journal in play (clean degrade, not an error).
    #[test]
    fn resolve_journal_absent_is_none() {
        let s = JournalScratch::new("absent", &[]);
        let args = carve_args_for(&s.db(), &[]);
        assert!(resolve_journal_path(&args).is_none(), "no journal sidecar");
    }

    /// `--no-journal` parses and sets the opt-out flag.
    #[test]
    fn no_journal_flag_parses() {
        let args = carve_args(&["sqlite4n6", "carve", "db.sqlite", "--no-journal"]);
        assert!(args.no_journal, "--no-journal sets the opt-out");
    }

    /// The committed `CFReDS` SFT-03 PERSIST pair, in a scratch copy.
    fn copy_sft03(dir: &Path) -> PathBuf {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/data/cfreds");
        let db = dir.join("SFT-03_PERSIST_ios.sqlite");
        std::fs::copy(src.join("SFT-03_PERSIST_ios.sqlite"), &db).unwrap();
        std::fs::copy(
            src.join("SFT-03_PERSIST_ios.sqlite-journal"),
            dir.join("SFT-03_PERSIST_ios.sqlite-journal"),
        )
        .unwrap();
        db
    }

    /// `recover_journal` recovers the NIST deletions+modifications when a journal is
    /// in play, and returns `None` (no error, no recovery) under `--no-journal`.
    #[test]
    fn recover_journal_recovers_or_opts_out() {
        let s = JournalScratch::new("recover", &[]);
        let db_path = copy_sft03(&s.0);
        let db = open_db(&db_path).expect("open SFT-03");

        let args = carve_args_for(&db_path, &[]);
        let recovery = recover_journal(&args, &db)
            .expect("journal read succeeds")
            .expect("a journal is in play");
        assert!(
            recovery.counts.deleted >= 99 && recovery.counts.modified >= 99,
            "the NIST 100 deletes + 100 mods recover: {:?}",
            recovery.counts
        );

        let opted_out = carve_args_for(&db_path, &["--no-journal"]);
        assert!(
            recover_journal(&opted_out, &db).unwrap().is_none(),
            "--no-journal yields no recovery"
        );
    }

    /// A `<db>-journal` that EXISTS but cannot be read (here it is a directory) is a
    /// loud journal-read error — `recover_journal` surfaces it rather than silently
    /// degrading to an empty recovery (fail-loud at the sidecar boundary).
    #[test]
    fn recover_journal_unreadable_sidecar_errors_loudly() {
        let s = JournalScratch::new("unreadable", &[]);
        // A real db to bind the journal to (the recovery diff needs a live schema).
        let db_path = copy_sft03(&s.0);
        // Replace the journal sidecar with a DIRECTORY: it exists but is unreadable.
        let mut jname = db_path.as_os_str().to_owned();
        jname.push("-journal");
        let jpath = PathBuf::from(jname);
        std::fs::remove_file(&jpath).unwrap();
        std::fs::create_dir(&jpath).unwrap();
        let db = open_db(&db_path).expect("open the real db");

        let args = carve_args_for(&db_path, &[]);
        let err = recover_journal(&args, &db)
            .expect_err("an unreadable journal must surface a loud error");
        assert!(
            err.contains("cannot read journal"),
            "the error names the journal-read failure: {err}"
        );
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

    /// `-f rowids` is a full-row rowid listing; fragments have no rowid, so it
    /// coherently implies no fragment section — a usage combination, not an error.
    #[test]
    fn rowids_format_suppresses_fragments() {
        let args = carve_args(&["sqlite4n6", "carve", "db.sqlite", "-f", "rowids"]);
        assert!(
            !args.wants_fragments(),
            "-f rowids implies the fragment section is omitted"
        );
        assert!(
            args.rowid_only(),
            "-f rowids selects the rowid-only projection"
        );
    }

    /// The bare default carve selects the `xlsx` file output (the default format),
    /// not a stdout rendering and not the carved db.
    #[test]
    fn default_carve_format_is_xlsx() {
        let args = carve_args(&["sqlite4n6", "carve", "db.sqlite"]);
        assert_eq!(args.format, FormatArg::Xlsx, "the default format is xlsx");
        assert!(
            !args.rowid_only(),
            "the default is not the rowid projection"
        );
    }

    /// `-f db` selects the carved-database file output — a single exclusive choice,
    /// distinct from the xlsx default.
    #[test]
    fn db_format_selects_the_carved_database() {
        let args = carve_args(&["sqlite4n6", "carve", "db.sqlite", "-f", "db"]);
        assert_eq!(args.format, FormatArg::Db, "-f db selects the carved db");
    }

    /// The stdout formats (`table`/`csv`/`jsonl`/`rowids`) map onto the right
    /// [`OutputFormat`] for rendering.
    #[test]
    fn stdout_formats_map_to_output_format() {
        for (flag, want) in [
            ("table", OutputFormat::Table),
            ("csv", OutputFormat::Csv),
            ("jsonl", OutputFormat::Jsonl),
            ("rowids", OutputFormat::Table),
        ] {
            let args = carve_args(&["sqlite4n6", "carve", "db.sqlite", "-f", flag]);
            assert_eq!(args.stdout_format(), want, "-f {flag} renders as {want:?}");
        }
    }

    /// The dropped `--db` / `--rowid-only` flags no longer parse — clap rejects
    /// them as unknown arguments (no deprecated alias).
    #[test]
    fn dropped_flags_no_longer_parse() {
        for argv in [
            &["sqlite4n6", "carve", "db.sqlite", "--db"][..],
            &["sqlite4n6", "carve", "db.sqlite", "--rowid-only"][..],
        ] {
            assert!(
                Cli::try_parse_from(argv).is_err(),
                "{argv:?} must be rejected as an unknown flag"
            );
        }
    }

    /// `audit --no-journal` parses and sets the opt-out flag, mirroring carve.
    #[test]
    fn audit_no_journal_flag_parses() {
        let args = audit_args(&["sqlite4n6", "audit", "db.sqlite", "--no-journal"]);
        assert!(args.no_journal, "audit --no-journal sets the opt-out");
    }

    /// `audit` over the committed SFT-03 PERSIST pair folds the rollback-journal
    /// §6 observations in: the PERSIST journal is recoverable. It is DML only (the
    /// schema cookie did not advance), so SCHEMA-CHANGE must NOT surface.
    #[test]
    fn audit_surfaces_journal_anomaly_codes() {
        let s = JournalScratch::new("audit_jrnl", &[]);
        let db_path = copy_sft03(&s.0);
        let db = open_db(&db_path).expect("open SFT-03");
        let args = audit_args(&["sqlite4n6", "audit", db_path.to_str().unwrap()]);

        let anomalies = audit_journal_for(&args, &db).expect("journal read succeeds");
        let codes: Vec<&str> = anomalies.iter().map(|a| a.code).collect();
        assert!(
            codes.contains(&"SQLITE-JOURNAL-RECOVERABLE"),
            "audit folds in the recoverable journal observation; got {codes:?}"
        );
        assert!(
            !codes.contains(&"SQLITE-JOURNAL-SCHEMA-CHANGE"),
            "DML-only PERSIST (schema cookie unchanged) must NOT raise SCHEMA-CHANGE; got {codes:?}"
        );
    }

    /// `audit --no-journal` suppresses the journal observations (no journal read).
    #[test]
    fn audit_no_journal_suppresses_journal_anomalies() {
        let s = JournalScratch::new("audit_nojrnl", &[]);
        let db_path = copy_sft03(&s.0);
        let db = open_db(&db_path).expect("open SFT-03");
        let args = audit_args(&[
            "sqlite4n6",
            "audit",
            db_path.to_str().unwrap(),
            "--no-journal",
        ]);

        let anomalies = audit_journal_for(&args, &db).expect("opt-out is not an error");
        assert!(
            anomalies.is_empty(),
            "--no-journal yields no journal observations; got {anomalies:?}"
        );
    }

    /// An audit `<db>-journal` that exists but cannot be read fails loud rather
    /// than silently dropping the journal observations.
    #[test]
    fn audit_unreadable_journal_errors_loudly() {
        let s = JournalScratch::new("audit_badjrnl", &[]);
        let db_path = copy_sft03(&s.0);
        let mut jname = db_path.as_os_str().to_owned();
        jname.push("-journal");
        let jpath = PathBuf::from(jname);
        std::fs::remove_file(&jpath).unwrap();
        std::fs::create_dir(&jpath).unwrap();
        let db = open_db(&db_path).expect("open the real db");
        let args = audit_args(&["sqlite4n6", "audit", db_path.to_str().unwrap()]);

        let err = audit_journal_for(&args, &db).expect_err("unreadable journal must error");
        assert!(
            err.contains("cannot read journal"),
            "the error names the journal-read failure: {err}"
        );
    }
}
