//! `sqlite4n6` — read-only SQLite forensic CLI.
//!
//! The binary is the irreducible Humble-Object shell: it parses arguments,
//! reads the evidence file into owned bytes, opens a read-only [`Database`],
//! drives the `sqlite4n6` library's pure decision helpers, and — per the single
//! `-f/--format` choice — emits one output. Every format writes a **derived-name
//! file by default** (`<db-stem>.<suffix>` in the CWD): the **combined recovered
//! workbook** (`-f xlsx`, the default → `<stem>.recovered.xlsx`), the **rebuilt
//! carved database** (`-f db` → `<stem>.carved.db`), or a rendered record stream
//! (`-f table`/`csv`/`jsonl` → `<stem>.carved.{txt,csv,jsonl}`).
//! `-o <FILE>` overrides the path verbatim; the literal `-o -` streams the format
//! to stdout instead. **The evidence file and its sidecars are never written** —
//! the evidence bytes are owned by the [`Database`] and never flushed back, and
//! every file output is *separate* (guarded so it can never resolve to the
//! evidence db or a `-wal`/`-shm`/`-journal` sidecar). Every decision (destination
//! resolution, projection, filtering, rendering) lives in the unit-tested library;
//! this file owns only I/O.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use sqlite4n6::{
    carve_output_dest, carve_wal_snapshots, combined_xlsx_bytes, count_blob_cells,
    filter_by_confidence, group_attributed_tables, journal_carved_records, render_audit,
    render_carve, render_carve_jsonl_interpreted, render_carve_snapshot_jsonl_interpreted,
    render_carve_tiered, render_carve_with_snapshot, render_fragments, render_timeline,
    tables_from_attrs, MinConfidence, OutputDest, OutputFormat, EXCEL_MAX_ROWS,
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

/// The `carve` output format — one choice selects exactly one destination. Every
/// format writes a derived-name FILE by default (`<db-stem>.<suffix>` in the CWD);
/// `-o <FILE>` overrides the path and `-o -` streams to STDOUT. The `xlsx` review
/// workbook is named `.recovered.xlsx`; every raw carved-records encoding (`db`,
/// `table`, `csv`, `jsonl`) shares the `.carved.*` family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, Default)]
enum FormatArg {
    /// The full recovered review workbook (`<stem>.recovered.xlsx`).
    #[default]
    Xlsx,
    /// The carved-records database (`<stem>.carved.db`).
    Db,
    /// Carved records as an aligned text table (`<stem>.carved.txt`).
    Table,
    /// Carved records as CSV (`<stem>.carved.csv`).
    Csv,
    /// Carved records as JSONL (`<stem>.carved.jsonl`).
    Jsonl,
    /// Recovered BLOBs as a CASE/UCO JSON-LD bundle for case-management interop
    /// (`<stem>.recovered.case.json`) — each blob a content observable with its
    /// media type and SHA-256 hash.
    Case,
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
    /// The stdout [`OutputFormat`] for a text rendering. Only meaningful for the
    /// stream formats (`table`/`csv`/`jsonl`).
    fn stdout_format(self) -> OutputFormat {
        match self {
            FormatArg::Csv => OutputFormat::Csv,
            FormatArg::Jsonl => OutputFormat::Jsonl,
            // Table (and the file formats, never reached on the stream path) use
            // the aligned table layout.
            _ => OutputFormat::Table,
        }
    }

    /// The two-part default extension for this format's derived output name
    /// (`<db-stem>.<suffix>` in the CWD when no `-o` is given). The `xlsx` workbook
    /// is the reconstructed review view (`recovered.xlsx`); every raw carved-records
    /// encoding shares the `carved.*` family.
    fn default_suffix(self) -> &'static str {
        match self {
            FormatArg::Xlsx => "recovered.xlsx",
            FormatArg::Db => "carved.db",
            FormatArg::Table => "carved.txt",
            FormatArg::Csv => "carved.csv",
            FormatArg::Jsonl => "carved.jsonl",
            FormatArg::Case => "recovered.case.json",
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
    /// Reconstruct per-rowid version history from the WAL commit sequence.
    Timeline(TimelineArgs),
}

/// `timeline` subcommand: per-rowid version history over the WAL commit sequence.
#[derive(Parser, Debug)]
struct TimelineArgs {
    /// Path to the SQLite database file (opened read-only). A conventional
    /// `<db>-wal` sidecar is applied automatically when present.
    #[arg(value_name = "DB")]
    db: PathBuf,
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

    /// Output format — one choice, one destination. Each writes a derived-name FILE
    /// by default: `xlsx` → `<stem>.recovered.xlsx` (the review workbook),
    /// `db` → `<stem>.carved.db` (the carved-records database),
    /// `table` → `<stem>.carved.txt`, `csv` → `<stem>.carved.csv`,
    /// `jsonl` → `<stem>.carved.jsonl`. BLOB fidelity differs: `db` (native bytes)
    /// and `jsonl` (`{"blob_base64": …}`) preserve blob CONTENT losslessly, while
    /// `csv` and `table` render a blob as a `<blob:N bytes>` placeholder (only the
    /// byte count survives) — use `db` or `jsonl` when blob content (e.g. recovered
    /// images) must be preserved.
    #[arg(short = 'f', long, value_enum, default_value = "xlsx")]
    format: FormatArg,

    /// Output path, honored EXACTLY as given (no extension rewriting). Defaults to
    /// the format's `<db-stem>.<suffix>` in the current directory. A path resolving
    /// to the evidence db or a `-wal`/`-shm`/`-journal` sidecar is refused. Use the
    /// literal `-o -` to stream this format to STDOUT instead (e.g. `-f jsonl -o -
    /// | jq`); a stdout stream prints the rendered rows only, with no summary line.
    #[arg(short = 'o', long, value_name = "FILE")]
    out: Option<PathBuf>,

    /// Drop output below this confidence level — a recall/noise dial applied to
    /// every emitted item (full records AND Tier-2 fragments). Fragments carry the
    /// flat confidence 0.2, so they appear at `info`/`low` but are dropped at
    /// `medium` and above; `--fragments` forces them back in, `--no-fragments`
    /// always drops them. This is NOT a safety control: a still-live row is never
    /// reported as deleted regardless of this threshold (that guarantee is
    /// structural and confidence-independent).
    ///
    /// Calibration (measured on the Nemetz record-deletion corpus, categories
    /// 0C/0D/0E — NOT a general guarantee): precision is 1.000 at EVERY band, so
    /// the band selects recall depth, not precision. Full records recovered:
    /// 110 at `medium` (>=0.4), 28 at `high` (>=0.6), 2 at `critical` (>=0.8);
    /// 0 false positives at every band. See docs/validation.md.
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
    /// can never be mistaken for a recovered row. Fragments are sourced from the
    /// on-disk image only.
    #[arg(long)]
    no_fragments: bool,

    /// Force the Tier-2 fragment section to be included even when `--min-confidence`
    /// would otherwise drop it. Fragments carry the flat confidence 0.2, so they are
    /// filtered out at `--min-confidence medium` and above; `--fragments` keeps them
    /// regardless. Conflicts with `--no-fragments`.
    #[arg(long, conflicts_with = "no_fragments")]
    fragments: bool,

    /// Ignore any `<db>-journal` rollback-journal sidecar — do not recover the
    /// last transaction's deletions/modifications from it. By default, when no WAL
    /// is in play and a `<db>-journal` sits beside the database, its prior-state
    /// rows are folded into the combined workbook (deleted → red, modified → blue).
    /// A WAL always takes precedence (the two journal modes are mutually exclusive).
    #[arg(long)]
    no_journal: bool,
}

impl CarveArgs {
    /// Apply the fragment output policy to a carved fragment set: `--no-fragments`
    /// → none; `--fragments` → all (forced, bypassing the confidence bar);
    /// otherwise only fragments meeting `--min-confidence` (the global filter —
    /// fragments are confidence 0.2, so they appear at `info`/`low`, not `medium`+).
    fn select_fragments(&self, frags: Vec<CarvedFragment>) -> Vec<CarvedFragment> {
        if self.no_fragments {
            return Vec::new();
        }
        if self.fragments {
            return frags;
        }
        let threshold = Into::<MinConfidence>::into(self.min_confidence).threshold();
        frags
            .into_iter()
            .filter(|f| f.confidence >= threshold)
            .collect()
    }

    /// The stdout [`OutputFormat`] for a text rendering (`table`/`csv`/`jsonl`).
    /// Only meaningful for the stream formats.
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
        Commands::Timeline(args) => run_timeline(&args),
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
    // Resolve + guard the destination BEFORE carving, uniformly for every format,
    // so an evidence-clobbering `-o` fails fast and nothing is read or written
    // under it. `-o -` resolves to stdout; otherwise the verbatim `-o <FILE>` or the
    // derived `<stem>.<suffix>` in the CWD.
    let dest = carve_output_dest(&args.db, args.out.as_deref(), args.format.default_suffix())?;
    match args.format {
        FormatArg::Xlsx => run_carve_xlsx(args, &dest),
        FormatArg::Db => run_carve_db(args, &dest),
        FormatArg::Case => run_carve_case(args, &dest),
        // table / csv / jsonl render the same record stream.
        _ => run_carve_stream(args, &dest),
    }
}

/// `-f case`: carve the full recovered records and emit a CASE/UCO JSON-LD bundle
/// of every recovered BLOB (each a content observable with its media type and
/// SHA-256 hash), for case-management interop. Records with no blobs contribute no
/// observable. Bytes go to the resolved `dest`; this shell only performs the I/O.
fn run_carve_case(args: &CarveArgs, dest: &OutputDest) -> Result<(), String> {
    let (_db, records, _fragments) = collect_for_rebuild(args)?;
    let bundle = sqlite_forensic::case_uco::bundle_for_records(&records);
    emit_bytes(dest, bundle.as_bytes(), "case bundle")?;
    if let OutputDest::File(path) = dest {
        print_carve_summary(records.len(), None, path);
    }
    Ok(())
}

/// `-f xlsx` (the default): carve the full recovered records and emit the combined
/// recovered workbook — one sheet per live table with the recovered (deleted) rows
/// folded back in by rowid (marked `is_deleted` / `is_guessed`, tinted),
/// unattributed rows + fragments in separate tabs. The rollback-journal prior rows
/// are folded in too when a `<db>-journal` is in play. The workbook bytes go to the
/// resolved `dest` (a file → `<stem>.recovered.xlsx` or the verbatim `-o`, with the
/// summary line; or stdout for `-o -`); this shell only performs the I/O.
fn run_carve_xlsx(args: &CarveArgs, dest: &OutputDest) -> Result<(), String> {
    let (db, records, fragments) = collect_for_rebuild(args)?;
    let journal = recover_journal(args, &db)?;
    let prior_schema = sidecar_prior_schema(args);

    // The library wants a path hint for the truncation warning; stdout has none.
    let path_hint = dest_path_hint(dest);

    // Built to an in-memory buffer by the library; this shell only emits bytes
    // (and the library warns on stderr for any >1M-row sheet truncation).
    let xlsx_bytes = combined_xlsx_bytes(
        &db,
        &records,
        fragments.as_deref(),
        journal.as_ref(),
        &prior_schema,
        &path_hint,
        EXCEL_MAX_ROWS,
    )?;
    emit_bytes(dest, &xlsx_bytes, "recovered xlsx")?;

    if let OutputDest::File(path) = dest {
        print_carve_summary(records.len(), fragments.as_deref(), path);
        print_journal_summary(journal.as_ref());
    }
    Ok(())
}

/// `-f db`: carve the full recovered records and emit the rebuilt carved database —
/// every carved record grouped into its attribution tier: `recovered_<table>`
/// (CERTAIN, real column names), `recovered_inferred` (consistent-with + an
/// ambiguity flag), `recovered_unattributed` (unknown), plus `recovered_fragments`.
/// The database bytes go to the resolved `dest` (a file → `<stem>.carved.db` or the
/// verbatim `-o`, with the summary line; or stdout for `-o -`); this shell only
/// performs the I/O.
fn run_carve_db(args: &CarveArgs, dest: &OutputDest) -> Result<(), String> {
    let (db, mut records, fragments) = collect_for_rebuild(args)?;
    // Fold in the rollback-journal recoveries so the carved db matches the xlsx
    // workbook and the stdout streams, which already include them; `-f db` formerly
    // omitted the last transaction's journal-recovered deletes/edits.
    let journal = recover_journal(args, &db)?;
    if let Some(j) = &journal {
        records.extend(journal_carved_records(j));
    }
    let prior_schema = sidecar_prior_schema(args);

    let tables = group_attributed_tables(&db, &records, fragments.as_deref(), &prior_schema);
    let bytes = build_recovered_db_tables(&tables);
    emit_bytes(dest, &bytes, "carved db")?;

    if let OutputDest::File(path) = dest {
        print_carve_summary(records.len(), fragments.as_deref(), path);
        print_journal_summary(journal.as_ref());
    }
    Ok(())
}

/// A path to hand the xlsx builder for its truncation-warning message. For a file
/// destination it is the real output path; for stdout there is no file, so a
/// neutral `<stdout>` placeholder is used (the warning is cosmetic).
fn dest_path_hint(dest: &OutputDest) -> PathBuf {
    match dest {
        OutputDest::File(path) => path.clone(),
        OutputDest::Stdout => PathBuf::from("<stdout>"),
    }
}

/// Emit `bytes` to the resolved destination: a file write or stdout (`-o -`). Both
/// paths funnel through one [`write_dest`] call, so a single shared error mapping
/// surfaces an I/O failure loudly (named by `label` + the destination) instead of
/// panicking on, e.g., a broken pipe.
fn emit_bytes(dest: &OutputDest, bytes: &[u8], label: &str) -> Result<(), String> {
    write_dest(dest, bytes, label)
}

/// Emit rendered `lines` to the resolved destination as one newline-terminated
/// body (a trailing newline after the last line so a file ends cleanly and a stdout
/// stream matches the historical `println!` output), via the same [`write_dest`].
fn emit_lines(dest: &OutputDest, lines: &[String], label: &str) -> Result<(), String> {
    let mut body = lines.join("\n");
    if !body.is_empty() {
        body.push('\n');
    }
    write_dest(dest, body.as_bytes(), label)
}

/// Write `bytes` to a file path or stdout, mapping any I/O error to a single
/// `label`ed diagnostic. Stdout uses a locked handle and is flushed; the file path
/// truncates/creates. This is the one place carve output reaches the OS, so the
/// fail-loud error mapping lives here once for every format and destination. The
/// error arm is reached by the write-failure tests (an `-o` path that cannot be
/// created, e.g. occupied by a directory or under a missing parent).
fn write_dest(dest: &OutputDest, bytes: &[u8], label: &str) -> Result<(), String> {
    use std::io::Write;
    let (mut sink, where_): (Box<dyn Write>, String) = match dest {
        OutputDest::File(path) => match std::fs::File::create(path) {
            Ok(f) => (Box::new(f), path.display().to_string()),
            Err(e) => return Err(format!("cannot write {label} {}: {e}", path.display())),
        },
        OutputDest::Stdout => (Box::new(std::io::stdout().lock()), "stdout".to_string()),
    };
    // `match` (not `.map_err(closure)`) so the fail-loud error arm is a region of
    // this covered function, not a separate closure that the write-success tests
    // would leave uncovered.
    match sink.write_all(bytes).and_then(|()| sink.flush()) {
        Ok(()) => Ok(()),
        Err(e) => Err(format!("cannot write {label} to {where_}: {e}")),
    }
}

/// The one-line carve summary naming the written file and the record (and, when
/// fragments were carved, fragment) counts. Printed only for a file destination —
/// a `-o -` stdout stream emits the rendered rows alone, with no summary.
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
/// full (Tier-1) rows always, and the Tier-2 fragments per the output policy
/// ([`CarveArgs::select_fragments`]: `--no-fragments` → `None`; `--fragments` →
/// all; otherwise those meeting `--min-confidence`). `None` (or an all-filtered
/// empty set) omits the fragment table.
///
/// The evidence bytes are read once. Fragments are sourced from the **on-disk
/// image only** (v1 has no WAL fragment pass), matching the stdout carve; so under
/// a WAL the records use the WAL-applied view while the fragments come from the
/// same bytes opened without the WAL. `--min-confidence` applies globally — to the
/// full records here and to the fragments via `select_fragments`.
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
    // The fragment tier is emitted as a tab whenever it is enabled (not
    // `--no-fragments`), with its content filtered by the output policy
    // (`--fragments` forces all; otherwise `--min-confidence`). An empty set — none
    // found, or all below the threshold — yields an empty tab, not a missing one,
    // so the tier's presence is stable regardless of confidence.
    let fragments =
        (!args.no_fragments).then(|| args.select_fragments(carve_with_fragments(&db).fragments));
    Ok((db, records, fragments))
}

/// The rendered stream plus the counts its summary line (and the lossy-format
/// warning) need: all output lines (the carved rows and, when enabled, the fragment
/// section), the rendered record count, the fragment count (`None` when fragments
/// were suppressed), and the number of `BLOB` cells in the rendered set (record
/// values + fragment surviving cells) — what `csv`/`table` collapse to a
/// `<blob:N bytes>` placeholder.
struct RenderedStream {
    lines: Vec<String>,
    records: usize,
    fragments: Option<usize>,
    blob_cells: usize,
}

/// Stream mode (`-f table`/`csv`/`jsonl`): render the carved records (and, by
/// default, the Tier-2 fragment section) the historical way, then emit to the
/// resolved `dest` — a derived-name file (`<stem>.carved.{txt,csv,jsonl}`) or the
/// verbatim `-o <FILE>` with the summary line, or stdout for `-o -` (rows only, no
/// summary). The rendering itself is byte-for-byte unchanged.
fn run_carve_stream(args: &CarveArgs, dest: &OutputDest) -> Result<(), String> {
    let rendered = render_carve_stream(args)?;
    emit_lines(dest, &rendered.lines, "carve output")?;
    // Fail loud on silent evidence loss: `csv`/`table` collapse a BLOB to a
    // `<blob:N bytes>` placeholder (content dropped). Warn on stderr (keeping stdout
    // clean for `-o -` piping) whenever at least one blob was actually truncated;
    // `jsonl` preserves blobs (base64) so it never warns.
    warn_lossy_blob_truncation(args.format, rendered.blob_cells);
    if let OutputDest::File(path) = dest {
        print_stream_summary(rendered.records, rendered.fragments, path);
    }
    Ok(())
}

/// Emit the lossy-blob warning to stderr when the chosen text format (`csv`/`table`)
/// actually dropped at least one blob's content to a `<blob:N bytes>` placeholder.
/// Silent on blob-free data (no noise) and on the blob-preserving formats.
fn warn_lossy_blob_truncation(format: FormatArg, blob_cells: usize) {
    if blob_cells == 0 {
        return;
    }
    let label = match format {
        FormatArg::Csv => "csv",
        FormatArg::Table => "table",
        // jsonl preserves blobs; xlsx/db never reach the stream path.
        _ => return,
    };
    eprintln!(
        "warning: {blob_cells} BLOB value(s) were truncated to a `<blob:N bytes>` \
         placeholder in {label} output (content NOT exported); use `-f db` or \
         `-f jsonl` to preserve blob content"
    );
}

/// Render the stream output lines and the summary counts, without emitting them.
/// Splits the WAL-applied view (LSN-labelled, with an on-disk fragment section)
/// from the on-disk-only view (which may fold in `<db>-journal` prior rows).
fn render_carve_stream(args: &CarveArgs) -> Result<RenderedStream, String> {
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
        // `rowid_only` is always false: the bare-rowid format was dropped (multiple
        // versions per rowid + rowid reuse + destroyed rowids made a flat list
        // misleading); the full record stream is always rendered. JSONL decodes
        // schema-known BLOBs (e.g. localStorage UTF-16) via the built-in interpreter.
        let mut lines = if fmt == OutputFormat::Jsonl {
            let tables = tables_from_attrs(&attrs);
            render_carve_snapshot_jsonl_interpreted(
                &records,
                &tables,
                &risks,
                Some(&sqlite_forensic::interpret::LocalStorageInterpreter),
            )
        } else {
            render_carve_with_snapshot(&records, &risks, fmt, false)
        };
        // v1 fragments are sourced from the on-disk image only (no WAL fragment
        // pass yet); render the default section under the WAL-applied view's `db`.
        let frags = if args.no_fragments {
            None
        } else {
            let selected = args.select_fragments(carve_with_fragments(&db).fragments);
            (!selected.is_empty()).then_some(selected)
        };
        if let Some(frags) = &frags {
            lines.extend(render_fragments(frags, fmt));
        }
        let blob_cells = count_blob_cells(&records, frags.as_deref());
        Ok(RenderedStream {
            lines,
            records: records.len(),
            fragments: frags.as_ref().map(Vec::len),
            blob_cells,
        })
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
        // Carve full rows always; the fragment pass too unless `--no-fragments`.
        // Then apply the fragment output policy (`--no-fragments` / `--fragments` /
        // the global `--min-confidence` filter) and render the tiered section only
        // when a fragment survives.
        let (full_raw, frags_raw) = if args.no_fragments {
            (carve_all_deleted_records(&db), Vec::new())
        } else {
            let tiers = carve_with_fragments(&db);
            (tiers.full, tiers.fragments)
        };
        let mut full = filter_by_confidence(full_raw, args.min_confidence.into());
        full.extend(journal_records);
        let attrs = attribute_records(&db, &full);
        let risks = table_instance_risks_with_sidecar(&db, &full, &attrs, &prior_schema);
        let frags = args.select_fragments(frags_raw);
        let frag_slice = (!frags.is_empty()).then_some(frags.as_slice());
        let blob_cells = count_blob_cells(&full, frag_slice);
        let lines = if fmt == OutputFormat::Jsonl {
            // Decode schema-known BLOBs (e.g. localStorage UTF-16) via the built-in
            // interpreter; append the fragment section unchanged.
            let tables = tables_from_attrs(&attrs);
            let mut l = render_carve_jsonl_interpreted(
                &full,
                &tables,
                &risks,
                Some(&sqlite_forensic::interpret::LocalStorageInterpreter),
            );
            l.extend(render_fragments(&frags, fmt));
            l
        } else if frags.is_empty() {
            render_carve(&full, &risks, fmt, false)
        } else {
            render_carve_tiered(&full, &risks, &frags, fmt, false)
        };
        Ok(RenderedStream {
            lines,
            records: full.len(),
            fragments: (!frags.is_empty()).then_some(frags.len()),
            blob_cells,
        })
    }
}

/// The stream-format file summary, mirroring [`print_carve_summary`] but taking the
/// fragment **count** directly (the stream path tracks counts, not slices).
fn print_stream_summary(records: usize, fragments: Option<usize>, path: &Path) {
    match fragments {
        Some(n) => println!(
            "wrote {records} record(s) and {n} fragment(s) to {}",
            path.display()
        ),
        None => println!("wrote {records} record(s) to {}", path.display()),
    }
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

fn run_timeline(args: &TimelineArgs) -> Result<(), String> {
    let db = open_db_with_wal(&args.db)?;
    for line in render_timeline(&db.row_histories()) {
        println!("{line}");
    }
    Ok(())
}

/// Open a database, applying a conventional `<db>-wal` sidecar when it exists so
/// the version history sees the WAL commit sequence. Read-only; neither file is
/// mutated (the WAL overlay is applied without checkpointing).
fn open_db_with_wal(db_path: &Path) -> Result<Database, String> {
    let mut wal_os = db_path.as_os_str().to_owned();
    wal_os.push("-wal");
    let wal_path = PathBuf::from(wal_os);
    if !wal_path.exists() {
        return open_db(db_path); // no sidecar: the plain (already-covered) open
    }
    let bytes = std::fs::read(db_path)
        .map_err(|e| format!("cannot read database {}: {e}", db_path.display()))?;
    let wal = std::fs::read(&wal_path)
        .map_err(|e| format!("cannot read WAL {}: {e}", wal_path.display()))?;
    Database::open_with_wal(bytes, &wal)
        .map_err(|e| format!("cannot parse database {}: {e:?}", db_path.display()))
}

#[cfg(test)]
mod tests {
    use super::{
        audit_journal_for, open_db, recover_journal, resolve_journal_path, run_timeline, AuditArgs,
        CarveArgs, CarvedFragment, Cli, Commands, FormatArg, OutputFormat, TimelineArgs,
    };
    use clap::Parser;
    use sqlite_core::Value;
    use sqlite_forensic::RecoverySource;
    use std::path::{Path, PathBuf};

    /// A Tier-2 fragment with a given confidence and one surviving distinctive cell.
    fn frag(confidence: f32) -> CarvedFragment {
        CarvedFragment {
            page: 1,
            offset: 0,
            surviving: vec![(1, Value::Text("lead".into()))],
            missing: 2,
            confidence,
            source: RecoverySource::InPageFreeBlock,
            wal: None,
        }
    }

    #[test]
    fn timeline_subcommand_parses_its_db_arg() {
        let cli = Cli::try_parse_from(["sqlite4n6", "timeline", "x.db"]).expect("argv must parse");
        match cli.command {
            Commands::Timeline(a) => assert!(a.db.ends_with("x.db")),
            _ => panic!("expected a timeline command"),
        }
    }

    #[test]
    fn run_timeline_handles_wal_and_plain_dbs() {
        let data = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/data");
        // WAL branch: the `<db>-wal` sidecar is auto-detected and applied.
        run_timeline(&TimelineArgs {
            db: data.join("wal_places.db"),
        })
        .expect("timeline over a WAL db");
        // Non-WAL branch: falls back to a plain read-only open.
        run_timeline(&TimelineArgs {
            db: data.join("places.db"),
        })
        .expect("timeline over a plain db");
    }

    #[test]
    fn open_db_with_wal_surfaces_io_and_parse_errors() {
        use super::open_db_with_wal;
        let dir = std::env::temp_dir().join(format!("s4n6_owdw_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // (a) the `-wal` sidecar exists but the database is absent → read-db error.
        std::fs::write(dir.join("a.db-wal"), b"walbytes").unwrap();
        assert!(open_db_with_wal(&dir.join("a.db")).is_err());

        // (b) database present but malformed, `-wal` present → open_with_wal parse error.
        std::fs::write(dir.join("b.db"), b"not a sqlite header").unwrap();
        std::fs::write(dir.join("b.db-wal"), b"walbytes").unwrap();
        assert!(open_db_with_wal(&dir.join("b.db")).is_err());

        // (c) database present, `<db>-wal` exists but is a DIRECTORY → read-wal error.
        std::fs::write(dir.join("c.db"), b"SQLite format 3\0").unwrap();
        std::fs::create_dir_all(dir.join("c.db-wal")).unwrap();
        assert!(open_db_with_wal(&dir.join("c.db")).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn carve_args(argv: &[&str]) -> CarveArgs {
        match Cli::try_parse_from(argv).expect("argv must parse").command {
            Commands::Carve(a) => a,
            _ => panic!("expected a carve command"),
        }
    }

    fn audit_args(argv: &[&str]) -> AuditArgs {
        match Cli::try_parse_from(argv).expect("argv must parse").command {
            Commands::Audit(a) => a,
            _ => panic!("expected an audit command"),
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
        assert!(
            !args.select_fragments(vec![frag(0.2)]).is_empty(),
            "fragments must be on by default"
        );
    }

    /// `--no-fragments` opts back into the high-precision full-row-only output.
    #[test]
    fn no_fragments_opts_out() {
        let args = carve_args(&["sqlite4n6", "carve", "db.sqlite", "--no-fragments"]);
        assert!(
            args.select_fragments(vec![frag(0.2)]).is_empty(),
            "--no-fragments must suppress the Tier-2 fragment section"
        );
    }

    /// Global confidence filtering: a 0.2 fragment survives the default (`info`) and
    /// `low`, but `--min-confidence medium`+ drops it (it falls below the bar).
    #[test]
    fn fragments_respect_min_confidence_globally() {
        let default = carve_args(&["sqlite4n6", "carve", "db.sqlite"]);
        assert_eq!(
            default.select_fragments(vec![frag(0.2)]).len(),
            1,
            "info keeps a 0.2 fragment"
        );

        let low = carve_args(&["sqlite4n6", "carve", "db.sqlite", "--min-confidence", "low"]);
        assert_eq!(
            low.select_fragments(vec![frag(0.2)]).len(),
            1,
            "low (0.2) keeps a 0.2 fragment"
        );

        let medium = carve_args(&[
            "sqlite4n6",
            "carve",
            "db.sqlite",
            "--min-confidence",
            "medium",
        ]);
        assert!(
            medium.select_fragments(vec![frag(0.2)]).is_empty(),
            "medium drops a 0.2 fragment (global confidence filter)"
        );

        let critical = carve_args(&[
            "sqlite4n6",
            "carve",
            "db.sqlite",
            "--min-confidence",
            "critical",
        ]);
        assert!(
            critical.select_fragments(vec![frag(0.2)]).is_empty(),
            "critical drops a 0.2 fragment"
        );
    }

    /// `--fragments` forces the fragment tier in even above the confidence bar.
    #[test]
    fn fragments_flag_forces_fragments_past_the_confidence_bar() {
        let forced = carve_args(&[
            "sqlite4n6",
            "carve",
            "db.sqlite",
            "--fragments",
            "--min-confidence",
            "critical",
        ]);
        assert_eq!(
            forced.select_fragments(vec![frag(0.2)]).len(),
            1,
            "--fragments keeps fragments at any threshold"
        );
    }

    /// `--no-fragments` drops the tier regardless of confidence.
    #[test]
    fn no_fragments_drops_fragments_regardless_of_confidence() {
        let none = carve_args(&["sqlite4n6", "carve", "db.sqlite", "--no-fragments"]);
        assert!(
            none.select_fragments(vec![frag(0.9)]).is_empty(),
            "--no-fragments drops even a high-confidence fragment"
        );
    }

    /// `--fragments` and `--no-fragments` are mutually exclusive.
    #[test]
    fn fragments_and_no_fragments_conflict() {
        assert!(
            Cli::try_parse_from([
                "sqlite4n6",
                "carve",
                "db.sqlite",
                "--fragments",
                "--no-fragments"
            ])
            .is_err(),
            "--fragments and --no-fragments must conflict"
        );
    }

    /// The bare default carve selects the `xlsx` file output (the default format),
    /// not a stream rendering and not the carved db.
    #[test]
    fn default_carve_format_is_xlsx() {
        let args = carve_args(&["sqlite4n6", "carve", "db.sqlite"]);
        assert_eq!(args.format, FormatArg::Xlsx, "the default format is xlsx");
        assert!(
            !args.select_fragments(vec![frag(0.2)]).is_empty(),
            "fragments are on by default (no --no-fragments)"
        );
    }

    /// `-f db` selects the carved-database file output — a single exclusive choice,
    /// distinct from the xlsx default.
    #[test]
    fn db_format_selects_the_carved_database() {
        let args = carve_args(&["sqlite4n6", "carve", "db.sqlite", "-f", "db"]);
        assert_eq!(args.format, FormatArg::Db, "-f db selects the carved db");
    }

    /// The stream formats (`table`/`csv`/`jsonl`) map onto the right
    /// [`OutputFormat`] for rendering.
    #[test]
    fn stdout_formats_map_to_output_format() {
        for (flag, want) in [
            ("table", OutputFormat::Table),
            ("csv", OutputFormat::Csv),
            ("jsonl", OutputFormat::Jsonl),
        ] {
            let args = carve_args(&["sqlite4n6", "carve", "db.sqlite", "-f", flag]);
            assert_eq!(args.stdout_format(), want, "-f {flag} renders as {want:?}");
        }
    }

    /// Each format's default-name suffix is the derived `<stem>.<suffix>` extension
    /// — `recovered.xlsx` for the review workbook, the `carved.*` family for every
    /// raw carved-records encoding. Covers every `FormatArg` arm.
    #[test]
    fn every_format_has_its_default_suffix() {
        for (flag, want) in [
            ("xlsx", "recovered.xlsx"),
            ("db", "carved.db"),
            ("table", "carved.txt"),
            ("csv", "carved.csv"),
            ("jsonl", "carved.jsonl"),
            ("case", "recovered.case.json"),
        ] {
            let args = carve_args(&["sqlite4n6", "carve", "db.sqlite", "-f", flag]);
            assert_eq!(
                args.format.default_suffix(),
                want,
                "-f {flag} default suffix"
            );
        }
    }

    /// The dropped `rowids` format value no longer parses — it was removed because a
    /// flat rowid list is misleading under WAL/journal multi-version recovery and
    /// rowid reuse, and freeblock-reconstructed records carry a destroyed rowid.
    #[test]
    fn rowids_format_is_rejected() {
        assert!(
            Cli::try_parse_from(["sqlite4n6", "carve", "db.sqlite", "-f", "rowids"]).is_err(),
            "-f rowids must be rejected as an unknown value"
        );
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
