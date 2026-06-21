#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Pure decision helpers for the `sqlite4n6` CLI (the Humble Object / functional
//! core). Every decision that can be made without I/O — output-format and
//! confidence-threshold parsing, projecting a carved record or an anomaly into a
//! row of string cells, confidence filtering, rowid-only projection, and the
//! table/CSV/JSONL rendering of both surfaces — lives here so it is directly
//! unit-testable. `main()` is the thin shell that only reads the evidence file
//! and writes the rendered lines to stdout.

use std::path::{Path, PathBuf};

use sqlite_core::rebuild::{FragmentRow, RebuildRow, RecoveredTable};
use sqlite_core::{Database, Value, WalTimeline};
use sqlite_forensic::{
    attribute_records, carve_all_deleted_records, carve_at_commit,
    table_instance_risks_with_sidecar, Anomaly, Attribution, CarvedFragment, CarvedRecord,
    JournalRecovery, RecoverySource, TableInstanceRisk,
};

/// Output rendering format, shared by `carve` and `audit`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum OutputFormat {
    /// Aligned, human-readable columns (default).
    #[default]
    Table,
    /// Comma-separated values with a header row.
    Csv,
    /// One JSON object per line.
    Jsonl,
}

/// Minimum confidence threshold for `carve --min-confidence`, mapped onto the
/// canonical severity ladder so the flag reads in the same vocabulary as `audit`.
/// Each level carries the lower bound, in `[0.0, 1.0]`, a carved record's
/// `confidence` must meet to be kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum MinConfidence {
    /// Keep everything (default).
    #[default]
    Info,
    /// Keep records with confidence ≥ 0.2.
    Low,
    /// Keep records with confidence ≥ 0.4.
    Medium,
    /// Keep records with confidence ≥ 0.6.
    High,
    /// Keep records with confidence ≥ 0.8.
    Critical,
}

impl MinConfidence {
    /// The lower bound a carved record's `confidence` must meet for this level.
    #[must_use]
    pub fn threshold(self) -> f32 {
        match self {
            MinConfidence::Info => 0.0,
            MinConfidence::Low => 0.2,
            MinConfidence::Medium => 0.4,
            MinConfidence::High => 0.6,
            MinConfidence::Critical => 0.8,
        }
    }
}

/// Render a [`RecoverySource`] as a stable, lowercase-kebab token for output.
#[must_use]
pub fn recovery_source_token(source: RecoverySource) -> &'static str {
    match source {
        RecoverySource::FreelistPage => "freelist-page",
        RecoverySource::InPageFreeBlock => "in-page-freeblock",
        RecoverySource::DroppedTable => "dropped-table",
        RecoverySource::PriorVersion => "prior-version",
        RecoverySource::FreeblockReconstructed => "freeblock-reconstructed",
        RecoverySource::WalFrame => "wal-frame",
        RecoverySource::CommitSnapshot => "commit-snapshot",
        RecoverySource::RollbackJournal(_) => "rollback-journal",
        // `RecoverySource` is #[non_exhaustive]: a future class renders as its
        // Debug form rather than panicking or mislabelling.
        _ => "other", // cov:unreachable: all RecoverySource variants known at build time are matched above
    }
}

/// Render one decoded column [`Value`] as a single output cell.
///
/// Text and integers/reals render as their natural form; a blob renders as a
/// length-prefixed hex-free placeholder so a binary column never injects control
/// bytes or delimiter characters into table/CSV output.
#[must_use]
pub fn value_to_cell(value: &Value) -> String {
    match value {
        Value::Null => "NULL".to_string(),
        Value::Integer(i) => i.to_string(),
        Value::Real(r) => r.to_string(),
        Value::Text(t) => t.clone(),
        Value::Blob(b) => format!("<blob:{} bytes>", b.len()),
    }
}

/// A single carved value as a JSON array element. A `BLOB` is emitted losslessly
/// as a self-describing `{"blob_base64": "..."}` object — raw binary cannot be a
/// JSON string, and base64 round-trips it exactly; every other type renders as
/// its JSON-escaped string form (matching [`value_to_cell`]). table/CSV keep the
/// `<blob:N bytes>` placeholder, since neither can carry raw binary safely.
fn value_to_json(value: &Value) -> String {
    match value {
        Value::Blob(b) => format!("{{\"blob_base64\":\"{}\"}}", base64_encode(b)),
        other => format!("\"{}\"", json_escape(&value_to_cell(other))),
    }
}

/// Base64-encode bytes (RFC 4648 standard alphabet, with `=` padding).
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;
        out.push(ALPHABET[b0 >> 2] as char);
        out.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[b2 & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

/// The rowid cell for a carved record: the decimal rowid, or `?` when the rowid
/// is unknown/destroyed (`0`, e.g. a freeblock reconstruction).
#[must_use]
pub fn rowid_cell(rowid: i64) -> String {
    if rowid == 0 {
        "?".to_string()
    } else {
        rowid.to_string()
    }
}

/// Keep only carved records whose confidence meets the threshold, preserving order.
#[must_use]
pub fn filter_by_confidence(records: Vec<CarvedRecord>, min: MinConfidence) -> Vec<CarvedRecord> {
    let threshold = min.threshold();
    records
        .into_iter()
        .filter(|r| r.confidence >= threshold)
        .collect()
}

/// The fixed leading columns of a carved record (everything before the decoded
/// values): page, offset, rowid, recovery source, confidence.
#[must_use]
pub fn carve_lead_cells(rec: &CarvedRecord) -> Vec<String> {
    vec![
        rec.page.to_string(),
        rec.offset.to_string(),
        rowid_cell(rec.rowid),
        recovery_source_token(rec.source).to_string(),
        format!("{:.2}", rec.confidence),
    ]
}

/// CSV escape: wrap in double quotes and double any embedded quote when the cell
/// contains a comma, quote, or newline.
#[must_use]
pub fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// JSON-escape a string for the hand-rolled JSONL writer (no serde dependency:
/// the CLI stays dependency-light and never pulls a serializer into the evidence
/// path). Escapes the JSON-mandatory characters and control bytes below 0x20.
#[must_use]
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// A JSON array literal of a record's decoded values, each rendered via
/// [`value_to_cell`] as a JSON string (typed JSON is out of scope — the cell text
/// is the published contract shared with the table/CSV surfaces).
#[must_use]
fn values_json_array(values: &[Value]) -> String {
    let parts: Vec<String> = values.iter().map(value_to_json).collect();
    format!("[{}]", parts.join(","))
}

// ---- WAL N-snapshot enumeration --------------------------------------------

/// The snapshot / LSN label for a carved record — the view it was recovered from.
///
/// - `on-disk` — the main file's base-image view (no WAL provenance).
/// - `commit:(salt1,salt2,commit_frame_index)` — a materialized commit snapshot.
/// - `wal-frame:(salt1,salt2,frame_index)` — uncheckpointed WAL-frame residue.
///
/// The `(salt1, salt2, …)` triple is the salt-qualified LSN: a bare frame index is
/// meaningless across checkpoint resets, so the label always carries the salts.
#[must_use]
pub fn snapshot_label(rec: &CarvedRecord) -> String {
    match (rec.source, rec.wal.as_ref()) {
        (RecoverySource::CommitSnapshot, Some(w)) => {
            format!("commit:({},{},{})", w.salt1, w.salt2, w.frame_index)
        }
        (RecoverySource::WalFrame, Some(w)) => {
            format!("wal-frame:({},{},{})", w.salt1, w.salt2, w.frame_index)
        }
        // A rollback-journal prior row is the immediately-preceding state captured
        // in the `-journal`; its provenance is the segment + restored page number.
        (RecoverySource::RollbackJournal(s), _) => {
            format!("rollback-journal:({},{})", s.segment, s.pgno)
        }
        // Every on-disk class (and any WAL record missing provenance) is the
        // on-disk base-image view.
        _ => "on-disk".to_string(),
    }
}

/// Enumerate the N materializable WAL states and carve each, LSN-labelled.
///
/// With a `-wal` in play this carves EVERY materializable view — the on-disk base
/// image, EACH commit snapshot of the timeline, and the WAL-frame residue — and
/// returns the union, each record tagged so [`snapshot_label`] resolves its LSN.
/// A record identical across views (same `rowid` + values) is collapsed to a
/// single copy, keeping the highest-confidence / earliest-labelled instance, so a
/// row is reported once rather than repeated per snapshot. The live-row precision
/// filter inside each carve guarantees no live row is ever re-surfaced.
#[must_use]
pub fn carve_wal_snapshots(db: &Database, timeline: &WalTimeline) -> Vec<CarvedRecord> {
    // (1) on-disk base image + (3) WAL-frame residue — both already produced by
    // the full carver (carve_all_deleted_records carves the main pages and, when a
    // WAL overlay is in effect, the WAL frames). On-disk records carry no WAL
    // provenance → labelled `on-disk`; WAL-frame residue keeps its WalFrame tag.
    let mut out: Vec<CarvedRecord> = carve_all_deleted_records(db);

    // (2) EACH commit snapshot — the per-commit temporal states.
    for snapshot in timeline.commit_snapshots() {
        out.extend(carve_at_commit(db, timeline, snapshot.id()));
    }

    dedup_keep_earliest_label(out)
}

/// Collapse records identical in `(rowid, values)` to one, preferring the earliest
/// snapshot label (a commit snapshot over the later wal-frame/on-disk view) and,
/// within that, the highest confidence — so a deleted row carries the LSN of the
/// earliest state it is recoverable in.
fn dedup_keep_earliest_label(mut records: Vec<CarvedRecord>) -> Vec<CarvedRecord> {
    // Rank: a full-fidelity prior state (commit snapshot / rollback-journal,
    // earliest) < wal-frame < on-disk free-space carve; tie-break high conf. A
    // journal prior row is the full-fidelity copy of a deleted row, so it is
    // preferred over a free-space carve of the same (rowid, values).
    fn rank(rec: &CarvedRecord) -> u8 {
        match rec.source {
            RecoverySource::CommitSnapshot | RecoverySource::RollbackJournal(_) => 0,
            RecoverySource::WalFrame => 1,
            _ => 2,
        }
    }
    records.sort_by(|a, b| {
        rank(a).cmp(&rank(b)).then_with(|| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    });
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut kept: Vec<CarvedRecord> = Vec::new();
    for rec in records.drain(..) {
        let key = format!("{}:{:?}", rec.rowid, rec.values);
        if seen.insert(key) {
            kept.push(rec);
        }
    }
    kept
}

// ---- carve rendering -------------------------------------------------------

/// Render carved records as full output lines in the chosen format.
///
/// `rowid_only` collapses each record to just its rowid cell (one per line, no
/// header) across every format — the projection a triage script pipes onward.
#[must_use]
pub fn render_carve(
    records: &[CarvedRecord],
    risks: &[TableInstanceRisk],
    format: OutputFormat,
    rowid_only: bool,
) -> Vec<String> {
    if rowid_only {
        return records.iter().map(|r| rowid_cell(r.rowid)).collect();
    }
    match format {
        OutputFormat::Table => render_carve_table(records),
        OutputFormat::Csv => render_carve_csv(records),
        OutputFormat::Jsonl => render_carve_jsonl(records, risks),
    }
}

/// The JSONL `table_instance_risk` field value for a record's risk: the quoted
/// evidence token, or the literal `null` for [`TableInstanceRisk::None`] / a risk
/// slice that does not cover this index. Kept null for the overwhelming majority
/// of records — only Detector A (AUTOINCREMENT `rowid > seq`) or Detector B
/// (sidecar schema change) populates a token. Keyed off the non-empty
/// [`TableInstanceRisk::token`] so every firing variant surfaces, not just A.
fn table_instance_risk_json(risks: &[TableInstanceRisk], idx: usize) -> String {
    match risks.get(idx).map(TableInstanceRisk::token) {
        Some(token) if !token.is_empty() => format!("\"{}\"", json_escape(&token)),
        _ => "null".to_string(),
    }
}

fn render_carve_table(records: &[CarvedRecord]) -> Vec<String> {
    let mut lines = vec![format!(
        "{:>6}  {:>8}  {:>8}  {:<24}  {:>5}  values",
        "page", "offset", "rowid", "recovery_source", "conf"
    )];
    for rec in records {
        let lead = carve_lead_cells(rec);
        let values: Vec<String> = rec.values.iter().map(value_to_cell).collect();
        lines.push(format!(
            "{:>6}  {:>8}  {:>8}  {:<24}  {:>5}  {}",
            lead[0],
            lead[1],
            lead[2],
            lead[3],
            lead[4],
            values.join(" | ")
        ));
    }
    lines
}

fn render_carve_csv(records: &[CarvedRecord]) -> Vec<String> {
    let mut lines = vec!["page,offset,rowid,recovery_source,confidence,values".to_string()];
    for rec in records {
        let lead = carve_lead_cells(rec);
        let values: Vec<String> = rec.values.iter().map(value_to_cell).collect();
        let joined = values.join(" | ");
        lines.push(format!(
            "{},{},{},{},{},{}",
            csv_escape(&lead[0]),
            csv_escape(&lead[1]),
            csv_escape(&lead[2]),
            csv_escape(&lead[3]),
            csv_escape(&lead[4]),
            csv_escape(&joined)
        ));
    }
    lines
}

fn render_carve_jsonl(records: &[CarvedRecord], risks: &[TableInstanceRisk]) -> Vec<String> {
    records
        .iter()
        .enumerate()
        .map(|(i, rec)| {
            format!(
                "{{\"page\":{},\"offset\":{},\"rowid\":{},\"recovery_source\":\"{}\",\"confidence\":{:.4},\"table_instance_risk\":{},\"values\":{}}}",
                rec.page,
                rec.offset,
                rec.rowid,
                recovery_source_token(rec.source),
                rec.confidence,
                table_instance_risk_json(risks, i),
                values_json_array(&rec.values)
            )
        })
        .collect()
}

// ---- Tier-2 fragment rendering (shown by default; `--no-fragments` opts out) -

/// The fixed leading cells of a fragment row: page, offset, confidence, source.
/// Fragments carry NO rowid (it was clobbered), so there is no rowid cell.
fn fragment_lead_cells(frag: &CarvedFragment) -> [String; 4] {
    [
        frag.page.to_string(),
        frag.offset.to_string(),
        format!("{:.2}", frag.confidence),
        recovery_source_token(frag.source).to_string(),
    ]
}

/// Render a fragment's surviving cells as a human-readable summary, e.g.
/// `col1='Anja' col2='Frank' (+1 column destroyed)`.
fn fragment_surviving_cell(frag: &CarvedFragment) -> String {
    let mut parts: Vec<String> = frag
        .surviving
        .iter()
        .map(|(idx, v)| format!("col{idx}='{}'", value_to_cell(v)))
        .collect();
    if frag.missing > 0 {
        let noun = if frag.missing == 1 {
            "column"
        } else {
            "columns"
        };
        parts.push(format!("(+{} {noun} destroyed)", frag.missing));
    }
    parts.join(" ")
}

/// Render the Tier-2 fragment section in the chosen format.
///
/// A fragment is **not** a recovered row: it has no rowid and an incomplete
/// column set, and the full-row 0-false-positive guarantee does NOT extend to it.
/// The section is therefore clearly labelled (table) / discriminated by a `kind`
/// column (CSV) / a `"kind":"fragment"` key (JSONL), so a fragment can never be
/// mistaken for a full row. Empty input yields no lines.
#[must_use]
pub fn render_fragments(frags: &[CarvedFragment], format: OutputFormat) -> Vec<String> {
    if frags.is_empty() {
        return Vec::new();
    }
    match format {
        OutputFormat::Table => render_fragments_table(frags),
        OutputFormat::Csv => render_fragments_csv(frags),
        OutputFormat::Jsonl => render_fragments_jsonl(frags),
    }
}

fn render_fragments_table(frags: &[CarvedFragment]) -> Vec<String> {
    let mut lines = vec![
        String::new(),
        "# fragments — partial rows, lower confidence (separate from the \
         full-row zero-false-positive output; --no-fragments to suppress)"
            .to_string(),
        format!(
            "{:>6}  {:>8}  {:>5}  {:<24}  surviving",
            "page", "offset", "conf", "source"
        ),
    ];
    for frag in frags {
        let lead = fragment_lead_cells(frag);
        lines.push(format!(
            "{:>6}  {:>8}  {:>5}  {:<24}  {}",
            lead[0],
            lead[1],
            lead[2],
            lead[3],
            fragment_surviving_cell(frag)
        ));
    }
    lines
}

fn render_fragments_csv(frags: &[CarvedFragment]) -> Vec<String> {
    let mut lines = vec!["kind,page,offset,confidence,source,missing,surviving".to_string()];
    for frag in frags {
        let lead = fragment_lead_cells(frag);
        lines.push(format!(
            "fragment,{},{},{},{},{},{}",
            csv_escape(&lead[0]),
            csv_escape(&lead[1]),
            csv_escape(&lead[2]),
            csv_escape(&lead[3]),
            frag.missing,
            csv_escape(&fragment_surviving_cell(frag))
        ));
    }
    lines
}

fn render_fragments_jsonl(frags: &[CarvedFragment]) -> Vec<String> {
    frags
        .iter()
        .map(|frag| {
            let surviving: Vec<String> = frag
                .surviving
                .iter()
                .map(|(idx, v)| {
                    format!(
                        "{{\"column\":{idx},\"value\":\"{}\"}}",
                        json_escape(&value_to_cell(v))
                    )
                })
                .collect();
            format!(
                "{{\"kind\":\"fragment\",\"page\":{},\"offset\":{},\"confidence\":{:.4},\"source\":\"{}\",\"missing\":{},\"surviving\":[{}]}}",
                frag.page,
                frag.offset,
                frag.confidence,
                recovery_source_token(frag.source),
                frag.missing,
                surviving.join(",")
            )
        })
        .collect()
}

/// Render full rows + the Tier-2 fragment section (the default carve output).
/// The full-row output is byte-identical to [`render_carve`] EXCEPT in CSV, where
/// both sections gain a leading `kind` column (`row` / `fragment`) so a consumer
/// can split the tiers unambiguously. `rowid_only` collapses to bare rowids of the
/// FULL rows only; callers suppress fragments whenever `rowid_only` is set (a
/// fragment has no rowid), so this `rowid_only` branch is a defensive guard that
/// renders full rowids and no fragment section.
#[must_use]
pub fn render_carve_tiered(
    full: &[CarvedRecord],
    risks: &[TableInstanceRisk],
    fragments: &[CarvedFragment],
    format: OutputFormat,
    rowid_only: bool,
) -> Vec<String> {
    if rowid_only {
        return full.iter().map(|r| rowid_cell(r.rowid)).collect();
    }
    if format == OutputFormat::Csv {
        // Both sections carry a leading `kind` column so the tiers split cleanly.
        let mut lines =
            vec!["kind,page,offset,rowid,recovery_source,confidence,values".to_string()];
        for rec in full {
            let lead = carve_lead_cells(rec);
            let values: Vec<String> = rec.values.iter().map(value_to_cell).collect();
            lines.push(format!(
                "row,{},{},{},{},{},{}",
                csv_escape(&lead[0]),
                csv_escape(&lead[1]),
                csv_escape(&lead[2]),
                csv_escape(&lead[3]),
                csv_escape(&lead[4]),
                csv_escape(&values.join(" | "))
            ));
        }
        lines.extend(render_fragments(fragments, format));
        return lines;
    }
    // Table / JSONL: full-row output unchanged, fragment section appended.
    let mut lines = render_carve(full, risks, format, false);
    lines.extend(render_fragments(fragments, format));
    lines
}

// ---- carve rendering with the snapshot/LSN column --------------------------

/// Render carved records WITH the `snapshot` (LSN) column — the N-snapshot WAL
/// carve view. Mirrors [`render_carve`] but inserts the [`snapshot_label`] between
/// the confidence and values columns across every format. `rowid_only` collapses
/// to bare rowids exactly as [`render_carve`] does.
#[must_use]
pub fn render_carve_with_snapshot(
    records: &[CarvedRecord],
    risks: &[TableInstanceRisk],
    format: OutputFormat,
    rowid_only: bool,
) -> Vec<String> {
    if rowid_only {
        return records.iter().map(|r| rowid_cell(r.rowid)).collect();
    }
    match format {
        OutputFormat::Table => render_carve_snapshot_table(records),
        OutputFormat::Csv => render_carve_snapshot_csv(records),
        OutputFormat::Jsonl => render_carve_snapshot_jsonl(records, risks),
    }
}

fn render_carve_snapshot_table(records: &[CarvedRecord]) -> Vec<String> {
    let mut lines = vec![format!(
        "{:>6}  {:>8}  {:>8}  {:<24}  {:>5}  {:<40}  values",
        "page", "offset", "rowid", "recovery_source", "conf", "snapshot"
    )];
    for rec in records {
        let lead = carve_lead_cells(rec);
        let values: Vec<String> = rec.values.iter().map(value_to_cell).collect();
        lines.push(format!(
            "{:>6}  {:>8}  {:>8}  {:<24}  {:>5}  {:<40}  {}",
            lead[0],
            lead[1],
            lead[2],
            lead[3],
            lead[4],
            snapshot_label(rec),
            values.join(" | ")
        ));
    }
    lines
}

fn render_carve_snapshot_csv(records: &[CarvedRecord]) -> Vec<String> {
    let mut lines =
        vec!["page,offset,rowid,recovery_source,confidence,snapshot,values".to_string()];
    for rec in records {
        let lead = carve_lead_cells(rec);
        let values: Vec<String> = rec.values.iter().map(value_to_cell).collect();
        let joined = values.join(" | ");
        lines.push(format!(
            "{},{},{},{},{},{},{}",
            csv_escape(&lead[0]),
            csv_escape(&lead[1]),
            csv_escape(&lead[2]),
            csv_escape(&lead[3]),
            csv_escape(&lead[4]),
            csv_escape(&snapshot_label(rec)),
            csv_escape(&joined)
        ));
    }
    lines
}

fn render_carve_snapshot_jsonl(
    records: &[CarvedRecord],
    risks: &[TableInstanceRisk],
) -> Vec<String> {
    records
        .iter()
        .enumerate()
        .map(|(i, rec)| {
            format!(
                "{{\"page\":{},\"offset\":{},\"rowid\":{},\"recovery_source\":\"{}\",\"confidence\":{:.4},\"snapshot\":\"{}\",\"table_instance_risk\":{},\"values\":{}}}",
                rec.page,
                rec.offset,
                rec.rowid,
                recovery_source_token(rec.source),
                rec.confidence,
                json_escape(&snapshot_label(rec)),
                table_instance_risk_json(risks, i),
                values_json_array(&rec.values)
            )
        })
        .collect()
}

// ---- audit rendering -------------------------------------------------------

/// Render the severity of an anomaly as a stable uppercase token.
#[must_use]
pub fn severity_token(severity: forensicnomicon::report::Severity) -> &'static str {
    use forensicnomicon::report::Severity;
    match severity {
        Severity::Info => "INFO",
        Severity::Low => "LOW",
        Severity::Medium => "MEDIUM",
        Severity::High => "HIGH",
        Severity::Critical => "CRITICAL",
        // `Severity` is #[non_exhaustive]: an unknown future level renders as
        // UNKNOWN rather than panicking.
        _ => "UNKNOWN", // cov:unreachable: all Severity variants known at build time are matched above
    }
}

/// A short human location string for an anomaly, derived from its evidence (page /
/// offset / rowid …). Empty when the anomaly carries no locating evidence.
#[must_use]
pub fn anomaly_location(anomaly: &Anomaly) -> String {
    use forensicnomicon::report::Observation;
    let parts: Vec<String> = anomaly
        .evidence()
        .iter()
        .map(|e| format!("{}={}", e.field, e.value))
        .collect();
    parts.join(" ")
}

/// Render audited anomalies as full output lines in the chosen format.
#[must_use]
pub fn render_audit(anomalies: &[Anomaly], format: OutputFormat) -> Vec<String> {
    match format {
        OutputFormat::Table => render_audit_table(anomalies),
        OutputFormat::Csv => render_audit_csv(anomalies),
        OutputFormat::Jsonl => render_audit_jsonl(anomalies),
    }
}

fn render_audit_table(anomalies: &[Anomaly]) -> Vec<String> {
    let mut lines = vec![format!(
        "{:<8}  {:<32}  {:<28}  note",
        "severity", "code", "location"
    )];
    for a in anomalies {
        lines.push(format!(
            "{:<8}  {:<32}  {:<28}  {}",
            severity_token(a.severity),
            a.code,
            anomaly_location(a),
            a.note
        ));
    }
    lines
}

fn render_audit_csv(anomalies: &[Anomaly]) -> Vec<String> {
    let mut lines = vec!["severity,code,location,note".to_string()];
    for a in anomalies {
        lines.push(format!(
            "{},{},{},{}",
            csv_escape(severity_token(a.severity)),
            csv_escape(a.code),
            csv_escape(&anomaly_location(a)),
            csv_escape(&a.note)
        ));
    }
    lines
}

fn render_audit_jsonl(anomalies: &[Anomaly]) -> Vec<String> {
    anomalies
        .iter()
        .map(|a| {
            format!(
                "{{\"severity\":\"{}\",\"code\":\"{}\",\"location\":\"{}\",\"note\":\"{}\"}}",
                severity_token(a.severity),
                json_escape(a.code),
                json_escape(&anomaly_location(a)),
                json_escape(&a.note)
            )
        })
        .collect()
}

// ---- carve output paths (.carved.db / .recovered.xlsx) ---------------------

/// Resolve the output path for the rebuilt **carved** database, enforcing the
/// forensic-soundness guard.
///
/// With no `-o`, the path is the evidence file's own stem with the `.carved.db`
/// suffix, in the **current working directory** (`History.db` →
/// `History.carved.db`), never beside the evidence. An explicit `out` is honored
/// **verbatim** — the exact path given, with no stem or extension stripping
/// (`-o /p/foo.db` → `/p/foo.db`). Either way the resolved path is **refused** (an
/// `Err`) when it equals the evidence database or any of its `-wal` / `-shm` /
/// `-journal` sidecars, so a carved db can never overwrite the evidence set.
pub fn carved_db_path(db: &Path, out: Option<&Path>) -> Result<PathBuf, String> {
    resolve_output_path(db, out, "carved.db", "carved db")
}

/// Resolve the output path for the **recovered** combined workbook — the
/// reconstructed live + recovered view.
///
/// Resolution mirrors [`carved_db_path`]: the evidence stem with the
/// `.recovered.xlsx` suffix in the CWD by default (`History.db` →
/// `History.recovered.xlsx`), or the explicit `-o` path **verbatim**
/// (`-o /p/foo.xlsx` → `/p/foo.xlsx`, no stripping). The same evidence-set guard
/// applies.
pub fn recovered_xlsx_path(db: &Path, out: Option<&Path>) -> Result<PathBuf, String> {
    resolve_output_path(db, out, "recovered.xlsx", "recovered xlsx")
}

/// Shared output-path resolution + evidence guard for a carve output. With an
/// explicit `out`, that path is used **verbatim** (the caller asked for an exact
/// file). With no `out`, the path is the evidence file's stem with the two-part
/// `suffix` (e.g. `carved.db`, `recovered.xlsx`) appended, as a bare filename so
/// it lands in the CWD; a source with no filename component degrades to the fixed
/// `recovered` stem rather than panicking. Either way the result is refused if it
/// lands on the evidence db or a sidecar (`label` names the output in the
/// diagnostic).
fn resolve_output_path(
    db: &Path,
    out: Option<&Path>,
    suffix: &str,
    label: &str,
) -> Result<PathBuf, String> {
    let resolved = if let Some(path) = out {
        // An explicit `-o` is honored verbatim — the exact file the caller named.
        path.to_path_buf()
    } else {
        // No `-o`: the evidence file's stem with the format suffix, in the CWD.
        let stem = db.file_stem().map_or_else(
            || "recovered".to_string(),
            |s| s.to_string_lossy().into_owned(),
        );
        let mut p = PathBuf::from(stem);
        p.set_extension(suffix);
        p
    };
    if let Some(clash) = evidence_path_clash(db, &resolved) {
        return Err(format!(
            "refusing to write {label} to {} — it is the evidence {}; \
             choose a different --out",
            resolved.display(),
            clash
        ));
    }
    Ok(resolved)
}

/// If `out` names the evidence db or one of its sidecars, return a label for the
/// clashing file; otherwise `None`. Comparison uses canonicalized paths when both
/// exist (so `./a` and `a` match), falling back to a lexical compare.
fn evidence_path_clash(db: &Path, out: &Path) -> Option<&'static str> {
    if same_path(db, out) {
        return Some("database");
    }
    for (suffix, label) in [
        ("-wal", "-wal sidecar"),
        ("-shm", "-shm sidecar"),
        ("-journal", "-journal sidecar"),
    ] {
        let mut name = db.as_os_str().to_owned();
        name.push(suffix);
        if same_path(&PathBuf::from(name), out) {
            return Some(label);
        }
    }
    None
}

/// Whether two paths denote the same file. Prefers `canonicalize` (resolves
/// `.`/`..`/symlinks for existing files); when neither resolves, compares the
/// lexical paths so a guard still fires before any file exists.
fn same_path(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => a == b,
    }
}

/// Project a carved record onto the writer's [`RebuildRow`], preserving native
/// cell types (a recovered BLOB stays a BLOB). A rowid of `0` — unknown/destroyed
/// (e.g. freeblock reconstruction) — maps to `None` so the rebuilt `_rowid` is
/// NULL rather than a fabricated 0.
#[must_use]
pub fn carved_to_rebuild_row(rec: &CarvedRecord) -> RebuildRow {
    RebuildRow {
        page: rec.page,
        offset: rec.offset,
        rowid: (rec.rowid != 0).then_some(rec.rowid),
        source: recovery_source_token(rec.source).to_string(),
        confidence: rec.confidence,
        cells: rec.values.clone(),
    }
}

/// Project a carved [`CarvedFragment`] onto the writer's [`FragmentRow`] for the
/// **separate** `recovered_fragments` table. A fragment carries no rowid (it was
/// clobbered) and only a subset of its columns survived; each surviving
/// `(col_index, value)` carries over verbatim — natively, so a recovered BLOB
/// stays a BLOB — and the writer places it at `c{col_index}`. The two recovery
/// sets stay structurally separate: a fragment is never mapped onto a
/// [`RebuildRow`] / `recovered_records`.
#[must_use]
pub fn fragment_to_rebuild_row(frag: &CarvedFragment) -> FragmentRow {
    FragmentRow {
        page: frag.page,
        offset: frag.offset,
        missing: frag.missing,
        confidence: frag.confidence,
        surviving: frag.surviving.clone(),
    }
}

// ---- table attribution → recovered tables ---------------------------------

/// The fixed provenance columns every recovered table carries before its cells.
const PROVENANCE_COLS: [&str; 6] = [
    "_page",
    "_offset",
    "_rowid",
    "_source",
    "_confidence",
    "_table_instance_risk",
];

/// Group carved records into the attribution-tiered [`RecoveredTable`] set that
/// both the rebuilt db and the xlsx are built from:
///
/// - **Tier 1 (CERTAIN):** one `recovered_<table>` per attributed live table,
///   with that table's **real** column names when the parse is confident AND its
///   column count equals the record's cell count — otherwise generic `c0..cN`
///   (never wrong names). Always prefixed by the provenance columns.
/// - **Tier 2 (INFERRED):** a single `recovered_inferred` with generic `c0..cN`,
///   plus `_table_guess` (TEXT) and `_table_match_ambiguous` (INTEGER 0/1).
/// - **Tier 3 (UNATTRIBUTED):** `recovered_unattributed` with generic `c0..cN`.
///
/// `fragments`, when `Some`, is appended as the existing `recovered_fragments`
/// table (schema unchanged: `_page,_offset,_missing,_confidence,c0..cM`). Empty
/// tiers are omitted; the row order within each table follows `records`.
///
/// `prior_schema` is the sidecar's PRIOR `sqlite_master` (`name -> CREATE SQL`),
/// threaded so the `_table_instance_risk` provenance column also carries Detector
/// B's `sidecar_schema_changed(table)` where a `-wal`/`-journal` captured an
/// unambiguous schema change. Pass an EMPTY map for the no-sidecar path (Detector
/// A only) — see [`sqlite_forensic::table_instance_risks_with_sidecar`].
#[must_use]
pub fn group_attributed_tables(
    db: &Database,
    records: &[CarvedRecord],
    fragments: Option<&[CarvedFragment]>,
    prior_schema: &std::collections::BTreeMap<String, String>,
) -> Vec<RecoveredTable> {
    let attributions = attribute_records(db, records);
    let risks = table_instance_risks_with_sidecar(db, records, &attributions, prior_schema);
    group_into_tables(records, &attributions, &risks, &db.live_tables(), fragments)
}

/// Pure core of [`group_attributed_tables`]: given the records, their parallel
/// attributions, their parallel [`TableInstanceRisk`]s, the live-table schema (for
/// real Tier-1 column names), and the fragments, produce the ordered
/// [`RecoveredTable`] set. No DB access, so it is directly unit-testable.
///
/// Every record-derived recovered table (Tier-1 / Tier-2 / Tier-3) carries the
/// `_table_instance_risk` provenance column; the value is the risk's evidence
/// token, empty (`NULL`) for [`TableInstanceRisk::None`] — which is every record
/// that is not an AUTOINCREMENT `rowid > sqlite_sequence` residue. The flag rides
/// as a column; no record is ever rerouted out of its attribution table.
#[must_use]
pub fn group_into_tables(
    records: &[CarvedRecord],
    attributions: &[Attribution],
    risks: &[TableInstanceRisk],
    live_tables: &[sqlite_core::attribution::LiveTable],
    fragments: Option<&[CarvedFragment]>,
) -> Vec<RecoveredTable> {
    // Each record's risk token (empty for None), looked up by index alongside the
    // record. Sized to `records`; a short `risks` slice degrades to empty tokens.
    let risk_token = |i: usize| -> String {
        risks
            .get(i)
            .map(TableInstanceRisk::token)
            .unwrap_or_default()
    };

    // Tier-1: one bucket per attributed live table, first-seen order preserved.
    // Each bucket entry pairs the record with its risk token.
    let mut known_order: Vec<String> = Vec::new();
    let mut known: std::collections::HashMap<String, Vec<(&CarvedRecord, String)>> =
        std::collections::HashMap::new();
    // Tier-2: parallel records + their (guess, ambiguous); Tier-3: (record, token).
    let mut inferred: Vec<(&CarvedRecord, &str, bool, String)> = Vec::new();
    let mut unattributed: Vec<(&CarvedRecord, String)> = Vec::new();

    for (i, (rec, attr)) in records.iter().zip(attributions).enumerate() {
        let token = risk_token(i);
        match attr {
            Attribution::Known(name) => {
                known.entry(name.clone()).or_insert_with(|| {
                    known_order.push(name.clone());
                    Vec::new()
                });
                if let Some(bucket) = known.get_mut(name) {
                    bucket.push((rec, token));
                }
            }
            Attribution::Inferred { guess, ambiguous } => {
                inferred.push((rec, guess.as_str(), *ambiguous, token));
            }
            Attribution::Unattributed => unattributed.push((rec, token)),
        }
    }

    let mut out: Vec<RecoveredTable> = Vec::new();

    // Tier-1 — CERTAIN: recovered_<table> with real names when confident.
    for table_name in &known_order {
        let Some(recs) = known.get(table_name) else {
            continue; // cov:unreachable: known_order mirrors known's keys
        };
        let max_cells = recs.iter().map(|(r, _)| r.values.len()).max().unwrap_or(0);
        let real_names = live_tables
            .iter()
            .find(|t| &t.name == table_name)
            .and_then(|t| t.column_names.as_ref())
            .filter(|names| names.len() == max_cells)
            .cloned();
        let cell_cols = match &real_names {
            Some(names) => names.clone(),
            None => generic_cell_columns(max_cells),
        };
        let columns = provenance_columns_then(&cell_cols);
        let rows = recs
            .iter()
            .map(|(r, token)| record_row_values(r, token, max_cells))
            .collect();
        out.push(RecoveredTable {
            name: format!("recovered_{table_name}"),
            columns,
            rows,
        });
    }

    // Tier-2 — INFERRED: a single recovered_inferred with guess + ambiguity.
    if !inferred.is_empty() {
        let max_cells = inferred
            .iter()
            .map(|(r, _, _, _)| r.values.len())
            .max()
            .unwrap_or(0);
        let mut columns: Vec<String> = PROVENANCE_COLS.iter().map(|s| (*s).to_string()).collect();
        columns.push("_table_guess".to_string());
        columns.push("_table_match_ambiguous".to_string());
        columns.extend(generic_cell_columns(max_cells));
        let rows = inferred
            .iter()
            .map(|(r, guess, ambiguous, token)| {
                let mut v = provenance_values(r, token);
                v.push(Value::Text((*guess).to_string()));
                v.push(Value::Integer(i64::from(*ambiguous)));
                v.extend(cell_values(r, max_cells));
                v
            })
            .collect();
        out.push(RecoveredTable {
            name: "recovered_inferred".to_string(),
            columns,
            rows,
        });
    }

    // Tier-3 — UNATTRIBUTED: generic recovered_unattributed.
    if !unattributed.is_empty() {
        let max_cells = unattributed
            .iter()
            .map(|(r, _)| r.values.len())
            .max()
            .unwrap_or(0);
        let columns = provenance_columns_then(&generic_cell_columns(max_cells));
        let rows = unattributed
            .iter()
            .map(|(r, token)| record_row_values(r, token, max_cells))
            .collect();
        out.push(RecoveredTable {
            name: "recovered_unattributed".to_string(),
            columns,
            rows,
        });
    }

    // Fragments: the existing recovered_fragments table, schema unchanged.
    if let Some(frags) = fragments {
        out.push(fragments_table(frags));
    }

    out
}

/// `c0..c{n-1}` generic cell column names.
fn generic_cell_columns(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("c{i}")).collect()
}

/// The five provenance columns followed by `cell_cols`.
fn provenance_columns_then(cell_cols: &[String]) -> Vec<String> {
    let mut columns: Vec<String> = PROVENANCE_COLS.iter().map(|s| (*s).to_string()).collect();
    columns.extend_from_slice(cell_cols);
    columns
}

/// The six provenance values for a record: page, offset, rowid (NULL when 0),
/// source token, confidence, and the `table_instance_risk` token (NULL when the
/// risk is [`TableInstanceRisk::None`], i.e. an empty `token`).
fn provenance_values(rec: &CarvedRecord, risk_token: &str) -> Vec<Value> {
    vec![
        Value::Integer(i64::from(rec.page)),
        Value::Integer(rec.offset as i64),
        if rec.rowid == 0 {
            Value::Null
        } else {
            Value::Integer(rec.rowid)
        },
        Value::Text(recovery_source_token(rec.source).to_string()),
        Value::Real(f64::from(rec.confidence)),
        if risk_token.is_empty() {
            Value::Null
        } else {
            Value::Text(risk_token.to_string())
        },
    ]
}

/// A record's `max_cells` cells, padding missing trailing cells with NULL.
fn cell_values(rec: &CarvedRecord, max_cells: usize) -> Vec<Value> {
    (0..max_cells)
        .map(|i| rec.values.get(i).cloned().unwrap_or(Value::Null))
        .collect()
}

/// Full row for a provenance-only table (Tier-1 / Tier-3): provenance + cells.
fn record_row_values(rec: &CarvedRecord, risk_token: &str, max_cells: usize) -> Vec<Value> {
    let mut v = provenance_values(rec, risk_token);
    v.extend(cell_values(rec, max_cells));
    v
}

/// Build the `recovered_fragments` [`RecoveredTable`], schema unchanged:
/// `_page,_offset,_missing,_confidence,c0..c{M}` where each surviving
/// `(idx, value)` lands at `c{idx}` and other cells are NULL.
fn fragments_table(frags: &[CarvedFragment]) -> RecoveredTable {
    let cell_cols = frags
        .iter()
        .flat_map(|f| f.surviving.iter().map(|(idx, _)| *idx))
        .max()
        .map_or(0, |m| m + 1);
    let mut columns = vec![
        "_page".to_string(),
        "_offset".to_string(),
        "_missing".to_string(),
        "_confidence".to_string(),
    ];
    columns.extend(generic_cell_columns(cell_cols));
    let rows = frags
        .iter()
        .map(|f| {
            let mut v = vec![
                Value::Integer(i64::from(f.page)),
                Value::Integer(f.offset as i64),
                Value::Integer(f.missing as i64),
                Value::Real(f64::from(f.confidence)),
            ];
            let mut cells = vec![Value::Null; cell_cols];
            for (idx, value) in &f.surviving {
                if let Some(slot) = cells.get_mut(*idx) {
                    *slot = value.clone();
                }
            }
            v.extend(cells);
            v
        })
        .collect();
    RecoveredTable {
        name: "recovered_fragments".to_string(),
        columns,
        rows,
    }
}

// ---- combined live + recovered merge --------------------------------------

/// Excel's hard cap on rows in a worksheet (`1,048,576`), including the header.
/// A merged sheet exceeding it is truncated and the drop is reported, never
/// silently swallowed.
pub const EXCEL_MAX_ROWS: usize = 1_048_576;

/// One recovered (deleted) row routed to a live table by [`route_recovered`].
/// `rowid` is `None` when the rowid was destroyed. `is_guessed` marks a Tier-2
/// inferred row, `ambiguous` that its shape matched more than one table. (The
/// temporal workbook folds residue via the row-history layer; this type is the
/// carried payload of [`RoutedRecovered::by_table`].)
#[derive(Debug, Clone, PartialEq)]
pub struct RecoveredRow {
    /// Recovered rowid, or `None` when destroyed/unknown.
    pub rowid: Option<i64>,
    /// Recovered cells, aligned to the real columns by position.
    pub cells: Vec<Value>,
    /// `true` for a Tier-2 inferred row (`is_guessed=1`), else `false`.
    pub is_guessed: bool,
    /// `true` when the inferred shape matched more than one table.
    pub ambiguous: bool,
}

/// Align `values` to exactly `width` cells: pad missing trailing cells with NULL,
/// truncate any surplus. The position-aligned mapping to a table's real columns.
fn align_cells(values: &[Value], width: usize) -> Vec<Value> {
    (0..width)
        .map(|i| values.get(i).cloned().unwrap_or(Value::Null))
        .collect()
}

/// The result of routing carved records to their destination: a bucket of
/// [`RecoveredRow`]s per live table (keyed by table name) plus the indices of the
/// records that could not be folded into any live sheet (Tier-3, or an inferred
/// guess whose table has no live sheet) — those go to `recovered_unattributed`.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct RoutedRecovered {
    /// Recovered rows per live table, in record order within each table.
    pub by_table: std::collections::HashMap<String, Vec<RecoveredRow>>,
    /// Indices into `records` of rows routed to `recovered_unattributed`.
    pub unattributed: Vec<usize>,
}

/// Route every carved record to a live-table bucket or to the unattributed set,
/// from its parallel [`Attribution`]. Pure (no DB access): the caller supplies
/// the live-table names so the routing of an inferred guess to a non-existent
/// sheet is decided here.
///
/// - **Tier-1 `Known(T)`** → `T`'s bucket, `is_guessed=false`.
/// - **Tier-2 `Inferred{guess:T, ambiguous}`** → `T`'s bucket with
///   `is_guessed=true` **iff** `T` is a live table; otherwise the record is
///   unattributed (the guessed sheet does not exist).
/// - **Tier-3 `Unattributed`** → unattributed.
///
/// A record's [`RecoveredRow::rowid`] is `Some(rowid)` for a recovered rowid and
/// `None` when destroyed (`0`), so the merge step sinks it to the sheet bottom.
#[must_use]
pub fn route_recovered(
    live_table_names: &[String],
    records: &[CarvedRecord],
    attributions: &[Attribution],
) -> RoutedRecovered {
    let is_live = |name: &str| live_table_names.iter().any(|n| n == name);
    let mut routed = RoutedRecovered::default();
    for (i, (rec, attr)) in records.iter().zip(attributions).enumerate() {
        let (table, is_guessed, ambiguous) = match attr {
            Attribution::Known(name) if is_live(name) => (name.clone(), false, false),
            Attribution::Inferred { guess, ambiguous } if is_live(guess) => {
                (guess.clone(), true, *ambiguous)
            }
            // Tier-3, or a guess/known with no matching live sheet → unattributed.
            _ => {
                routed.unattributed.push(i);
                continue;
            }
        };
        routed
            .by_table
            .entry(table)
            .or_default()
            .push(RecoveredRow {
                rowid: (rec.rowid != 0).then_some(rec.rowid),
                cells: rec.values.clone(),
                is_guessed,
                ambiguous,
            });
    }
    routed
}

// ---- XLSX export: blob classification + human size ------------------------

/// How a recovered BLOB should be presented in the XLSX export.
///
/// Carved bytes are hostile and untyped, so the kind is derived purely from
/// magic bytes — never from a column name or a fixture-specific assumption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlobKind {
    /// A still image (PNG/JPEG/GIF/BMP/WebP/TIFF): embed a thumbnail in-cell.
    Image,
    /// A recognized video container: render a typed `video/<ext> · <size>`
    /// placeholder (first-frame extraction is deferred — no pure-Rust decoder).
    Video {
        /// Lowercase container extension (`mp4`, `mov`, `mkv`, `webm`, `avi`).
        ext: &'static str,
    },
    /// Anything else: the existing `<blob:N bytes>` placeholder.
    Other,
}

/// Classify a recovered BLOB by its leading magic bytes (file signatures), so a
/// binary cell is presented by what it *is*, not by where it came from.
///
/// Images are recognized by [`image::guess_format`] (the same decoder the
/// thumbnailer will use, so a "classified Image" is always one the embedder can
/// at least attempt). Video containers are recognized by their well-known box /
/// header signatures: an ISO-BMFF `ftyp` box (MP4/MOV, sub-typed by its major
/// brand), the Matroska/WebM EBML header, and the RIFF `AVI ` form. Everything
/// else — including too-short blobs — is [`BlobKind::Other`].
#[must_use]
pub fn classify_blob(bytes: &[u8]) -> BlobKind {
    if image::guess_format(bytes).is_ok() {
        return BlobKind::Image;
    }
    if let Some(ext) = video_container_ext(bytes) {
        return BlobKind::Video { ext };
    }
    BlobKind::Other
}

/// Recognize a video container from its magic bytes, returning a lowercase
/// extension, or `None`. Covers the containers the feature names: ISO-BMFF
/// (`ftyp` box at offset 4 → MP4/MOV by major brand), Matroska/WebM (EBML
/// header), and AVI (RIFF `AVI ` form).
fn video_container_ext(bytes: &[u8]) -> Option<&'static str> {
    // Matroska / WebM: EBML header 1A 45 DF A3. WebM is a Matroska profile and
    // shares the header; both map to `mkv` (the generic container extension).
    if bytes.starts_with(&[0x1a, 0x45, 0xdf, 0xa3]) {
        return Some("mkv");
    }
    // RIFF container: `RIFF` ... `AVI ` (the form type at offset 8).
    if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"AVI " {
        return Some("avi");
    }
    // ISO Base Media File Format: a `ftyp` box whose body starts at offset 8 with
    // a 4-char major brand. MOV uses `qt  `; everything else (isom/mp4*/M4V/3gp…)
    // is reported as `mp4`, the dominant ISO-BMFF extension.
    if bytes.len() >= 12 && &bytes[4..8] == b"ftyp" {
        let brand = &bytes[8..12];
        return Some(if brand == b"qt  " { "mov" } else { "mp4" });
    }
    None
}

/// Format a byte count as a short human-readable size (`512 B`, `1.5 KB`,
/// `4.2 MB`) using 1024-based units. Bytes render without a decimal; KB and up
/// render with one decimal place. Used for the video placeholder string.
#[must_use]
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

// ---- XLSX export: thumbnail / transcode -----------------------------------

/// Longest-side bound, in pixels, for an embedded image thumbnail. Keeps the
/// workbook small and the cell legible; not a knob (an internal presentation
/// constant, like the rebuilt-db page size).
pub const THUMB_MAX_PX: u32 = 160;

/// Decode an image BLOB, downscale it to a [`THUMB_MAX_PX`] thumbnail (longest
/// side, aspect preserved, never upscaled), and re-encode it to **PNG** bytes
/// ready for [`rust_xlsxwriter::Image::new_from_buffer`].
///
/// Returns `None` on any failure — undecodable bytes, an unsupported codec, or
/// an encode error — so the caller falls back to the `<blob:N bytes>`
/// placeholder rather than panicking on hostile carved input. Transcoding to PNG
/// is unconditional, so a WebP/TIFF source (which `embed_image` will not accept
/// directly) still embeds.
#[must_use]
pub fn thumbnail_png(bytes: &[u8]) -> Option<Vec<u8>> {
    let img = image::load_from_memory(bytes).ok()?;
    let (w, h) = (img.width(), img.height());
    // Downscale only: a source already within the bound is left untouched
    // (`image::thumbnail` would otherwise enlarge a tiny image to fill).
    let thumb = if w > THUMB_MAX_PX || h > THUMB_MAX_PX {
        img.thumbnail(THUMB_MAX_PX, THUMB_MAX_PX)
    } else {
        img
    };
    let mut out = std::io::Cursor::new(Vec::new());
    thumb.write_to(&mut out, image::ImageFormat::Png).ok()?;
    Some(out.into_inner())
}

// ---- XLSX export: workbook builder ----------------------------------------

use rust_xlsxwriter::{Format, Image, Workbook, Worksheet, XlsxError};

/// Column width (in characters) for a cell that embeds an image thumbnail, and
/// the matching row height (in points), so the ~160 px thumbnail is visible.
const IMAGE_COL_WIDTH: f64 = 24.0;
const IMAGE_ROW_HEIGHT: f64 = 120.0;

/// Excel's hard limit on worksheet-name length (characters).
const MAX_SHEET_NAME: usize = 31;

/// The characters Excel forbids in a worksheet name.
const FORBIDDEN_SHEET_CHARS: [char; 7] = [':', '\\', '/', '?', '*', '[', ']'];

/// Sanitize a recovered-table name into a **valid, unique** Excel worksheet
/// name given the names already `taken` (in assignment order):
///
/// - strip the characters Excel forbids (`: \ / ? * [ ]`);
/// - a blank result becomes `sheet`;
/// - truncate to 31 characters;
/// - de-duplicate against `taken` by appending `_<n>` (n ≥ 1), re-truncating the
///   base so the suffixed name still fits 31 characters.
#[must_use]
pub fn sanitize_sheet_name(name: &str, taken: &[String]) -> String {
    let mut base: String = name
        .chars()
        .filter(|c| !FORBIDDEN_SHEET_CHARS.contains(c))
        .collect();
    if base.trim().is_empty() {
        base = "sheet".to_string();
    }
    let truncate_to = |s: &str, max: usize| -> String { s.chars().take(max).collect() };
    let candidate = truncate_to(&base, MAX_SHEET_NAME);
    if !taken.iter().any(|t| t == &candidate) {
        return candidate;
    }
    // Collision: append `_<n>`, shrinking the base so the whole fits 31 chars.
    let mut n = 1usize;
    loop {
        let suffix = format!("_{n}");
        let room = MAX_SHEET_NAME.saturating_sub(suffix.chars().count());
        let candidate = format!("{}{suffix}", truncate_to(&base, room));
        if !taken.iter().any(|t| t == &candidate) {
            return candidate;
        }
        n += 1;
    }
}

/// Build an `.xlsx` workbook (as in-memory bytes) with **one sheet per recovered
/// table**, mirroring the rebuilt multi-table database. Each sheet's name is the
/// table name run through [`sanitize_sheet_name`] (≤ 31 chars, forbidden
/// characters stripped, de-duplicated). The header row is bold and every data
/// row carries the recovered-row fill; cell values follow their storage class
/// (a `Blob` image is thumbnailed and embedded in-cell, exactly as before).
pub fn build_recovered_tables_xlsx(tables: &[RecoveredTable]) -> Result<Vec<u8>, XlsxError> {
    let header_fmt = Format::new().set_bold();
    let recovered_fmt = Format::new().set_background_color(0x00FF_F2CC);
    let mut workbook = Workbook::new();
    let mut taken: Vec<String> = Vec::new();
    for table in tables {
        let sheet_name = sanitize_sheet_name(&table.name, &taken);
        taken.push(sheet_name.clone());
        let sheet = workbook.add_worksheet().set_name(&sheet_name)?;
        write_table_sheet(sheet, table, &header_fmt, &recovered_fmt)?;
    }
    workbook.save_to_buffer()
}

/// Build the per-table recovered `.xlsx` bytes, mapping any [`XlsxError`] to an
/// actionable string keyed by `path`.
pub fn recovered_tables_xlsx_bytes(
    tables: &[RecoveredTable],
    path: &Path,
) -> Result<Vec<u8>, String> {
    build_recovered_tables_xlsx(tables)
        .map_err(|e| format!("cannot build recovered xlsx {}: {e}", path.display()))
}

/// The pale-red fill marking a **certain** recovered (deleted) row across the
/// combined workbook — a live row is left unfilled so deleted rows read at a glance.
const RECOVERED_FILL: u32 = 0x00FF_E0E0;

/// The pale-yellow fill marking a **guessed** (Tier-2 inferred) recovered row, so
/// an inferred row reads distinct from a certain one at a glance.
const GUESSED_FILL: u32 = 0x00FF_FFCC;

/// The pale-purple fill marking a **rowid-reused** version, so a reader never
/// mistakes two distinct entities sharing one reused rowid for one continuous row.
/// Highest precedence: a reused rowid is the strongest "do not conflate" signal.
const REUSED_FILL: u32 = 0x00E6_CCFF;

/// The pale-blue fill marking a **superseded** historical version
/// ([`ViewState::ValueChangedLater`](sqlite_core::row_history::ViewState::ValueChangedLater)):
/// a prior value of a still-live rowid that a later commit replaced.
const SUPERSEDED_FILL: u32 = 0x00DD_EBFF;

/// The row fill for a combined-workbook version row, by a 5-level PRECEDENCE
/// (highest first):
///
/// 1. `rowid_reused` → pale purple — overrides the rest because the rowid may span
///    DIFFERENT entities (delete+reinsert), never a continuous update.
/// 2. `is_guessed` → pale yellow (Tier-2 inferred attribution).
/// 3. `is_deleted` → pale red (deleted / carved-residue).
/// 4. `superseded` (`ViewState::ValueChangedLater`) → pale blue (a prior value of a
///    still-live rowid that a later commit replaced).
/// 5. otherwise (`PresentInFinalView` / live current) → no fill.
// The four bools are independent EVIDENCE bits forming a fixed precedence ladder,
// not a flag-soup that an enum would clarify — the task mandates this signature so
// every tint outcome is unit-testable directly.
#[allow(clippy::fn_params_excessive_bools)]
fn fill_for(
    rowid_reused: bool,
    is_guessed: bool,
    is_deleted: bool,
    superseded: bool,
) -> Option<u32> {
    if rowid_reused {
        Some(REUSED_FILL)
    } else if is_guessed {
        Some(GUESSED_FILL)
    } else if is_deleted {
        Some(RECOVERED_FILL)
    } else if superseded {
        Some(SUPERSEDED_FILL)
    } else {
        None
    }
}

/// Render a [`ViewState`](sqlite_core::row_history::ViewState) as a stable output
/// token for the `view_state` column.
#[must_use]
pub fn view_state_token(state: sqlite_core::row_history::ViewState) -> &'static str {
    use sqlite_core::row_history::ViewState;
    match state {
        ViewState::PresentInFinalView => "present",
        ViewState::ValueChangedLater => "changed_later",
        ViewState::AbsentInFinalView => "absent_final",
        ViewState::CarvedResidue => "carved_residue",
    }
}

/// Render a [`VersionOrigin`](sqlite_core::row_history::VersionOrigin) as the
/// `wal_commit` column token, resolving a [`Commit`](sqlite_core::row_history::VersionOrigin::Commit)
/// to `commit:(salt1,salt2,frame_index)` from its `lsn` (the salt-qualified
/// log-sequence identity the caller resolved via the timeline).
///
/// `Live` → `live`; `CarvedResidue` → `residue`; a `Commit` whose LSN could not be
/// resolved degrades to `commit:?` rather than panicking — the WAL carries NO
/// wall-clock time, only this logical commit coordinate.
#[must_use]
pub fn wal_commit_token(
    origin: &sqlite_core::row_history::VersionOrigin,
    lsn: Option<sqlite_core::WalLsn>,
) -> String {
    use sqlite_core::row_history::VersionOrigin;
    match origin {
        VersionOrigin::Live => "live".to_string(),
        VersionOrigin::CarvedResidue => "residue".to_string(),
        VersionOrigin::Commit(_) => match lsn {
            Some(l) => format!("commit:({},{},{})", l.salt1, l.salt2, l.frame_index),
            None => "commit:?".to_string(),
        },
    }
}

/// The eight temporal/flag columns appended to every per-table version-history
/// sheet, after the table's real columns, in order: the rowid, the WAL commit
/// label, the logical commit sequence, the evidence-based view state, then the
/// four 0/1 flag columns.
pub const TEMPORAL_FLAG_COLS: [&str; 9] = [
    "_rowid",
    "wal_commit",
    "commit_seq",
    "view_state",
    "is_deleted",
    "is_guessed",
    "rowid_reused",
    "attribution_uncertain",
    "_table_instance_risk",
];

/// The annotation note a `WITHOUT ROWID` table's sheet carries instead of versions:
/// such a table has no rowid to key a history on, so it is not version-tracked.
const WITHOUT_ROWID_NOTE: &str = "WITHOUT ROWID — not version-tracked";

/// One rendered version row of a per-table temporal sheet: the real-column cells
/// followed by the eight temporal/flag cells, plus the four tint inputs the
/// renderer feeds to `fill_for` (so the fill decision is made once, here).
// The four bools are the independent tint inputs of the 5-level precedence, each
// separately consumed by the renderer — not a state machine an enum would clarify.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq)]
pub struct TemporalRow {
    /// Real-column cells followed by the eight temporal/flag cells.
    pub cells: Vec<Value>,
    /// Whether this rowid was reused (delete+reinsert) — pale-purple tint.
    pub rowid_reused: bool,
    /// Whether this version's attribution was inferred/guessed — pale-yellow tint.
    pub is_guessed: bool,
    /// Whether this version is deleted / carved residue — pale-red tint.
    pub is_deleted: bool,
    /// Whether this version was superseded by a later value (`ValueChangedLater`)
    /// — pale-blue tint.
    pub superseded: bool,
}

/// A per-table VERSION-HISTORY sheet: the table name, the header (real columns +
/// [`TEMPORAL_FLAG_COLS`]), and one [`TemporalRow`] per row version.
#[derive(Debug, Clone, PartialEq)]
pub struct TemporalSheet {
    /// Table name (later run through [`sanitize_sheet_name`] for the worksheet).
    pub name: String,
    /// Real columns followed by [`TEMPORAL_FLAG_COLS`].
    pub columns: Vec<String>,
    /// One row per [`RowVersion`](sqlite_core::row_history::RowVersion), capped at
    /// `row_cap`.
    pub rows: Vec<TemporalRow>,
}

/// Build one table's VERSION-HISTORY sheet from its
/// [`TableHistory`](sqlite_core::row_history::TableHistory).
///
/// The header is the table's real `columns` followed by [`TEMPORAL_FLAG_COLS`].
/// Each [`RowVersion`](sqlite_core::row_history::RowVersion) becomes one row: its
/// `values` aligned to the real columns (padded with NULL / truncated), then the
/// temporal cells (`_rowid`, `wal_commit`, `commit_seq`, `view_state`) and the four
/// 0/1 flags. A `Commit` origin's `wal_commit` label is resolved to
/// `commit:(salt1,salt2,frame_index)` via `resolve_lsn` (the timeline lookup the
/// caller supplies); `Live` → `live`, `CarvedResidue` → `residue`.
///
/// A `WITHOUT ROWID` table (no rowid to track) emits a single annotation row
/// noting it is not version-tracked rather than a blank or fabricated body. A sheet
/// exceeding `row_cap` data rows is truncated and the surplus returned so the
/// caller can warn (never a silent drop).
///
/// Pure (no I/O beyond the supplied resolver), so it is directly unit-testable.
#[must_use]
pub fn temporal_sheet(
    history: &sqlite_core::row_history::TableHistory,
    resolve_lsn: impl Fn(&sqlite_core::CommitId) -> Option<sqlite_core::WalLsn>,
    risk_token: impl Fn(i64) -> String,
    row_cap: usize,
) -> (TemporalSheet, usize) {
    use sqlite_core::row_history::VersionOrigin;

    let width = history.columns.len();
    let mut columns: Vec<String> = history.columns.clone();
    columns.extend(TEMPORAL_FLAG_COLS.iter().map(|s| (*s).to_string()));

    // WITHOUT ROWID: no rowid to key a history on → a single annotation row. The
    // note sits in the first cell; the remaining cells are blank.
    if history.without_rowid {
        let mut cells = vec![Value::Text(WITHOUT_ROWID_NOTE.to_string())];
        cells.resize(columns.len(), Value::Null);
        let rows = vec![TemporalRow {
            cells,
            rowid_reused: false,
            is_guessed: false,
            is_deleted: false,
            superseded: false,
        }];
        return (
            TemporalSheet {
                name: history.table.clone(),
                columns,
                rows,
            },
            0,
        );
    }

    let mut rows: Vec<TemporalRow> = Vec::with_capacity(history.versions.len());
    for v in &history.versions {
        let mut cells = align_cells(&v.values, width);
        // _rowid
        cells.push(match v.rowid {
            Some(id) => Value::Integer(id),
            None => Value::Null,
        });
        // wal_commit — resolve a Commit's LSN through the caller's lookup.
        let lsn = match &v.origin {
            VersionOrigin::Commit(id) => resolve_lsn(id),
            _ => None,
        };
        cells.push(Value::Text(wal_commit_token(&v.origin, lsn)));
        // commit_seq — blank when None.
        cells.push(match v.commit_seq {
            Some(seq) => Value::Integer(i64::from(seq)),
            None => Value::Null,
        });
        // view_state
        cells.push(Value::Text(view_state_token(v.view_state).to_string()));
        // the four 0/1 flags
        cells.push(Value::Integer(i64::from(v.is_deleted)));
        cells.push(Value::Integer(i64::from(v.is_guessed)));
        cells.push(Value::Integer(i64::from(v.rowid_reused)));
        cells.push(Value::Integer(i64::from(v.attribution_uncertain)));
        // _table_instance_risk — the Detector-A evidence token for a residue row
        // whose rowid exceeds this AUTOINCREMENT table's high-water mark, else NULL.
        let token = v.rowid.map(&risk_token).unwrap_or_default();
        cells.push(if token.is_empty() {
            Value::Null
        } else {
            Value::Text(token)
        });

        let superseded = v.view_state == sqlite_core::row_history::ViewState::ValueChangedLater;
        rows.push(TemporalRow {
            cells,
            rowid_reused: v.rowid_reused,
            is_guessed: v.is_guessed,
            is_deleted: v.is_deleted,
            superseded,
        });
    }

    let dropped = rows.len().saturating_sub(row_cap);
    rows.truncate(row_cap);

    (
        TemporalSheet {
            name: history.table.clone(),
            columns,
            rows,
        },
        dropped,
    )
}

/// Render the **combined** TEMPORAL workbook to in-memory bytes.
///
/// One sheet per [`TemporalSheet`] (a live user table's per-rowid VERSION HISTORY),
/// followed by the `extra` tables (`recovered_unattributed`, `recovered_fragments`)
/// as separate sheets. Sheet names are sanitized and de-duplicated via
/// [`sanitize_sheet_name`]. The header row is bold; each version row is tinted by
/// the 5-level `fill_for` precedence (reused → purple, guessed → yellow, deleted
/// → red, superseded → blue, present/live → none). Every cell follows its storage
/// class — a `Blob` image (live, historical, OR carved) is thumbnailed and embedded
/// in-cell exactly as the separate recovered tables do.
pub fn render_combined_xlsx(
    sheets: &[TemporalSheet],
    extra: &[RecoveredTable],
) -> Result<Vec<u8>, XlsxError> {
    let header_fmt = Format::new().set_bold();
    let recovered_fmt = Format::new().set_background_color(RECOVERED_FILL);
    let guessed_fmt = Format::new().set_background_color(GUESSED_FILL);
    let reused_fmt = Format::new().set_background_color(REUSED_FILL);
    let superseded_fmt = Format::new().set_background_color(SUPERSEDED_FILL);
    let plain_fmt = Format::new();
    let mut workbook = Workbook::new();
    let mut taken: Vec<String> = Vec::new();

    for sheet in sheets {
        let sheet_name = sanitize_sheet_name(&sheet.name, &taken);
        taken.push(sheet_name.clone());
        let ws = workbook.add_worksheet().set_name(&sheet_name)?;
        write_header(ws, &sheet.columns, &header_fmt)?;
        for (r, trow) in sheet.rows.iter().enumerate() {
            let row = r as u32 + 1;
            // 5-level precedence: purple > yellow > red > blue > none.
            let fmt = match fill_for(
                trow.rowid_reused,
                trow.is_guessed,
                trow.is_deleted,
                trow.superseded,
            ) {
                None => &plain_fmt,
                Some(REUSED_FILL) => &reused_fmt,
                Some(GUESSED_FILL) => &guessed_fmt,
                Some(SUPERSEDED_FILL) => &superseded_fmt,
                Some(_) => &recovered_fmt,
            };
            for (c, value) in trow.cells.iter().enumerate() {
                write_value_cell(ws, row, c as u16, value, fmt)?;
            }
        }
    }

    // The separate Tier-3 / fragment tables: every data row is recovered, so the
    // existing all-rows-tinted rendering applies.
    for table in extra {
        let sheet_name = sanitize_sheet_name(&table.name, &taken);
        taken.push(sheet_name.clone());
        let ws = workbook.add_worksheet().set_name(&sheet_name)?;
        write_table_sheet(ws, table, &header_fmt, &recovered_fmt)?;
    }

    workbook.save_to_buffer()
}

/// A planned combined TEMPORAL workbook: the per-table version-history `sheets`,
/// the separate `extra` tables (`recovered_unattributed`, `recovered_fragments`
/// — only the residue NOT folded into a table history), and the `dropped`
/// `(table, count)` pairs for any sheet truncated to the Excel row cap.
#[derive(Debug, Clone, PartialEq)]
pub struct CombinedWorkbook {
    /// One version-history sheet per live user table, in `row_histories` order.
    pub sheets: Vec<TemporalSheet>,
    /// The separate Tier-3 / fragment tables (each a whole-recovered sheet).
    pub extra: Vec<RecoveredTable>,
    /// `(table, dropped_row_count)` for each sheet truncated to `row_cap`.
    pub dropped: Vec<(String, usize)>,
}

/// Project a [`JournalRecovery`] into stand-alone [`CarvedRecord`]s for the stdout
/// text surfaces (table / CSV / JSONL), each tagged
/// [`RecoverySource::RollbackJournal`] so [`recovery_source_token`] reads
/// `rollback-journal` and [`snapshot_label`] resolves its `(segment, pgno)`
/// provenance.
///
/// Both classes surface as recovered content: a **deleted** prior row carries its
/// full prior `values`; a **modified** row carries its PRIOR (pre-edit)
/// `prior_values` — the edit history the live row replaced. The journal restores
/// whole pages, so the per-record `offset` within the prior page is not tracked at
/// the API boundary and is reported as `0`; `page` is the restored page number.
#[must_use]
pub fn journal_carved_records(recovery: &JournalRecovery) -> Vec<CarvedRecord> {
    let source_of = |source: &RecoverySource| -> RecoverySource {
        // The prior image's journal provenance is carried on the source variant.
        match source {
            RecoverySource::RollbackJournal(s) => RecoverySource::RollbackJournal(*s),
            // cov:unreachable: carve_rollback_journal only ever tags rows RollbackJournal
            other => *other,
        }
    };
    let page_of = |source: &RecoverySource| -> u32 {
        match source {
            RecoverySource::RollbackJournal(s) => s.pgno,
            _ => 0, // cov:unreachable: see source_of
        }
    };
    let mut out = Vec::with_capacity(recovery.deleted.len() + recovery.modified.len());
    for row in &recovery.deleted {
        out.push(CarvedRecord {
            page: page_of(&row.source),
            offset: 0,
            rowid: row.rowid,
            values: row.values.clone(),
            confidence: 1.0,
            allocated: false,
            source: source_of(&row.source),
            wal: None,
            overflow: None,
        });
    }
    for rec in &recovery.modified {
        out.push(CarvedRecord {
            page: page_of(&rec.source),
            offset: 0,
            rowid: rec.rowid,
            values: rec.prior_values.clone(),
            confidence: 1.0,
            allocated: false,
            source: source_of(&rec.source),
            wal: None,
            overflow: None,
        });
    }
    out
}

/// Fold a [`JournalRecovery`] into the per-table version histories, in place.
///
/// The rollback `-journal` captures exactly the prior state, so each recovered
/// row slots as the immediately-preceding version of its KNOWN table+rowid (the
/// journal carries the prior schema, so attribution is CERTAIN — Tier-1,
/// `is_guessed=false`):
///
/// - a **deleted** [`PriorRow`](sqlite_forensic::PriorRow) → an `is_deleted`
///   `CarvedResidue` version (red), the full-fidelity copy of the row the last
///   transaction removed;
/// - a **modified** [`PriorVersionRecord`](sqlite_forensic::PriorVersionRecord) →
///   the PRIOR value as a `ValueChangedLater` superseded version (blue), while the
///   live current row stays present (we do not touch it).
///
/// A recovered version byte-identical to one already in the history (same rowid +
/// values + deletion state) is skipped — the same de-dup the residue fold uses, so
/// a journal copy never double-lists a row already carried at equal fidelity. A
/// recovered row whose table has no live history sheet is dropped here (no
/// fabricated home), exactly as the residue fold drops `Unattributed` records.
/// Each touched history is re-sorted into the canonical version order.
fn fold_journal_into_histories(
    histories: &mut [sqlite_core::row_history::TableHistory],
    recovery: &JournalRecovery,
) {
    use sqlite_core::row_history::{sort_table_versions, RowVersion, VersionOrigin, ViewState};

    // A (rowid, is_deleted, values) identity, so a journal version identical to one
    // already present is not double-listed (the residue fold's de-dup key shape).
    fn version_key(rowid: Option<i64>, is_deleted: bool, values: &[Value]) -> String {
        format!("{rowid:?}:{is_deleted}:{values:?}")
    }

    // Map each live table name to its history index, once.
    let index: std::collections::HashMap<&str, usize> = histories
        .iter()
        .enumerate()
        .map(|(i, h)| (h.table.as_str(), i))
        .collect();

    // The candidate new versions, grouped by target history index. A recovered row
    // whose table has no live history is dropped here (no fabricated home).
    let mut to_add: std::collections::BTreeMap<usize, Vec<RowVersion>> =
        std::collections::BTreeMap::new();

    // Deleted prior rows → is_deleted CarvedResidue versions (red), full fidelity.
    for row in &recovery.deleted {
        if let Some(&i) = index.get(row.table.as_str()) {
            to_add.entry(i).or_default().push(RowVersion {
                rowid: Some(row.rowid),
                values: row.values.clone(),
                origin: VersionOrigin::CarvedResidue,
                commit_seq: None,
                view_state: ViewState::CarvedResidue,
                is_deleted: true,
                // The journal carries the prior schema, so attribution is CERTAIN.
                is_guessed: false,
                rowid_reused: false,
                attribution_uncertain: false,
            });
        }
    }

    // Modified rows → the PRIOR value as a ValueChangedLater superseded version
    // (blue); the live current row is left untouched (it stays present/current).
    for rec in &recovery.modified {
        if let Some(&i) = index.get(rec.table.as_str()) {
            to_add.entry(i).or_default().push(RowVersion {
                rowid: Some(rec.rowid),
                values: rec.prior_values.clone(),
                origin: VersionOrigin::CarvedResidue,
                commit_seq: None,
                view_state: ViewState::ValueChangedLater,
                is_deleted: false,
                is_guessed: false,
                rowid_reused: false,
                attribution_uncertain: false,
            });
        }
    }

    for (i, extra) in to_add {
        let Some(history) = histories.get_mut(i) else {
            continue; // cov:unreachable: `i` is an index built from `histories` above
        };
        let mut seen: std::collections::HashSet<String> = history
            .versions
            .iter()
            .map(|v| version_key(v.rowid, v.is_deleted, &v.values))
            .collect();
        for v in extra {
            if seen.insert(version_key(v.rowid, v.is_deleted, &v.values)) {
                history.versions.push(v);
            }
        }
        sort_table_versions(&mut history.versions);
    }
}

/// Plan the combined TEMPORAL workbook from the open evidence database, the carved
/// records (for the unattributed extra split), and the optional fragments.
///
/// Each live user table becomes one VERSION-HISTORY sheet from
/// [`sqlite_forensic::row_histories_with_residue`], which already folds ATTRIBUTED
/// carved residue into its table's history. The separate `extra` tables therefore
/// carry ONLY what is NOT in a table history: Tier-3 `recovered_unattributed`
/// residue (attributed to no live table) and the `recovered_fragments`. The
/// unattributed split is computed by [`route_recovered`] (the same attribution the
/// histories use), so an attributed deleted row appears EXACTLY once — in its
/// table's sheet as a `carved_residue` / `absent_final` version — never twice. A
/// `Commit` version's `wal_commit` label is resolved through the WAL timeline. A
/// sheet exceeding `row_cap` is truncated and the drop recorded in `dropped`.
///
/// `journal` is the optional rollback-`-journal` recovery (mutually exclusive with
/// a WAL — the caller passes `None` under a WAL): its deleted prior rows fold in as
/// red `is_deleted` versions and its modified rows' prior values as blue superseded
/// versions, under their KNOWN table+rowid, via `fold_journal_into_histories`.
///
/// `prior_schema` is the sidecar's PRIOR `sqlite_master` (`name -> CREATE SQL`), so
/// a residue version in a schema-changed table's sheet carries Detector B's
/// `sidecar_schema_changed(table)` token in its `_table_instance_risk` column.
/// Pass an EMPTY map for the no-sidecar path (Detector A only).
#[must_use]
pub fn plan_combined_workbook(
    db: &Database,
    records: &[CarvedRecord],
    fragments: Option<&[CarvedFragment]>,
    journal: Option<&JournalRecovery>,
    prior_schema: &std::collections::BTreeMap<String, String>,
    row_cap: usize,
) -> CombinedWorkbook {
    // The per-table version histories (live + WAL-historical + attributed residue).
    let mut histories = sqlite_forensic::row_histories_with_residue(db);

    // Fold the rollback-journal recovery (when present) into the histories: deleted
    // prior rows → red is_deleted versions, modified rows → blue superseded prior
    // versions, both under their KNOWN table+rowid (Tier-1 certain).
    if let Some(recovery) = journal {
        fold_journal_into_histories(&mut histories, recovery);
    }

    // Resolve a Commit's salt-qualified LSN through the WAL timeline so a commit
    // version renders `commit:(salt1,salt2,frame_index)`. No timeline → no salts.
    let timeline = db.wal_timeline();
    let resolve_lsn = |id: &sqlite_core::CommitId| -> Option<sqlite_core::WalLsn> {
        timeline
            .as_ref()?
            .snapshot_at(*id)
            .map(sqlite_core::CommitSnapshot::lsn)
    };

    // The instance-risk per carved record, keyed by (table, rowid) so a residue
    // version folded into a table's history carries its evidence token in the
    // `_table_instance_risk` column. Detector A (AUTOINCREMENT `rowid > seq`) AND
    // Detector B (sidecar schema change) both populate the map; a record with no
    // risk is absent (→ NULL column).
    let attributions = attribute_records(db, records);
    let risks = table_instance_risks_with_sidecar(db, records, &attributions, prior_schema);
    let mut risk_by_table_rowid: std::collections::BTreeMap<(String, i64), String> =
        std::collections::BTreeMap::new();
    for ((rec, risk), attr) in records.iter().zip(&risks).zip(&attributions) {
        let table = match risk {
            TableInstanceRisk::RowidExceedsAutoincHighwater { table, .. }
            | TableInstanceRisk::SidecarSchemaChanged { table } => Some(table.clone()),
            // TableInstanceRisk::None and any future #[non_exhaustive] variant carry
            // no table key here → no token in the risk map (NULL column).
            _ => None,
        };
        // A Known attribution guarantees the residue rides on a real table sheet;
        // the (table, rowid) key matches how the history lookup later reads it.
        if let (Some(table), Attribution::Known(_)) = (table, attr) {
            risk_by_table_rowid.insert((table, rec.rowid), risk.token());
        }
    }

    let mut sheets = Vec::with_capacity(histories.len());
    let mut dropped = Vec::new();
    for h in &histories {
        let table = h.table.clone();
        let risk_token = |rowid: i64| -> String {
            risk_by_table_rowid
                .get(&(table.clone(), rowid))
                .cloned()
                .unwrap_or_default()
        };
        let (sheet, n) = temporal_sheet(h, resolve_lsn, risk_token, row_cap);
        if n > 0 {
            dropped.push((h.table.clone(), n));
        }
        sheets.push(sheet);
    }

    // The separate extra tables carry ONLY the residue NOT folded into a table
    // history: the Tier-3 unattributed records (+ any inferred guess to a
    // non-existent table) and the fragments. route_recovered's `unattributed`
    // bucket is exactly that set, so the attributed residue (already in its table's
    // version history) is never double-listed.
    let live_names: Vec<String> = histories.iter().map(|h| h.table.clone()).collect();
    let routed = route_recovered(&live_names, records, &attributions);
    let unattr_records: Vec<CarvedRecord> = routed
        .unattributed
        .iter()
        .map(|&i| records[i].clone())
        .collect();
    let unattr_attrs = vec![Attribution::Unattributed; unattr_records.len()];
    // Unattributed residue is never Known+AUTOINCREMENT, so its risk is always
    // None; an empty risks slice degrades each token to empty (NULL column).
    let extra = group_into_tables(&unattr_records, &unattr_attrs, &[], &[], fragments);

    CombinedWorkbook {
        sheets,
        extra,
        dropped,
    }
}

/// The stderr warning for a sheet truncated to the Excel row cap, naming the
/// table and the dropped row count so a truncation is never silent. Pure so the
/// message is unit-testable without provoking a million-row carve.
#[must_use]
pub fn row_cap_warning(table: &str, dropped: usize, cap: usize) -> String {
    format!(
        "warning: table {table} exceeds Excel's {cap}-row limit; \
         dropped {dropped} row(s) from the {table} sheet"
    )
}

/// Build the combined live + recovered `.xlsx` bytes, warning on stderr for any
/// sheet truncated to `row_cap`, and mapping any [`XlsxError`] to an actionable
/// string keyed by `path`.
///
/// This is the String-returning façade the binary shell calls (with `row_cap` =
/// [`EXCEL_MAX_ROWS`]): it plans the workbook ([`plan_combined_workbook`]), emits
/// one [`row_cap_warning`] per dropped-row warning so a truncation is never
/// silent, and renders the bytes via [`render_combined_xlsx`]. `row_cap` is a
/// parameter so a unit test can drive the truncation-warning path at a small cap.
pub fn combined_xlsx_bytes(
    db: &Database,
    records: &[CarvedRecord],
    fragments: Option<&[CarvedFragment]>,
    journal: Option<&JournalRecovery>,
    prior_schema: &std::collections::BTreeMap<String, String>,
    path: &Path,
    row_cap: usize,
) -> Result<Vec<u8>, String> {
    let plan = plan_combined_workbook(db, records, fragments, journal, prior_schema, row_cap);
    for (table, count) in &plan.dropped {
        eprintln!("{}", row_cap_warning(table, *count, row_cap));
    }
    render_combined_xlsx(&plan.sheets, &plan.extra)
        .map_err(|e| format!("cannot build recovered xlsx {}: {e}", path.display()))
}

/// Write one [`RecoveredTable`] to a worksheet: bold header from `columns`, then
/// one recovered-marked row per row, each cell by storage class.
fn write_table_sheet(
    sheet: &mut Worksheet,
    table: &RecoveredTable,
    header_fmt: &Format,
    recovered_fmt: &Format,
) -> Result<(), XlsxError> {
    write_header(sheet, &table.columns, header_fmt)?;
    for (r, values) in table.rows.iter().enumerate() {
        let row = r as u32 + 1;
        for (c, value) in values.iter().enumerate() {
            write_value_cell(sheet, row, c as u16, value, recovered_fmt)?;
        }
    }
    Ok(())
}

/// Build an `.xlsx` workbook (as in-memory bytes) mirroring the rebuilt database:
/// a `recovered_records` sheet always, and a `recovered_fragments` sheet when
/// `fragments` is `Some`. Returns the bytes so `main` is a humble shell that only
/// writes them to a file.
///
/// Every data row is a recovered/deleted row, so it is **marked as recovered**
/// with a distinct light fill; the header row is bold. Cell values follow their
/// storage class: `Null`→empty, `Integer`/`Real`→numeric, `Text`→string. A
/// `Blob` is classified by [`classify_blob`] — an image is thumbnailed and
/// **embedded in-cell**, a video shows a typed `video/<ext> · <size>`
/// placeholder, and anything else (or an image that fails to decode) shows the
/// `<blob:N bytes>` placeholder. Image decoding never panics; it falls back to
/// the placeholder.
pub fn build_recovered_xlsx(
    records: &[RebuildRow],
    fragments: Option<&[FragmentRow]>,
) -> Result<Vec<u8>, XlsxError> {
    let header_fmt = Format::new().set_bold();
    // A light fill marks every data row as recovered — unmistakable that these
    // are carved/deleted rows, not live data.
    let recovered_fmt = Format::new().set_background_color(0x00FF_F2CC);

    let mut workbook = Workbook::new();

    let max_cells = records.iter().map(|r| r.cells.len()).max().unwrap_or(0);
    let rec_sheet = workbook.add_worksheet().set_name("recovered_records")?;
    write_records_sheet(rec_sheet, records, max_cells, &header_fmt, &recovered_fmt)?;

    if let Some(frags) = fragments {
        let cell_cols = frags
            .iter()
            .flat_map(|f| f.surviving.iter().map(|(idx, _)| *idx))
            .max()
            .map_or(0, |m| m + 1);
        let frag_sheet = workbook.add_worksheet().set_name("recovered_fragments")?;
        write_fragments_sheet(frag_sheet, frags, cell_cols, &header_fmt, &recovered_fmt)?;
    }

    workbook.save_to_buffer()
}

/// Build the recovered `.xlsx` bytes, mapping any [`XlsxError`] to an actionable
/// string keyed by `path` (the file the bytes are destined for). This is the
/// String-returning façade the binary shell calls, so `main` carries no inline
/// xlsx error-formatting closure.
pub fn recovered_xlsx_bytes(
    records: &[RebuildRow],
    fragments: Option<&[FragmentRow]>,
    path: &Path,
) -> Result<Vec<u8>, String> {
    build_recovered_xlsx(records, fragments)
        .map_err(|e| format!("cannot build recovered xlsx {}: {e}", path.display()))
}

/// Write the `recovered_records` sheet: bold header
/// `_page,_offset,_rowid,_source,_confidence,c0..c{max_cells-1}`, then one
/// recovered-marked row per record.
fn write_records_sheet(
    sheet: &mut Worksheet,
    records: &[RebuildRow],
    max_cells: usize,
    header_fmt: &Format,
    recovered_fmt: &Format,
) -> Result<(), XlsxError> {
    let mut header = vec![
        "_page".to_string(),
        "_offset".to_string(),
        "_rowid".to_string(),
        "_source".to_string(),
        "_confidence".to_string(),
    ];
    for i in 0..max_cells {
        header.push(format!("c{i}"));
    }
    write_header(sheet, &header, header_fmt)?;

    for (r, rec) in records.iter().enumerate() {
        let row = r as u32 + 1;
        write_number(sheet, row, 0, f64::from(rec.page), recovered_fmt)?;
        write_number(sheet, row, 1, rec.offset as f64, recovered_fmt)?;
        match rec.rowid {
            Some(id) => write_number(sheet, row, 2, id as f64, recovered_fmt)?,
            None => {
                sheet.write_blank(row, 2, recovered_fmt)?;
            }
        }
        sheet.write_string_with_format(row, 3, &rec.source, recovered_fmt)?;
        write_number(sheet, row, 4, f64::from(rec.confidence), recovered_fmt)?;
        for (c, value) in rec.cells.iter().enumerate() {
            write_value_cell(sheet, row, 5 + c as u16, value, recovered_fmt)?;
        }
    }
    Ok(())
}

/// Write the `recovered_fragments` sheet: bold header
/// `_page,_offset,_missing,_confidence,c0..c{cell_cols-1}`, then one
/// recovered-marked row per fragment (each surviving cell placed at `c{idx}`).
fn write_fragments_sheet(
    sheet: &mut Worksheet,
    frags: &[FragmentRow],
    cell_cols: usize,
    header_fmt: &Format,
    recovered_fmt: &Format,
) -> Result<(), XlsxError> {
    let mut header = vec![
        "_page".to_string(),
        "_offset".to_string(),
        "_missing".to_string(),
        "_confidence".to_string(),
    ];
    for i in 0..cell_cols {
        header.push(format!("c{i}"));
    }
    write_header(sheet, &header, header_fmt)?;

    for (r, frag) in frags.iter().enumerate() {
        let row = r as u32 + 1;
        write_number(sheet, row, 0, f64::from(frag.page), recovered_fmt)?;
        write_number(sheet, row, 1, frag.offset as f64, recovered_fmt)?;
        write_number(sheet, row, 2, frag.missing as f64, recovered_fmt)?;
        write_number(sheet, row, 3, f64::from(frag.confidence), recovered_fmt)?;
        // Columns not in `surviving` stay blank (NULL) but still recovered-marked.
        for c in 0..cell_cols {
            sheet.write_blank(row, 4 + c as u16, recovered_fmt)?;
        }
        for (idx, value) in &frag.surviving {
            write_value_cell(sheet, row, 4 + *idx as u16, value, recovered_fmt)?;
        }
    }
    Ok(())
}

/// Write a bold header row at row 0.
fn write_header(sheet: &mut Worksheet, header: &[String], fmt: &Format) -> Result<(), XlsxError> {
    for (c, title) in header.iter().enumerate() {
        sheet.write_string_with_format(0, c as u16, title, fmt)?;
    }
    Ok(())
}

/// Write a numeric cell carrying the recovered-row fill.
fn write_number(
    sheet: &mut Worksheet,
    row: u32,
    col: u16,
    value: f64,
    fmt: &Format,
) -> Result<(), XlsxError> {
    sheet.write_number_with_format(row, col, value, fmt)?;
    Ok(())
}

/// Render one decoded [`Value`] into a worksheet cell, all recovered-marked.
///
/// `Null`→blank, `Integer`/`Real`→numeric, `Text`→string. A `Blob` is presented
/// by [`classify_blob`]: an image thumbnail embedded in-cell (with the column
/// widened / row heightened), a typed `video/<ext> · <size>` placeholder, or the
/// `<blob:N bytes>` placeholder for anything else / a failed decode.
fn write_value_cell(
    sheet: &mut Worksheet,
    row: u32,
    col: u16,
    value: &Value,
    fmt: &Format,
) -> Result<(), XlsxError> {
    match value {
        Value::Null => {
            sheet.write_blank(row, col, fmt)?;
        }
        Value::Integer(i) => {
            sheet.write_number_with_format(row, col, *i as f64, fmt)?;
        }
        Value::Real(r) => {
            sheet.write_number_with_format(row, col, *r, fmt)?;
        }
        Value::Text(t) => {
            sheet.write_string_with_format(row, col, t, fmt)?;
        }
        Value::Blob(b) => write_blob_cell(sheet, row, col, b, fmt)?,
    }
    Ok(())
}

/// Present a recovered BLOB cell by its classified kind (see [`write_value_cell`]).
fn write_blob_cell(
    sheet: &mut Worksheet,
    row: u32,
    col: u16,
    bytes: &[u8],
    fmt: &Format,
) -> Result<(), XlsxError> {
    match classify_blob(bytes) {
        BlobKind::Image => {
            // Thumbnail + transcode to PNG, then embed in-cell. A decode failure
            // (hostile carved bytes) falls back to the byte placeholder.
            if let Some(png) = thumbnail_png(bytes) {
                let image = Image::new_from_buffer(&png)?;
                sheet.set_column_width(col, IMAGE_COL_WIDTH)?;
                sheet.set_row_height(row, IMAGE_ROW_HEIGHT)?;
                sheet.embed_image_with_format(row, col, &image, fmt)?;
            } else {
                sheet.write_string_with_format(row, col, blob_placeholder(bytes), fmt)?;
            }
        }
        BlobKind::Video { ext } => {
            let label = format!("video/{ext} · {}", human_size(bytes.len() as u64));
            sheet.write_string_with_format(row, col, &label, fmt)?;
        }
        BlobKind::Other => {
            sheet.write_string_with_format(row, col, blob_placeholder(bytes), fmt)?;
        }
    }
    Ok(())
}

/// The `<blob:N bytes>` placeholder string (shared with the stdout `value_to_cell`
/// contract).
fn blob_placeholder(bytes: &[u8]) -> String {
    format!("<blob:{} bytes>", bytes.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlite_forensic::AnomalyKind;

    fn rec(
        rowid: i64,
        confidence: f32,
        source: RecoverySource,
        values: Vec<Value>,
    ) -> CarvedRecord {
        CarvedRecord {
            page: 3,
            offset: 128,
            rowid,
            values,
            confidence,
            allocated: false,
            source,
            wal: None,
            overflow: None,
        }
    }

    use sqlite_forensic::{
        JournalCounts, JournalHeaderState, JournalRecovery, PriorRow, PriorVersionRecord,
        RollbackJournalSource,
    };

    /// A rollback-journal provenance with a Tier-A intact, checksum-valid image.
    fn rollback_src(segment: usize, pgno: u32) -> RollbackJournalSource {
        RollbackJournalSource {
            segment,
            pgno,
            header_state: JournalHeaderState::Valid,
            checksum_valid: Some(true),
        }
    }

    /// A carved record sourced from a rollback-journal prior image.
    fn journal_rec(rowid: i64, segment: usize, pgno: u32, values: Vec<Value>) -> CarvedRecord {
        rec(
            rowid,
            1.0,
            RecoverySource::RollbackJournal(rollback_src(segment, pgno)),
            values,
        )
    }

    use sqlite_core::attribution::{Affinity, LiveTable};

    fn live(name: &str, cols: &[&str], affs: Vec<Affinity>) -> LiveTable {
        LiveTable {
            name: name.to_string(),
            rootpage: 2,
            column_names: Some(cols.iter().map(|s| (*s).to_string()).collect()),
            affinities: affs,
            create_sql: String::new(),
        }
    }

    fn cols_of<'a>(tables: &'a [RecoveredTable], name: &str) -> &'a [String] {
        let t = tables.iter().find(|t| t.name == name);
        assert!(t.is_some(), "missing table {name}");
        &t.unwrap().columns
    }

    #[test]
    fn tier1_known_uses_real_column_names_when_arity_matches() {
        let people = live(
            "people",
            &["id", "name"],
            vec![Affinity::Integer, Affinity::Text],
        );
        let records = vec![rec(
            5,
            0.7,
            RecoverySource::InPageFreeBlock,
            vec![Value::Integer(1), Value::Text("a".into())],
        )];
        let attrs = vec![Attribution::Known("people".to_string())];
        let tables = group_into_tables(&records, &attrs, &[], std::slice::from_ref(&people), None);
        assert_eq!(
            cols_of(&tables, "recovered_people"),
            [
                "_page",
                "_offset",
                "_rowid",
                "_source",
                "_confidence",
                "_table_instance_risk",
                "id",
                "name"
            ]
            .map(String::from)
        );
    }

    #[test]
    fn tier1_known_falls_back_to_generic_when_arity_mismatches() {
        // The record has 3 cells but the table declares 2 columns → never emit
        // wrong names; fall back to c0..c2 while keeping the real table name.
        let people = live(
            "people",
            &["id", "name"],
            vec![Affinity::Integer, Affinity::Text],
        );
        let records = vec![rec(
            5,
            0.7,
            RecoverySource::InPageFreeBlock,
            vec![
                Value::Integer(1),
                Value::Text("a".into()),
                Value::Integer(9),
            ],
        )];
        let attrs = vec![Attribution::Known("people".to_string())];
        let tables = group_into_tables(&records, &attrs, &[], std::slice::from_ref(&people), None);
        assert_eq!(
            cols_of(&tables, "recovered_people"),
            [
                "_page",
                "_offset",
                "_rowid",
                "_source",
                "_confidence",
                "_table_instance_risk",
                "c0",
                "c1",
                "c2"
            ]
            .map(String::from)
        );
    }

    #[test]
    fn tier2_inferred_has_guess_and_ambiguity_columns() {
        let records = vec![
            rec(
                0,
                0.9,
                RecoverySource::FreelistPage,
                vec![Value::Integer(1)],
            ),
            rec(
                0,
                0.9,
                RecoverySource::FreelistPage,
                vec![Value::Integer(2)],
            ),
        ];
        let attrs = vec![
            Attribution::Inferred {
                guess: "people".to_string(),
                ambiguous: false,
            },
            Attribution::Inferred {
                guess: "notes".to_string(),
                ambiguous: true,
            },
        ];
        let tables = group_into_tables(&records, &attrs, &[], &[], None);
        assert_eq!(
            cols_of(&tables, "recovered_inferred"),
            [
                "_page",
                "_offset",
                "_rowid",
                "_source",
                "_confidence",
                "_table_instance_risk",
                "_table_guess",
                "_table_match_ambiguous",
                "c0"
            ]
            .map(String::from)
        );
        let inferred = tables
            .iter()
            .find(|t| t.name == "recovered_inferred")
            .unwrap();
        assert_eq!(inferred.rows.len(), 2);
        // Row 0: guess "people", ambiguous 0 (after the six provenance columns).
        assert_eq!(inferred.rows[0][6], Value::Text("people".into()));
        assert_eq!(inferred.rows[0][7], Value::Integer(0));
        // Row 1: guess "notes", ambiguous 1.
        assert_eq!(inferred.rows[1][6], Value::Text("notes".into()));
        assert_eq!(inferred.rows[1][7], Value::Integer(1));
    }

    #[test]
    fn tier3_unattributed_is_generic() {
        let records = vec![rec(
            7,
            0.5,
            RecoverySource::DroppedTable,
            vec![Value::Integer(1), Value::Integer(2)],
        )];
        let attrs = vec![Attribution::Unattributed];
        let tables = group_into_tables(&records, &attrs, &[], &[], None);
        assert_eq!(
            cols_of(&tables, "recovered_unattributed"),
            [
                "_page",
                "_offset",
                "_rowid",
                "_source",
                "_confidence",
                "_table_instance_risk",
                "c0",
                "c1"
            ]
            .map(String::from)
        );
    }

    #[test]
    fn empty_tiers_are_omitted_and_fragments_appended() {
        let records = vec![rec(
            0,
            0.9,
            RecoverySource::FreelistPage,
            vec![Value::Integer(1)],
        )];
        let attrs = vec![Attribution::Inferred {
            guess: "people".to_string(),
            ambiguous: false,
        }];
        let frags = vec![CarvedFragment {
            page: 2,
            offset: 3965,
            surviving: vec![(0, Value::Integer(20004))],
            missing: 1,
            confidence: 0.2,
            source: RecoverySource::FreeblockReconstructed,
            wal: None,
        }];
        let tables = group_into_tables(&records, &attrs, &[], &[], Some(&frags));
        let names: Vec<&str> = tables.iter().map(|t| t.name.as_str()).collect();
        // Only the inferred tier + fragments — no empty recovered_unattributed.
        assert!(names.contains(&"recovered_inferred"));
        assert!(names.contains(&"recovered_fragments"));
        assert!(!names.contains(&"recovered_unattributed"));
        assert_eq!(
            cols_of(&tables, "recovered_fragments"),
            ["_page", "_offset", "_missing", "_confidence", "c0"].map(String::from)
        );
    }

    #[test]
    fn sheet_name_strips_forbidden_chars() {
        assert_eq!(
            sanitize_sheet_name(r"recovered_a:b/c\d?e*f[g]h", &[]),
            "recovered_abcdefgh"
        );
    }

    #[test]
    fn sheet_name_truncates_to_31_chars() {
        let long = "recovered_a_very_long_table_name_exceeding_limit";
        let s = sanitize_sheet_name(long, &[]);
        assert!(s.chars().count() <= 31, "got {} chars", s.chars().count());
        assert_eq!(s, &long[..31]);
    }

    #[test]
    fn sheet_name_blank_becomes_sheet() {
        assert_eq!(sanitize_sheet_name("[]:", &[]), "sheet");
    }

    #[test]
    fn sheet_name_deduplicates() {
        let taken = vec!["recovered_t".to_string()];
        assert_eq!(sanitize_sheet_name("recovered_t", &taken), "recovered_t_1");
        let taken2 = vec!["recovered_t".to_string(), "recovered_t_1".to_string()];
        assert_eq!(sanitize_sheet_name("recovered_t", &taken2), "recovered_t_2");
    }

    #[test]
    fn sheet_name_dedup_retruncates_to_fit_suffix() {
        // A 31-char name that collides must shrink to fit "_1" within 31.
        let base = "recovered_xxxxxxxxxxxxxxxxxxxxx"; // 31 chars
        assert_eq!(base.chars().count(), 31);
        let taken = vec![base.to_string()];
        let s = sanitize_sheet_name(base, &taken);
        assert!(s.chars().count() <= 31);
        assert!(s.ends_with("_1"));
    }

    #[test]
    fn min_confidence_thresholds_are_monotonic() {
        assert!(MinConfidence::Info.threshold() < MinConfidence::Low.threshold());
        assert!(MinConfidence::Low.threshold() < MinConfidence::Medium.threshold());
        assert!(MinConfidence::Medium.threshold() < MinConfidence::High.threshold());
        assert!(MinConfidence::High.threshold() < MinConfidence::Critical.threshold());
        assert!(MinConfidence::Info.threshold() <= f32::EPSILON);
    }

    #[test]
    fn recovery_source_tokens_are_stable() {
        assert_eq!(
            recovery_source_token(RecoverySource::FreelistPage),
            "freelist-page"
        );
        assert_eq!(
            recovery_source_token(RecoverySource::FreeblockReconstructed),
            "freeblock-reconstructed"
        );
        assert_eq!(
            recovery_source_token(RecoverySource::PriorVersion),
            "prior-version"
        );
        assert_eq!(
            recovery_source_token(RecoverySource::InPageFreeBlock),
            "in-page-freeblock"
        );
        assert_eq!(
            recovery_source_token(RecoverySource::DroppedTable),
            "dropped-table"
        );
        assert_eq!(
            recovery_source_token(RecoverySource::RollbackJournal(rollback_src(0, 5))),
            "rollback-journal"
        );
    }

    #[test]
    fn value_cells_render_each_storage_class() {
        assert_eq!(value_to_cell(&Value::Null), "NULL");
        assert_eq!(value_to_cell(&Value::Real(1.5)), "1.5");
        assert_eq!(value_to_cell(&Value::Integer(42)), "42");
        assert_eq!(value_to_cell(&Value::Text("hi".into())), "hi");
        assert_eq!(value_to_cell(&Value::Blob(vec![1, 2, 3])), "<blob:3 bytes>");
    }

    #[test]
    fn rowid_zero_renders_as_question_mark() {
        assert_eq!(rowid_cell(0), "?");
        assert_eq!(rowid_cell(7), "7");
    }

    #[test]
    fn confidence_filter_drops_below_threshold() {
        let records = vec![
            rec(1, 0.9, RecoverySource::FreelistPage, vec![]),
            rec(2, 0.4, RecoverySource::InPageFreeBlock, vec![]),
            rec(3, 0.1, RecoverySource::FreeblockReconstructed, vec![]),
        ];
        let kept = filter_by_confidence(records, MinConfidence::Medium);
        assert_eq!(kept.len(), 2);
        assert_eq!(kept[0].rowid, 1);
        assert_eq!(kept[1].rowid, 2);
    }

    #[test]
    fn rowid_only_projection_ignores_format_and_values() {
        let records = vec![
            rec(
                5,
                0.9,
                RecoverySource::FreelistPage,
                vec![Value::Text("x".into())],
            ),
            rec(0, 0.4, RecoverySource::FreeblockReconstructed, vec![]),
        ];
        let lines = render_carve(&records, &[], OutputFormat::Csv, true);
        assert_eq!(lines, vec!["5".to_string(), "?".to_string()]);
    }

    #[test]
    fn carve_csv_has_header_and_one_row_per_record() {
        let records = vec![rec(
            5,
            0.9,
            RecoverySource::FreelistPage,
            vec![Value::Text("alice".into()), Value::Integer(30)],
        )];
        let lines = render_carve(&records, &[], OutputFormat::Csv, false);
        assert_eq!(
            lines[0],
            "page,offset,rowid,recovery_source,confidence,values"
        );
        assert_eq!(lines.len(), 2);
        assert!(lines[1].contains("freelist-page"), "{}", lines[1]);
        assert!(lines[1].contains("alice | 30"), "{}", lines[1]);
    }

    #[test]
    fn carve_csv_escapes_comma_bearing_values() {
        let records = vec![rec(
            1,
            0.9,
            RecoverySource::FreelistPage,
            vec![Value::Text("a,b".into())],
        )];
        let lines = render_carve(&records, &[], OutputFormat::Csv, false);
        assert!(lines[1].contains("\"a,b\""), "{}", lines[1]);
    }

    #[test]
    fn carve_jsonl_is_one_object_per_record() {
        let records = vec![
            rec(
                5,
                0.9,
                RecoverySource::FreelistPage,
                vec![Value::Integer(1)],
            ),
            rec(
                0,
                0.4,
                RecoverySource::FreeblockReconstructed,
                vec![Value::Null],
            ),
        ];
        let lines = render_carve(&records, &[], OutputFormat::Jsonl, false);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("{\"page\":3"), "{}", lines[0]);
        assert!(
            lines[0].contains("\"recovery_source\":\"freelist-page\""),
            "{}",
            lines[0]
        );
        assert!(lines[0].contains("\"rowid\":5"), "{}", lines[0]);
        assert!(lines[1].contains("\"rowid\":0"), "{}", lines[1]);
    }

    #[test]
    fn carve_jsonl_emits_lossless_base64_for_blobs() {
        // A BLOB column must be recoverable from JSONL, not reduced to a
        // "<blob:N bytes>" placeholder: it renders as a self-describing
        // {"blob_base64": "..."} object so a consumer can round-trip the bytes.
        // table/CSV keep the placeholder (raw binary is unsafe in those).
        let records = vec![rec(
            5,
            0.9,
            RecoverySource::FreelistPage,
            vec![Value::Blob(b"foobar".to_vec())],
        )];
        let lines = render_carve(&records, &[], OutputFormat::Jsonl, false);
        // RFC 4648 test vector: base64("foobar") == "Zm9vYmFy".
        assert!(
            lines[0].contains("\"values\":[{\"blob_base64\":\"Zm9vYmFy\"}]"),
            "{}",
            lines[0]
        );
        assert!(!lines[0].contains("<blob:"), "{}", lines[0]);
    }

    #[test]
    fn carve_table_has_header_and_renders_values() {
        let records = vec![rec(
            1,
            0.9,
            RecoverySource::FreelistPage,
            vec![Value::Text("alice".into()), Value::Integer(30)],
        )];
        let lines = render_carve(&records, &[], OutputFormat::Table, false);
        assert!(lines[0].contains("page"));
        assert!(lines[0].contains("recovery_source"));
        assert_eq!(lines.len(), 2);
        assert!(lines[1].contains("freelist-page"), "{}", lines[1]);
        assert!(lines[1].contains("alice | 30"), "{}", lines[1]);
    }

    #[test]
    fn json_escape_handles_quotes_and_controls() {
        assert_eq!(json_escape("a\"b"), "a\\\"b");
        assert_eq!(json_escape("a\\b"), "a\\\\b");
        assert_eq!(json_escape("a\nb"), "a\\nb");
        assert_eq!(json_escape("a\rb"), "a\\rb");
        assert_eq!(json_escape("a\tb"), "a\\tb");
        assert_eq!(json_escape("\u{0001}"), "\\u0001");
    }

    #[test]
    fn base64_encode_matches_rfc4648_vectors() {
        // RFC 4648 §10 test vectors — the canonical external reference.
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    fn anomaly() -> Anomaly {
        Anomaly::new(AnomalyKind::NonEmptyFreelist { free_pages: 4 })
    }

    fn wal_rec(source: RecoverySource, frame_index: usize) -> CarvedRecord {
        CarvedRecord {
            page: 2,
            offset: 64,
            rowid: 130,
            values: vec![Value::Text("secret WAL body 130".into())],
            confidence: 0.9,
            allocated: false,
            source,
            wal: Some(sqlite_forensic::WalProvenance {
                frame_index,
                salt1: 3_131_615_003,
                salt2: 3_836_839_008,
            }),
            overflow: None,
        }
    }

    #[test]
    fn snapshot_label_distinguishes_on_disk_commit_and_wal_frame() {
        // On-disk record: no WAL provenance → the on-disk base-image view.
        let on_disk = rec(7, 0.9, RecoverySource::FreelistPage, vec![]);
        assert_eq!(snapshot_label(&on_disk), "on-disk");

        // Commit-snapshot record: labelled commit:(salt1,salt2,commit_frame_index).
        let commit = wal_rec(RecoverySource::CommitSnapshot, 0);
        assert_eq!(snapshot_label(&commit), "commit:(3131615003,3836839008,0)");

        // WAL-frame residue (#60): labelled wal-frame:(salt1,salt2,frame_index).
        let frame = wal_rec(RecoverySource::WalFrame, 1);
        assert_eq!(
            snapshot_label(&frame),
            "wal-frame:(3131615003,3836839008,1)"
        );
    }

    #[test]
    fn carve_with_snapshot_table_has_snapshot_column() {
        let records = vec![
            wal_rec(RecoverySource::CommitSnapshot, 0),
            wal_rec(RecoverySource::WalFrame, 1),
        ];
        let lines = render_carve_with_snapshot(&records, &[], OutputFormat::Table, false);
        assert!(
            lines[0].contains("snapshot"),
            "header has snapshot col: {}",
            lines[0]
        );
        assert_eq!(lines.len(), 3);
        assert!(
            lines[1].contains("commit:(3131615003,3836839008,0)"),
            "{}",
            lines[1]
        );
        assert!(
            lines[2].contains("wal-frame:(3131615003,3836839008,1)"),
            "{}",
            lines[2]
        );
    }

    #[test]
    fn carve_with_snapshot_csv_has_snapshot_header_and_value() {
        let records = vec![wal_rec(RecoverySource::CommitSnapshot, 0)];
        let lines = render_carve_with_snapshot(&records, &[], OutputFormat::Csv, false);
        assert_eq!(
            lines[0],
            "page,offset,rowid,recovery_source,confidence,snapshot,values"
        );
        assert!(
            lines[1].contains("\"commit:(3131615003,3836839008,0)\"")
                || lines[1].contains("commit:(3131615003,3836839008,0)"),
            "{}",
            lines[1]
        );
    }

    #[test]
    fn carve_with_snapshot_jsonl_carries_snapshot_field() {
        let records = vec![wal_rec(RecoverySource::WalFrame, 1)];
        let lines = render_carve_with_snapshot(&records, &[], OutputFormat::Jsonl, false);
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains("\"snapshot\":\"wal-frame:(3131615003,3836839008,1)\""),
            "{}",
            lines[0]
        );
    }

    #[test]
    fn carve_with_snapshot_rowid_only_still_projects_rowids() {
        let records = vec![wal_rec(RecoverySource::CommitSnapshot, 0)];
        let lines = render_carve_with_snapshot(&records, &[], OutputFormat::Jsonl, true);
        assert_eq!(lines, vec!["130".to_string()]);
    }

    #[test]
    fn snapshot_recovery_source_token_is_stable() {
        assert_eq!(
            recovery_source_token(RecoverySource::CommitSnapshot),
            "commit-snapshot"
        );
    }

    #[test]
    fn dedup_collapses_identical_record_to_earliest_committed_label() {
        // The SAME deleted row (rowid 130, identical values) surfaces in all three
        // views; dedup keeps ONE copy carrying the earliest committed coordinate
        // (commit snapshot over wal-frame over on-disk), exercising every rank arm
        // including the on-disk `_` arm.
        let values = vec![Value::Text("secret WAL body 130".into())];
        let on_disk = rec(130, 0.95, RecoverySource::FreelistPage, values.clone());
        let wal_frame = wal_rec(RecoverySource::WalFrame, 1);
        let commit = wal_rec(RecoverySource::CommitSnapshot, 0);
        // Feed them out of order so the sort (not input order) decides the winner.
        let kept = dedup_keep_earliest_label(vec![on_disk, wal_frame, commit]);
        assert_eq!(kept.len(), 1, "identical record collapses to one copy");
        assert_eq!(kept[0].source, RecoverySource::CommitSnapshot);
        assert_eq!(snapshot_label(&kept[0]), "commit:(3131615003,3836839008,0)");
    }

    #[test]
    fn dedup_keeps_distinct_records_from_different_views() {
        // Distinct rows (different rowid/values) are all kept.
        let a = rec(
            7,
            0.9,
            RecoverySource::FreelistPage,
            vec![Value::Integer(7)],
        );
        let b = wal_rec(RecoverySource::CommitSnapshot, 0); // rowid 130
        let kept = dedup_keep_earliest_label(vec![a, b]);
        assert_eq!(kept.len(), 2);
    }

    #[test]
    fn snapshot_label_names_rollback_journal_segment_and_page() {
        // A rollback-journal prior row labels with its (segment, restored-page).
        let jr = journal_rec(42, 1, 7, vec![Value::Integer(42)]);
        assert_eq!(snapshot_label(&jr), "rollback-journal:(1,7)");
    }

    #[test]
    fn dedup_prefers_rollback_journal_over_free_space_carve() {
        // The SAME deleted row recovered from BOTH the rollback journal (full
        // fidelity) and a free-space carve collapses to ONE copy — the journal's,
        // because its rank ties with a commit snapshot (earliest) and beats the
        // on-disk free-space carve.
        let values = vec![Value::Text("deleted invoice row".into())];
        let on_disk = rec(900, 0.95, RecoverySource::FreelistPage, values.clone());
        let journal = journal_rec(900, 0, 12, values.clone());
        let kept = dedup_keep_earliest_label(vec![on_disk, journal]);
        assert_eq!(kept.len(), 1, "the duplicate collapses to one copy");
        assert!(
            matches!(kept[0].source, RecoverySource::RollbackJournal(_)),
            "the full-fidelity journal copy is preferred: {:?}",
            kept[0].source
        );
    }

    /// A minimal one-table history (a single live, present row) to fold into.
    fn history_with_live_row(
        table: &str,
        columns: &[&str],
        rowid: i64,
        values: Vec<Value>,
    ) -> sqlite_core::row_history::TableHistory {
        use sqlite_core::row_history::{RowVersion, TableHistory, VersionOrigin, ViewState};
        TableHistory {
            table: table.to_string(),
            columns: columns.iter().map(|s| (*s).to_string()).collect(),
            without_rowid: false,
            versions: vec![RowVersion {
                rowid: Some(rowid),
                values,
                origin: VersionOrigin::Live,
                commit_seq: None,
                view_state: ViewState::PresentInFinalView,
                is_deleted: false,
                is_guessed: false,
                rowid_reused: false,
                attribution_uncertain: false,
            }],
        }
    }

    #[test]
    fn fold_journal_adds_deleted_red_and_modified_blue_versions() {
        use sqlite_core::row_history::ViewState;
        let mut histories = vec![history_with_live_row(
            "t",
            &["id", "q"],
            5,
            vec![Value::Integer(5), Value::Integer(200)],
        )];
        let recovery = JournalRecovery {
            deleted: vec![PriorRow {
                table: "t".into(),
                rowid: 9,
                values: vec![Value::Integer(9), Value::Integer(3)],
                source: RecoverySource::RollbackJournal(rollback_src(0, 2)),
            }],
            modified: vec![PriorVersionRecord {
                table: "t".into(),
                rowid: 5,
                prior_values: vec![Value::Integer(5), Value::Integer(7)],
                current_values: vec![Value::Integer(5), Value::Integer(200)],
                replaced_rowid: true,
                source: RecoverySource::RollbackJournal(rollback_src(0, 2)),
            }],
            counts: JournalCounts {
                deleted: 1,
                modified: 1,
            },
        };
        fold_journal_into_histories(&mut histories, &recovery);

        let t = &histories[0];
        // The live row stays present; a deleted version and a superseded prior
        // version are folded in.
        let deleted = t
            .versions
            .iter()
            .find(|v| v.is_deleted)
            .expect("a deleted version folded in");
        assert_eq!(deleted.rowid, Some(9));
        assert_eq!(deleted.view_state, ViewState::CarvedResidue);
        assert!(
            !deleted.is_guessed,
            "a known-table delete is Tier-1 certain"
        );

        let superseded = t
            .versions
            .iter()
            .find(|v| v.view_state == ViewState::ValueChangedLater)
            .expect("a superseded prior version folded in");
        assert_eq!(superseded.rowid, Some(5));
        assert!(!superseded.is_deleted, "a modification is not a deletion");
        assert_eq!(
            superseded.values,
            vec![Value::Integer(5), Value::Integer(7)]
        );

        // The original live row is untouched (still present, not deleted).
        assert!(t
            .versions
            .iter()
            .any(|v| v.view_state == ViewState::PresentInFinalView && !v.is_deleted));
    }

    #[test]
    fn fold_journal_skips_byte_identical_and_unknown_tables() {
        use sqlite_core::row_history::ViewState;
        // A history that ALREADY carries the deleted row as residue, plus a recovery
        // whose delete is byte-identical (must not double-list) and another whose
        // table has no history (must be dropped, never invented).
        let mut histories = vec![history_with_live_row(
            "t",
            &["id"],
            1,
            vec![Value::Integer(1)],
        )];
        // Pre-seed the byte-identical deleted residue version.
        {
            use sqlite_core::row_history::{RowVersion, VersionOrigin};
            histories[0].versions.push(RowVersion {
                rowid: Some(2),
                values: vec![Value::Integer(2)],
                origin: VersionOrigin::CarvedResidue,
                commit_seq: None,
                view_state: ViewState::CarvedResidue,
                is_deleted: true,
                is_guessed: false,
                rowid_reused: false,
                attribution_uncertain: false,
            });
        }
        let before = histories[0].versions.len();
        let recovery = JournalRecovery {
            deleted: vec![
                PriorRow {
                    table: "t".into(),
                    rowid: 2,
                    values: vec![Value::Integer(2)],
                    source: RecoverySource::RollbackJournal(rollback_src(0, 1)),
                },
                PriorRow {
                    table: "ghost".into(), // no history sheet → dropped
                    rowid: 3,
                    values: vec![Value::Integer(3)],
                    source: RecoverySource::RollbackJournal(rollback_src(0, 1)),
                },
            ],
            modified: vec![],
            counts: JournalCounts {
                deleted: 2,
                modified: 0,
            },
        };
        fold_journal_into_histories(&mut histories, &recovery);
        assert_eq!(
            histories[0].versions.len(),
            before,
            "the byte-identical delete is not double-listed"
        );
        assert_eq!(
            histories.len(),
            1,
            "no fabricated history for the ghost table"
        );
    }

    #[test]
    fn journal_carved_records_projects_deleted_and_modified_prior_rows() {
        let recovery = JournalRecovery {
            deleted: vec![PriorRow {
                table: "t".into(),
                rowid: 9,
                values: vec![Value::Integer(9)],
                source: RecoverySource::RollbackJournal(rollback_src(0, 4)),
            }],
            modified: vec![PriorVersionRecord {
                table: "t".into(),
                rowid: 5,
                prior_values: vec![Value::Integer(5), Value::Text("OLD".into())],
                current_values: vec![Value::Integer(5), Value::Text("new".into())],
                replaced_rowid: true,
                source: RecoverySource::RollbackJournal(rollback_src(0, 6)),
            }],
            counts: JournalCounts {
                deleted: 1,
                modified: 1,
            },
        };
        let records = journal_carved_records(&recovery);
        assert_eq!(records.len(), 2, "one per deleted + one per modified");
        // Deleted prior row: full values, RollbackJournal source, page = pgno.
        assert_eq!(records[0].rowid, 9);
        assert_eq!(records[0].page, 4);
        assert_eq!(recovery_source_token(records[0].source), "rollback-journal");
        assert_eq!(snapshot_label(&records[0]), "rollback-journal:(0,4)");
        // Modified row: the PRIOR (pre-edit) values, not the current ones.
        assert_eq!(records[1].rowid, 5);
        assert_eq!(
            records[1].values,
            vec![Value::Integer(5), Value::Text("OLD".into())]
        );
        assert_eq!(snapshot_label(&records[1]), "rollback-journal:(0,6)");
    }

    #[test]
    fn plan_combined_workbook_folds_journal_recovery() {
        // End to end through the planner: a deleted prior row tints red (is_deleted)
        // and a modified prior value tints blue (superseded) under the live table.
        let db = minted_people_db();
        let recovery = JournalRecovery {
            deleted: vec![PriorRow {
                table: "people".into(),
                rowid: 99,
                values: vec![Value::Integer(99), Value::Text("ghost".into())],
                source: RecoverySource::RollbackJournal(rollback_src(0, 2)),
            }],
            modified: vec![PriorVersionRecord {
                table: "people".into(),
                rowid: 1,
                prior_values: vec![Value::Integer(1), Value::Text("OLD".into())],
                current_values: vec![Value::Integer(1), Value::Text("alice".into())],
                replaced_rowid: true,
                source: RecoverySource::RollbackJournal(rollback_src(0, 2)),
            }],
            counts: JournalCounts {
                deleted: 1,
                modified: 1,
            },
        };
        let plan = plan_combined_workbook(
            &db,
            &[],
            None,
            Some(&recovery),
            &std::collections::BTreeMap::new(),
            EXCEL_MAX_ROWS,
        );
        let people = plan.sheets.iter().find(|s| s.name == "people").unwrap();
        assert!(
            people.rows.iter().any(|r| r.is_deleted),
            "the journal delete folds in as a red is_deleted version"
        );
        assert!(
            people.rows.iter().any(|r| r.superseded && !r.is_deleted),
            "the journal modification folds in as a blue superseded version"
        );
    }

    #[test]
    fn severity_tokens_are_stable() {
        use forensicnomicon::report::Severity;
        assert_eq!(severity_token(Severity::Info), "INFO");
        assert_eq!(severity_token(Severity::Low), "LOW");
        assert_eq!(severity_token(Severity::Medium), "MEDIUM");
        assert_eq!(severity_token(Severity::High), "HIGH");
        assert_eq!(severity_token(Severity::Critical), "CRITICAL");
    }

    #[test]
    fn anomaly_location_renders_evidence_fields() {
        let a = anomaly();
        let loc = anomaly_location(&a);
        assert!(loc.contains("free_pages=4"), "{loc}");
    }

    #[test]
    fn audit_csv_has_header_and_row() {
        let anomalies = vec![anomaly()];
        let lines = render_audit(&anomalies, OutputFormat::Csv);
        assert_eq!(lines[0], "severity,code,location,note");
        assert_eq!(lines.len(), 2);
        assert!(
            lines[1].contains("SQLITE-FREELIST-NONEMPTY"),
            "{}",
            lines[1]
        );
        assert!(lines[1].starts_with("LOW,"), "{}", lines[1]);
    }

    #[test]
    fn audit_jsonl_is_one_object_per_anomaly() {
        let anomalies = vec![anomaly()];
        let lines = render_audit(&anomalies, OutputFormat::Jsonl);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("\"severity\":\"LOW\""), "{}", lines[0]);
        assert!(
            lines[0].contains("\"code\":\"SQLITE-FREELIST-NONEMPTY\""),
            "{}",
            lines[0]
        );
    }

    #[test]
    fn audit_table_has_header() {
        let anomalies = vec![anomaly()];
        let lines = render_audit(&anomalies, OutputFormat::Table);
        assert!(lines[0].contains("severity"));
        assert!(lines[0].contains("code"));
        assert_eq!(lines.len(), 2);
    }

    // ---- Tier-2 fragment rendering (task #72) ------------------------------

    fn frag() -> CarvedFragment {
        CarvedFragment {
            page: 2,
            offset: 3965,
            surviving: vec![
                (0, Value::Integer(20004)),
                (1, Value::Text("Anja".into())),
                (2, Value::Text("Frank".into())),
            ],
            missing: 2,
            confidence: 0.2,
            source: RecoverySource::FreeblockReconstructed,
            wal: None,
        }
    }

    #[test]
    fn fragments_table_has_labelled_section_and_row() {
        let lines = render_fragments(&[frag()], OutputFormat::Table);
        assert!(
            lines.iter().any(|l| l.contains("# fragments")),
            "labelled fragment section header"
        );
        assert!(lines.iter().any(|l| l.contains("surviving")));
        assert!(
            lines.iter().any(|l| l.contains("col1='Anja'")),
            "surviving cells rendered"
        );
        assert!(
            lines.iter().any(|l| l.contains("destroyed")),
            "missing-column count shown"
        );
    }

    #[test]
    fn fragments_csv_carries_kind_column() {
        let lines = render_fragments(&[frag()], OutputFormat::Csv);
        assert_eq!(
            lines[0],
            "kind,page,offset,confidence,source,missing,surviving"
        );
        assert!(lines[1].starts_with("fragment,2,3965,0.20,"));
    }

    #[test]
    fn fragments_jsonl_marks_kind_fragment() {
        let lines = render_fragments(&[frag()], OutputFormat::Jsonl);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("\"kind\":\"fragment\""));
        assert!(lines[0].contains("\"column\":1,\"value\":\"Anja\""));
        assert!(lines[0].contains("\"missing\":2"));
    }

    #[test]
    fn fragments_empty_input_renders_nothing() {
        assert!(render_fragments(&[], OutputFormat::Table).is_empty());
        assert!(render_fragments(&[], OutputFormat::Csv).is_empty());
        assert!(render_fragments(&[], OutputFormat::Jsonl).is_empty());
    }

    #[test]
    fn fragment_single_missing_column_is_singular() {
        let mut f = frag();
        f.missing = 1;
        let lines = render_fragments(&[f], OutputFormat::Table);
        assert!(
            lines.iter().any(|l| l.contains("(+1 column destroyed)")),
            "singular noun for a single missing column"
        );
    }

    #[test]
    fn tiered_default_full_rows_unchanged_jsonl() {
        // Without fragments, the JSONL full-row output is byte-identical to
        // render_carve (no `kind` key added to full rows — published contract).
        let records = vec![rec(
            7,
            0.9,
            RecoverySource::FreelistPage,
            vec![Value::Integer(7)],
        )];
        let plain = render_carve(&records, &[], OutputFormat::Jsonl, false);
        let tiered = render_carve_tiered(&records, &[], &[], OutputFormat::Jsonl, false);
        assert_eq!(plain, tiered, "no fragments → full-row JSONL unchanged");
        assert!(!tiered[0].contains("\"kind\""));
    }

    #[test]
    fn tiered_csv_adds_kind_column_to_both_sections() {
        let records = vec![rec(
            7,
            0.9,
            RecoverySource::FreelistPage,
            vec![Value::Integer(7)],
        )];
        let lines = render_carve_tiered(&records, &[], &[frag()], OutputFormat::Csv, false);
        assert_eq!(
            lines[0],
            "kind,page,offset,rowid,recovery_source,confidence,values"
        );
        assert!(lines.iter().any(|l| l.starts_with("row,")));
        assert!(lines.iter().any(|l| l.starts_with("fragment,")));
    }

    #[test]
    fn tiered_rowid_only_emits_full_rowids_no_fragments() {
        let records = vec![rec(7, 0.9, RecoverySource::FreelistPage, vec![])];
        let lines = render_carve_tiered(&records, &[], &[frag()], OutputFormat::Table, true);
        assert_eq!(lines, vec!["7".to_string()]);
    }

    // ---- rebuilt-db output: path derivation + safety guard -----------------

    #[test]
    fn default_carved_db_path_is_stem_carved_db_in_cwd() {
        // History.db -> History.carved.db (final extension stripped).
        assert_eq!(
            carved_db_path(Path::new("/evidence/History.db"), None).unwrap(),
            PathBuf::from("History.carved.db")
        );
        // ChatStorage.sqlite -> ChatStorage.carved.db.
        assert_eq!(
            carved_db_path(Path::new("ChatStorage.sqlite"), None).unwrap(),
            PathBuf::from("ChatStorage.carved.db")
        );
        // A name with no extension keeps the whole stem.
        assert_eq!(
            carved_db_path(Path::new("/data/wal_only"), None).unwrap(),
            PathBuf::from("wal_only.carved.db")
        );
        // A path with no filename component degrades to a fixed safe name rather
        // than panicking (exercises the no-stem fallback arm).
        assert_eq!(
            carved_db_path(Path::new("/"), None).unwrap(),
            PathBuf::from("recovered.carved.db")
        );
    }

    #[test]
    fn default_recovered_xlsx_path_is_stem_recovered_xlsx_in_cwd() {
        // History.db -> History.recovered.xlsx (final extension stripped).
        assert_eq!(
            recovered_xlsx_path(Path::new("/evidence/History.db"), None).unwrap(),
            PathBuf::from("History.recovered.xlsx")
        );
        // ChatStorage.sqlite -> ChatStorage.recovered.xlsx.
        assert_eq!(
            recovered_xlsx_path(Path::new("ChatStorage.sqlite"), None).unwrap(),
            PathBuf::from("ChatStorage.recovered.xlsx")
        );
        // No-stem fallback.
        assert_eq!(
            recovered_xlsx_path(Path::new("/"), None).unwrap(),
            PathBuf::from("recovered.recovered.xlsx")
        );
    }

    #[test]
    fn out_is_honored_verbatim_for_both_outputs() {
        // `-o /p/foo.xlsx` is the EXACT path — no stem/extension stripping. The db
        // and xlsx helpers each take the path as given (the caller picks which
        // suffix to ask for; the helper does not append one).
        assert_eq!(
            recovered_xlsx_path(Path::new("History.db"), Some(Path::new("/p/foo.xlsx"))).unwrap(),
            PathBuf::from("/p/foo.xlsx")
        );
        assert_eq!(
            carved_db_path(Path::new("History.db"), Some(Path::new("/p/foo.db"))).unwrap(),
            PathBuf::from("/p/foo.db")
        );
        // An unusual name (no extension, or a different extension) is kept exactly.
        assert_eq!(
            recovered_xlsx_path(Path::new("History.db"), Some(Path::new("/p/bare"))).unwrap(),
            PathBuf::from("/p/bare")
        );
        assert_eq!(
            carved_db_path(Path::new("History.db"), Some(Path::new("out/x.sqlite"))).unwrap(),
            PathBuf::from("out/x.sqlite")
        );
    }

    #[test]
    fn carved_db_guard_refuses_an_out_onto_the_evidence() {
        // An explicit `-o` landing exactly on the evidence db is refused.
        let db = Path::new("/evidence/History.db");
        assert!(carved_db_path(db, Some(Path::new("/evidence/History.db"))).is_err());
        // A genuinely different path is allowed.
        assert!(carved_db_path(db, Some(Path::new("/out/History.carved.db"))).is_ok());
    }

    #[test]
    fn recovered_xlsx_guard_refuses_an_out_onto_a_sidecar() {
        // An explicit `-o` landing on a `-wal` sidecar is refused.
        let db = Path::new("/evidence/History.db");
        assert!(recovered_xlsx_path(db, Some(Path::new("/evidence/History.db-wal"))).is_err());
        // A genuinely different path is allowed.
        assert!(recovered_xlsx_path(db, Some(Path::new("/out/History.recovered.xlsx"))).is_ok());
    }

    #[test]
    fn evidence_path_clash_flags_db_and_each_sidecar() {
        // The guard predicate, exercised directly so all sidecar arms are covered
        // (the suffix-fixed derived paths above cannot themselves land on a
        // `-wal`/`-shm`/`-journal` name).
        let db = Path::new("/evidence/History.db");
        assert_eq!(evidence_path_clash(db, db), Some("database"));
        for (sidecar, label) in [
            ("-wal", "-wal sidecar"),
            ("-shm", "-shm sidecar"),
            ("-journal", "-journal sidecar"),
        ] {
            let mut name = db.as_os_str().to_owned();
            name.push(sidecar);
            assert_eq!(evidence_path_clash(db, &PathBuf::from(name)), Some(label));
        }
        assert_eq!(evidence_path_clash(db, Path::new("/out/x.carved.db")), None);
    }

    #[test]
    fn carved_record_maps_to_rebuild_row_natively() {
        let mut r = rec(
            55,
            0.9,
            RecoverySource::FreelistPage,
            vec![Value::Integer(1), Value::Blob(vec![1, 2, 3])],
        );
        r.page = 9;
        r.offset = 321;
        let row = carved_to_rebuild_row(&r);
        assert_eq!(row.page, 9);
        assert_eq!(row.offset, 321);
        assert_eq!(row.rowid, Some(55));
        assert_eq!(row.source, "freelist-page");
        assert!((row.confidence - 0.9).abs() < 1e-6);
        assert_eq!(
            row.cells,
            vec![Value::Integer(1), Value::Blob(vec![1, 2, 3])]
        );
    }

    #[test]
    fn carved_record_zero_rowid_maps_to_none() {
        // A clobbered rowid (0, e.g. freeblock reconstruction) becomes NULL.
        let r = rec(0, 0.4, RecoverySource::FreeblockReconstructed, vec![]);
        assert_eq!(carved_to_rebuild_row(&r).rowid, None);
    }

    // ---- fragment -> rebuilt fragment row ----------------------------------

    #[test]
    fn carved_fragment_maps_to_fragment_row_preserving_native_cells() {
        // A fragment's provenance + each surviving (col_index, value) carries over
        // verbatim and natively (a BLOB stays a BLOB); the writer owns where each
        // value lands. No rowid and no source label exist on the fragment table.
        let f = CarvedFragment {
            page: 2,
            offset: 3965,
            surviving: vec![(0, Value::Integer(20004)), (2, Value::Blob(vec![1, 2, 3]))],
            missing: 1,
            confidence: 0.2,
            source: RecoverySource::FreeblockReconstructed,
            wal: None,
        };
        let row = fragment_to_rebuild_row(&f);
        assert_eq!(row.page, 2);
        assert_eq!(row.offset, 3965);
        assert_eq!(row.missing, 1);
        assert!((row.confidence - 0.2).abs() < 1e-6);
        assert_eq!(
            row.surviving,
            vec![(0, Value::Integer(20004)), (2, Value::Blob(vec![1, 2, 3]))],
            "surviving (index, value) pairs preserved natively"
        );
    }

    // ---- XLSX export: blob classification + human size --------------------

    /// A minimal but real 1x1 PNG (the 8-byte signature + IHDR/IDAT/IEND), used
    /// across the blob-classification and thumbnail tests as a genuine image.
    fn tiny_png() -> Vec<u8> {
        const PNG: &[u8] = &[
            0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, // signature
            0x00, 0x00, 0x00, 0x0d, b'I', b'H', b'D', b'R', // IHDR len + type
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // 1x1
            0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, 0xde, // bit depth/color + crc
            0x00, 0x00, 0x00, 0x0c, b'I', b'D', b'A', b'T', // IDAT len + type
            0x08, 0xd7, 0x63, 0xf8, 0xcf, 0xc0, 0x00, 0x00, 0x00, 0x03, 0x01, 0x01, // data
            0x18, 0xdd, 0x8d, 0xb4, // IDAT crc
            0x00, 0x00, 0x00, 0x00, b'I', b'E', b'N', b'D', 0xae, 0x42, 0x60, 0x82, // IEND
        ];
        PNG.to_vec()
    }

    #[test]
    fn classify_blob_detects_image_formats() {
        // PNG (8-byte signature).
        assert_eq!(classify_blob(&tiny_png()), BlobKind::Image);
        // JPEG SOI marker FF D8 FF.
        assert_eq!(
            classify_blob(&[0xff, 0xd8, 0xff, 0xe0, 0, 16, b'J', b'F', b'I', b'F']),
            BlobKind::Image
        );
        // GIF89a.
        assert_eq!(classify_blob(b"GIF89a\x01\x00\x01\x00"), BlobKind::Image);
        // BMP.
        assert_eq!(
            classify_blob(b"BM\x00\x00\x00\x00\x00\x00"),
            BlobKind::Image
        );
    }

    #[test]
    fn classify_blob_detects_video_containers() {
        // MP4: a `ftyp` box at offset 4 (`....ftypisom`).
        let mp4 = b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isom";
        assert_eq!(classify_blob(mp4), BlobKind::Video { ext: "mp4" });
        // QuickTime MOV: `ftypqt  `.
        let mov = b"\x00\x00\x00\x14ftypqt  \x00\x00\x00\x00";
        assert_eq!(classify_blob(mov), BlobKind::Video { ext: "mov" });
        // Matroska / WebM EBML header 1A 45 DF A3.
        let mkv = &[0x1a, 0x45, 0xdf, 0xa3, 0x01, 0x00, 0x00, 0x00];
        assert_eq!(classify_blob(mkv), BlobKind::Video { ext: "mkv" });
        // AVI: RIFF....AVI .
        let avi = b"RIFF\x24\x00\x00\x00AVI LIST";
        assert_eq!(classify_blob(avi), BlobKind::Video { ext: "avi" });
    }

    #[test]
    fn classify_blob_other_for_non_media() {
        assert_eq!(classify_blob(b"plain text bytes"), BlobKind::Other);
        assert_eq!(classify_blob(&[0u8; 4]), BlobKind::Other);
        // Too short to carry any magic.
        assert_eq!(classify_blob(&[0xff]), BlobKind::Other);
        assert_eq!(classify_blob(&[]), BlobKind::Other);
    }

    #[test]
    fn human_size_renders_units() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1024), "1.0 KB");
        assert_eq!(human_size(1536), "1.5 KB");
        assert_eq!(human_size(1024 * 1024), "1.0 MB");
        assert_eq!(human_size(4_404_019), "4.2 MB");
        assert_eq!(human_size(1024 * 1024 * 1024), "1.0 GB");
    }

    // ---- XLSX export: thumbnail / transcode --------------------------------

    /// An 8x4 RGB PNG, used to verify the thumbnailer downscales the longest side
    /// and always re-encodes to PNG (so WebP/TIFF sources transcode too).
    fn rgb_png(w: u32, h: u32) -> Vec<u8> {
        let img = image::RgbImage::from_fn(w, h, |x, _| image::Rgb([(x % 256) as u8, 0, 0]));
        let mut out = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageRgb8(img)
            .write_to(&mut out, image::ImageFormat::Png)
            .unwrap();
        out.into_inner()
    }

    #[test]
    fn thumbnail_png_downscales_longest_side_and_emits_png() {
        // A 400x200 source: longest side must shrink to THUMB_MAX_PX, aspect kept.
        let src = rgb_png(400, 200);
        let thumb = thumbnail_png(&src).expect("a valid PNG must thumbnail");
        // The output is itself a PNG (transcoded), readable back by the decoder.
        assert_eq!(
            image::guess_format(&thumb).unwrap(),
            image::ImageFormat::Png
        );
        let decoded = image::load_from_memory(&thumb).unwrap();
        let (tw, th) = (decoded.width(), decoded.height());
        assert!(
            tw <= THUMB_MAX_PX && th <= THUMB_MAX_PX,
            "both sides within the thumbnail bound, got {tw}x{th}"
        );
        assert_eq!(tw, THUMB_MAX_PX, "longest side scaled to the bound");
        assert_eq!(th, THUMB_MAX_PX / 2, "aspect ratio (2:1) preserved");
    }

    #[test]
    fn thumbnail_png_does_not_upscale_small_images() {
        // A real 2x2 PNG must not be enlarged; it stays within bounds and
        // re-encodes. (`tiny_png()` is a signature-only fixture for the
        // magic-byte classifier; the thumbnailer needs a fully-decodable image,
        // so it is encoder-minted here — Doer-Checker over a real round-trip.)
        let src = rgb_png(2, 2);
        let thumb = thumbnail_png(&src).expect("small png thumbnails");
        let decoded = image::load_from_memory(&thumb).unwrap();
        assert_eq!((decoded.width(), decoded.height()), (2, 2), "not upscaled");
    }

    #[test]
    fn thumbnail_png_fails_soft_on_non_image() {
        // Hostile / non-image bytes must return None, never panic.
        assert!(thumbnail_png(b"not an image at all").is_none());
        assert!(thumbnail_png(&[]).is_none());
        // A truncated PNG signature with no decodable body also fails soft.
        assert!(thumbnail_png(&[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).is_none());
    }

    // ---- XLSX export: workbook builder -------------------------------------

    use calamine::{Data, Reader};

    fn rebuild_row(rowid: Option<i64>, cells: Vec<Value>) -> RebuildRow {
        RebuildRow {
            page: 3,
            offset: 128,
            rowid,
            source: "freelist-page".to_string(),
            confidence: 0.9,
            cells,
        }
    }

    /// Open an in-memory .xlsx buffer with calamine (a real external reader).
    fn open_xlsx(buf: &[u8]) -> calamine::Xlsx<std::io::Cursor<Vec<u8>>> {
        calamine::open_workbook_from_rs(std::io::Cursor::new(buf.to_vec()))
            .expect("produced bytes must be a valid xlsx calamine can open")
    }

    #[test]
    fn per_table_xlsx_has_one_sheet_per_recovered_table_with_sanitized_names() {
        let tables = vec![
            RecoveredTable {
                name: "recovered_people".to_string(),
                columns: ["_page", "_rowid", "name"].map(String::from).to_vec(),
                rows: vec![vec![
                    Value::Integer(3),
                    Value::Integer(5),
                    Value::Text("alice".into()),
                ]],
            },
            // A name with a forbidden char + over 31 chars → sanitized + truncated.
            RecoveredTable {
                name: "recovered_a/very_long_table_name_that_overflows".to_string(),
                columns: ["_page", "c0"].map(String::from).to_vec(),
                rows: vec![vec![Value::Integer(1), Value::Integer(9)]],
            },
        ];
        let buf = build_recovered_tables_xlsx(&tables).unwrap();
        let mut wb = open_xlsx(&buf);
        let names = wb.sheet_names();
        assert!(names.iter().any(|n| n == "recovered_people"), "{names:?}");
        // Sanitized: no '/', ≤ 31 chars.
        let sanitized = names
            .iter()
            .find(|n| n.as_str() != "recovered_people")
            .expect("a second, sanitized sheet exists");
        assert!(!sanitized.contains('/'));
        assert!(sanitized.chars().count() <= 31);

        // The real column name survived on the first sheet.
        let people = wb.worksheet_range("recovered_people").unwrap();
        let header: Vec<String> = people
            .rows()
            .next()
            .unwrap()
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        assert_eq!(header, vec!["_page", "_rowid", "name"]);
    }

    #[test]
    fn recovered_tables_xlsx_bytes_returns_buffer_and_maps_errors() {
        // Happy path returns bytes calamine can open.
        let tables = vec![RecoveredTable {
            name: "recovered_t".to_string(),
            columns: vec!["c0".to_string()],
            rows: vec![vec![Value::Integer(1)]],
        }];
        let buf = recovered_tables_xlsx_bytes(&tables, Path::new("/out/x.recovered.xlsx")).unwrap();
        assert!(!buf.is_empty());
        let _ = open_xlsx(&buf);

        // Error path: a row wider than Excel's column limit makes the writer fail;
        // the error maps to a string keyed by the destination path.
        let wide = vec![RecoveredTable {
            name: "recovered_wide".to_string(),
            columns: (0..20_000).map(|i| format!("c{i}")).collect(),
            rows: vec![(0..20_000).map(Value::Integer).collect()],
        }];
        let err = recovered_tables_xlsx_bytes(&wide, Path::new("/out/wide.xlsx")).unwrap_err();
        assert!(
            err.contains("recovered xlsx") && err.contains("wide.xlsx"),
            "error maps to a path-keyed string: {err}"
        );
    }

    #[test]
    fn carve_wal_snapshots_over_the_real_wal_fixture() {
        // Drive the WAL-snapshot carve in-process so its monomorphization is
        // exercised by a unit test (the integration test covers the binary path).
        const MAIN: &[u8] = include_bytes!("../../tests/data/wal_carve.db");
        const WAL: &[u8] = include_bytes!("../../tests/data/wal_carve.db-wal");
        let db = Database::open_with_wal(MAIN.to_vec(), WAL).expect("open with wal");
        let tl = db.wal_timeline().expect("timeline present");
        let records = carve_wal_snapshots(&db, &tl);
        assert!(!records.is_empty(), "the WAL fixture yields carved records");
    }

    #[test]
    fn group_and_attribute_over_a_real_database() {
        // Mint a tiny valid db via the writer, open it, and drive the db-backed
        // attribution wrappers (no sqlite3 needed). The minted db has live tables,
        // so group_attributed_tables / attribute_records exercise the real path.
        use sqlite_core::rebuild::{build_recovered_db_tables, RecoveredTable as RT};
        let seed = vec![RT {
            name: "people".to_string(),
            columns: vec!["id".to_string(), "name".to_string()],
            rows: vec![vec![Value::Integer(1), Value::Text("a".into())]],
        }];
        let bytes = build_recovered_db_tables(&seed);
        let db = Database::open(bytes).expect("minted db opens");

        // A freelist record shaped like (INTEGER, TEXT) — attribute_records reads
        // the db's live schema to classify it.
        let records = vec![rec(
            0,
            0.9,
            RecoverySource::FreelistPage,
            vec![Value::Integer(2), Value::Text("b".into())],
        )];
        let attrs = attribute_records(&db, &records);
        assert_eq!(attrs.len(), 1);

        let tables =
            group_attributed_tables(&db, &records, None, &std::collections::BTreeMap::new());
        // The single record must land in exactly one recovered_* table.
        assert!(tables.iter().all(|t| t.name.starts_with("recovered_")));
        assert_eq!(tables.iter().map(|t| t.rows.len()).sum::<usize>(), 1);
    }

    #[test]
    fn per_table_xlsx_deduplicates_colliding_sheet_names() {
        // Two tables sanitizing to the same 31-char prefix must get unique sheets.
        let long_a = "recovered_collide_aaaaaaaaaaaaaaaaaaa_x"; // > 31
        let long_b = "recovered_collide_aaaaaaaaaaaaaaaaaaa_y"; // same 31-char prefix
        let tables = vec![
            RecoveredTable {
                name: long_a.to_string(),
                columns: vec!["c0".to_string()],
                rows: vec![vec![Value::Integer(1)]],
            },
            RecoveredTable {
                name: long_b.to_string(),
                columns: vec!["c0".to_string()],
                rows: vec![vec![Value::Integer(2)]],
            },
        ];
        let buf = build_recovered_tables_xlsx(&tables).unwrap();
        let wb = open_xlsx(&buf);
        let names = wb.sheet_names();
        assert_eq!(names.len(), 2);
        assert_ne!(names[0], names[1], "sheet names must be unique: {names:?}");
    }

    #[test]
    fn xlsx_has_both_sheets_with_headers() {
        let records = vec![rebuild_row(
            Some(5),
            vec![Value::Text("alice".into()), Value::Integer(30)],
        )];
        let frags = vec![FragmentRow {
            page: 2,
            offset: 3965,
            missing: 1,
            confidence: 0.2,
            surviving: vec![(0, Value::Integer(20004))],
        }];
        let buf = build_recovered_xlsx(&records, Some(&frags)).unwrap();
        let mut wb = open_xlsx(&buf);
        let names = wb.sheet_names();
        assert!(names.iter().any(|n| n == "recovered_records"));
        assert!(names.iter().any(|n| n == "recovered_fragments"));

        // Records header mirrors the rebuilt-db schema.
        let recs = wb.worksheet_range("recovered_records").unwrap();
        let header: Vec<String> = recs
            .rows()
            .next()
            .unwrap()
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        assert_eq!(
            header,
            vec![
                "_page",
                "_offset",
                "_rowid",
                "_source",
                "_confidence",
                "c0",
                "c1"
            ]
        );

        // Fragments header mirrors the fragment-table schema.
        let fr = wb.worksheet_range("recovered_fragments").unwrap();
        let fheader: Vec<String> = fr
            .rows()
            .next()
            .unwrap()
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        assert_eq!(
            fheader,
            vec!["_page", "_offset", "_missing", "_confidence", "c0"]
        );
    }

    #[test]
    fn xlsx_no_fragments_omits_the_second_sheet() {
        let records = vec![rebuild_row(Some(1), vec![Value::Integer(7)])];
        let buf = build_recovered_xlsx(&records, None).unwrap();
        let wb = open_xlsx(&buf);
        let names = wb.sheet_names();
        assert!(names.iter().any(|n| n == "recovered_records"));
        assert!(
            !names.iter().any(|n| n == "recovered_fragments"),
            "no fragments → no fragment sheet"
        );
    }

    #[test]
    fn xlsx_cell_values_round_trip_by_type() {
        let records = vec![rebuild_row(
            Some(42),
            vec![
                Value::Null,
                Value::Integer(30),
                Value::Real(1.5),
                Value::Text("hello".into()),
            ],
        )];
        let buf = build_recovered_xlsx(&records, None).unwrap();
        let mut wb = open_xlsx(&buf);
        let recs = wb.worksheet_range("recovered_records").unwrap();
        // Row 0 is the header; row 1 is the data row.
        let row: Vec<&Data> = recs.rows().nth(1).unwrap().iter().collect();
        // Lead cols: _page=3, _offset=128, _rowid=42, _source, _confidence.
        assert_eq!(*row[0], Data::Float(3.0));
        assert_eq!(
            *row[2],
            Data::Float(42.0),
            "integer rowid is a numeric cell"
        );
        assert_eq!(*row[3], Data::String("freelist-page".into()));
        // Cells c0..c3: Null (empty), Integer, Real, Text.
        assert_eq!(*row[5], Data::Empty, "Null renders as an empty cell");
        assert_eq!(*row[6], Data::Float(30.0), "Integer is a numeric cell");
        assert_eq!(*row[7], Data::Float(1.5), "Real is a numeric cell");
        assert_eq!(
            *row[8],
            Data::String("hello".into()),
            "Text is a string cell"
        );
    }

    #[test]
    fn xlsx_video_blob_shows_typed_placeholder() {
        // An MP4 BLOB cell must render the `video/<ext> · <size>` placeholder
        // string — first-frame extraction is deferred.
        let mut mp4 = b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isom".to_vec();
        mp4.resize(4_404_019, 0); // pad to ~4.2 MB so the size string is meaningful
        let records = vec![rebuild_row(Some(1), vec![Value::Blob(mp4)])];
        let buf = build_recovered_xlsx(&records, None).unwrap();
        let mut wb = open_xlsx(&buf);
        let recs = wb.worksheet_range("recovered_records").unwrap();
        let cell = recs.rows().nth(1).unwrap()[5].to_string();
        assert_eq!(cell, "video/mp4 · 4.2 MB", "typed video placeholder");
    }

    #[test]
    fn xlsx_other_blob_shows_byte_placeholder() {
        let records = vec![rebuild_row(Some(1), vec![Value::Blob(vec![1, 2, 3])])];
        let buf = build_recovered_xlsx(&records, None).unwrap();
        let mut wb = open_xlsx(&buf);
        let recs = wb.worksheet_range("recovered_records").unwrap();
        let cell = recs.rows().nth(1).unwrap()[5].to_string();
        assert_eq!(cell, "<blob:3 bytes>");
    }

    #[test]
    fn xlsx_image_blob_is_embedded_as_media() {
        // An image BLOB must end up as embedded media inside the xlsx zip
        // (calamine does not surface embedded images, so assert on the zip).
        let png = rgb_png(40, 40);
        let records = vec![rebuild_row(Some(1), vec![Value::Blob(png)])];
        let buf = build_recovered_xlsx(&records, None).unwrap();
        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(buf)).unwrap();
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
        assert!(media, "an embedded image must appear under xl/media/*.png");
    }

    #[test]
    fn xlsx_corrupt_image_blob_falls_back_to_placeholder() {
        // Bytes whose PNG signature is present but body is undecodable must NOT
        // be embedded; the cell falls back to the <blob:N bytes> placeholder.
        let bad = vec![0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0];
        let records = vec![rebuild_row(Some(1), vec![Value::Blob(bad.clone())])];
        let buf = build_recovered_xlsx(&records, None).unwrap();
        let mut wb = open_xlsx(&buf);
        let recs = wb.worksheet_range("recovered_records").unwrap();
        let cell = recs.rows().nth(1).unwrap()[5].to_string();
        assert_eq!(cell, format!("<blob:{} bytes>", bad.len()));
    }

    #[test]
    fn recovered_xlsx_bytes_returns_buffer_for_valid_rows() {
        // The String-returning façade yields the same valid xlsx buffer for valid
        // input (the error mapping is keyed by the destination path).
        let records = vec![rebuild_row(Some(1), vec![Value::Integer(7)])];
        let buf =
            recovered_xlsx_bytes(&records, None, Path::new("/out/foo.recovered.xlsx")).unwrap();
        let wb = open_xlsx(&buf);
        assert!(wb.sheet_names().iter().any(|n| n == "recovered_records"));
    }

    #[test]
    fn recovered_xlsx_bytes_maps_build_error_to_string() {
        // A record wider than Excel's 16,384-column limit makes the builder emit
        // an XlsxError; the façade maps it to an actionable, path-keyed string
        // (exercising the error arm — a real in-domain limit, not a contrived
        // failure). The lead columns push the cell columns past the limit.
        let huge = vec![Value::Integer(0); 17_000];
        let records = vec![rebuild_row(Some(1), huge)];
        let err = recovered_xlsx_bytes(&records, None, Path::new("/out/wide.xlsx"))
            .expect_err("an over-wide record must fail the build");
        assert!(
            err.contains("recovered xlsx") && err.contains("wide.xlsx"),
            "the error is path-keyed and actionable: {err}"
        );
    }

    #[test]
    fn xlsx_empty_records_still_builds_with_header() {
        // No records: the sheet still exists with the lead-column header.
        let buf = build_recovered_xlsx(&[], None).unwrap();
        let mut wb = open_xlsx(&buf);
        let recs = wb.worksheet_range("recovered_records").unwrap();
        let header: Vec<String> = recs
            .rows()
            .next()
            .unwrap()
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        assert_eq!(
            header,
            vec!["_page", "_offset", "_rowid", "_source", "_confidence"]
        );
    }

    // ---- routing recovered records into live-table buckets -----------------

    /// Tier-1 Known routes to its table (certain: `is_guessed=0`); Tier-2
    /// Inferred routes to the guessed table (`is_guessed=1`, carrying ambiguity);
    /// Tier-3 Unattributed and an inferred guess with no live sheet both land in
    /// the unattributed bucket. A destroyed rowid (0) becomes `None`.
    #[test]
    fn route_recovered_buckets_by_attribution_tier() {
        let live_names = vec!["people".to_string(), "notes".to_string()];
        let records = vec![
            rec(
                5,
                0.9,
                RecoverySource::InPageFreeBlock,
                vec![Value::Integer(5)],
            ),
            rec(
                7,
                0.8,
                RecoverySource::FreelistPage,
                vec![Value::Integer(7)],
            ),
            rec(
                0,
                0.6,
                RecoverySource::DroppedTable,
                vec![Value::Integer(0)],
            ),
            // Inferred guess to a table with no live sheet → unattributed.
            rec(
                9,
                0.5,
                RecoverySource::FreelistPage,
                vec![Value::Integer(9)],
            ),
        ];
        let attrs = vec![
            Attribution::Known("people".to_string()),
            Attribution::Inferred {
                guess: "notes".to_string(),
                ambiguous: true,
            },
            Attribution::Unattributed,
            Attribution::Inferred {
                guess: "ghost".to_string(),
                ambiguous: false,
            },
        ];
        let routed = route_recovered(&live_names, &records, &attrs);

        let people = routed.by_table.get("people").expect("people bucket");
        assert_eq!(people.len(), 1);
        assert_eq!(people[0].rowid, Some(5));
        assert!(!people[0].is_guessed, "Tier-1 certain");

        let notes = routed.by_table.get("notes").expect("notes bucket");
        assert_eq!(notes.len(), 1);
        assert!(notes[0].is_guessed, "Tier-2 inferred");
        assert!(notes[0].ambiguous, "ambiguity carried");

        // Tier-3 (index 2) and the ghost-guess (index 3) are unattributed.
        assert_eq!(routed.unattributed, vec![2, 3]);
    }

    /// A destroyed rowid (0) routes to its bucket with `rowid: None` so the
    /// merge step sinks it to the bottom of the sheet.
    #[test]
    fn route_recovered_destroyed_rowid_is_none() {
        let live_names = vec!["people".to_string()];
        let records = vec![rec(
            0,
            0.9,
            RecoverySource::InPageFreeBlock,
            vec![Value::Integer(1)],
        )];
        let attrs = vec![Attribution::Known("people".to_string())];
        let routed = route_recovered(&live_names, &records, &attrs);
        assert_eq!(routed.by_table["people"][0].rowid, None);
    }

    // ---- combined workbook renderer (tint + flags + image embed) -----------

    fn sample_commit_id() -> sqlite_core::CommitId {
        sqlite_core::CommitId {
            segment: sqlite_core::WalSegmentId(0),
            commit_frame_index: 2,
            db_size_after_commit: 4,
        }
    }

    #[test]
    fn combined_fill_marks_guessed_yellow_and_certain_red() {
        // A guessed (Tier-2 inferred) row tints pale yellow; a certain recovered
        // row pale red; a live row is left unfilled. (5-arg precedence form: no
        // reuse, no superseding.)
        assert_eq!(fill_for(false, false, false, false), None);
        assert_eq!(fill_for(false, false, true, false), Some(RECOVERED_FILL));
        assert_eq!(fill_for(false, true, true, false), Some(GUESSED_FILL));
    }

    #[test]
    fn fill_for_five_level_precedence() {
        // Precedence (highest first):
        //   1 rowid_reused → purple (overrides everything: rowid may span entities)
        //   2 is_guessed   → yellow
        //   3 is_deleted   → red
        //   4 superseded   → blue
        //   5 otherwise    → none
        // (1) reused wins over guessed/deleted/superseded all set.
        assert_eq!(
            fill_for(true, true, true, true),
            Some(REUSED_FILL),
            "rowid_reused has highest precedence"
        );
        // (2) guessed wins over deleted + superseded.
        assert_eq!(
            fill_for(false, true, true, true),
            Some(GUESSED_FILL),
            "is_guessed beats deleted/superseded"
        );
        // (3) deleted wins over superseded.
        assert_eq!(
            fill_for(false, false, true, true),
            Some(RECOVERED_FILL),
            "is_deleted beats superseded"
        );
        // (4) superseded alone → blue.
        assert_eq!(
            fill_for(false, false, false, true),
            Some(SUPERSEDED_FILL),
            "superseded historical → blue"
        );
        // (5) nothing set → no fill (live current / present).
        assert_eq!(fill_for(false, false, false, false), None);
    }

    #[test]
    fn view_state_tokens_are_stable() {
        use sqlite_core::row_history::ViewState;
        assert_eq!(view_state_token(ViewState::PresentInFinalView), "present");
        assert_eq!(
            view_state_token(ViewState::ValueChangedLater),
            "changed_later"
        );
        assert_eq!(
            view_state_token(ViewState::AbsentInFinalView),
            "absent_final"
        );
        assert_eq!(view_state_token(ViewState::CarvedResidue), "carved_residue");
    }

    #[test]
    fn wal_commit_token_renders_origin() {
        use sqlite_core::row_history::VersionOrigin;
        use sqlite_core::WalLsn;
        // Live → "live".
        assert_eq!(wal_commit_token(&VersionOrigin::Live, None), "live");
        // CarvedResidue → "residue".
        assert_eq!(
            wal_commit_token(&VersionOrigin::CarvedResidue, None),
            "residue"
        );
        // A Commit resolves to commit:(salt1,salt2,frame_index) from its LSN.
        let lsn = WalLsn {
            salt1: 3_131_615_003,
            salt2: 3_836_839_008,
            frame_index: 2,
        };
        let origin = VersionOrigin::Commit(sample_commit_id());
        assert_eq!(
            wal_commit_token(&origin, Some(lsn)),
            "commit:(3131615003,3836839008,2)"
        );
        // A Commit whose LSN could not be resolved degrades to a stable label,
        // never a panic.
        assert_eq!(wal_commit_token(&origin, None), "commit:?");
    }

    // ---- TableHistory → temporal sheet plan (pure) -------------------------

    use sqlite_core::row_history::{RowVersion, TableHistory, VersionOrigin, ViewState};

    // A test constructor mirroring RowVersion's fields 1:1; the bool/arity lints are
    // noise on a flat field-by-field builder.
    #[allow(clippy::fn_params_excessive_bools, clippy::too_many_arguments)]
    fn version(
        rowid: Option<i64>,
        values: Vec<Value>,
        origin: VersionOrigin,
        commit_seq: Option<u32>,
        view_state: ViewState,
        is_deleted: bool,
        is_guessed: bool,
        rowid_reused: bool,
        attribution_uncertain: bool,
    ) -> RowVersion {
        RowVersion {
            rowid,
            values,
            origin,
            commit_seq,
            view_state,
            is_deleted,
            is_guessed,
            rowid_reused,
            attribution_uncertain,
        }
    }

    fn no_lsn(_: &sqlite_core::CommitId) -> Option<sqlite_core::WalLsn> {
        None
    }

    /// A `risk_token` lookup that never reports a `table_instance_risk` (the
    /// common case: a sheet whose rows carry no AUTOINCREMENT-high-water hint).
    fn no_risk(_: i64) -> String {
        String::new()
    }

    #[test]
    fn temporal_sheet_header_appends_flag_columns() {
        let h = TableHistory {
            table: "t".to_string(),
            columns: vec!["id".to_string(), "name".to_string()],
            without_rowid: false,
            versions: vec![],
        };
        let (sheet, dropped) = temporal_sheet(&h, no_lsn, no_risk, EXCEL_MAX_ROWS);
        assert_eq!(dropped, 0);
        assert_eq!(
            sheet.columns,
            [
                "id",
                "name",
                "_rowid",
                "wal_commit",
                "commit_seq",
                "view_state",
                "is_deleted",
                "is_guessed",
                "rowid_reused",
                "attribution_uncertain",
                "_table_instance_risk",
            ]
            .map(String::from)
        );
        assert_eq!(sheet.name, "t");
        assert!(sheet.rows.is_empty(), "no versions → no data rows");
    }

    #[test]
    fn temporal_sheet_without_rowid_emits_single_annotation_row() {
        let h = TableHistory {
            table: "idx_tbl".to_string(),
            columns: vec!["k".to_string()],
            without_rowid: true,
            versions: vec![],
        };
        let (sheet, _) = temporal_sheet(&h, no_lsn, no_risk, EXCEL_MAX_ROWS);
        assert_eq!(sheet.rows.len(), 1, "exactly one annotation row");
        let note = &sheet.rows[0].cells[0];
        assert_eq!(
            *note,
            Value::Text("WITHOUT ROWID — not version-tracked".to_string()),
            "annotation note in the first cell"
        );
    }

    #[test]
    fn temporal_sheet_row_carries_temporal_and_flag_cells() {
        // A changed_later historical version of rowid 1 from a commit.
        let v = version(
            Some(1),
            vec![Value::Integer(1), Value::Text("a".into())],
            VersionOrigin::Commit(sample_commit_id()),
            Some(7),
            ViewState::ValueChangedLater,
            false,
            false,
            false,
            false,
        );
        let h = TableHistory {
            table: "t".to_string(),
            columns: vec!["id".to_string(), "name".to_string()],
            without_rowid: false,
            versions: vec![v],
        };
        let resolve = |_: &sqlite_core::CommitId| {
            Some(sqlite_core::WalLsn {
                salt1: 11,
                salt2: 22,
                frame_index: 3,
            })
        };
        let (sheet, _) = temporal_sheet(&h, resolve, no_risk, EXCEL_MAX_ROWS);
        assert_eq!(sheet.rows.len(), 1);
        let cells = &sheet.rows[0].cells;
        // Real columns first.
        assert_eq!(cells[0], Value::Integer(1));
        assert_eq!(cells[1], Value::Text("a".into()));
        // _rowid, wal_commit, commit_seq, view_state, then the 4 flags.
        assert_eq!(cells[2], Value::Integer(1));
        assert_eq!(cells[3], Value::Text("commit:(11,22,3)".into()));
        assert_eq!(cells[4], Value::Integer(7));
        assert_eq!(cells[5], Value::Text("changed_later".into()));
        assert_eq!(cells[6], Value::Integer(0)); // is_deleted
        assert_eq!(cells[7], Value::Integer(0)); // is_guessed
        assert_eq!(cells[8], Value::Integer(0)); // rowid_reused
        assert_eq!(cells[9], Value::Integer(0)); // attribution_uncertain
                                                 // A ValueChangedLater version is superseded → blue.
        let row = &sheet.rows[0];
        assert!(row.superseded);
        assert!(!row.is_deleted && !row.is_guessed && !row.rowid_reused);
    }

    #[test]
    fn temporal_sheet_blank_commit_seq_and_none_rowid() {
        // A carved-residue version: rowid None, commit_seq None, residue token.
        let v = version(
            None,
            vec![Value::Text("ghost".into())],
            VersionOrigin::CarvedResidue,
            None,
            ViewState::CarvedResidue,
            true,
            true,
            false,
            true,
        );
        let h = TableHistory {
            table: "t".to_string(),
            columns: vec!["name".to_string()],
            without_rowid: false,
            versions: vec![v],
        };
        let (sheet, _) = temporal_sheet(&h, no_lsn, no_risk, EXCEL_MAX_ROWS);
        let cells = &sheet.rows[0].cells;
        assert_eq!(cells[0], Value::Text("ghost".into()));
        assert_eq!(cells[1], Value::Null, "None rowid → blank _rowid");
        assert_eq!(cells[2], Value::Text("residue".into()));
        assert_eq!(cells[3], Value::Null, "None commit_seq → blank");
        assert_eq!(cells[4], Value::Text("carved_residue".into()));
        assert_eq!(cells[5], Value::Integer(1)); // is_deleted
        assert_eq!(cells[6], Value::Integer(1)); // is_guessed
        assert_eq!(cells[7], Value::Integer(0)); // rowid_reused
        assert_eq!(cells[8], Value::Integer(1)); // attribution_uncertain
    }

    #[test]
    fn temporal_sheet_commit_with_unresolved_lsn_degrades() {
        // A Commit-origin version whose LSN the resolver cannot resolve degrades
        // its wal_commit to `commit:?` (never a panic), exercising the resolver
        // call + the wal_commit_token None-lsn fallback.
        let v = version(
            Some(9),
            vec![Value::Integer(9)],
            VersionOrigin::Commit(sample_commit_id()),
            Some(3),
            ViewState::AbsentInFinalView,
            true,
            false,
            false,
            false,
        );
        let h = TableHistory {
            table: "t".to_string(),
            columns: vec!["id".to_string()],
            without_rowid: false,
            versions: vec![v],
        };
        let (sheet, _) = temporal_sheet(&h, no_lsn, no_risk, EXCEL_MAX_ROWS);
        // _rowid, wal_commit cells.
        assert_eq!(sheet.rows[0].cells[1], Value::Integer(9));
        assert_eq!(sheet.rows[0].cells[2], Value::Text("commit:?".into()));
    }

    #[test]
    fn temporal_sheet_truncates_to_row_cap() {
        let versions: Vec<RowVersion> = (0..5)
            .map(|i| {
                version(
                    Some(i),
                    vec![Value::Integer(i)],
                    VersionOrigin::Live,
                    None,
                    ViewState::PresentInFinalView,
                    false,
                    false,
                    false,
                    false,
                )
            })
            .collect();
        let h = TableHistory {
            table: "t".to_string(),
            columns: vec!["id".to_string()],
            without_rowid: false,
            versions,
        };
        let (sheet, dropped) = temporal_sheet(&h, no_lsn, no_risk, 2);
        assert_eq!(sheet.rows.len(), 2);
        assert_eq!(dropped, 3);
    }

    /// A [`TemporalRow`] with the given cells and tint inputs (all false unless set).
    fn temporal_row(cells: Vec<Value>, is_deleted: bool, superseded: bool) -> TemporalRow {
        TemporalRow {
            cells,
            rowid_reused: false,
            is_guessed: false,
            is_deleted,
            superseded,
        }
    }

    /// The temporal renderer writes one sheet per [`TemporalSheet`] plus the extra
    /// (unattributed / fragments) tables, carrying the real header + the eight
    /// temporal/flag columns.
    #[test]
    fn combined_renderer_writes_temporal_and_extra_sheets() {
        let people = TemporalSheet {
            name: "people".to_string(),
            columns: {
                let mut c = vec!["id".to_string(), "name".to_string()];
                c.extend(TEMPORAL_FLAG_COLS.iter().map(|s| (*s).to_string()));
                c
            },
            rows: vec![
                // A present (live) row, untinted.
                temporal_row(
                    vec![
                        Value::Integer(1),
                        Value::Text("live".into()),
                        Value::Integer(1),
                        Value::Text("live".into()),
                        Value::Null,
                        Value::Text("present".into()),
                        Value::Integer(0),
                        Value::Integer(0),
                        Value::Integer(0),
                        Value::Integer(0),
                    ],
                    false,
                    false,
                ),
                // A deleted (absent_final) row, tinted red.
                temporal_row(
                    vec![
                        Value::Integer(2),
                        Value::Text("gone".into()),
                        Value::Integer(2),
                        Value::Text("commit:(1,2,0)".into()),
                        Value::Integer(0),
                        Value::Text("absent_final".into()),
                        Value::Integer(1),
                        Value::Integer(0),
                        Value::Integer(0),
                        Value::Integer(0),
                    ],
                    true,
                    false,
                ),
            ],
        };
        let extra = vec![RecoveredTable {
            name: "recovered_unattributed".to_string(),
            columns: vec!["c0".to_string()],
            rows: vec![vec![Value::Integer(7)]],
        }];
        let buf = render_combined_xlsx(&[people], &extra).unwrap();
        let mut wb = open_xlsx(&buf);
        let names = wb.sheet_names();
        assert!(names.iter().any(|n| n == "people"), "{names:?}");
        assert!(
            names.iter().any(|n| n == "recovered_unattributed"),
            "{names:?}"
        );

        let sheet = wb.worksheet_range("people").unwrap();
        let header: Vec<String> = sheet
            .rows()
            .next()
            .unwrap()
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        assert!(header.iter().any(|h| h == "wal_commit"), "{header:?}");
        assert!(header.iter().any(|h| h == "view_state"), "{header:?}");
        assert!(header.iter().any(|h| h == "rowid_reused"), "{header:?}");
        // The deleted row's view_state cell reads absent_final.
        assert_eq!(
            sheet.rows().nth(2).unwrap()[5],
            Data::String("absent_final".into())
        );
    }

    /// A BLOB image in a temporal version row is embedded as media (a live,
    /// historical, OR carved image embeds in-cell).
    #[test]
    fn combined_renderer_embeds_image_blob() {
        let png = rgb_png(40, 40);
        let mut cells = vec![Value::Blob(png)];
        // The eight temporal/flag cells after the one real column.
        cells.extend([
            Value::Integer(1),
            Value::Text("live".into()),
            Value::Null,
            Value::Text("present".into()),
            Value::Integer(0),
            Value::Integer(0),
            Value::Integer(0),
            Value::Integer(0),
        ]);
        let sheet = TemporalSheet {
            name: "photos".to_string(),
            columns: {
                let mut c = vec!["img".to_string()];
                c.extend(TEMPORAL_FLAG_COLS.iter().map(|s| (*s).to_string()));
                c
            },
            rows: vec![temporal_row(cells, false, false)],
        };
        let buf = render_combined_xlsx(&[sheet], &[]).unwrap();
        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(buf)).unwrap();
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
        assert!(media, "an image BLOB must embed under xl/media/*.png");
    }

    // ---- combined workbook planner (db → sheets + extra + drops) ------------

    /// Mint a tiny valid db with a `people(id, name)` live table holding one live
    /// row, so the planner can be driven against a real `Database`.
    fn minted_people_db() -> Database {
        use sqlite_core::rebuild::{build_recovered_db_tables, RecoveredTable as RT};
        let seed = vec![RT {
            name: "people".to_string(),
            columns: vec!["id".to_string(), "name".to_string()],
            rows: vec![vec![Value::Integer(1), Value::Text("live".into())]],
        }];
        Database::open(build_recovered_db_tables(&seed)).expect("minted db opens")
    }

    /// Mint a `people(id, name)` db with `n` live rows, so the temporal planner has
    /// a history of `n` present versions to plan against.
    fn minted_people_db_n(n: i64) -> Database {
        use sqlite_core::rebuild::{build_recovered_db_tables, RecoveredTable as RT};
        let rows = (1..=n)
            .map(|i| vec![Value::Integer(i), Value::Text(format!("p{i}"))])
            .collect();
        let seed = vec![RT {
            name: "people".to_string(),
            columns: vec!["id".to_string(), "name".to_string()],
            rows,
        }];
        Database::open(build_recovered_db_tables(&seed)).expect("minted db opens")
    }

    /// The temporal planner produces one VERSION-HISTORY sheet per live table whose
    /// header carries the real columns plus the eight temporal/flag columns, and
    /// one row per live version (the minted db has no deletions, so each row is a
    /// present/live version).
    #[test]
    fn plan_combined_workbook_builds_temporal_sheet_per_table() {
        let db = minted_people_db();
        let plan = plan_combined_workbook(
            &db,
            &[],
            None,
            None,
            &std::collections::BTreeMap::new(),
            EXCEL_MAX_ROWS,
        );

        let people = plan
            .sheets
            .iter()
            .find(|s| s.name == "people")
            .expect("people version-history sheet");
        // Real header + the eight temporal/flag columns.
        assert_eq!(people.columns[0], "id");
        assert_eq!(people.columns[1], "name");
        assert_eq!(&people.columns[2..], &TEMPORAL_FLAG_COLS);
        // One live (present) version, untinted.
        assert_eq!(people.rows.len(), 1);
        let r = &people.rows[0];
        assert!(!r.is_deleted && !r.is_guessed && !r.rowid_reused && !r.superseded);
        assert!(
            plan.extra.is_empty(),
            "no residue, no fragments → no extra tables"
        );
        assert!(plan.dropped.is_empty(), "no truncation under the full cap");
    }

    /// A Tier-3 (dropped-table) record with no shape match becomes a row in the
    /// separate `recovered_unattributed` extra table, never folded into a history.
    #[test]
    fn plan_combined_workbook_unattributed_goes_to_extra_table() {
        let db = minted_people_db();
        // A 4-column dropped-table record matches no surviving table → Tier-3.
        let records = vec![rec(
            0,
            0.5,
            RecoverySource::DroppedTable,
            vec![
                Value::Text("a".into()),
                Value::Text("b".into()),
                Value::Text("c".into()),
                Value::Text("d".into()),
            ],
        )];
        let plan = plan_combined_workbook(
            &db,
            &records,
            None,
            None,
            &std::collections::BTreeMap::new(),
            EXCEL_MAX_ROWS,
        );
        let extra_names: Vec<&String> = plan.extra.iter().map(|t| &t.name).collect();
        assert!(
            extra_names.iter().any(|n| *n == "recovered_unattributed"),
            "Tier-3 lands in recovered_unattributed: {extra_names:?}"
        );
        // The people sheet has only its one live version (no fold of the Tier-3).
        let people = plan.sheets.iter().find(|s| s.name == "people").unwrap();
        assert_eq!(people.rows.len(), 1);
        assert!(!people.rows[0].is_deleted);
    }

    /// A `row_cap` below a table's version count truncates the sheet and records
    /// the drop as `(table, dropped_count)` so the shell can warn.
    #[test]
    fn plan_combined_workbook_reports_row_cap_drops() {
        // Three live rows → three present versions; cap at 1 → 2 dropped.
        let db = minted_people_db_n(3);
        let plan =
            plan_combined_workbook(&db, &[], None, None, &std::collections::BTreeMap::new(), 1);
        let drop = plan
            .dropped
            .iter()
            .find(|(name, _)| name == "people")
            .expect("people drop recorded");
        assert_eq!(drop.1, 2, "two data rows dropped past the cap of 1");
    }

    /// The row-cap warning names the table and the dropped count.
    #[test]
    fn row_cap_warning_names_table_and_count() {
        let w = row_cap_warning("people", 7, EXCEL_MAX_ROWS);
        assert!(w.contains("people"), "names the table: {w}");
        assert!(w.contains('7'), "names the dropped count: {w}");
        assert!(
            w.contains(&EXCEL_MAX_ROWS.to_string()),
            "names the cap: {w}"
        );
    }

    /// `combined_xlsx_bytes` builds a valid workbook and, at a small injected cap,
    /// drives the truncation-warning path (a drop occurs) without a million-row
    /// carve. The produced bytes still open in calamine.
    #[test]
    fn combined_xlsx_bytes_builds_and_warns_at_small_cap() {
        // Two live rows → two present versions; cap of 1 truncates the people
        // version-history sheet, exercising the dropped-row warning loop.
        let db = minted_people_db_n(2);
        let buf = combined_xlsx_bytes(
            &db,
            &[],
            None,
            None,
            &std::collections::BTreeMap::new(),
            Path::new("/out/x.recovered.xlsx"),
            1,
        )
        .unwrap();
        assert!(!buf.is_empty());
        let _ = open_xlsx(&buf);
    }

    /// `combined_xlsx_bytes` maps an `XlsxError` to a path-keyed string. A Tier-3
    /// record far wider than Excel's column limit makes the `recovered_unattributed`
    /// sheet fail to render, exercising the error arm.
    #[test]
    fn combined_xlsx_bytes_maps_render_error_to_path() {
        let db = minted_people_db();
        // A dropped-table record with > Excel's 16384 columns: unattributed (it
        // cannot shape-match the 2-column `people`), so it becomes a too-wide
        // recovered_unattributed sheet the writer rejects.
        let wide = (0..20_000).map(Value::Integer).collect();
        let records = vec![rec(0, 0.5, RecoverySource::DroppedTable, wide)];
        let err = combined_xlsx_bytes(
            &db,
            &records,
            None,
            None,
            &std::collections::BTreeMap::new(),
            Path::new("/out/wide.recovered.xlsx"),
            EXCEL_MAX_ROWS,
        )
        .unwrap_err();
        assert!(
            err.contains("recovered xlsx") && err.contains("wide.recovered.xlsx"),
            "error maps to a path-keyed string: {err}"
        );
    }
}
