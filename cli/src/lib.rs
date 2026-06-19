#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Pure decision helpers for the `sqlite4n6` CLI (the Humble Object / functional
//! core). Every decision that can be made without I/O — output-format and
//! confidence-threshold parsing, projecting a carved record or an anomaly into a
//! row of string cells, confidence filtering, rowid-only projection, and the
//! table/CSV/JSONL rendering of both surfaces — lives here so it is directly
//! unit-testable. `main()` is the thin shell that only reads the evidence file
//! and writes the rendered lines to stdout.

use sqlite_core::{Database, Value, WalTimeline};
use sqlite_forensic::{
    carve_all_deleted_records, carve_at_commit, Anomaly, CarvedFragment, CarvedRecord,
    RecoverySource,
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
    let parts: Vec<String> = values
        .iter()
        .map(|v| format!("\"{}\"", json_escape(&value_to_cell(v))))
        .collect();
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
    // Rank: commit snapshot (earliest) < wal-frame < on-disk; tie-break high conf.
    fn rank(rec: &CarvedRecord) -> u8 {
        match rec.source {
            RecoverySource::CommitSnapshot => 0,
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
    format: OutputFormat,
    rowid_only: bool,
) -> Vec<String> {
    if rowid_only {
        return records.iter().map(|r| rowid_cell(r.rowid)).collect();
    }
    match format {
        OutputFormat::Table => render_carve_table(records),
        OutputFormat::Csv => render_carve_csv(records),
        OutputFormat::Jsonl => render_carve_jsonl(records),
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

fn render_carve_jsonl(records: &[CarvedRecord]) -> Vec<String> {
    records
        .iter()
        .map(|rec| {
            format!(
                "{{\"page\":{},\"offset\":{},\"rowid\":{},\"recovery_source\":\"{}\",\"confidence\":{:.4},\"values\":{}}}",
                rec.page,
                rec.offset,
                rec.rowid,
                recovery_source_token(rec.source),
                rec.confidence,
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
    let mut lines = render_carve(full, format, false);
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
    format: OutputFormat,
    rowid_only: bool,
) -> Vec<String> {
    if rowid_only {
        return records.iter().map(|r| rowid_cell(r.rowid)).collect();
    }
    match format {
        OutputFormat::Table => render_carve_snapshot_table(records),
        OutputFormat::Csv => render_carve_snapshot_csv(records),
        OutputFormat::Jsonl => render_carve_snapshot_jsonl(records),
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

fn render_carve_snapshot_jsonl(records: &[CarvedRecord]) -> Vec<String> {
    records
        .iter()
        .map(|rec| {
            format!(
                "{{\"page\":{},\"offset\":{},\"rowid\":{},\"recovery_source\":\"{}\",\"confidence\":{:.4},\"snapshot\":\"{}\",\"values\":{}}}",
                rec.page,
                rec.offset,
                rec.rowid,
                recovery_source_token(rec.source),
                rec.confidence,
                json_escape(&snapshot_label(rec)),
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
        let lines = render_carve(&records, OutputFormat::Csv, true);
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
        let lines = render_carve(&records, OutputFormat::Csv, false);
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
        let lines = render_carve(&records, OutputFormat::Csv, false);
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
        let lines = render_carve(&records, OutputFormat::Jsonl, false);
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
        let lines = render_carve(&records, OutputFormat::Jsonl, false);
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
        let lines = render_carve(&records, OutputFormat::Table, false);
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
        let lines = render_carve_with_snapshot(&records, OutputFormat::Table, false);
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
        let lines = render_carve_with_snapshot(&records, OutputFormat::Csv, false);
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
        let lines = render_carve_with_snapshot(&records, OutputFormat::Jsonl, false);
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
        let lines = render_carve_with_snapshot(&records, OutputFormat::Jsonl, true);
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
        let plain = render_carve(&records, OutputFormat::Jsonl, false);
        let tiered = render_carve_tiered(&records, &[], OutputFormat::Jsonl, false);
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
        let lines = render_carve_tiered(&records, &[frag()], OutputFormat::Csv, false);
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
        let lines = render_carve_tiered(&records, &[frag()], OutputFormat::Table, true);
        assert_eq!(lines, vec!["7".to_string()]);
    }
}
