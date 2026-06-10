#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
//! Pure decision helpers for the `sqlite4n6` CLI (the Humble Object / functional
//! core). Every decision that can be made without I/O — output-format and
//! confidence-threshold parsing, projecting a carved record or an anomaly into a
//! row of string cells, confidence filtering, rowid-only projection, and the
//! table/CSV/JSONL rendering of both surfaces — lives here so it is directly
//! unit-testable. `main()` is the thin shell that only reads the evidence file
//! and writes the rendered lines to stdout.

use sqlite_core::Value;
use sqlite_forensic::{Anomaly, CarvedRecord, RecoverySource};

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
}
