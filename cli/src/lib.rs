#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
#![allow(unused_variables, clippy::needless_pass_by_value)]
//! Pure decision helpers for the `sqlite4n6` CLI (the Humble Object / functional
//! core). RED skeleton: the decision functions are stubbed so the unit tests in
//! this module fail; the GREEN commit fills in the real projection / filtering /
//! rendering logic.

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

/// Minimum confidence threshold for `carve --min-confidence`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum MinConfidence {
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl MinConfidence {
    /// The lower bound a carved record's `confidence` must meet for this level.
    #[must_use]
    pub fn threshold(self) -> f32 {
        0.0
    }
}

/// Render a [`RecoverySource`] as a stable token.
#[must_use]
pub fn recovery_source_token(source: RecoverySource) -> &'static str {
    ""
}

/// Render one decoded column [`Value`] as a single output cell.
#[must_use]
pub fn value_to_cell(value: &Value) -> String {
    String::new()
}

/// The rowid cell for a carved record (`?` when unknown/destroyed).
#[must_use]
pub fn rowid_cell(rowid: i64) -> String {
    String::new()
}

/// Keep only carved records whose confidence meets the threshold.
#[must_use]
pub fn filter_by_confidence(records: Vec<CarvedRecord>, min: MinConfidence) -> Vec<CarvedRecord> {
    records
}

/// CSV escape.
#[must_use]
pub fn csv_escape(s: &str) -> String {
    s.to_string()
}

/// JSON-escape a string for the hand-rolled JSONL writer.
#[must_use]
pub fn json_escape(s: &str) -> String {
    s.to_string()
}

/// Render carved records as full output lines in the chosen format.
#[must_use]
pub fn render_carve(records: &[CarvedRecord], format: OutputFormat, rowid_only: bool) -> Vec<String> {
    Vec::new()
}

/// Render the severity of an anomaly as a stable token.
#[must_use]
pub fn severity_token(severity: forensicnomicon::report::Severity) -> &'static str {
    ""
}

/// A short human location string for an anomaly, derived from its evidence.
#[must_use]
pub fn anomaly_location(anomaly: &Anomaly) -> String {
    String::new()
}

/// Render audited anomalies as full output lines in the chosen format.
#[must_use]
pub fn render_audit(anomalies: &[Anomaly], format: OutputFormat) -> Vec<String> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlite_forensic::AnomalyKind;

    fn rec(rowid: i64, confidence: f32, source: RecoverySource, values: Vec<Value>) -> CarvedRecord {
        CarvedRecord {
            page: 3,
            offset: 128,
            rowid,
            values,
            confidence,
            allocated: false,
            source,
        }
    }

    #[test]
    fn min_confidence_thresholds_are_monotonic() {
        assert!(MinConfidence::Info.threshold() < MinConfidence::Low.threshold());
        assert!(MinConfidence::Low.threshold() < MinConfidence::Medium.threshold());
        assert!(MinConfidence::Medium.threshold() < MinConfidence::High.threshold());
        assert!(MinConfidence::High.threshold() < MinConfidence::Critical.threshold());
        assert_eq!(MinConfidence::Info.threshold(), 0.0);
    }

    #[test]
    fn recovery_source_tokens_are_stable() {
        assert_eq!(recovery_source_token(RecoverySource::FreelistPage), "freelist-page");
        assert_eq!(
            recovery_source_token(RecoverySource::FreeblockReconstructed),
            "freeblock-reconstructed"
        );
        assert_eq!(recovery_source_token(RecoverySource::PriorVersion), "prior-version");
    }

    #[test]
    fn value_cells_render_each_storage_class() {
        assert_eq!(value_to_cell(&Value::Null), "NULL");
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
            rec(5, 0.9, RecoverySource::FreelistPage, vec![Value::Text("x".into())]),
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
        assert_eq!(lines[0], "page,offset,rowid,recovery_source,confidence,values");
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
            rec(5, 0.9, RecoverySource::FreelistPage, vec![Value::Integer(1)]),
            rec(0, 0.4, RecoverySource::FreeblockReconstructed, vec![Value::Null]),
        ];
        let lines = render_carve(&records, OutputFormat::Jsonl, false);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("{\"page\":3"), "{}", lines[0]);
        assert!(lines[0].contains("\"recovery_source\":\"freelist-page\""), "{}", lines[0]);
        assert!(lines[0].contains("\"rowid\":5"), "{}", lines[0]);
        assert!(lines[1].contains("\"rowid\":0"), "{}", lines[1]);
    }

    #[test]
    fn carve_table_has_header() {
        let records = vec![rec(1, 0.9, RecoverySource::FreelistPage, vec![])];
        let lines = render_carve(&records, OutputFormat::Table, false);
        assert!(lines[0].contains("page"));
        assert!(lines[0].contains("recovery_source"));
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn json_escape_handles_quotes_and_controls() {
        assert_eq!(json_escape("a\"b"), "a\\\"b");
        assert_eq!(json_escape("a\nb"), "a\\nb");
        assert_eq!(json_escape("\u{0001}"), "\\u0001");
    }

    fn anomaly() -> Anomaly {
        Anomaly::new(AnomalyKind::NonEmptyFreelist { free_pages: 4 })
    }

    #[test]
    fn severity_tokens_are_stable() {
        use forensicnomicon::report::Severity;
        assert_eq!(severity_token(Severity::Info), "INFO");
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
        assert!(lines[1].contains("SQLITE-FREELIST-NONEMPTY"), "{}", lines[1]);
        assert!(lines[1].starts_with("LOW,"), "{}", lines[1]);
    }

    #[test]
    fn audit_jsonl_is_one_object_per_anomaly() {
        let anomalies = vec![anomaly()];
        let lines = render_audit(&anomalies, OutputFormat::Jsonl);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("\"severity\":\"LOW\""), "{}", lines[0]);
        assert!(lines[0].contains("\"code\":\"SQLITE-FREELIST-NONEMPTY\""), "{}", lines[0]);
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
