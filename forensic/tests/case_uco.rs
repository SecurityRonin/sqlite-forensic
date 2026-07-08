//! CASE/UCO JSON-LD export of recovered BLOBs (roadmap §4.5).
//!
//! Structure verified against the CASE/UCO ontology and published examples
//! (caseontology.org): a `uco-observable:ObservableObject` with a
//! `uco-observable:ContentDataFacet` carrying `mimeType`, `sizeInBytes`, and a
//! `uco-types:Hash` (method `SHA256`, `xsd:hexBinary` value).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use sqlite_core::Value;
use sqlite_forensic::blob::sha256_hex;
use sqlite_forensic::case_uco::bundle_for_records;
use sqlite_forensic::{CarvedRecord, RecoverySource};

fn blob_record(rowid: i64, bytes: Vec<u8>) -> CarvedRecord {
    CarvedRecord {
        page: 3,
        offset: 128,
        rowid,
        values: vec![Value::Integer(rowid), Value::Blob(bytes)],
        confidence: 0.9,
        allocated: false,
        source: RecoverySource::InPageFreeBlock,
        wal: None,
        overflow: None,
    }
}

fn brace_balanced(s: &str) -> bool {
    let mut depth: i64 = 0;
    for c in s.chars() {
        match c {
            '{' | '[' => depth += 1,
            '}' | ']' => depth -= 1,
            _ => {}
        }
        if depth < 0 {
            return false;
        }
    }
    depth == 0
}

#[test]
fn bundle_carries_context_and_content_data_for_each_blob() {
    let png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRxx".to_vec();
    let hash = sha256_hex(&png);
    let records = vec![
        blob_record(1, png),
        // A record with NO blob contributes no observable.
        CarvedRecord {
            page: 3,
            offset: 200,
            rowid: 2,
            values: vec![Value::Text("no blob here".into())],
            confidence: 0.9,
            allocated: false,
            source: RecoverySource::InPageFreeBlock,
            wal: None,
            overflow: None,
        },
    ];
    let bundle = bundle_for_records(&records);

    assert!(
        brace_balanced(&bundle),
        "bundle must be brace-balanced: {bundle}"
    );
    // JSON-LD envelope.
    assert!(bundle.contains("\"@context\""));
    assert!(bundle.contains("\"@graph\""));
    assert!(bundle.contains("ontology.unifiedcyberontology.org/uco/observable/"));
    // The observable + content-data facet for the PNG blob.
    assert!(bundle.contains("uco-observable:ObservableObject"));
    assert!(bundle.contains("uco-observable:ContentDataFacet"));
    assert!(bundle.contains("\"uco-observable:mimeType\":\"image/png\""));
    // The SHA-256 hash, method + hex value, per the verified structure.
    assert!(bundle.contains("uco-types:Hash"));
    assert!(bundle.contains("\"@value\":\"SHA256\""));
    assert!(
        bundle.contains(&format!("\"@value\":\"{hash}\"")),
        "bundle must carry the blob's SHA-256 hex: {bundle}"
    );
    // Exactly one observable (the text-only record contributed none).
    assert_eq!(
        bundle.matches("uco-observable:ObservableObject").count(),
        1,
        "only the blob-bearing record yields an observable: {bundle}"
    );
}

#[test]
fn bundle_with_no_blobs_is_a_valid_empty_graph() {
    let records = vec![CarvedRecord {
        page: 3,
        offset: 200,
        rowid: 2,
        values: vec![Value::Integer(2)],
        confidence: 0.9,
        allocated: false,
        source: RecoverySource::InPageFreeBlock,
        wal: None,
        overflow: None,
    }];
    let bundle = bundle_for_records(&records);
    assert!(brace_balanced(&bundle));
    assert!(bundle.contains("\"@graph\":[]"), "empty graph: {bundle}");
}

#[test]
fn unknown_blob_omits_mime_but_keeps_hash() {
    let records = vec![blob_record(1, b"no known magic".to_vec())];
    let bundle = bundle_for_records(&records);
    assert!(!bundle.contains("mimeType"), "no guessed mime: {bundle}");
    assert!(bundle.contains("uco-types:Hash"), "still hashed: {bundle}");
}
