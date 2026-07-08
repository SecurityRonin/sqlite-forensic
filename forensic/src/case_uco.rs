//! CASE/UCO JSON-LD export of recovered BLOBs (roadmap §4.5).
//!
//! Emits a CASE/UCO bundle so recovered media is addressable in case-management
//! tools. Each recovered `BLOB` becomes a `uco-observable:ObservableObject` with a
//! `uco-observable:ContentDataFacet` carrying its media type (when a magic
//! signature is recognized), byte size, and a `uco-types:Hash` (method `SHA256`,
//! `xsd:hexBinary` value). The structure follows the CASE/UCO ontology and its
//! published examples (caseontology.org); the inner hash literals carry `@type` +
//! `@value` only (no `@id`), per the ontology's typed-literal rule.
//!
//! Scope: this maps recovered *media blobs* to UCO content observables — the
//! part of the recovery that has a clean UCO representation. It does not attempt
//! to model arbitrary deleted rows (UCO has no observable type for a carved
//! table row). Validate the output with the CASE validator before relying on it.

use std::fmt::Write as _;

use sqlite_core::Value;

use crate::blob::{identify_media_type, sha256_hex};
use crate::CarvedRecord;

/// The CASE/UCO `@context` prefix map (ontology 1.x IRIs).
const CONTEXT: &str = "\"@context\":{\
     \"kb\":\"http://example.org/kb/\",\
     \"uco-core\":\"https://ontology.unifiedcyberontology.org/uco/core/\",\
     \"uco-observable\":\"https://ontology.unifiedcyberontology.org/uco/observable/\",\
     \"uco-types\":\"https://ontology.unifiedcyberontology.org/uco/types/\",\
     \"uco-vocabulary\":\"https://ontology.unifiedcyberontology.org/uco/vocabulary/\",\
     \"xsd\":\"http://www.w3.org/2001/XMLSchema#\"}";

/// Build a CASE/UCO JSON-LD bundle of every recovered `BLOB` across `records`.
///
/// Deterministic `@id`s (blob index within the run) so the output is reproducible.
/// A record with no blobs contributes no observable; a run with no blobs yields a
/// valid bundle with an empty `@graph`.
#[must_use]
pub fn bundle_for_records(records: &[CarvedRecord]) -> String {
    let blobs: Vec<&[u8]> = records
        .iter()
        .flat_map(|r| r.values.iter())
        .filter_map(|v| match v {
            Value::Blob(b) => Some(b.as_slice()),
            _ => None,
        })
        .collect();

    let mut graph = String::new();
    for (i, bytes) in blobs.iter().enumerate() {
        if i > 0 {
            graph.push(',');
        }
        let hash = sha256_hex(bytes);
        // mimeType field is present ONLY when a signature is recognized.
        let mime = identify_media_type(bytes)
            .map(|m| format!("\"uco-observable:mimeType\":\"{m}\","))
            .unwrap_or_default();
        let _ = write!(
            graph,
            "{{\"@id\":\"kb:observable-blob-{i}\",\
             \"@type\":\"uco-observable:ObservableObject\",\
             \"uco-core:hasFacet\":[{{\"@id\":\"kb:content-data-facet-{i}\",\
             \"@type\":\"uco-observable:ContentDataFacet\",\
             {mime}\"uco-observable:sizeInBytes\":{size},\
             \"uco-observable:hash\":[{{\"@type\":\"uco-types:Hash\",\
             \"uco-types:hashMethod\":{{\"@type\":\"uco-vocabulary:HashNameVocab\",\"@value\":\"SHA256\"}},\
             \"uco-types:hashValue\":{{\"@type\":\"xsd:hexBinary\",\"@value\":\"{hash}\"}}}}]}}]}}",
            size = bytes.len()
        );
    }

    format!("{{{CONTEXT},\"@graph\":[{graph}]}}")
}
