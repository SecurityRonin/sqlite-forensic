//! Step 1 of the blob-interpreter seam (dependency inversion): sqlite-forensic
//! defines the *contract* for context-aware BLOB decoding — a `BlobInterpreter`
//! trait plus `BlobContext`/`Interpretation` types — and a passthrough that
//! applies an `Option<&dyn BlobInterpreter>` to a record's values. The library
//! gains ZERO decoding dependencies and no MSRV cost; a consumer (blob-decoder
//! adapter, or the built-in localstorage decoder) supplies the interpreter.
//!
//! This step proves the seam: an interpreter's `Interpretation` reaches the output
//! when supplied, and `None` leaves the output empty (unchanged behaviour).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use sqlite_core::Value;
use sqlite_forensic::interpret::{interpret_values, BlobContext, BlobInterpreter, Interpretation};

/// A trivial test interpreter: any BLOB is "interpreted" as its byte length. Real
/// interpreters (localstorage UTF-16, blob-decoder) live in consumers.
struct ByteLen;

impl BlobInterpreter for ByteLen {
    fn interpret(&self, bytes: &[u8], _ctx: &BlobContext<'_>) -> Option<Interpretation> {
        Some(Interpretation {
            text: format!("{} bytes", bytes.len()),
            kind: "bytelen".to_string(),
            lossy: false,
            confidence: 1.0,
        })
    }
}

fn sample_values() -> Vec<Value> {
    vec![
        Value::Integer(7),
        Value::Text("hello".to_string()),
        Value::Blob(vec![0xDE, 0xAD, 0xBE, 0xEF]),
    ]
}

#[test]
fn interpreter_reaches_only_the_blob_value() {
    let values = sample_values();
    let ctx = BlobContext {
        table: Some("moz_places"),
        column: None,
    };
    let out = interpret_values(&values, &ctx, Some(&ByteLen));

    // Exactly the one BLOB (index 2) is interpreted; the int/text are skipped.
    assert_eq!(out.len(), 1, "only the BLOB value is interpreted: {out:?}");
    let (idx, interp) = &out[0];
    assert_eq!(*idx, 2, "the BLOB is at column index 2");
    assert_eq!(interp.text, "4 bytes");
    assert_eq!(interp.kind, "bytelen");
    assert!(!interp.lossy);
}

#[test]
fn none_interpreter_is_passthrough_no_interpretations() {
    let values = sample_values();
    let ctx = BlobContext {
        table: None,
        column: None,
    };
    let out = interpret_values(&values, &ctx, None);
    assert!(
        out.is_empty(),
        "with no interpreter, behaviour is unchanged (no interpretations): {out:?}"
    );
}

#[test]
fn no_blobs_yields_no_interpretations_even_with_an_interpreter() {
    let values = vec![Value::Integer(1), Value::Text("x".to_string()), Value::Null];
    let ctx = BlobContext {
        table: None,
        column: None,
    };
    let out = interpret_values(&values, &ctx, Some(&ByteLen));
    assert!(out.is_empty(), "no BLOB → nothing to interpret: {out:?}");
}
