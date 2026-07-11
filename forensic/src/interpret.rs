//! The blob-interpreter seam (roadmap §4.5 follow-up): a dependency-inversion
//! contract so consumers can decode opaque `BLOB` values in schema context —
//! `WebKit` Local Storage UTF-16, or the general [`blob-decoder`] crate (plist /
//! gzip / JSON / …) — WITHOUT this reader library taking on any decode dependency
//! or MSRV cost.
//!
//! [`blob-decoder`]: https://crates.io/crates/blob-decoder
//!
//! The library owns the *contract* + the *schema context* ([`BlobContext`]); a
//! consumer supplies the *decoder* by implementing [`BlobInterpreter`]. Passing
//! `None` is the default: unchanged behaviour, the raw bytes are surfaced as-is.
//!
//! Secure by design: [`Interpretation::lossy`] is a struct field, so a caller
//! cannot render a lossy decode as a faithful one — the uncertainty is structural,
//! not a side-channel warning.

use sqlite_core::{decode_localstorage_value, is_local_storage_item_table, Value};

/// The schema context a [`BlobInterpreter`] may use as a decoding prior — e.g. a
/// known table/column ("this column holds UTF-16 Local Storage values") lifts a
/// structural, low-confidence reading to a high-confidence one.
#[derive(Debug, Clone, Copy, Default)]
pub struct BlobContext<'a> {
    /// The table the record was attributed to, when known.
    pub table: Option<&'a str>,
    /// The column the value came from, when known.
    pub column: Option<&'a str>,
}

/// A consumer-supplied decoding of an opaque `BLOB` value. The observation of what
/// the bytes *are*, never a guarantee — [`lossy`](Self::lossy) records when the
/// decode dropped or substituted data.
#[derive(Debug, Clone, PartialEq)]
pub struct Interpretation {
    /// The decoded, human-readable form of the value.
    pub text: String,
    /// A short label for the reading (e.g. `utf-16`, `bplist`, `gzip`).
    pub kind: String,
    /// Whether the decode was lossy (an unpaired surrogate, a truncated payload,
    /// bytes substituted with U+FFFD). Structural, so a consumer cannot present a
    /// lossy decode as faithful.
    pub lossy: bool,
    /// Heuristic confidence in `(0.0, 1.0]` that this reading is correct.
    pub confidence: f32,
}

/// A consumer-supplied interpreter of opaque `BLOB` values. Implemented OUTSIDE
/// this crate (a `blob-decoder` adapter, or the built-in Local Storage decoder) so
/// the reader library carries no decode dependency.
pub trait BlobInterpreter {
    /// Interpret a `BLOB`'s bytes in the given schema context, or `None` when this
    /// interpreter recognises nothing in them.
    fn interpret(&self, bytes: &[u8], ctx: &BlobContext<'_>) -> Option<Interpretation>;
}

/// Confidence assigned when a BLOB is decoded under a matching schema-name prior
/// (a `WebKit` Local Storage `ItemTable` column): the context makes UTF-16-LE the
/// confident reading, not a coincidental structural match.
const SCHEMA_MATCHED_CONFIDENCE: f32 = 0.95;

/// The built-in, dependency-free [`BlobInterpreter`] for `WebKit`/Chromium Local
/// Storage. A `.localstorage` `ItemTable.value` BLOB holds its string as raw
/// UTF-16-LE (no BOM, no type byte); this decodes it — but ONLY when the schema
/// context identifies the `ItemTable` column, which is the prior that makes the
/// UTF-16-LE reading confident. An arbitrary BLOB is not this interpreter's job
/// (that is the general `blob-decoder` adapter); it returns `None`.
#[derive(Debug, Clone, Copy, Default)]
pub struct LocalStorageInterpreter;

impl BlobInterpreter for LocalStorageInterpreter {
    fn interpret(&self, bytes: &[u8], ctx: &BlobContext<'_>) -> Option<Interpretation> {
        // Fire only under the ItemTable schema-name prior — without it there is no
        // evidence these bytes are UTF-16-LE rather than any other encoding.
        if !ctx.table.is_some_and(is_local_storage_item_table) {
            return None;
        }
        let decoded = decode_localstorage_value(bytes);
        Some(Interpretation {
            text: decoded.text,
            kind: "utf-16le".to_string(),
            lossy: decoded.lossy,
            confidence: SCHEMA_MATCHED_CONFIDENCE,
        })
    }
}

/// Apply `interpreter` to every `BLOB` in `values`, returning `(column_index,
/// interpretation)` for each blob the interpreter recognised. Non-blob values are
/// skipped. `interpreter == None` yields an empty result — the default, unchanged
/// behaviour, so this passthrough is non-breaking for every existing caller.
#[must_use]
pub fn interpret_values(
    values: &[Value],
    ctx: &BlobContext<'_>,
    interpreter: Option<&dyn BlobInterpreter>,
) -> Vec<(usize, Interpretation)> {
    let Some(interpreter) = interpreter else {
        return Vec::new();
    };
    values
        .iter()
        .enumerate()
        .filter_map(|(i, value)| match value {
            Value::Blob(bytes) => interpreter.interpret(bytes, ctx).map(|interp| (i, interp)),
            _ => None,
        })
        .collect()
}
