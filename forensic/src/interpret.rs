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

use sqlite_core::Value;

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
