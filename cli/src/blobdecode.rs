//! The consumer-side `blob-decoder` adapter (seam step 4).
//!
//! sqlite-core / sqlite-forensic stay lean at MSRV 1.80 with a decode *contract*
//! ([`BlobInterpreter`]) but no decode dependency. This CLI (MSRV 1.96, heavy deps
//! allowed) is where the general [`blob-decoder`](https://crates.io/crates/blob-decoder)
//! crate — and its `flate2` / `plist` / `serde_json` / `snap` weight — is pulled in and
//! adapted to that contract, decoding plist / gzip / JSON / base64 blobs the
//! built-in localStorage interpreter does not touch.

use blob_decoder::{identify, BlobKind, Confidence};
use sqlite_forensic::interpret::{BlobContext, BlobInterpreter, Interpretation};

/// Confidence floor: a [`blob_decoder`] reading is surfaced only when it is a
/// genuine recognition (a magic match or a full parse — Medium/High), never a
/// coincidence-prone Low structural guess, which would be noise on every blob.
fn score_to_confidence(score: Confidence) -> f32 {
    match score {
        Confidence::High => 0.9,
        // Only High/Medium reach here (Low is filtered before mapping).
        _ => 0.6,
    }
}

/// A [`BlobInterpreter`] backed by the general [`blob_decoder`] crate: identifies
/// and decodes an opaque BLOB (binary/XML plist, gzip/zlib/Snappy, JSON, base64/
/// hex, UUID, protobuf, UTF-8/16 text), recursively unwrapping nested wrappers.
/// Returns `None` for an unrecognised blob or a Low-confidence structural guess.
pub struct BlobDecoderInterpreter;

impl BlobInterpreter for BlobDecoderInterpreter {
    fn interpret(&self, bytes: &[u8], _ctx: &BlobContext<'_>) -> Option<Interpretation> {
        // `identify` returns candidates best-first; take the best genuine reading.
        let best = identify(bytes).into_iter().find(|c| {
            !matches!(c.kind, BlobKind::Unknown) && !matches!(c.score, Confidence::Low)
        })?;
        Some(Interpretation {
            text: best.summary,
            kind: best.kind.label().to_string(),
            // blob-decoder identifies; a truncation/bomb-cap is reported inside the
            // chain summary rather than as a lossy top-level flag.
            lossy: false,
            confidence: score_to_confidence(best.score),
        })
    }
}

/// Compose interpreters, returning the first that recognises the blob. Order is
/// priority: a schema-aware interpreter (e.g. [`LocalStorageInterpreter`]) first
/// for its high-confidence prior, then a general fallback like
/// [`BlobDecoderInterpreter`].
///
/// [`LocalStorageInterpreter`]: sqlite_forensic::interpret::LocalStorageInterpreter
pub struct ChainInterpreter<'a>(pub &'a [&'a dyn BlobInterpreter]);

impl BlobInterpreter for ChainInterpreter<'_> {
    fn interpret(&self, bytes: &[u8], ctx: &BlobContext<'_>) -> Option<Interpretation> {
        self.0.iter().find_map(|i| i.interpret(bytes, ctx))
    }
}
