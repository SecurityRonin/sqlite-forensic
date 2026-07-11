//! Seam step 4: the consumer-side `blob-decoder` adapter. The CLI (MSRV 1.96,
//! heavy deps allowed) implements the library's `BlobInterpreter` contract over
//! the general `blob-decoder` crate — decoding plist / gzip / JSON / base64 blobs
//! the built-in localStorage interpreter doesn't touch. This is where blob-decoder's
//! 1.88 / flate2 / plist weight lands, OUTSIDE the 1.80 reader library.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use sqlite4n6::blobdecode::{BlobDecoderInterpreter, ChainInterpreter};
use sqlite_forensic::interpret::{BlobContext, BlobInterpreter, LocalStorageInterpreter};

#[test]
fn blob_decoder_interprets_a_json_blob() {
    let out = BlobDecoderInterpreter
        .interpret(b"{\"user\":\"alice\"}", &BlobContext::default())
        .expect("JSON must be recognised");
    assert!(
        out.kind.to_lowercase().contains("json"),
        "kind names JSON: {out:?}"
    );
    assert!(
        out.confidence >= 0.6,
        "a full JSON parse is confident: {out:?}"
    );
}

#[test]
fn blob_decoder_returns_none_for_unrecognised_bytes() {
    // Arbitrary bytes with no magic and no confident structure → no interpretation
    // (the adapter surfaces only Medium/High readings, never Low-confidence noise).
    let out = BlobDecoderInterpreter.interpret(&[0x9f, 0x3a, 0x7c], &BlobContext::default());
    assert!(out.is_none(), "unrecognised bytes yield None: {out:?}");
}

#[test]
fn chain_prefers_localstorage_then_falls_back_to_blob_decoder() {
    let ls = LocalStorageInterpreter;
    let bd = BlobDecoderInterpreter;
    let interps: [&dyn BlobInterpreter; 2] = [&ls, &bd];
    let chain = ChainInterpreter(&interps);

    // An ItemTable UTF-16-LE value: localStorage wins (schema-aware, high conf).
    let utf16le: Vec<u8> = "hi".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let ctx = BlobContext {
        table: Some("ItemTable"),
        column: None,
    };
    let out = chain
        .interpret(&utf16le, &ctx)
        .expect("localStorage handles it");
    assert!(out.kind.contains("utf-16"), "{out:?}");

    // A JSON blob with no ItemTable context: localStorage passes, blob-decoder
    // handles it — the fallback in the chain.
    let json = chain
        .interpret(b"[1,2,3]", &BlobContext::default())
        .expect("blob-decoder handles JSON");
    assert!(json.kind.to_lowercase().contains("json"), "{json:?}");
}
