//! Step 2 of the blob-interpreter seam: the built-in [`LocalStorageInterpreter`]
//! (no external deps) that decodes a `WebKit` Local Storage `ItemTable.value` BLOB —
//! raw UTF-16-LE — using the schema-name context as the high-confidence prior.
//! This is "schema context lifts a structural-Low reading to High" made concrete:
//! an arbitrary blob is not our job (that's the blob-decoder adapter), but a blob
//! from a known `ItemTable` column IS confidently UTF-16-LE.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use sqlite_forensic::interpret::{BlobContext, BlobInterpreter, LocalStorageInterpreter};

/// UTF-16-LE bytes for an ASCII string (each char → 2 little-endian bytes).
fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

#[test]
fn decodes_item_table_blob_with_high_confidence() {
    let interp = LocalStorageInterpreter;
    let ctx = BlobContext {
        table: Some("ItemTable"),
        column: Some("value"),
    };
    let out = interp
        .interpret(&utf16le("https://example.test/path"), &ctx)
        .expect("an ItemTable BLOB must be interpreted");
    assert_eq!(out.text, "https://example.test/path");
    assert!(
        out.kind.contains("utf-16"),
        "kind names the encoding: {out:?}"
    );
    assert!(!out.lossy, "clean UTF-16-LE is not lossy");
    assert!(
        out.confidence >= 0.9,
        "the ItemTable schema-name match is a high-confidence prior: {out:?}"
    );
}

#[test]
fn does_not_fire_without_the_item_table_context() {
    // Without the ItemTable schema context there is no prior that the bytes are
    // UTF-16-LE, so this interpreter recognises nothing (blob-decoder's job).
    let interp = LocalStorageInterpreter;
    let ctx = BlobContext {
        table: Some("moz_places"),
        column: Some("value"),
    };
    assert!(
        interp.interpret(&utf16le("anything"), &ctx).is_none(),
        "no ItemTable context → the localstorage interpreter must not fire"
    );
    // And with no table context at all.
    let bare = BlobContext {
        table: None,
        column: None,
    };
    assert!(interp.interpret(&utf16le("x"), &bare).is_none());
}

#[test]
fn flags_a_lossy_decode() {
    // An odd-length blob cannot be whole UTF-16-LE code units; the decode is lossy
    // and the interpretation must say so (secure by design — never faithful).
    let interp = LocalStorageInterpreter;
    let ctx = BlobContext {
        table: Some("ItemTable"),
        column: None,
    };
    let mut bytes = utf16le("ok");
    bytes.push(0x41); // trailing odd byte
    let out = interp.interpret(&bytes, &ctx).expect("still interpreted");
    assert!(
        out.lossy,
        "an odd-length UTF-16-LE blob is a lossy decode: {out:?}"
    );
}
