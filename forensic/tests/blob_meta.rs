//! Blob typing + content hashing (roadmap §4.5): a recovered BLOB is made
//! addressable in a case by a magic-based media type and a SHA-256 content hash.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use sqlite_forensic::blob::{identify_media_type, sha256_hex};

#[test]
fn identifies_common_media_types_from_magic() {
    // Magic numbers are documented file-format facts (see each format spec).
    let png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR";
    let jpeg = b"\xFF\xD8\xFF\xE0\x00\x10JFIF";
    let gif = b"GIF89a\x01\x00";
    let pdf = b"%PDF-1.7\n";
    let gzip = b"\x1f\x8b\x08\x00";
    let zip = b"PK\x03\x04\x14\x00";

    assert_eq!(identify_media_type(png), Some("image/png"));
    assert_eq!(identify_media_type(jpeg), Some("image/jpeg"));
    assert_eq!(identify_media_type(gif), Some("image/gif"));
    assert_eq!(identify_media_type(pdf), Some("application/pdf"));
    assert_eq!(identify_media_type(gzip), Some("application/gzip"));
    assert_eq!(identify_media_type(zip), Some("application/zip"));
}

#[test]
fn unknown_or_short_blobs_return_none() {
    assert_eq!(identify_media_type(b"not a known magic"), None);
    assert_eq!(identify_media_type(b""), None);
    assert_eq!(identify_media_type(b"\x89P"), None); // too short for the PNG magic
}

#[test]
fn sha256_matches_the_nist_test_vector() {
    // FIPS 180-2 test vector: SHA-256("abc").
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    // Empty input has a well-known digest too.
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}
