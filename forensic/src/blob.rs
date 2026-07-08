//! Recovered-BLOB enrichment (roadmap §4.5): make carved binary payloads
//! addressable in a case by a magic-based media type and a SHA-256 content hash.
//!
//! The media detection reads only documented file-format **magic numbers** (each
//! cited below) from the leading bytes — a signature match, not a decode, so it is
//! panic-free and never mis-parses a truncated payload. The hash is SHA-256 via
//! the audited `RustCrypto` `sha2` crate (never a hand-rolled digest), giving the
//! court-standard content address every recovered image/document can be keyed on.

use sha2::{Digest, Sha256};

/// Identify a BLOB's media type from its leading magic bytes, or `None` when no
/// known signature matches (or the payload is too short to carry one).
///
/// Signature match only — it does NOT validate the rest of the file, so a
/// truncated or partially-overwritten carve still types by its surviving header.
/// The type is an *observation* ("the leading bytes are a PNG signature"), never a
/// guarantee the whole payload decodes.
#[must_use]
pub fn identify_media_type(bytes: &[u8]) -> Option<&'static str> {
    // RIFF containers carry the concrete type at bytes 8..12 (e.g. WEBP, WAVE).
    if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" {
        match &bytes[8..12] {
            b"WEBP" => return Some("image/webp"),
            b"WAVE" => return Some("audio/wav"),
            b"AVI " => return Some("video/x-msvideo"),
            _ => {}
        }
    }
    // ISO base-media (MP4 and friends): `....ftyp` at offset 4.
    if bytes.len() >= 8 && &bytes[4..8] == b"ftyp" {
        return Some("video/mp4");
    }
    // Prefix signatures, longest/most-specific first. Each magic is a documented
    // file-format constant.
    const SIGNATURES: &[(&[u8], &str)] = &[
        (b"\x89PNG\r\n\x1a\n", "image/png"), // PNG, RFC 2083 §3.1
        (b"\xFF\xD8\xFF", "image/jpeg"),     // JPEG/JFIF/EXIF SOI + marker
        (b"GIF87a", "image/gif"),            // GIF87a
        (b"GIF89a", "image/gif"),            // GIF89a
        (b"BM", "image/bmp"),                // BMP (Windows bitmap)
        (b"II\x2a\x00", "image/tiff"),       // TIFF little-endian
        (b"MM\x00\x2a", "image/tiff"),       // TIFF big-endian
        (b"%PDF-", "application/pdf"),       // PDF, ISO 32000 §7.5.2
        (b"\x1f\x8b", "application/gzip"),   // gzip, RFC 1952 §2.3.1
        (b"PK\x03\x04", "application/zip"),  // ZIP local file header
        (b"BZh", "application/x-bzip2"),     // bzip2
        (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed"), // 7-Zip
        (b"SQLite format 3\x00", "application/vnd.sqlite3"), // SQLite db header
        (b"OggS", "application/ogg"),        // Ogg
        (b"fLaC", "audio/flac"),             // FLAC
        (b"ID3", "audio/mpeg"),              // MP3 with ID3 tag
        (b"\x25\x21PS", "application/postscript"), // PostScript "%!PS"
        (
            b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
            "application/x-ole-storage",
        ), // OLE (legacy .doc/.xls)
    ];
    SIGNATURES
        .iter()
        .find(|(magic, _)| bytes.starts_with(magic))
        .map(|(_, mime)| *mime)
}

/// The lowercase hex SHA-256 of `bytes` — the court-standard content address for a
/// recovered BLOB, computed with the audited `RustCrypto` `sha2` implementation.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        // Two lowercase hex nibbles per byte.
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}
