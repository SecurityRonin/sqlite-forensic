//! Contract test for the whole-database SQLite [`Carver`] (fleet ADR 0001 §4).
//!
//! A `SqliteCarver` lets a disk-unallocated or memory sweep recover a complete
//! SQLite database from a raw window: the 100-byte header anchors and bounds the
//! carve, and the recovery method is *echoed* from the driver's [`CarveContext`]
//! (never hard-coded), so the same carver stamps `UnallocatedCarve` on a disk
//! sweep and `MemoryCarve` on a memory sweep.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use forensic_carve::{CarveContext, CarvedPayload, Carver, RecoveryMethod};
use sqlite_forensic::carve::SqliteCarver;

/// Build a minimal but structurally valid SQLite image: a 100-byte header
/// declaring `page_size` × `page_count`, padded out to that full length.
fn build_min_db(page_size: u32, page_count: u32) -> Vec<u8> {
    let total = (page_size as usize) * (page_count as usize);
    let mut db = vec![0u8; total];
    // Magic (offset 0).
    db[..16].copy_from_slice(b"SQLite format 3\0");
    // Page size (offset 16, BE u16; the special value 1 encodes 65536).
    let raw: u16 = if page_size == 65536 {
        1
    } else {
        u16::try_from(page_size).unwrap()
    };
    db[16..18].copy_from_slice(&raw.to_be_bytes());
    // Reserved bytes per page (offset 20) — 0 is the standard, sane value.
    db[20] = 0;
    // In-header database size in pages (offset 28, BE u32).
    db[28..32].copy_from_slice(&page_count.to_be_bytes());
    // Text encoding (offset 56, BE u32) — 1 = UTF-8.
    db[56..60].copy_from_slice(&1u32.to_be_bytes());
    db
}

#[test]
fn carves_whole_db_at_nonzero_offset_and_echoes_method() {
    let page_size = 512u32;
    let page_count = 2u32;
    let db = build_min_db(page_size, page_count);
    let expected_len = (page_size as usize) * (page_count as usize);
    assert_eq!(db.len(), expected_len);

    // Embed the DB at a nonzero offset inside a larger scratch buffer, with
    // trailing bytes past the DB end (the sweep hands a window that starts at the
    // magic but may run long).
    let off = 4096u64;
    let mut scratch = vec![0u8; off as usize];
    scratch.extend_from_slice(&db);
    scratch.extend(std::iter::repeat(0u8).take(256));
    let window = &scratch[off as usize..];

    let ctx = CarveContext::at(off).with_method(RecoveryMethod::UnallocatedCarve);
    let items = SqliteCarver.carve(window, &ctx);

    assert_eq!(items.len(), 1, "one whole-DB item expected");
    let item = &items[0];
    assert_eq!(item.format(), "sqlite");
    // Method is ECHOED from the context, not hard-coded.
    assert_eq!(item.recovery_method(), RecoveryMethod::UnallocatedCarve);
    assert_eq!(item.image_offset(), off);
    assert!(item.confidence() > 0.0 && item.confidence() <= 1.0);
    match item.payload() {
        CarvedPayload::ArtifactBytes(bytes) => {
            assert_eq!(
                bytes.len(),
                expected_len,
                "artifact bounded to page_size * page_count"
            );
        }
        CarvedPayload::Records => panic!("expected ArtifactBytes payload"),
    }
}

#[test]
fn method_is_echoed_not_hardcoded_memory_sweep() {
    let db = build_min_db(1024, 3);
    let ctx = CarveContext::at(0).with_method(RecoveryMethod::MemoryCarve);
    let items = SqliteCarver.carve(&db, &ctx);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].recovery_method(), RecoveryMethod::MemoryCarve);
}

#[test]
fn short_window_carves_nothing() {
    let garbage = vec![0xAAu8; 50];
    let ctx = CarveContext::at(0).with_method(RecoveryMethod::UnallocatedCarve);
    assert!(SqliteCarver.carve(&garbage, &ctx).is_empty());
}

#[test]
fn magic_but_structurally_invalid_carves_nothing() {
    // Correct magic, but a page size that is neither a power of two nor in
    // [512, 65536] — structural validation (not just magic) must reject it.
    let mut bad = build_min_db(512, 2);
    bad[16] = 0x00;
    bad[17] = 0x07; // page size 7
    let ctx = CarveContext::at(0).with_method(RecoveryMethod::UnallocatedCarve);
    assert!(SqliteCarver.carve(&bad, &ctx).is_empty());

    // Correct magic and page size, but a zero page count — no bounded DB.
    let mut zero_pages = build_min_db(512, 2);
    zero_pages[28..32].copy_from_slice(&0u32.to_be_bytes());
    assert!(SqliteCarver.carve(&zero_pages, &ctx).is_empty());
}

#[test]
fn signatures_and_format_advertise_sqlite() {
    let sigs = SqliteCarver.signatures();
    assert_eq!(SqliteCarver.format(), "sqlite");
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].magic(), b"SQLite format 3\0");
    assert_eq!(sigs[0].offset(), 0);
    assert!(SqliteCarver.max_window() > 0);
}
