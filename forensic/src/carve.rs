//! Whole-database SQLite carver satisfying the fleet [`forensic_carve::Carver`]
//! contract (ADR 0001 §4).
//!
//! A disk-unallocated or memory sweep hits the `SQLite format 3\0` magic and
//! hands this carver a capped window starting at that magic. The carver validates
//! the 100-byte file header (magic, page size, in-header page count, reserved
//! space), bounds the database to `page_size × page_count`, and emits the bounded
//! byte range as a [`forensic_carve::CarvedItem`] that re-enters the normal
//! classify → parse pipeline. It is **medium-agnostic**: it echoes
//! [`CarveContext::recovery_method`] (so the *same* carver stamps `UnallocatedCarve`
//! on a disk sweep and `MemoryCarve` on a memory sweep) and never touches a
//! `Read`/`Seek`, a VFS handle, or a memory provider.
//!
//! Header field offsets come from `forensicnomicon::sqlite` (the KNOWLEDGE leaf) —
//! the same constants `sqlite-core`'s reader parses, kept in one place. All reads
//! are bounds-checked; a window that fails validation emits nothing.

use forensic_carve::{CarveContext, CarvedItem, Carver, CarverRegistration, Signature};
use forensicnomicon::sqlite::{
    SQLITE_DB_SIZE_OFFSET, SQLITE_HEADER_SIZE, SQLITE_MAGIC, SQLITE_PAGE_SIZE_OFFSET,
    SQLITE_RESERVED_SPACE_OFFSET, SQLITE_TEXT_ENCODING_OFFSET,
};

/// The format id every carved SQLite item advertises.
const FORMAT: &str = "sqlite";

/// Upper bound on the bytes one hit may claim, so the sweep engine caps the window
/// it materializes. SQLite's in-header page count is a `u32`, so a maximal image is
/// enormous; `1 GiB` comfortably covers real-world evidence databases (browser,
/// messaging, OS artifact stores are tens of MB) while bounding a lying header.
const MAX_WINDOW: u64 = 1 << 30;

/// The single header-magic signature that anchors a SQLite candidate window.
static SIGNATURES: [Signature; 1] = [Signature::new(b"SQLite format 3\0", 0)];

/// Whole-database SQLite carver (see the module docs).
#[derive(Debug, Clone, Copy, Default)]
pub struct SqliteCarver;

/// The registered instance the fleet sweep engine collects at link time.
static SQLITE_CARVER: SqliteCarver = SqliteCarver;

inventory::submit! { CarverRegistration::new(&SQLITE_CARVER) }

/// Read a big-endian `u16` at `off`, or `None` if the window is too short.
fn be_u16(bytes: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    let slice = bytes.get(off..end)?;
    Some(u16::from_be_bytes([slice[0], slice[1]]))
}

/// Read a big-endian `u32` at `off`, or `None` if the window is too short.
fn be_u32(bytes: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let slice = bytes.get(off..end)?;
    Some(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

impl Carver for SqliteCarver {
    fn format(&self) -> &'static str {
        FORMAT
    }

    fn signatures(&self) -> &[Signature] {
        &SIGNATURES
    }

    fn max_window(&self) -> u64 {
        MAX_WINDOW
    }

    fn carve(&self, window: &[u8], ctx: &CarveContext) -> Vec<CarvedItem> {
        // A valid database is at least a full 100-byte header.
        let Some(header) = window.get(..SQLITE_HEADER_SIZE) else {
            return Vec::new();
        };

        // Check 1 (mandatory): the file-header magic.
        if !header.starts_with(SQLITE_MAGIC) {
            return Vec::new();
        }

        // Check 2 (mandatory): a valid page size. Byte 16 (BE u16); the special
        // value 1 encodes 65536. Must be a power of two in [512, 65536].
        let Some(raw_page_size) = be_u16(header, SQLITE_PAGE_SIZE_OFFSET) else {
            return Vec::new(); // cov:unreachable: header is >= 100 bytes here
        };
        let page_size: u32 = if raw_page_size == 1 {
            65536
        } else {
            u32::from(raw_page_size)
        };
        if !(512..=65536).contains(&page_size) || !page_size.is_power_of_two() {
            return Vec::new();
        }

        // Check 3 (mandatory): a non-zero in-header page count (byte 28, BE u32).
        // Zero is the legacy "derive size from file length" encoding, which a
        // detached carving window cannot honor — so it is not a bounded DB here.
        let Some(page_count) = be_u32(header, SQLITE_DB_SIZE_OFFSET) else {
            return Vec::new(); // cov:unreachable: header is >= 100 bytes here
        };
        if page_count == 0 {
            return Vec::new();
        }

        // Grading checks (independent header signals — each raises confidence).
        // Reserved space (byte 20) must leave a positive usable page size.
        let reserved = header
            .get(SQLITE_RESERVED_SPACE_OFFSET)
            .copied()
            .unwrap_or(0);
        let reserved_sane = u32::from(reserved) < page_size;
        // Text encoding (byte 56, BE u32): 1 = UTF-8, 2 = UTF-16LE, 3 = UTF-16BE.
        let encoding_valid = matches!(be_u32(header, SQLITE_TEXT_ENCODING_OFFSET), Some(1..=3));

        // Bound the database to page_size * page_count, clamped to the window and
        // the max-window cap.
        let declared_len = u64::from(page_size) * u64::from(page_count);
        let full_db_present = declared_len <= window.len() as u64;
        let bounded_len = declared_len.min(window.len() as u64).min(MAX_WINDOW);
        let end = usize::try_from(bounded_len).unwrap_or(usize::MAX);
        let Some(db_bytes) = window.get(..end) else {
            return Vec::new(); // cov:unreachable: end <= window.len() by the min above
        };

        // Confidence = fraction of independent header checks that passed. The three
        // mandatory checks always hold here (a floor of 3/6); the three grading
        // checks distinguish a fully-consistent header from a bare magic + size.
        let graded = [reserved_sane, encoding_valid, full_db_present]
            .iter()
            .filter(|p| **p)
            .count();
        #[allow(clippy::cast_precision_loss)]
        let confidence = (3 + graded) as f32 / 6.0;

        vec![CarvedItem::artifact_bytes(
            FORMAT,
            ctx.base_offset(),
            confidence,
            ctx.recovery_method(),
            db_bytes.to_vec(),
        )]
    }
}
