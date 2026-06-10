//! `sqlite-core` — native, read-only, panic-free `SQLite` file-format reader.
//!
//! WS-C feasibility spike. Proves the native path: parse the 100-byte file
//! header (validate magic + page size) and walk one table b-tree, yielding its
//! rows as typed [`Value`]s — bounds-checked and panic-free on crafted input.
//!
//! Format constants are consumed from [`forensicnomicon::sqlite`] (the KNOWLEDGE
//! leaf) rather than re-hardcoded here.
//!
//! Scope of the spike: file header + a single table b-tree walk (interior +
//! leaf). Index b-trees, overflow pages, WAL overlay, and freelist/unallocated
//! carving are deliberately OUT of scope — they are what WS-E (`sqlite-forensic`)
//! would build on top of this reader.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use forensicnomicon::sqlite::{
    SQLITE_FREELIST_TRUNK_OFFSET, SQLITE_HEADER_SIZE, SQLITE_MAGIC, SQLITE_PAGE_SIZE_OFFSET,
};

/// Byte offset of the 1-byte "reserved space per page" field in the file header
/// (file-format §1.3.4). forensicnomicon does not yet expose this; WS-E should
/// promote it into `forensicnomicon::sqlite`.
const RESERVED_SPACE_OFFSET: usize = 20;

/// Byte offset of the in-header database size, in pages (file-format §1.3.6).
/// 4-byte big-endian. Valid only when it equals the change counter at offset 24
/// (a "size is valid" sentinel); the file-length fallback covers the rest.
/// forensicnomicon does not yet expose this — promote it in a later pass.
const DB_SIZE_IN_PAGES_OFFSET: usize = 28;

/// Byte offset of the freelist page **count** in the file header (file-format
/// §1.3.5). 4-byte big-endian. The trunk pointer lives at
/// [`SQLITE_FREELIST_TRUNK_OFFSET`] (32); this count is the next field (36).
const FREELIST_COUNT_OFFSET: usize = 36;

/// Errors that can arise while reading a `SQLite` database, all recoverable —
/// the reader never panics on malformed input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// File is shorter than the 100-byte header.
    TooShort,
    /// First 16 bytes are not the `SQLite format 3\0` magic.
    BadMagic,
    /// Page-size field is not a power of two in `[512, 65536]`.
    BadPageSize(u32),
    /// A page number referenced by the b-tree is out of range for the file.
    PageOutOfRange(u32),
    /// A b-tree page had an unexpected type byte where a table page was required.
    NotATablePage(u8),
    /// A cell pointer or payload ran past the end of its page.
    TruncatedCell,
    /// The b-tree was deeper / wider than the safety cap allows.
    TooManyPages,
    /// The freelist trunk chain cycled or exceeded the file's page count.
    MalformedFreelist,
    /// An overflow-page chain cycled or exceeded the file's page count.
    MalformedOverflow,
}

/// A single decoded column value from a table row. Mirrors `SQLite`'s storage
/// classes.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

/// One table row: its rowid plus decoded column values, in column order.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub rowid: i64,
    pub values: Vec<Value>,
}

/// Parsed 100-byte `SQLite` file header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Logical page size in bytes (512..=65536).
    pub page_size: u32,
    /// Reserved bytes at the end of each page (usually 0).
    pub reserved: u8,
}

impl Header {
    /// Usable bytes per page = `page_size` − reserved (file-format §1.3.4).
    #[must_use]
    pub fn usable_size(self) -> u32 {
        self.page_size.saturating_sub(u32::from(self.reserved))
    }
}

/// A read-only view over the raw bytes of a `SQLite` database file.
///
/// Holds the whole file in memory — adequate for the spike and for browser
/// evidence DBs (tens of MB). A `Read + Seek` / mmap backend is a later
/// refinement and does not change the parsing logic proven here.
pub struct Database {
    bytes: Vec<u8>,
    header: Header,
}

/// Hard cap on b-tree pages visited in one table walk, to bound work on a
/// crafted file with cyclic interior pointers.
const MAX_PAGES_PER_WALK: usize = 1_000_000;

impl Database {
    /// Parse the file header and validate magic + page size.
    pub fn open(bytes: Vec<u8>) -> Result<Self, Error> {
        let header = parse_header(&bytes)?;
        Ok(Self { bytes, header })
    }

    #[must_use]
    pub fn header(&self) -> Header {
        self.header
    }

    /// Number of pages in the database file.
    ///
    /// Prefers the in-header DB size (offset 28) when it is a valid, non-zero
    /// value that is consistent with the file length; otherwise falls back to
    /// `file_len / page_size`. A mismatch between the two is itself a forensic
    /// signal (see [`Database::header_page_count`] / [`Database::file_page_count`]).
    #[must_use]
    pub fn page_count(&self) -> u32 {
        let header = self.header_page_count();
        let file = self.file_page_count();
        if header != 0 && header == file {
            header
        } else {
            file
        }
    }

    /// The page count recorded in the file header (offset 28). May be 0 (legacy
    /// "size not valid" sentinel) or disagree with the file length after an
    /// out-of-band truncation/extension.
    #[must_use]
    pub fn header_page_count(&self) -> u32 {
        be_u32(&self.bytes, DB_SIZE_IN_PAGES_OFFSET)
    }

    /// The page count implied by the raw file length (`file_len / page_size`).
    #[must_use]
    pub fn file_page_count(&self) -> u32 {
        let ps = self.header.page_size as usize;
        u32::try_from(self.bytes.len() / ps).unwrap_or(u32::MAX)
    }

    /// The freelist page **count** recorded in the file header (offset 36).
    #[must_use]
    pub fn freelist_count(&self) -> u32 {
        be_u32(&self.bytes, FREELIST_COUNT_OFFSET)
    }

    /// Walk the freelist trunk/leaf chain and return every free (unallocated)
    /// page number, in trunk order. Free pages retain the bytes of whatever they
    /// last held — on a `secure_delete=OFF` database that includes deleted
    /// records, which the analyzer can carve.
    ///
    /// Bounded against crafted cyclic trunk chains: a page already visited, an
    /// out-of-range page, or a leaf-pointer count larger than a trunk page can
    /// hold aborts with [`Error::MalformedFreelist`] rather than looping.
    pub fn freelist_pages(&self) -> Result<Vec<u32>, Error> {
        let mut free = Vec::new();
        let mut trunk = be_u32(&self.bytes, SQLITE_FREELIST_TRUNK_OFFSET);
        let total_pages = self.file_page_count();
        // Each trunk page holds at most (page_size/4 - 2) leaf pointers.
        let max_leaves = (self.header.page_size as usize / 4).saturating_sub(2);
        let mut visited = 0usize;
        let cap = total_pages as usize + 1;

        while trunk != 0 {
            visited += 1;
            if visited > cap {
                return Err(Error::MalformedFreelist);
            }
            if trunk > total_pages {
                return Err(Error::MalformedFreelist);
            }
            let slice = self.page_slice(trunk)?;
            let next = be_u32(slice, 0);
            let leaf_count = be_u32(slice, 4) as usize;
            if leaf_count > max_leaves {
                return Err(Error::MalformedFreelist);
            }
            for i in 0..leaf_count {
                let leaf = be_u32(slice, 8 + i * 4);
                if leaf == 0 || leaf > total_pages {
                    return Err(Error::MalformedFreelist);
                }
                free.push(leaf);
            }
            // The trunk page itself is also a free page.
            free.push(trunk);
            trunk = next;
        }
        Ok(free)
    }

    /// Walk a single table b-tree rooted at `root_page` (1-based) and collect
    /// every leaf row as typed values. `column_count` is the table's declared
    /// column count, used to apply the `INTEGER PRIMARY KEY` rowid-alias rule.
    pub fn read_table(&self, root_page: u32, column_count: usize) -> Result<Vec<Row>, Error> {
        let mut rows = Vec::new();
        let mut visited = 0usize;
        self.walk_table_page(root_page, column_count, &mut rows, &mut visited)?;
        Ok(rows)
    }

    /// Bytes of the 1-based `page` number, or `PageOutOfRange`.
    fn page_slice(&self, page: u32) -> Result<&[u8], Error> {
        if page == 0 {
            return Err(Error::PageOutOfRange(0));
        }
        let ps = self.header.page_size as usize;
        let start = (page as usize - 1) * ps;
        let end = start.checked_add(ps).ok_or(Error::PageOutOfRange(page))?;
        self.bytes
            .get(start..end)
            .ok_or(Error::PageOutOfRange(page))
    }

    fn walk_table_page(
        &self,
        page: u32,
        column_count: usize,
        rows: &mut Vec<Row>,
        visited: &mut usize,
    ) -> Result<(), Error> {
        *visited += 1;
        if *visited > MAX_PAGES_PER_WALK {
            return Err(Error::TooManyPages);
        }
        let slice = self.page_slice(page)?;

        // Page 1 carries the 100-byte file header before its b-tree header.
        let hdr_off = if page == 1 { SQLITE_HEADER_SIZE } else { 0 };

        let page_type = *slice.get(hdr_off).ok_or(Error::TruncatedCell)?;
        let cell_count = be_u16(slice, hdr_off + 3) as usize;

        match page_type {
            0x0d => read_leaf_cells(slice, hdr_off, cell_count, column_count, rows),
            0x05 => {
                // Interior table page: 12-byte header; cell = 4-byte child ptr +
                // varint key. Recurse into every child plus the right-most ptr.
                let cell_ptr_array = hdr_off + 12;
                for i in 0..cell_count {
                    let p = cell_ptr_array + i * 2;
                    let cell_off = be_u16(slice, p) as usize;
                    let child = be_u32(slice, cell_off);
                    self.walk_table_page(child, column_count, rows, visited)?;
                }
                let right = be_u32(slice, hdr_off + 8);
                self.walk_table_page(right, column_count, rows, visited)
            }
            other => Err(Error::NotATablePage(other)),
        }
    }
}

fn read_leaf_cells(
    slice: &[u8],
    hdr_off: usize,
    cell_count: usize,
    column_count: usize,
    rows: &mut Vec<Row>,
) -> Result<(), Error> {
    let cell_ptr_array = hdr_off + 8; // leaf b-tree header is 8 bytes
    for i in 0..cell_count {
        let p = cell_ptr_array + i * 2;
        let cell_off = be_u16(slice, p) as usize;
        let row = decode_leaf_cell(slice, cell_off, column_count)?;
        rows.push(row);
    }
    Ok(())
}

/// Decode one table-leaf cell at `off` into a [`Row`]. Overflow pages are out
/// of spike scope: we only read payload bytes present on the page (never
/// over-read past the page).
fn decode_leaf_cell(slice: &[u8], off: usize, column_count: usize) -> Result<Row, Error> {
    let (_payload_len, n1) = read_varint(slice, off)?;
    let (rowid, n2) = read_varint(slice, off + n1)?;
    let payload_start = off + n1 + n2;
    let payload = slice.get(payload_start..).ok_or(Error::TruncatedCell)?;
    let values = decode_record(payload, column_count, rowid)?;
    Ok(Row { rowid, values })
}

/// Parse + validate the 100-byte file header.
fn parse_header(bytes: &[u8]) -> Result<Header, Error> {
    let head = bytes.get(..SQLITE_HEADER_SIZE).ok_or(Error::TooShort)?;
    if !head.starts_with(SQLITE_MAGIC) {
        return Err(Error::BadMagic);
    }
    let raw = be_u16(head, SQLITE_PAGE_SIZE_OFFSET);
    let page_size: u32 = if raw == 1 { 65536 } else { u32::from(raw) };
    let valid = (512..=65536).contains(&page_size) && page_size.is_power_of_two();
    if !valid {
        return Err(Error::BadPageSize(page_size));
    }
    let reserved = *head.get(RESERVED_SPACE_OFFSET).ok_or(Error::TooShort)?;
    Ok(Header {
        page_size,
        reserved,
    })
}

/// Decode a record (payload) into values. Serial type 0 on the first column of
/// a rowid table is the `INTEGER PRIMARY KEY` alias → the cell's rowid.
fn decode_record(payload: &[u8], _column_count: usize, rowid: i64) -> Result<Vec<Value>, Error> {
    let (header_len, n) = read_varint(payload, 0)?;
    let header_len = header_len as usize;
    if header_len > payload.len() {
        return Err(Error::TruncatedCell);
    }
    // Pass 1: read serial types from the record header.
    let mut serials = Vec::new();
    let mut hpos = n;
    while hpos < header_len {
        let (s, used) = read_varint(payload, hpos)?;
        serials.push(s);
        hpos += used;
    }
    // Pass 2: read the body, one value per serial type.
    let mut values = Vec::with_capacity(serials.len());
    let mut bpos = header_len;
    for (idx, &serial) in serials.iter().enumerate() {
        let (val, size) = decode_value(payload, bpos, serial)?;
        let val = if idx == 0 && serial == 0 {
            // INTEGER PRIMARY KEY alias: NULL in column 0 reads the rowid.
            Value::Integer(rowid)
        } else {
            val
        };
        values.push(val);
        bpos += size;
    }
    Ok(values)
}

/// Decode a single value of the given serial type at `off`. Returns the value
/// and the number of body bytes it consumed.
fn decode_value(buf: &[u8], off: usize, serial: i64) -> Result<(Value, usize), Error> {
    Ok(match serial {
        // 0 = NULL; 10/11 are reserved for internal use and surfaced as NULL.
        0 | 10 | 11 => (Value::Null, 0),
        1 => (
            Value::Integer(i64::from(read_be_u64(buf, off, 1)? as i8)),
            1,
        ),
        2 => (
            Value::Integer(i64::from(read_be_u64(buf, off, 2)? as i16)),
            2,
        ),
        3 => (Value::Integer(sign_extend(read_be_u64(buf, off, 3)?, 3)), 3),
        4 => (
            Value::Integer(i64::from(read_be_u64(buf, off, 4)? as i32)),
            4,
        ),
        5 => (Value::Integer(sign_extend(read_be_u64(buf, off, 6)?, 6)), 6),
        6 => (Value::Integer(read_be_u64(buf, off, 8)? as i64), 8),
        7 => {
            let bits = read_be_u64(buf, off, 8)?;
            (Value::Real(f64::from_bits(bits)), 8)
        }
        8 => (Value::Integer(0), 0),
        9 => (Value::Integer(1), 0),
        n if n >= 12 && n % 2 == 0 => {
            let len = ((n - 12) / 2) as usize;
            let bytes = buf.get(off..off + len).ok_or(Error::TruncatedCell)?;
            (Value::Blob(bytes.to_vec()), len)
        }
        n => {
            // odd, >= 13: UTF-8 text. Lossy decode so a corrupt byte can't panic.
            let len = ((n - 13) / 2) as usize;
            let bytes = buf.get(off..off + len).ok_or(Error::TruncatedCell)?;
            (
                Value::Text(String::from_utf8_lossy(bytes).into_owned()),
                len,
            )
        }
    })
}

/// Read `width` (1..=8) big-endian bytes into a raw u64 (no sign extension).
fn read_be_u64(buf: &[u8], off: usize, width: usize) -> Result<u64, Error> {
    let bytes = buf.get(off..off + width).ok_or(Error::TruncatedCell)?;
    let mut acc: u64 = 0;
    for &b in bytes {
        acc = (acc << 8) | u64::from(b);
    }
    Ok(acc)
}

/// Sign-extend a `width`-byte (3 or 6) value held in the low bits of `raw`.
fn sign_extend(raw: u64, width: usize) -> i64 {
    let bits = width * 8;
    let shift = 64 - bits;
    ((raw as i64) << shift) >> shift
}

/// Read a `SQLite` varint (1..=9 bytes) at `off`. Returns value + bytes consumed.
fn read_varint(buf: &[u8], off: usize) -> Result<(i64, usize), Error> {
    let mut result: u64 = 0;
    for i in 0..8 {
        let b = *buf.get(off + i).ok_or(Error::TruncatedCell)?;
        result = (result << 7) | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            return Ok((result as i64, i + 1));
        }
    }
    // 9th byte contributes all 8 bits.
    let b = *buf.get(off + 8).ok_or(Error::TruncatedCell)?;
    result = (result << 8) | u64::from(b);
    Ok((result as i64, 9))
}

/// Bounds-checked big-endian u16; out-of-range yields 0 (never panics).
fn be_u16(buf: &[u8], off: usize) -> u16 {
    let mut b = [0u8; 2];
    if let Some(s) = buf.get(off..off + 2) {
        b.copy_from_slice(s);
    }
    u16::from_be_bytes(b)
}

/// Bounds-checked big-endian u32; out-of-range yields 0 (never panics).
fn be_u32(buf: &[u8], off: usize) -> u32 {
    let mut b = [0u8; 4];
    if let Some(s) = buf.get(off..off + 4) {
        b.copy_from_slice(s);
    }
    u32::from_be_bytes(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_single_byte() {
        assert_eq!(read_varint(&[0x05], 0).unwrap(), (5, 1));
    }

    #[test]
    fn varint_two_bytes() {
        // 0x81 0x00 => (1<<7) = 128
        assert_eq!(read_varint(&[0x81, 0x00], 0).unwrap(), (128, 2));
    }

    #[test]
    fn varint_truncated_is_err() {
        assert_eq!(read_varint(&[0x81], 0), Err(Error::TruncatedCell));
    }

    #[test]
    fn sign_extend_three_byte_negative() {
        // 0xFFFFFF as 3-byte => -1
        assert_eq!(sign_extend(0x00FF_FFFF, 3), -1);
    }

    #[test]
    fn decode_value_text_and_blob() {
        let (v, n) = decode_value(b"hi", 0, 17).unwrap(); // 17 => text len (17-13)/2 = 2
        assert_eq!(v, Value::Text("hi".into()));
        assert_eq!(n, 2);
        let (v, n) = decode_value(&[0xAA, 0xBB], 0, 16).unwrap(); // 16 => blob len 2
        assert_eq!(v, Value::Blob(vec![0xAA, 0xBB]));
        assert_eq!(n, 2);
    }

    #[test]
    fn decode_value_int_literals() {
        assert_eq!(decode_value(&[], 0, 8).unwrap(), (Value::Integer(0), 0));
        assert_eq!(decode_value(&[], 0, 9).unwrap(), (Value::Integer(1), 0));
    }

    #[test]
    fn bad_magic_rejected() {
        let mut b = vec![0u8; 100];
        b[..16].copy_from_slice(b"NOT SQLITE 3\0\0\0\0");
        assert_eq!(parse_header(&b), Err(Error::BadMagic));
    }

    #[test]
    fn too_short_rejected() {
        assert_eq!(parse_header(&[0u8; 10]), Err(Error::TooShort));
    }
}
