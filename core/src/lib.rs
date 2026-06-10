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

/// A record-shaped cell recovered from unallocated / free space by
/// [`Database::carve_cells`]. Carries the decoded row plus enough provenance for
/// the analyzer to grade it as a "consistent with a deleted row" observation.
#[derive(Debug, Clone, PartialEq)]
pub struct CarvedCell {
    /// Byte offset of the cell within the page slice that was scanned.
    pub offset: usize,
    /// Total bytes the candidate cell occupies (cell header + payload), so the
    /// scanner can skip past a recovered record.
    pub byte_len: usize,
    /// Decoded rowid varint.
    pub rowid: i64,
    /// Decoded column values, in column order.
    pub values: Vec<Value>,
    /// Heuristic confidence in `(0.0, 1.0]` that these bytes are a real record
    /// rather than a coincidental match.
    pub confidence: f32,
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
    /// Read-only WAL overlay: newest committed page versions from a `-wal`
    /// sidecar, applied without checkpointing (never mutates `bytes`).
    /// `None` when opened without a WAL.
    wal: Option<WalOverlay>,
}

/// The newest committed version of each WAL page, materialized into owned bytes.
///
/// Built once at open; `page_slice` consults it before the main file so a table
/// walk transparently sees the WAL-applied view. Read-only: building it copies
/// frame data out of the `-wal` sidecar and never writes back to either file.
struct WalOverlay {
    /// page number (1-based) → that page's newest committed contents.
    pages: std::collections::BTreeMap<u32, Vec<u8>>,
}

/// Hard cap on b-tree pages visited in one table walk, to bound work on a
/// crafted file with cyclic interior pointers.
const MAX_PAGES_PER_WALK: usize = 1_000_000;

/// WAL magic, big-endian variant (native byte order in the page checksums; the
/// little-endian variant `0x377f_0683` differs only in checksum endianness,
/// which the overlay does not verify). file-format §4.1.
const WAL_MAGIC_BE: u32 = 0x377f_0682;
/// WAL magic, little-endian-checksum variant.
const WAL_MAGIC_LE: u32 = 0x377f_0683;

impl Database {
    /// Parse the file header and validate magic + page size. No WAL overlay.
    pub fn open(bytes: Vec<u8>) -> Result<Self, Error> {
        let header = parse_header(&bytes)?;
        Ok(Self {
            bytes,
            header,
            wal: None,
        })
    }

    /// Parse the main database plus a `-wal` sidecar, overlaying the newest
    /// **committed** page versions from the WAL on top of the main file.
    ///
    /// This is the forensic-safe alternative to libsqlite checkpointing: neither
    /// file is mutated. The resulting [`Database`] answers `read_table` with the
    /// WAL-applied view (use [`Database::open`] for the main-only view). Frames
    /// past the last commit frame, or whose salt does not match the WAL header,
    /// are ignored — they are uncommitted / superseded and not part of the
    /// consistent snapshot.
    pub fn open_with_wal(bytes: Vec<u8>, wal: &[u8]) -> Result<Self, Error> {
        let header = parse_header(&bytes)?;
        let overlay = WalOverlay::parse(wal, header.page_size)?;
        Ok(Self {
            bytes,
            header,
            wal: overlay,
        })
    }

    /// Whether a non-empty WAL overlay is in effect (at least one committed
    /// frame was applied on top of the main file).
    #[must_use]
    pub fn wal_applied(&self) -> bool {
        self.wal.as_ref().is_some_and(|w| !w.pages.is_empty())
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

    /// Raw bytes of the 1-based `page` from the **main file only**, ignoring any
    /// WAL overlay. Carving wants the on-disk page (where deleted residue lives),
    /// not the WAL-applied view. Returns `None` for page 0 or out-of-range pages.
    #[must_use]
    pub fn raw_page(&self, page: u32) -> Option<&[u8]> {
        if page == 0 {
            return None;
        }
        let ps = self.header.page_size as usize;
        let start = (page as usize - 1).checked_mul(ps)?;
        let end = start.checked_add(ps)?;
        self.bytes.get(start..end)
    }

    /// Scan a slice of page bytes for record-shaped table-leaf cells of exactly
    /// `column_count` columns, recovering each as a [`CarvedCell`].
    ///
    /// This is the carving primitive the forensic analyzer drives over free /
    /// unallocated regions: at every byte offset it speculatively parses a
    /// `payload_len` varint, a `rowid` varint, and a record header, accepting the
    /// candidate only when the serial-type count matches `column_count`, the
    /// declared lengths stay within the slice, and every value decodes. Strict
    /// validation keeps the false-positive rate low; `confidence` reflects how
    /// strongly the bytes are record-shaped. Bounded: each offset does O(record)
    /// work and the scan is linear in the slice length.
    #[must_use]
    pub fn carve_cells(&self, page_bytes: &[u8], column_count: usize) -> Vec<CarvedCell> {
        let mut out = Vec::new();
        if column_count == 0 {
            return out;
        }
        let mut off = 0usize;
        while off < page_bytes.len() {
            if let Some(cell) = try_carve_cell_at(page_bytes, off, column_count) {
                // Skip past this record to avoid re-reporting sub-slices of it.
                off += cell.byte_len.max(1);
                out.push(cell);
            } else {
                off += 1;
            }
        }
        out
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
    ///
    /// When a WAL overlay is in effect and holds a committed version of this
    /// page, the overlaid bytes are returned in preference to the main file —
    /// this is what makes a table walk see the WAL-applied view. The main file
    /// is never mutated.
    fn page_slice(&self, page: u32) -> Result<&[u8], Error> {
        if page == 0 {
            return Err(Error::PageOutOfRange(0));
        }
        if let Some(wal) = &self.wal {
            if let Some(overlaid) = wal.pages.get(&page) {
                return Ok(overlaid.as_slice());
            }
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
            0x0d => self.read_leaf_cells(slice, hdr_off, cell_count, column_count, rows),
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

    fn read_leaf_cells(
        &self,
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
            let row = self.decode_leaf_cell(slice, cell_off, column_count)?;
            rows.push(row);
        }
        Ok(())
    }

    /// Decode one table-leaf cell at `off` into a [`Row`], reassembling the
    /// payload from its overflow-page chain when it spills past the leaf page.
    fn decode_leaf_cell(
        &self,
        slice: &[u8],
        off: usize,
        column_count: usize,
    ) -> Result<Row, Error> {
        let (payload_len, n1) = read_varint(slice, off)?;
        let (rowid, n2) = read_varint(slice, off + n1)?;
        let payload_start = off + n1 + n2;
        let total = usize::try_from(payload_len).map_err(|_| Error::TruncatedCell)?;

        let usable = self.header.usable_size() as usize;
        let local = local_payload_len(total, usable);

        let payload = if local >= total {
            // Whole payload is on the leaf page (no spill).
            slice
                .get(payload_start..payload_start + total)
                .ok_or(Error::TruncatedCell)?
                .to_vec()
        } else {
            // Spilled: `local` bytes on the leaf, then a 4-byte overflow page
            // pointer, then the remainder follows the overflow chain.
            let head = slice
                .get(payload_start..payload_start + local)
                .ok_or(Error::TruncatedCell)?;
            let first_overflow = be_u32(slice, payload_start + local);
            let mut buf = Vec::with_capacity(total);
            buf.extend_from_slice(head);
            self.read_overflow_chain(first_overflow, total - local, &mut buf)?;
            buf
        };

        let values = decode_record(&payload, column_count, rowid)?;
        Ok(Row { rowid, values })
    }

    /// Follow an overflow-page chain starting at `first` (1-based page number),
    /// appending up to `remaining` payload bytes to `buf`. Each overflow page is
    /// a 4-byte big-endian "next page" pointer (0 ends the chain) followed by up
    /// to `usable - 4` content bytes.
    ///
    /// Bounded against cyclic/over-long chains via [`Error::MalformedOverflow`].
    fn read_overflow_chain(
        &self,
        first: u32,
        mut remaining: usize,
        buf: &mut Vec<u8>,
    ) -> Result<(), Error> {
        let usable = self.header.usable_size() as usize;
        let per_page = usable.saturating_sub(4);
        if per_page == 0 {
            return Err(Error::MalformedOverflow);
        }
        let total_pages = self.file_page_count();
        let cap = total_pages as usize + 1;

        let mut page = first;
        let mut visited = 0usize;
        while remaining > 0 {
            if page == 0 || page > total_pages {
                return Err(Error::MalformedOverflow);
            }
            visited += 1;
            if visited > cap {
                return Err(Error::MalformedOverflow);
            }
            let slice = self.page_slice(page)?;
            let next = be_u32(slice, 0);
            let take = remaining.min(per_page);
            let chunk = slice.get(4..4 + take).ok_or(Error::TruncatedCell)?;
            buf.extend_from_slice(chunk);
            remaining -= take;
            page = next;
        }
        Ok(())
    }
}

/// Number of payload bytes stored locally on a table-leaf page for a record of
/// `total` bytes, given the page's `usable` size (file-format §1.6 overflow
/// rule). When the return value equals `total`, the record does not spill.
fn local_payload_len(total: usize, usable: usize) -> usize {
    let max_local = usable - 35; // X: largest payload kept entirely local
    if total <= max_local {
        return total;
    }
    let min_local = (usable - 12) * 32 / 255 - 23; // M
    let k = min_local + (total - min_local) % (usable - 4);
    if k <= max_local {
        k
    } else {
        min_local
    }
}

impl WalOverlay {
    /// Parse a `-wal` sidecar into the newest committed page versions.
    ///
    /// Returns `Ok(None)` when `wal` is absent of a usable header / has no
    /// frames (a no-op overlay). Iterates frames in file order, accumulating the
    /// page data of each frame whose salt matches the WAL header; on reaching a
    /// COMMIT frame (`db_size_after_commit != 0`) the accumulated pages are
    /// promoted into the committed snapshot. Frames after the last commit are
    /// uncommitted and dropped. Bounds-checked and breadth-capped against a
    /// crafted WAL (a frame whose declared page data runs past the file ends the
    /// scan rather than panicking).
    fn parse(wal: &[u8], page_size: u32) -> Result<Option<Self>, Error> {
        use forensicnomicon::sqlite::{SQLITE_WAL_FRAME_HEADER_SIZE, SQLITE_WAL_HEADER_SIZE};

        // No header → no overlay (treat a too-short WAL as empty, not an error:
        // a missing/zero-length sidecar is normal and must not fail the open).
        let Some(hdr) = wal.get(..SQLITE_WAL_HEADER_SIZE) else {
            return Ok(None);
        };
        let magic = be_u32(hdr, 0);
        if magic != WAL_MAGIC_BE && magic != WAL_MAGIC_LE {
            return Ok(None);
        }
        // The WAL records its own page size (offset 8); trust the DB header's
        // page size but require agreement to avoid mis-slicing frames.
        let wal_page_size = be_u32(hdr, 8);
        if wal_page_size != page_size {
            return Ok(None);
        }
        // WAL header layout (file-format §4.1): salt-1 at offset 16, salt-2 at
        // offset 20 (the two checksum words follow at 24 and 28).
        let salt1 = be_u32(hdr, 16);
        let salt2 = be_u32(hdr, 20);

        let ps = page_size as usize;
        let frame_stride = SQLITE_WAL_FRAME_HEADER_SIZE + ps;

        let mut committed: std::collections::BTreeMap<u32, Vec<u8>> =
            std::collections::BTreeMap::new();
        let mut pending: std::collections::BTreeMap<u32, Vec<u8>> =
            std::collections::BTreeMap::new();

        let mut off = SQLITE_WAL_HEADER_SIZE;
        // One frame per page in the file is the natural breadth cap; allow a
        // generous multiple for repeated rewrites, but keep it bounded.
        let max_frames = wal.len() / frame_stride + 1;
        let mut frame_no = 0usize;

        while let Some(frame) = wal.get(off..off + frame_stride) {
            frame_no += 1;
            if frame_no > max_frames {
                break; // cov:unreachable: the slice walk already bounds frame_no
            }
            let page_no = be_u32(frame, 0);
            let db_size = be_u32(frame, 4);
            let fsalt1 = be_u32(frame, 8);
            let fsalt2 = be_u32(frame, 12);
            // A frame from a different checkpoint generation (salt mismatch) is
            // stale residue, not part of this WAL's live content — stop here.
            if fsalt1 != salt1 || fsalt2 != salt2 {
                break;
            }
            if page_no == 0 {
                break; // malformed frame; stop rather than mis-index
            }
            let data = frame
                .get(SQLITE_WAL_FRAME_HEADER_SIZE..)
                .ok_or(Error::TruncatedCell)?;
            pending.insert(page_no, data.to_vec());

            if db_size != 0 {
                // COMMIT frame: promote everything pending into the snapshot.
                for (p, d) in std::mem::take(&mut pending) {
                    committed.insert(p, d);
                }
            }
            off += frame_stride;
        }

        if committed.is_empty() {
            Ok(None)
        } else {
            Ok(Some(WalOverlay { pages: committed }))
        }
    }
}

/// The body byte-width of a serial type (file-format §2.1), or `None` for a
/// serial value that cannot legally appear in a record body.
fn serial_body_len(serial: i64) -> Option<usize> {
    match serial {
        0 | 8 | 9 | 10 | 11 => Some(0),
        1 => Some(1),
        2 => Some(2),
        3 => Some(3),
        4 => Some(4),
        5 => Some(6),
        6 | 7 => Some(8),
        n if n >= 12 => Some(((n - 12) / 2) as usize),
        _ => None, // negative serial: impossible
    }
}

/// Attempt to recognize a table-leaf cell at `off` in `buf` as a record of
/// exactly `column_count` columns. Returns a [`CarvedCell`] only when the bytes
/// are self-consistently record-shaped; otherwise `None` (a non-match at this
/// offset). Never panics — every access is bounds-checked.
fn try_carve_cell_at(buf: &[u8], off: usize, column_count: usize) -> Option<CarvedCell> {
    // Cell prefix: payload_len varint, rowid varint.
    let (payload_len, n1) = read_varint(buf, off).ok()?;
    let payload_len = usize::try_from(payload_len).ok()?;
    if payload_len == 0 {
        return None;
    }
    let (rowid, n2) = read_varint(buf, off + n1).ok()?;
    // A negative rowid is legal but vanishingly rare for browser tables; treat a
    // non-positive rowid as a non-match to suppress coincidental hits.
    if rowid <= 0 {
        return None;
    }
    let payload_start = off + n1 + n2;
    let payload = buf.get(payload_start..payload_start + payload_len)?;

    // Record header: header_len varint, then one serial type per column.
    let (header_len, hn) = read_varint(payload, 0).ok()?;
    let header_len = usize::try_from(header_len).ok()?;
    if header_len > payload.len() || header_len < hn {
        return None;
    }
    let mut serials = Vec::with_capacity(column_count);
    let mut hpos = hn;
    while hpos < header_len {
        let (s, used) = read_varint(payload, hpos).ok()?;
        serials.push(s);
        hpos += used;
    }
    // Exactly the right column count, and the header consumed cleanly.
    if serials.len() != column_count || hpos != header_len {
        return None;
    }

    // Body length implied by the serial types must equal payload_len - header_len
    // — a strong self-consistency check that rejects coincidental matches.
    let mut body_len = 0usize;
    for &s in &serials {
        body_len += serial_body_len(s)?;
    }
    if header_len + body_len != payload_len {
        return None;
    }

    // Decode the record (reusing the live decoder for storage-class fidelity).
    let values = decode_record(payload, column_count, rowid).ok()?;
    if values.len() != column_count {
        return None; // cov:unreachable: decode_record yields one value per serial
    }

    // Confidence: a fully self-consistent record already passed strong checks;
    // raise confidence when at least one column is a non-empty, valid-UTF-8 TEXT
    // (record-shaped *and* human-meaningful), which coincidental byte runs rarely
    // satisfy.
    let has_real_text = values.iter().any(|v| match v {
        Value::Text(t) => !t.is_empty() && !t.contains('\u{FFFD}'),
        _ => false,
    });
    let confidence = if has_real_text { 0.9 } else { 0.6 };

    Some(CarvedCell {
        offset: off,
        byte_len: (payload_start + payload_len) - off,
        rowid,
        values,
        confidence,
    })
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
