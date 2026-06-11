//! `sqlite-core` — native, read-only, panic-free `SQLite` file-format reader.
//!
//! Parses the 100-byte file header (magic + page size), walks table b-trees
//! (interior + leaf) yielding rows as typed [`Value`]s, reassembles
//! overflow-page chains for large payloads, walks the freelist
//! ([`Database::freelist_pages`]), and applies a read-only `-wal` overlay
//! ([`Database::open_with_wal`]) — all bounds-checked and panic-free on crafted
//! input. [`Database::carve_cells`] recognizes record-shaped cells in
//! free/unallocated space for the analyzer's deleted-record recovery. The bespoke
//! [`WalTimeline`] ([`Database::wal_timeline`]) models a `-wal` as a salt-bounded
//! segment of materializable [`CommitSnapshot`]s for "carve all snapshots".
//!
//! Format constants are consumed from [`forensicnomicon::sqlite`] (the KNOWLEDGE
//! leaf) where exposed; a few not-yet-promoted offsets (reserved-space 20,
//! in-header DB-size 28, freelist-count 36) are held locally and flagged for
//! promotion. Still out of scope: index b-trees, `WITHOUT ROWID` tables,
//! UTF-16 text, and WAL frame-checksum verification.

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

/// A **partial** deleted record salvaged from a freed-cell reconstruction that
/// failed full-row validation: the maximal decodable column prefix at a
/// structural anchor [`Database::reconstruct_freeblock_records`] already trusts.
///
/// Deliberately NOT a [`CarvedCell`]: it has no rowid (clobbered) and an
/// incomplete value set, so the type system keeps it out of the full-row output
/// — a fragment can never be silently rendered as a recovered row. Emitted only
/// at an anchor where full reconstruction failed but at least one *distinctive*
/// cell (TEXT ≥ 4 bytes of valid UTF-8, or REAL) decoded cleanly, so a lone
/// coincidental integer pattern never anchors a fragment. Graded
/// [`FRAGMENT_CONFIDENCE`] — strictly below every full-row class.
#[derive(Debug, Clone, PartialEq)]
pub struct CellFragment {
    /// Byte offset of the failed cell's anchor within the scanned page slice.
    pub offset: usize,
    /// Bytes covered by the decoded prefix (anchor to the last decoded body byte).
    pub byte_len: usize,
    /// `(column_index, value)` for each column that decoded cleanly, ascending by
    /// index. Column indexes come from the page's schema template, so they are
    /// meaningful against the table's column order.
    pub surviving: Vec<(usize, Value)>,
    /// Number of the template's columns that did NOT decode (`column_count` minus
    /// the number of surviving columns).
    pub missing: usize,
    /// Always [`FRAGMENT_CONFIDENCE`] for now; the field is kept so future
    /// per-fragment grading does not change the public type.
    pub confidence: f32,
}

/// A freed table-leaf cell whose declared payload **spills onto an overflow-page
/// chain** (task #73). Recognized by [`try_carve_spilled_cell_at`] from the
/// cell's intact local prefix; the chain itself is resolved separately
/// ([`Database::read_freed_overflow_chain`]) because that needs whole-database
/// access. A `SpilledCell` is deliberately NOT a [`CarvedCell`]: until its chain
/// is walked and validated it cannot masquerade as a recovered row (secure by
/// design — the type system keeps an unresolved spill out of the full-row output).
#[derive(Debug, Clone, PartialEq)]
pub struct SpilledCell {
    /// Byte offset of the cell within the scanned slice.
    pub offset: usize,
    /// On-page footprint of the cell prefix: `n1 + n2 + local_len + 4`.
    pub byte_len: usize,
    /// Declared total payload length `P` (header + full body).
    pub payload_len: usize,
    /// Decoded rowid varint (intact-prefix anchors); `0` when the prefix was
    /// clobbered and the rowid is unrecoverable (template path).
    pub rowid: i64,
    /// Full serial-type array, decoded from the local record header.
    pub serials: Vec<i64>,
    /// Local payload bytes kept on the leaf page (`local_payload_len(P, usable)`).
    pub local_len: usize,
    /// Offset, within the scanned slice, at which the local payload begins.
    pub local_payload_off: usize,
    /// First overflow-page number (big-endian u32 at `local_payload_off + local_len`).
    pub first_overflow: u32,
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
    /// Every committed frame's page image, in file order, with provenance. Unlike
    /// `pages` (newest version per page, the consistent view), this keeps EACH
    /// committed frame so the carver can recover deleted residue that a later
    /// frame for the same page superseded in `pages` but that still survives in an
    /// earlier frame's slack — the genuinely-different records an on-disk-only
    /// carve cannot see.
    frames: Vec<WalFramePage>,
    /// The original `-wal` sidecar bytes, retained so [`Database::wal_timeline`]
    /// can re-parse them into the richer segmented temporal model without the
    /// caller re-supplying the file. Held read-only; never mutated.
    raw: Vec<u8>,
}

/// One committed WAL frame's full page image plus its provenance, exposed by
/// [`Database::wal_frame_pages`] so the deleted-record carver can scan the
/// uncheckpointed WAL frames the main file does not yet reflect.
///
/// The `(salt1, salt2, frame_index)` triple is the WAL log-sequence identity that
/// task #55 will formalize: `salt1`/`salt2` pin the checkpoint generation and
/// `frame_index` the position within it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalFramePage {
    /// 0-based position of this frame within the `-wal` file (its LSN ordinal).
    pub frame_index: usize,
    /// 1-based database page number this frame rewrites.
    pub page_no: u32,
    /// WAL header salt-1 (checkpoint generation), shared by every live frame.
    pub salt1: u32,
    /// WAL header salt-2 (checkpoint generation), shared by every live frame.
    pub salt2: u32,
    /// Whether this is a COMMIT frame (`db_size_after_commit != 0`).
    pub is_commit: bool,
    /// The frame's full page image (`page_size` bytes).
    pub page: Vec<u8>,
}

/// Hard cap on b-tree pages visited in one table walk, to bound work on a
/// crafted file with cyclic interior pointers.
const MAX_PAGES_PER_WALK: usize = 1_000_000;

/// Minimum column count accepted when **inferring** a record's width during
/// dropped-table carving. A coincidental byte run can look like a self-consistent
/// 1-column record far too easily; requiring at least two columns (the smallest a
/// real rowid table with a non-rowid column has) suppresses that false-positive
/// class without losing real records.
const MIN_INFERRED_COLUMNS: usize = 2;

/// Confidence multiplier applied to records carved from an allocated page's
/// in-page free space. Such residue is more often partially overwritten (its
/// freeblock may have been reused) than whole-page freelist recovery, so it is
/// graded a notch lower even when it parses cleanly.
const IN_PAGE_CONFIDENCE_FACTOR: f32 = 0.8;

/// Confidence assigned to a record rebuilt by **freeblock reconstruction**
/// ([`Database::reconstruct_freeblock_records`]). The cell's first four bytes
/// (payload-length + rowid varints, the record `header_len`, and the leading
/// serial type) were destroyed by freeblock conversion, so the record is rebuilt
/// from its surviving serial-type tail plus a schema-derived header template — a
/// weaker reconstruction than an intact-header carve, hence graded LOW (a
/// "consistent with a deleted row" lead the examiner weighs, never a certainty).
const FREEBLOCK_RECONSTRUCT_CONFIDENCE: f32 = 0.4;

/// Confidence assigned to a Tier-2 [`CellFragment`] — a partial recovery whose
/// full row could not be reconstructed but at least one distinctive cell survived.
/// Flat 0.2 = the `MinConfidence::Low` threshold, one notch below freeblock
/// reconstruction's 0.4 (= Medium): a fragment is the weakest lead in the ladder,
/// "consistent with a partial deleted row", never a recovered row.
const FRAGMENT_CONFIDENCE: f32 = 0.2;

/// Upper bound on the number of freeblocks walked on a single page, to cap work
/// on a crafted file whose freeblock `next` pointers form a long or cyclic chain.
/// Real pages hold at most a few hundred cells.
const MAX_FREEBLOCKS_PER_PAGE: usize = 4096;

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

    /// Every committed `-wal` frame's page image, in file order, with provenance.
    ///
    /// Empty when the database was opened without a WAL (or the WAL held no
    /// committed frames). The carver scans these page images for deleted-cell
    /// residue that lives ONLY in the uncheckpointed WAL — the genuinely-different
    /// records the on-disk pages do not hold — tagging each with the
    /// `(salt1, salt2, frame_index)` log-sequence identity.
    #[must_use]
    pub fn wal_frame_pages(&self) -> &[WalFramePage] {
        self.wal.as_ref().map_or(&[], |w| w.frames.as_slice())
    }

    /// Build the bespoke, format-exact [`WalTimeline`] for this database's `-wal`
    /// sidecar, if one was supplied to [`Database::open_with_wal`].
    ///
    /// Returns `None` when the database was opened without a WAL, or the WAL held
    /// no committed frame (no materializable state). The timeline enumerates the
    /// segment's [`CommitSnapshot`]s — the only materializable database states —
    /// each addressable by [`CommitId`]; see [`WalTimeline`].
    ///
    /// This consults the original `-wal` bytes retained at open time, re-parsing
    /// them into the richer temporal model (the on-open [`WalOverlay`] keeps only
    /// the consistent-view pages; the timeline keeps every segment, snapshot, and
    /// residue tail). A page-size mismatch or malformed header surfaces as `None`
    /// here — use [`Database::wal_timeline_from`] when you need the typed
    /// [`WalValidationError`].
    #[must_use]
    pub fn wal_timeline(&self) -> Option<WalTimeline> {
        let raw = self.wal.as_ref()?.raw.as_slice();
        WalTimeline::parse(&self.bytes, raw, self.header.page_size).ok()
    }

    /// Parse a main database + `-wal` sidecar directly into a [`WalTimeline`],
    /// surfacing the typed [`WalValidationError`] when the WAL is malformed.
    ///
    /// This is the validation-tier entry point: a page-size mismatch between the DB
    /// header and the WAL header is a HARD STOP ([`WalValidationError::PageSizeMismatch`]),
    /// not a silently mis-sliced overlay; a bad magic / unparsable header is
    /// [`WalValidationError::BadMagic`]. Both are caught at the physical-validation
    /// tier before any replay.
    pub fn wal_timeline_from(bytes: &[u8], wal: &[u8]) -> Result<WalTimeline, WalValidationError> {
        let header = parse_header(bytes).map_err(WalValidationError::Header)?;
        WalTimeline::parse(bytes, wal, header.page_size)
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
            if let Some(cell) = try_carve_cell_at(page_bytes, off, Some(column_count)) {
                // Skip past this record to avoid re-reporting sub-slices of it.
                off += cell.byte_len.max(1);
                out.push(cell);
            } else {
                off += 1;
            }
        }
        out
    }

    /// Carve record-shaped cells from a page slice **inferring** each record's
    /// column count from its own serial-type array, instead of requiring a fixed
    /// count. This is what makes **dropped-table / schema-gone** recovery
    /// possible: the page's table was `DROP`ped, so `sqlite_master` no longer
    /// records a column count, but each record still self-describes its columns.
    ///
    /// Inferring the count removes one validity check, so the remaining
    /// self-consistency checks are kept strict to hold the false-positive rate
    /// down: `header_len + body_len == payload_len`, every serial type legal,
    /// `rowid > 0`, the payload fully in-bounds, and at least
    /// [`MIN_INFERRED_COLUMNS`] columns. Records carved this way are graded a
    /// notch lower in confidence than fixed-count carving.
    #[must_use]
    pub fn carve_cells_inferred(&self, page_bytes: &[u8]) -> Vec<CarvedCell> {
        let mut out = Vec::new();
        let mut off = 0usize;
        while off < page_bytes.len() {
            if let Some(cell) = try_carve_cell_at(page_bytes, off, None) {
                off += cell.byte_len.max(1);
                out.push(cell);
            } else {
                off += 1;
            }
        }
        out
    }

    /// Decode **every cell present in a table-leaf page image** (type `0x0D`) by
    /// walking its cell-pointer array, inferring each record's column count from
    /// its own serial-type array. Unlike [`Database::carve_free_regions`] (which
    /// scans only free space and excludes live cells), this returns the cells the
    /// page itself records as allocated.
    ///
    /// This is the primitive WAL-frame recovery needs: a `-wal` frame is a full
    /// page snapshot at one point in time, so a cell that is allocated in an
    /// EARLIER frame's image but absent from the final WAL-applied view is a row
    /// that was deleted later and survives ONLY in that superseded frame. The
    /// caller filters the returned cells against the final live view to isolate
    /// exactly those genuinely-deleted rows (so a still-live row is never
    /// re-surfaced — the filter is the caller's responsibility, mirroring the
    /// freeblock-reconstruction discipline).
    ///
    /// Bounded and panic-free: a malformed cell pointer or record simply yields
    /// fewer cells. Non-leaf pages yield nothing.
    #[must_use]
    pub fn carve_leaf_cells(&self, page_bytes: &[u8]) -> Vec<CarvedCell> {
        let hdr_off = if page_bytes.starts_with(SQLITE_MAGIC) {
            SQLITE_HEADER_SIZE
        } else {
            0
        };
        let Some(&page_type) = page_bytes.get(hdr_off) else {
            return Vec::new();
        };
        if page_type != 0x0d {
            return Vec::new(); // only table-leaf pages hold decodable cells here
        }
        let cell_count = be_u16(page_bytes, hdr_off + 3) as usize;
        let cell_ptr_array = hdr_off + 8; // leaf b-tree header is 8 bytes
        let mut out = Vec::new();
        for i in 0..cell_count {
            let cell_off = be_u16(page_bytes, cell_ptr_array + i * 2) as usize;
            if cell_off == 0 || cell_off >= page_bytes.len() {
                continue; // cov:unreachable: a valid leaf points cells within page
            }
            if let Some(cell) = try_carve_cell_at(page_bytes, cell_off, None) {
                out.push(cell);
            }
        }
        out
    }

    /// Carve deleted records from the **free (unallocated) regions** of an
    /// allocated table-leaf page (type `0x0D`), never re-surfacing a live cell.
    ///
    /// On an allocated leaf, deleted-cell residue survives in two places: the
    /// unallocated gap between the cell-pointer array and the cell-content area,
    /// and the slack between/after live cells (a former freeblock whose chain
    /// pointer may already be gone). This method computes the exact byte ranges
    /// occupied by **live** cells and carves only the complement — so a live
    /// (allocated) cell can never be returned as a deleted record. That is the
    /// 0-false-positive guarantee, enforced structurally rather than by a filter.
    ///
    /// `page_bytes` is one whole page. `column_count_hint`, when non-zero, is the
    /// table's known column count (matched exactly); pass 0 to infer the count
    /// per record (for a page whose schema is gone). Non-leaf pages yield nothing.
    #[must_use]
    pub fn carve_free_regions(
        &self,
        page_bytes: &[u8],
        column_count_hint: usize,
    ) -> Vec<CarvedCell> {
        // Page 1 carries the 100-byte file header before its b-tree header; for a
        // standalone page slice we assume hdr_off 0 unless it starts with the
        // file magic (page 1 passed whole).
        let hdr_off = if page_bytes.starts_with(SQLITE_MAGIC) {
            SQLITE_HEADER_SIZE
        } else {
            0
        };
        let Some(&page_type) = page_bytes.get(hdr_off) else {
            return Vec::new();
        };
        if page_type != 0x0d {
            return Vec::new(); // only table-leaf pages have carvable cell residue
        }
        // Carve each maximal free region (complement of the live cell extents),
        // within the cell-content area only — so no allocated cell is ever
        // re-surfaced (the 0-false-positive guarantee, enforced structurally).
        let mut out = Vec::new();
        let regions = self.free_regions_of_leaf(page_bytes, hdr_off);
        for (lo, hi) in regions {
            let Some(region) = page_bytes.get(lo..hi) else {
                continue; // cov:unreachable: free_regions yields in-bounds spans
            };
            let cells = if column_count_hint == 0 {
                self.carve_cells_inferred(region)
            } else {
                self.carve_cells(region, column_count_hint)
            };
            for mut cell in cells {
                // Translate the offset from region-local to page-local, and grade
                // in-page recovery a notch lower (residue here is more often
                // partially overwritten than freed-page recovery).
                cell.offset += lo;
                cell.confidence *= IN_PAGE_CONFIDENCE_FACTOR;
                out.push(cell);
            }
        }
        out
    }

    /// Reconstruct deleted records from the **freeblock chain** of an allocated
    /// table-leaf page (type `0x0d`) — the records a forward parse cannot recover
    /// because their first four bytes were destroyed by freeblock conversion.
    ///
    /// When SQLite frees an in-page cell it converts it into a **freeblock**
    /// (file-format §1.6): the cell's first two bytes become the next-freeblock
    /// offset and the next two the freeblock size, **overwriting the cell's
    /// payload-length + rowid varints, the record `header_len` varint, and the
    /// leading serial type(s)**. The record's surviving serial-type tail and its
    /// whole value body remain intact *after* those four bytes.
    ///
    /// This method rebuilds each freed cell from that surviving tail plus a
    /// **schema template** derived from a LIVE cell on the same page (the table's
    /// column count, header length, and the serial types of the leading columns
    /// that fall inside the clobbered prefix). The destroyed rowid is surfaced as
    /// unknown (`0`) — never invented — and the record is graded LOW.
    ///
    /// Precision discipline (task #56): a candidate is emitted only when its body
    /// decodes cleanly with every serial type legal AND the record fits within
    /// the freeblock's `[offset, offset + size)` bounds. Implausible or
    /// out-of-bounds candidates are rejected, so reconstruction does not
    /// manufacture phantom rows. (The forensic layer additionally drops any
    /// reconstruction whose values match a live row, so a live row is never
    /// re-surfaced.)
    ///
    /// Bounded and panic-free: every freeblock pointer, size, and serial length
    /// is range-checked against the page before use, and the chain walk is capped
    /// at [`MAX_FREEBLOCKS_PER_PAGE`] to defeat a crafted cyclic `next` chain.
    /// Non-leaf pages, pages with no freeblock chain, and pages with no usable
    /// schema template yield an empty result.
    #[must_use]
    pub fn reconstruct_freeblock_records(&self, page_bytes: &[u8]) -> Vec<CarvedCell> {
        // Tier-1 cells are the `.0` of the shared two-tier walker, so the full-row
        // output and the fragment output ([`Database::reconstruct_freeblock_fragments`])
        // can never diverge. The walk (freeblock-chain pass + unallocated-gap pass)
        // and its precision discipline live in [`reconstruct_freeblock_inner`].
        let _ = self;
        reconstruct_freeblock_inner(page_bytes).0
    }

    /// Tier-2 partial salvage: the [`CellFragment`]s abandoned by
    /// [`Database::reconstruct_freeblock_records`] on this page.
    ///
    /// At every anchor where full reconstruction failed — an illegal serial in
    /// the surviving tail, a tail that overruns the span, or a body that does not
    /// fit — the columns that DID decode cleanly before the failure are salvaged
    /// as the maximal decodable prefix. A fragment is emitted only when that
    /// prefix contains at least one *distinctive* cell (TEXT ≥ 4 bytes of valid
    /// UTF-8, or REAL): a lone surviving integer pattern is coincidence-prone and
    /// never anchors a fragment.
    ///
    /// Mutually exclusive with the full reconstructions of
    /// [`Database::reconstruct_freeblock_records`] **by construction**: an anchor
    /// yields a cell or a fragment, never both. Inherits the same anchor
    /// discipline — no sliding scan, no strings-style hunt — so Tier-2 carries
    /// Tier-1's precision architecture. Bounded and panic-free identically.
    #[must_use]
    pub fn reconstruct_freeblock_fragments(&self, page_bytes: &[u8]) -> Vec<CellFragment> {
        let _ = self;
        reconstruct_freeblock_inner(page_bytes).1
    }

    /// The maximal FREE (unallocated) byte ranges of a table-leaf page — the
    /// complement of its live cells within the cell-content area. Shared by
    /// [`Database::carve_free_regions`] and
    /// [`Database::reconstruct_freeblock_records`] so both scan exactly the same
    /// ranges and never touch a live cell. Returns empty for a non-leaf page.
    fn free_regions_of_leaf(&self, page_bytes: &[u8], hdr_off: usize) -> Vec<(usize, usize)> {
        if page_bytes.get(hdr_off) != Some(&0x0d) {
            return Vec::new(); // cov:unreachable: callers gate on page_type == 0x0d
        }
        let cell_count = be_u16(page_bytes, hdr_off + 3) as usize;
        let cell_ptr_array = hdr_off + 8; // leaf header is 8 bytes
        let usable = self.header.usable_size() as usize;
        let mut live: Vec<(usize, usize)> = Vec::with_capacity(cell_count);
        for i in 0..cell_count {
            let cell_off = be_u16(page_bytes, cell_ptr_array + i * 2) as usize;
            if cell_off == 0 || cell_off >= page_bytes.len() {
                continue; // cov:unreachable: a valid leaf points cells within page
            }
            if let Some(len) = live_cell_len(page_bytes, cell_off, usable) {
                live.push((cell_off, cell_off.saturating_add(len)));
            }
        }
        live.sort_unstable_by_key(|&(s, _)| s);
        let content_lo = cell_ptr_array + cell_count * 2;
        free_regions(&live, content_lo, page_bytes.len())
    }

    /// Whether `sqlite_master` (the schema table rooted at page 1) lists at least
    /// one **user** table — i.e. a `type='table'` row whose name is not an
    /// internal `sqlite_*` table. A database where every table was `DROP`ped (or
    /// that never had one) returns `false`; the forensic carver uses this to label
    /// freed content as dropped-table residue. Errors (unreadable schema) are
    /// treated as "no user table" so the carver degrades safely.
    #[must_use]
    pub fn has_user_table(&self) -> bool {
        // sqlite_master is a 5-column table: (type, name, tbl_name, rootpage, sql).
        let Ok(rows) = self.read_table(1, 5) else {
            return false; // cov:unreachable: a validly-opened DB has a readable page-1 schema
        };
        rows.iter().any(|row| {
            let is_table = matches!(row.values.first(), Some(Value::Text(t)) if t == "table");
            let user = matches!(
                row.values.get(1),
                Some(Value::Text(n)) if !n.starts_with("sqlite_")
            );
            is_table && user
        })
    }

    /// Collect the rowids of every **currently-live** row across all user table
    /// b-trees (the roots listed in `sqlite_master`). The forensic carver uses
    /// this to drop any carved "deleted" record whose rowid is in fact still live
    /// — a stale copy of a live row can linger in free space after a b-tree
    /// rebalance moved the row to another page, and reporting it as deleted would
    /// be a false positive. Rowid collection ignores the column count (the rowid
    /// is in the cell prefix), so it works even when a schema row is malformed.
    ///
    /// Bounded and panic-free: unreadable schema or a malformed b-tree yields a
    /// partial (possibly empty) set rather than an error.
    #[must_use]
    pub fn live_rowids(&self) -> std::collections::BTreeSet<i64> {
        let mut ids = std::collections::BTreeSet::new();
        let Ok(schema) = self.read_table(1, 5) else {
            return ids; // cov:unreachable: a validly-opened DB has a readable page-1 schema
        };
        for row in schema {
            // sqlite_master row: (type, name, tbl_name, rootpage, sql).
            let is_table = matches!(row.values.first(), Some(Value::Text(t)) if t == "table");
            if !is_table {
                continue; // cov:unreachable: the test fixtures' schemas hold only table rows
            }
            let Some(Value::Integer(root)) = row.values.get(3) else {
                continue; // cov:unreachable: a 'table' schema row always has an integer rootpage
            };
            let Ok(root) = u32::try_from(*root) else {
                continue; // cov:unreachable: a real rootpage is a small positive page number
            };
            let mut visited = 0usize;
            self.collect_rowids(root, &mut ids, &mut visited);
        }
        ids
    }

    /// Collect every **currently-live** row's decoded column values, keyed by
    /// rowid, across all user table b-trees. This is the value-aware companion to
    /// [`Database::live_rowids`]: the forensic carver uses it to tell a stale
    /// rebalance copy (same rowid AND same values → drop) from a deleted prior
    /// version (same rowid but DIFFERENT values → recover, e.g. an edited message
    /// or a changed amount).
    ///
    /// Column values are decoded by inferring the column count from each live
    /// cell's own serial-type array (the same self-describing record format the
    /// carver uses), so no schema column count is required. Best-effort,
    /// bounded, and panic-free: a malformed b-tree yields a partial map.
    #[must_use]
    pub fn live_rows(&self) -> std::collections::BTreeMap<i64, Vec<Value>> {
        let mut rows = std::collections::BTreeMap::new();
        let Ok(schema) = self.read_table(1, 5) else {
            return rows; // cov:unreachable: a validly-opened DB has a readable page-1 schema
        };
        for row in schema {
            let is_table = matches!(row.values.first(), Some(Value::Text(t)) if t == "table");
            if !is_table {
                continue; // cov:unreachable: the test fixtures' schemas hold only table rows
            }
            let Some(Value::Integer(root)) = row.values.get(3) else {
                continue; // cov:unreachable: a 'table' schema row always has an integer rootpage
            };
            let Ok(root) = u32::try_from(*root) else {
                continue; // cov:unreachable: a real rootpage is a small positive page number
            };
            let mut visited = 0usize;
            self.collect_rows(root, &mut rows, &mut visited);
        }
        rows
    }

    /// Decode every **currently-live** `sqlite_master` row (the schema table
    /// rooted at page 1) into its column values: `(type, name, tbl_name,
    /// rootpage, sql)`. This is the schema-table companion to
    /// [`Database::live_rows`], which collects only USER-table b-trees and so
    /// never sees the schema rows themselves.
    ///
    /// The forensic carver folds these into the same value-based live set it uses
    /// to drop stale copies of live user rows: a record carved from a materialized
    /// page 1 whose values equal a CURRENT schema row is the live schema entry
    /// re-surfaced (drop it), whereas a genuinely-deleted PRIOR schema version has
    /// different values (e.g. an old `CREATE TABLE`) and is still recovered.
    ///
    /// Best-effort, bounded, and panic-free: an unreadable schema yields an empty
    /// vector rather than an error.
    #[must_use]
    pub fn live_schema_rows(&self) -> Vec<Vec<Value>> {
        match self.read_table(1, 5) {
            Ok(rows) => rows.into_iter().map(|row| row.values).collect(),
            Err(_) => Vec::new(), // cov:unreachable: a validly-opened DB has a readable page-1 schema
        }
    }

    /// Walk the table b-tree rooted at `page`, decoding every live leaf cell's
    /// values (column count inferred per cell) into `rows` keyed by rowid.
    /// Best-effort and bounded, mirroring [`Database::collect_rowids`].
    fn collect_rows(
        &self,
        page: u32,
        rows: &mut std::collections::BTreeMap<i64, Vec<Value>>,
        visited: &mut usize,
    ) {
        *visited += 1;
        if *visited > MAX_PAGES_PER_WALK {
            return; // cov:unreachable: test b-trees are far below the 1M-page cap
        }
        let Ok(slice) = self.page_slice(page) else {
            return; // cov:unreachable: schema rootpages and their children are in range
        };
        let hdr_off = if page == 1 { SQLITE_HEADER_SIZE } else { 0 };
        let Some(&page_type) = slice.get(hdr_off) else {
            return; // cov:unreachable: a full page slice always has its header byte
        };
        let cell_count = be_u16(slice, hdr_off + 3) as usize;
        match page_type {
            0x0d => {
                let cell_ptr_array = hdr_off + 8;
                for i in 0..cell_count {
                    let cell_off = be_u16(slice, cell_ptr_array + i * 2) as usize;
                    // Decode the live cell with an inferred column count; on any
                    // parse hiccup (e.g. a table narrower than MIN_INFERRED_COLUMNS),
                    // fall back to the rowid alone (empty values) so the row is
                    // still known to be live.
                    if let Some(cell) = try_carve_cell_at(slice, cell_off, None) {
                        rows.insert(cell.rowid, cell.values);
                    } else if let Some(rowid) = live_cell_rowid(slice, cell_off) {
                        rows.entry(rowid).or_default(); // cov:unreachable: a >=2-col live cell always decodes above
                    }
                }
            }
            0x05 => {
                let cell_ptr_array = hdr_off + 12;
                for i in 0..cell_count {
                    let cell_off = be_u16(slice, cell_ptr_array + i * 2) as usize;
                    let child = be_u32(slice, cell_off);
                    if child != 0 && child != page {
                        self.collect_rows(child, rows, visited);
                    }
                }
                let right = be_u32(slice, hdr_off + 8);
                if right != 0 && right != page {
                    self.collect_rows(right, rows, visited);
                }
            }
            _ => {} // cov:unreachable: a table b-tree root/child is leaf (0x0d) or interior (0x05)
        }
    }

    /// Walk the table b-tree rooted at `page`, inserting every live leaf cell's
    /// rowid into `ids`. Best-effort and bounded: a malformed/cyclic structure
    /// stops the walk rather than erroring or looping.
    fn collect_rowids(
        &self,
        page: u32,
        ids: &mut std::collections::BTreeSet<i64>,
        visited: &mut usize,
    ) {
        *visited += 1;
        if *visited > MAX_PAGES_PER_WALK {
            return; // cov:unreachable: test b-trees are far below the 1M-page cap
        }
        let Ok(slice) = self.page_slice(page) else {
            return; // cov:unreachable: schema rootpages and their children are in range
        };
        let hdr_off = if page == 1 { SQLITE_HEADER_SIZE } else { 0 };
        let Some(&page_type) = slice.get(hdr_off) else {
            return; // cov:unreachable: a full page slice always has its header byte
        };
        let cell_count = be_u16(slice, hdr_off + 3) as usize;
        match page_type {
            0x0d => {
                let cell_ptr_array = hdr_off + 8;
                for i in 0..cell_count {
                    let cell_off = be_u16(slice, cell_ptr_array + i * 2) as usize;
                    if let Some(rowid) = live_cell_rowid(slice, cell_off) {
                        ids.insert(rowid);
                    }
                }
            }
            0x05 => {
                let cell_ptr_array = hdr_off + 12;
                for i in 0..cell_count {
                    let cell_off = be_u16(slice, cell_ptr_array + i * 2) as usize;
                    let child = be_u32(slice, cell_off);
                    if child != 0 && child != page {
                        self.collect_rowids(child, ids, visited);
                    }
                }
                let right = be_u32(slice, hdr_off + 8);
                if right != 0 && right != page {
                    self.collect_rowids(right, ids, visited);
                }
            }
            _ => {} // cov:unreachable: a table b-tree root/child is leaf (0x0d) or interior (0x05)
        }
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
        // Every committed frame's page image (file order), and the pending frames
        // not yet promoted by a COMMIT. Mirrors the page promotion above so
        // uncommitted trailing frames are dropped from BOTH the view and the carve.
        let mut frames: Vec<WalFramePage> = Vec::new();
        let mut pending_frames: Vec<WalFramePage> = Vec::new();

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
            let is_commit = db_size != 0;
            pending_frames.push(WalFramePage {
                frame_index: frame_no - 1, // 0-based file order
                page_no,
                salt1,
                salt2,
                is_commit,
                page: data.to_vec(),
            });

            if is_commit {
                // COMMIT frame: promote everything pending into the snapshot AND
                // into the committed frame list (keeping every frame, not just the
                // newest version of each page).
                for (p, d) in std::mem::take(&mut pending) {
                    committed.insert(p, d);
                }
                frames.append(&mut pending_frames);
            }
            off += frame_stride;
        }

        if committed.is_empty() {
            Ok(None)
        } else {
            Ok(Some(WalOverlay {
                pages: committed,
                frames,
                raw: wal.to_vec(),
            }))
        }
    }
}

// ===========================================================================
// Bespoke, format-exact WAL temporal model (task #55)
// ===========================================================================
//
// A `-wal` sidecar is NOT an open-ended event log. It is a BOUNDED SEGMENT under a
// single salt epoch: every live frame shares the WAL header's (salt1, salt2). A
// checkpoint reset renumbers frames and rolls the salts — a DISCONTINUITY, not a
// continuation. The only materializable database states are the COMMIT snapshots:
// the replay of all valid frames up to a commit frame. A frame BETWEEN commits is
// not independently materializable, so it is never surfaced as a snapshot. Tails
// past the last commit, or after a salt reset, are WAL residue — forensic leads,
// never committed history.
//
// This model is self-contained in sqlite-core. The future state-history-forensic
// [H] adapter attaches at the seam exposed here (WalLsn + CohortTopology +
// `checksums_are_tamper_evident`), but sqlite-core does NOT depend on it.

/// Cap on the number of salt segments and frames the timeline parser will walk on a
/// crafted `-wal`, bounding work against an attacker-supplied file. A real WAL holds
/// one segment with at most a few frames per database page.
const MAX_WAL_SEGMENTS: usize = 1024;

/// Identity of one salt epoch within a `-wal` file: its 0-based segment ordinal.
/// A fresh segment begins at file start and after every checkpoint salt reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WalSegmentId(pub usize);

/// One salt epoch of a `-wal` file — a single bounded segment.
///
/// A `-wal` is a bounded segment, not an open-ended log: every live frame here shares
/// `(salt1, salt2)`. A checkpoint reset (salt change + frame renumber) starts a NEW
/// `WalSegment`; it is a discontinuity, never another epoch of the same segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalSegment {
    /// This segment's ordinal within the WAL (0 = the segment at file start).
    pub id: WalSegmentId,
    /// WAL salt-1 (checkpoint generation), shared by every frame in the segment.
    pub salt1: u32,
    /// WAL salt-2 (checkpoint generation), shared by every frame in the segment.
    pub salt2: u32,
    /// Page size declared by the segment's frames (bytes).
    pub page_size: u32,
    /// Number of frames belonging to this segment.
    pub frame_count: usize,
    /// The checkpoint sequence number recorded in the WAL header (offset 12). For a
    /// segment discovered after a reset within the same file this is the header's
    /// value; per-segment sequence is otherwise not separately recorded.
    pub checkpoint_seq: u32,
}

/// Address of a materializable database state: the replay of all valid frames up to
/// a COMMIT frame. `CommitId = (segment, commit_frame_index, db_size_after_commit)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CommitId {
    /// The salt segment this commit belongs to.
    pub segment: WalSegmentId,
    /// 0-based file-order index of the COMMIT frame within the segment.
    pub commit_frame_index: usize,
    /// `db_size_after_commit` recorded in the COMMIT frame header — the database's
    /// page count once this commit is materialized.
    pub db_size_after_commit: u32,
}

/// The salt-qualified log-sequence identity of a WAL position — the seam the future
/// `state-history-forensic` `[H]` adapter maps onto `LsnKind::SqliteWal`.
///
/// A bare `frame_index` is meaningless across checkpoint resets (frames renumber), so
/// ordering is ALWAYS qualified by `(salt1, salt2)`. The adapter must reconstruct
/// `LsnKind::SqliteWal { salt1, salt2, frame_index }` from exactly this triple — never
/// from a bare index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WalLsn {
    /// Salt-1 of the owning segment (checkpoint generation).
    pub salt1: u32,
    /// Salt-2 of the owning segment (checkpoint generation).
    pub salt2: u32,
    /// 0-based frame index within that segment.
    pub frame_index: usize,
}

/// Topology of the temporal cohort the WAL exposes — the shape the `[H]` adapter maps
/// to `state-history-forensic::CohortTopology`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CohortTopology {
    /// A single salt epoch: the commit snapshots form one linearly-ordered chain.
    LinearSegment,
    /// Multiple salt epochs (checkpoint resets) with no replay continuity between
    /// them — each segment is linear internally but the segments are disconnected.
    Disconnected,
}

/// One page's image at a particular [`CommitSnapshot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedPageVersion {
    /// 1-based database page number.
    pub page_no: u32,
    /// The page's full image (`page_size` bytes) as of this commit.
    pub bytes: Vec<u8>,
}

/// A materializable database state: the replay of all valid frames up to a COMMIT.
///
/// This is the ONLY independently-materializable WAL state. `page_version` resolves a
/// page to its image as of this commit (the newest frame ≤ this commit that rewrote
/// the page, else the acquired base image). A frame between commits is never a
/// snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitSnapshot {
    id: CommitId,
    /// Salt-1 of the owning segment, carried so [`CommitSnapshot::lsn`] is
    /// self-contained without a back-reference to the segment.
    salt1: u32,
    /// Salt-2 of the owning segment.
    salt2: u32,
    /// The materialized page images at this commit: base image overlaid with every
    /// committed frame up to and including this commit (newest version per page),
    /// capped to `db_size_after_commit` pages. `page_version` reads from this map.
    overlaid: std::collections::BTreeMap<u32, Vec<u8>>,
}

impl CommitSnapshot {
    /// This snapshot's [`CommitId`].
    #[must_use]
    pub fn id(&self) -> CommitId {
        self.id
    }

    /// The database page count once this commit is materialized.
    #[must_use]
    pub fn db_size_after_commit(&self) -> u32 {
        self.id.db_size_after_commit
    }

    /// The salt-qualified [`WalLsn`] of this commit (the `[H]` adapter seam).
    #[must_use]
    pub fn lsn(&self) -> WalLsn {
        WalLsn {
            salt1: self.salt1,
            salt2: self.salt2,
            frame_index: self.id.commit_frame_index,
        }
    }

    /// The 1-based page numbers this commit materialized (base ∪ committed frames
    /// up to this commit, capped to `db_size_after_commit`), ascending.
    ///
    /// The carve-at-snapshot primitive iterates these to drive the carving
    /// primitives over each page image, WITHOUT assuming the pages form a
    /// contiguous `1..=db_size` range (a truncating commit or a sparse base image
    /// can leave gaps). Every returned page resolves via [`Self::page_version`].
    #[must_use]
    pub fn page_numbers(&self) -> Vec<u32> {
        self.overlaid.keys().copied().collect()
    }

    /// The image of `page_no` as of this commit, or `None` for a page beyond the
    /// committed database size that the WAL never rewrote.
    #[must_use]
    pub fn page_version(&self, page_no: u32) -> Option<CommittedPageVersion> {
        let bytes = self.overlaid.get(&page_no)?.clone();
        Some(CommittedPageVersion { page_no, bytes })
    }
}

/// A page-level delta between two materialized states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalDiff {
    changed: Vec<u32>,
}

impl WalDiff {
    /// The 1-based page numbers whose bytes differ between the two states, ascending.
    #[must_use]
    pub fn changed_pages(&self) -> &[u32] {
        &self.changed
    }
}

/// A stale WAL tail surfaced for forensics — NOT committed history.
///
/// Frames past the last COMMIT of a segment, frames after a salt reset that cannot be
/// replayed into the current segment, or a header/page-size break: all are residue.
/// The examiner weighs them; they are never part of a consistent snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalResidue {
    /// The segment the residue trails (the segment whose last commit it follows).
    pub segment: WalSegmentId,
    /// 0-based frame index (within the file) of the first residual frame.
    pub first_frame_index: usize,
    /// Number of residual frames.
    pub frame_count: usize,
    /// Why these frames are residue rather than committed history.
    pub reason: ResidueReason,
}

/// Why a WAL tail is [`WalResidue`] (an invalidated-frame candidate), not history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResidueReason {
    /// Frames written after the segment's last COMMIT (uncommitted tail).
    BeyondLastCommit,
    /// Frames whose salt no longer matches the segment header (post-reset residue).
    SaltReset,
}

/// Validation tier a WAL has cleared — strictly increasing assurance.
///
/// `PhysicalValidation` < `CommitValidation` < `ReplaySafe`. The timeline reports the
/// highest tier reached; a page-size mismatch never even produces a timeline (it is a
/// hard stop at parse, surfaced as [`WalValidationError::PageSizeMismatch`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MaterializationSafety {
    /// Header magic / format / page-size / salts / frame boundaries are well-formed,
    /// but no committed snapshot was found (nothing to replay).
    PhysicalValidated,
    /// A last valid commit and committed frame ranges were established, but the
    /// read-only replay overlay was not (or could not be) built.
    CommitValidated,
    /// A read-only replay overlay to the last commit is available — safe to
    /// materialize without mutating either file.
    ReplaySafe,
}

/// A WAL that cannot be admitted to the timeline at all (physical-validation hard
/// stops). Distinct from "no committed snapshot", which is a valid empty timeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalValidationError {
    /// The `-wal` is shorter than its 32-byte header, or carries the wrong magic.
    BadMagic,
    /// The WAL header's page size disagrees with the DB header's — a HARD STOP, since
    /// every frame would be mis-sliced. `db` and `wal` are the two declared sizes.
    PageSizeMismatch { db: u32, wal: u32 },
    /// The main database header itself failed to parse.
    Header(Error),
}

/// The bespoke, format-exact temporal model of a `-wal` sidecar.
///
/// Enumerates the salt segments, the materializable [`CommitSnapshot`]s within them
/// (CommitId-addressable), and the [`WalResidue`] tails. Materialize a snapshot's page
/// images via [`CommitSnapshot::page_version`]; diff the acquired base against the last
/// valid commit via [`WalTimeline::diff_base_to_last_commit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalTimeline {
    page_size: u32,
    base_pages: std::collections::BTreeMap<u32, Vec<u8>>,
    segments: Vec<WalSegment>,
    snapshots: Vec<CommitSnapshot>,
    residue: Vec<WalResidue>,
    safety: MaterializationSafety,
}

impl WalTimeline {
    /// Physical-validation tier: header magic + format check.
    ///
    /// Parses `bytes` (the acquired main DB) and `wal` (the `-wal` sidecar) into the
    /// segmented temporal model. A page-size mismatch between the DB header and the
    /// WAL header is a HARD STOP; a bad/short header is [`WalValidationError::BadMagic`].
    fn parse(bytes: &[u8], wal: &[u8], page_size: u32) -> Result<Self, WalValidationError> {
        use forensicnomicon::sqlite::{SQLITE_WAL_FRAME_HEADER_SIZE, SQLITE_WAL_HEADER_SIZE};

        // --- PhysicalValidation: header magic / format / page-size / salts -------
        let hdr = wal
            .get(..SQLITE_WAL_HEADER_SIZE)
            .ok_or(WalValidationError::BadMagic)?;
        let magic = be_u32(hdr, 0);
        if magic != WAL_MAGIC_BE && magic != WAL_MAGIC_LE {
            return Err(WalValidationError::BadMagic);
        }
        let wal_page_size = be_u32(hdr, 8);
        if wal_page_size != page_size {
            return Err(WalValidationError::PageSizeMismatch {
                db: page_size,
                wal: wal_page_size,
            });
        }
        let checkpoint_seq = be_u32(hdr, 12);
        let mut salt1 = be_u32(hdr, 16);
        let mut salt2 = be_u32(hdr, 20);

        let ps = page_size as usize;
        let frame_stride = SQLITE_WAL_FRAME_HEADER_SIZE + ps;

        // The acquired main DB image: the pre-WAL base for replay within the current
        // validated segment (NOT "epoch 0" — just the base each commit overlays onto).
        let mut base_pages: std::collections::BTreeMap<u32, Vec<u8>> =
            std::collections::BTreeMap::new();
        // `chunks_exact` yields only whole pages (infallible by construction — no
        // out-of-bounds slice to guard); cap at `u32::MAX` pages so the 1-based page
        // number never overflows on a pathologically large image.
        for (idx, page) in bytes
            .chunks_exact(ps)
            .take(u32::MAX as usize - 1)
            .enumerate()
        {
            let pno = idx as u32 + 1; // 1-based page number
            base_pages.insert(pno, page.to_vec());
        }

        let mut segments: Vec<WalSegment> = Vec::new();
        let mut snapshots: Vec<CommitSnapshot> = Vec::new();
        let mut residue: Vec<WalResidue> = Vec::new();

        // Per-segment running state.
        let mut seg_ordinal = 0usize;
        let mut seg_frame_count = 0usize;
        // Cumulative newest-page map across all COMMITTED frames of the segment, so a
        // snapshot's `overlaid` is base ∪ committed-up-to-this-commit.
        let mut committed_pages: std::collections::BTreeMap<u32, Vec<u8>> = base_pages.clone();
        let mut pending: std::collections::BTreeMap<u32, Vec<u8>> =
            std::collections::BTreeMap::new();
        let mut last_commit_global_frame: Option<usize> = None;
        let mut uncommitted_tail_start: Option<usize> = None;

        let mut off = SQLITE_WAL_HEADER_SIZE;
        let max_frames = wal.len() / frame_stride + 1;
        let mut frame_no = 0usize;

        while let Some(frame) = wal.get(off..off + frame_stride) {
            if frame_no >= max_frames {
                break; // cov:unreachable: the slice walk already bounds frame_no
            }
            let page_no = be_u32(frame, 0);
            let db_size = be_u32(frame, 4);
            let fsalt1 = be_u32(frame, 8);
            let fsalt2 = be_u32(frame, 12);

            // A salt change opens a NEW segment (checkpoint reset = discontinuity).
            // Anything between the prior segment's last commit and here is residue.
            if fsalt1 != salt1 || fsalt2 != salt2 {
                if segments.len() >= MAX_WAL_SEGMENTS {
                    break; // cov:unreachable: real WALs hold far fewer than 1024 salt epochs
                }
                // Close the current segment, recording its residue tail (if any).
                Self::close_segment(
                    &mut segments,
                    &mut residue,
                    WalSegmentId(seg_ordinal),
                    salt1,
                    salt2,
                    page_size,
                    checkpoint_seq,
                    seg_frame_count,
                    uncommitted_tail_start,
                );
                // Begin the next segment under the new salts. Its base for replay is
                // the prior committed view (a checkpoint would have flushed it, but on
                // a forensic image we keep what we can replay).
                seg_ordinal += 1;
                salt1 = fsalt1;
                salt2 = fsalt2;
                seg_frame_count = 0;
                pending.clear();
                uncommitted_tail_start = None;
                // The post-reset frames replay onto the latest committed view.
                // committed_pages carries forward.
            }

            if page_no == 0 {
                break; // malformed frame; stop rather than mis-index
            }
            let data = match frame.get(SQLITE_WAL_FRAME_HEADER_SIZE..) {
                Some(d) => d.to_vec(),
                None => break, // cov:unreachable: frame slice is exactly frame_stride
            };

            let frame_index_in_seg = seg_frame_count;
            seg_frame_count += 1;
            pending.insert(page_no, data);
            let is_commit = db_size != 0;

            if is_commit {
                for (p, d) in std::mem::take(&mut pending) {
                    committed_pages.insert(p, d);
                }
                // Drop base/committed pages beyond the committed size so a snapshot
                // reflects the database's page count at that commit. `db_size` is
                // non-zero here (that is what makes this a COMMIT frame).
                committed_pages.retain(|&p, _| p <= db_size);
                let id = CommitId {
                    segment: WalSegmentId(seg_ordinal),
                    commit_frame_index: frame_index_in_seg,
                    db_size_after_commit: db_size,
                };
                snapshots.push(CommitSnapshot {
                    id,
                    overlaid: committed_pages.clone(),
                    salt1,
                    salt2,
                });
                last_commit_global_frame = Some(frame_no);
                uncommitted_tail_start = None;
            } else if uncommitted_tail_start.is_none() {
                uncommitted_tail_start = Some(frame_index_in_seg);
            }

            frame_no += 1;
            off += frame_stride;
        }

        // Close the final segment (it may have an uncommitted tail).
        Self::close_segment(
            &mut segments,
            &mut residue,
            WalSegmentId(seg_ordinal),
            salt1,
            salt2,
            page_size,
            checkpoint_seq,
            seg_frame_count,
            uncommitted_tail_start,
        );

        let safety = if snapshots.is_empty() {
            MaterializationSafety::PhysicalValidated
        } else if last_commit_global_frame.is_some() {
            MaterializationSafety::ReplaySafe
        } else {
            MaterializationSafety::CommitValidated // cov:unreachable: a snapshot implies a commit
        };

        Ok(Self {
            page_size,
            base_pages,
            segments,
            snapshots,
            residue,
            safety,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn close_segment(
        segments: &mut Vec<WalSegment>,
        residue: &mut Vec<WalResidue>,
        id: WalSegmentId,
        salt1: u32,
        salt2: u32,
        page_size: u32,
        checkpoint_seq: u32,
        frame_count: usize,
        uncommitted_tail_start: Option<usize>,
    ) {
        if frame_count == 0 {
            return;
        }
        segments.push(WalSegment {
            id,
            salt1,
            salt2,
            page_size,
            frame_count,
            checkpoint_seq,
        });
        if let Some(start) = uncommitted_tail_start {
            residue.push(WalResidue {
                segment: id,
                first_frame_index: start,
                frame_count: frame_count - start,
                reason: ResidueReason::BeyondLastCommit,
            });
        }
    }

    /// The salt segments of this WAL, in file order (one per salt epoch).
    #[must_use]
    pub fn segments(&self) -> &[WalSegment] {
        &self.segments
    }

    /// Every materializable [`CommitSnapshot`] across all segments, in commit order.
    #[must_use]
    pub fn commit_snapshots(&self) -> &[CommitSnapshot] {
        &self.snapshots
    }

    /// The stale WAL tails surfaced for forensics (not committed history).
    #[must_use]
    pub fn residue(&self) -> &[WalResidue] {
        &self.residue
    }

    /// Resolve a [`CommitId`] back to its [`CommitSnapshot`].
    #[must_use]
    pub fn snapshot_at(&self, id: CommitId) -> Option<&CommitSnapshot> {
        self.snapshots.iter().find(|s| s.id == id)
    }

    /// The highest validation tier this WAL cleared (see [`MaterializationSafety`]).
    #[must_use]
    pub fn safety(&self) -> MaterializationSafety {
        self.safety
    }

    /// The temporal-cohort topology — `LinearSegment` for one salt epoch, else
    /// `Disconnected` across checkpoint resets. The `[H]` adapter maps this onto
    /// `state-history-forensic::CohortTopology`.
    #[must_use]
    pub fn topology(&self) -> CohortTopology {
        if self.segments.len() <= 1 {
            CohortTopology::LinearSegment
        } else {
            CohortTopology::Disconnected
        }
    }

    /// Whether the WAL's integrity checks are tamper-EVIDENT. Always `false`: WAL
    /// frame checksums are non-cryptographic (corruption detection, not tamper proof),
    /// so the `[H]` adapter must record `tamper_resistance = LOW`.
    #[must_use]
    pub fn checksums_are_tamper_evident(&self) -> bool {
        false
    }

    /// Diff the acquired base image against the last valid commit snapshot, returning
    /// the page numbers whose bytes changed. `None` when there is no committed snapshot.
    #[must_use]
    pub fn diff_base_to_last_commit(&self) -> Option<WalDiff> {
        let last = self.snapshots.last()?;
        let mut changed = Vec::new();
        let mut pages: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
        pages.extend(self.base_pages.keys().copied());
        pages.extend(last.overlaid.keys().copied());
        for p in pages {
            let base = self.base_pages.get(&p);
            let now = last.overlaid.get(&p);
            if base != now {
                changed.push(p);
            }
        }
        Some(WalDiff { changed })
    }

    /// The page size (bytes) common to the base image and the WAL frames.
    #[must_use]
    pub fn page_size(&self) -> u32 {
        self.page_size
    }

    /// Map this WAL timeline onto the canonical `forensicnomicon::history` cohort
    /// vocabulary — the `[H]` adapter (#43 / WS-F).
    ///
    /// Each materializable [`CommitSnapshot`] becomes one `TemporalState<CommitId>`:
    /// - **ordering key** — a salt-qualified `LsnKind::SqliteWalFrame` (`frame_seq` is the
    ///   COMMIT frame index; `commit_seq` is the 0-based commit ordinal within the salt
    ///   segment). The `(salt1, salt2)` pair keeps the key meaningful across a checkpoint
    ///   reset, which renumbers frames and rolls the salts.
    /// - **clock + safety** — the canonical SQLite-WAL profile, single-sourced from
    ///   [`forensicnomicon::history::profiles`], so no consumer re-asserts the four
    ///   classifications locally.
    /// - **handle** — the snapshot's [`CommitId`]; resolve it back via [`Self::snapshot_at`].
    ///
    /// The topology is uniformly `SubJournalCommits`: every state is a committed
    /// transaction, and a checkpoint reset is visible as a salt change *inside* the
    /// ordering key — there is no separate "disconnected" topology to special-case. The
    /// cohort is `PathStable` (a `-wal` belongs to exactly one database path), so the
    /// caller supplies the path identity via `artifact`.
    #[must_use]
    pub fn to_temporal_cohort(
        &self,
        artifact: forensicnomicon::history::identity::ArtifactRef,
    ) -> forensicnomicon::history::cohort::TemporalCohort<CommitId> {
        use forensicnomicon::history::cohort::{TemporalCohort, TemporalState};
        use forensicnomicon::history::epoch::{CohortTopology, EpochTag, LsnKind};
        use forensicnomicon::history::identity::IdentityDiscipline;
        use forensicnomicon::history::profiles;

        // One canonical profile drives every state's clock + safety — read from
        // forensicnomicon, never re-asserted here, so the fleet cannot drift.
        let profile = profiles::SourceTemporalProfile::sqlite_wal();
        let mut commit_seq_in_segment: std::collections::HashMap<WalSegmentId, u32> =
            std::collections::HashMap::new();

        let states = self
            .snapshots
            .iter()
            .map(|snap| {
                let id = snap.id();
                let lsn = snap.lsn();
                let seq = commit_seq_in_segment.entry(id.segment).or_insert(0);
                let commit_seq = *seq;
                *seq += 1;

                // Deterministic and collision-free within a cohort: the
                // (salt1, salt2, commit_frame_index, db_size_after_commit) quadruple is
                // unique per commit state. Packed big-endian into the leading 16 bytes.
                let mut tag = [0u8; 32];
                tag[0..4].copy_from_slice(&lsn.salt1.to_be_bytes());
                tag[4..8].copy_from_slice(&lsn.salt2.to_be_bytes());
                tag[8..12].copy_from_slice(&(id.commit_frame_index as u32).to_be_bytes());
                tag[12..16].copy_from_slice(&id.db_size_after_commit.to_be_bytes());

                TemporalState {
                    epoch: EpochTag::from_bytes(tag),
                    ordering_key: Some(LsnKind::SqliteWalFrame {
                        salt1: lsn.salt1,
                        salt2: lsn.salt2,
                        frame_seq: lsn.frame_index as u32,
                        commit_seq,
                    }),
                    wall_time: None,
                    clock: profile.clock.clone(),
                    safety: profile.safety.clone(),
                    handle: id,
                }
            })
            .collect();

        TemporalCohort {
            artifact,
            discipline: IdentityDiscipline::PathStable,
            topology: CohortTopology::SubJournalCommits,
            states,
        }
    }
}

/// Whether a decoded [`Value`] is **distinctive** enough to anchor a Tier-2
/// fragment emission (the §3.1 gate): TEXT of ≥ 4 bytes of valid UTF-8 (no
/// replacement char), or a REAL. Bare integers (1–8-byte serial patterns),
/// NULL, and BLOBs are NOT distinctive alone — a short integer byte-pattern
/// coincides far too often in a 4 `KiB` page to serve as identity, so it can ride
/// along inside a fragment but never justify emitting one.
fn is_distinctive(value: &Value) -> bool {
    match value {
        Value::Text(t) => t.len() >= 4 && !t.contains('\u{FFFD}'),
        Value::Real(_) => true,
        Value::Null | Value::Integer(_) | Value::Blob(_) => false,
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

/// Byte length of a **live** table-leaf cell at `off`, for computing the byte
/// extent the cell occupies (so [`Database::carve_free_regions`] can exclude it).
/// Returns `None` if the cell header does not parse in bounds.
///
/// Mirrors the live cell layout: payload-length varint, rowid varint, then the
/// local payload (capped at the spill threshold) plus a 4-byte overflow pointer
/// when the payload spills. We only need the on-page footprint, so for a spilled
/// cell that is `local + 4` bytes, not the full reassembled payload.
fn live_cell_len(buf: &[u8], off: usize, usable: usize) -> Option<usize> {
    let (payload_len, n1) = read_varint(buf, off).ok()?;
    let (_rowid, n2) = read_varint(buf, off + n1).ok()?;
    let total = usize::try_from(payload_len).ok()?;
    let local = local_payload_len(total, usable);
    let on_page = if local >= total {
        n1 + n2 + total
    } else {
        n1 + n2 + local + 4 // 4-byte first-overflow-page pointer
    };
    Some(on_page)
}

/// The rowid of a table-leaf cell at `off` — its 2nd varint (after the
/// payload-length varint). `None` if either varint is out of bounds. Used to
/// identify a live row even when its full record cannot be decoded.
fn live_cell_rowid(buf: &[u8], off: usize) -> Option<i64> {
    let (_payload_len, n1) = read_varint(buf, off).ok()?;
    let (rowid, _) = read_varint(buf, off + n1).ok()?;
    Some(rowid)
}

/// Given the sorted byte extents of live cells, return the maximal **free**
/// (unallocated) spans within `[lo, hi)` — the complement of the live extents.
/// These are the only ranges [`Database::carve_free_regions`] scans, so a live
/// cell can never be re-surfaced.
fn free_regions(live: &[(usize, usize)], lo: usize, hi: usize) -> Vec<(usize, usize)> {
    let mut regions = Vec::new();
    let mut cursor = lo;
    for &(s, e) in live {
        let s = s.clamp(lo, hi);
        let e = e.clamp(lo, hi);
        if s > cursor {
            regions.push((cursor, s));
        }
        if e > cursor {
            cursor = e;
        }
    }
    if cursor < hi {
        regions.push((cursor, hi));
    }
    regions
}

/// Derive a [`FreeblockTemplate`] from the first live cell on a table-leaf page:
/// the record's header length, its serial-type array, and the byte width of the
/// cell prefix (payload-length + rowid varints) that the freeblock header
/// overwrites. Returns `None` when no live cell parses or the prefix is wider
/// than the 4 bytes a freeblock header clobbers (the simple template cannot then
/// place the surviving serial tail).
/// Shared internal walker producing BOTH recovery tiers in one pass so the cell
/// and fragment outputs can never diverge: `(full_cells, fragments)`.
/// [`Database::reconstruct_freeblock_records`] takes `.0`,
/// [`Database::reconstruct_freeblock_fragments`] takes `.1`. A free function (it
/// needs no `Database` state — only the page bytes and the page-derived
/// template), keeping the two public entry points a thin projection of one walk.
fn reconstruct_freeblock_inner(page_bytes: &[u8]) -> (Vec<CarvedCell>, Vec<CellFragment>) {
    let mut cells = Vec::new();
    let mut frags = Vec::new();
    let hdr_off = if page_bytes.starts_with(SQLITE_MAGIC) {
        SQLITE_HEADER_SIZE
    } else {
        0
    };
    let Some(&page_type) = page_bytes.get(hdr_off) else {
        return (cells, frags);
    };
    if page_type != 0x0d {
        return (cells, frags); // only table-leaf pages have freeblock residue
    }
    let Some(template) = freeblock_template(page_bytes, hdr_off) else {
        return (cells, frags);
    };

    let first_freeblock = be_u16(page_bytes, hdr_off + 1) as usize;
    let mut fb = first_freeblock;
    let mut walked = 0usize;
    let mut visited = std::collections::BTreeSet::new();
    while fb != 0 && walked < MAX_FREEBLOCKS_PER_PAGE {
        walked += 1;
        if !visited.insert(fb) {
            break; // cyclic next pointer
        }
        let next = be_u16(page_bytes, fb) as usize;
        let size = be_u16(page_bytes, fb + 2) as usize;
        let Some(fb_end) = fb.checked_add(size) else {
            break; // cov:unreachable: usize add of two u16-range values
        };
        if size >= 4 && fb_end <= page_bytes.len() {
            template.reconstruct_span_tiered(page_bytes, fb, fb_end, false, &mut cells, &mut frags);
        }
        fb = next;
    }

    let cell_count = be_u16(page_bytes, hdr_off + 3) as usize;
    let cptr_end = hdr_off + 8 + cell_count * 2;
    let cca = be_u16(page_bytes, hdr_off + 5) as usize;
    if cca > cptr_end && cca <= page_bytes.len() {
        for anchor_off in cptr_end..cca {
            let Some(anchor) =
                try_carve_cell_at(page_bytes, anchor_off, Some(template.column_count))
            else {
                continue;
            };
            let has_text = anchor
                .values
                .iter()
                .any(|v| matches!(v, Value::Text(t) if !t.is_empty() && !t.contains('\u{FFFD}')));
            if !has_text {
                continue;
            }
            let tail_start = anchor.offset + anchor.byte_len;
            template
                .reconstruct_span_tiered(page_bytes, tail_start, cca, true, &mut cells, &mut frags);
            break; // one anchored run per page — the contiguous freed tail
        }
    }
    (cells, frags)
}

fn freeblock_template(page_bytes: &[u8], hdr_off: usize) -> Option<FreeblockTemplate> {
    let cell_count = be_u16(page_bytes, hdr_off + 3) as usize;
    let cell_ptr_array = hdr_off + 8;
    for i in 0..cell_count {
        let cell_off = be_u16(page_bytes, cell_ptr_array + i * 2) as usize;
        if cell_off == 0 || cell_off >= page_bytes.len() {
            continue;
        }
        // Prefix: payload-length varint, rowid varint.
        let Ok((_payload_len, n1)) = read_varint(page_bytes, cell_off) else {
            continue; // cov:unreachable: a live cell-pointer addresses an in-bounds prefix
        };
        let Ok((_rowid, n2)) = read_varint(page_bytes, cell_off + n1) else {
            continue; // cov:unreachable: the rowid varint follows the payload-len varint in-page
        };
        let prefix_len = n1 + n2;
        // The freeblock header overwrites exactly 4 bytes. If the prefix alone is
        // wider, no record-header byte is clobbered in a way this simple template
        // handles — skip (those tables keep an intact header tail the forward
        // carver already reaches).
        if prefix_len > 4 {
            continue; // cov:unreachable: the corpus tables all encode a <=4-byte cell prefix
        }
        let payload_start = cell_off + n1 + n2;
        let Ok((header_len, hn)) = read_varint(page_bytes, payload_start) else {
            continue; // cov:unreachable: a live cell's record header follows its prefix in-page
        };
        let header_len = usize::try_from(header_len).ok()?;
        if header_len < hn {
            continue; // cov:unreachable: a live record's header_len covers its own varint
        }
        // Read the template's serial-type array, recording each serial's byte
        // offset within the header so we can split clobbered vs surviving.
        let mut serials = Vec::new();
        let mut hpos = hn;
        let mut ok = true;
        while hpos < header_len {
            let Ok((s, used)) = read_varint(page_bytes, payload_start + hpos) else {
                ok = false; // cov:unreachable: header_len bounds the serial array within the page
                break; // cov:unreachable: paired with the read failure above
            };
            serials.push((s, hpos, used));
            hpos += used;
        }
        if !ok || hpos != header_len || serials.len() < MIN_INFERRED_COLUMNS {
            continue; // cov:unreachable: a live cell's header parses cleanly with >= 2 columns
        }
        return FreeblockTemplate::build(prefix_len, header_len, hn, &serials);
    }
    None
}

/// A record-header template derived from a live cell on a table-leaf page, used
/// to rebuild freeblock-clobbered records (see
/// [`Database::reconstruct_freeblock_records`]).
///
/// Freeblock conversion overwrites the freed cell's first four bytes — the
/// payload-length + rowid varints, the record `header_len`, and the leading
/// serial type(s). The surviving serial-type tail and the value body remain. The
/// template supplies what was destroyed: the total column count, the serial types
/// of the leading (clobbered) columns, and the page offset, relative to the
/// freeblock start, at which the surviving serial tail begins.
struct FreeblockTemplate {
    /// Total number of columns in a record of this table.
    column_count: usize,
    /// Serial types of the leading columns whose header bytes the freeblock
    /// header clobbered (taken from the template; e.g. the fixed-width `id`).
    known_lead_serials: Vec<i64>,
    /// Offset, relative to the freeblock start, at which the **surviving** serial
    /// tail begins (== `prefix_len + first_surviving_serial_header_offset`).
    surviving_serials_off: usize,
}

impl FreeblockTemplate {
    /// Build a template from a parsed live-cell header. `serials` is the list of
    /// `(serial_type, header_offset, varint_width)` tuples for every column.
    /// Returns `None` when the 4-byte freeblock clobber boundary cannot be
    /// resolved to a clean split between leading and surviving serials.
    fn build(
        prefix_len: usize,
        _header_len: usize,
        _hn: usize,
        serials: &[(i64, usize, usize)],
    ) -> Option<FreeblockTemplate> {
        // Bytes of the record header the 4-byte freeblock header destroys.
        let clobbered_header_bytes = 4usize.checked_sub(prefix_len)?;
        // The first column whose header bytes survive intact is the first serial
        // whose header offset is at or beyond the clobber boundary. Everything
        // before it is supplied from the template.
        let mut known_lead = Vec::new();
        let mut surviving_serials_off = None;
        for &(serial, hpos, _used) in serials {
            if hpos >= clobbered_header_bytes {
                surviving_serials_off = Some(prefix_len + hpos);
                break;
            }
            known_lead.push(serial);
        }
        // Require at least one surviving serial AND at least one clobbered serial
        // (otherwise the forward carver already reaches the record, or nothing
        // survives to anchor reconstruction).
        let surviving_serials_off = surviving_serials_off?;
        if known_lead.is_empty() || known_lead.len() >= serials.len() {
            return None;
        }
        Some(FreeblockTemplate {
            column_count: serials.len(),
            known_lead_serials: known_lead,
            surviving_serials_off,
        })
    }

    /// Reconstruct **every** clobbered cell coalesced into the free span
    /// `[lo, hi)` — a chained freeblock or a page's unallocated gap — and append
    /// each to `out`.
    ///
    /// When SQLite frees adjacent cells it coalesces them into one freeblock whose
    /// interior still holds the freed cells back-to-back, **each** prefixed by a
    /// stale 4-byte freeblock header (`next`/`size`) that clobbers that cell's
    /// payload-length + rowid varints and leading serial(s). A single-shot
    /// reconstruction at `lo` recovers only the span's first cell; the trailing
    /// cells are intact records sitting at the previous record's end. This walks
    /// the template across the span: reconstruct at `lo`, advance to that record's
    /// end, repeat to `hi`. Every value is derived from the span bounds and the
    /// page's own schema template — no per-cell or per-database constant.
    ///
    /// Each candidate is validated identically to the single-cell case (legal
    /// serial types, record fits within `[cell_start, hi)`). The walk is
    /// **structural, not a sliding scan**: SQLite coalesces freed cells exactly
    /// back-to-back (each freed record's end abuts the next freed cell's clobbered
    /// 4-byte prefix), so the next cell begins precisely at the previous record's
    /// end. The walk therefore reconstructs at `lo`, advances to that record's
    /// end, and repeats — and STOPS the moment a position does not reconstruct
    /// cleanly. It never slides forward byte-by-byte hunting for the next cell:
    /// that fallback would synthesize a record from any run of bytes that happens
    /// to satisfy the legal-serial + fits-in-span checks, manufacturing phantoms
    /// in non-cell free space. Anchoring every cell at the prior record's exact
    /// end is what keeps the broader span-walk at single-cell precision. Bounded:
    /// the walk strictly advances (a record is non-empty) and is capped at
    /// [`MAX_FREEBLOCKS_PER_PAGE`] reconstructions per span.
    ///
    /// Follower precision (the coalesced-freeblock signature): the span's FIRST
    /// cell at `lo` is reconstructed unconditionally — `lo` is a real boundary (a
    /// freeblock-chain entry, or the gap anchor's first follower). Every SUBSEQUENT
    /// follower must carry the structural mark of a freed-and-coalesced cell: its
    /// clobbered 4-byte prefix is a stale freeblock header whose 2-byte `next`
    /// field is `0x0000` (a terminal/orphaned freeblock — what SQLite leaves when
    /// it coalesces freed cells back-to-back). A position whose leading two bytes
    /// are non-zero is a byte-shifted remnant, not a coalesced cell, so the run
    /// ends there. This is the check that separates a true coalesced tail (0D-06's
    /// `00 00 NN NN`-prefixed followers) from a misaligned fragment (0B-02's
    /// `24 09 …` remnant), keeping the gap pass phantom-free.
    ///
    /// `enforce_follower_mark` is `true` for the unallocated-gap pass, where the
    /// span is bounded only by `cellContentArea` (not by a page-recorded freeblock
    /// size) and so a byte-shifted remnant could otherwise be mistaken for a
    /// follower: there EVERY position must carry the `next == 0` mark. It is `false`
    /// for the freeblock-chain pass, whose span bounds are the page-recorded
    /// `[fb, fb + size)` — a strong boundary that already pins the coalesced run, so
    /// the interior followers (whose clobbered bytes are the original record's own
    /// varints, not necessarily `00 00 …`) are accepted on the fit-in-span check
    /// alone.
    ///
    /// Tiered walk: it pushes each reconstructed full cell into `cells`, and at the
    /// anchor where `reconstruct_one` would `break` it salvages the maximal
    /// decodable column prefix into `frags` as a [`CellFragment`] (when the §3.1
    /// distinctiveness gate passes) before stopping. Fragment salvage does NOT
    /// extend the walk — it stops at exactly the position the full walk does,
    /// preserving Tier-1's phantom discipline. Callers that want only the full
    /// cells (the Tier-1 [`Database::reconstruct_freeblock_records`]) discard
    /// `frags`; both tiers therefore come from one walk and can never diverge.
    fn reconstruct_span_tiered(
        &self,
        page: &[u8],
        lo: usize,
        hi: usize,
        enforce_follower_mark: bool,
        cells: &mut Vec<CarvedCell>,
        frags: &mut Vec<CellFragment>,
    ) {
        let mut cell_start = lo;
        let mut built = 0usize;
        while cell_start < hi && built < MAX_FREEBLOCKS_PER_PAGE {
            if enforce_follower_mark && be_u16(page, cell_start) != 0 {
                break; // not a coalesced freeblock follower — the contiguous run ends
            }
            let Some((cell, record_end)) = self.reconstruct_one(page, cell_start, hi) else {
                // Full reconstruction failed at this anchor; try to salvage the
                // decodable prefix as a fragment, then stop (do not extend the
                // walk past the failed anchor).
                if let Some(frag) = self.salvage_fragment(page, cell_start, hi) {
                    frags.push(frag);
                }
                break;
            };
            cells.push(cell);
            built += 1;
            cell_start = record_end;
        }
    }

    /// Salvage the maximal decodable column prefix at `cell_start` (bounded by
    /// `span_end`) when full reconstruction failed there. Walks the template +
    /// surviving serial array forward, decoding each column's body while it fits
    /// in the span; the first illegal serial, out-of-bounds read, or body that
    /// overruns the span ends the prefix. Returns a [`CellFragment`] **only** when
    /// the salvaged prefix contains at least one distinctive cell (TEXT ≥ 4 bytes
    /// of valid UTF-8, or REAL) — the §3.1 emission gate — otherwise `None`.
    fn salvage_fragment(
        &self,
        page: &[u8],
        cell_start: usize,
        span_end: usize,
    ) -> Option<CellFragment> {
        let surviving_count = self.column_count - self.known_lead_serials.len();
        let tail_start = cell_start.checked_add(self.surviving_serials_off)?;

        // Read as many legal surviving serials as decode in-bounds within the span.
        // The template's leading serials are always legal (they came from a live
        // cell), so the full serial array is `known_lead ++ legal_surviving`.
        let mut serials = self.known_lead_serials.clone();
        let mut pos = tail_start;
        for _ in 0..surviving_count {
            let Ok((s, used)) = read_varint(page, pos) else {
                break; // cov:unreachable: the surviving serials sit near the cell start, inside the freeblock/gap span the inner walker already bounds to the page; this read mirrors reconstruct_one's bounds guard so a truncated tail ends the prefix rather than panicking
            };
            if serial_body_len(s).is_none() {
                break; // cov:unreachable: serial_body_len is None only for a negative serial, which read_varint yields only from a crafted 9-byte varint; kept as a defence-in-depth guard so a malformed surviving tail ends the prefix rather than mis-decoding
            }
            let Some(next) = pos.checked_add(used) else {
                break; // cov:unreachable: usize add of an in-page varint width
            };
            if next > span_end {
                break; // serial tail overran the span
            }
            serials.push(s);
            pos = next;
        }

        // Decode column bodies left-to-right, keeping each whose body ends within
        // the span. The body begins right after the surviving serial tail.
        let body_start = pos;
        let mut surviving: Vec<(usize, Value)> = Vec::new();
        let mut bpos = body_start;
        for (idx, &s) in serials.iter().enumerate() {
            let Some(blen) = serial_body_len(s) else {
                break; // cov:unreachable: only legal serials were pushed above
            };
            let Some(body_end) = bpos.checked_add(blen) else {
                break; // cov:unreachable: usize add of an in-page body length
            };
            if body_end > span_end {
                break; // this column's body overruns the span — prefix ends here
            }
            let Some(body) = page.get(bpos..body_end) else {
                break; // cov:unreachable: body_end <= span_end <= page.len()
            };
            let Ok((val, _)) = decode_value(body, 0, s) else {
                break; // cov:unreachable: serial_body_len-legal serials decode in-bounds
            };
            surviving.push((idx, val));
            bpos = body_end;
        }

        // Emission gate: at least one distinctive cell (TEXT >= 4 UTF-8 bytes, or
        // REAL). A lone integer/NULL/blob prefix is coincidence-prone — no fragment.
        if !surviving.iter().any(|(_, v)| is_distinctive(v)) {
            return None;
        }
        let last_body_end = bpos;
        Some(CellFragment {
            offset: cell_start,
            byte_len: last_body_end.saturating_sub(cell_start),
            missing: self.column_count - surviving.len(),
            surviving,
            confidence: FRAGMENT_CONFIDENCE,
        })
    }

    /// Rebuild the single record whose clobbered cell begins at `cell_start`,
    /// bounded by the enclosing span end `span_end`: read the surviving serial
    /// tail, prepend the template's leading serials, decode the body, and validate
    /// the whole record fits within `[cell_start, span_end)`. Returns the carved
    /// cell and the record's end offset (the next coalesced cell's start), or
    /// `None` on any out-of-bounds or implausible parse.
    fn reconstruct_one(
        &self,
        page: &[u8],
        cell_start: usize,
        span_end: usize,
    ) -> Option<(CarvedCell, usize)> {
        let surviving_count = self.column_count - self.known_lead_serials.len();
        let tail_start = cell_start.checked_add(self.surviving_serials_off)?;

        // Read the surviving serial tail from the freeblock.
        let mut serials = self.known_lead_serials.clone();
        let mut pos = tail_start;
        for _ in 0..surviving_count {
            let (s, used) = read_varint(page, pos).ok()?;
            // A serial type must be legal; reject the candidate otherwise.
            serial_body_len(s)?;
            serials.push(s);
            pos = pos.checked_add(used)?;
            if pos > span_end {
                return None;
            }
        }

        // The body begins right after the surviving serial tail. Compute its
        // length from the full (template + surviving) serial array.
        let mut body_len = 0usize;
        for &s in &serials {
            body_len = body_len.checked_add(serial_body_len(s)?)?;
        }
        let body_start = pos;
        let record_end = body_start.checked_add(body_len)?;
        // The reconstructed record MUST fit within the enclosing span — the core
        // precision check that rejects coincidental/garbage reconstructions.
        if record_end > span_end {
            return None;
        }

        // Synthesize a record payload (header + body) for the shared decoder so
        // values are decoded with the same storage-class fidelity as live rows.
        // The rowid is destroyed; pass 0 so a serial-0 column reads as NULL rather
        // than a fabricated rowid.
        let body = page.get(body_start..record_end)?;
        let values = decode_synthetic_record(&serials, body)?;
        if values.len() != self.column_count {
            return None; // cov:unreachable: one value per serial by construction
        }

        Some((
            CarvedCell {
                offset: cell_start,
                byte_len: record_end - cell_start,
                rowid: 0, // destroyed by freeblock conversion — surfaced as unknown
                values,
                confidence: FREEBLOCK_RECONSTRUCT_CONFIDENCE,
            },
            record_end,
        ))
    }
}

/// Decode a record body given an explicit serial-type array (the freeblock
/// reconstructor supplies the array; the on-disk `header_len` + leading serials
/// were destroyed). Mirrors [`decode_record`]'s body pass. Returns `None` on any
/// out-of-bounds read so a malformed reconstruction is rejected, never panics.
fn decode_synthetic_record(serials: &[i64], body: &[u8]) -> Option<Vec<Value>> {
    let mut values = Vec::with_capacity(serials.len());
    let mut bpos = 0usize;
    for &serial in serials {
        let (val, size) = decode_value(body, bpos, serial).ok()?;
        values.push(val);
        bpos = bpos.checked_add(size)?;
    }
    Some(values)
}

/// Attempt to recognize a table-leaf cell at `off` in `buf` as a record.
///
/// `expected_columns` is `Some(n)` to require exactly `n` columns (fixed-schema
/// carving), or `None` to **infer** the column count from the record's own
/// serial-type array (dropped-table / schema-gone carving). Returns a
/// [`CarvedCell`] only when the bytes are self-consistently record-shaped;
/// otherwise `None`. Never panics — every access is bounds-checked.
fn try_carve_cell_at(
    buf: &[u8],
    off: usize,
    expected_columns: Option<usize>,
) -> Option<CarvedCell> {
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
    let cap = expected_columns.unwrap_or(0);
    let mut serials = Vec::with_capacity(cap);
    let mut hpos = hn;
    while hpos < header_len {
        let (s, used) = read_varint(payload, hpos).ok()?;
        serials.push(s);
        hpos += used;
    }
    // The header must consume cleanly, and match the expected column count when
    // one was given. When inferring, require a minimum plausible column count to
    // suppress coincidental 1-column matches.
    if hpos != header_len {
        return None;
    }
    match expected_columns {
        Some(n) if serials.len() != n => return None,
        None if serials.len() < MIN_INFERRED_COLUMNS => return None,
        _ => {}
    }
    let column_count = serials.len();

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

/// Recognize a freed **spilled** table-leaf cell at `off` whose payload exceeds
/// the in-page threshold (`usable - 35`) and therefore continues on an
/// overflow-page chain (task #73). The sibling of [`try_carve_cell_at`] for the
/// overflow class: the two partition the candidate space by the spec spill
/// threshold, so a cell is recognized by exactly one of them.
///
/// `expected_columns` is `Some(n)` to require exactly `n` columns, or `None` to
/// infer the count (≥ [`MIN_INFERRED_COLUMNS`]). Returns a [`SpilledCell`]
/// (recognition only — the chain is resolved later) when the local prefix is
/// self-consistent: header fits in the local payload, the serial array consumes
/// the header cleanly, `header_len + Σ serial_body_len == P` (length closure
/// over the *declared* P), and the local payload plus its 4-byte overflow
/// pointer are in-bounds. Never panics — every access is bounds-checked.
fn try_carve_spilled_cell_at(
    buf: &[u8],
    off: usize,
    usable: usize,
    expected_columns: Option<usize>,
) -> Option<SpilledCell> {
    let (payload_len, n1) = read_varint(buf, off).ok()?;
    let payload_len = usize::try_from(payload_len).ok()?;
    // Only the overflow class — in-page payloads belong to `try_carve_cell_at`.
    if payload_len <= usable.checked_sub(35)? {
        return None;
    }
    let (rowid, n2) = read_varint(buf, off + n1).ok()?;
    if rowid <= 0 {
        return None;
    }
    let payload_start = off + n1 + n2;
    let local_len = local_payload_len(payload_len, usable);
    // The local payload prefix plus the 4-byte first-overflow pointer must be in
    // bounds of the scanned slice.
    let prefix = buf.get(payload_start..payload_start + local_len + 4)?;

    // The record header must fit entirely within the local prefix — otherwise the
    // serial array is not addressable locally and we abstain rather than guess.
    let (header_len, hn) = read_varint(prefix, 0).ok()?;
    let header_len = usize::try_from(header_len).ok()?;
    if header_len > local_len || header_len < hn {
        return None;
    }
    let mut serials = Vec::new();
    let mut hpos = hn;
    while hpos < header_len {
        let (s, used) = read_varint(prefix, hpos).ok()?;
        serials.push(s);
        hpos += used;
    }
    if hpos != header_len {
        return None;
    }
    match expected_columns {
        Some(n) if serials.len() != n => return None,
        None if serials.len() < MIN_INFERRED_COLUMNS => return None,
        _ => {}
    }

    // Length closure over the DECLARED payload: header + body must equal P.
    let mut body_len = 0usize;
    for &s in &serials {
        body_len += serial_body_len(s)?;
    }
    if header_len + body_len != payload_len {
        return None;
    }

    let first_overflow = be_u32(prefix, local_len);
    Some(SpilledCell {
        offset: off,
        byte_len: n1 + n2 + local_len + 4,
        payload_len,
        rowid,
        serials,
        local_len,
        local_payload_off: payload_start,
        first_overflow,
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

    /// The deleted-record carving fixture (see `docs/corpus-catalog.md`).
    const DELETED_DB: &[u8] = include_bytes!("../../tests/data/deleted_places.db");
    /// A clean DB with one live `moz_places` table and no deletions.
    const CLEAN_DB: &[u8] = include_bytes!("../../tests/data/places.db");

    #[test]
    fn free_regions_is_complement_of_live_extents() {
        // Live cells [10,20) and [30,40) within content area [5, 50).
        let live = [(10, 20), (30, 40)];
        let regions = free_regions(&live, 5, 50);
        assert_eq!(regions, vec![(5, 10), (20, 30), (40, 50)]);
        // No live cells -> the whole span is free.
        assert_eq!(free_regions(&[], 5, 50), vec![(5, 50)]);
        // Live cell covering the whole span -> no free region.
        assert!(free_regions(&[(0, 100)], 5, 50).is_empty());
    }

    #[test]
    fn live_cell_len_reads_on_page_footprint() {
        // Cell: payload_len=3 (varint 0x03), rowid=1 (varint 0x01), 3 payload bytes.
        let buf = [0x03, 0x01, 0xAA, 0xBB, 0xCC];
        let usable = 4096;
        assert_eq!(live_cell_len(&buf, 0, usable), Some(1 + 1 + 3));
        // Truncated prefix -> None, never panics.
        assert_eq!(live_cell_len(&[0x81], 0, usable), None);
    }

    #[test]
    fn carve_free_regions_recovers_in_page_remnant() {
        let db = Database::open(DELETED_DB.to_vec()).unwrap();
        // Page 8 is an allocated leaf (live ids 181..=200) whose free gap holds
        // deleted-row residue including rowid 237.
        let page = db.raw_page(8).unwrap();
        let carved = db.carve_free_regions(page, 6);
        assert!(carved.iter().any(|c| c.rowid == 237));
        // 0-FP: never a live (id<=200) rowid.
        assert!(carved.iter().all(|c| c.rowid > 200));
        // A non-leaf page yields nothing.
        assert!(db.carve_free_regions(&[0x05u8; 4096], 6).is_empty());
        // An empty / too-short slice yields nothing (no panic).
        assert!(db.carve_free_regions(&[], 6).is_empty());
    }

    #[test]
    fn carve_leaf_cells_reads_allocated_cells_and_rejects_non_leaf() {
        let db = Database::open(DELETED_DB.to_vec()).unwrap();
        // Page 8 is an allocated table-leaf (live ids 181..=200); carve_leaf_cells
        // decodes every cell the page records as allocated, so the live ids appear
        // (unlike carve_free_regions, which excludes them).
        let page = db.raw_page(8).unwrap();
        let cells = db.carve_leaf_cells(page);
        assert!(
            cells.iter().any(|c| c.rowid == 181),
            "must read the allocated cells of the leaf"
        );
        // Page 1 is passed whole (starts with the file magic) → header read at 100.
        let _ = db.carve_leaf_cells(db.raw_page(1).unwrap());
        // A non-leaf page (interior 0x05) and an empty/too-short slice yield nothing
        // (no panic) — the same defensive arms carve_free_regions guards.
        assert!(db.carve_leaf_cells(&[0x05u8; 4096]).is_empty());
        assert!(db.carve_leaf_cells(&[]).is_empty());
    }

    #[test]
    fn carve_free_regions_handles_page_one_and_inferred() {
        let db = Database::open(DELETED_DB.to_vec()).unwrap();
        // Page 1 is passed whole (starts with the file magic) -> the b-tree header
        // is read at offset 100, exercising the page-1 branch.
        let page1 = db.raw_page(1).unwrap();
        let _ = db.carve_free_regions(page1, 6);
        // With column_count_hint = 0, the inferred path runs over the free regions.
        let page8 = db.raw_page(8).unwrap();
        let inferred = db.carve_free_regions(page8, 0);
        assert!(inferred.iter().any(|c| c.rowid == 237));
    }

    #[test]
    fn live_cell_len_accounts_for_overflow_pointer() {
        let usable = 4096usize;
        // Non-spilling cell: payload_len small -> footprint = prefix + payload.
        // varint 0x03 (payload_len=3), 0x01 (rowid=1), 3 payload bytes.
        assert_eq!(live_cell_len(&[0x03, 0x01, 0, 0, 0], 0, usable), Some(5));

        // Spilling cell: a payload_len far above the local threshold takes the
        // overflow branch -> footprint = prefix + local + 4 (overflow pointer).
        // Encode payload_len = 5000 as a 2-byte varint (0xA7 0x08), rowid = 1.
        let mut buf = vec![0xA7, 0x08, 0x01];
        buf.extend(std::iter::repeat_n(0u8, 5000));
        let total = 5000usize;
        let local = local_payload_len(total, usable);
        assert!(local < total, "this payload must spill");
        assert_eq!(live_cell_len(&buf, 0, usable), Some(2 + 1 + local + 4));
    }

    #[test]
    fn carve_cells_inferred_matches_fixed_count() {
        let db = Database::open(DELETED_DB.to_vec()).unwrap();
        // A freed leaf page body carves the same rows whether the column count is
        // fixed at 6 or inferred.
        let page = db.raw_page(10).unwrap();
        let fixed = db.carve_cells(page, 6);
        let inferred = db.carve_cells_inferred(page);
        assert!(!fixed.is_empty());
        let fixed_ids: std::collections::BTreeSet<i64> = fixed.iter().map(|c| c.rowid).collect();
        let inf_ids: std::collections::BTreeSet<i64> = inferred.iter().map(|c| c.rowid).collect();
        assert!(fixed_ids.is_subset(&inf_ids));
    }

    #[test]
    fn has_user_table_distinguishes_live_and_dropped() {
        let live = Database::open(CLEAN_DB.to_vec()).unwrap();
        assert!(live.has_user_table());
        let with_deletions = Database::open(DELETED_DB.to_vec()).unwrap();
        assert!(with_deletions.has_user_table());
    }

    #[test]
    fn live_rowids_collects_live_rows_only() {
        let db = Database::open(CLEAN_DB.to_vec()).unwrap();
        let ids = db.live_rowids();
        // places.db has 5 live rows, rowids 1..=5.
        assert_eq!(ids.len(), 5);
        assert!(ids.contains(&1) && ids.contains(&5));

        // On the deletions fixture, live rowids are 1..=200; none of the deleted
        // 201..=400 appear.
        let del = Database::open(DELETED_DB.to_vec()).unwrap();
        let live = del.live_rowids();
        assert!(live.contains(&1) && live.contains(&200));
        assert!(!live.contains(&201) && !live.contains(&400));
    }

    #[test]
    fn live_rows_decodes_current_values() {
        let db = Database::open(CLEAN_DB.to_vec()).unwrap();
        let rows = db.live_rows();
        // places.db has 5 live rows keyed by rowid 1..=5, each decoded to values.
        assert_eq!(rows.len(), 5);
        // Row 1's url column (index 1) is the rust-lang URL (cross-checks that
        // values are decoded, not just rowids collected).
        let r1 = rows.get(&1).expect("row 1 present");
        assert!(
            matches!(r1.get(1), Some(Value::Text(t)) if t.contains("rust-lang")),
            "row 1 values must be decoded: {r1:?}"
        );
        // The value map and the rowid set agree on which rows are live.
        let ids = db.live_rowids();
        assert_eq!(
            rows.keys().copied().collect::<Vec<_>>(),
            ids.into_iter().collect::<Vec<_>>()
        );

        // The deletions fixture's table b-tree has an INTERIOR root page (0x05),
        // so this exercises the interior-walk branch of collect_rows and confirms
        // values are decoded for all 200 live rows.
        let del = Database::open(DELETED_DB.to_vec()).unwrap();
        let del_rows = del.live_rows();
        assert_eq!(del_rows.len(), 200);
        let r1 = del_rows.get(&1).expect("live row 1");
        assert!(
            matches!(r1.get(1), Some(Value::Text(t)) if t.contains("site-1.example")),
            "interior-walked live row 1 must decode its url: {r1:?}"
        );
    }

    /// Real-corpus freeblock reconstruction: 0C-01 page 2 has six freeblock-head
    /// cells the forward parser cannot reach; reconstruction recovers them
    /// (including the destroyed-rowid `id` column) from the surviving serial tail.
    const NEMETZ_0C_01: &[u8] = include_bytes!("../../tests/data/nemetz/0C/0C-01.db");

    #[test]
    fn reconstruct_freeblock_records_recovers_clobbered_rows() {
        let db = Database::open(NEMETZ_0C_01.to_vec()).unwrap();
        let page = db.raw_page(2).unwrap();
        let recovered = db.reconstruct_freeblock_records(page);
        // Row 20005 is a freeblock-head cell only reconstruction can recover.
        assert!(recovered.iter().any(|c| c.values
            == vec![
                Value::Integer(20005),
                Value::Integer(3_780_322_152),
                Value::Integer(3_909_007_646),
                Value::Integer(120_462_986),
                Value::Integer(1_290_558_629),
            ]));
        assert!(recovered
            .iter()
            .all(|c| c.rowid == 0 && c.confidence <= 0.5));
    }

    /// Real-corpus span-walking reconstruction (task #66): 0D-07 page 3 coalesces
    /// three deleted cells into a single freeblock `[0xf79,0xfe0)` —
    /// `Luca|Schumacher` (the head), then `Kurt|Schubert`, then `Georg|Schulz`,
    /// each prefixed by a stale `00 00 00 NN` freeblock header that clobbers its
    /// leading four bytes. A single-shot head reconstruction recovers only the
    /// first; walking the template across the whole span recovers all three.
    const NEMETZ_0D_07: &[u8] = include_bytes!("../../tests/data/nemetz/0D/0D-07.db");

    #[test]
    fn reconstruct_freeblock_records_walks_coalesced_cells() {
        let db = Database::open(NEMETZ_0D_07.to_vec()).unwrap();
        let page = db.raw_page(3).unwrap();
        let recovered = db.reconstruct_freeblock_records(page);
        let has = |name: &str, surname: &str| {
            recovered.iter().any(|c| {
                matches!(c.values.get(1), Some(Value::Text(t)) if t == name)
                    && matches!(c.values.get(2), Some(Value::Text(t)) if t == surname)
            })
        };
        // The span-head cell a single-shot reconstruction already reached.
        assert!(has("Luca", "Schumacher"), "head cell must be recovered");
        // The two trailing cells deeper inside the same freeblock — only a
        // span-walk reaches these.
        assert!(
            has("Kurt", "Schubert"),
            "second coalesced cell must be recovered"
        );
        assert!(
            has("Georg", "Schulz"),
            "third coalesced cell must be recovered"
        );
        // Every reconstruction carries a destroyed rowid and low confidence.
        assert!(recovered
            .iter()
            .all(|c| c.rowid == 0 && c.confidence <= 0.5));
    }

    /// Helper: a real opened DB to call the page-slice methods against crafted
    /// page byte slices (the methods take `page_bytes` explicitly).
    fn opened() -> Database {
        Database::open(NEMETZ_0C_01.to_vec()).unwrap()
    }

    /// A leaf page advertising a freeblock chain but whose cells do not parse
    /// yields no template, so reconstruction returns empty (covers the
    /// `freeblock_template` rejection arms and the final `None`).
    #[test]
    fn reconstruct_freeblock_records_without_template_is_empty() {
        let db = opened();
        let mut page = vec![0u8; 256];
        page[0] = 0x0d; // table-leaf
        page[1] = 0x00;
        page[2] = 0x40; // first freeblock at offset 64
        page[3] = 0x00;
        page[4] = 0x01; // cell_count = 1
                        // The single cell pointer (offset 8) points at 0 -> cell_off == 0 -> skipped,
                        // so no template can be derived.
        page[8] = 0x00;
        page[9] = 0x00;
        // A freeblock at 64: next=0, size=8 (in-bounds), but no template anyway.
        page[64] = 0x00;
        page[65] = 0x00;
        page[66] = 0x00;
        page[67] = 0x08;
        assert!(db.reconstruct_freeblock_records(&page).is_empty());
    }

    /// A cyclic freeblock `next` chain terminates (covers the cycle-break guard)
    /// and a freeblock whose size runs past the page is skipped — all without a
    /// panic.
    #[test]
    fn reconstruct_freeblock_records_breaks_cyclic_chain() {
        let db = opened();
        // Build a page WITH a usable template by copying 0C-01 page 2's header +
        // first live cell, then point the freeblock chain at itself.
        let src = db.raw_page(2).unwrap().to_vec();
        let mut page = src.clone();
        // Repoint first-freeblock to a self-cycle at offset 100: next -> 100.
        page[1] = 0x00;
        page[2] = 100;
        page[100] = 0x00;
        page[101] = 100; // next = 100 (points to itself)
        page[102] = 0xff;
        page[103] = 0xff; // size huge -> runs past page -> skipped
                          // Must not panic and must terminate.
        let _ = db.reconstruct_freeblock_records(&page);
    }

    // ---- Tier-2 fragment salvage (task #72) --------------------------------

    #[test]
    fn is_distinctive_classifies_every_storage_class() {
        // TEXT >= 4 UTF-8 bytes and REAL are distinctive; everything else is not.
        assert!(is_distinctive(&Value::Text("Anja".into())));
        assert!(is_distinctive(&Value::Text("\u{00e4}\u{00f6}".into()))); // 4 UTF-8 bytes
        assert!(is_distinctive(&Value::Real(3.5)));
        assert!(!is_distinctive(&Value::Text("abc".into()))); // 3 bytes
        assert!(!is_distinctive(&Value::Text(String::new())));
        assert!(!is_distinctive(&Value::Text("ab\u{fffd}x".into()))); // replacement char
        assert!(!is_distinctive(&Value::Integer(20004)));
        assert!(!is_distinctive(&Value::Null));
        assert!(!is_distinctive(&Value::Blob(vec![1, 2, 3, 4, 5])));
    }

    /// Build a synthetic 256-byte table-leaf (0x0d) page for the fragment tests.
    ///
    /// Schema implied by the template live cell: 3 columns
    /// `(c0: 1-byte int, c1: TEXT-4, c2: TEXT-4)` → serials `[1, 21, 21]`,
    /// `header_len = 4`. The live cell (the freeblock template source) is placed
    /// at `live_off`. A single freeblock spanning `[fb, fb + fb_size)` holds the
    /// freed-cell payload `freed`, whose leading 4 bytes are the stale freeblock
    /// header (`next`, `size`) — exactly what freeblock conversion clobbers.
    fn synth_frag_page(live_off: usize, fb: usize, fb_size: usize, freed: &[u8]) -> Vec<u8> {
        let mut page = vec![0u8; 256];
        page[0] = 0x0d; // table-leaf
        page[1] = (fb >> 8) as u8;
        page[2] = (fb & 0xff) as u8;
        page[3] = 0x00;
        page[4] = 0x01; // cell_count = 1
        page[5] = (live_off >> 8) as u8;
        page[6] = (live_off & 0xff) as u8; // cellContentArea = live_off
        page[8] = (live_off >> 8) as u8;
        page[9] = (live_off & 0xff) as u8; // cell pointer -> live_off

        // Live template cell: payload_len=13, rowid=5, header_len=4, serials
        // [int1, text4, text4], body 1+4+4.
        let live = [
            13u8, 5u8, 0x04, 0x01, 0x15, 0x15, 0x09, b'L', b'i', b'v', b'e', b'R', b'o', b'w', b'!',
        ];
        page[live_off..live_off + live.len()].copy_from_slice(&live);

        // Lay the freed-cell bytes first, then stamp the stale freeblock header
        // (next=0, size=fb_size) over its first 4 bytes — exactly what freeblock
        // conversion does (the header clobbers the freed cell's leading 4 bytes).
        page[fb..fb + freed.len()].copy_from_slice(freed);
        page[fb] = 0x00;
        page[fb + 1] = 0x00;
        page[fb + 2] = (fb_size >> 8) as u8;
        page[fb + 3] = (fb_size & 0xff) as u8;
        page
    }

    /// (a) Truncated tail: the freed cell's body overruns the freeblock span, so
    /// full reconstruction fails — salvage emits the decodable column prefix
    /// (incl. a distinctive TEXT cell) with correct `missing`/confidence, while
    /// `reconstruct_freeblock_records` recovers nothing from that anchor.
    #[test]
    fn fragment_salvage_truncated_tail() {
        let db = opened();
        // surviving serials [21,21] at fb+4,fb+5; body c0(1)+c1(4)+c2(4) at fb+6.
        // A full record needs fb+15. Span size 12 ends at fb+12: c0,c1 fit, c2
        // overruns → salvage keeps [c0, c1].
        let mut freed = vec![0u8; 16];
        freed[4] = 0x15;
        freed[5] = 0x15;
        freed[6] = 0x07;
        freed[7..11].copy_from_slice(b"Anja");
        freed[11..15].copy_from_slice(b"Frnk");
        let page = synth_frag_page(96, 64, 12, &freed);

        let frags = db.reconstruct_freeblock_fragments(&page);
        assert_eq!(frags.len(), 1, "exactly one fragment salvaged");
        let f = &frags[0];
        assert_eq!(f.offset, 64);
        assert_eq!(
            f.surviving,
            vec![(0, Value::Integer(7)), (1, Value::Text("Anja".into()))]
        );
        assert_eq!(f.missing, 1, "c2 did not decode");
        assert!((f.confidence - 0.2).abs() < f32::EPSILON);
        let cells = db.reconstruct_freeblock_records(&page);
        assert!(cells.iter().all(|c| c.offset != 64));
    }

    /// (b) A surviving column whose body cannot fit ends the prefix early —
    /// salvage keeps the columns decoded before the failure.
    #[test]
    fn fragment_salvage_partial_tail() {
        let db = opened();
        let mut freed = vec![0u8; 16];
        freed[4] = 0x15;
        freed[5] = 0x15;
        freed[6] = 0x07;
        freed[7..11].copy_from_slice(b"Lena");
        let page = synth_frag_page(96, 64, 11, &freed); // c1 fits, c2 overruns
        let frags = db.reconstruct_freeblock_fragments(&page);
        assert_eq!(frags.len(), 1);
        assert_eq!(
            frags[0].surviving,
            vec![(0, Value::Integer(7)), (1, Value::Text("Lena".into()))]
        );
    }

    /// (c) A fully reconstructable freeblock yields NO fragment (mutual exclusion).
    #[test]
    fn fragment_salvage_full_record_yields_no_fragment() {
        let db = opened();
        let mut freed = vec![0u8; 16];
        freed[4] = 0x15;
        freed[5] = 0x15;
        freed[6] = 0x07;
        freed[7..11].copy_from_slice(b"Whol");
        freed[11..15].copy_from_slice(b"Erow");
        let page = synth_frag_page(96, 64, 15, &freed);
        let cells = db.reconstruct_freeblock_records(&page);
        assert!(
            cells.iter().any(|c| c.offset == 64),
            "full record recovered"
        );
        assert!(
            db.reconstruct_freeblock_fragments(&page).is_empty(),
            "no fragment when the full record is recoverable"
        );
    }

    /// (d) Salvage yielding only non-distinctive (INTEGER) cells emits NO fragment.
    #[test]
    fn fragment_salvage_integer_only_is_rejected() {
        let db = opened();
        let mut freed = vec![0u8; 12];
        freed[4] = 0x01; // surviving 1-byte int
        freed[5] = 0x01; // surviving 1-byte int
        freed[6] = 0x07;
        freed[7] = 0x08;
        let page = synth_frag_page(96, 64, 8, &freed); // c2 overruns; only ints decode
        assert!(
            db.reconstruct_freeblock_fragments(&page).is_empty(),
            "integer-only prefix is not distinctive — no fragment"
        );
    }

    /// (e) Fragment salvage does NOT extend the span walk: a failed head stops
    /// the walk, emitting at most one fragment, never sliding forward.
    #[test]
    fn fragment_salvage_does_not_extend_walk() {
        let db = opened();
        let mut freed = vec![0u8; 16];
        freed[4] = 0x15;
        freed[5] = 0x15;
        freed[6] = 0x07;
        freed[7..11].copy_from_slice(b"Stop");
        freed[11..15].copy_from_slice(b"Here");
        let page = synth_frag_page(96, 64, 12, &freed);
        assert_eq!(db.reconstruct_freeblock_fragments(&page).len(), 1);
    }

    /// (Step 2) Real-artifact validation: 0D-01 page 2 salvages the genuine
    /// partial deleted row for id 20004 — `Text("Anja")`/`Text("Frank")` survive
    /// in a freeblock whose full-row reconstruction fails. Full pass unchanged.
    const NEMETZ_0D_01: &[u8] = include_bytes!("../../tests/data/nemetz/0D/0D-01.db");

    #[test]
    fn fragment_salvage_recovers_anja_on_0d01() {
        let db = Database::open(NEMETZ_0D_01.to_vec()).unwrap();
        let page = db.raw_page(2).unwrap();
        let frags = db.reconstruct_freeblock_fragments(page);
        let f = frags
            .iter()
            .find(|f| {
                f.surviving
                    .iter()
                    .any(|(_, v)| matches!(v, Value::Text(t) if t == "Anja"))
            })
            .expect("0D-01 page 2 must salvage the Anja fragment");
        assert!(f
            .surviving
            .iter()
            .any(|(_, v)| matches!(v, Value::Text(t) if t == "Frank")));
        assert!((f.confidence - 0.2).abs() < f32::EPSILON);
        let cells = db.reconstruct_freeblock_records(page);
        assert!(cells.iter().all(|c| !c
            .values
            .iter()
            .any(|v| matches!(v, Value::Text(t) if t == "Anja"))));
    }

    // ---- task #73: chain-aware overflow recovery — spilled-cell recognition ----

    /// Encode a SQLite varint (minimal big-endian 7-bit groups).
    fn enc_varint(mut n: u64) -> Vec<u8> {
        if n == 0 {
            return vec![0];
        }
        let mut groups = Vec::new();
        while n > 0 {
            groups.push((n & 0x7f) as u8);
            n >>= 7;
        }
        groups.reverse();
        let last = groups.len() - 1;
        for (i, g) in groups.iter_mut().enumerate() {
            if i != last {
                *g |= 0x80;
            }
        }
        groups
    }

    /// Build the **local prefix** bytes of a freed spilled table-leaf cell:
    /// `payload_len varint, rowid varint, record header, local payload bytes,
    /// 4-byte big-endian first-overflow pointer`. Returns `(bytes, P, local,
    /// serials)`. The record is `(id INTEGER, name TEXT, code TEXT)` with `code`
    /// large enough to force a spill past `usable - 35`.
    fn synth_spilled_prefix(
        rowid: i64,
        id: i64,
        name: &str,
        code_len: usize,
        usable: usize,
        first_overflow: u32,
    ) -> (Vec<u8>, usize, usize, Vec<i64>) {
        let id_serial = 1i64; // 1-byte integer
        let name_serial = 13 + 2 * name.len() as i64; // TEXT
        let code_serial = 13 + 2 * code_len as i64; // TEXT
        let serials = vec![id_serial, name_serial, code_serial];
        let mut serial_bytes = Vec::new();
        for &s in &serials {
            serial_bytes.extend(enc_varint(s as u64));
        }
        // header_len varint counts itself — solve the fixed point.
        let mut header_len = serial_bytes.len() + 1;
        while enc_varint(header_len as u64).len() + serial_bytes.len() != header_len {
            header_len += 1;
        }
        let mut header = enc_varint(header_len as u64);
        header.extend(&serial_bytes);
        let body_len = 1 + name.len() + code_len;
        let payload_len = header.len() + body_len;
        let local = local_payload_len(payload_len, usable);

        // Full payload = header ++ id-body ++ name-body ++ code-body.
        let mut payload = header.clone();
        payload.push(id as u8); // 1-byte id
        payload.extend(name.as_bytes());
        payload.extend(std::iter::repeat_n(b'C', code_len));
        assert_eq!(payload.len(), payload_len);

        // Cell = prefix varints ++ local payload prefix ++ 4-byte overflow ptr.
        let mut cell = enc_varint(payload_len as u64);
        cell.extend(enc_varint(rowid as u64));
        cell.extend(&payload[..local]);
        cell.extend(first_overflow.to_be_bytes());
        (cell, payload_len, local, serials)
    }

    #[test]
    fn spilled_recognizer_reads_intact_prefix() {
        let usable = 4096usize;
        let (cell, p, local, serials) =
            synth_spilled_prefix(20012, 42, "Ella", 4200, usable, 13);
        assert!(p > usable - 35, "this record must spill");
        // Place the cell inside a larger scanned slice at a nonzero offset.
        let off = 50usize;
        let mut buf = vec![0u8; off];
        buf.extend(&cell);
        let sc = try_carve_spilled_cell_at(&buf, off, usable, Some(3))
            .expect("must recognize the intact-prefix spilled cell");
        assert_eq!(sc.payload_len, p);
        assert_eq!(sc.local_len, local);
        assert_eq!(sc.rowid, 20012);
        assert_eq!(sc.first_overflow, 13);
        assert_eq!(sc.serials, serials);
        assert_eq!(sc.offset, off);
    }

    #[test]
    fn spilled_recognizer_abstains_for_in_page_payload() {
        let usable = 4096usize;
        // A small (in-page) payload: the existing carve path owns it.
        let (cell, p, _local, _s) = {
            // header (3 serials) + body for a tiny code -> P <= usable-35.
            let r = synth_spilled_prefix(7, 1, "Bob", 10, usable, 9);
            r
        };
        assert!(p <= usable - 35, "this record must NOT spill");
        assert!(try_carve_spilled_cell_at(&cell, 0, usable, Some(3)).is_none());
    }

    #[test]
    fn spilled_recognizer_abstains_on_truncated_pointer() {
        let usable = 4096usize;
        let (cell, _p, _local, _s) =
            synth_spilled_prefix(20012, 42, "Ella", 4200, usable, 13);
        // Drop the final 2 bytes so the 4-byte overflow pointer is out of bounds.
        let truncated = &cell[..cell.len() - 2];
        assert!(try_carve_spilled_cell_at(truncated, 0, usable, Some(3)).is_none());
    }

    #[test]
    fn spilled_recognizer_abstains_on_column_mismatch() {
        let usable = 4096usize;
        let (cell, _p, _local, _s) =
            synth_spilled_prefix(20012, 42, "Ella", 4200, usable, 13);
        // Expect 5 columns but the record has 3.
        assert!(try_carve_spilled_cell_at(&cell, 0, usable, Some(5)).is_none());
        // Inferred (None) still recognizes it.
        assert!(try_carve_spilled_cell_at(&cell, 0, usable, None).is_some());
    }

    #[test]
    fn spilled_recognizer_abstains_on_nonpositive_rowid() {
        let usable = 4096usize;
        let (cell, _p, _local, _s) =
            synth_spilled_prefix(0, 42, "Ella", 4000, usable, 13);
        assert!(try_carve_spilled_cell_at(&cell, 0, usable, Some(3)).is_none());
    }
}
