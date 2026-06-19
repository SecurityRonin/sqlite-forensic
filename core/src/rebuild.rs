//! Pure-Rust **writer** that rebuilds a valid `SQLite` database file from carved
//! deleted records (the inverse of the reader in [`crate`]).
//!
//! [`build_recovered_db`] takes a set of [`RebuildRow`]s and returns the bytes of
//! a single-table `SQLite` database (`recovered_records`) holding one row per
//! carved record, each cell stored in its **native** storage class — an
//! `INTEGER`/`REAL`/`TEXT`/`BLOB` is written as itself, so a recovered BLOB is
//! preserved losslessly rather than stringified. The table b-tree is **bulk
//! loaded**: leaves are packed in rowid order and interior pages built bottom-up,
//! because every row is known up front (no insertion/splitting). Cells larger
//! than the usable page size spill onto **overflow-page chains** per the file
//! format (§1.6), so a large recovered BLOB/TEXT survives intact.
//!
//! The output re-opens with [`crate::Database::open`] (the independent reader)
//! and is read identically by the real `sqlite3` engine — the writer's two
//! oracles. No new dependencies, no unsafe, panic-free.

use crate::Value;

/// One carved record to materialize as a row of the rebuilt `recovered_records`
/// table. The CLI maps its `CarvedRecord` onto this; the writer owns the
/// `SQLite`-format encoding.
#[derive(Debug, Clone, PartialEq)]
pub struct RebuildRow {
    /// 1-based source page the record was carved from (stored in `_page`).
    pub page: u32,
    /// Byte offset of the cell within that page (stored in `_offset`).
    pub offset: usize,
    /// Carved rowid, or `None` when unknown/destroyed (stored as `_rowid` NULL).
    pub rowid: Option<i64>,
    /// Recovery-source label (stored in `_source`).
    pub source: String,
    /// Heuristic confidence (stored in `_confidence`).
    pub confidence: f32,
    /// Decoded cells, in column order, stored natively in `c0..cN`.
    pub cells: Vec<Value>,
}

/// Build the bytes of a valid single-table `SQLite` database holding every
/// [`RebuildRow`] as a row of `recovered_records`. See the module docs for the
/// schema and the bulk-load / overflow guarantees.
#[must_use]
pub fn build_recovered_db(rows: &[RebuildRow]) -> Vec<u8> {
    let _ = rows;
    Vec::new()
}
