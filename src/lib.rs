//! `sqlite-core` — native, read-only, panic-free SQLite file-format reader.
//!
//! WS-C feasibility spike (RED skeleton — not yet implemented).

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

/// Errors that can arise while reading a SQLite database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    TooShort,
    BadMagic,
    BadPageSize(u32),
    PageOutOfRange(u32),
    NotATablePage(u8),
    TruncatedCell,
    TooManyPages,
}

/// A single decoded column value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

/// One table row.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub rowid: i64,
    pub values: Vec<Value>,
}

/// Parsed 100-byte SQLite file header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub page_size: u32,
    pub reserved: u8,
}

/// A read-only view over a SQLite database file.
pub struct Database {
    _bytes: Vec<u8>,
}

impl Database {
    /// RED stub: not implemented.
    pub fn open(_bytes: Vec<u8>) -> Result<Self, Error> {
        Err(Error::TooShort)
    }

    #[must_use]
    pub fn header(&self) -> Header {
        Header { page_size: 0, reserved: 0 }
    }

    /// RED stub: not implemented.
    pub fn read_table(&self, _root_page: u32, _column_count: usize) -> Result<Vec<Row>, Error> {
        Ok(Vec::new())
    }
}
