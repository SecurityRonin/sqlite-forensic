//! Fuzz the deleted-record carver over a database opened from arbitrary bytes.
//!
//! Drives the free-space / freelist / dropped-table carving primitives on a
//! parser-accepted-but-hostile database: it must return records or an empty
//! vector, never panic, on any input `Database::open` admits.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(db) = sqlite_core::Database::open(data.to_vec()) {
        let _ = sqlite_forensic::carve_all_deleted_records(&db);
    }
});
