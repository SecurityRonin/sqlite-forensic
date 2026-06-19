//! Fuzz the anomaly auditor over a database opened from arbitrary bytes.
//!
//! Grades header- and structure-level anomalies on a parser-accepted-but-hostile
//! database: it must return findings or an empty vector, never panic, on any
//! input `Database::open` admits.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(db) = sqlite_core::Database::open(data.to_vec()) {
        let _ = sqlite_forensic::audit(&db);
    }
});
