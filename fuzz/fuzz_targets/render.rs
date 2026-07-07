//! Fuzz the CLI output writers over records carved from arbitrary bytes.
//!
//! The parse and carve stages are already fuzzed (`database_open`, `carve`); this
//! target drives the EMIT stage — the table / CSV / JSONL writers must never panic
//! on adversarial carved values (huge blobs, NUL, control characters, invalid
//! UTF-16 surrogates) that a hostile database can produce.
#![no_main]
use libfuzzer_sys::fuzz_target;
use sqlite4n6::OutputFormat;

fuzz_target!(|data: &[u8]| {
    if let Ok(db) = sqlite_core::Database::open(data.to_vec()) {
        let records = sqlite_forensic::carve_all_deleted_records(&db);
        for format in [OutputFormat::Table, OutputFormat::Csv, OutputFormat::Jsonl] {
            let _ = sqlite4n6::render_carve(&records, &[], format, false);
        }
        // The rowid-only projection across every format.
        let _ = sqlite4n6::render_carve(&records, &[], OutputFormat::Table, true);
    }
});
