//! Fuzz the core parser entry point on arbitrary bytes.
//!
//! `Database::open` is the most important hostile-input surface: every other
//! analysis path starts here. On crafted / corrupted / truncated input it must
//! return `Ok` or a typed `Err` — never panic, abort, or over-allocate.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = sqlite_core::Database::open(data.to_vec());
});
