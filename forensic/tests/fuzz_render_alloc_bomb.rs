//! Regression for a fuzz-found allocation-bomb crash in the `render` campaign.
//!
//! The `render` fuzz target opens arbitrary bytes as a database and carves every
//! deleted record. A crafted table-leaf cell whose payload spills onto an
//! overflow chain can declare a multi-exabyte `payload_len` varint; the spill
//! branch of `decode_leaf_cell` reached `Vec::with_capacity(total)` with that
//! untrusted length and aborted the process with
//! "memory allocation of 5955248086788122959 bytes failed"
//! (`core/src/lib.rs`, `decode_leaf_cell`).
//!
//! The fix caps the pre-allocation against what the file can physically supply
//! (`local + per_page * page_bound`), rejecting an impossible claim with
//! `MalformedOverflow` before the allocation. This test replays the exact fuzz
//! crash input through the same `open → carve` path and asserts it returns
//! cleanly instead of aborting. Crash input: `fuzz/artifacts/render/`
//! `crash-ebdd2ca632cdce51e172def5dd1414e4da57383b`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use sqlite_core::Database;
use sqlite_forensic::carve_all_deleted_records;

const CRASH: &[u8] = include_bytes!("../../tests/data/fuzz_render_alloc_bomb.db");

#[test]
fn oversized_payload_len_does_not_alloc_bomb() {
    // Must not abort the process on the untrusted payload length; a malformed
    // spill cell is rejected and carving degrades to an empty/partial result.
    let db = Database::open(CRASH.to_vec()).expect("crash input parses as a database");
    let records = carve_all_deleted_records(&db);
    // The exact count is not the contract — surviving without aborting is.
    let _ = records.len();
}
