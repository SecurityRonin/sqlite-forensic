//! Chain-aware overflow recovery (task #73) validated on the real Nemetz `0E`
//! corpus. A deleted row whose payload spilled onto an overflow-page chain is
//! recovered as a Tier-1 full row **only** when every chain page survives as a
//! freelist leaf (content-preserving); a chain page reallocated as the freelist
//! trunk destroys the record, which must NOT surface as a Tier-1 row.
//!
//! Probed ground truth (verified against the raw bytes of `0E-01.db`):
//!   * rowid 20012 `Ella`: P=4110, prefix on page 12, chain ptr -> page 13
//!     (freelist LEAF) -> assembled payload byte-equals the expected record.
//!     Tier-1 full row, chain provenance [13].
//!   * rowid 20003 `Matteo`: P=4108, prefix on page 4, chain ptr -> page 5
//!     (freelist TRUNK, clobbered) -> NOT recoverable as a Tier-1 row.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use sqlite_core::{Database, Value};
use sqlite_forensic::{carve_all_deleted_records, carve_with_fragments, RecoverySource};

const NEMETZ_0E_01: &[u8] = include_bytes!("../../tests/data/nemetz/0E/0E-01.db");

/// The surviving chain (Ella, page-13 leaf) recovers as a full Tier-1 row with
/// its complete answer-key values and chain provenance `[13]`.
#[test]
fn recovers_surviving_overflow_chain_as_full_row() {
    let db = Database::open(NEMETZ_0E_01.to_vec()).unwrap();
    let carved = carve_all_deleted_records(&db);

    let ella = carved
        .iter()
        .find(|r| {
            matches!(r.values.first(), Some(Value::Integer(20012)))
                && matches!(r.values.get(1), Some(Value::Text(t)) if t == "Ella")
        })
        .expect("Ella (rowid 20012) must be recovered as a full Tier-1 row");

    // The `id` column (20012) is a stored value; the cell's implicit rowid is 12
    // (the table's `id` is not declared INTEGER PRIMARY KEY, so it is a real
    // column, not the rowid alias).
    assert_eq!(ella.rowid, 12);
    // code is the 4095-char TEXT reassembled across the local prefix + page 13.
    match ella.values.get(2) {
        Some(Value::Text(code)) => {
            assert_eq!(code.len(), 4095, "code must be fully reassembled");
            assert!(code.starts_with("KIxfqvOjIlMi"));
            assert!(code.ends_with("ggZhAWZ9GPDs"));
        }
        other => panic!("code column should be Text, got {other:?}"),
    }
    assert!(matches!(ella.values.get(3), Some(Value::Integer(38533))));

    // Overflow provenance names the chain pages the bytes came from.
    let prov = ella
        .overflow
        .as_ref()
        .expect("a chain-reassembled row carries OverflowProvenance");
    assert_eq!(prov.first_page, 13);
    assert_eq!(prov.chain, vec![13]);
}

/// Negative test (the corpus's own built-in FP probe): rowid 20003 `Matteo`'s
/// chain points at page 5, the freelist TRUNK whose head was clobbered. It must
/// NEVER appear as a Tier-1 full row — a carver that "recovers" it has a false
/// positive.
#[test]
fn rejects_trunk_clobbered_chain_from_tier1() {
    let db = Database::open(NEMETZ_0E_01.to_vec()).unwrap();
    let carved = carve_all_deleted_records(&db);

    // No Tier-1 record reconstructs Matteo's full row (id + name + the full code).
    let matteo_full = carved.iter().any(|r| {
        matches!(r.values.first(), Some(Value::Integer(20003)))
            && matches!(r.values.get(1), Some(Value::Text(t)) if t == "Matteo")
            && matches!(r.values.get(2), Some(Value::Text(c)) if c.len() == 4091)
    });
    assert!(
        !matteo_full,
        "trunk-clobbered Matteo chain must NOT be a Tier-1 full row (false positive)"
    );
}

/// 0-FP regression: every Tier-1 overflow recovery is tagged with a real anchor
/// recovery source (never a live row re-read), and the chain-reassembled row is
/// graded BELOW the in-page full-row tier (Codex ruling #1: overflow Tier-1 is a
/// graded recovery, not part of the structural 0-FP guarantee).
#[test]
fn overflow_tier1_confidence_is_graded_below_in_page() {
    let db = Database::open(NEMETZ_0E_01.to_vec()).unwrap();
    let carved = carve_all_deleted_records(&db);
    let ella = carved
        .iter()
        .find(|r| matches!(r.values.first(), Some(Value::Integer(20012))))
        .expect("Ella recovered");
    // Graded strictly below a clean in-page full-row carve (0.9 * in-page factor).
    assert!(
        ella.confidence < 0.72,
        "overflow Tier-1 confidence {} must be graded below the in-page full-row tier",
        ella.confidence
    );
    assert!(matches!(
        ella.source,
        RecoverySource::InPageFreeBlock | RecoverySource::FreelistPage
    ));
    assert!(!ella.allocated);
}

/// The full tier still equals `carve_all_deleted_records` under `carve_with_fragments`
/// and the surviving chain row appears there too.
#[test]
fn carve_with_fragments_full_tier_includes_surviving_chain() {
    let db = Database::open(NEMETZ_0E_01.to_vec()).unwrap();
    let tiers = carve_with_fragments(&db);
    let full = carve_all_deleted_records(&db);
    assert_eq!(tiers.full, full);
    assert!(tiers
        .full
        .iter()
        .any(|r| matches!(r.values.first(), Some(Value::Integer(20012)))));
}

/// Tier-2 broken-chain fragment (Codex ruling #4): Matteo's trunk-clobbered
/// chain cannot be a Tier-1 row, but its LOCAL prefix survives intact on page 4,
/// so the columns that decode locally — `id = 20003`, `name = "Matteo"` — are
/// salvaged as a Tier-2 fragment. The fragment carries ONLY the local-prefix
/// columns; the chain-resident `code`/`zip` are lost (untrusted by definition).
#[test]
fn matteo_broken_chain_surfaces_as_fragment() {
    let db = Database::open(NEMETZ_0E_01.to_vec()).unwrap();
    let tiers = carve_with_fragments(&db);

    let matteo = tiers
        .fragments
        .iter()
        .find(|f| {
            f.surviving
                .iter()
                .any(|(_, v)| matches!(v, Value::Text(t) if t == "Matteo"))
        })
        .expect("Matteo's broken chain must surface as a Tier-2 fragment");

    // id (column 0) and name (column 1) survive locally.
    assert!(matteo
        .surviving
        .iter()
        .any(|(i, v)| *i == 0 && matches!(v, Value::Integer(20003))));
    assert!(matteo
        .surviving
        .iter()
        .any(|(i, v)| *i == 1 && matches!(v, Value::Text(t) if t == "Matteo")));

    // The full chain-resident code (4091 chars) is NOT in the fragment.
    assert!(!matteo
        .surviving
        .iter()
        .any(|(_, v)| matches!(v, Value::Text(t) if t.len() == 4091)));

    // And Matteo is NOT in the full tier (it was rejected from Tier-1).
    assert!(!tiers.full.iter().any(|r| {
        matches!(r.values.first(), Some(Value::Integer(20003)))
            && matches!(r.values.get(2), Some(Value::Text(c)) if c.len() == 4091)
    }));
}
