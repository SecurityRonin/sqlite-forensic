//! Tier-2 partial-recovery API: `carve_with_fragments` returns disjoint
//! `full` (byte-identical to `carve_all_deleted_records`) and `fragments`
//! buckets. The fragment bucket is the opt-in, lower-precision lead surface;
//! the full bucket keeps its structural 0-false-positive guarantee.
//!
//! Validated against the real Nemetz 0D corpus (the genuine fragment substrate)
//! plus the wider corpus for the tier-separation invariants. Doer-Checker:
//! these assert real surviving evidence (0D-01 id 20004 "Anja"/"Frank"), never
//! a synthetic fixture we authored both sides of.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use sqlite_core::{Database, Value};
use sqlite_forensic::{carve_all_deleted_records, carve_with_fragments};

const NEMETZ_0D_01: &[u8] = include_bytes!("../../tests/data/nemetz/0D/0D-01.db");
const NEMETZ_0C_01: &[u8] = include_bytes!("../../tests/data/nemetz/0C/0C-01.db");
const DELETED: &[u8] = include_bytes!("../../tests/data/deleted_places.db");

/// `CarveTiers::full` is byte-identical to `carve_all_deleted_records` — the
/// load-bearing Tier-1 regression gate. Adding Tier-2 must not perturb Tier-1.
#[test]
fn full_tier_is_byte_identical_to_carve_all() {
    for bytes in [NEMETZ_0D_01, NEMETZ_0C_01, DELETED] {
        let db = Database::open(bytes.to_vec()).unwrap();
        let tiers = carve_with_fragments(&db);
        assert_eq!(
            tiers.full,
            carve_all_deleted_records(&db),
            "full tier must equal carve_all_deleted_records"
        );
    }
}

/// 0D-01 yields at least one genuine fragment — the id-20004 partial row whose
/// distinctive TEXT cells ("Anja"/"Frank") survive but whose full identity is
/// destroyed (so it is NOT in the full tier).
#[test]
fn fragments_recovered_on_0d01() {
    let db = Database::open(NEMETZ_0D_01.to_vec()).unwrap();
    let tiers = carve_with_fragments(&db);
    let anja = tiers.fragments.iter().find(|f| {
        f.surviving
            .iter()
            .any(|(_, v)| matches!(v, Value::Text(t) if t == "Anja"))
    });
    let f = anja.expect("0D-01 must yield the Anja fragment");
    assert!(f
        .surviving
        .iter()
        .any(|(_, v)| matches!(v, Value::Text(t) if t == "Frank")));
    assert!((f.confidence - 0.2).abs() < f32::EPSILON);
    assert_eq!(f.page, 2);
    // The same row is NOT in the full tier (its full identity is destroyed).
    assert!(tiers.full.iter().all(|r| !r
        .values
        .iter()
        .any(|v| matches!(v, Value::Text(t) if t == "Anja"))));
}

/// Suppression layer 2: no fragment's surviving set is a projection of any
/// `full` record (a row recovered in full is never also emitted as a fragment).
#[test]
fn no_fragment_duplicates_a_full_record() {
    for bytes in [NEMETZ_0D_01, NEMETZ_0C_01, DELETED] {
        let db = Database::open(bytes.to_vec()).unwrap();
        let tiers = carve_with_fragments(&db);
        for frag in &tiers.fragments {
            let dup = tiers.full.iter().any(|rec| {
                frag.surviving
                    .iter()
                    .all(|(idx, v)| rec.values.get(*idx) == Some(v))
            });
            assert!(!dup, "fragment {:?} duplicates a full record", frag.surviving);
        }
    }
}

/// Suppression layer 3: no fragment's surviving set matches the corresponding
/// columns of a currently-live row (never re-surface a live row, even partially
/// — the structural 0-false-positive guarantee extends to fragments).
#[test]
fn no_fragment_matches_a_live_row() {
    for bytes in [NEMETZ_0D_01, NEMETZ_0C_01, DELETED] {
        let db = Database::open(bytes.to_vec()).unwrap();
        let live = db.live_rows();
        let tiers = carve_with_fragments(&db);
        for frag in &tiers.fragments {
            let matches_live = live.values().any(|lv| {
                frag.surviving
                    .iter()
                    .all(|(idx, v)| lv.get(*idx) == Some(v))
            });
            assert!(
                !matches_live,
                "fragment {:?} matches a live row",
                frag.surviving
            );
        }
    }
}

/// A corpus DB with no genuine fragment substrate yields an empty fragment
/// bucket while still producing its full-tier rows (0C is fully reconstructable).
#[test]
fn no_fragments_when_substrate_absent() {
    let db = Database::open(NEMETZ_0C_01.to_vec()).unwrap();
    let tiers = carve_with_fragments(&db);
    assert!(
        tiers.fragments.is_empty(),
        "0C-01 is fully reconstructable — no fragments expected"
    );
    assert!(!tiers.full.is_empty(), "0C-01 still recovers full rows");
}
