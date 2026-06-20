//! Known-answer rollback-journal recovery against NIST CFReDS SFT-03 PERSIST.
//!
//! NIST committed 100 deletions + 100 modifications into a 2240-row
//! `invoice_items` table under `journal_mode=PERSIST`, leaving the pre-images in
//! the `-journal` sidecar (header zeroed on commit, bodies intact). The recovery
//! is a prior-snapshot diff (design §4): deleted = prior \ current by rowid;
//! modified = both present, values differ (the journal carries the OLD value).
//!
//! The oracle is DERIVED, not transcribed: `invoice_items.InvoiceLineId` is the
//! INTEGER PRIMARY KEY (= rowid), originally contiguous `1..=2240`, so
//! `expected_deleted = {1..=2240} \ {live InvoiceLineId}` — computed from the db
//! itself. The 100 modified rows had their `Quantity` set to 200, so each prior
//! row's `Quantity` is `!= 200`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::pedantic)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use sqlite_core::{Database, Value};
use sqlite_forensic::{carve_rollback_journal, RecoverySource};

fn cfreds(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../tests/data/cfreds")
        .join(name)
}

/// The derived expected-deleted set: `{1..=2240} \ {live InvoiceLineId}`.
fn derived_deleted(db: &Database) -> BTreeSet<i64> {
    let live: BTreeSet<i64> = db
        .live_table_rows()
        .iter()
        .find(|d| d.name == "invoice_items")
        .map(|d| d.rows.iter().map(|r| r.rowid).collect())
        .unwrap_or_default();
    (1..=2240).filter(|id| !live.contains(id)).collect()
}

/// Column index of `Quantity` in `invoice_items`
/// (InvoiceLineId, InvoiceId, TrackId, UnitPrice, Quantity).
const QUANTITY_COL: usize = 4;

#[test]
fn recovers_nist_deletes_and_modifications() {
    for platform in ["ios", "android"] {
        let main = std::fs::read(cfreds(&format!("SFT-03_PERSIST_{platform}.sqlite"))).unwrap();
        let journal =
            std::fs::read(cfreds(&format!("SFT-03_PERSIST_{platform}.sqlite-journal"))).unwrap();
        let db = Database::open(main).expect("open main");

        let expected = derived_deleted(&db);
        assert_eq!(expected.len(), 100, "{platform}: oracle = 100 deletions");

        let recovery = carve_rollback_journal(&db, &journal);

        // --- Deletions: prior rows whose rowid is absent from the live db. ---
        let recovered_deleted: BTreeSet<i64> = recovery
            .deleted
            .iter()
            .filter(|r| r.table == "invoice_items")
            .map(|r| r.rowid)
            .collect();
        let hit = expected.intersection(&recovered_deleted).count();
        assert!(
            hit >= 99,
            "{platform}: recover the NIST deletions (got {hit}/100); \
             recovered set size {}",
            recovered_deleted.len()
        );
        assert_eq!(hit, 100, "{platform}: target is the full 100/100");

        // Provenance: every deleted row names the rollback journal as its source.
        for r in recovery
            .deleted
            .iter()
            .filter(|r| r.table == "invoice_items")
        {
            assert!(
                matches!(r.source, RecoverySource::RollbackJournal(_)),
                "{platform}: deleted row provenance is the rollback journal"
            );
        }

        // --- Modifications: 100 rows whose prior Quantity != 200. ---
        let mods: Vec<_> = recovery
            .modified
            .iter()
            .filter(|m| m.table == "invoice_items")
            .collect();
        let prior_q_not_200 = mods
            .iter()
            .filter(|m| !matches!(m.prior_values.get(QUANTITY_COL), Some(Value::Integer(200))))
            .count();
        assert_eq!(
            prior_q_not_200, 100,
            "{platform}: recover 100 modified rows whose PRIOR Quantity != 200"
        );

        // Counts mirror the recovered vectors (NIST SFT-03 source-file report).
        assert_eq!(recovery.counts.deleted, recovered_deleted.len());
        assert_eq!(recovery.counts.modified, mods.len());
    }
}

#[test]
fn wal_applied_database_yields_empty_recovery_not_panic() {
    // A db opened WAL-applied must not accept a rollback journal (exclusive
    // timelines) — carve_rollback_journal degrades to an empty recovery.
    let main = std::fs::read(cfreds("sft-03-WAL_ios.sqlite")).unwrap();
    let wal = std::fs::read(cfreds("sft-03-WAL_ios.sqlite-wal")).unwrap();
    let db = Database::open_with_wal(main, &wal).expect("open_with_wal");
    let journal = std::fs::read(cfreds("SFT-03_PERSIST_ios.sqlite-journal")).unwrap();

    let recovery = carve_rollback_journal(&db, &journal);
    assert!(
        recovery.deleted.is_empty(),
        "WAL-applied: no journal recovery"
    );
    assert!(recovery.modified.is_empty());
    assert_eq!(recovery.counts, Default::default());
}

#[test]
fn garbage_journal_yields_empty_recovery_not_panic() {
    // A garbage journal (no decodable records) recovers nothing, never panics.
    let main = std::fs::read(cfreds("SFT-03_PERSIST_ios.sqlite")).unwrap();
    let db = Database::open(main).expect("open main");
    let recovery = carve_rollback_journal(&db, &[0xABu8; 64]);
    assert!(recovery.deleted.is_empty());
    assert!(recovery.modified.is_empty());
}
