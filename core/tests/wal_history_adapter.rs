//! `[H]` adapter — map the bespoke `WalTimeline` (#55) onto the canonical
//! `forensicnomicon::history` vocabulary (#43 / WS-F).
//!
//! Validated against the same real `wal_carve.db` + `-wal` fixture as the timeline
//! tests: ONE salt segment with TWO COMMIT frames → two materializable commit
//! snapshots → two temporal states. Each state carries a salt-qualified WAL LSN and
//! the canonical SQLite-WAL clock/safety profile single-sourced from forensicnomicon.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use forensicnomicon::history::epoch::{CohortTopology, LsnKind};
use forensicnomicon::history::identity::{ArtifactRef, IdentityClaim, IdentityDiscipline};
use forensicnomicon::history::profiles;
use sqlite_core::Database;

const CARVE_MAIN: &[u8] = include_bytes!("../../tests/data/wal_carve.db");
const CARVE_WAL: &[u8] = include_bytes!("../../tests/data/wal_carve.db-wal");

fn artifact() -> ArtifactRef {
    ArtifactRef {
        claims: vec![IdentityClaim::CanonicalPath {
            volume: "C:".into(),
            path: std::path::PathBuf::from("Users/anja/wal_carve.db"),
        }],
    }
}

#[test]
fn cohort_has_one_state_per_commit_snapshot() {
    let db = Database::open_with_wal(CARVE_MAIN.to_vec(), CARVE_WAL).expect("open with wal");
    let tl = db.wal_timeline().expect("timeline present");
    let cohort = tl.to_temporal_cohort(artifact());

    // Two materializable commits → two temporal states.
    assert_eq!(cohort.states.len(), tl.commit_snapshots().len());
    assert_eq!(cohort.states.len(), 2);
    // The artifact identity is carried verbatim; a WAL is intrinsically path-scoped.
    assert_eq!(cohort.artifact, artifact());
    assert_eq!(cohort.discipline, IdentityDiscipline::PathStable);
    // Each state is a committed transaction, and the salt in the LSN marks any reset, so
    // the topology is uniformly commit-boundary — no special-case Disconnected branch.
    assert!(matches!(cohort.topology, CohortTopology::SubJournalCommits));
}

#[test]
fn states_carry_salt_qualified_lsn_and_canonical_wal_profile() {
    let db = Database::open_with_wal(CARVE_MAIN.to_vec(), CARVE_WAL).expect("open with wal");
    let tl = db.wal_timeline().expect("timeline present");
    let seg = tl.segments()[0].clone();
    let cohort = tl.to_temporal_cohort(artifact());

    for (i, state) in cohort.states.iter().enumerate() {
        // Ordering key is salt-qualified: frame_seq = the COMMIT frame index, commit_seq =
        // the 0-based ordinal of this commit within its salt segment.
        match state.ordering_key {
            Some(LsnKind::SqliteWalFrame {
                salt1,
                salt2,
                frame_seq,
                commit_seq,
            }) => {
                assert_eq!(salt1, seg.salt1);
                assert_eq!(salt2, seg.salt2);
                assert_eq!(
                    frame_seq as usize,
                    tl.commit_snapshots()[i].id().commit_frame_index
                );
                assert_eq!(commit_seq as usize, i);
            }
            ref other => panic!("expected SqliteWalFrame LSN, got {other:?}"),
        }
        // A WAL frame has no wall clock.
        assert!(state.wall_time.is_none());
        // Canonical WAL profile, single-sourced from forensicnomicon (no local re-assertion).
        assert_eq!(state.clock, profiles::sqlite_wal_clock());
        assert!(state.clock.ordering_only);
        assert_eq!(state.safety, profiles::SQLITE_WAL_SAFETY);
        // The handle locates the materializable snapshot.
        assert_eq!(state.handle, tl.commit_snapshots()[i].id());
    }

    // Distinct epochs per state (the (salt, frame, db_size) triple is unique).
    assert_ne!(cohort.states[0].epoch, cohort.states[1].epoch);
}
