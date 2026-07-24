# 7. Temporal recovery — WAL after-images and rollback-journal before-images

Date: 2026-07-24
Status: Accepted

## Context

Deleted-row evidence lives in two SQLite sidecars that the live `sqlite3` path
either applies silently or ignores. A `-wal` holds committed *after*-images the
main file does not yet reflect; the default `DELETE`/`PERSIST` **rollback journal**
holds the *before*-image of the last transaction. A checkpoint folds the WAL into
the main file and discards the uncheckpointed residue, so the temporal evidence is
transient and must be captured live. There is no wall-clock timestamp in a SQLite
WAL — only a logical commit sequence.

## Decision

- **Model the `-wal` as a full per-commit timeline**, not a two-point
  before/after approximation (`core/src/lib.rs` `WalTimeline` / `wal_timeline`,
  `CommitSnapshot`; README "Time-travel"). Each materializable committed state is
  labelled with its salt-qualified LSN coordinate
  (`commit:(salt1,salt2,frame_index)`), and the timeline maps onto the canonical
  `forensicnomicon::history` cohort (`to_temporal_cohort`, ADR 0004). Per-rowid
  version history is reconstructed purely from bytes, with rowid *reuse*
  (delete-then-reinsert) detected as two entities (`core/src/row_history.rs`).
- **Parse the rollback journal as the temporal inverse** (`core/src/lib.rs`
  `RollbackJournal::parse`, `Database::rollback_prior`; `forensic/` `audit_journal`
  / `carve_rollback_journal`; `docs/design/journal-recovery.md`). A two-tier
  parser reads a valid hot/crash header or reconstructs a `PERSIST` zeroed header
  from the database's own page size; journal-header offsets are verified against
  SQLite's `pager.c` (README "The rollback journal"). Diffing the prior state
  against the live database recovers deletions (full deleted row) and
  modifications (pre-edit value).
- **Never write the evidence or its sidecars** — the WAL/journal are read-only
  overlays (`Database::open_with_wal`; ADR 0006).

## Consequences

- A row deleted late in a transaction history is still a live cell in an earlier
  commit's page image, so the snapshot coordinate tells the examiner the exact
  committed state a deleted row was last alive in.
- Validated end-to-end against NIST CFReDS SFT-03 PERSIST (NIST-authored ground
  truth): 100/100 documented deletions and 100/100 modifications recovered
  (README; commit `f0162cb` documents WITHOUT ROWID reading in the same temporal
  surface).
- Limits are stated plainly: only the *last* transaction survives in a rollback
  journal; `DELETE`-mode (file unlinked) and `TRUNCATE`-mode (file zeroed) leave
  no in-band residue (README "Out of scope").
