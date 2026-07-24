# 4. Depend down on the `forensicnomicon` KNOWLEDGE leaf

Date: 2026-07-24
Status: Accepted

## Context

Two facts about the SQLite format need one home: the byte-level constants (magic,
page-size offset, the page-1 header field offsets for reserved-space, in-header
DB size, freelist count, text encoding) and the normalized reporting vocabulary
every fleet analyzer emits. The fleet architecture (`~/src/ronin-issen/CLAUDE.md`,
"The Reporting Model" and the layer hierarchy) puts both in the zero-dependency
`forensicnomicon` KNOWLEDGE leaf: analyzers depend *down* onto it, and it depends
on no one. Re-hardcoding header offsets in each crate is the duplication this
policy exists to prevent.

## Decision

Both library crates depend on `forensicnomicon` (`Cargo.toml`
`[workspace.dependencies] forensicnomicon = "1"`). Concretely:

- **Constants flow down.** `sqlite-core` consumes the page-1 header offsets from
  `forensicnomicon::sqlite` (`core/src/lib.rs`: `SQLITE_MAGIC`,
  `SQLITE_PAGE_SIZE_OFFSET`, `SQLITE_RESERVED_SPACE_OFFSET`,
  `SQLITE_DB_SIZE_OFFSET`, `SQLITE_FREELIST_COUNT_OFFSET`,
  `SQLITE_TEXT_ENCODING_OFFSET`), aliased to the historical local names so use
  sites are unchanged. These offsets were previously local and were promoted into
  the leaf in the §3.1 refactor (commit `98f430d`). The carver reads the same
  constants (`forensic/src/carve.rs`).
- **Findings flow up.** `sqlite-forensic` grades every observation into
  `forensicnomicon::report::Finding` via `impl Observation` / builders
  (`forensic/src/lib.rs` imports `Confidence, Evidence, Finding, Location,
  Observation, Severity, Source`), so a SQLite database's anomalies aggregate
  uniformly with the partition / container / filesystem layers in a triage report.
- The WAL temporal model maps onto the canonical `forensicnomicon::history` cohort
  vocabulary (`core/src/lib.rs` `WalTimeline::to_temporal_cohort`), single-sourcing
  the clock/safety profile from `forensicnomicon::history::profiles`.

## Consequences

- One place owns SQLite format facts; a spec correction is a `forensicnomicon`
  bump, not a fleet-wide edit.
- `AnomalyKind` is `#[non_exhaustive]` (`forensic/src/lib.rs`), so new anomaly
  codes are additive; downstream `match` arms must carry a `_` arm.
- The crate stays a leaf-consumer: it never re-asserts the four `ClockProvenance`
  classifications locally, so the fleet cannot drift on WAL temporal semantics.
