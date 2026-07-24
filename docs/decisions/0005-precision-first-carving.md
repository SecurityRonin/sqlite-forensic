# 5. Precision-first structural carving — carve the complement of live cells; full rows vs Tier-2 fragments

Date: 2026-07-24
Status: Accepted

## Context

A carver that *over*-reports is worse than useless on an evidence database — it
manufactures rows that were never deleted, and it re-surfaces live rows as
"deleted." Reference oracles exhibit exactly these failure modes: on a
no-deletion database some re-read live cells, and on a B-tree-rebalancing scenario
`bring2lite` re-surfaces 13 live rows as deleted (README "Trust but verify";
`docs/competitive-landscape.md`). For an evidence tool, precision must be
enforced structurally, not by inspection.

## Decision

1. **Carve only the complement of the live cell extents on a page**, then drop any
   carved record whose rowid is currently live (README "Trust but verify"; the
   reader exposes `live_rowids` / `carve_free_regions`). A recovered record is
   never a byte-copy of a live row.
2. **Return two structurally separate result sets, never merged** (README "Two
   recovery sets"): *Set 1* full rows (every cell intact, page/offset/rowid
   provenance, confidence-scored) and *Set 2* Tier-2 fragments (a single
   distinctive surviving cell — `TEXT ≥ 4` bytes or a `REAL` — that is *not* a
   row). The rebuilt database keeps them in separate tables
   (`recovered_records` vs `recovered_fragments`; `core/src/rebuild.rs`).
3. **Freeblock reconstruction accepts a coalesced run only when it tiles the freed
   slot exactly**, so a misaligned read is rejected rather than emitted as a
   column-shifted phantom (README "Two recovery sets").
4. **Overflow-chain reassembly is bounded** — a spilled row is rebuilt to a full
   row only when every chain page survives as a freelist leaf; otherwise it is
   refused from the full tier and surfaces only as a fragment.

## Consequences

- Measured against independent third-party ground truth (Nemetz *SQLite Forensic
  Corpus*, DFRWS-EU 2018, CC0; harness `forensic/tests/nemetz_metrics.rs`): the
  highest precision in the comparison, **0 live-row re-reads**, and on the
  B-tree-rebalancing scenario 0 false positives where `bring2lite` produces 13.
- Recall is deliberately traded for precision and reported honestly
  (`docs/recovery-comparison.md`, `docs/validation.md`); the `0E` overflow
  category is a bounded capability, graded below the in-page tier.
- Carved records stay confidence-graded *observations* ("consistent with a deleted
  row"), never verdicts — matching the fleet's observation-not-conclusion rule.
