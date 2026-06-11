# Two-Tier Deleted-Record Recovery — Design Memo (task #72)

Status: DESIGN ONLY — no implementation. To be adversarially critiqued by Codex,
then implemented under strict TDD (separate RED and GREEN commits per step).

## Executive Summary

Add a second, strictly separated recovery tier to sqlite-forensic:

- **Tier 1 — full rows** (exists today): `carve_all_deleted_records`
  (`forensic/src/lib.rs:418`) reconstructs complete scored identities. This tier
  keeps its structural 0-false-positive guarantee and remains the recall metric
  and the zero-config CLI output. **Nothing about it changes.**
- **Tier 2 — fragments** (new, opt-in): when a freed cell's full row cannot be
  reconstructed but ≥1 *distinctive* cell (TEXT ≥ 4 bytes or REAL) decodes
  cleanly at a structural anchor, emit it as a `CarvedFragment` — a new type,
  returned by a new function, rendered in a separate CLI section behind
  `--fragments`. Fragments can never be mistaken for rows because the type
  system separates them (secure by design); the default path never produces
  them (secure by default).

**Recommendation on type design**: a separate `CarvedFragment` type + a separate
entry point — NOT a `kind` enum on `CarvedRecord`. A fragment has no rowid and an
incomplete `values` vector; folding it into `CarvedRecord` would force sentinel
values and let an unaware consumer render a fragment as a row — the exact
silent-wrong-output failure the 0-FP claim forbids. A separate type is also a
non-breaking minor bump: no external consumer of the carve API exists (grep over
`~/src/issen` and `~/src/browser-forensic` finds none), and the in-repo consumers
(`cli/src/lib.rs`, `forensic/tests/*`) are untouched on the Tier-1 path.

**Extraction point**: the abandonment sites inside freeblock reconstruction —
`FreeblockTemplate::reconstruct_one` (`core/src/lib.rs:2124`), which today
returns `None` (and `reconstruct_span` then `break`s at `core/src/lib.rs:2107`)
when a surviving serial is illegal, the tail overruns the span, or the body does
not fit. The fragment is the **maximal decodable column prefix** at that same
structural anchor — no new scanning, no sliding search, so Tier-2 inherits
Tier-1's anchor discipline.

**Measured ground truth** (prototype run, 2026-06-11, scripts inline in §5.1; the
implementer re-derives these in `gen_ground_truth.py`):

| category | deleted | full-row recoverable | legacy-proxy fragment-only | of which distinctive-TEXT | destroyed (no legacy hit) |
|---|---|---|---|---|---|
| 0C | 101 | 101 | 0 | 0 | 0 |
| 0D | 45 | 19 | 17 | **5** | 9 |
| 0E | 12 | 3 | 6 | ~4 | 3 |

**Key honesty finding (pre-empting Codex)**: the proposed reuse of the legacy
`any_distinctive_column_present` proxy (`tests/data/nemetz/gen_ground_truth.py:177`)
as the fragment denominator is **partly noise**. Of the 17 0D fragment-only rows,
**12 match only via 1–4-byte big-endian INTEGER patterns** (e.g. rowid 20005 =
`4E 25`, which appears coincidentally anywhere in a 4 KiB page). Only 5 rows have
a genuinely surviving distinctive TEXT cell (verified by locating the bytes:
e.g. 0D-01 `Anja` at page 2 offset 3975, inside a freeblock span). The fragment
denominator must therefore use the **distinctive-cell rule defined in §3.1
(TEXT ≥ 4 bytes, REAL; bare INTEGER excluded)** — the same rule the extractor
uses, so numerator and denominator measure one concept. The honest 0D story is:
**19 full + ~5 fragment-recoverable + ~21 undecidable-or-destroyed** (the 12
integer-only "survivors" are indistinguishable from coincidence, which is
precisely why they cannot anchor a denominator). The legacy-proxy split
(19/17/9) is reported in §5 as context, not as the metric.

---

## 0. Current state (verified citations)

Core (`core/src/lib.rs`):

- `CarvedCell { offset, byte_len, rowid, values, confidence }` — `core/src/lib.rs:87`.
- `carve_cells` `:411`, `carve_cells_inferred` `:442`, `carve_leaf_cells` `:474`.
- `carve_free_regions` `:516` — carves only the complement of live-cell extents
  (`free_regions_of_leaf` `:703`); in-page confidence factor 0.8
  (`IN_PAGE_CONFIDENCE_FACTOR`, `:192`).
- `reconstruct_freeblock_records` `:592` — template from a live cell
  (`freeblock_template` `:1927`, `FreeblockTemplate` `:1989`); chain pass calls
  `template.reconstruct_span(page_bytes, fb, fb_end, false, ..)` at `:647`;
  unallocated-gap pass anchors at `:674` (`for anchor_off in cptr_end..cca`) and
  span-walks followers at `:691`. Confidence 0.4
  (`FREEBLOCK_RECONSTRUCT_CONFIDENCE`, `:201`).
- **Abandonment sites** (where a freed cell is thrown away today — the Tier-2
  emission points):
  1. `reconstruct_one` `:2124` returns `None` when a surviving serial type is
     illegal (`serial_body_len(s)?`, `:2139`), the serial tail overruns the span
     (`:2142`), or the computed body does not fit (`record_end > span_end`,
     `:2157`) — even though the columns decoded *before* the failure are valid.
  2. `reconstruct_span` `:2089` then `break`s (`:2107`), abandoning the entire
     remainder of the coalesced span.
  3. `freeblock_template` returning `None` (`:607`) abandons the whole page —
     out of scope for this task (no template = no column indexes; see §6 open
     question Q3).

Forensic (`forensic/src/lib.rs`):

- `RecoverySource` `:282` (`#[non_exhaustive]`), `WalProvenance` `:326` area,
  `CarvedRecord { page, offset, rowid, values, confidence, allocated, source, wal }` `:339`.
- `carve_all_deleted_records` `:418`: freelist pass, in-page pass (`carve_free_regions`
  + `reconstruct_freeblock_records` per page), WAL-frame pass, then the
  value-aware live-row precision filter (`live_value_keys`, `:558`;
  `retain_mut`, `:563`) and `dedup_keep_best` `:674`. `carve_at_commit` `:616`.

CLI (`cli/`):

- Humble Object split: decisions in `cli/src/lib.rs`, shell in `cli/src/main.rs`.
- `OutputFormat` `cli/src/lib.rs:17`, `MinConfidence` `:32` (Low = 0.2,
  Medium = 0.4), `filter_by_confidence` `:106`, `carve_lead_cells` `:117`,
  `render_carve` `:261`, `render_carve_with_snapshot` `:340`,
  `carve_wal_snapshots` `:208`.
- `CarveArgs` `cli/src/main.rs:79` (`--format`, `--rowid-only`,
  `--min-confidence`, `--wal`, `--no-wal`); `run_carve` `:161`.

Metrics (`forensic/tests/`):

- `nemetz_metrics.rs`: `carved_key` `:65`, `Matrix { d_deleted, d_recoverable,
  tp, fp, fn_, live_reread }` `:80`, `matrix_for` `:130`, pinned constants
  `NEMETZ_0D_TP_FLOOR = 19` `:441`, `NEMETZ_0D_DRECOVERABLE = 19` `:451`,
  `NEMETZ_0E_DRECOVERABLE = 3` `:461`, `NEMETZ_FP_CEILING = 10` `:463`.
- `nemetz_support/mod.rs`: `normalize_row` `:25`, `DeletedRow` `:53` with private
  `substrate_recoverable` field `:55` + accessor `:64`, manifest JSON parser
  `parse_manifest` `:128` (reads `substrate_recoverable` at `:145`).

Ground truth (`tests/data/nemetz/gen_ground_truth.py`):

- `any_distinctive_column_present` `:177` — the legacy proxy (TEXT ≥ 4 chars as
  UTF-8, INTEGER as 1/2/3/4/6/8-byte big-endian, REAL as 8-byte IEEE-754,
  searched anywhere in the file).
- `_serial_body` `:217`, `contiguous_identity_present` `:251`,
  `substrate_recoverable` `:278` (the honest full-row rule, task #68).

---

## 1. Type design

### 1.1 Decision: separate types, separate entry point (option b)

Rejected: `kind: RecordKind` on `CarvedRecord`. Three concrete failure modes:

1. **Sentinel pollution.** A fragment has no rowid and incomplete `values`; the
   enum variant would carry the real data while the struct fields
   (`rowid: i64`, `values: Vec<Value>`, `forensic/src/lib.rs:343-347`) carry
   lies or duplicates. Every existing consumer that reads `rec.values`
   (e.g. `carved_key`, `forensic/tests/nemetz_metrics.rs:65`; `values_json_array`,
   `cli/src/lib.rs:165`) would silently render a partial row as a full one.
2. **Contract breakage.** The 0-FP precision claim is attached to the
   *function* `carve_all_deleted_records`. If its return type can contain
   fragments, the claim becomes "0 FP if you remember to filter by kind" —
   documentation-enforced safety, which the Secure-by-Design axiom forbids.
3. **Churn.** Adding a field/variant to `CarvedRecord` breaks every struct
   literal in `forensic/tests/` and `cli/` tests; a separate type breaks nothing.

### 1.2 New core type (`core/src/lib.rs`, next to `CarvedCell`)

```rust
/// A partial deleted record salvaged from a freed-cell reconstruction that
/// failed full-row validation: the maximal decodable column prefix at a
/// structural anchor. Lower confidence than any full-row class; never mixed
/// into full-row output.
#[derive(Debug, Clone, PartialEq)]
pub struct CellFragment {
    /// Byte offset of the failed cell's anchor within the scanned page slice.
    pub offset: usize,
    /// Bytes covered by the decoded prefix (anchor to last decoded body byte).
    pub byte_len: usize,
    /// `(column_index, value)` for each column that decoded cleanly, ascending
    /// by index. Column indexes come from the page's schema template, so they
    /// are meaningful against the table's column order.
    pub surviving: Vec<(usize, Value)>,
    /// Columns of the template's column count that did NOT decode.
    pub missing: usize,
    /// Always `FRAGMENT_CONFIDENCE` (0.2) for now; field kept so future
    /// grading does not change the type.
    pub confidence: f32,
}
```

New constant next to `FREEBLOCK_RECONSTRUCT_CONFIDENCE` (`core/src/lib.rs:201`):
`const FRAGMENT_CONFIDENCE: f32 = 0.2;` — exactly the `MinConfidence::Low`
threshold (`cli/src/lib.rs:49-56`), one notch below freeblock reconstruction's
0.4 (= Medium), keeping the one severity ladder (one concept, one name).

### 1.3 New forensic type (`forensic/src/lib.rs`, next to `CarvedRecord`)

```rust
/// A Tier-2 partial recovery. Deliberately NOT a `CarvedRecord`: it has no
/// rowid and an incomplete column set, and it does not share the full-row
/// 0-false-positive guarantee. Opt-in surface only.
#[derive(Debug, Clone, PartialEq)]
pub struct CarvedFragment {
    pub page: u32,
    pub offset: usize,
    pub surviving: Vec<(usize, Value)>,
    pub missing: usize,
    pub confidence: f32,
    pub source: RecoverySource,        // reuses the existing provenance enum
    pub wal: Option<WalProvenance>,    // None in v1 (no WAL fragment pass yet)
}
```

`RecoverySource` is reused unchanged (`FreeblockReconstructed` for chain-pass
fragments, `InPageFreeBlock` for gap-pass fragments) — it is already
`#[non_exhaustive]` (`forensic/src/lib.rs:281`), and provenance class is the
same concept for both tiers.

### 1.4 Entry points

```rust
// forensic/src/lib.rs
/// Tier-1 + Tier-2 in one pass. `full` is byte-identical to
/// `carve_all_deleted_records(db)`; `fragments` is the opt-in bucket.
pub struct CarveTiers {
    pub full: Vec<CarvedRecord>,
    pub fragments: Vec<CarvedFragment>,
}
pub fn carve_with_fragments(db: &Database) -> CarveTiers;
```

`carve_all_deleted_records` keeps its exact signature and output (asserted by a
RED test, §6). Internally it may become `carve_with_fragments(db).full` or stay
as-is — implementer's choice, provided the equality test passes.

```rust
// core/src/lib.rs
impl Database {
    /// Fragments abandoned by `reconstruct_freeblock_records` on this page.
    /// Mutually exclusive with full reconstructions BY CONSTRUCTION: a fragment
    /// is emitted only at an anchor where `reconstruct_one` failed.
    pub fn reconstruct_freeblock_fragments(&self, page_bytes: &[u8]) -> Vec<CellFragment>;
}
```

Panic-free discipline: all new code follows the workspace lints
(`unwrap_used`/`expect_used = deny`); every read goes through the existing
bounds-checked helpers (`be_u16`, `read_varint`, `decode_value`); no new
`unsafe`.

---

## 2. Extraction — where a fragment is produced

### 2.1 The general rule (no special cases)

A fragment is **the maximal decodable column prefix of a failed template
reconstruction at an existing structural anchor**. Anchors are exactly the
positions Tier 1 already trusts: freeblock-chain entries
(`core/src/lib.rs:647`), and gap-pass follower positions reached by the
span-walk (`:691`, including positions where the walk `break`s at `:2107`).
There is **no sliding byte scan and no strings-style hunt** — Tier 2 inherits
the precision architecture of `reconstruct_span`'s doc comment
(`core/src/lib.rs:2039-2088`): never slide, only stand where structure points.

Concretely, refactor `reconstruct_one` (`core/src/lib.rs:2124`) so its three
rejection sites salvage instead of discard:

1. **Illegal serial mid-tail** (`serial_body_len(s)?` at `:2139`): columns
   `0..j` (template leads + surviving serials decoded before position `j`) have
   legal serials. Decode their bodies; if the bodies fit in the span, those are
   the fragment's `surviving` set; `missing = column_count - j`.
2. **Tail overrun** (`:2142`) — same salvage of the serials read so far.
3. **Body does not fit** (`record_end > span_end` at `:2157`): walk the serial
   array forward accumulating body lengths; keep every column whose body ends
   ≤ `span_end`; `missing` = the rest. (This is the dominant 0D mechanism: a
   later same-rowid insert overwrote the record's tail; the head — id, name,
   surname — survives. Verified on 0D-01: `15 17 04 07 | 4E 24 'Anja' 'Frank…'`
   at page 2 offset 3975 inside a freeblock whose full-row reconstruction fails.)
4. `decode_synthetic_record` failure (`:2168` area): keep the values decoded
   before the failing column.

Suggested shape: `reconstruct_one` returns an enum (private to core):

```rust
enum Reconstruction {
    Full(CarvedCell, usize /* record_end */),
    Partial(CellFragment),   // only if the §3.1 distinctiveness gate passes
    Nothing,
}
```

`reconstruct_span` pushes `Full` into the cells vec and `Partial` into a
fragments vec; on `Partial`/`Nothing` it still `break`s the walk exactly as
today (`:2107`) — fragment salvage must NOT extend the walk, or Tier-1 phantom
discipline would be weakened. The public `reconstruct_freeblock_records`
returns cells only (unchanged); the new `reconstruct_freeblock_fragments`
returns fragments only. Both can share one internal walker; determinism makes
the two-call form safe, but a shared `(cells, fragments)` internal return is
preferred to avoid divergence.

### 2.2 Scope (YAGNI boundary)

In scope for v1: the **freeblock-chain pass and the unallocated-gap pass** of
`reconstruct_freeblock_records` — the measured fragment substrate lives there
(0D-01 `Anja` in a freeblock; 0E-01/0E-02 surviving TEXT in the gap; §0 table).

Out of scope, flagged for follow-up, not built now:
- Fragments from `carve_free_regions` candidates (forward-parse failures
  without a template — no column indexes available).
- WAL-frame fragments (`carve_all_deleted_records` step 3,
  `forensic/src/lib.rs:489-535`) and commit-snapshot fragments
  (`carve_at_commit`, `:616`). The architecture extends trivially (same core
  methods over frame/snapshot page images), but yield is unmeasured —
  measure first. *(Speculation: 0E gap survivors suggest snapshot fragments
  would add little on this corpus.)*
- Bytes inside live-cell extents are **permanently** out of scope, not deferred:
  scanning them would structurally break the never-resurface-a-live-row
  guarantee. At least one legacy 0D "survivor" (0D-05 `Leni`, page 2 offset
  4040) appears to sit inside a live cell's extent — unreachable by design;
  the denominator definition in §5 accounts for this.

### 2.3 Double-counting avoidance (three layers)

1. **By construction (core)**: a fragment is emitted only at an anchor where
   full reconstruction failed; an anchor yields a cell or a fragment, never both.
2. **Cross-pass value suppression (forensic)**: `carve_with_fragments` drops any
   fragment whose every `(column_index, value)` pair matches the corresponding
   column of a Tier-1 `CarvedRecord` already in `full` (the row was recovered
   another way — e.g. the same residue reachable via `carve_free_regions` on an
   overlapping span). This directly implements the requirement "fragment NOT
   emitted when the full row was already recovered".
3. **Live-row suppression (forensic)**: drop any fragment whose every
   `(column_index, value)` pair matches the corresponding columns of one live
   row (projection of `db.live_rows()` — the same source as `live_value_keys`,
   `forensic/src/lib.rs:558`). Rationale: a fragment that is column-consistent
   with a live row is "consistent with a stale copy of a live row", the
   fragment analog of the rebalance-copy drop (`:584-586`). A fragment matching
   a live row only *partially* on some cells is kept — equality of the full
   surviving set is the drop rule, mirroring the full-row rule's whole-values
   comparison.

Fragment dedup: key `(page, offset)` first (one fragment per anchor by
construction), then a value-level pass keyed on the normalized `surviving` set,
keeping the copy with more surviving columns — mirroring `dedup_keep_best`
(`forensic/src/lib.rs:674`).

---

## 3. Confidence and the precision contract

### 3.1 Distinctive cell (the emission gate) — precise definition

A decoded `(column_index, value)` is **distinctive** iff:

- **TEXT**: serial type odd and ≥ 13, body length ≥ 4 bytes, decoded by the
  shared `decode_value` as valid UTF-8 containing no U+FFFD (same bar the gap
  anchor already applies, `core/src/lib.rs:683-687`); or
- **REAL**: serial type 7 (8-byte IEEE-754 — a 2^-64 coincidence space).

**Not distinctive alone**: INTEGER serials 1–6, NULL/zero/one serials 0/8/9,
and BLOBs. Measured basis: 12 of 17 legacy 0D fragment-only rows "survive" only
as 1–4-byte integer patterns — pure pattern-collision noise (§Exec Summary).
A genuine domain citation for excluding short integers: a 2-byte big-endian
pattern has a 1/65536 per-offset collision rate, i.e. ~1 expected coincidental
hit per 16 pages of 4 KiB — useless as identity. Integer and other
non-distinctive cells **ride along** inside a fragment that contains ≥ 1
distinctive cell (so the examiner still sees `id=20004, name='Anja'`), but can
never justify emission by themselves.

A fragment is emitted iff its `surviving` set contains ≥ 1 distinctive cell.
This is the **same rule** `gen_ground_truth.py` will use for
`fragment_recoverable` (§5) — numerator and denominator share one definition.

### 3.2 Grading

- Every fragment: `confidence = FRAGMENT_CONFIDENCE = 0.2` (flat; no
  speculative per-fragment scoring knobs — YAGNI). 0.2 = `MinConfidence::Low`,
  strictly below every full-row class (freelist ~1.0·, in-page ×0.8, freeblock
  reconstruction 0.4).
- `audit_carved_findings` (`forensic/src/lib.rs:748`) is **not** extended to
  fragments in v1. If/when it is, fragments map to `Severity::Info` +
  `Confidence::Low` findings with a distinct code (e.g.
  `SQLITE-FRAGMENT-RESIDUE`) — never the full-row code. Out of scope here.

### 3.3 API contract (what the docs and rustdoc must say)

- The 0-FP claim remains attached to `carve_all_deleted_records` /
  `CarveTiers::full` only. `CarveTiers::fragments` is documented as a
  **lead-generation surface with an expected non-zero false-positive rate**:
  a lone surviving cell can be a coincidental byte run that satisfies the
  serial+UTF-8 checks. The measured fragment FP rate is published in
  `docs/recovery-comparison.md` (§5.3), not hand-waved.
- Fragments never carry a rowid (none survives clobbering); there is no field
  to misread as one.
- Wording discipline: a fragment is "consistent with a partial deleted row" —
  observation language, per the fleet reporting model.

---

## 4. CLI surfacing (`sqlite4n6 carve`)

- New flag on `CarveArgs` (`cli/src/main.rs:79`): `--fragments` (bool,
  `#[arg(long)]`). Default off ⇒ output byte-identical to today: the
  zero-config path stays the high-precision one (secure by default).
- New pure renderers in `cli/src/lib.rs` (Humble Object — `main.rs` only calls
  them): `render_fragments(&[CarvedFragment], OutputFormat) -> Vec<String>`.
  - **Table**: after the full-row table, a blank line, then a labelled section:
    `# fragments — partial rows, lower confidence (opt-in; not part of the
    full-row zero-false-positive output)` with columns
    `page  offset  conf  source  surviving` where `surviving` renders as
    `col3='Anja' col4='Frank…' (+5 columns destroyed)` using the existing
    `value_to_cell` (`cli/src/lib.rs:83`) per value.
  - **CSV**: full rows keep today's exact header and rows. With `--fragments`,
    fragments are emitted after them with their **own header row**
    (`kind,page,offset,confidence,source,missing,surviving`) prefixed by a
    comment-style separator is NOT possible in strict CSV — instead emit
    fragments to the same stream with a leading `kind` column **only on the
    fragment rows is wrong too** (ragged CSV). Decision: with `--fragments`,
    **both** sections gain a leading `kind` column (`row` / `fragment`); without
    the flag the header is unchanged. The flag is the explicit opt-in to the
    schema change, so no zero-config consumer breaks.
  - **JSONL**: fragment objects carry `"kind":"fragment"`,
    `"surviving":[{"column":3,"value":"Anja"},…]`, `"missing":N`,
    plus the shared `page/offset/confidence/source` keys. Full-row objects are
    unchanged (no `kind` key added — their schema is a published contract,
    `cli/src/lib.rs:163`). A consumer distinguishes by presence of `kind`.
    *(Codex may push to add `"kind":"row"` to full rows for symmetry — that
    changes the published JSONL contract; flag-gated if adopted.)*
- `--rowid-only` ignores fragments (they have no rowid); combining
  `--rowid-only --fragments` is a clap `conflicts_with` error — fail loud.
- `--min-confidence` applies to fragments too (all fragments are 0.2, so
  `medium` and above filters them all out — consistent semantics for free).
- WAL mode (`run_carve`'s `carve_wal_snapshots` branch, `cli/src/main.rs:169-183`):
  v1 emits fragments from the on-disk pass only (§2.2); the fragment section is
  still printed under `--fragments` with `--wal`/auto-WAL, sourced from the base
  image. Document this in the flag's help text.

---

## 5. Metrics, ground truth, and the comparison doc

### 5.1 `gen_ground_truth.py`

Per deleted row, emit **both** flags:

- `substrate_recoverable` (unchanged, task #68 honest contiguous full-row rule,
  `gen_ground_truth.py:278`).
- `fragment_recoverable` (new): true iff the row is NOT `substrate_recoverable`
  AND ≥ 1 distinctive cell's **whole serial body** (built by the existing
  `_serial_body`, `:217`) survives contiguously anywhere in the `.db` bytes,
  where distinctive = TEXT with UTF-8 body ≥ 4 bytes, or REAL — the §3.1 rule,
  INTEGER excluded. (The legacy `any_distinctive_column_present` `:177` stays
  for the 0A/0B dropped-table path it still serves, `:284`; it is NOT the
  fragment rule — see Exec Summary.)
- Regenerate `nemetz_ground_truth.json`; `nemetz_support/mod.rs` `DeletedRow`
  (`:53`) gains a `fragment_recoverable` field + accessor, parsed at
  `parse_manifest` (`:145`) alongside `substrate_recoverable`.

Expected values (prototype, to be confirmed by the generator): 0D ≈ 5,
0E ≈ 3–4, 0C = 0. Note the denominator counts survival *anywhere in the file*,
including inside live-cell extents the carver must never touch (§2.2), so
fragment recall < 1.0 is expected and honest — the doc says so explicitly.

### 5.2 Harness (`forensic/tests/nemetz_metrics.rs`)

New test fns alongside the existing matrix (full-row `Matrix` and all its
pinned constants unchanged):

- **Fragment yield**: per 0D/0E database, run `carve_with_fragments`; a deleted,
  non-full-row-recovered row counts as a fragment-TP when some fragment's every
  distinctive surviving cell equals that row's corresponding column (per-cell
  normalization mirroring `carved_key` `:65` — integers decimal, reals `{:.5}`,
  text verbatim). Pin `NEMETZ_0D_FRAGMENT_TP_FLOOR` /
  `NEMETZ_0E_FRAGMENT_TP_FLOOR` at the measured values (constants given real
  numbers at GREEN time, like `:441-463` today).
- **Fragment FP rate, separately measured**: a fragment whose distinctive cells
  match no deleted row's and no live row's corresponding columns is a
  fragment-phantom; one matching a live row is a fragment-live-reread. Pin
  `NEMETZ_FRAGMENT_FP_CEILING` (measured; expected small but non-zero — that is
  the honest, labelled cost of Tier 2).
- **Tier separation invariants**:
  - `carve_all_deleted_records(db) == carve_with_fragments(db).full` on every
    corpus DB (Tier 1 untouched — the load-bearing regression gate).
  - full-row `never_resurfaces_a_live_row` (`:243`) and `phantom_fp_ceiling`
    (`:415`) keep passing unchanged.
  - no fragment's surviving set equals the projection of any `full` record
    (suppression works, §2.3 layer 2).

### 5.3 `docs/recovery-comparison.md`

Add a "two-tier recovery" subsection presenting current state only (binding
writing rule — no previous-attempt narration): of 45 deleted 0D rows, 19 are
fully reconstructable (all recovered, precision 1.000); a further N yield a
labelled fragment (N = measured fragment-TP against the ≈5-row fragment
substrate); the remainder are destroyed or undecidable. State the fragment
bucket's measured FP rate next to the full-row 0-FP claim — never blended.
The legacy 17-row proxy figure may appear once, explicitly labelled as the
integer-pattern-inflated upper bound. Update the §H-style metric definitions
(`:208-224`) with the fragment-TP/FP definitions from §5.2. fqlite/undark have
no comparable fragment tier; the comparison table stays full-row-only
(apples-to-apples), with fragments reported in a separate ours-only table.

### 5.4 Corpus catalog

No new test data is downloaded or generated (the Nemetz corpus and manifest
already exist); the regenerated `nemetz_ground_truth.json` keeps its existing
catalog entry — update the generator-command note in
`tests/data/README.md`/`issen/docs/corpus-catalog.md` only if the regeneration
command line changes (it does not; same `python3 tests/data/nemetz/gen_ground_truth.py`).

---

## 6. TDD plan — ordered RED → GREEN steps

Each step = one RED commit (failing tests only) + one GREEN commit
(implementation), per the fleet's mandatory discipline. Run targeted tests
(`cargo test -p <crate> --test <file>` / `--lib`) sequentially, never parallel
heavy runs. Coverage gate: new lines covered or `// cov:unreachable`-annotated.

1. **core RED — fragment salvage unit tests** (`core/src/lib.rs` `#[cfg(test)]`
   or `core` integration test): synthetic 0x0D page builders (reuse the
   existing test builders in core's test module) for:
   a. truncated-tail freeblock (body overruns span) → exactly one
      `CellFragment` with the expected `(idx, value)` prefix incl. a TEXT cell,
      correct `missing`, `confidence == 0.2`; `reconstruct_freeblock_records`
      output on the same page unchanged;
   b. illegal-serial-mid-tail → fragment with columns decoded before the bad
      serial;
   c. fully reconstructable freeblock → `reconstruct_freeblock_fragments`
      returns empty (mutual exclusion);
   d. salvage yielding only INTEGER/NULL cells → no fragment (distinctiveness
      gate);
   e. fragment salvage does not extend the span walk (a span whose head fails
      still stops there — assert no fragment/cell is emitted beyond it… assert
      count, not position sliding).
   **core GREEN**: `Reconstruction` enum refactor of `reconstruct_one`,
   `reconstruct_freeblock_fragments`, `FRAGMENT_CONFIDENCE`.
2. **core RED — real artifact** (integration test,
   `include_bytes!("../../tests/data/nemetz/0D/0D-01.db")` per the repo-root
   fixtures rule): page 2 fragment pass yields a fragment whose surviving cells
   include `Text("Anja")` (answer-key row 20004), and the page's full-row
   reconstruction output is unchanged. **GREEN**: usually zero code (covered by
   step 1's GREEN); the commit proves it on real evidence — if it fails, the
   salvage logic, not the test, is wrong (Doer-Checker).
3. **forensic RED — tiered API**: `carve_with_fragments` exists;
   `tiers.full == carve_all_deleted_records(db)` on 0D-01 and a synthetic DB;
   `tiers.fragments` non-empty on 0D-01; suppression tests — (i) a fragment
   value-matching a `full` record is absent, (ii) synthetic page where the
   freed prefix equals a live row's columns → fragment dropped
   (live-projection rule). **GREEN**: `CarvedFragment`, `CarveTiers`,
   `carve_with_fragments` with §2.3 suppression layers.
4. **ground truth RED**: regenerate manifest with `fragment_recoverable`;
   RED = harness tests asserting (i) `DeletedRow::fragment_recoverable()`
   parses, (ii) pinned per-category fragment-substrate totals
   (`NEMETZ_0D_FRAGMENT_RECOVERABLE` ≈ 5 — exact value from the generator),
   (iii) `fragment_recoverable ⇒ !substrate_recoverable` (disjoint buckets).
   **GREEN**: `gen_ground_truth.py` change + regenerated JSON +
   `nemetz_support` field.
5. **metrics RED**: fragment yield + fragment-FP tests of §5.2 with measured
   pinned constants; tier-separation invariants. **GREEN**: constants set from
   the measured run (the carve code itself should already satisfy them).
6. **CLI RED**: renderer unit tests in `cli/src/lib.rs` tests — table section
   header + row shape, CSV `kind` column appears only with fragments requested,
   JSONL `"kind":"fragment"` schema, default (no `--fragments`) output
   byte-identical to current snapshots, `--rowid-only --fragments` conflict.
   **GREEN**: `render_fragments`, `CarveArgs.fragments`, `run_carve` wiring.
7. **docs**: recovery-comparison.md two-tier section + README capability note
   (docs commit; no RED applicable — but verify the numbers against the step-5
   harness output, not prose memory).

Dependency order is strict: 1→2→3 before 5; 4 independent after 3 (can run as
step 4 or in parallel branch, but commit sequentially); 6 after 3; 7 last.

---

## Open questions for Codex to attack

1. **Fragment denominator location-blindness.** `fragment_recoverable` counts a
   distinctive cell surviving *anywhere* in the file, including inside
   live-cell extents the carver must never scan (0D-05 `Leni` appears to sit
   inside extent (4030, 4062) of a live cell on page 2 — single prototype
   measurement, unverified against a second parser). Should the denominator be
   tightened to "survives within free space" (gen_ground_truth would need a
   freeblock/gap/free-region model — heavier Python, but a fairer recall
   ceiling), or is "anywhere" the right corpus-property definition with the
   shortfall documented?
2. **Live-projection suppression aggressiveness.** Dropping a fragment whose
   entire surviving set matches one live row's columns can destroy true
   evidence when a deleted row's surviving prefix coincides with a live row
   (e.g. duplicate names). The full-row rule survives this because it compares
   *whole* rows; fragments compare fewer cells, so collisions are likelier. Is
   the rebalance-copy analogy strong enough, or should suppression also require
   byte-extent evidence (offset inside a span the live row once occupied —
   which we cannot generally know)?
3. **Template dependency.** Fragments require `freeblock_template`
   (`core/src/lib.rs:607`) — a live cell on the same page. A page whose rows
   were ALL deleted (no template) yields no fragments even when distinctive
   text survives. Acceptable v1 boundary, or does Codex see a precision-safe
   template-free salvage (e.g. serials-only suffix decode) worth specifying now?
4. **JSONL schema symmetry.** Should full-row JSONL objects gain `"kind":"row"`
   (published-contract change, flag-gated?) or stay implicit (fragment-only
   `kind` key)? §4 currently proposes implicit.
5. **CSV under `--fragments`.** The leading `kind` column added to *both*
   sections only when the flag is set — is a single stream with a discriminator
   column better or worse for triage pipelines than two separate outputs
   (e.g. `--fragments-csv <path>`)? §4 proposes the single stream.
6. **Flat 0.2 confidence.** Should fragment confidence scale with surviving
   distinctive-byte mass (e.g. total TEXT bytes), or does any scaling invite
   false precision? §3.2 proposes flat.
7. **0E overflow interaction.** 0E fragment-only rows include long TEXT cells
   split across overflow pages; whole-cell-contiguous `fragment_recoverable`
   excludes them, and the extractor cannot reach them without overflow-chain
   walking (explicit future work per `NEMETZ_0E_DRECOVERABLE` comment,
   `nemetz_metrics.rs:452-458`). Confirm: out of scope here, no partial-cell
   (substring) fragments in v1?
