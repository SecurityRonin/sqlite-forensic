# Chain-Aware Overflow Recovery — Design Memo (task #73)

Status: DESIGN ONLY — no implementation. To be adversarially critiqued by Codex,
then implemented under strict TDD (separate RED and GREEN commits per step).

## Executive Summary

Recover deleted records whose payload spilled onto SQLite **overflow page
chains** — the records the honest substrate denominator (#68) conservatively
excludes today because a flat-file contiguity test cannot model a
non-contiguous body.

The mechanism, in one sentence: when a freed cell's declared payload exceeds
the in-page limit (`X = usable − 35`), compute the spec-defined local-payload
split, read the 4-byte big-endian first-overflow-page pointer that follows the
local prefix, walk the chain **only through pages that are freelist *leaves***
(freed, content-preserved), assemble local-prefix + chain content, and decode
exactly as the live path does. An intact, fully-decoding chain is a **Tier-1
full row**; a broken chain degrades to a **Tier-2 fragment** built from the
columns that survive in the local prefix (the #72 two-tier API absorbs both
outcomes with no new surface).

**Honest expected numbers — the task brief's "~9 of 12" is wrong.** Verified
against the real Nemetz `0E` databases (probe results in §1.3): only **2** of
the 12 deleted `0E` rows genuinely overflow (payloads 4108 and 4110 bytes vs
threshold 4061); the other 7 currently-not-recoverable rows are
large-but-in-page bodies that were genuinely overwritten. Of the 2 overflow
chains, **one survives byte-perfect** (chain page 13 became a freelist leaf —
content preserved) and **one is destroyed** (chain page 5 was converted into
the freelist *trunk*, whose `next`/`count`/leaf-array header overwrote the
first 24 content bytes). Therefore:

- `0E` substrate `Drec` rises **3 → 4** (not ~9), TP **3 → 4**, substrate
  recall stays **1.000**, end-to-end recall **0.250 → 0.333**, precision stays
  **1.000** (the broken chain is structurally rejected from Tier-1 and
  surfaces as a Tier-2 fragment instead).
- The destroyed-chain record (`0E-01` rowid 3) is the corpus's own built-in
  negative test: a chain-aware carver that "recovers" it as a full row has a
  false positive.

Top risks (each addressed in §4): following a stale pointer into live or
reused pages (mitigated structurally — chain pages must be freelist leaves);
`decode_value`'s lossy UTF-8 (`core/src/lib.rs:2510`) masking overwritten
chain bytes (mitigated by a strict-UTF-8 gate on chain-resident TEXT); and
allocation bombs from attacker-controlled payload-length varints (mitigated by
a freelist-capacity cap).

---

## 1. Verified baseline (what exists today, with citations)

### 1.1 The reader already handles overflow for LIVE cells

- `Database::decode_leaf_cell` (`core/src/lib.rs:993-1028`): reads
  `payload_len` + `rowid` varints, computes
  `local = local_payload_len(total, usable)` (line 1005); when `local < total`
  it takes `local` payload bytes from the leaf, reads the 4-byte BE
  first-overflow-page number at `payload_start + local` (line 1019), and calls
  `read_overflow_chain` (line 1022).
- `Database::read_overflow_chain` (`core/src/lib.rs:1036-1069`): per page,
  bytes 0..4 BE = next page (0 ends the chain), bytes `4..4+min(remaining,
  usable−4)` = content; guarded by page-range checks (line 1053) and a
  visited-count cap (`cap = total_pages + 1`, lines 1048, 1057), erroring with
  `Error::MalformedOverflow` (`core/src/lib.rs:62`).
- `local_payload_len` (`core/src/lib.rs:1075-1087`) implements the table-leaf
  spill formula from the SQLite file format, §"B-tree Pages" (payload overflow
  rules, <https://www.sqlite.org/fileformat2.html#b_tree_pages>):
  `X = U − 35` (line 1076), `M = ((U − 12) * 32 / 255) − 23` (line 1080),
  `K = M + ((P − M) % (U − 4))` (line 1081); if `P ≤ X` all local, else `K` if
  `K ≤ X`, else `M`. This is the **general domain rule** for any payload
  exceeding `X` — not a per-fixture branch (spec section: "Cell payload
  overflow pages" describes the chain page layout).
- Page geometry: `page_size` from header offset 16, reserved byte at offset 20
  (`RESERVED_SPACE_OFFSET`, `core/src/lib.rs:25`),
  `usable = page_size − reserved` via `Header::usable_size`
  (`core/src/lib.rs:141-144`). Same logic in the ground-truth generator's
  `page_geometry` (`tests/data/nemetz/gen_ground_truth.py:85-97`).
- `live_cell_len` (`core/src/lib.rs:1851-1862`) already knows the on-page
  footprint of a spilled **live** cell is `n1 + n2 + local + 4` (line 1859) —
  so `free_regions_of_leaf` (`core/src/lib.rs:664-684`) correctly excludes
  live spilled cells from the carve regions.

### 1.2 The carve paths are all overflow-blind

- `try_carve_cell_at` (`core/src/lib.rs:2339-2398`) requires the **whole**
  payload in-bounds: `buf.get(payload_start..payload_start + payload_len)`
  (line 2357). A freed spilled cell (payload 4110, gap region < 1400 bytes)
  always fails → invisible to `carve_cells` (line 447),
  `carve_cells_inferred` (line 478), `carve_free_regions` (line 552), and the
  freelist-page pass of `carve_all_deleted_records`
  (`forensic/src/lib.rs:474-497`).
- `FreeblockTemplate::reconstruct_one` (`core/src/lib.rs:2257-2314`) computes
  `body_len` from the full serial array and rejects when
  `record_end > span_end` (line 2290) — a spilled freed cell's body always
  overruns the freeblock/gap span, so the template path fails too, falling to
  `salvage_fragment` (`core/src/lib.rs:2180-2249`).
- The two-tier API from #72: `carve_all_deleted_records`
  (`forensic/src/lib.rs:465`), `carve_with_fragments` returning `CarveTiers`
  (`forensic/src/lib.rs:401-406`), `CarvedFragment`
  (`forensic/src/lib.rs:374-393`), shared single walk
  `reconstruct_freeblock_inner` (`core/src/lib.rs:1908-1970`).

### 1.3 Empirical probe of the real 0E corpus (run 2026-06-11, this design pass)

Probe: re-encoded every deleted row from `nemetz_ground_truth.json` to its
exact record payload (same encoders as `gen_ground_truth.py:112-175`),
classified against `X = usable − 35 = 4061` (both DBs: page_size 4096,
reserved 0), located local prefixes in the raw files, and walked the chains.

| record | payload P | class | local prefix | chain | outcome |
|---|---|---|---|---|---|
| 0E-01 rowid 3 (`del[0]`) | 4108 | overflow | intact cell at page 4 off 1055, **in the unallocated gap** (page type 0x0D, 1 live cell, cca=1551, no freeblocks); prefix varints intact: `n1=2, n2=1` | ptr→page **5** = freelist **trunk** (count=5 → first 28 page bytes overwritten; first 24 of 3619 expected tail bytes destroyed, 3595 survive) | broken — Tier-2 fragment only |
| 0E-01 rowid 12 (`del[5]`) | 4110 | overflow | intact cell at page 12 off 632, in the unallocated gap (cca=1372) | ptr→page **13** = freelist **leaf** — assembled bytes **match the expected payload exactly** | intact — Tier-1 full row |
| 0E-01 other 5 deleted | 1371–3750 | in-page | — | — | 3 substrate-recoverable today (`del[1,3,6]`), 2 destroyed |
| 0E-02 all 5 deleted | 3677–4007 | in-page | — | — | all bodies overwritten (substrate False) |

Verified context: `0E-01` freelist = {5, 10, 11, 13, 14, 19} with trunk 5;
no **live** row in either DB overflows (so there are no live chains to
protect in this corpus — the protection still must exist, see §4.1). Table:
`(id INTEGER, name TEXT, code TEXT, zip INTEGER)`; for rowid 3 the local
prefix fully contains `id = 20003` and `name = 'Matteo'` (TEXT ≥ 4 →
distinctive per `is_distinctive`, `core/src/lib.rs:1819`), so the broken-chain
fragment passes the Tier-2 emission gate.

Both real overflow cells have **intact prefixes in the unallocated gap** (the
page was rebuilt; old cell bytes remain below `cellContentArea`). Neither is
freeblock-clobbered. This drives the implementation order in §7: the
intact-prefix path is validated on real data; the clobbered-prefix path needs
a synthetic fixture.

### 1.4 Current published numbers

`docs/recovery-comparison.md:104`: `0E ours: Ddel 12, Drec 3, TP 3, FP 0,
recall(substrate) 1.000, recall(e2e) 0.250, precision 1.000`; the overflow
weakness is documented at lines 33-37 and 87. The CSV behind the PNG is
emitted by `forensic/tests/nemetz_tool_comparison.rs`
(`emit_three_tool_comparison`, per `docs/plot_comparison.py:1-13`) and
rendered by `docs/plot_comparison.py`.

---

## 2. Design question 1 — identifying a freed overflow-bearing cell

Two anchor classes, one shared rule. The rule (and the only rule): a candidate
whose **declared payload exceeds `usable − 35`** is spilled by the format's own
definition; its local share is `local_payload_len(P, usable)` and the 4-byte BE
first-overflow-page number sits at `payload_start + local`. No fixture-specific
constant anywhere — `P`, `local`, and the pointer offset are all derived from
the candidate's own bytes plus the DB header geometry.

### 2.1 Intact-prefix anchors (gap, freeblock slack, freelist pages) — covers both real 0E cases

Extend the candidate recognizer rather than special-casing a caller. Today
`try_carve_cell_at` returns `None` for spilled cells at line 2357. Add a
sibling recognizer (free function, like `try_carve_cell_at`):

```text
try_carve_spilled_cell_at(buf, off, usable, expected_columns)
    -> Option<SpilledCell>

SpilledCell {
    offset, prefix_len,          // n1 + n2
    payload_len: usize,          // P, declared
    rowid: i64,
    serials: Vec<i64>,           // full serial array, decoded from the LOCAL header
    local_len: usize,            // local_payload_len(P, usable)
    local_payload_off: usize,    // offset of payload start within buf
    first_overflow: u32,         // BE u32 at payload_start + local_len
}
```

Acceptance checks (all derived, mirroring `try_carve_cell_at`'s discipline at
`core/src/lib.rs:2344-2394`):

1. `payload_len > usable − 35` (otherwise this recognizer abstains — the
   existing in-page path owns it; the two recognizers partition the space by
   the spec threshold, no overlap).
2. `rowid > 0` (same coincidence suppression as line 2353).
3. The **record header must fit entirely in the local prefix**:
   `header_len ≤ local_len`. (For table-leaf pages `min_local M ≥ 489` at
   usable 4096; a header longer than `local` is possible only for
   pathologically wide tables — abstain rather than guess. This is a guard,
   not a special case: the serial array is simply not addressable locally.)
4. Header self-consistency: `header_len` consumes cleanly into serials,
   `serials.len()` matches `expected_columns` (or `≥ MIN_INFERRED_COLUMNS`,
   `core/src/lib.rs:215`, when inferring), and
   `header_len + Σ serial_body_len == payload_len` — the same strong
   length-closure check as line 2392, now closing over the *declared* P rather
   than in-bounds bytes.
5. `local` payload bytes plus the 4-byte pointer are in-bounds of the scanned
   slice: `buf.get(payload_start .. payload_start + local_len + 4)`.

Why a separate function + type instead of widening `CarvedCell`
(`core/src/lib.rs:87-100`): recognition is per-slice and pure, but resolution
needs whole-database access (the chain pages). A `SpilledCell` that hasn't been
resolved must be **structurally unable** to masquerade as a recovered row
(secure by design — same argument as `CarvedFragment` in the #72 memo).

Caller integration: each carve walker (`carve_cells`/`carve_cells_inferred`
loops at `core/src/lib.rs:452-461` and 480-488, and the gap-anchor scan at
`core/src/lib.rs:1950-1967`) tries `try_carve_cell_at` first; on `None`, tries
the spilled recognizer; spilled candidates are collected and returned alongside
(e.g. `carve_free_regions` gains a sibling `carve_free_regions_spilled`, or the
walkers return `(Vec<CarvedCell>, Vec<SpilledCell>)` internally — exact shape
is an implementation detail for the TDD steps; the offset translation at
`core/src/lib.rs:589` applies identically). The recognizer needs `usable`,
which `try_carve_cell_at` today does not take — threading it is the one
signature ripple (all callers are in-crate).

### 2.2 Freeblock-clobbered anchors (template path) — no corpus instance; synthetic fixture

When the freed cell was converted to a freeblock (#56/#68), the first 4 bytes
— `payload_len` varint, `rowid` varint, and possibly the leading record-header
byte(s) — are destroyed (`core/src/lib.rs:2028-2033`). The declared `P` is
gone, but it is **re-derivable from the surviving structure**, which is the
general solution (no guessing):

- The template (`freeblock_template`, `core/src/lib.rs:1972-2022`) supplies
  `prefix_len`, the clobbered leading serials, and `surviving_serials_off`.
- `reconstruct_one` (line 2257) already reads the surviving serial tail and
  computes `body_len = Σ serial_body_len` (lines 2282-2285). The header length
  is structurally known too: `header_len = (tail_end − cell_start) −
  prefix_len` (the bytes from payload start to the end of the serial array).
- Therefore `P = header_len + body_len`. Today, when
  `record_end > span_end` the candidate is rejected (line 2290). The
  generalization: **before** rejecting, test `P > usable − 35`. If so, the
  record is spilled by construction; compute `local = local_payload_len(P,
  usable)`, require the cell footprint `prefix_len + local + 4` to fit in
  `[cell_start, span_end)`, read the pointer at
  `cell_start + prefix_len + local`, and emit a `SpilledCell` (with `rowid = 0`,
  destroyed — same convention as line 2308) instead of `None`.

Caveat to state honestly: the template's `prefix_len` is borrowed from a live
cell; a freed cell with a different varint-width prefix shifts
`surviving_serials_off` by ±1. This ambiguity already exists for the in-page
template path (accepted in #56); the spilled extension inherits it unchanged
and the length-closure + chain-decode gates reject a mis-aligned candidate.

---

## 3. Design question 2 — following the chain and assembling the record

New method, the carve-side dual of `read_overflow_chain`
(`core/src/lib.rs:1036`), reading **raw main-file pages only** (`raw_page`,
`core/src/lib.rs:425` — carving wants on-disk residue, never the WAL view):

```text
Database::read_freed_overflow_chain(
    first: u32,
    remaining: usize,            // P − local
    freed_leaves: &BTreeSet<u32>,  // freelist leaf pages (see §4.1)
) -> Result<(Vec<u8>, Vec<u32>), ChainBreak>   // (content, chain pages)
```

Walk: `page → bytes 0..4 BE = next (0 = end) → bytes 4..4+min(remaining,
usable−4) = content → repeat until remaining == 0` — identical layout to the
live walker (spec: "Cell payload overflow pages"). Assembly: `local_payload ++
chain_content` must total exactly `P`; then decode via the same record decoder
the live path uses (`decode_record`, `core/src/lib.rs:2442`) so storage-class
fidelity matches live rows, with the carve-validation gates of §4.3 on top.

For the clobbered-prefix variant the serial array is template+tail and the
decode goes through `decode_synthetic_record` (`core/src/lib.rs:2321`) —
exactly mirroring how the two existing in-page paths split.

---

## 4. Design question 3 — robustness (Paranoid Gatekeeper)

### 4.1 The freed-pages-only discipline (the core 0-FP guard)

A stale overflow pointer in freed space may point at: (a) a still-freed
overflow page (recoverable), (b) a page reallocated to live content — a live
b-tree page or a **live** row's overflow chain, (c) a freelist *trunk* page,
(d) garbage (0, out of range, page 1, a ptrmap page).

Rule: **every chain page must currently be a freelist LEAF page.** Grounding
in the format (file format §"The Freelist"): freed pages go onto the freelist;
trunk pages get a 4-byte next-trunk pointer + 4-byte count + leaf-number array
written over their head (destroying former content — measured: 28 bytes on
0E-01 page 5), while **leaf pages' content is not written at all** — exactly
why 0E-01 page 13 survived byte-perfect. So:

- a chain page **not on the freelist** is live or unreachable → `ChainBreak`
  (this is what makes following a pointer into a live overflow chain
  *structurally impossible*, not merely unlikely — Tier-1's 0-FP discipline);
- a chain page that is a freelist **trunk** had its head clobbered by
  construction → `ChainBreak` (this rejects 0E-01 rowid 3 without consulting
  ground truth).

Plumbing: `freelist_pages` (`core/src/lib.rs:384-419`) currently returns
leaves and trunks mixed (trunk pushed at line 415). Add a variant that returns
them separated (e.g. `freelist_pages_split() -> (BTreeSet<u32> leaves,
BTreeSet<u32> trunks)`), keeping the existing method delegating to it so no
caller breaks. The forensic layer computes the split once per carve (it
already walks the freelist at `forensic/src/lib.rs:474`).

### 4.2 Bounds, cycles, bombs

- Every page number range-checked against `file_page_count`
  (`core/src/lib.rs:363-367`); `page == 0` mid-chain with `remaining > 0` is a
  break (premature terminator).
- Cycle detection by **visited set** (`BTreeSet<u32>`), not just a count —
  matching `reconstruct_freeblock_inner`'s discipline (line 1929-1933).
- Anti-bomb cap, structural not magic: the chain can deliver at most
  `(usable − 4) × freed_leaves.len()` bytes, so reject upfront any candidate
  with `remaining` above that — an attacker-declared 2^40 payload_len varint
  dies before any allocation. Additionally cap the assembly buffer by the same
  bound (`Vec::with_capacity` only after the cap check).
- All reads through `be_u32`/`page_slice`/`.get(..)` — out-of-range yields a
  break, never a panic; no `unwrap`/`expect` (workspace denies them).
- Fuzz: extend the repo's one-target-per-structure standard with an
  `overflow_chain` fuzz target (crafted multi-page images: cycles, premature
  zeros, trunk-typed chain pages, huge declared payloads); invariant "must not
  panic", plus the existing `fuzz_forensic` end-to-end target now exercises
  the new path for free.

### 4.3 Detecting an overwritten-but-walkable chain

A freed leaf page can have been freed *earlier* and hold stale bytes from
something else entirely; the walk then "succeeds" mechanically. Gates, in
order:

1. **Exact length closure**: assembled bytes must total exactly `P` and the
   serial-array body lengths must consume them exactly (already enforced by
   construction of the serial sum).
2. **Strict UTF-8 on chain-resident TEXT**: `decode_value` is lossy
   (`String::from_utf8_lossy`, `core/src/lib.rs:2510`), so decode alone cannot
   catch clobbered TEXT. For Tier-1 acceptance of a *spilled* record, every
   TEXT column whose body intersects the chain-supplied region must be valid
   UTF-8 (reject on any `U+FFFD` replacement). Precedent: the gap-anchor pass
   already rejects `\u{FFFD}` text (`core/src/lib.rs:1959`). This is a
   *stricter* gate than in-page Tier-1 — justified because the chain pointer is
   one more indirection of attacker/entropy exposure than a contiguous span.
3. Serial legality and `MIN_INFERRED_COLUMNS` as today.

What this cannot catch (state plainly in docs): a chain page overwritten with
*valid-UTF-8 text of exactly consistent length* — vanishingly contrived, and
precisely why the output remains a confidence-graded observation
("consistent with a deleted row"), never a verdict.

---

## 5. Design question 4 — Tier-1 / Tier-2 boundary (#72 integration)

The boundary, precisely:

- **Tier-1 full row** (`CarveTiers::full`, byte-compatible with
  `carve_all_deleted_records`) iff ALL of: anchor in freed space (gap /
  freeblock / freelist page — guaranteed by the existing structural carve
  discipline); every chain page a freelist leaf (§4.1); cycle/bounds/cap clean
  (§4.2); exact length closure + strict-UTF-8 + legality (§4.3). Emitted as
  `CarvedRecord` with real `rowid` (intact-prefix path) or `rowid = 0`
  (template path).
- **Tier-2 fragment** (`CarveTiers::fragments`) iff the candidate was
  recognized as spilled but ANY chain gate failed. Salvage = decode the
  columns whose bodies lie **entirely within the local prefix** (for 0E-01
  rowid 3: `id = 20003`, `name = 'Matteo'`; the 4091-char `code` and trailing
  `zip` are lost), emit as `CellFragment` (`core/src/lib.rs:114-128`) →
  `CarvedFragment` under the existing distinctiveness gate (≥1 TEXT ≥ 4 bytes
  valid UTF-8 or REAL — `is_distinctive`, `core/src/lib.rs:1819`) and
  `FRAGMENT_CONFIDENCE` (= 0.2, `core/src/lib.rs:237`). A failed chain never
  silently upgrades; a fragment never carries chain-derived bytes (only the
  local prefix — chain bytes that failed validation are untrusted by
  definition).

An anchor yields a full row or a fragment, **never both** — preserved by
routing both outcomes through one resolution function, exactly the
shared-walk pattern of `reconstruct_freeblock_inner`
(`core/src/lib.rs:1908`).

Provenance surface (recommendation): tag Tier-1 spilled recoveries with the
**anchor's** existing `RecoverySource` class (`InPageFreeBlock` /
`FreelistPage` / `FreeblockReconstructed` — `forensic/src/lib.rs:282-311`) and
add an `overflow: Option<OverflowProvenance { first_page: u32, chain: Vec<u32> }>`
field to `CarvedRecord`, mirroring `wal: Option<WalProvenance>`
(`forensic/src/lib.rs:358`). Rationale: an examiner citing the row as evidence
must be able to name the pages its bytes came from; a bare new enum variant
would lose the anchor class, which is still the precision-relevant fact.
`RecoverySource` is `#[non_exhaustive]` (`forensic/src/lib.rs:281`) so the
alternative (new variant) is non-breaking too — Codex may prefer it; the
struct-field route is also low-risk since the #72 memo established no external
consumers of the carve API exist.

Open sub-question (flagged, default = defer/YAGNI): the intact-prefix
broken-chain fragment *knows its rowid* (3), but `CarvedFragment` has no rowid
field (deliberately, per #72 — fragments were clobbered-prefix only). v1
proposal: drop the rowid (no metric uses it) and note the loss; alternative:
`rowid: Option<i64>` on `CarvedFragment`. Codex to adjudicate.

CLI: no new flags. Tier-1 spilled rows appear in the default output like any
recovered row; broken-chain fragments appear under the existing `--fragments`
opt-in. (Fewest decisions on the common path.)

---

## 6. Design questions 5–6 — ground truth, metrics, and the no-special-case argument

### 6.1 `gen_ground_truth.py`

Replace the conservative overflow branch (`return False`,
`gen_ground_truth.py:307-308`) with a **chain-followability test** — still
computed purely from the file bytes, independent of our carver:

1. Build the expected full payload (header + body) via the existing encoders
   (`record_payload_len` machinery, lines 112-175, already constructs serial
   types; add the header-bytes construction it already performs internally).
2. `local = local_payload_len(P, usable)` (port of `core/src/lib.rs:1075` —
   the same spec formula the generator already half-encodes at line 306).
3. For **every** occurrence of `payload[:local]` in the raw bytes (not just
   the first — find-all, general rule): read the 4-byte BE pointer after it,
   walk the chain (4-byte next + `usable−4` content), assemble, and compare
   `assembled == expected_payload`. Any exact match ⇒ `substrate_recoverable
   = True`.

Byte-equality against the expected payload is the honest substrate criterion
(does the scored identity physically survive and is it structurally
addressable?); the freelist-leaf discipline is a *carver* precision rule and
deliberately not part of the substrate definition — if bytes survive on a
non-freelist page the substrate genuinely exists even though our Tier-1
declines it. (For this corpus the two definitions agree: rowid 12 True, rowid
3 False because the trunk overwrote the bytes themselves.)

Disjointness is automatic: `fragment_recoverable` short-circuits on
`substrate` (`gen_ground_truth.py:354`), so rowid 12 flips out of the fragment
denominator when its substrate flips True. The 0A/0B dropped-table proxy
(lines 79-82, 296-297) is untouched.

### 6.2 Expected metric deltas (to be confirmed by the harness, never hand-typed)

- Manifest: `0E` `Drec` 3 → **4**; `0E` fragment denominator decreases by 1
  (rowid 12 leaves it); rowid 3 stays fragment-recoverable (its `name`
  survives locally — already True in today's manifest).
- `forensic/tests/nemetz_metrics.rs`: ours `0E` TP 3 → **4**, FN 0,
  recall(substrate) 1.000, recall(e2e) 4/12 = **0.333**, precision 1.000, live
  re-reads 0. Plus a new explicit negative assertion: rowid 3's full row is
  NOT in Tier-1 output (it would be an FP — its bytes are destroyed).
- Re-run `emit_three_tool_comparison` (with undark/fqlite oracles) →
  `docs/img/comparison_metrics.csv` → `docs/plot_comparison.py` → PNG. The
  oracle tools' rows against the new `Drec = 4` denominator are recomputed by
  the harness — do not predict them here (fqlite's substrate recall will shift
  because the denominator grew; whether it recovers the chained row is for the
  harness to measure).
- `docs/recovery-comparison.md`: rewrite the `0E` narrative (lines 33-37, 87,
  104-106, 123-126) to the current state only: overflow chains are recovered
  when they survive as freelist leaves; a chain page reallocated as the
  freelist trunk (or any reuse) destroys the record and is honestly reported
  as substrate-destroyed — `0E` end-to-end recall remains low (0.333) because
  most `0E` deleted bodies were genuinely overwritten, which no carver can
  undo. No previous-attempt narration.

### 6.3 Why this is not a special case

The spill rule is the file format's own general rule for any
`P > usable − 35` ("Cell payload overflow pages" + the X/M/K local-payload
formulas, fileformat2.html §"B-tree Pages") — the same code path the live
reader has always taken (`core/src/lib.rs:1005-1024`). The carve-side
recognizer applies it to *every* candidate by threshold, in both anchor
classes (intact-prefix and template), with `P`, `local`, and the pointer
offset derived from the candidate's bytes and the header geometry. Nothing
keys on the Nemetz fixtures: a different member of the class (different page
size, reserved bytes, chain length > 1 page, clobbered prefix) takes the same
branch by construction — and the synthetic multi-page chain tests in §7
exercise exactly those unseen members.

---

## 7. Design question 7 — TDD plan (ordered RED → GREEN pairs, two commits each)

Each step: RED commit = failing tests only; GREEN commit = minimal
implementation. Real-artifact validation is steps 3, 5, and 7 (the Nemetz 0E
DBs); synthetic fixtures cover the class members the corpus lacks.

1. **Spilled-cell recognition (core, synthetic).**
   RED: unit tests building a leaf-page image holding a freed spilled cell in
   the gap (intact prefix; payload > usable − 35): recognizer returns the
   exact `P/local/serials/rowid/first_overflow`; abstains for in-page
   payloads, header > local, bad length closure, truncated pointer; existing
   `try_carve_cell_at` results unchanged on every current fixture.
   GREEN: `try_carve_spilled_cell_at` + `usable` threading.
2. **Freed-chain walk (core, synthetic multi-page images).**
   RED: intact 1-page and ≥ 2-page chains assemble exactly; breaks on:
   non-freelist page, freelist-trunk page, cycle (visited set), page 0
   mid-chain, out-of-range page, `remaining` exceeding the freelist capacity
   cap. No panics (also wire the `overflow_chain` fuzz target here).
   GREEN: `freelist_pages_split` + `read_freed_overflow_chain`.
3. **Tier-1 end-to-end on REAL data.**
   RED (integration, `forensic/tests/`): on `tests/data/nemetz/0E/0E-01.db`,
   `carve_all_deleted_records` recovers the rowid-12 row with its full
   answer-key values (`id`, `name`, `code` 4093 chars, `zip`), `rowid == 12`,
   chain provenance `[13]`; **negative**: no Tier-1 record matches rowid 3's
   answer-key row (the trunk-clobbered chain — must NOT be falsely recovered);
   0-FP regression: zero live rows re-read across all 12 Nemetz DBs (the
   existing harness checks stay green).
   GREEN: resolution wiring in `carve_all_deleted_records` /
   `carve_with_fragments` + `OverflowProvenance` + strict-UTF-8 gate.
4. **Tier-2 broken-chain fragment on REAL data.**
   RED: `carve_with_fragments` on 0E-01 yields a fragment whose surviving set
   includes `(0, 20003)` and `(1, "Matteo")` at the page-4 anchor;
   `full` does NOT contain it; fragment count/dedup discipline intact.
   GREEN: salvage path for failed chains.
5. **Template-path spilled cells (synthetic).**
   RED: a crafted leaf page whose freed spilled cell is freeblock-clobbered
   (4-byte header over the prefix) + freed chain pages: reconstruct as Tier-1
   with `rowid = 0`; broken-chain variant yields a fragment.
   GREEN: the `reconstruct_one` spill branch (§2.2).
6. **Ground truth + harness expectations.**
   RED: update `gen_ground_truth.py` (§6.1), regenerate the manifest, and
   update `nemetz_metrics.rs` expectations (`0E Drec = 4`, TP = 4, e2e 0.333,
   fragment denominator − 1) — committed together as the RED of this step is
   the failing manifest-consistency tests
   (`substrate_denominators_match_manifest`-style checks at
   `forensic/tests/nemetz_metrics.rs:351` ff.) against the not-yet-regenerated
   manifest; GREEN regenerates and reconciles. (If the carver steps above are
   already green, this step's RED/GREEN is the manifest/expectation pair
   only.)
7. **Comparison + docs.**
   Re-run `emit_three_tool_comparison` (oracles installed) → CSV → PNG;
   rewrite `docs/recovery-comparison.md` 0E sections; update
   `docs/validation.md` (the chain-recovery validation story: real 0E chains +
   the trunk-clobbered negative). 100%-coverage gate: new lines covered or
   `// cov:unreachable: <invariant>` annotated per repo standard.

Test-runner discipline: sequential runs, targeted (`cargo test -p
sqlite-forensic --test nemetz_metrics` etc.), no parallel heavy suites.

---

## Open questions for Codex to attack

1. **Freelist-leaf discipline vs. substrate definition split (§4.1 / §6.1)**:
   the carver requires chain pages to be freelist leaves; the ground truth
   only requires byte-survival + followability. They agree on this corpus. Is
   the divergence (a survivable chain on a non-freelist page would count in
   `Drec` but be declined by Tier-1) acceptable as an honest
   carver-capability gap, or should the substrate definition also encode the
   freed-space requirement?
2. **Strict-UTF-8 gate asymmetry (§4.3)**: chain-assembled Tier-1 rows get a
   stricter TEXT gate than in-page Tier-1 rows (whose decode stays lossy). Is
   the asymmetry justified by the extra indirection, or should the lossy
   in-page decode be tightened fleet-wide instead (bigger change, separate
   task)?
3. **Provenance shape (§5)**: `overflow: Option<OverflowProvenance>` field on
   `CarvedRecord` vs. a new `RecoverySource::OverflowChain` variant vs. both.
   The field preserves the anchor class; the variant is more visible in
   per-source grading. Which serves the examiner and the dedup/grading logic
   (`forensic/src/lib.rs:458-460`) better?
4. **Fragment rowid (§5)**: intact-prefix broken-chain fragments know their
   rowid; `CarvedFragment` deliberately has none. Add `Option<i64>` now or
   defer?
5. **Template-path spill (§2.2, step 5)**: no corpus instance exists — is
   synthetic-only validation acceptable for v1, or should it be deferred to
   its own task to keep this one fully real-data-validated? (Deferring
   re-creates an "only intact prefixes spill" asymmetry that the
   no-special-case rule dislikes.)
6. **Chain confidence grading**: proposal keeps the anchor class's confidence
   (e.g. gap anchor × `IN_PAGE_CONFIDENCE_FACTOR` 0.8,
   `core/src/lib.rs:221`). Should a chain hop apply an additional factor,
   given the extra indirection — or does the strict gate set make the
   recovered row *as* trustworthy as a contiguous one?
7. **WAL interaction (out of scope v1)**: chains are walked on raw main-file
   pages only; a chain page whose newer version lives in an uncheckpointed
   WAL frame is read in its on-disk (older) state — correct for residue, but
   the WAL-frame carve pass (`forensic/src/lib.rs:536-554`) does not yet
   resolve spilled cells inside frame images at all. Acceptable deferral?
8. **`Drec` 3 → 4, not ~9 (§1.3)**: the probe contradicts the task brief's
   expectation. Please re-verify the probe's payload-length encoding against
   `gen_ground_truth.py` (it reuses the same serial-type logic) — if an
   encoding subtlety (e.g. TEXT affinity on the INTEGER `zip` column) inflated
   P for some rows, more rows could be overflow-class than measured.
