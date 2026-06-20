# Design — Rollback-Journal (`-journal`) Recovery and Anomaly Detection

## Executive Summary

`sqlite-forensic` recovers deleted rows from main-database free space and from
uncheckpointed WAL frames, but **not** from the SQLite **rollback journal**
(`-journal`) — the residue of the *default* (`DELETE`/`PERSIST`) journal mode.
NIST CFReDS test set **SFT-03 PERSIST** makes the gap concrete: of 100 deletions
NIST documents, all 100 survive intact in the `-journal` page images, yet our
carver recovers **0/100** because it reads only the main database. (A reference
parser confirmed 100/100 are present; see `tests/data/cfreds/README.md`.)

**Recommendation.** Add a rollback-journal recovery substrate that is the
**temporal inverse** of the existing WAL feature: where the WAL holds *after*-images
that roll the database *forward* to current state, the journal holds *before*-images
that roll it *back* to the single pre-transaction state. Diffing that prior
snapshot against the live main database yields the last transaction's **deletions**
(rowid present in the journal image, absent now) and **modifications** (rowid
present in both, values differ — the journal carries the *old* value). This is a
principled diff, not a heuristic carve, and it reuses the codebase's existing
temporal model (commit snapshots, per-rowid version history, `RecoverySource`
provenance, the XLSX/JSONL/`.carved.db` pipeline).

**Scope.** Recover deletes + modifications from `PERSIST` (committed, header
zeroed) and hot (`crash`/in-progress) rollback journals; attribute to tables;
reconcile against free-space and WAL carves; and emit a set of
`forensicnomicon` **anomaly observations** (hot journal = interrupted
transaction, checksum failure = corruption/tampering, schema-page journaled =
last-transaction DDL, stale journal, page-size mismatch, …). `DELETE`-mode
(file unlinked) and `TRUNCATE`-mode (file zero-length) leave no in-band residue
and are explicitly out of scope (that is disk-level file carving, a different
layer).

**Validation.** Strict TDD with NIST SFT-03 PERSIST as the known-answer oracle
(target 100/100 deletes + 100/100 modified prior-values), `fqlite` (which already
parses rollback journals) as an independent cross-check oracle via the existing
`FQLITE_TAP` gate, crafted unit vectors for the header/checksum parser, and a
no-panic robustness sweep over truncated/garbage/zeroed journals. The Paranoid
Gate's 100% function-coverage floor is maintained.

---

## 1. Background — the rollback journal format

Authoritative spec: <https://sqlite.org/fileformat.html> (§ "The Rollback
Journal") and <https://sqlite.org/tempfiles.html>. Cross-checked against the
FQLite recovery technique (Pawlaszczyk & Hummert, *Making the Invisible Visible —
Techniques for Recovering Deleted SQLite Data Records*, IJCFATI 2021,
<https://conceptechint.net/index.php/CFATI/article/view/17>).

A rollback journal is one or more **segments**. Each segment is a sector-aligned
**header** followed by **page records**:

Verified against SQLite's `pager.c` (`writeJournalHdr`/`readJournalHdr`,
`zHeader[sizeof(aJournalMagic)+16]`) — the authoritative source, **not** a
secondary summary (an earlier secondary summary swapped the offset-12/16 fields):

| Header field | offset | bytes | `pager.c` name | meaning |
|---|---|---|---|---|
| magic | 0 | 8 | `aJournalMagic` | `d9 d5 05 f9 20 a1 63 d7` |
| nRec | 8 | 4 BE | `nRec` | page records in this segment (`0xFFFFFFFF` ⇒ "read to EOF / until invalid"; `0` ⇒ zero records, treat as anomalous/until-invalid) |
| **nonce** | **12** | 4 BE | `cksumInit` | checksum initializer (pseudo-random) |
| **mxPage** | **16** | 4 BE | `dbOrigSize` | db page count **at transaction start** (the pre-txn db size) |
| sectorSize | 20 | 4 BE | `sectorSize` | VFS sector size (header is padded to this) |
| pageSize | 24 | 4 BE | `pageSize` | db page size at transaction start |

Each **page record** (immediately after the sector-padded header):

```
[ page number : 4 BE ] [ original page content : pageSize bytes ] [ checksum : 4 BE ]
```

`checksum` = the **offset-12 nonce** plus a sample of the page image: starting at
byte index `X = pageSize − 200`, add `page[X]` and step `X −= 200` while `X > 0`
(equivalently, every 200th byte at indices `pageSize%200, +200, …`). It detects
torn/partial page writes; it is **not** a cryptographic integrity guarantee, so a
forged page cannot be excluded by checksum alone (and in the zeroed-header tier the
nonce is gone, so checksums cannot be verified at all — see §3).

**The forensic essence.** Before SQLite modifies a page, it writes that page's
*original* bytes to the journal. So the journal's page images are the database
**as it was before the last transaction** — including the rows that transaction
deleted and the pre-edit values of rows it modified.

### Journal fate by `journal_mode` (what is recoverable)

| mode | on commit | in-band residue? |
|---|---|---|
| `DELETE` (default ≤ most builds) | file unlinked | none in-band (disk-carving only) — **out of scope** |
| `TRUNCATE` | file → 0 bytes | none — **out of scope** |
| **`PERSIST`** | header overwritten with zeros, **bodies kept** | **yes — page images intact** (the NIST SFT-03 case) |
| `MEMORY` / `OFF` | no file | none |
| *crash / power-loss / `kill -9`* (any disk mode) | journal left **with valid header** = a *hot journal* | **yes — the pre-crash prior state** |

The two recoverable cases — **PERSIST (header zeroed, bodies intact)** and **hot
journal (header valid)** — are the two parsing tiers in §3.

---

## 2. Design principle — the journal is the WAL, inverted

The codebase already models WAL time precisely (`WalTimeline`, `CommitSnapshot`,
`carve_at_commit`, per-rowid `row_history`). The rollback journal is the same
idea with the arrow of time reversed:

| | WAL | Rollback journal |
|---|---|---|
| stores | *after*-images (new page versions) | *before*-images (original pages) |
| base db is | the **old** state | the **new** (post-commit) state |
| applying it yields | the **current** state (roll forward) | the **prior** state (roll back) |
| number of recoverable snapshots | one per COMMIT frame | exactly **one** (the pre-transaction state) |
| deleted row appears as | a tombstone / absent in a later commit | **present in the prior snapshot, absent now** |
| modified row appears as | new value in a later commit | **old value in the prior snapshot** |

Therefore the recovery is a **two-snapshot diff**, reusing the machinery that
already exists for WAL version history — not a new carving heuristic. This keeps
the mental model, the provenance types, and the output pipeline uniform.

**Secure-by-design corollary.** The WAL accessor `open_with_wal` returns a
`Database` whose *live* reads reflect the WAL-applied **current** state — correct,
because the WAL *is* the present. Applying a journal yields the **past**;
surfacing past/deleted rows as if live would be a forensic footgun. So the
journal API must **not** overlay into a normal `Database`. It returns a distinct
`PriorSnapshot` type that cannot be mistaken for the current database (type system
as enforcement; see §5).

---

## 3. Parsing — two tiers, robust against real-world deviation

Research-first, then assume real data violates the spec (zeroed headers, stale
`nRec`, torn tails, odd sector sizes, multi-segment savepoint journals).

### Tier A — header-valid journal (hot journal / crash residue / in-progress)

Magic present ⇒ trust the header. Read `pageSize`, `nonce`, `sectorSize`, `nRec`,
`mxPage`. Page records start at `sectorSize`. Walk `nRec` records (or to EOF when
`nRec ∈ {0, 0xFFFFFFFF}`). **Verify each checksum** (nonce known) → a mismatch is
not discarded silently but recorded as an anomaly (§6.3) and the record is kept as
low-confidence. After the segment, probe the next sector-aligned offset for
another valid header (multi-segment).

### Tier B — header zeroed/invalid (PERSIST post-commit — the dominant real case)

Magic absent ⇒ reconstruct parameters, because the header was deliberately
invalidated but the bodies remain:

- **`pageSize` ← the main database header.** Authoritative: the journal's pages
  are images of *this* db's pages, so they share its page size. (Never guess it
  from the zeroed journal header.)
- **`sectorSize` is unknown** (the offset-20 field was zeroed), and real VFS sector
  sizes exceed 512. So **do not hard-assume 512.** Treat the standard sizes
  (512, 4096, and the page size) as *candidates*: for each, walk records at stride
  `4 + pageSize + 4` from `offset = sectorSize_candidate` and **score** the result
  by (record count, all `pgno` in `1..=mainDbPageCount+slack`, no impossible
  duplicate `pgno`, stride consistency across ≥2 records, decoded cells matching
  the main db's schema for that page's table, valid root→child page-graph linkage).
  Pick the highest-scoring candidate; a tie or low score ⇒ low confidence + anomaly.
- **Accept all SQLite page types**, not just table leaves: a valid record may carry
  page 1, interior b-tree pages (`0x02`/`0x05`), table/index leaves (`0x0d`/`0x0a`),
  overflow pages, freelist trunk pages, or pointer-map pages. The acceptance test is
  "structurally a valid page of *some* type **and** consistent with the other
  records," not "is a table-leaf." (Restricting to leaves would drop interior pages
  needed to *walk* a prior table — §4.)
- Checksums cannot be verified (nonce zeroed), so a single isolated record can
  false-positive; acceptance therefore rests on **cross-record consistency** (the
  scoring above), never one record in isolation.
- **Last-resort fallback** (non-standard sector, partial overwrite, torn segment):
  a structural scan for page-record boundaries — slide a window for runs of
  `[plausible pgno][valid page image]` at a consistent stride. This reached 100/100
  on the reference parser; it is the robustness floor, flagged lower-confidence.
- **Limit:** a zeroed-header *multi-segment* journal cannot be segmented by a single
  fixed stride (no `nRec`, sub-headers also zeroed). Stride-scan recovers records
  but segment boundaries/order become best-effort — stated as a known limit (§9).

Both tiers degrade gracefully: a malformed/truncated journal yields fewer page
images (or none) and a typed `Err`/empty result, **never a panic** (`forbid(unsafe)`,
bounded loops, no `unwrap` in non-test code — same contract as the rest of core).

### Multi-segment / repeated pages

A journal may contain multiple sector-aligned **segments** (header + records,
repeated) when the page cache spills mid-transaction. Per the spec, a given page
is journaled **at most once** within the main rollback journal (the pager tracks
journaled pages in a bit-vector), so the *expected* case has no duplicate `pgno`.
Parse each segment exactly: after a segment's `nRec` records, advance to the next
sector boundary and probe for the next header. If a `pgno` nonetheless appears
twice, do **not** silently dedup — keep the **first** (earliest) occurrence as the
truest pre-transaction image and **raise a duplicate-page-record anomaly** (§6),
since a duplicate is consistent with corruption, a super-journal/savepoint
artifact, or tampering.

---

## 4. Recovery — the prior-snapshot diff

1. **Materialize the prior snapshot.** `prior[pgno] = journal_image(pgno)` where
   present, else `main_db[pgno]`. This is the pre-transaction database image
   (read-only, page-addressable) — the analog of a WAL `CommitSnapshot`.
   The overlay materializes **every** valid journal page image (interior, leaf,
   overflow, page 1, freelist trunk, pointer-map) — not just table leaves — so a
   prior table can be *walked* through its interior pages, and overflow payloads
   reassembled, exactly as for the live db.
2. **Resolve schema.** Default to the main db's current schema. If the journal's
   page-1 image carries a **different schema cookie** (file-header offset 40, BE)
   than the live db, the last transaction changed the schema (CREATE/DROP/ALTER);
   read the prior schema from the journal's page-1 image and reconcile (a table dropped
   in the last txn reappears in `prior`; a table created in the last txn is absent
   in `prior`). This recovers the **prior schema**; whether the dropped table's
   *rows* are also recoverable depends on whether its b-tree pages were journaled
   (they may instead be freelist/overflow pages absent from the journal) — so this
   is "prior schema + best-effort rows," not a guaranteed full dropped-table dump.
3. **Diff per table.** For each rowid table T (see limit on `WITHOUT ROWID` below),
   read `prior_rows: rowid→values` and `current_rows: rowid→values`. Because the
   journal only contains *changed* pages, the two differ only on journaled pages —
   the diff is naturally bounded.
   - **Deleted** = `rowid ∈ prior \ current` → recover the prior row (full fidelity).
   - **Replaced/updated** = `rowid ∈ prior ∩ current, values differ` → recover the
     prior values as edit history; carry both old and new. **Do not assert
     "UPDATE":** a transaction that deletes rowid X then inserts a *new* row reusing
     rowid X is indistinguishable here from an in-place UPDATE, and conflating them
     would merge two distinct entities. Classify as `replaced_rowid` (prior value
     present, identity may differ) and flag it, mirroring the existing
     `rowid_reused` handling in the WAL/version-history path.
   - **Inserted** = `rowid ∈ current \ prior` → a timeline fact / anomaly, not a
     recovery target.
   - **`WITHOUT ROWID` tables** have no integer rowid key (they are index b-trees
     keyed by the primary key); the existing `CommitSnapshot` reader flags rather
     than reads them, so the rowid-diff does not apply. **Excluded** from journal
     diff recovery in v1 (a PK-keyed index-btree diff is a later enhancement) —
     stated as a limit, not silently mishandled.
4. **Tag provenance.** Every recovered record is `RecoverySource::RollbackJournal`
   carrying: journal source path, segment index, page number, header-state
   (`Valid`/`ReconstructedZeroed`), and checksum status. NIST SFT-03 explicitly
   requires reporting **the number of deleted/modified records and their source
   file** — the provenance is that report, structurally present, not a side note.

### Reconciliation / dedup

- **Vs free-space carve:** the same deleted row may also linger in main-db slack.
  The journal copy is higher fidelity (full original page); dedup by
  `(table, rowid, normalized values)`, prefer the journal source, note
  corroboration.
- **Vs WAL:** `journal_mode` is exclusive, so a db is not simultaneously in WAL and
  rollback-journal mode. A stale `-journal` beside a WAL-mode db is possible
  (mode was switched); process independently, dedup, and flag the stale journal
  (§6.8).

---

## 5. API (fleet `-core` / `-forensic` split, secure-by-default)

### `sqlite-core` (raw decode; `Read + Seek`; no findings)

```rust
/// Parsed (or reconstructed) rollback-journal header.
pub enum JournalHeader {
    Valid { n_rec: u32, mx_page: u32, nonce: u32, sector_size: u32, page_size: u32 },
    /// PERSIST post-commit: header zeroed; parameters reconstructed from the main db.
    ReconstructedZeroed { page_size: u32, sector_size: u32 },
}

pub struct JournalPageImage {
    pub pgno: u32,
    pub segment: usize,
    pub bytes: Vec<u8>,        // pageSize bytes, the original page content
    pub checksum_valid: Option<bool>, // Some(_) in Tier A, None when nonce unknown
}

pub struct RollbackJournal { /* header + ordered, deduped page images */ }
impl RollbackJournal {
    /// LOWER-LEVEL, UNAUTHENTICATED: parses arbitrary bytes as a journal given an
    /// externally-supplied `page_size`. It does NOT check the journal belongs to
    /// any particular database — callers should prefer `Database::rollback_prior`,
    /// which binds the journal to a real db and its authoritative page size.
    pub fn parse(bytes: &[u8], page_size: u32) -> Result<Self, Error>;
    pub fn header(&self) -> &JournalHeader;
    pub fn page_images(&self) -> &[JournalPageImage];
}

impl Database {
    /// Safe entry point. Materializes the single pre-transaction state, binding the
    /// journal to THIS database (its page size is authoritative; a page-size or
    /// stale-counter mismatch is surfaced, not silently accepted). Returns a
    /// DISTINCT read-only view — NOT a `Database` — so prior/deleted rows can never
    /// be read as "live". **Errors if `self` was opened WAL-applied**
    /// (`open_with_wal`): WAL and rollback-journal modes are mutually exclusive
    /// timelines and must not be overlaid.
    pub fn rollback_prior(&self, journal: &[u8]) -> Result<PriorSnapshot, Error>;
}

/// Read-only, page-addressable pre-transaction image. Mirrors `CommitSnapshot`.
pub struct PriorSnapshot { /* overlay: journal-where-present else main db */ }
impl PriorSnapshot {
    pub fn tables(&self) -> Vec<SnapshotTable>;
    pub fn read_table(&self, root_page: u32, column_count: usize) -> Result<Vec<Row>, Error>;
}
```

### `sqlite-forensic` (findings)

```rust
pub struct JournalRecovery {
    /// Rows present in the prior snapshot but absent now — genuinely deleted by the
    /// last txn, recovered at full fidelity. NOT free-space carves: in the prior
    /// state these were LIVE allocated rows, so they are NOT modeled as
    /// `CarvedRecord { allocated: false }` (which means "from current free space").
    pub deleted:  Vec<PriorRow>,
    /// Rows present in both, values differ — prior (pre-edit) values + the current
    /// values, flagged `replaced_rowid` when identity may differ (see §4).
    pub modified: Vec<PriorVersionRecord>,
    pub anomalies: Vec<forensicnomicon::report::Observation>,
    pub counts: JournalCounts,         // NIST SFT-03 "number of deleted/modified … source file"
}

/// A row recovered from the prior snapshot, carrying full journal provenance.
pub struct PriorRow { pub table: String, pub rowid: i64, pub values: Vec<Value>, pub source: RollbackJournalSource }

pub fn carve_rollback_journal(db: &Database, journal: &[u8]) -> JournalRecovery;
```

`RecoverySource` gains a `RollbackJournal(RollbackJournalSource)` variant — a
**struct** (not a thin enum payload) carrying `{ journal_path, segment, pgno,
byte_offset, header_state: Valid|ReconstructedZeroed, sector_candidate,
checksum_valid: Option<bool>, confidence }` — parallel to `WalFrame` /
`CommitSnapshot`, so the existing attribution → XLSX/JSONL/`.carved.db` pipeline
carries it with no special-casing. The variant's *meaning* is "prior allocated
row from the rollback journal," which downstream reports must not relabel as
unallocated free-space residue.

### CLI / sidecar discovery (secure-by-default UX)

The CLI already auto-attaches a `-wal` sidecar. Extend the same zero-config
discovery to `<db>-journal`: if present, run `carve_rollback_journal` and fold its
output in. No new required flags; advanced users can point at an out-of-tree
journal explicitly. One concept, one name ("rollback journal") across flags, docs,
columns, and provenance.

---

## 6. Associated anomaly detection (→ `forensicnomicon::report::Observation`)

Each observation is "consistent with …", confidence-graded; the examiner draws the
conclusion (the report never asserts a legal/intent conclusion).

1. **Hot journal present (valid header).** A `-journal` with valid magic beside the
   db is *consistent with* an **interrupted or in-progress** write transaction
   (crash, power loss, process kill, or acquisition captured mid-write); SQLite
   would roll it back on next open, and the current main db may require rollback.
   The journal holds the pre-interruption state. (State the observation; the
   examiner concludes whether it was a crash, a normal in-flight write, or
   deliberate — the design must not assert "anti-forensic.")
2. **Committed PERSIST journal (header zeroed, bodies intact).** *Consistent with* a
   normally-committed transaction whose pre-images (incl. deleted/modified rows)
   remain recoverable. The NIST SFT-03 case — benign mechanism, high recovery value.
3. **Page-record checksum mismatch** (Tier A). *Consistent with* corruption, a torn
   page (power-loss mid-sector), or post-write modification of the journal.
4. **Page-size / sector-size inconsistency** (journal header vs main db).
   *Consistent with* a mismatched/wrong-db journal or tampering.
5. **`mxPage` ≠ current page count** (Tier A only — `mxPage` is gone in a zeroed
   header). `mxPage < current` ⇒ the txn grew the db (pages beyond `mxPage` are new;
   their pre-images aren't journaled — this bounds what can be rolled back).
   `mxPage > current` ⇒ the db file shrank — *consistent with* `auto_vacuum`/
   incremental-vacuum or truncation (an ordinary `DELETE` does **not** shrink the
   file, so do not name "large delete").
6. **Schema cookie advanced.** The journal's prior page-1 image schema cookie
   (file-header offset 40, BE) differs from the live db's. *Consistent with* a DDL
   change in the last transaction (CREATE/DROP/ALTER); enables prior-schema +
   dropped-table recovery. Page 1 presence alone is **not** the signal — page 1
   is journaled on nearly every write (change-counter / freelist-count / db-size
   header fields update routinely), so only a cookie difference indicates DDL. For
   an *uncommitted* hot journal the live file may not yet carry the new cookie, so
   a committed-cookie DDL can be undetectable mid-flight — acceptable, since the
   detector never false-positives.
7. **Page-type/schema drift** — a journal image of page N decodes to a different
   table shape than main-db page N. *Consistent with* page repurposing
   (DROP+CREATE reused the page) / aggressive space reuse.
8. **Stale journal** — the journal does not correspond to the current db
   (file-change-counter / schema-cookie mismatch, or a `-journal` beside a WAL-mode
   db). *Consistent with* leftover residue from an older transaction or a journal-mode
   switch — recovered content is prior-state but not the immediately-preceding txn.
9. **Duplicate / impossible page records** — a repeated `pgno` (spec says ≤ once),
   a `pgno` outside `1..=mxPage`/db size, an impossible sector/page size, or a
   truncated final record. *Consistent with* corruption, a savepoint/super-journal
   artifact, or tampering. (Note: rollback-journal recoverability says **nothing**
   about the `secure_delete` pragma — the journal stores pre-images for rollback
   regardless — so secure-delete inference is drawn only from main-db free-space
   residue, never from journal page images.)
10. **Super-journal / `ATTACH` context** — a `<db>-journal` may be coordinated by a
    super-(master-)journal across multiple attached databases; its presence frames
    whether the txn spanned several files. Surface it as context, not a conclusion.
11. **Counts + source-file report** (NIST SFT-03 requirement) — structured counts
    of deleted/modified records and the naming of the `-journal` as their source.

---

## 7. Output integration

- **`RecoverySource::RollbackJournal`** flows unchanged through attribution and the
  combined/temporal XLSX, JSONL, and rebuilt `.carved.db`.
- **Temporal XLSX:** the prior snapshot is exactly one step before "current", so a
  journal-recovered prior row slots as the immediately-preceding version in the
  per-rowid history. Deletes → red tint (`is_deleted`); modifications → blue
  (`superseded`) with the prior value; a `source` column reads `rollback-journal`
  with the page/segment/checksum provenance. Reuses the existing flag columns and
  tint precedence (no new colors).
- **JSONL:** `source: "rollback-journal"` plus provenance fields.
- **Audit / report:** the §6 observations join the existing anomaly list.

---

## 8. TDD plan (strict RED → GREEN, separate commits)

**Derive the oracle, don't transcribe it.** The NIST RTF prose lists IDs in an
OCR-prone form and labels PERSIST deletes by `InvoiceId` but WAL by `InvoiceLineId`.
The *reproducible* ground truth is structural: `InvoiceLineId` is the
`INTEGER PRIMARY KEY` (= rowid) and was originally contiguous `1..=2240`, so the
**expected-deleted set = `{1..=2240} \ live_InvoiceLineId`**, computed from the db
itself. This was confirmed empirically: gap = 100, and all 100 missing PKs are
present in the `-journal` page images (100/100). The RED asserts against this
derived set, cross-checked against the RTF — not a hand-typed ID list.

Each step below is its **own** RED→GREEN pair (separate commits); the first GREEN
is deliberately *minimal* (parser only), not the whole feature, so failures localize:

1. **Parser + checksum** — RED: `core/tests/rollback_journal.rs` (header parse
   valid + zeroed; every-200th checksum on a known vector seeded from the **offset-12
   nonce**; multi-segment; truncated tail; `nRec = 0xFFFFFFFF` ⇒ to-EOF, `nRec = 0`
   ⇒ zero/anomalous; duplicate `pgno` ⇒ anomaly). GREEN: `RollbackJournal::parse`.
2. **Prior snapshot + Tier-B reconstruction** — RED: read the prior `invoice_items`
   from SFT-03 PERSIST and assert 2240 rows (pre-delete). GREEN: `rollback_prior` +
   `PriorSnapshot` + the sector-candidate ranking.
3. **Diff recovery** — RED: `forensic/tests/cfreds_journal_recovery.rs` asserts the
   100 derived deletions recovered (target 100/100, floor ≥ 99) and the 100 modified
   rows' **prior** `Quantity` (≠ 200) recovered. GREEN: `carve_rollback_journal`.
4. **Anomalies** — RED per observation class. GREEN: the §6 observations.
5. **Output integration** — CLI sidecar discovery + XLSX/JSONL/`.carved.db`.

**Independent oracles / Doer-Checker:**
- **NIST SFT-03 PERSIST** derived ground truth = primary (100 deletes + 100 mods),
  plus crafted minimal journals built with the real `sqlite3` engine under
  `PRAGMA journal_mode=PERSIST` (Tier-A valid-header *and* Tier-B zeroed cases).
- **`fqlite`** via the existing `FQLITE_TAP` gate = **optional** cross-check (not a
  required gate condition — keep NIST + crafted fixtures as the required tests).
- Robustness: attach `-journal` sidecars in the no-panic CFReDS sweep; fuzz
  truncated/garbage/zeroed journals (cargo-fuzz target).
- **Paranoid Gate / coverage:** malformed-journal handling **is the threat model**,
  so those defensive branches are *reachable* and must be covered by **negative
  tests** (truncated, garbage, bad sector guess, checksum mismatch, duplicate page,
  impossible sizes) — `// cov:unreachable:` is reserved for branches a current
  invariant truly makes unreachable, not for unexercised error paths.

---

## 9. Limits (stated plainly)

- **DELETE / TRUNCATE modes leave no in-band residue** (file unlinked / zeroed) —
  recovering those is disk-level file carving, a different layer, out of scope here.
- A journal captures exactly **one** prior state (the last transaction); older
  history is gone unless it also survives in free space / WAL.
- The zeroed-header (PERSIST) tier cannot verify page checksums (nonce gone); it
  relies on cross-record structural consistency, so a deliberately-forged journal
  page is a residual risk (surfaced as low-confidence, never silently trusted).
- A **zeroed-header multi-segment** journal cannot be segmented by a fixed stride
  (no `nRec`, sub-headers also zeroed); records are recovered by stride-scan but
  segment boundaries/order are best-effort.
- **`WITHOUT ROWID` tables** are excluded from the v1 rowid diff (index-btree
  PK-keyed diff is a later enhancement).
- Encrypted databases (SQLCipher/SEE) have encrypted journal pages — out of scope.

---

## 10. Build sequence

1. core: `RollbackJournal::parse` + checksum + `PriorSnapshot` (+ unit RED→GREEN).
2. forensic: `carve_rollback_journal` diff + `RecoverySource::RollbackJournal`
   (+ NIST SFT-03 RED→GREEN, fqlite cross-check).
3. forensic: the §6 anomaly observations.
4. CLI: sidecar discovery + XLSX/JSONL/`.carved.db` integration.
5. docs: flip `tests/data/cfreds/README.md` "Known gap" → validated; add a
   `validation.md` oracle row (CFReDS SFT-03 PERSIST, journal substrate).
