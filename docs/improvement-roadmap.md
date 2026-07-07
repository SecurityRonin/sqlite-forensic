# Improvement Roadmap — `sqlite4n6` / `sqlite-forensic`

## How this document was produced (and a correction)

This roadmap was drafted, then reviewed by an independent model (Codex/GPT-5) against
the live code, and every claim below was re-verified by hand to a `file:line`. The first
draft leaned on stale *test and code comments* (e.g. "overflow recoverability is future
work") and consequently misranked several items that are in fact already implemented. The
corrections are folded in; the failure mode itself — trusting a comment over the current
code — is one of the findings (see §2).

**Evidence basis** is marked per item: `verified` (checked against a `file:line` in this
repo this session) or `proposed` (a design suggestion, not a claim about current code).
Effort: S ≤ 2 days · M ≤ 2 weeks · L > 2 weeks. Priority: P0 do-next · P1 soon · P2
opportunistic. Recall/precision figures are this repo's own measured values.

---

## Executive Summary

The engine is more complete than a first read of its comments suggests. Chain-aware
**deleted overflow** recovery (`core/src/lib.rs:692,943`; `forensic/src/lib.rs:829,847`),
**WAL frame-checksum verification** (`core/src/lib.rs:407,2478,2860`), **rollback-journal**
pre-image recovery (`forensic/tests/cfreds_journal_recovery.rs:45-71`), and **Detector-B**
sidecar schema-change detection (`forensic/src/lib.rs:1860,2018`) are all implemented and
tested. The recovery *substrate* coverage is good.

The highest-leverage work is therefore not "more recovery features." It is, in order:

1. **Row/table identity correctness.** Live-row identity and dedup are keyed by `rowid`
   alone, with no table dimension. On a real multi-table database where two tables share a
   `rowid` value (the normal case — every rowid table starts at 1), this can (a) let a
   still-live row be re-surfaced as a deleted "prior version" — a latent breach of the
   exclusion invariant the whole tool is built around — and (b) silently drop a genuinely
   distinct deleted record. Both are `verified` below. The evaluation corpus does not appear
   to exercise cross-table rowid collision, so the tests are green while the hazard is real
   on field data.
2. **Truth-in-evidence cleanup.** Several shipped comments, the paper, and (until this
   edit) this roadmap claim capabilities the opposite of the code — both *understating*
   (overflow/WAL-checksum "out of scope") and *overstating* (the paper says the project
   "declares a conservative minimum supported version"; no crate declares one). A forensic
   tool's credibility is its evidence discipline; stale self-description erodes it.
3. **Large-artifact handling.** The reader holds the **entire file in a `Vec<u8>`**
   (`core/src/lib.rs:257`, with a comment conceding it is "adequate for the spike … tens of
   MB"). Real phone/app stores (WhatsApp `msgstore`, browser history) reach multiple GB.
   This is an operational ceiling, not polish.

---

## Priority shortlist

**Status (as of this branch): items 1–5 SHIPPED and merged to `main`; item 6 (§3.1) in
progress.** Each shipped item landed as strict-TDD RED→GREEN commits with the full gate
green (100% function coverage, `clippy -D warnings`, rustdoc, workspace tests).

| # | Item | Why | Effort | Status |
|---|------|-----|:--:|---|
| 1 | Table-scope live-row identity (close the exclusion-invariant hole) | Core guarantee can break on multi-table field data | M | ✅ shipped §1.1 |
| 2 | Add table/source to the dedup key | Distinct deleted rows are being dropped | S | ✅ shipped §1.2 |
| 3 | Add raw `evidence()` to anomalies that return none | Violates the tool's own show-the-value rule | S | ✅ shipped §2.2 |
| 4 | Reconcile stale comments + paper MSRV claim with the code | Evidence integrity | S | ✅ shipped §2.1 |
| 5 | Split MSRV: low floor for the two libs, pin for the CLI | Fleet policy; widens library audience | S | ✅ shipped §4.1 |
| 6 | Bounded-memory / streaming read path for multi-GB DBs | Real-world scale ceiling | L | 🚧 in progress §3.1 |

Everything **below** this shortlist (§1.3–1.4, §3.2–3.4, §4.2–4.3, §5.\*, §6) remains
**open** — the P1/P2 backlog, unchanged.

---

## 1. Row/table identity correctness (the headline)

### 1.1 Live-row identity is keyed by global `rowid`, not `(table, rowid)` — **P0, M, ✅ SHIPPED**
`Database::live_rows()` accumulates every user table's rows into one
`BTreeMap<i64, Vec<Value>>` keyed by `rowid` (`core/src/lib.rs:1338-1357`); `collect_rows`
shares that map across tables (`core/src/lib.rs:1734`). Because rowid is the only key, two
tables that share a rowid collapse to one entry.

The exclusion filter then trusts that map (`forensic/src/lib.rs:919-963`):
```rust
match live.get(&rec.rowid) {
    None => true,                                   // not live → keep as deleted
    Some(live_values) => if &rec.values == live_values { false }  // identical → drop
                         else { rec.source = PriorVersion; true } // differs → keep as deleted
}
```
Failure case: table A's **live** row `rowid=5=[x]` appears as a rebalance/freeblock artifact
on a freed page (intact rowid). If table B (iterated later) also has `rowid=5=[y]`, the live
map holds `5→[y]`. The filter compares `[x] != [y]`, keeps the record, and labels it a deleted
`PriorVersion` — **re-surfacing a live row as deleted.** The value backstop (`live_value_keys`,
`forensic/src/lib.rs:927-933`) cannot save it: it is built from the *same collapsed map*, so
the overwritten table's live values are not in it, and it only guards `FreeblockReconstructed`
/ `WalFrame` sources anyway.
- **Fix (one small seam):** carry the source table/rootpage on the carved record where
  attribution is known and key the live map by `(rootpage, rowid)`. A cheaper interim fix
  that closes the *invariant* hole immediately: build `live_value_keys` from a structure that
  keeps **all** live rows' value-tuples (not the rowid-collapsed map), so the value backstop
  is complete for every source. Add a regression fixture with two tables sharing rowids, one
  row surfaced as carvable live residue — the test that is currently missing.

### 1.2 Dedup key omits table/source/page — **P0, S, ✅ SHIPPED**
Both dedup passes key on `(rowid, values)` only:
```rust
// forensic/src/lib.rs:1278   and   cli/src/lib.rs:316-318
let key = format!("{}:{:?}", rec.rowid, rec.values);
```
Two different tables can legitimately hold the same `(rowid, values)` (e.g. two lookup tables
with `1→"US"`). One deleted record is dropped — recall and evidence loss. Include source/table
(and page where known) in the key, or dedup *after* attribution with the table in the identity.

### 1.3 Coalesced / boundary freeblock recall — **P1, M, verified (open)**
`forensic/tests/nemetz_metrics.rs:673` pins a conservative floor ("salvage is future work").
When SQLite coalesces adjacent freeblocks the cell boundaries blur; tightening reconstruction
here recovers rows currently dropped. Genuinely still open (unlike overflow, which is done).

### 1.4 Index b-trees & `WITHOUT ROWID` tables — **P1, L, verified (open)**
`core/src/lib.rs:16` lists both as out of scope, and that part is current. `WITHOUT ROWID`
tables store their data in the index b-tree, so they are invisible to recovery today; they
appear in real app schemas. Index leaves are also a second substrate for ordinary tables (key
columns survive there when table-leaf residue is gone).

---

## 2. Truth-in-evidence cleanup

### 2.1 Stale capability claims in code, paper, and comments — **P0/P1, S, ✅ SHIPPED**
- `core/src/lib.rs:16-17` — "Still out of scope: index b-trees, `WITHOUT ROWID` tables,
  **UTF-16 text**, and **WAL frame-checksum verification**." UTF-16 (`TextEncoding::Utf16Le/Be`,
  `decode_utf16`, `core/src/lib.rs:209-229`) and WAL checksum verification
  (`core/src/lib.rs:2478,2860`) are **implemented**. Reword to the two that remain (index
  b-trees, `WITHOUT ROWID`). Editing this published-crate `src` is itself enough to justify
  the next patch release.
- `forensic/tests/nemetz_metrics.rs:345` — "chain-aware overflow recoverability is future
  work" contradicts `core/src/lib.rs:943` + `forensic/tests/overflow_chain.rs`. Update the
  comment so it stops misleading the next reader (and the next roadmap).
- `paper/sqlite-recovery.tex:407` — the project "declares a conservative minimum supported
  version." It does **not**: no `rust-version` in the workspace or any crate (verified). Either
  add the field (§4.1) and keep the sentence, or remove the sentence. A paper claim the code
  contradicts is the highest-stakes version of this.

### 2.2 Anomalies that report no raw evidence — **P0, S, ✅ SHIPPED (all three anomalies)**
`Observation::evidence()` returns `Vec::new()` for `NonZeroReservedSpace`, `HotJournal`, and
`JournalDuplicatePage` (`forensic/src/lib.rs:492-494`). The project's own discipline is to
surface the offending value + offset on every finding. `NonZeroReservedSpace` should carry the
reserved-byte count and the header offset; `HotJournal` the journal magic/header bytes;
`JournalDuplicatePage` the page number and the two offsets. Cheap, and it is the difference
between "something looks off" and a usable lead.

---

## 3. Large-artifact handling & robustness

### 3.1 Whole-file `Vec<u8>` ownership — **P1, L, 🚧 IN PROGRESS**
`Database { bytes: Vec<u8>, … }` (`core/src/lib.rs:257`); the doc-comment concedes it suits
"tens of MB" and defers a `Read + Seek` / mmap backend. For multi-GB stores this is a hard
ceiling (and a DoS surface on a crafted huge file). Introduce a paged/mmap-backed byte source
behind the existing slice accessors so the parsing logic is unchanged. Pair with a bounded,
streaming carve→output path so a large DB does not also accumulate all records in RAM.

### 3.2 Anti-forensic fingerprinting — **P1, M, proposed**
Promote explicit, evidence-bearing anomalies for residue destruction: `secure_delete`
fingerprint (zeroed freeblock slack where residue was expected), `VACUUM` fingerprint
(compacted file, no freelist residue), WAL salt rewind, freelist-count vs trunk inconsistency.
This converts a silent empty result into "residue was deliberately destroyed, here is the
evidence" — the forensically meaningful distinction, and the substantive answer to the
`secure_delete`/WeChat question. Each finding carries the raw value + offset (§2.2 discipline).

### 3.3 Output-stage (writer) fuzzing — **P2, M, proposed**
The three libFuzzer targets cover `Database::open`, the carver, and the auditor (parse side).
The XLSX/DB/CSV/JSONL writers in `cli/src/lib.rs` run on adversarial carved values (huge blobs,
NUL, control chars, invalid UTF-16 surrogates). Add a writer-layer fuzz/property target so the
emit stage is exercised too. (Note: traversal cycle guards already exist —
`core/src/lib.rs:1746` visited-set in `collect_rows`, `core/src/lib.rs:692` freed-overflow caps
— so a generic "add bound guards" item from the first draft was unwarranted; target the writers
instead.)

### 3.4 Encrypted-DB diagnostics — **P2, S, verified (partial today)**
Encryption is *not* silently ignored: a bad magic fails loud (`cli/src/main.rs:282`) and
`NonZeroReservedSpace` already flags SQLCipher/SEE-style reserved space
(`forensic/src/lib.rs:43-47,1475`). The improvement is a *clearer* diagnostic — name the likely
scheme from header heuristics, state that record recovery needs the key, and (per §2.2) emit the
reserved-byte evidence — rather than a generic anomaly. Detection only; decryption stays out of
scope.

---

## 4. Library / API & fleet hygiene

### 4.1 Split MSRV: low floor for libs, pin for the CLI — **P1, S, ✅ SHIPPED**
No crate declares `rust-version` (absent from workspace, `core`, `forensic`, `cli`), and the
only MSRV CI job tests **1.96** (`.github/workflows/ci.yml:65-70`). Per fleet policy the two
**published libraries** should declare and CI-verify a **low** MSRV (e.g. 1.75/1.80) — a
deliberate compatibility signal — while the **CLI app** declares `rust-version = 1.96`. Add the
fields and a library-only low-MSRV CI job. Fixing this also resolves the paper contradiction in
§2.1. (Demoted from the first draft's P0: real, but identity correctness outranks it.)

### 4.2 Promote the `forensicnomicon` constants — **P1, S, verified**
`core/src/lib.rs:30,35,42` flag reserved-space offset, text-encoding field, and in-header
DB-size as locally redefined pending promotion to the shared KNOWLEDGE layer. DRY across the
fleet; removes the local duplicates.

### 4.3 Python bindings (`pyo3`) — **P2, L, proposed**
Most DFIR scripting is Python. A thin `pyo3` wrapper over `carve`/`audit`/timeline would widen
reach. Caveat (not casual): it needs an isolated boundary crate because the workspace is
`unsafe_code = "forbid"` and pyo3's glue is `unsafe`. Scope deliberately.

---

## 5. Forensic workflow & output

### 5.1 `timeline` subcommand — **P1, M, verified (partial today)**
`core/src/row_history.rs` reconstructs per-rowid version histories across WAL snapshots, and the
default workbook already renders version-history sheets (`cli/src/lib.rs:1586-1600,1930-1943`).
The CLI exposes only `Carve`/`Audit` (`cli/src/main.rs:134-140`). A dedicated `timeline` command
(value history for a rowid/table across commit generations, including deletion) is useful but
not foundational — demoted from the first draft's P0.

### 5.2 Surface delete+reinsert with identical values — **P1, S, verified (design choice)**
`row_history.rs:177-180` deliberately collapses a same-value-across-a-gap run ("still the same
record by evidence"), so a delete-then-reinsert of an identical value is **not** flagged as
reuse (`row_history.rs:211-215`). Defensible, but the WAL proves an absence occurred, and that
event has forensic value (e.g. a message deleted and re-sent). Consider emitting it as a
low-confidence event rather than collapsing it silently — absence is evidence.

### 5.3 Confidence calibration (corpus-scoped) — **P1, M, proposed**
State the empirical precision behind each `--min-confidence` band *as observed on the evaluation
corpus* (e.g. "high = observed precision ≥ X on corpus C"), never as a general guarantee. Gives
the examiner a measured meaning for the threshold without overclaiming.

### 5.4 Court-defensible provenance, uniformly — **P2, M, partly present**
Records already carry source class and confidence. Make the evidence record uniform across all
formats: source page, byte offset/range, substrate, method, confidence — framed in the
expert-witness layers (observed bytes vs forensic inference; never a legal conclusion).

### 5.5 Standards export (CASE/UCO) and blob typing/hashing — **P2, S–L, proposed**
Optional CASE/UCO JSON-LD export for case-management interop; magic-based type ID + content hash
(via the fleet's `blazehash`) for every recovered BLOB so media is addressable in a case.

---

## 6. Validation & the paper

- **Commercial-tool oracle (Sanderson / Belkasoft / AXIOM)** — P1, M, proposed. One commercial
  oracle would lift a comparison column to tier-1 (independent author + answer key). Respect
  redistribution/license (do not commit it), drive it headlessly, env-gate it like the existing
  oracles, document provenance.
- **One-command reproducibility artifact** — P1, M, proposed. A `make reproduce` / pinned
  container that fetches the oracles at their versions and emits the comparison CSV+PNG
  deterministically; suits a DFRWS artifact-evaluation submission.
- **Property-based differential vs `sqlite3`** — P2, M, proposed. Random construct→delete→carve,
  assert every carved row is derivable from the construction log and no live row is surfaced —
  directly the §1.1 hazard a fixed corpus misses.
- **Scheduled fuzz campaign + persisted corpus** — P2, S, proposed. CI builds the harnesses;
  add a cron campaign with a saved corpus (OSS-Fuzz optional).
- **Paper: add the FP comparison table** (now four tools), a dedicated **Threats to Validity**
  section, and fix the MSRV sentence (§2.1) — P1, S–M.

---

## What this roadmap does *not* propose

No change to the exclusion invariant (§1.1 *defends* it), no decryption of encrypted databases
(detection only), and no coverage-number chasing by deleting defensive code. `forbid(unsafe)`,
the 100%-function-coverage gate, and the panic-free reader are load-bearing and stay. Items the
first draft proposed that turned out to be already implemented — deleted overflow recovery, WAL
checksum verification, journal recovery, Detector-B — have been removed rather than left to
flatter the gap list.
