# Improvement Roadmap — `sqlite4n6` / `sqlite-forensic`

## How this document was produced

This roadmap was drafted, reviewed by an independent model (Codex/GPT-5) against the
live code, and every claim re-verified by hand to a `file:line`. The first draft leaned
on stale *test and code comments* (e.g. "overflow recoverability is future work") and
misranked several items already implemented; those corrections are folded in. **Evidence
basis** is marked per item: `verified` (checked against a `file:line`) or `proposed` (a
design suggestion). Effort: S ≤ 2 days · M ≤ 2 weeks · L > 2 weeks. Priority: P0 · P1 · P2.

## Shipped (archived in git)

The entire P0 shortlist is done and merged to `main` — each as strict-TDD RED→GREEN
commits with the full gate green (100% function coverage, `clippy -D warnings`, rustdoc,
workspace tests). The completed items are **not** repeated here; git is the archive:

| Item | What | Commits |
|---|---|---|
| §1.1 | Exclusion-invariant fix — live-row identity was keyed by global `rowid`; table-scoped now | `386b679`→`09e780f` |
| §1.2 | Table-aware dedup — cross-table rows sharing `(rowid,values)` no longer collapse | `063ed7e`→`f6bea97` |
| §2.1 | Stale capability comments corrected; the paper's MSRV claim made true | `bc2c230` |
| §2.2 | Anomaly `evidence()` — reserved-space, duplicate-page, hot-journal now carry the value | `96e2f48`→`5fbd60a` |
| §4.1 | MSRV split — libs `1.80` (CI-verified), CLI `1.96` | `3423bf2` |
| §3.1 | Bounded-memory paged read (`Database::open_path` + LRU) | `0aef805`→`6e7c84a` |
| §4.1 | `timeline` subcommand — per-rowid version history over the WAL commit sequence | RED→GREEN this branch |

A second wave of the **P1/P2 backlog** has since shipped to `main`, same gate
(strict-TDD RED→GREEN where an implementation changed, 100% function coverage,
`clippy -D warnings`, rustdoc, workspace tests):

| Backlog item | What | Commits |
|---|---|---|
| §2.1 | Anti-forensic freelist fingerprints — count-vs-trunk inconsistency + zeroed-residue (secure_delete), verified vs sqlite 3.45.3 | `265c639` |
| §2.2 | Output-stage (writer) fuzz target + scheduled campaign | `fuzz.yml` + `render` target |
| §2.3 | Encrypted-DB diagnostic names the scheme from reserved bytes (SQLCipher 4 = 80, checksum VFS = 8), verified vs SQLCipher 4.16 | `d7dd22c` |
| §4.2 | Delete+reinsert of an identical value surfaced as a low-confidence event | `753fade` |
| §4.3 | Corpus-scoped confidence-band calibration (precision 1.000 at every band; bands select recall depth) | `b3f55ae` |
| §5 | Paper FP comparison table + Threats to Validity | this branch |
| §5 | One-command reproducibility artifact (`scripts/reproduce.sh`) | this branch |
| §5 | Property-based differential vs `sqlite3` (no fabrication + exclusion invariant over random construction) | `13cfe3a` |

Everything below is the **remaining P1/P2 backlog**.

---

## 1. Row/table identity correctness

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

## 2. Large-artifact handling & robustness

*(§2.1 anti-forensic fingerprinting, §2.2 writer fuzzing, §2.3 encrypted-DB
diagnostics — all shipped; see the Shipped table above.)*

---

## 3. Library / API & fleet hygiene

### 3.1 Promote the `forensicnomicon` constants — **P1, S, verified**
`core/src/lib.rs` flags the reserved-space offset, text-encoding field, and in-header DB-size as
locally redefined pending promotion to the shared KNOWLEDGE layer. DRY across the fleet; removes
the local duplicates.

### 3.2 Python bindings (`pyo3`) — **P2, L, proposed**
Most DFIR scripting is Python. A thin `pyo3` wrapper over `carve`/`audit`/timeline would widen
reach. Caveat (not casual): it needs an isolated boundary crate because the workspace is
`unsafe_code = "forbid"` and pyo3's glue is `unsafe`. Scope deliberately.

---

## 4. Forensic workflow & output

*(§4.2 delete+reinsert surfacing, §4.3 confidence-band calibration — shipped; see
the Shipped table above.)*

### 4.4 Court-defensible provenance, uniformly — **P2, M, partly present**
Records already carry source class and confidence. Make the evidence record uniform across all
formats: source page, byte offset/range, substrate, method, confidence — framed in the
expert-witness layers (observed bytes vs forensic inference; never a legal conclusion).

### 4.5 Standards export (CASE/UCO) and blob typing/hashing — **P2, S–L, proposed**
Optional CASE/UCO JSON-LD export for case-management interop; magic-based type ID + content hash
(via the fleet's `blazehash`) for every recovered BLOB so media is addressable in a case.

---

## 5. Validation & the paper

- **Commercial-tool oracle (Sanderson / Belkasoft / AXIOM)** — P1, M, proposed. One commercial
  oracle would lift a comparison column to tier-1 (independent author + answer key). Respect
  redistribution/license (do not commit it), drive it headlessly, env-gate it like the existing
  oracles, document provenance.
- *(Shipped: one-command reproducibility artifact `scripts/reproduce.sh`;
  property-based differential vs `sqlite3`; scheduled fuzz campaign `fuzz.yml`;
  paper FP comparison table + Threats to Validity — see the Shipped table above.)*

---

## What this roadmap does *not* propose

No change to the exclusion invariant, no decryption of encrypted databases (detection only), and
no coverage-number chasing by deleting defensive code. `forbid(unsafe)`, the
100%-function-coverage gate, and the panic-free reader are load-bearing and stay.
