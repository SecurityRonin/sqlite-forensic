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
| §4.4 | Overflow-chain / WAL-frame method provenance surfaced in the JSONL output | `c4d6f54` |
| §4.5 | BLOB media-typing + SHA-256 hashing (JSONL) and a CASE/UCO `-f case` bundle export | `471749c` |
| §3.2 | Python bindings — standalone `python/` pyo3 crate (`carve`/`audit`/`timeline`), maturin-built + pytested | `1cdb307` |
| §1.4 | Index-b-tree leaf reading foundation (`index_leaf_cells`), tier-2 vs `sqlite3` | `928af77` |
| §3.1 | Promote the four page-1 header offsets to `forensicnomicon::sqlite` (≥ 1.5.0) and consume them; local duplicates removed | `59ecf8b` |
| §1.4 | Read live `WITHOUT ROWID` table rows — full index-b-tree walk (`without_rowid_table_rows`), tier-2 vs `sqlite3` | `ff6a575` |
| §1.4 | Surface `WITHOUT ROWID` live rows in the carve workbook (`TableHistory::without_rowid_rows` → temporal sheet) | `7736af3` |

The remaining backlog is now small, and what's left is deliberate: §1.3 (safe scope done —
residual precision-bounded), §1.4's deleted-index-entry carving + overflow (the live-data half
shipped; the deleted half is §1.3-class precision-bounded with an information-theoretic limit on
small keys — deferred, not a clean slice), and one externally-blocked item — §5's commercial-tool
oracle (needs a licensed GUI tool). Details below.

---

## 1. Row/table identity correctness

### 1.3 Coalesced / boundary freeblock recall — **P1, M, safe scope done; residual precision-bounded**
Investigated: the general coalesced multi-cell recovery is already implemented (task #66 —
"iterate template reconstruction across the whole free span"), verified by
`category_0d_true_positive_floor` and by a direct probe (a real sqlite3 coalesced 42-byte
freeblock recovers *both* freed rows). The remaining residual — e.g. 4 of 5 fragment-recoverable
0D rows (`nemetz_metrics.rs`, `NEMETZ_0D_FRAGMENT_TP_FLOOR`) — is bounded by two hard constraints:
rows surviving **inside live-cell extents** are unrecoverable by the never-scan-live discipline,
and the rest need a template-free salvage that would risk the structural **0-false-positive
guarantee** this roadmap explicitly protects. Not pursued: chasing corpus-specific recall by
loosening the precision gates trades the tool's headline property for a few rows on one category.

### 1.4 Index b-trees & `WITHOUT ROWID` tables — **P1, L, live-data half shipped; deleted-data deferred**
**Shipped — the live-data half.** Three pieces landed: `Database::index_leaf_cells` parses live
index-b-tree leaf cells (type `0x0a`); `Database::without_rowid_table_rows` walks each
`WITHOUT ROWID` table's whole index b-tree (interior `0x02` → leaf `0x0a`, decoding the interior
cells' own key records too) to return its live rows keyed by table name; and those rows are now
**surfaced in the carve workbook** (`TableHistory::without_rowid_rows` → the temporal sheet shows
them as present/live rows, replacing the bare "not version-tracked" note). All validated tier-2 vs
`sqlite3`. So `WITHOUT ROWID` tables are read AND shown, and the index is a usable second data
substrate.

**Deferred — carving DELETED index entries** is `§1.3`-class (precision-bounded), not a clean
slice. Byte-level investigation (real `sqlite3`, `secure_delete=OFF`): a deleted index cell loses
its **leading 4 bytes** to the freeblock header — the `[payload-len][header-len][serial-array]`
prefix — for a lone deletion *and* every cell of a coalesced run alike. The record *body* survives
but the *serial array* that delimits its columns is destroyed, so recovery needs the full
template-reconstruction machinery (re-derive the header from a same-page template + exact-tiling
validation) — the same large, precision-delicate engine `§1.3` flags as the precision-risk zone.
And there is a genuine **information-theoretic limit**: for a small pure-TEXT key (e.g. a 2-column
key table) the column split is unrecoverable from the page alone (`dddDEL-ddd` could split many
ways; nothing disambiguates it). The honest achievable yield is Tier-2 *fragments* on 3+ column
tables where trailing serials survive — deliberately not pursued here rather than ship a fragile,
fixture-gaming carver that violates the precision discipline. **Also open:** following index-key
overflow chains. See the Shipped table.

---

## 2. Large-artifact handling & robustness

*(§2.1 anti-forensic fingerprinting, §2.2 writer fuzzing, §2.3 encrypted-DB
diagnostics — all shipped; see the Shipped table above.)*

---

## 3. Library / API & fleet hygiene

*(§3.1 forensicnomicon constants — shipped: the four page-1 header offsets
(reserved-space 20, in-header DB-size 28, freelist-count 36, text-encoding 56) were
promoted into `forensicnomicon::sqlite` (≥ 1.5.0) and are now consumed here; the
local duplicates are gone. See the Shipped table.)*

*(§3.2 Python bindings — shipped: the standalone `python/` pyo3 crate exposes
`carve`/`audit`/`timeline`, built + tested end-to-end with maturin. See the Shipped table.)*

---

## 4. Forensic workflow & output

*(§4.2 delete+reinsert surfacing, §4.3 confidence-band calibration — shipped; see
the Shipped table above.)*

*(§4.4 uniform provenance — shipped: the overflow-chain / WAL-frame method
provenance every renderer dropped is now surfaced in the structured JSONL output.
§4.5 standards export + blob typing/hashing — shipped: magic-based media typing +
SHA-256 content hashing for recovered BLOBs, surfaced in JSONL and as a CASE/UCO
`-f case` bundle. Both in the Shipped table. Note: §4.5 uses SHA-256 (the
court-standard content address) rather than `blazehash` for evidence integrity.)*

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
