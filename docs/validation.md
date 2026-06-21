# Tool Validation — `sqlite-forensic`

Validation, and a documented validation record, are a baseline requirement for a
forensic tool: results have to be defensible, which means every capability is checked
against a reference the authors did not write, and the regime is written down. This
document is that record. It opens with the **whole-tool validation regime** (the
coverage backstop and the independent-oracle suite across every capability), then gives
the detailed **deleted-record carving differential** — the Doer-Checker evidence for how
the carver's output was reconciled against independent reference tools so that
correctness is not asserted only by tests we wrote against a fixture we generated. The
machine-checkable form of the differential is `forensic/tests/oracle_differential.rs`.

## Validation regime (whole-tool)

Validation here has **two layers**: a regression backstop (test coverage) and the
substantive validation (independent oracles + third-party ground truth). The first
proves the code is *exercised*; the second is what establishes the results are *right*.

### Layer 1 — coverage backstop (every function exercised)

CI enforces **100% function coverage** of the workspace
(`cargo llvm-cov --all-features --fail-under-functions 100`): every function in
`sqlite-core`, `sqlite-forensic`, and the `sqlite4n6` CLI is executed by the test suite
on every push, on **Linux, macOS, and Windows**. Per our coverage discipline this is a
**regression backstop that proves real behaviour is exercised — not, by itself, proof of
correctness** (line coverage runs lower where reader-generic code monomorphizes; the
function gate is the meaningful invariant). The substantive validation is Layer 2. The
full Paranoid-Gatekeeper gate runs alongside on every push: `rustfmt`, Clippy
(`-D warnings`), the 3-OS test suite, `cargo-deny` (licenses/advisories/sources), an MSRV
build (1.96), a `gitleaks` secret scan, docs-as-error, and libFuzzer harnesses over
`Database::open`, the carver, and the auditor. The whole workspace is `forbid(unsafe)`.

### Layer 2 — independent oracles (the substantive validation)

No test we authored is independent of our own assumptions, so each capability is checked
against a reference we did not write. Seven distinct authors/engines (the SQLite team,
undark's author, fqlite's author, bring2lite's author, Mari DeGrazia / SQL-DRP, the
Nemetz team, the DC3 team) plus the `calamine` reader, across C / Java / Python /
SQLite-C / Rust. The **Tier** column is the trust axis defined in *Input provenance*
below: **1** = real third-party ground truth / real-device data; **2** = real-engine
bytes checked by a derivable answer key or an independent oracle (`sqlite3` / `calamine`),
with the scenario chosen by us; **3** = we authored both fixture and expected answer with
no independent check:

| Capability | Independent reference | What it establishes | Tier | Machine-checked in |
|---|---|---|:-:|---|
| Deleted-record **recall & precision** | **Nemetz SQLite Forensic Corpus** (DFRWS-EU 2018, CC0) — the full **141-DB** v2.0 corpus (incl. 9 anti-forensic categories) whose authors shipped a per-row deleted **answer key** | recall + precision as a reproducible per-DB confusion matrix against **third-party ground truth** (the authors wrote both the deletions *and* the key) | 1 | `nemetz_metrics.rs` · [`recovery-comparison.md`](recovery-comparison.md) |
| **Header / encoding reporting** (UTF-8, UTF-16LE, UTF-16BE; page size) | **NIST CFReDS / CFTT** SFT-01 — real-device DBs, NIST-published ground truth + MD5s | page size + text encoding + 100-row table read correctly across all three on-disk encodings (real-device replacement for the self-minted UTF-16 fixtures) | 1 | `cfreds_encoding.rs` |
| **Deleted/modified records** (WAL substrate) | **NIST CFReDS / CFTT** SFT-03 — 100 documented deletes in an uncheckpointed WAL | main-only (pre-delete, 2240 rows) and WAL-applied (post-delete, 2140) states both surfaced, matching NIST's documented delta of 100 | 1 | `cfreds_recovery.rs` |
| **Deleted + modified records** (rollback-journal substrate) | **NIST CFReDS / CFTT** SFT-03 PERSIST — 100 documented deletes + 100 modifications in a `-journal` (ios + android) | `carve_rollback_journal` recovers **100/100 deletes + 100/100 modified prior values** by diffing the journal's pre-transaction snapshot against the live db; the derived oracle (`{1..=2240} \ live PKs`) is cross-checked against NIST's documented IDs | 1 | `cfreds_journal_recovery.rs` |
| **Rollback-journal anomalies** — RECOVERABLE, SCHEMA-CHANGE arms | the real **NIST SFT-03 PERSIST** artifact + a real-engine committed-DDL PERSIST journal (`ddl_persist`) | `audit_journal` fires PERSIST-RECOVERABLE on the NIST artifact, and SCHEMA-CHANGE only when the journal's prior page-1 schema cookie differs from the live db's — so DML-only NIST PERSIST does **not** raise it | 1 | `cfreds_journal_anomaly.rs`, `hot_journal_anomaly.rs` |
| **Rollback-journal anomalies** — HOT, CHECKSUM-MISMATCH, DUPLICATE-PAGE, DBSIZE-DELTA arms | a real-engine-minted **hot** journal (`hot.db-journal`) + crafted variants (NIST's artifact is PERSIST-only, so these arms have no real-corpus instance) | `audit_journal` emits the "consistent with" observation for each arm, each showing the offending value; ground truth derivable from the journal-header construction | 2 | `hot_journal_anomaly.rs` |
| **Deleted records — real-case, end-to-end** | **NIST CFReDS *Data Leakage Case*** — the Google Drive `snapshot.db` carved from a **Volume Shadow Copy** of the 20 GB PC image; NIST's published answer to Q49 "what files were deleted from Google Drive?" | both deleted `cloud_entry` records NIST documents recovered — the clean freed row (`do_u_wanna_build_a_snow_man.mp3`) **and** the freeblock-clobbered one (`happy_holiday.jpg`, reconstructed from its surviving tail) — with the live `root` row never re-surfaced; independent artifact *and* answer key | 1 | `nist_dlc_snapshot.rs` |
| **Freeblock recovery, independent keys** (incl. 2-byte rowid / UTF-8) | **`sqlite-unhide`** (`little-brother/sqlite-unhide`) — nine hand-built DBs each with the tool author's per-case `.txt` answer key (env-gated, home-use, never committed) | the structural-noise invariant + the 2-byte-rowid (UTF-8 `09.db`) freeblock recovery confirmed against a key neither we nor our oracles wrote; this corpus **surfaced two real defects** our own fixtures missed, since fixed | 1 | `sqlite_unhide_corpus.rs` |
| **Dropped-table schema recovery** | a real `sqlite3`-minted drop fixture (`dropped_table_schema.db`; answer derivable from construction) | `recover_dropped_schemas` recovers a dropped table's name + `CREATE` statement from page-1 residue, never reports a live table; surfaced in `audit` as `SQLITE-DROPPED-SCHEMA-RECOVERED` | 2 | `dropped_schema.rs` |
| Deleted-record **carving** | `undark` (C), `fqlite` (Java) — independent carvers | inter-tool **concordance** (agreement, page-level-diagnosed — *not* correctness) | 1 | `oracle_differential.rs` (below) |
| Deleted-record **head-to-head** (carving) | `undark`, `fqlite`, **`bring2lite`** (Python 3), **SQL-DRP / `sqlparse`** (Python 2→3) — four independent carvers, each gated (`UNDARK_BIN` / `FQLITE_TAP` / `BRING2LITE_CMD` / `SQLDRP_CMD`), all scored against the same Nemetz answer key | per-tool precision/recall on the **same** `(col1,col2)` matcher; SQL-DRP's string-carver boundary recorded explicitly (0 cross-tool identities, not a confounded score) | 1 | `nemetz_tool_comparison.rs` · [`recovery-comparison.md`](recovery-comparison.md) |
| **False-positive benchmark** (B-tree rebalancing, drop+recreate, WAL+secure_delete) | a real-engine **replication** of the 2025 survey's Table-5 construction (Lee, Park, Lee & Choi, *FSI:DI* 55) — **not** the official corpus (not public yet) — scored vs `bring2lite` / SQL-DRP on identical bytes | 0 live-row false positives on the rebalancing scenario where `bring2lite` re-surfaces 13 live rows; FQLite scenario-10 figure is **cited from the paper**, not measured here (its WAL recovery is GUI-coupled) | 2 | `paper_fp_scenarios.rs` · [`competitive-landscape.md`](competitive-landscape.md) |
| **Live b-tree read** | `sqlite3 SELECT` — the engine that wrote the file | live rows read **byte-identical** to the canonical engine | 2 | `live_read_matches_sqlite3` |
| **`.recover` differential** | `sqlite3 .recover` | ours ⊇ `.recover`, 100% content agreement on the overlap | 2 | `our_fixture_agrees_with_sqlite3_recover` |
| **Rebuilt `.carved.db`** | `sqlite3` (`PRAGMA integrity_check`, `SELECT`) | the pure-Rust writer emits a valid DB an external engine reads identically | 2 | `rebuild_sqlite3_oracle.rs`, `rebuild_tables_oracle.rs` |
| **Snapshot-aware reads** (WAL per-commit, overflow-correct) | `sqlite3` on per-commit file snapshots | each commit's table state read byte-for-byte, incl. a 12 KB overflow blob | 2 | `wal_snapshot_oracle.rs` |
| **WAL version history** (current / superseded / deleted, rowid-reuse) | `sqlite3` minted mutation sequence | the per-rowid history matches a known insert/update/delete/reinsert script | 2 | `row_history_oracle.rs` |
| **Output XLSX** (combined temporal workbook, in-cell images) | `calamine` (independent XLSX reader) + `zip` (embedded media) | sheet structure, cell values, the flag columns, and the embedded image media read back and verified — the round-trip is independently checked; only the input image is synthetic | 2 | `cli/tests/cli_binary.rs` |
| **No-false-positive** regression | DC3 `sqlite_dissect` corpus — **third-party input** | 0 false positives on no-deletion / dropped-table DBs | 1 | `oracle_differential.rs` |
| **`table_instance_risk` hint** — Detector A (rowid > `sqlite_sequence`) | real `sqlite3`-minted drop-recreate fixtures + the `sqlite3` `sqlite_sequence` reading (answer derivable from construction) | the flag fires on AUTOINCREMENT residue whose `rowid` exceeds the high-water mark (`b_autoinc` 6..=10, `upd_autoinc` 1000 — a current-instance row, proving the flag is a hint, not a predecessor claim), never on the plain-PK recreate (`b_plainpk`), and on **zero** ordinary Nemetz deleted rows | 2 | `drop_recreate_risk.rs` |
| **`table_instance_risk` hint** — Detector B (sidecar schema change) | real `sqlite3`-minted `-journal` fixtures (answer derivable from construction) | the table-level flag fires when the sidecar's prior CREATE SQL differs (`b_journal_altered`, an `ALTER`), never on a DML-only sidecar (`b_journal_dml`) | 2 | `detector_b.rs` |
| **Real-device robustness** (no panic) | genuine **Josh Hickman iOS-17** application databases (env-gated, manually downloaded) | the full open → audit → carve pipeline survives every real iOS db **without panic** — a robustness sweep, NOT a known-answer recall test | 1 | `ios_realdata_robustness.rs` |
| **WAL frame integrity** | SQLite WAL §4.2 cumulative checksum | valid commits vs post-reset residue distinguished | 2 | known-vector unit test + `wal_snapshot_oracle.rs` |

### Input provenance — the three validation tiers

The axis that matters for a forensic tool is **whether the correctness check is
trustworthy**, not whether the input bytes were "synthetic". A fixture minted by the real
SQLite engine and read back by an independent reader is far better validated than a
hand-encoded fixture we also hand-scored — even though both are "synthetic input". So each
capability sits in one of three tiers. The one-line rule: **Tier 2 = an independent thing
(a derivable answer key, or `sqlite3` / `calamine`) confirms we're right; Tier 3 = only we
say we're right.**

**Tier 1 — real third-party ground truth / real-device data.** An independent third party
authored the artifact AND (for recall/precision) the answer key, or it is genuine device
data. Members:

- deleted-record carving **recall + precision** → the Nemetz **141-DB** corpus (its authors
  wrote both the deletions and the key);
- **text encoding** (UTF-8 / 16LE / 16BE) → NIST CFReDS **SFT-01**;
- **WAL** deleted/modified recovery → NIST CFReDS **SFT-03 WAL**;
- **rollback-journal** recovery (100/100 deletes + 100/100 modifications) → NIST CFReDS
  **SFT-03 PERSIST**;
- journal-anomaly **RECOVERABLE** and **SCHEMA-CHANGE** arms → fire on the real NIST PERSIST
  artifact;
- **real-case, end-to-end** deleted-record recovery → the NIST CFReDS *Data Leakage Case*
  `snapshot.db` (extracted from a Volume Shadow Copy of the 20 GB PC image; both deleted
  `cloud_entry` records in NIST's answer recovered, incl. the freeblock-clobbered one);
- **independent-key freeblock recovery** (2-byte rowid / UTF-8) → the third-party
  `sqlite-unhide` corpus (the author's per-case `.txt` keys);
- **overflow / fragments / freeblock** recovery → the Nemetz corpus;
- **corrupted-header robustness** → the SharifCTF damaged-header db;
- **no-false-positives** regression → the DC3 corpus;
- **inter-tool concordance** → undark / fqlite / bring2lite / SQL-DRP;
- **real-device no-panic robustness** → the Josh Hickman iOS-17 images (a robustness sweep,
  NOT a known-answer recall test).

**Tier 2 — real `sqlite3` engine bytes plus a *checkable* answer.** The input is produced by
the real engine (or read back by an independent reader), and ground truth is either
DERIVABLE from the documented construction OR confirmed by an INDEPENDENT oracle (`sqlite3`
/ `calamine`). The validation genuinely confirms correctness; the only weakness is that **we
chose the scenarios** (a coverage gap — it can miss real-world quirks we did not construct),
not that the check is untrustworthy. Members:

- `table_instance_risk` **Detector A** (rowid vs `sqlite_sequence`) and **Detector B**
  (sidecar schema-change) → real-engine-minted drop-recreate fixtures (answer derivable from
  the construction);
- journal anomalies **HOT / CHECKSUM-MISMATCH / DUPLICATE-PAGE / DBSIZE-DELTA** → a
  real-engine-minted hot journal + crafted variants (NIST's artifact is PERSIST-only, so
  these four arms have no real-corpus instance);
- the survey **false-positive benchmark** (0F / 0B / 10) → a real-engine **replication** of
  the paper's Table-5 construction (NOT the byte-identical official corpus, which is not
  public yet);
- **throughput** → a minted ~100 MB db;
- plus the pre-existing WAL **version history / rowid-reuse**, **snapshot reads**, the
  rebuilt `.carved.db`, and the **in-cell image thumbnails** (`calamine` reads the embedded
  media back, so the round-trip IS checked; only the input image is synthetic) →
  minted-at-test-time and checked against `sqlite3` / `calamine`.

**Tier 3 — only WE vouch for it.** We authored BOTH the fixture AND the expected answer, with
NO independent check, and the scenario is not confirmed to occur in real data (the maximal
Doer-Checker / "LZNT1 trap" risk). By this strict definition Tier 3 is essentially **just the
freeblock-clobbered *spilled*-cell path** — `core/src/lib.rs` notes its "real-data behavior is
not yet observed", and it is flagged **`unproven-by-corpus`** in the code and here. Note in
particular that the **in-cell image thumbnail is Tier 2, not Tier 3**: `calamine` independently
reads the embedded media back, so the round-trip is checked.

### Epistemic stance

Precision is **confirmed against independent ground truth** (0 live-row re-reads; the
highest precision in the comparison); recall is **measured**, with a documented in-page
gap. Differentials are **concordance**, not correctness. There are **no wall-clock
timestamps** in the SQLite WAL — the temporal columns surface *logical* commit order
(`commit_seq`), never time. Carved records remain **confidence-graded observations**
("consistent with a deleted row"), never a verdict: the tool is validated as *consistent
with* independent references, **not proven correct**.

**Limitations that bound these tiers, stated plainly:**

- A **same-schema drop+recreate** is undecidable from a single snapshot AND from a sidecar
  (it is indistinguishable from a benign `VACUUM` page-move). `table_instance_risk` flags only
  AUTOINCREMENT rowid-overflow (Detector A — a *hint*, not proof) and UNAMBIGUOUS sidecar
  schema changes (Detector B — different CREATE SQL, or the table absent in the prior), never
  the same-schema case.
- **DELETE-mode** (the `-journal` is unlinked) and **TRUNCATE-mode** (it is zeroed) rollback
  journals leave no in-band residue — recovering those is a disk-carving-layer concern, out of
  scope here.
- **Encrypted databases** (SQLCipher / SEE) are out of scope.
- The survey **false-positive benchmark is a replication** of the paper's construction, not the
  official corpus (which is not public yet); and **FQLite scenario-10** (WAL + `secure_delete`)
  is **cited from the paper**, not measured here, because FQLite's WAL recovery is GUI-coupled.
- A **Boyer-Moore signature scan** is inapplicable by design — this carver is structural (it
  reads the b-tree / freelist / journal layout), not signature-based.

> **This document is the historical *differential* record; the current capability
> matrix lives in [`recovery-comparison.md`](recovery-comparison.md).** The page-level
> findings below remain accurate as the record of how each tool draws the
> freelist/allocated boundary, but several carver *scope boundaries* they describe are
> now closed — so read the per-scenario **numbers and the "Summary" section below as
> the pre-fix snapshot** and defer to `recovery-comparison.md` for current numbers:
>
> - `carve_all_deleted_records` added **in-page free-block carving** and
>   **dropped-table carving**, so on the fixture it recovers the in-page remnant
>   (rowid 237) and **exactly matches undark**, and it recovers the DC3 dropped-table
>   rows. Where this doc says "our freelist-only carver recovers none" of those cases,
>   that is the *pre-fix* state.
> - It then added **value-aware prior-version recovery**: an `UPDATE`'s freed old
>   version (same rowid, *different* values) is recovered (tagged `PriorVersion`), not
>   dropped. The differential test (`oracle_differential.rs`) asserts agreement now,
>   plus a prior-version reconciliation, rather than the former exemptions.
>
> The Summary's "consistent with / agree exactly" statements describe the
> **freelist-page differential** specifically and still hold for that scenario; they
> are not the whole-corpus capability claim — for that, see `recovery-comparison.md`.

## Summary

- **Conclusion:** on the freelist-page deletion scenario our carver is designed for,
  its output is **consistent with** three independent references — `undark` (C),
  `fqlite` (Java), and SQLite's own `.recover` — with **100% content agreement on every
  overlapping row** and no false positives. Where the tools overlap on our fixture, they
  agree exactly.
- **Two independent oracles, two corpora.** `undark` and a headless source-instrumented
  tap of `fqlite`'s recovery engine are both used as oracles; our `deleted_places.db`
  fixture and the third-party DC3 `sqlite_dissect` corpus are both used as input.
- **The reference implementation itself, as a third oracle.** SQLite's own
  `sqlite3 .recover` is added as a third deleted-record oracle: on the fixture it
  recovers the freelist-**leaf** subset (124 rows, ids 277..=400) into its
  `lost_and_found` table — **every one of which our carver also recovers** (ours ⊇
  `.recover`). Separately, `sqlite3 SELECT *` validates the **live-read foundation**:
  our base parser reads **byte-identical** rows to the engine that wrote the file
  (all 200 live rows, no deleted-row leakage). Both are machine-checked in
  `oracle_differential.rs` (`our_fixture_agrees_with_sqlite3_recover`,
  `live_read_matches_sqlite3`), gated on a `sqlite3` binary so CI without it still
  passes. Three different authors, three algorithms (C / Java / SQLite's own C),
  plus the canonical engine as the live-read yardstick.
- **Divergences are diagnosed at the page level, not papered over.** Each tool draws the
  freelist-vs-allocated and trunk-vs-leaf boundaries slightly differently; every
  ours-vs-oracle difference is explained by *which page* a row lives on and *which pages
  each tool scans*. None is a defect in our freelist-carving path.
- We make no claim that our carver is "proven correct". The evidence supports only that
  its freelist-page recovery is **consistent with** three independent tools' recovery.

## The oracles

### Oracle 1 — `undark` (C)

| | |
|---|---|
| Tool | `undark` |
| Version | 0.7.1 (Paul L. Daniels) |
| Upstream | <https://github.com/inflex/undark> |
| Source tarball (master) | <https://github.com/inflex/undark/archive/refs/heads/master.tar.gz> |
| Source tarball sha256 | `c0a9ee7ebd180727deef52fbafe0ef0e2b7c9b43c5604761bfeb86bc9306912a` |
| Local binary | `tools/undark` (gitignored, not committed) |
| Test gate | `UNDARK_BIN` |

### Oracle 2 — `fqlite` (Java), via a headless source-instrumentation tap

fqlite was the originally-named oracle. Its command-line mode was removed in v2.0
(README: *"With version 2.0, the support for the command line mode was cancelled"*),
releases ship only ~440 MB `JavaFX` `jpackage` installers (no runnable CLI jar), it is
**not on Maven Central**, and its repo ships no test databases. So it cannot be used as
a packaged CLI oracle.

**But fqlite IS usable as an oracle via source instrumentation** — the CLI cancellation
was the only blocker, not the engine. fqlite's carving engine (`fqlite.base.Job`) is
plain Java that populates a result list the GUI merely reads. A small headless tap
(`tools/fqlite/HeadlessTap.java`) constructs `Job`, runs `Job.run(path)`, and emits the
recovered DELETED records as CSV — never launching the JavaFX UI. The engine is not
cleanly decoupled from JavaFX in the current source (its logger's static init builds a
JavaFX `TextArea`, `processDB()` posts a `Platform.runLater` cleanup fence and calls
`gui.add_table` unguarded), so the tap (a) null-guards those `add_table` calls, (b) sets
`GUI.baseDir`, and (c) boots the JavaFX *toolkit* headlessly (no window). The full engine
API map, the JavaFX-coupling findings, and the minimal changes a clean
`fqlite.base.MAIN` revival would need are in `tools/fqlite/ENGINE_NOTES.md`.

| | |
|---|---|
| Tool | `fqlite` (recovery engine) |
| Version | 4.22 |
| Commit | `26922bd9e3cdc60c93b72dfb1fb2f5972a0af6a6` |
| Upstream | <https://github.com/pawlaszczyk/fqlite> |
| Driver | `tools/fqlite/HeadlessTap.java` + `run-tap.sh` (gitignored; recipe in `tools/fqlite/README.md`) |
| Test gate | `FQLITE_TAP` |

(`sqlite_dissect` was also evaluated as an oracle but its free-block carver produced
misaligned/garbled column boundaries on these fixtures — recovering corrupt `title`
values and surfacing live rows — so it was rejected as a yardstick. Its *test databases*,
authored by DC3, are still used as independent *input*; see below.)

### Oracle 3 — `sqlite3` (the canonical reference implementation)

`undark` and `fqlite` are third-party carvers. The strongest possible independent
reference is **SQLite itself** — the engine that wrote the file. It serves two distinct
roles, both gated on a `sqlite3` binary (`SQLITE3_BIN` overrides; tests skip if absent):

| | |
|---|---|
| Tool | `sqlite3` (the `.recover` dot-command + `SELECT`) |
| Version | 3.45.3 (validated); any modern `sqlite3` with `.recover` |
| Upstream | <https://sqlite.org/cli.html#recover> |
| Roles | (a) deleted-record carving oracle via `.recover`; (b) live-read yardstick via `SELECT` |
| Test gate | `SQLITE3_BIN` (defaults to `sqlite3` on `PATH`) |
| Machine-checkable | `our_fixture_agrees_with_sqlite3_recover`, `live_read_matches_sqlite3` |

**Role (a) — `.recover` as a third carving oracle.** `sqlite3 .recover` is SQLite's own
corruption-recovery command; it reconstructs reachable content into a `lost_and_found`
table. On the fixture it recovers **exactly the freelist-leaf rows (124 rows, ids
277..=400)** — the subset every carver agrees on — and **nothing our carver misses**. Our
carver additionally reaches the freelist **trunk-page body** (238..=276), so
**ours ⊇ `.recover`**: the reference engine's own recovery is contained in ours, with full
content agreement on the overlap. The harness reloads `.recover`'s dump into an in-memory
db and `SELECT`s the rows back out, so SQLite parses its own output (no hand-rolled
SQL-literal parser).

**Role (b) — `SELECT` as the live-read yardstick.** Before any carving, the base parser
must read the *intact* b-tree correctly. `live_read_matches_sqlite3` asserts our
`Database::live_rows()` is **byte-identical** to `sqlite3 SELECT id, url, title FROM
moz_places` — all **200 live rows (ids 1..=200)**, no deleted-row leakage. This validates
the foundation the carving sits on against the engine that authored the file. (Note: the
carving oracles above already use `sqlite3` incidentally to compute the live set that
distinguishes recovered-deleted rowids from live ones; this test makes that dependency an
explicit, asserted parity check.)

### `undark` build recipe (macOS / clang)

### Build recipe (macOS / clang)

Upstream undark uses two GCC nested-function definitions and a function named `ntohll`
that collides with the macOS `<sys/_endian.h>` `ntohll` macro, so it does not compile
with clang out of the box. Two minimal, behavior-preserving patches make it build:

1. Hoist the nested `swap64` / `ntohll` helpers out of `decode_row` to file scope.
2. Rename undark's `ntohll` to `u_ntohll` to avoid the macOS macro collision.

```sh
curl -sL https://github.com/inflex/undark/archive/refs/heads/master.tar.gz | tar xz
cd undark-master
# patch 1+2 (see tools/undark.c.patched for the exact patched source)
make                     # produces ./undark
./undark -V              # => undark version 0.7.1, by Paul L Daniels
```

The exact patched source is kept at `tools/undark.c.patched` (gitignored) for
reproducibility.

### CLI invocation

undark dumps every record it can reconstruct (live + recovered-deleted) to stdout as CSV,
one record per line: `rowid,id,col1,col2,…`. The command used by the test is simply:

```sh
undark -i <database.db>
```

Deleted rows are identified by rowid: any recovered rowid that is **not** present in the
live b-tree (read via `sqlite3`) is a recovered-deleted record. (`--freespace` scans free
*blocks within allocated pages*; it returns nothing on these fixtures because the deleted
content there is on freed whole pages, not in allocated-page free blocks.)

### `fqlite` tap invocation

```sh
FQLITE_TAP=tools/fqlite/run-tap.sh
"$FQLITE_TAP" <database.db>   # -> CSV: rowid,col1,col2,...  (recovered DELETED rows)
```

fqlite often cannot recover a carved row's rowid (emits `-1`), so the fqlite comparison
is keyed by the row's text content (url), not rowid. Build recipe in
`tools/fqlite/README.md`; engine API map in `tools/fqlite/ENGINE_NOTES.md`.

## Comparison projection

Each tool's output is reduced to the same identity per row: the `url`/`title`
(moz_places) or `name`/`surname` (DC3 `users`) text columns at record positions 1 and 2.
The undark comparison keys by rowid; the fqlite comparison keys by url (fqlite does not
always recover the rowid). Agreement is defined on this projection.

## Results

### Corpus 1 — our fixture (undark AND fqlite as oracles over our input)

`forensic/tests/data/deleted_places.db` — `moz_places`, 400 rows inserted, ids 201..=400
`DELETE`d without `VACUUM` under `secure_delete=OFF`; freed whole leaf pages onto the
freelist. Ground truth: 200 live (1..=200), 200 deleted (201..=400). Freelist =
trunk page 9 + leaf pages 10,11,12,13.

Recovery over the deleted range (ids 201..=400):

| tool | recovers | which rows |
|---|---|---|
| our carver | **162** | 238..=400 (except 250) |
| undark | **163** | 237..=400 (except 250) |
| fqlite | **126** | 235, 237, and 277..=400 |
| `sqlite3 .recover` | **124** | 277..=400 (freelist-leaf only) |

`sqlite3 .recover` recovers the freelist-**leaf** rows (277..=400) into `lost_and_found`
and nothing else — it reaches neither the freelist trunk-page body (238..=276, which our
carver and undark recover) nor the allocated-page in-page free blocks (235, 237, which
undark and fqlite recover). Its set is therefore a strict subset of ours, with full
content agreement: **every row the reference engine recovers, we recover too.**

Agreement:

| comparison | result |
|---|---|
| content agreement (url + title) on every overlapping row | **100%, 0 mismatches** (all four tools) |
| our false positives (rows we carve no oracle corroborates) | **0** |
| ours vs undark | ours ⊇ undark minus 1 row (237); **162/163 = 99.4%** |
| ours vs fqlite | ours adds 238..=276; fqlite adds 235, 237 — all explained below |

**Why the three tools draw the freelist boundary differently — page-level diagnosis:**

- **Rows 277..=400 live on freelist *leaf* pages 10–13.** All four tools carve these. ✓
- **Rows 238..=276 live on page 9, the freelist *trunk* page.** Our carver and undark
  scan the trunk page body (below its small 8-byte trunk header + leaf-pointer array) and
  recover them. **fqlite reads page 9 only as a trunk** (next-pointer + leaf-pointer
  array) and does **not** carve record content from its body — so fqlite misses 238..=276.
  This is a genuine fqlite-specific behaviour, not a defect in either carver.
- **Rows 235, 237 live on page 8, a still-*allocated* leaf page** (in-page free blocks
  from rows deleted in place). undark (byte-by-byte) and fqlite (in-page free-block carver)
  reach them; our carver scans only freelist pages by design, so it skips them — the same
  safety property (never re-surface content from an allocated page) seen in the DC3 corpus.
- **Rows 201..=236 and 250** are recovered by no tool: their cells were overwritten by the
  freelist trunk header / leaf-pointer array when the pages were freed.

Both divergence sets are encoded as explicit, asserted exemptions in the test
(`FIXTURE_IN_PAGE_DIVERGENCES` / `FQLITE_IN_PAGE_DIVERGENCES` for the allocated-page rows;
`FQLITE_TRUNK_PAGE_DIVERGENCES` for the trunk-page rows). Each is asserted to be a *real*
disagreement, so a future carver change that closes a gap fails the test and forces the
exemption to be re-derived rather than silently passing.

### Corpus 2 — DC3 `sqlite_dissect` test corpus (independent input *and* independent oracle)

The Department of Defense Cyber Crime Center (DC3) `sqlite_dissect` test databases were
authored by neither us nor undark's author, so for these cases **neither the input DB nor
the oracle is ours** — the strongest Doer-Checker form. Provenance + hashes are in
`tests-oracle-corpus/README.md` and `docs/corpus-catalog.md`. The DBs with carvable
deleted records:

| DB | table cols | freelist_count | undark recovers | fqlite recovers | our carver recovers | agreement |
|---|---|---|---|---|---|---|
| `corpus_01-01.db` | 4 | 0 | 10 | 6 | 0 | documented gap |
| `corpus_01-02.db` | 4 | 0 | 10 | 6 | 0 | documented gap |
| `corpus_03-02.db` | 4 | 0 | 11 | 7 | 0 | documented gap |
| `corpus_07-01.db` | 4 | 0 | 19 | 7 | 0 | documented gap |
| `corpus_0A-01.db` | 6 | 1 | 20 | 20 | 0 | documented gap |
| `corpus_0A-02.db` | 6 | 1 | 10 | 19 | 0 | documented gap |

Both independent oracles (undark and fqlite) recover deleted rows from these in-page /
dropped-table DBs; our freelist-only carver recovers none — the same documented scope
boundary, now corroborated by two tools rather than one.

**Divergence — our carver recovers 0 from every DC3 case (documented scope boundary).**
This is the load-bearing independent finding. These DBs delete records **without freeing
whole pages onto the freelist** (`freelist_count = 0` for the in-page cases) or **drop a
table entirely** (`0A-01`/`0A-02` have no table in `sqlite_master`; the dropped table's
page went on the freelist). The deleted content therefore lives in **free blocks inside
still-allocated b-tree pages** or in **dropped-table pages**, neither of which our
freelist-page scan covers. undark, scanning byte-by-byte, recovers them.

We did **not** "fix" this by bolting on in-page free-block carving: that is a new
capability (a feature), not a bug in the freelist path, and adding it under a validation
task would exceed scope. It is recorded here honestly as the carver's current boundary and
asserted explicitly in the test (each DC3 case asserts our carver recovers **0** here — if
a future in-page carver lands, the assertion fires and forces a re-reconciliation against
undark rather than passing silently). On the cases where undark and ours overlap, content
agreement is required and holds (vacuously, since our set is empty); our carver produces
**no false positives** on any DC3 DB.

## What this validates, and what it does not

- **Validates:** the freelist-page carving path — the scenario our carver targets — is
  consistent with **three** independent tools' recovery (100% content agreement, no false
  positives; 99.4% recall vs undark, full agreement vs fqlite outside the trunk-page rows
  fqlite structurally skips, and a clean superset of SQLite's own `.recover`). Separately,
  the **live-read foundation** is byte-identical to `sqlite3 SELECT *` (the canonical
  engine) on all 200 intact rows — so the b-tree parse the carving builds on is validated
  against the implementation that authored the file.
- **Does not validate / out of scope:** in-page free-block recovery and dropped-table
  recovery. Both undark and fqlite recover these; our carver does not — surfaced here as
  the documented divergence and the candidate next feature, not claimed as working.
- **Epistemic stance:** carved records remain confidence-graded observations
  ("consistent with a deleted row"); this validation likewise establishes *consistency
  with* two independent oracles, not proof of correctness.

## Chain-aware overflow recovery (task #73)

Deleted rows whose payload spilled onto a SQLite **overflow-page chain** are recovered
when every chain page survives as a freelist **leaf** (content-preserving). The
validation evidence:

- **Independent byte-equality substrate.** The ground-truth generator
  (`tests/data/nemetz/gen_ground_truth.py`, `chain_followable`) decides recoverability
  purely from the raw `.db` bytes, with no reference to our carver: it rebuilds the
  expected record payload from the answer key, finds its local-payload prefix, walks the
  chain through the file's freelist leaves, and requires the assembled bytes to equal the
  expected payload **exactly**. This is the substrate oracle for the overflow class.
- **Real-corpus probe (`0E-01.db`).** Two deleted rows genuinely overflow. `Ella`
  (`id = 20012`, chain page 13 — a freelist leaf) reassembles byte-perfect and is
  recovered as a Tier-1 full row with chain provenance `[13]`. `Matteo`
  (`id = 20003`, chain page 5 — reallocated as the freelist trunk, head clobbered) does
  **not** reassemble: it is rejected from Tier-1 and surfaces only as a Tier-2 fragment
  (`id`, `name` from its intact local prefix). Asserted in
  `forensic/tests/overflow_chain.rs`.
- **Differential.** Against the `Drec = 4` denominator, ours recovers all 4 at precision
  1.000; undark 3/4, fqlite 2/4 (`recovery-comparison.md`). The destroyed `Matteo` chain
  is the corpus's built-in false-positive probe: a carver that "recovers" it as a full
  row is wrong.

- **Residual risk (documented, not hidden).** Overflow Tier-1 is **not** part of the
  in-page tier's structural 0-false-positive guarantee. A freelist leaf can be *stale* —
  allocated, overwritten, freed, and now a leaf holding unrelated bytes that happen to
  decode. The freelist-leaf requirement plus a strict-UTF-8 reject gate make a clean
  decode strong evidence, but cannot *prove* the reassembled bytes are the original
  record (a stale leaf with valid-UTF-8 content of matching length is not detectable).
  The chain-reassembled row is therefore graded **below** the in-page full-row tier and
  remains a "consistent with a deleted row" observation, never a verdict. A synthetic
  negative test (`forensic/tests/overflow_chain.rs`) exercises this rejection path.
- **Out of scope / unproven.** A freeblock-clobbered *spilled* cell (prefix destroyed
  AND payload spilled) is reconstructable in principle (P re-derived from the surviving
  serial array) but has **no instance in this corpus**, so it is validated against a
  **synthetic fixture only** and marked unproven-by-corpus in the code and here. WAL-frame
  resolution of spilled cells is also deferred.
