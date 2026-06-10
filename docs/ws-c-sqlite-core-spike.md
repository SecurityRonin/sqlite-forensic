# WS-C Spike — Native `sqlite-core` Reader: Go / No-Go

## Executive Summary

**Verdict: GO.** A native, read-only, panic-free `sqlite-core` is both *worth
building* and *feasible*. The feasibility prototype in this crate parses the
100-byte SQLite file header and walks a table b-tree, decoding records into
typed values — panic-free and bounds-checked — and its output was differentially
validated against the `sqlite3` CLI on a **real `.db` file**. The native path is
not merely as good as the current `rusqlite` route; for forensics it is
**strictly safer** (no FFI, no checkpoint risk, panic-bounded on crafted input)
and unlocks a capability rusqlite *cannot* provide: recovery of deleted /
freelist / unallocated records.

Recommendation: greenlight **WS-E** (`sqlite-forensic`) to build the full reader
(index b-trees, overflow pages, WAL overlay) plus the carving analyzer on top of
this `sqlite-core` foundation. Migrating `browser-core` off rusqlite onto
`sqlite-core` is the *eventual* payoff but must be **deferred** until the
in-flight browser-forensic (br4n6) work lands — that migration touches
browser-forensic, which is live.

This is a spike: it proves the **header + one table-walk** path. It does **not**
yet implement index b-trees, overflow pages, WAL overlay, or carving. Those are
WS-E scope. The prototype was validated only against a `sqlite3`-CLI-built `.db`
(not yet against a real browser `places.sqlite`/`History`) — stated honestly so
the validation claim is not overstated.

---

## What the prototype proves

| Capability | Status in this spike |
|---|---|
| Validate `SQLite format 3\0` magic + page-size field (incl. value-1 → 65536) | ✅ proven, tested |
| Consume `forensicnomicon::sqlite` constants (no re-hardcoding) | ✅ done |
| Walk a table b-tree: interior (`0x05`) + leaf (`0x0d`) | ✅ proven (recursion + right-most ptr) |
| Decode record serial types → `Null`/`Integer`/`Real`/`Text`/`Blob` | ✅ all storage classes |
| `INTEGER PRIMARY KEY` rowid-alias rule (serial 0 in col 0 → rowid) | ✅ proven |
| Panic-free, bounds-checked reads on malformed/truncated input | ✅ fuzz-style prefix test |
| Differential validation vs `sqlite3` SELECT on a REAL `.db` | ✅ done (see below) |
| Index b-trees, overflow pages, WAL overlay, freelist carving | ❌ out of scope (WS-E) |
| Validated against a real browser `places.sqlite`/`History` | ❌ not yet (synthetic real `.db` only) |

### Validation evidence (Doer-Checker)

The test DB was **built with the real `sqlite3` CLI**, not synthesised in Rust:

```
sqlite3 tests/data/places.db <<'SQL'
CREATE TABLE moz_places (
  id INTEGER PRIMARY KEY,
  url TEXT NOT NULL,
  title TEXT,
  visit_count INTEGER DEFAULT 0,
  last_visit_date INTEGER,
  frecency REAL
);
INSERT INTO moz_places (url, title, visit_count, last_visit_date, frecency) VALUES
 ('https://www.rust-lang.org/', 'Rust Programming Language', 5, 1700000000000000, 2000.5),
 ('https://github.com/', 'GitHub', 12, 1700000100000000, 5500.0),
 ('https://news.ycombinator.com/', 'Hacker News', 3, NULL, -1.0),
 ('https://en.wikipedia.org/wiki/SQLite', 'SQLite - Wikipedia', 1, 1700000200000000, NULL),
 ('https://example.com/', NULL, 0, 1700000300000000, 0.0);
SQL
```

(`sqlite3 3.45.3`, page_size 4096, 2 pages.) The reader's rows were cross-checked
against:

```
sqlite3 tests/data/places.db \
  "SELECT id,url,title,visit_count,last_visit_date,frecency FROM moz_places ORDER BY id;"
```

**A real forensic distinction surfaced during validation.** `frecency` is a
`REAL`-affinity column, yet `5500.0`, `-1.0`, and `0.0` are stored on disk with
**integer** serial types — SQLite stores integral-valued reals compactly. So:

- `rusqlite` returns `5500.0` (applies the column's REAL **affinity** at the SQL layer).
- `sqlite-core` returns `Integer(5500)` (reports the on-disk **storage class**).

For forensics the native answer is the more faithful one: it tells the analyst
*what is actually on disk*, byte-for-byte, with no affinity transformation
interposed. This is documented in the integration test and is exactly the kind of
ground-truth fidelity a from-scratch reader exists to give.

---

## Design for the full `sqlite-core` (what WS-E builds)

Read-only by construction; consumes `forensicnomicon::sqlite` for all format
constants. Layered as the fleet's `*-core` reader, with `sqlite-forensic` the
analyzer on top.

1. **Backing store.** Spike holds the file in `Vec<u8>`. Full crate: a
   `Read + Seek` or mmap backend (same parsing logic; only `page_slice` changes).
2. **File header** (§1.3): page size, reserved bytes, freelist trunk, in-header
   DB size, text encoding (UTF-8/16-le/16-be — spike assumes UTF-8 via lossy
   decode), schema format.
3. **Schema discovery.** Parse `sqlite_schema` (root page 1) to map table/index
   names → root pages, so callers select tables by name rather than page number
   (spike targets page 2 directly).
4. **B-tree walk** (§1.6): table + index, interior + leaf. Spike does table
   interior+leaf; add index pages and **overflow-page chains** for large payloads.
5. **Record decode** (§2.1): serial types → typed values. Spike covers all
   storage classes; add UTF-16 text and overflow-spill reassembly.
6. **WAL-aware overlay** (the forensic-correctness crux). Read the `-wal`
   sidecar's frames as an overlay *without checkpointing* — apply the newest
   committed frame per page number on top of the main file. This is where native
   beats rusqlite decisively (see trade-off below).
7. **Carving (the forensic upside).** Freelist trunk/leaf pages, unallocated
   regions between the cell-pointer array and cell content, and freeblocks within
   a page all retain **deleted record bytes**. A native reader can scan these and
   recover dropped rows; rusqlite cannot see them at all.

`sqlite-forensic` (WS-E) then emits `forensicnomicon::report::Finding`s
(tampering, checkpoint anomalies, recovered-deleted-row residue) via
`impl Observation`, mirroring ntfs-forensic.

### Constants to promote into `forensicnomicon::sqlite`

The KNOWLEDGE leaf currently exposes magic, header size, page-size offset,
freelist-trunk offset, and WAL sizes — but **not** B-tree page-type bytes
(`0x05`/`0x0d`/`0x02`/`0x0a`), serial-type rules, the reserved-space offset (20),
or the in-header DB-size offset (28). The spike hardcodes `RESERVED_SPACE_OFFSET`
locally and inlines page-type bytes; WS-E should add these to
`forensicnomicon::sqlite` so the analyzer fleet shares one source of truth.
(This is a forensicnomicon change — flagged here, **not** made in this spike,
since forensicnomicon is live under other agents.)

---

## rusqlite vs native `sqlite-core` — honest trade-off

| Dimension | `rusqlite` (FFI → libsqlite) | native `sqlite-core` |
|---|---|---|
| **Read-only safety** | Risk: a read-write open can checkpoint a `-wal` on close, **mutating the evidence**. Mitigated today by `open_evidence_db` (immutable URI / temp-copy), but the safety lives in *discipline*, not structure. | Structurally read-only: the parser never writes. Secure-by-construction. |
| **WAL correctness** | `immutable=1` silently **drops uncheckpointed rows**; the workaround copies `{db,-wal,-shm}` to a temp dir and opens the copy. Works, but is I/O + temp-file machinery. | Reads the `-wal` as an overlay directly, no checkpoint, no temp copy. |
| **Deleted/freelist/unallocated carving** | **Impossible** — libsqlite only returns live rows. | **Native capability** — the whole forensic reason to build this. |
| **Panic / crash bounding on crafted input** | C library; malformed input is a memory-safety surface outside Rust's guarantees. | Panic-free, bounds-checked, fuzzable to the Paranoid-Gatekeeper bar. |
| **FFI / build** | Links system or bundled libsqlite (C toolchain, version skew). | Pure Rust, `unsafe_code = forbid`, no C dependency. |
| **On-disk fidelity** | Applies column **affinity** (e.g. returns `5500.0` for an integer-stored cell). | Reports the **raw storage class** — ground truth. |
| **Maturity for *live* reads** | Battle-tested across millions of deployments; full SQL engine. | New code; reader-only, no SQL engine, must earn trust via fuzzing + real-corpus validation. |
| **Query convenience** | Full SQL (`SELECT … JOIN …`). | Row iteration only; joins/filters are the caller's job. |

**Honest summary:** rusqlite wins on *maturity* and *query convenience* for
**live, trusted** databases. Native wins on every axis that matters for
**forensic, read-only, possibly-hostile** input: no mutation risk, WAL honesty,
**carving**, panic-bounding, and on-disk fidelity. The fleet's `*-core` doctrine
(from-scratch, panic-free, read-only) already chose the native trade-off for
NTFS, the registry, VHDX, etc.; SQLite is the same call.

---

## Migration path (deferred)

1. **Now (this spike):** `sqlite-core` exists as a local crate proving header +
   table-walk. No dependents touched.
2. **WS-E:** build out index/overflow/WAL/carving in `sqlite-core`, add the
   `sqlite-forensic` analyzer member (core/ + forensic/ split per fleet standard),
   promote the missing constants into `forensicnomicon::sqlite`.
3. **Later (deferred, gated on br4n6):** migrate `browser-core`'s
   `open_evidence_db` callers from `rusqlite` row extraction to `sqlite-core`.
   This **touches browser-forensic**, which is currently under active
   development by other agents — so it must wait until that work lands. The
   `EvidenceProvenance`/snapshot semantics map cleanly onto the native WAL
   overlay (the temp-copy dance disappears).
4. Keep `rusqlite` available behind a feature flag during transition for
   differential testing (native vs libsqlite) on a large real corpus.

## What WS-E would build on top of this

- Full b-tree coverage: index pages, overflow chains, WITHOUT ROWID tables.
- WAL/`-shm` overlay reader (checkpoint-free).
- **Carver**: freelist + unallocated + freeblock deleted-record recovery.
- `sqlite-forensic` analyzer emitting `forensicnomicon::report::Finding`s.
- `Read + Seek`/mmap backend; UTF-16 text; schema-driven table selection by name.
- Fuzz targets per parsed structure (header, varint, record, leaf cell, interior
  cell, carve) + a `fuzz_forensic` pipeline target, per the Paranoid-Gatekeeper
  standard.

---

## Prototype status

- **Repo:** `~/src/sqlite-forensic` — a workspace on the fleet `*-core`/`*-forensic`
  standard (matching `ntfs-forensic`/`vmdk-forensic`):
  - `core/` → crate `sqlite-core` (`[lib] name = "sqlite_core"`) — the native
    reader this spike proves.
  - `forensic/` → crate `sqlite-forensic` — the anomaly auditor; WS-C ships a
    minimal skeleton grading one header observation (`SQLITE-RESERVED-SPACE-NONZERO`),
    which WS-E expands into b-tree carving, deleted-record recovery, freelist
    anomalies, and WAL-overlay honesty.
  - Root carries the Paranoid-Gatekeeper `[workspace.lints]` (`unwrap_used`/
    `expect_used = deny`, `unsafe_code = forbid`) and the tooling files
    (`deny.toml`, `clippy.toml`, `rustfmt.toml`, `.gitleaks.toml`, `LICENSE`).
- **Tests:** 15 passing (8 reader unit + 4 reader integration + 3 forensic).
  Clippy pedantic clean; `cargo fmt --check` clean. Production code is panic-free
  (no `unwrap`/`expect`/`panic!`/unchecked indexing).
- **Origin:** the spike began life as the single-crate `~/src/sqlite-core` repo;
  its git history is preserved through the restructure via `git mv`.
