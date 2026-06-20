# Design — Drop-Recreate Residue Attribution (rowid→table inference)

## Executive Summary

When a table `T` is `DROP`ped and a new table `T'` with the **same name and schema**
is created and populated, SQLite reallocates `T`'s freed pages to `T'`. `T`'s old
row residue survives in the in-page free space of those now-`T'`-owned pages. Our
carver attributes that residue to `T'` as Tier-1 **CERTAIN** (page ownership → the
owning live table is known). The forensic risk — the survey's *Type-\** false
positive (Lee, Park, Lee & Choi, *FSI:DI* 55, 2025) — is that an examiner reading
`recovered_students` takes an `OLD-NAME` residue row for a *prior state of the
current* `students` table, when it belonged to a **different, dropped** instance.

**The honest feasibility verdict (the design's pivot).** Whether a residue row is
"a deleted row of the current `T'`" or "residue of a dropped predecessor" is
**reliably decidable only by two signals**, and **fundamentally undecidable** from a
bare snapshot otherwise:

| Situation | Reliable signal | Detectable? |
|---|---|---|
| `T'` is `AUTOINCREMENT` (bare db) | residue rowid `r` **>** current `sqlite_sequence(T')` ⟹ the current instance never assigned `r` (AUTOINCREMENT never reuses) ⟹ predecessor | **Yes** |
| a `-wal`/`-journal` captured the DDL | prior schema cookie ≠ current, or prior `sqlite_master` shows `T` absent / at a different rootpage ⟹ recreation | **Yes** |
| bare db, **plain** `INTEGER PRIMARY KEY` | none — residue rowid `6..10` is indistinguishable from the current table having inserted `1..10` then deleted `6..10` | **No** (the paper agrees) |

Empirically: a recreated `AUTOINCREMENT students` shows `sqlite_sequence = 5` with
residue rowids `6..10` (detectable); a plain-PK recreate leaves `sqlite_sequence`
absent and the same rowids ambiguous.

> **Soundness correction (Codex adversarial review — supersedes the original
> "Detector A/B label predecessor rows" plan).** Neither signal is a *sound
> per-row predecessor classifier*, and building one as such would manufacture a
> **new** false-positive class (current rows mislabelled "predecessor"):
> - **`r > sqlite_sequence(T')` is NOT proof of predecessor.** Confirmed
>   empirically: `UPDATE t SET id=1000` leaves `sqlite_sequence` at its old value
>   while the *current* live row now has rowid 1000 — so a current-instance row can
>   exceed `seq`. And `sqlite_sequence` is a **mutable user table** (`UPDATE
>   sqlite_sequence SET seq=0` succeeds), so `r > seq` is reachable with no
>   drop-recreate at all. `seq` tracks the INSERT high-water mark, not rowid
>   assignment.
> - **A sidecar DDL diff is a *table-level* boundary event, not row-level
>   provenance.** `DROP; CREATE; INSERT 1..100; DELETE 90..100` yields a real
>   schema diff, yet rowids 90..100 are ordinary current-instance deletions; the
>   detector cannot tell which carved bytes predate the `CREATE` frame.
> - **Rootpage change ≠ drop-recreate** — `VACUUM` reassigns rootpages and bumps
>   the cookie. Drop-recreate must be shown by a prior-vs-current `sqlite_master`
>   row diff (name/SQL/presence) plus, ideally, DDL chronology — not a rootpage move.

**Recommendation (corrected).** Do **not** ship a per-row "predecessor"
classifier or reroute residue into a `recovered_<table>__predecessor` table — the
evidence cannot support row-level provenance. Instead:
1. **Ship a non-overclaiming diagnostic flag** `table_instance_risk` on a record,
   with explicit, evidence-bearing values — `rowid_exceeds_autoinc_highwater
   (r=…, seq=…)` and `sidecar_schema_changed_for_table` — framed as **"consistent
   with prior-incarnation residue, but also explainable by an UPDATE / a
   `sqlite_sequence` edit / current-instance deletion."** It surfaces exactly the
   evidence the survey says an examiner must check (the RowID, the WAL/journal
   schema event), and the examiner concludes. Never asserts predecessor; never
   reroutes; never sets the attribution tier.
2. **Make the attribution claim honest in the LABEL, not just prose** — page-owned
   in-page residue is "found in `<table>`'s current b-tree pages" (storage), which
   is a weaker claim than "a deleted row of the current `<table>` instance"
   (logical membership). The visible column should reflect storage vs logical
   assessment so the prose caveat is not the only guard.
3. **Bare, plain-`INTEGER PRIMARY KEY`, no sidecar** (the survey's exact 0B case)
   has **no sound positive predecessor detector** from a single snapshot — stated
   as a limit, matching the survey's own statement. Current-state structures
   (b-tree key ranges, freelist, ptrmap) can *falsify* some hypotheses as
   diagnostics but never *prove* provenance, so they are not attribution inputs.

---

## 1. The problem (survey Type-\*)

`DROP TABLE students; CREATE TABLE students(... same schema ...); INSERT 5 rows`.
`T`'s 10 old rows' pages go to the freelist, then get reused by the new `students`.
Our `page_to_table_map` marks those pages as belonging to the live `students`
b-tree; `carve_free_regions` recovers the old residue from their in-page free
space; attribution tags it CERTAIN → `recovered_students`. Measured on our
replication: 5 OLD rows (rowids `6..10`, disjoint from live `1..5`) recovered and
attributed to `recovered_students`. We never present them as *live* rows (they are
flagged deleted), so we avoid the strong FP — but we do not flag that they may
predate the current table instance.

## 2. What is observable (feasibility — the crux)

For carved residue `R = (rowid r, values v)` attributed to live table `T'`:

1. **`sqlite_sequence`** (AUTOINCREMENT only) — one row `(name, seq)`; `seq` = the
   highest rowid ever assigned, **monotonic within an instance**, and the row is
   **deleted on `DROP TABLE`**. So for an AUTOINCREMENT `T'`, `r > seq` is
   **impossible** for the current instance (AUTOINCREMENT never reuses or
   decreases) ⟹ `R` predates a reset ⟹ predecessor. `r ≤ seq` is ambiguous
   (could be a deleted current row) ⟹ not flagged. **Reliable positive signal.**
2. **Schema cookie** (header offset 40) — advances on every DDL. A drop+recreate
   increments it. But a single snapshot exposes only the *current* cookie; the
   prior is gone unless a sidecar holds it. **Not usable bare; usable with a
   sidecar.**
3. **Sidecar prior schema** — a `-wal` commit snapshot or a `-journal` prior
   snapshot carries the *prior* `sqlite_master` + cookie. If the cookie advanced
   and the prior `sqlite_master` shows `T` absent or at a different rootpage, `T'`
   is a recreation. **Reliable, when a sidecar captured the DDL.** (Reuses the
   `PriorSnapshot`/`CommitSnapshot` schema reads and the journal schema-cookie
   detector already built.)
4. **Live rowid range** — `r ∉ live(T')` only means *deleted*; it does **not**
   separate "predecessor" from "current table deleted its high rowids."
   **Ambiguous on its own.**
5. **Freelist-trunk *history*** — a single snapshot shows the *current* freelist,
   not the *history* (which pages `T` freed and `T'` later reused). The
   page→freelist→`T'` chain is **not recorded on disk**, so freelist history is
   **not observable** from one image. (Observable: residue on a *currently-free*
   page — already "no live owner", not the Type-\* case — vs residue in the
   in-page free space of a *currently-live* `T'` page — the Type-\* case.)
6. **Same-schema shape** — the *general* dropped-table case (different shape) is
   already handled by Tier-2 inferred/unattributed. The Type-\* **hard** case is
   *same* schema ⟹ shape matches ⟹ no help.

**Conclusion:** reliable detection ⟺ Detector A (AUTOINCREMENT sequence) ∨ Detector
B (sidecar DDL). The bare-plain-PK case is genuinely undecidable; a rowid-range or
"freelist-history" heuristic would **fabricate** drop-recreate labels and create a
new FP class, so it is rejected.

## 3. Detectors

### Detector A — `sqlite_sequence` reconciliation (bare AUTOINCREMENT)
For each live table `T'` that is `AUTOINCREMENT` (parse `AUTOINCREMENT` in its
`CREATE TABLE`; read its `sqlite_sequence.seq = S`): any residue attributed to `T'`
with `rowid r > S` is labelled **`predecessor_residue`** (drop-recreate suspected),
with evidence `r > sqlite_sequence(S)`. `r ≤ S` is left as ordinary deleted
residue. Soundness: AUTOINCREMENT guarantees the current instance assigned only
rowids `≤ S` and never reused freed rowids, so `r > S` cannot be a current-instance
row. Documented caveat: a manual `UPDATE sqlite_sequence` / `DELETE FROM
sqlite_sequence` could lower `S` (rare, adversarial) — the label stays "consistent
with", not asserted.

### Detector B — sidecar DDL reconciliation (`-wal`/`-journal` present)
When a prior snapshot is available, compare prior vs current schema for the
residue's table: if the schema cookie advanced **and** the prior `sqlite_master`
lacks `T` (or carries it at a different rootpage), the current `T'` is a recreation
⟹ residue carved from the reused pages that predates the recreation is
`predecessor_residue`. Reuses `Database::rollback_prior` / `wal_timeline` schema
reads + the offset-40 cookie helper already added for journal anomalies.

### Default (bare, non-AUTOINCREMENT) — honest non-detection
No reliable signal ⟹ **do not** label predecessor (guessing manufactures FPs).
Instead, the attribution semantics are clarified (next section): page-ownership
CERTAIN means "physically in `T'`'s storage", not "a row of the current `T'`
instance." Optionally a single low-severity observation per table when *any*
in-page residue exists in a table whose schema cookie is high — but this is noisy
and **deferred** unless it proves valuable.

## 4. Labeling / output

- Add a provenance flag **`predecessor_residue: bool`** (or a `RecoverySource`
  refinement) set **only** by Detector A/B, carrying its evidence (`r`, `S`, or
  prior-rootpage).
- **Rebuilt `.carved.db`:** route flagged residue to a distinct
  `recovered_<table>__predecessor` table (or a `_predecessor` provenance column),
  not folded into `recovered_<table>`.
- **Combined XLSX:** a distinct value in a `provenance`/`view_state` column (e.g.
  `predecessor`) and/or a note; reuse existing flag-column + tint machinery, no new
  colour needed (it is a kind of deleted residue → stays red, with the
  `predecessor` flag set).
- **Attribution-claim honesty (all cases):** document that Tier-1 CERTAIN for
  in-page-freeblock residue asserts *storage location* (found in `T'`'s pages), and
  that logical membership in the current instance is only guaranteed when no
  same-name recreation is possible — which Detectors A/B test.

## 5. API / implementation (fleet `-core`/`-forensic`)

- **`sqlite-core`:** expose `sqlite_sequence` for a table (read the
  `sqlite_sequence` b-tree → `name→seq`), an `is_autoincrement(create_sql)` parse
  (mirroring `without_rowid_sql`), and a `schema_cookie()` header accessor (offset
  40) — partly exists from the journal work; promote to a public getter.
- **`sqlite-forensic`:** in the attribution pass, after a record is attributed
  CERTAIN to a live `T'`, run Detector A (and B when a prior snapshot is supplied)
  and set `predecessor_residue`. Keep it additive (the attribution tier is
  unchanged; the flag is orthogonal provenance), so no Nemetz regression.
- **CLI:** thread the flag into the `.carved.db` table routing, the XLSX column,
  and JSONL.

Secure-by-design: the flag is set **only** on a reliable signal; the note shows the
evidence; no heuristic guess ever sets it.

## 6. TDD plan (strict RED → GREEN, separate commits)

Commit real fixtures (built with the real `sqlite3` engine; small):
- `b_autoinc.db` — AUTOINCREMENT `students`, drop+recreate, residue rowids `6..10`,
  `sqlite_sequence = 5` (Detector A fires).
- `b_plainpk.db` — the existing plain-PK case (Detector A does **not** fire — the
  honest-limit characterization test).
- `b_wal_ddl.db` + `-wal` (or `-journal`) — drop+recreate captured in a sidecar
  (Detector B fires).

RED:
- `forensic/tests/drop_recreate.rs`: AUTOINCREMENT residue rowids `> sqlite_sequence`
  are flagged `predecessor_residue`; plain-PK residue is **not** flagged (no false
  positive — the limit); sidecar case flags via Detector B. Fails today (no flag).
- core unit tests: `sqlite_sequence` read, `is_autoincrement` parse, `schema_cookie`.
GREEN: implement Detectors A/B + the flag + output routing.

**Anti-regression:** a Nemetz test asserting the flag is set on **zero** ordinary
Nemetz deleted rows (no Nemetz DB is a same-name drop-recreate) — proving Detector
A/B never fire spuriously and precision is unharmed.

Oracle: the survey's Type-\* framing; `bring2lite`/SQL-DRP emit the residue as
unattributed blobs (no table claim at all), so our distinct `predecessor` label is
*more* informative than either while staying honest.

## 7. Scope

- **v1:** Detector A (bare AUTOINCREMENT) + the `predecessor_residue` flag + output
  routing + the anti-regression guard. Self-contained, no sidecar needed, covers
  the common AUTOINCREMENT app-schema case.
- **v1 (if cheap):** Detector B, reusing the journal/WAL prior-schema machinery.
- **Explicit limit (documented, not faked):** bare, non-AUTOINCREMENT, no sidecar →
  drop-recreate is undecidable; residue stays attributed by storage with the
  honesty caveat. This matches the survey's own statement of the problem.
