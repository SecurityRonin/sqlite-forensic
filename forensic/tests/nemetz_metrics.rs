//! Ground-truth recall/precision metrics for [`carve_all_deleted_records`] over
//! the **SQLite Forensic Corpus** (Nemetz, Schmitt & Freiling, DFRWS-EU 2018;
//! CC0 public domain).
//!
//! # Why this test exists (independent ground truth)
//!
//! Unlike a fixture WE deleted rows from and then carve (Doer-Checker-weak: we
//! author both the deleter and the carver), every database here was authored by
//! a third party who *also* shipped the answer key: a per-database `.xml` tagging
//! each deleted row (`deleted="1"`) with its full decoded column content, plus a
//! `.sql` build+DELETE provenance script. The expected deleted-row set is theirs,
//! not ours — so a recall number computed against it is real ground truth.
//!
//! The answer keys are parsed once into a committed manifest
//! (`tests/data/nemetz/nemetz_ground_truth.json`, produced by the co-located
//! `gen_ground_truth.py`); this harness reads that manifest and the vendored
//! `.db` files and computes, **per database**, a confusion matrix:
//!
//! * **TP** — a carved row whose decoded columns equal an expected *deleted* row.
//! * **FP** — a carved row equal to neither a deleted nor a *live* row (a phantom
//!   parse). A carved row equal to a live row is counted separately as a
//!   live-re-read, NOT folded into FP, so the two failure modes stay distinct.
//! * **FN** — an expected deleted row no carved row matched.
//!
//! Recall is reported with **two denominators** because they answer different
//! questions:
//!
//! * **substrate-limited recall** = TP / `|D_recoverable|` — of the deleted rows
//!   whose bytes *physically survive* in the file (a corpus property computed
//!   independently of our carver, from `substrate_recoverable` in the manifest),
//!   how many did we recover? This is the carver-capability number.
//! * **end-to-end recall** = TP / `|D_deleted|` — of *all* rows the workload
//!   deleted (some destroyed by later overwrites), how many did we recover? This
//!   is the examiner-usefulness number.
//!
//! These are reported PER DATABASE, never as a single global figure — the
//! deletion scenario (in-page free block vs dropped table vs overwrite vs
//! overflow) dominates the result, so a global mean would be meaningless.
//!
//! # What the numbers do and do NOT claim
//!
//! They are an honest measurement of *this* carver against *this* corpus. A low
//! recall on a category (e.g. `0E` overflow, where the in-page freeblock template
//! does not apply — see "Freeblock reconstruction" in
//! `docs/recovery-comparison.md`) is a true statement about a capability
//! boundary, not a defect in the harness. The assertions below pin the *currently
//! measured* matrix so a regression (recall drop or a new FP class) fails CI;
//! raising recall by improving the carver is expected to *update* these numbers
//! upward.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::pedantic)]

mod nemetz_support;

use std::collections::BTreeSet;
use std::path::Path;

use nemetz_support::{manifest, normalize_row};
use sqlite_core::{Database, Value};
use sqlite_forensic::carve_all_deleted_records;

/// Decode a carved [`Value`] vector to the string form the answer key uses:
/// integers in decimal, reals at 5 decimal places (the corpus's fixed format),
/// text verbatim, NULL as empty, blobs to an unmatchable sentinel.
fn carved_key(values: &[Value]) -> String {
    let cells: Vec<String> = values
        .iter()
        .map(|v| match v {
            Value::Null => String::new(),
            Value::Integer(n) => n.to_string(),
            Value::Real(r) => format!("{r:.5}"),
            Value::Text(t) => t.clone(),
            Value::Blob(_) => "\u{0}<blob>".to_string(),
        })
        .collect();
    normalize_row(&cells)
}

/// One database's measured confusion matrix.
struct Matrix {
    nid: String,
    category: String,
    d_deleted: usize,
    d_recoverable: usize,
    tp: usize,
    fp: usize,
    fn_: usize,
    live_reread: usize,
}

impl Matrix {
    fn precision(&self) -> f64 {
        let denom = self.tp + self.fp;
        if denom == 0 {
            1.0
        } else {
            self.tp as f64 / denom as f64
        }
    }
    fn recall_substrate(&self) -> f64 {
        if self.d_recoverable == 0 {
            1.0
        } else {
            self.tp as f64 / self.d_recoverable as f64
        }
    }
    fn recall_end_to_end(&self) -> f64 {
        if self.d_deleted == 0 {
            1.0
        } else {
            self.tp as f64 / self.d_deleted as f64
        }
    }
    /// F-beta with beta=2 (recall-weighted: in recovery, missing evidence costs
    /// more than a low-confidence phantom the examiner discards). Uses
    /// substrate-limited recall (carver capability).
    fn f_beta(&self, beta: f64) -> f64 {
        let p = self.precision();
        let r = self.recall_substrate();
        if p == 0.0 && r == 0.0 {
            return 0.0;
        }
        let b2 = beta * beta;
        (1.0 + b2) * p * r / (b2 * p + r)
    }
}

/// Compute the confusion matrix for one database from its carved output and the
/// answer-key element list.
fn matrix_for(nid: &str, category: &str, db: &Database) -> Matrix {
    let elements = manifest().db(nid).elements();

    // Ground-truth sets, keyed by normalized full-row content.
    let mut deleted: BTreeSet<String> = BTreeSet::new();
    let mut recoverable: BTreeSet<String> = BTreeSet::new();
    let mut alive: BTreeSet<String> = BTreeSet::new();
    let mut d_deleted = 0usize;
    let mut d_recoverable = 0usize;
    for el in elements {
        for row in el.deleted() {
            d_deleted += 1;
            let key = normalize_row(row.cells());
            deleted.insert(key.clone());
            if row.substrate_recoverable() {
                d_recoverable += 1;
                recoverable.insert(key);
            }
        }
        for row in el.alive() {
            alive.insert(normalize_row(row));
        }
    }

    let carved: BTreeSet<String> = carve_all_deleted_records(db)
        .iter()
        .map(|r| carved_key(&r.values))
        .collect();

    let tp = carved.iter().filter(|k| deleted.contains(*k)).count();
    let live_reread = carved
        .iter()
        .filter(|k| !deleted.contains(*k) && alive.contains(*k))
        .count();
    let fp = carved
        .iter()
        .filter(|k| !deleted.contains(*k) && !alive.contains(*k))
        .count();
    // TP counted against the substrate-recoverable subset for substrate recall.
    let tp_recoverable = carved.iter().filter(|k| recoverable.contains(*k)).count();
    let fn_ = d_recoverable.saturating_sub(tp_recoverable);

    Matrix {
        nid: nid.to_string(),
        category: category.to_string(),
        d_deleted,
        d_recoverable,
        tp,
        fp,
        fn_,
        live_reread,
    }
}

fn all_matrices() -> Vec<Matrix> {
    let mut out = Vec::new();
    for (nid, category) in manifest().databases() {
        let path = format!(
            "{}/../tests/data/nemetz/{category}/{nid}.db",
            env!("CARGO_MANIFEST_DIR")
        );
        if !Path::new(&path).exists() {
            continue;
        }
        let db = Database::open(std::fs::read(&path).unwrap()).unwrap();
        out.push(matrix_for(&nid, &category, &db));
    }
    out.sort_by(|a, b| a.nid.cmp(&b.nid));
    out
}

/// Emit the full per-DB matrix as a table (visible with `--nocapture`), so the
/// numbers in `docs/recovery-comparison.md` are reproducible, not hand-written.
#[test]
fn emit_per_db_confusion_matrix() {
    let matrices = all_matrices();
    assert!(!matrices.is_empty(), "Nemetz corpus must be vendored");
    println!(
        "\n{:<6} {:<3} {:>4} {:>5} {:>3} {:>3} {:>3} {:>4} {:>7} {:>7} {:>6} {:>5}",
        "DB", "cat", "Ddel", "Drec", "TP", "FP", "FN", "live", "rec_sub", "rec_e2e", "prec", "F2"
    );
    for m in &matrices {
        println!(
            "{:<6} {:<3} {:>4} {:>5} {:>3} {:>3} {:>3} {:>4} {:>7.3} {:>7.3} {:>6.3} {:>5.3}",
            m.nid,
            m.category,
            m.d_deleted,
            m.d_recoverable,
            m.tp,
            m.fp,
            m.fn_,
            m.live_reread,
            m.recall_substrate(),
            m.recall_end_to_end(),
            m.precision(),
            m.f_beta(2.0),
        );
    }
}

/// No *live* row is ever re-surfaced as a deleted record — the structural
/// 0-false-positive guarantee of the in-page carver, measured against real
/// live/deleted ground truth.
///
/// Scoped to the **record-deletion** categories (0C deleted records, 0D deleted
/// then overwritten, 0E deleted overflow) where a live table coexists with the
/// deletions, so the answer key's non-deleted rows are genuinely live and must
/// never be carved. The dropped/overwritten-*table* categories (0A, 0B) are
/// excluded here on purpose: there the answer key's "alive" rows belong to a
/// table that was itself dropped, so recovering them is correct dropped-table
/// recovery, not a live re-read (those categories are covered by
/// `dropped_table_recovery_is_bounded` and the DC3 differential test).
#[test]
fn never_resurfaces_a_live_row() {
    for m in all_matrices()
        .iter()
        .filter(|m| matches!(m.category.as_str(), "0C" | "0D" | "0E"))
    {
        assert_eq!(
            m.live_reread, 0,
            "{}: carved {} live row(s) as deleted — live-re-read FP regression",
            m.nid, m.live_reread
        );
    }
}

/// Dropped/overwritten-table categories (0A, 0B): the carver must stay
/// panic-free and bounded. These carry no record-level deleted ground truth that
/// anchors a live-vs-deleted distinction (the whole table is gone), so we assert
/// only that recovery is bounded — correctness of dropped-table recovery is
/// measured by the DC3 differential test, not here.
#[test]
fn dropped_table_recovery_is_bounded() {
    for m in all_matrices()
        .iter()
        .filter(|m| matches!(m.category.as_str(), "0A" | "0B"))
    {
        let recovered = m.tp + m.live_reread;
        assert!(
            recovered + m.fp <= DROPPED_TABLE_CARVE_CEILING,
            "{}: dropped-table recovery {} + fp {} exceeds ceiling {}",
            m.nid,
            recovered,
            m.fp,
            DROPPED_TABLE_CARVE_CEILING
        );
    }
}

/// On the clean in-page-deletion category (0C: `secure_delete=0`, no later
/// overwrite, so every deleted row's bytes survive) the carver must recover the
/// freeblock-clobbered rows via freeblock reconstruction (task #56). This pins
/// the measured 0C true-positive total so a recall regression fails CI. SQLite
/// overwrites a freed cell's first four bytes (payload-length + rowid varints,
/// `header_len`, leading serial) with the freeblock next/size pointers;
/// `reconstruct_freeblock_records` rebuilds each record from its surviving
/// serial tail plus the page's schema template (see "Freeblock reconstruction"
/// in `docs/recovery-comparison.md`), raising this floor from 24 to 79.
#[test]
fn category_0c_true_positive_floor() {
    let total_tp: usize = all_matrices()
        .iter()
        .filter(|m| m.category == "0C")
        .map(|m| m.tp)
        .sum();
    // Measured value pinned as a regression floor (see emit_per_db_confusion_matrix).
    assert!(
        total_tp >= NEMETZ_0C_TP_FLOOR,
        "0C true-positive total {total_tp} dropped below the measured floor {NEMETZ_0C_TP_FLOOR}"
    );
}

/// On the deleted-then-overwritten category (0D) the freed cells are coalesced
/// back-to-back inside a single free span — a chained freeblock OR the page's
/// unallocated gap — where every cell's leading four bytes are clobbered by a
/// stale freeblock header (`next`/`size`), not just the span's first cell. The
/// span-walking freeblock reconstruction rebuilds **each** such clobbered cell
/// (template tail + body, fits-in-span validated), so the carver recovers the
/// trailing intact records a single-shot head reconstruction missed. This pins
/// the measured 0D true-positive total so the recovery does not regress.
///
/// Byte-evidence for the mechanism (task #66): e.g. 0D-07 page 3 freeblock
/// `[0xf79,0xfe0)` holds three coalesced cells (`Luca|Schumacher`,
/// `Kurt|Schubert`, `Georg|Schulz`) each prefixed by a `00 00 00 NN` stale
/// header; 0D-06 page 2 packs four such cells in its unallocated gap. The general
/// rule — iterate template reconstruction across the whole free span — recovers
/// all of them, with no per-database constant.
#[test]
fn category_0d_true_positive_floor() {
    let total_tp: usize = all_matrices()
        .iter()
        .filter(|m| m.category == "0D")
        .map(|m| m.tp)
        .sum();
    assert!(
        total_tp >= NEMETZ_0D_TP_FLOOR,
        "0D true-positive total {total_tp} dropped below the measured floor {NEMETZ_0D_TP_FLOOR}"
    );
}

/// The substrate-recoverable denominator is the **honest contiguous
/// full-row-identity** count: a deleted row is counted recoverable only when its
/// whole scored record body — every column's SQLite serial encoding, in column
/// order, exactly as the recall matcher's full-row key (`normalize_row` over all
/// cells) discriminates on — survives **contiguously** in the database bytes. A
/// row whose scored identity was destroyed by a later same-rowid overwrite (so
/// only a coincidental single-column byte match remains) is NO LONGER counted, as
/// the earlier any-distinctive-column rule wrongly did.
///
/// The contiguity decision is made **per record by body size**, never by category
/// (no special case): a record whose payload fits in-page (≤ the page's usable−35
/// threshold) is a single contiguous run and the contiguity test is exact; a
/// record large enough to spill onto a non-contiguous overflow-page chain (SQLite
/// file format, "Cell payload overflow pages") cannot be modelled by a flat-file
/// contiguity test and is treated conservatively as not-recoverable (chain-aware
/// overflow recoverability is future work).
///
/// For 0D this tightens `d_recoverable` from the inflated 36 to the honest 19 —
/// the substrate is small because overwrites genuinely destroyed roughly half the
/// deleted rows, not because the harness is lenient.
///
/// Two checks, both against the regenerated manifest:
///  1. the 0D `d_recoverable` total equals the measured honest value, and
///  2. it never falls below the 0D true-positive total — TP > Drec would be a
///     logical impossibility (we cannot recover a row whose identity does not
///     survive), so this guards the denominator against silently re-inflating
///     above what the carver could ever reach.
#[test]
fn category_0d_drecoverable_is_contiguous_identity() {
    let total_drec: usize = all_matrices()
        .iter()
        .filter(|m| m.category == "0D")
        .map(|m| m.d_recoverable)
        .sum();
    assert_eq!(
        total_drec, NEMETZ_0D_DRECOVERABLE,
        "0D d_recoverable total {total_drec} != honest contiguous-identity denominator {NEMETZ_0D_DRECOVERABLE}"
    );
    let total_tp: usize = all_matrices()
        .iter()
        .filter(|m| m.category == "0D")
        .map(|m| m.tp)
        .sum();
    assert!(
        total_drec >= total_tp,
        "0D d_recoverable {total_drec} < tp {total_tp} — a recovered row whose identity does not survive is impossible"
    );
}

/// The overflow category (0E) is held to the **same** honest per-record
/// contiguous-identity rule as every other category — no exemption. Most 0E
/// deleted bodies are large-but-IN-PAGE (≤ the usable−35 threshold) and survive as
/// a single contiguous run, so the contiguity test applies to them exactly; only
/// the genuinely-overflowing records (body > threshold, spilling to a
/// non-contiguous overflow-page chain) are excluded as future work. Under this
/// honest rule the 0E substrate denominator drops from the inflated 9 (legacy
/// any-distinctive-column proxy) to 3 — the rows whose full in-page identity
/// physically survives. The same TP ≤ Drec invariant is asserted.
#[test]
fn category_0e_drecoverable_is_contiguous_identity() {
    let total_drec: usize = all_matrices()
        .iter()
        .filter(|m| m.category == "0E")
        .map(|m| m.d_recoverable)
        .sum();
    assert_eq!(
        total_drec, NEMETZ_0E_DRECOVERABLE,
        "0E d_recoverable total {total_drec} != honest contiguous-identity denominator {NEMETZ_0E_DRECOVERABLE}"
    );
    let total_tp: usize = all_matrices()
        .iter()
        .filter(|m| m.category == "0E")
        .map(|m| m.tp)
        .sum();
    assert!(
        total_drec >= total_tp,
        "0E d_recoverable {total_drec} < tp {total_tp} — a recovered row whose identity does not survive is impossible"
    );
}

/// The total phantom-FP count across the recall corpus, pinned so a new
/// systematic FP class fails CI. Phantoms here are low-confidence all-empty/NULL
/// records the inferred carver matches on a run of zero bytes (documented in
/// `docs/recovery-comparison.md`).
#[test]
fn phantom_fp_ceiling() {
    let total_fp: usize = all_matrices().iter().map(|m| m.fp).sum();
    assert!(
        total_fp <= NEMETZ_FP_CEILING,
        "total phantom FP {total_fp} exceeded the measured ceiling {NEMETZ_FP_CEILING} — new FP class?"
    );
}

// --- measured constants (pinned from emit_per_db_confusion_matrix) -----------
// These are the values measured by the harness on the vendored corpus; they pin
// the matrix so a recall regression or a new FP class fails CI. Raising recall by
// improving the carver is expected to UPDATE these (the floor rises, the harness
// is re-run to confirm). See docs/recovery-comparison.md for the full table.
//
// 0C true-positive total measured across the ten 0C databases (sum of the TP
// column). Freeblock-aware reconstruction (task #56) recovers the freed cells
// whose first four bytes were clobbered by freeblock conversion, by rebuilding
// each record from its surviving serial-type tail plus the schema-derived header
// template — raising this floor far above the forward-parse-only value (24).
const NEMETZ_0C_TP_FLOOR: usize = 79;
// 0D true-positive total measured across the eight 0D databases. Span-walking
// freeblock reconstruction (task #66) recovers every coalesced clobbered cell in
// a free span (chained freeblock or unallocated gap), not just the span's head —
// lifting 0D recovery from 11 to 19 at precision 1.000 on every 0D database.
// Against the honest full-row substrate (19 recoverable rows), the carver recovers
// all 19. The floor is the honestly-measured 19.
const NEMETZ_0D_TP_FLOOR: usize = 19;
// 0D substrate-recoverable denominator under the honest contiguous full-row-identity
// rule (gen_ground_truth.py now requires the whole scored record body to survive
// contiguously, mirroring the recall matcher's full-row key, decided per record by
// body size). The earlier any-distinctive-column rule inflated this to 36 by
// counting rows whose scored identity was destroyed by a later same-rowid overwrite
// but a single column coincidentally survived elsewhere; the honest count is 19,
// all of which the carver recovers (0D substrate recall 19/19 = 1.000 vs the
// inflated 19/36 = 0.528). The substrate is small because overwrites genuinely
// destroyed ~26 of the 45 deleted rows, not because the harness is lenient.
const NEMETZ_0D_DRECOVERABLE: usize = 19;
// 0E substrate-recoverable denominator under the SAME honest per-record contiguous
// rule (no overflow-category exemption). Most 0E deleted bodies are large-but-in-page
// and contiguous; only the genuinely-overflowing records (body > usable-35, spilling
// to a non-contiguous overflow-page chain) are excluded as future work. This honest
// count is 3 (down from the inflated 9 the any-distinctive-column proxy produced),
// all of which the carver recovers (0E substrate recall 3/3 = 1.000).
const NEMETZ_0E_DRECOVERABLE: usize = 3;
// Total phantom FP across the recall corpus (all-empty/NULL inferred records).
const NEMETZ_FP_CEILING: usize = 10;
// 0D fragment-recoverable denominator (Tier-2): deleted rows whose full identity
// is destroyed (NOT substrate-recoverable) yet a distinctive cell — TEXT >= 4
// UTF-8 bytes, or REAL — still survives contiguously somewhere in the .db bytes.
// INTEGER-only "survivors" are excluded (coincidence-prone), so this is the
// honest ~5, not the integer-pattern-inflated legacy any-column upper bound.
const NEMETZ_0D_FRAGMENT_RECOVERABLE: usize = 5;
// 0E fragment-recoverable denominator under the same distinctive-cell rule.
const NEMETZ_0E_FRAGMENT_RECOVERABLE: usize = 4;
// 0C is fully reconstructable, so no row is fragment-recoverable.
const NEMETZ_0C_FRAGMENT_RECOVERABLE: usize = 0;
// Dropped/overwritten-table recovery is bounded per DB (max recovered+fp seen).
const DROPPED_TABLE_CARVE_CEILING: usize = 24;
// Category-11 tampered DBs (manipulated page/cell pointers): the carver
// currently recovers 0 records from all five (the structural self-consistency
// checks reject the tampered cells) and, above all, never panics. A small
// non-zero ceiling leaves headroom for a future freeblock-aware carver while
// still failing CI on a phantom blow-up.
const ANTIFORENSIC_11_CARVE_CEILING: usize = 8;

/// Category 11 (anti-forensic: manipulated page/cell pointers) carries NO deleted
/// rows in its answer key — it is a robustness corpus. The carver must stay
/// panic-free and emit no phantom *deleted* records that masquerade as real rows.
/// We assert only that opening and carving every tampered DB does not panic and
/// yields a bounded, low phantom count (it has no live/deleted ground truth to
/// score precision/recall against — agreement, not correctness).
#[test]
fn antiforensic_category_11_is_panic_free() {
    let dir = format!("{}/../tests/data/nemetz/11", env!("CARGO_MANIFEST_DIR"));
    let mut ran = 0usize;
    let entries = std::fs::read_dir(&dir).expect("category 11 vendored");
    for entry in entries {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("db") {
            continue;
        }
        // Some category-11 files are `*_antifor.db`; open whatever .db is present.
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        if let Ok(db) = Database::open(bytes) {
            // Must not panic; bound the phantom output so a blow-up fails CI.
            let carved = carve_all_deleted_records(&db);
            assert!(
                carved.len() <= ANTIFORENSIC_11_CARVE_CEILING,
                "{}: tampered DB produced {} carved records (> ceiling {}) — possible FP blow-up",
                path.display(),
                carved.len(),
                ANTIFORENSIC_11_CARVE_CEILING
            );
            ran += 1;
        }
    }
    assert!(ran > 0, "no category-11 DB opened");
}

// --- Tier-2 fragment metrics (task #72) -------------------------------------

/// The fragment-recoverable denominator per category, parsed from the manifest's
/// `fragment_recoverable` flag, equals the pinned honest totals — and the two
/// buckets are DISJOINT (`fragment_recoverable ⇒ !substrate_recoverable`).
#[test]
fn fragment_substrate_denominators_match_manifest() {
    let mut by_cat: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for (nid, category) in manifest().databases() {
        for el in manifest().db(&nid).elements() {
            for row in el.deleted() {
                if row.fragment_recoverable() {
                    *by_cat.entry(category.clone()).or_default() += 1;
                    // Disjoint buckets: a fragment row is never substrate-recoverable.
                    assert!(
                        !row.substrate_recoverable(),
                        "{nid}: row is both substrate- and fragment-recoverable"
                    );
                }
            }
        }
    }
    assert_eq!(
        by_cat.get("0D").copied().unwrap_or(0),
        NEMETZ_0D_FRAGMENT_RECOVERABLE,
        "0D fragment-recoverable total"
    );
    assert_eq!(
        by_cat.get("0E").copied().unwrap_or(0),
        NEMETZ_0E_FRAGMENT_RECOVERABLE,
        "0E fragment-recoverable total"
    );
    assert_eq!(
        by_cat.get("0C").copied().unwrap_or(0),
        NEMETZ_0C_FRAGMENT_RECOVERABLE,
        "0C fragment-recoverable total"
    );
}
