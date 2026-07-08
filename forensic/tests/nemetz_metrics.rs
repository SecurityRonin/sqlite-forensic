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

/// Aggregate precision of carved records whose confidence is >= `threshold`,
/// pooled over the record-deletion categories (0C/0D/0E) where live-vs-deleted is
/// well defined. Returns (tp, fp, precision). Precision = TP/(TP+FP); an empty
/// band is precision 1.0 (nothing claimed, nothing wrong). This is the measured
/// meaning of a `--min-confidence` band on the evaluation corpus (§4.3).
fn band_precision(threshold: f32) -> (usize, usize, f64) {
    let mut tp = 0usize;
    let mut fp = 0usize;
    for (nid, category) in manifest().databases() {
        if !matches!(category.as_str(), "0C" | "0D" | "0E") {
            continue;
        }
        let path = format!(
            "{}/../tests/data/nemetz/{category}/{nid}.db",
            env!("CARGO_MANIFEST_DIR")
        );
        if !Path::new(&path).exists() {
            continue;
        }
        let db = Database::open(std::fs::read(&path).unwrap()).unwrap();

        let elements = manifest().db(&nid).elements();
        let mut deleted: BTreeSet<String> = BTreeSet::new();
        for el in elements {
            for row in el.deleted() {
                deleted.insert(normalize_row(row.cells()));
            }
        }
        // Carved records passing the confidence bar, keyed like the answer key.
        let carved: BTreeSet<String> = carve_all_deleted_records(&db)
            .iter()
            .filter(|r| r.confidence >= threshold)
            .map(|r| carved_key(&r.values))
            .collect();
        for k in &carved {
            if deleted.contains(k) {
                tp += 1;
            } else {
                fp += 1;
            }
        }
    }
    let precision = if tp + fp == 0 {
        1.0
    } else {
        tp as f64 / (tp + fp) as f64
    };
    (tp, fp, precision)
}

/// Emit the measured precision at each `--min-confidence` band (§4.3), so the
/// numbers documented in the CLI help / `docs/validation.md` are reproducible.
#[test]
fn emit_precision_by_confidence_band() {
    assert!(!all_matrices().is_empty(), "Nemetz corpus must be vendored");
    println!(
        "\n{:<9} {:>9} {:>4} {:>4} {:>9}",
        "band", "threshold", "TP", "FP", "precision"
    );
    for (band, threshold) in [
        ("info", 0.0f32),
        ("low", 0.2),
        ("medium", 0.4),
        ("high", 0.6),
        ("critical", 0.8),
    ] {
        let (tp, fp, precision) = band_precision(threshold);
        println!("{band:<9} {threshold:>9.1} {tp:>4} {fp:>4} {precision:>9.3}");
    }
}

/// §4.3 calibration contract: pin the MEASURED precision + recall depth of each
/// `--min-confidence` band on the corpus so the numbers documented in the CLI help
/// and `docs/validation.md` cannot silently drift. Precision is 1.000 at every
/// band (the exclusion invariant surfaces no phantom/live row at any confidence),
/// so the band selects recall depth, not precision: full records at thresholds
/// 0.4 (110), 0.6 (28), 0.8 (2). A regression that surfaces a false positive at
/// any band, or drops recall depth, fails here.
#[test]
fn confidence_bands_are_calibrated_on_the_corpus() {
    for (band, threshold, expect_tp) in [
        ("info", 0.0f32, 110usize),
        ("low", 0.2, 110),
        ("medium", 0.4, 110),
        ("high", 0.6, 28),
        ("critical", 0.8, 2),
    ] {
        let (tp, fp, precision) = band_precision(threshold);
        assert_eq!(
            fp, 0,
            "{band} (>= {threshold}): {fp} false positive(s) — precision regression"
        );
        assert!(
            (precision - 1.0).abs() < 1e-9,
            "{band}: measured precision {precision} != 1.000"
        );
        assert_eq!(
            tp, expect_tp,
            "{band} (>= {threshold}): recall depth changed ({tp} vs pinned {expect_tp}) — \
             update the CLI help + docs/validation.md if this is intentional"
        );
    }
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
/// contiguity test and is treated conservatively as not-recoverable. (The carver
/// itself DOES recover surviving overflow chains — see `overflow_chain.rs`; this
/// flat-file estimator simply does not model them, keeping the denominator honest.)
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

/// A carved FP (a record matching neither the deleted nor the live ground-truth
/// set) falls into exactly one of two **benign, content-free** classes — proven
/// across the full corpus rather than asserted by count alone:
///
///   * **BenignPhantom** — the record carries NO distinctive data content: every
///     value is NULL, empty text, an all-zero text run, a BLOB, or a lone small
///     integer (a leaked rowid). This is the "inferred carver matched a near-zero
///     byte run" class the anti-forensic manipulated-structure categories (17, 18)
///     and a few `PriorVersion`/freeblock misparses produce. It can never be
///     mistaken for a real deleted row because it reconstructs no field identity.
///   * **RecoveredSchemaRow** — a real `sqlite_master` catalog row (`type` in
///     {table,index,trigger,view}) carved from a freed page in the dropped-table
///     categories (0A). This is correct dropped-table *schema* recovery; the
///     data-row answer key simply does not model catalog rows, so it scores FP.
///
/// A FP that is neither — i.e. one carrying a distinctive cell (TEXT ≥ 4 non-zero
/// bytes, or a REAL) that matches a real data column — would be a genuine
/// precision regression and fails this test, even if the total count stayed under
/// the ceiling. That is the load-bearing guarantee: the gate is on FP *content*,
/// not just FP *count*.
#[derive(Debug, PartialEq, Eq)]
enum FpClass {
    BenignPhantom,
    RecoveredSchemaRow,
    RealContent,
}

fn classify_fp(values: &[Value]) -> FpClass {
    // A real sqlite_master row recovered from free space.
    if matches!(values.first(), Some(Value::Text(t))
        if matches!(t.as_str(), "table" | "index" | "trigger" | "view"))
    {
        return FpClass::RecoveredSchemaRow;
    }
    // Distinctive content = the same rule the Tier-2 fragment extractor uses to
    // decide a cell anchors identity: TEXT with ≥ 4 non-zero UTF-8 bytes, or REAL.
    // A record with none of those reconstructs no field identity → benign phantom.
    let distinctive = values.iter().any(|v| match v {
        Value::Real(_) => true,
        Value::Text(t) => t.len() >= 4 && t.bytes().any(|b| b != 0),
        _ => false,
    });
    if distinctive {
        FpClass::RealContent
    } else {
        FpClass::BenignPhantom
    }
}

/// Every carved FP across the full corpus is content-free (a benign phantom or a
/// recovered schema row), and the total stays within the measured ceiling.
///
/// Measured per-category FP breakdown (sum = 44):
///   0A = 6  (1 benign phantom + 5 recovered `sqlite_master` schema rows)
///   0C = 4  (benign phantoms: `PriorVersion` wide misparses, lone leaked rowid)
///   17 = 33 (benign phantoms: 20 `FreeblockReconstructed` `[0,…]` + 13 `PriorVersion`)
///   18 = 1  (benign phantom: one `PriorVersion` wide misparse)
/// Of the 44: 39 benign phantoms, 5 recovered schema rows, **0 real-content** —
/// the full 141-DB corpus exposed no precision regression.
#[test]
fn phantom_fp_ceiling() {
    let mut total = 0usize;
    let mut benign = 0usize;
    let mut schema = 0usize;
    for (nid, category) in manifest().databases() {
        let path = format!(
            "{}/../tests/data/nemetz/{category}/{nid}.db",
            env!("CARGO_MANIFEST_DIR")
        );
        if !Path::new(&path).exists() {
            continue;
        }
        let db = Database::open(std::fs::read(&path).unwrap()).unwrap();

        let mut deleted: BTreeSet<String> = BTreeSet::new();
        let mut alive: BTreeSet<String> = BTreeSet::new();
        for el in manifest().db(&nid).elements() {
            for row in el.deleted() {
                deleted.insert(normalize_row(row.cells()));
            }
            for row in el.alive() {
                alive.insert(normalize_row(row));
            }
        }
        for rec in carve_all_deleted_records(&db) {
            let key = carved_key(&rec.values);
            if deleted.contains(&key) || alive.contains(&key) {
                continue;
            }
            total += 1;
            match classify_fp(&rec.values) {
                FpClass::BenignPhantom => benign += 1,
                FpClass::RecoveredSchemaRow => schema += 1,
                FpClass::RealContent => panic!(
                    "{nid}: carved a REAL-CONTENT false positive (precision regression): {:?}",
                    rec.values
                ),
            }
        }
    }
    assert_eq!(
        benign + schema,
        total,
        "every FP must be a benign phantom or a recovered schema row"
    );
    assert!(
        total <= NEMETZ_FP_CEILING,
        "total FP {total} exceeded the measured ceiling {NEMETZ_FP_CEILING} — new FP class?"
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
// 0E substrate-recoverable denominator under the honest per-record rule, now
// EXTENDED to the overflow class by chain-followability (task #73): a genuinely-
// overflowing row (body > usable-35) counts when its freed overflow chain is
// followable through freelist LEAVES to a byte-exact reassembly of the expected
// payload. Most 0E deleted bodies are large-but-in-page and contiguous; of the two
// truly-overflowing rows, one (0E-01 'Ella', chain page 13 a freelist leaf)
// survives byte-perfect and now counts, the other (0E-01 'Matteo', chain page 5
// reallocated as the freelist trunk) is destroyed and does NOT. The honest count
// is 4 (3 in-page contiguous + 1 followable chain), all of which the carver
// recovers (0E substrate recall 4/4 = 1.000).
const NEMETZ_0E_DRECOVERABLE: usize = 4;
// Total FP across the FULL 141-DB corpus, every one proven content-free by
// `phantom_fp_ceiling` (39 benign phantoms + 5 recovered sqlite_master schema
// rows, 0 real-content). The full corpus raised this from the 0A-0E-only 10 to
// 44: the manipulated-structure categories 17 (+33) and 18 (+1) reconstruct
// degenerate near-zero records the carver cannot distinguish from a freed cell.
// The strengthened test gates on FP *content* (no distinctive cell), so this
// count rising with benign phantoms is allowed but a single real-content FP is
// not — see the test's doc comment for the per-category breakdown.
const NEMETZ_FP_CEILING: usize = 44;
// 0D fragment-recoverable denominator (Tier-2): deleted rows whose full identity
// is destroyed (NOT substrate-recoverable) yet a distinctive cell — TEXT >= 4
// UTF-8 bytes, or REAL — still survives contiguously somewhere in the .db bytes.
// INTEGER-only "survivors" are excluded (coincidence-prone), so this is the
// honest ~5, not the integer-pattern-inflated legacy any-column upper bound.
const NEMETZ_0D_FRAGMENT_RECOVERABLE: usize = 5;
// 0E fragment-recoverable denominator under the same distinctive-cell rule. Now 3
// (was 4): chain-aware overflow recovery (task #73) lifted 'Ella' out of the
// fragment denominator into the substrate-recoverable set (its chain is now
// followable), since fragment-recoverable short-circuits on substrate.
const NEMETZ_0E_FRAGMENT_RECOVERABLE: usize = 3;
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

// 0D fragment-TP floor measured by the harness: of the 5 fragment-recoverable 0D
// rows, the on-disk freeblock-fragment extractor reaches the genuine "Anja"
// partial row on 0D-01 (id 20004). The other 4 survive only inside live-cell
// extents the carver must never scan, or at offsets no freeblock/gap anchor
// walks — so fragment recall < 1.0 is expected and honest (see
// docs/recovery-comparison.md). Raising it by an overflow-chain or template-free
// salvage is future work; this floor pins the current honest yield.
const NEMETZ_0D_FRAGMENT_TP_FLOOR: usize = 1;
// 0E fragment-TP floor: chain-aware overflow recovery (task #73) salvages the
// broken-chain 'Matteo' row (0E-01, chain page 5 reallocated as the freelist
// trunk) as a Tier-2 fragment — its intact local prefix yields id=20003 and
// name='Matteo'. The chain-resident code/zip are lost, so it is a fragment, not
// a full row. Measured 0E fragment-TP is 1.
const NEMETZ_0E_FRAGMENT_TP_FLOOR: usize = 1;
// Fragment false-positive ceiling across the whole recall corpus: a fragment
// whose distinctive cells match NO deleted row and NO live row is a
// fragment-phantom. The Tier-2 mechanism PERMITS a non-zero rate (a lone
// surviving cell can be a coincidental byte run) — that is why fragments are
// opt-in — but on this corpus the measured count is 0.
const NEMETZ_FRAGMENT_FP_CEILING: usize = 0;

/// One database's fragment confusion counts.
struct FragMatrix {
    tp: usize,
    phantom_fp: usize,
    live_reread: usize,
}

/// Whether a fragment's surviving distinctive cells equal the corresponding
/// columns of some normalized answer-key row (the per-cell key mirrors
/// `carved_key`: integers decimal, reals 5dp, text verbatim).
fn fragment_matches_any(rows: &BTreeSet<String>, frag: &sqlite_forensic::CarvedFragment) -> bool {
    rows.iter().any(|d| {
        let dcells: Vec<&str> = d.split('\u{1f}').collect();
        frag.surviving.iter().all(|(i, v)| {
            let s = match v {
                Value::Integer(n) => n.to_string(),
                Value::Real(r) => format!("{r:.5}"),
                Value::Text(t) => t.clone(),
                Value::Null => String::new(),
                Value::Blob(_) => "\u{0}<blob>".to_string(),
            };
            dcells.get(*i).copied() == Some(s.as_str())
        })
    })
}

fn frag_matrix_for(nid: &str, db: &Database) -> FragMatrix {
    let mut deleted: BTreeSet<String> = BTreeSet::new();
    let mut alive: BTreeSet<String> = BTreeSet::new();
    for el in manifest().db(nid).elements() {
        for row in el.deleted() {
            deleted.insert(normalize_row(row.cells()));
        }
        for row in el.alive() {
            alive.insert(normalize_row(row));
        }
    }
    let tiers = sqlite_forensic::carve_with_fragments(db);
    let mut m = FragMatrix {
        tp: 0,
        phantom_fp: 0,
        live_reread: 0,
    };
    for frag in &tiers.fragments {
        if fragment_matches_any(&deleted, frag) {
            m.tp += 1;
        } else if fragment_matches_any(&alive, frag) {
            m.live_reread += 1;
        } else {
            m.phantom_fp += 1;
        }
    }
    m
}

fn frag_matrices() -> Vec<(String, String, FragMatrix)> {
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
        out.push((nid.clone(), category, frag_matrix_for(&nid, &db)));
    }
    out
}

/// Fragment YIELD (Tier-2 true positives) meets the measured per-category floor.
#[test]
fn fragment_yield_meets_floor() {
    let mats = frag_matrices();
    let tp_0d: usize = mats
        .iter()
        .filter(|(_, c, _)| c == "0D")
        .map(|(_, _, m)| m.tp)
        .sum();
    let tp_0e: usize = mats
        .iter()
        .filter(|(_, c, _)| c == "0E")
        .map(|(_, _, m)| m.tp)
        .sum();
    assert!(
        tp_0d >= NEMETZ_0D_FRAGMENT_TP_FLOOR,
        "0D fragment-TP {tp_0d} < floor {NEMETZ_0D_FRAGMENT_TP_FLOOR}"
    );
    // 0E fragment-TP is the exact measured value (1: the broken-chain 'Matteo'
    // salvage) so a future regression that loses it, or an unexpected gain, both
    // surface rather than silently pass a `>= 0` tautology.
    assert_eq!(
        tp_0e, NEMETZ_0E_FRAGMENT_TP_FLOOR,
        "0E fragment-TP {tp_0e} != measured {NEMETZ_0E_FRAGMENT_TP_FLOOR}"
    );
}

/// Fragment FALSE-POSITIVE rate stays within the measured ceiling — separately
/// measured and reported (it is expected non-zero in general; on this corpus 0).
#[test]
fn fragment_fp_within_ceiling() {
    let total_fp: usize = frag_matrices()
        .iter()
        .map(|(_, _, m)| m.phantom_fp + m.live_reread)
        .sum();
    // The ceiling is currently 0, so assert exact equality (a `<= 0` comparison on
    // usize is a tautology clippy rejects). Any phantom or live-reread fragment
    // appearing in future raises this and must be re-measured, never waved through.
    assert_eq!(
        total_fp, NEMETZ_FRAGMENT_FP_CEILING,
        "fragment FP {total_fp} != measured ceiling {NEMETZ_FRAGMENT_FP_CEILING}"
    );
}

/// Tier separation: `carve_all_deleted_records(db) == carve_with_fragments(db).full`
/// on EVERY corpus DB — the load-bearing Tier-1 regression gate.
#[test]
fn full_tier_equals_carve_all_on_every_corpus_db() {
    for (nid, category) in manifest().databases() {
        let path = format!(
            "{}/../tests/data/nemetz/{category}/{nid}.db",
            env!("CARGO_MANIFEST_DIR")
        );
        if !Path::new(&path).exists() {
            continue;
        }
        let db = Database::open(std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            carve_all_deleted_records(&db),
            sqlite_forensic::carve_with_fragments(&db).full,
            "{nid}: full tier diverged from carve_all_deleted_records"
        );
    }
}

// --- full-corpus deleted-ground-truth coverage (task: full 141-DB vendoring) --
// The vendored corpus now carries deleted answer keys for EIGHT categories, not
// just the original five. These are the categories whose `.xml` tags one or more
// rows `deleted="1"`; every other category is a parse/format fixture with only
// LIVE content (covered by the panic-free robustness harness, not scored here).
//
//   07 Fragmented contents          (1 deleted row, in 07-03)
//   0A Deleted tables               (dropped-table proxy)
//   0B Overwritten tables           (dropped-table proxy)
//   0C Deleted records              (clean in-page free block)
//   0D Overwritten records          (deleted then reclaimed)
//   0E Deleted overflow pages       (long text, overflow chains)
//   17 Manipulated Freeblock Structures   (anti-forensic, 15 deleted/DB)
//   18 Manipulated Freelist Trunks        (anti-forensic, 7..240 deleted/DB)
const DELETED_GROUND_TRUTH_CATEGORIES: &[&str] = &["07", "0A", "0B", "0C", "0D", "0E", "17", "18"];

/// The ground-truth manifest covers every deletion category, and ONLY deletion
/// categories — a parse-only fixture is never silently scored as deleted-recall.
/// Pins the classification so re-vendoring or a generator change that drops a
/// deletion category (or wrongly admits a parse-only one) fails CI.
#[test]
fn manifest_covers_exactly_the_deleted_ground_truth_categories() {
    let mut present: BTreeSet<String> = BTreeSet::new();
    for (_nid, category) in manifest().databases() {
        present.insert(category);
    }
    let expected: BTreeSet<String> = DELETED_GROUND_TRUTH_CATEGORIES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    assert_eq!(
        present, expected,
        "manifest categories {present:?} != deleted-ground-truth set {expected:?}"
    );
}

/// The three newly-vendored deletion categories (07, 17, 18) actually carry
/// per-row deleted ground truth in the regenerated manifest — proof the generator
/// parsed their answer keys, not just that the folders exist.
#[test]
fn new_deletion_categories_carry_deleted_rows() {
    for cat in ["07", "17", "18"] {
        let deleted: usize = manifest()
            .databases()
            .iter()
            .filter(|(_, c)| c == cat)
            .map(|(nid, _)| {
                manifest()
                    .db(nid)
                    .elements()
                    .iter()
                    .map(|el| el.deleted().len())
                    .sum::<usize>()
            })
            .sum();
        assert!(
            deleted > 0,
            "category {cat} contributes no deleted rows to the manifest — generator did not parse its answer key"
        );
    }
}

/// Categories 17 and 18 are anti-forensic (manipulated freeblock / freelist-trunk
/// structures) yet ship per-row deleted answer keys, so they ARE scored. The
/// carver must stay panic-free and never re-surface a LIVE row as deleted on them
/// (the structural 0-false-positive guarantee), exactly as on 0C/0D/0E. Recovery
/// yield may legitimately be 0 (the structures are manipulated to defeat naive
/// carving) — that is asserted honestly as a bounded result, not a silent pass.
#[test]
fn manipulated_structure_categories_17_18_never_resurface_a_live_row() {
    let mut scored = 0usize;
    for m in all_matrices()
        .iter()
        .filter(|m| matches!(m.category.as_str(), "17" | "18"))
    {
        assert_eq!(
            m.live_reread, 0,
            "{}: carved {} live row(s) as deleted on a manipulated-structure DB",
            m.nid, m.live_reread
        );
        scored += 1;
    }
    assert!(
        scored > 0,
        "no category-17/18 DB was scored — manifest coverage regressed"
    );
}

/// No fragment's surviving set equals the column-projection of any `full` record
/// (suppression layer 2 works) on every corpus DB.
#[test]
fn no_fragment_shadows_a_full_record_on_corpus() {
    for (nid, category) in manifest().databases() {
        let path = format!(
            "{}/../tests/data/nemetz/{category}/{nid}.db",
            env!("CARGO_MANIFEST_DIR")
        );
        if !Path::new(&path).exists() {
            continue;
        }
        let db = Database::open(std::fs::read(&path).unwrap()).unwrap();
        let tiers = sqlite_forensic::carve_with_fragments(&db);
        for frag in &tiers.fragments {
            let shadow = tiers.full.iter().any(|rec| {
                frag.surviving
                    .iter()
                    .all(|(i, v)| rec.values.get(*i) == Some(v))
            });
            assert!(!shadow, "{nid}: fragment shadows a full record");
        }
    }
}
