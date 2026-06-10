//! Direct head-to-head: **our carver vs `undark` vs `fqlite`**, every tool scored
//! against the **same** independent Nemetz answer key — exactly as our own carver
//! is scored in `nemetz_metrics.rs`.
//!
//! # Why this test exists (a real head-to-head, not inter-tool concordance)
//!
//! `oracle_differential.rs` reconciles our output against undark/fqlite as
//! *oracles over our own fixture* — it answers "do we agree with them?", not "how
//! does each tool score against ground truth?". This harness answers the second
//! question: it runs undark and fqlite over the Nemetz corpus and computes, **per
//! tool, per database**, a confusion matrix against the *same* `.xml` answer keys
//! the Nemetz authors shipped (`nemetz_ground_truth.json`). All three tools pass
//! through the identical ground-truth comparison, so the recall/precision numbers
//! are directly comparable.
//!
//! # The comparison key (format-stable, symmetric, documented)
//!
//! The three tools render a row differently: undark prints the SQLite rowid + a
//! page address and omits the schema's `id` column; fqlite prints the `id` plus
//! the columns at 8 decimal places; our carver renders reals at 5 dp. A *full
//! decoded-row* match would therefore penalise a tool for its float-formatting,
//! not its recovery — a measurement artifact, not a capability gap. So every tool
//! AND the answer key are projected to the **two columns at positions 1 and 2**
//! (`name`/`surname` for the text tables; the two non-id integer columns for the
//! integer tables) — the columns that are integer-or-text (format-stable) and that
//! **uniquely identify** every deleted row in every 0C/0D/0E database (verified:
//! `(col1,col2)` is injective over each DB's deleted set). This is the same
//! projection `oracle_differential.rs` already uses (text columns at index 1/2).
//!
//! Two databases — **0C-06 and 0C-07** — have *floating-point* values at positions
//! 1 and 2 (their `name`/`surname` columns are `FLOAT`), so no format-stable
//! cross-tool identity exists for them; they are **excluded from the head-to-head
//! and the exclusion is stated explicitly** rather than scored with a confounded
//! key. Our own `nemetz_metrics.rs` still scores them (it rounds reals to 5 dp
//! symmetrically with the answer key), but a *cross-tool* comparison cannot.
//!
//! # Scope of the recall table
//!
//! Only the **record-deletion** categories carry a clean row-level deleted set:
//! `0C` (deleted records, in-page free block), `0D` (deleted then overwritten),
//! `0E` (deleted overflow). The dropped/overwritten-*table* categories `0A`/`0B`
//! (the whole table is gone — no live-vs-deleted anchor) and category `11`
//! (anti-forensic tampering — a robustness corpus with no deleted answer key) have
//! no clean recall denominator and are **out of scope** for this table, matching
//! the scoping in `nemetz_metrics.rs`.
//!
//! # Gating
//!
//! undark legs skip unless `UNDARK_BIN` is set; fqlite legs skip unless
//! `FQLITE_TAP` is set (optionally `FQLITE_JAVA`) — identical to
//! `oracle_differential.rs`, so CI without the tools still passes. The `ours`
//! column needs no tool and is always computed. Run with `--nocapture` to
//! regenerate the table in `docs/recovery-comparison.md`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::pedantic)]

mod nemetz_support;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use nemetz_support::manifest;
use sqlite_core::{Database, Value};
use sqlite_forensic::carve_all_deleted_records;

/// A row's format-stable identity: the two columns at positions 1 and 2.
type RowId = (String, String);

/// Databases whose positions 1/2 are `FLOAT` — no format-stable cross-tool key.
const FLOAT_KEY_EXCLUSIONS: &[&str] = &["0C-06", "0C-07"];

fn undark_bin() -> Option<PathBuf> {
    std::env::var_os("UNDARK_BIN").map(PathBuf::from)
}

fn fqlite_tap() -> Option<PathBuf> {
    std::env::var_os("FQLITE_TAP").map(PathBuf::from)
}

/// One tool's confusion matrix on one database, scored against the Nemetz answer
/// key via the `(col1,col2)` identity projection.
#[derive(Default, Clone)]
struct ToolMatrix {
    /// Distinct recovered identities equal to an answer-key **deleted** row.
    tp: usize,
    /// …restricted to the substrate-recoverable deleted subset (recall numerator).
    tp_recoverable: usize,
    /// Recovered identities equal to a **live** row (re-read; counted separately).
    live_reread: usize,
    /// Recovered identities equal to neither deleted nor live (phantom parse).
    fp: usize,
    /// Recovered identity count (deduped).
    carved: usize,
}

impl ToolMatrix {
    fn add(&mut self, o: &ToolMatrix) {
        self.tp += o.tp;
        self.tp_recoverable += o.tp_recoverable;
        self.live_reread += o.live_reread;
        self.fp += o.fp;
        self.carved += o.carved;
    }
}

/// The answer-key identity sets for one database, via the `(col1,col2)` key.
struct GroundTruth {
    deleted: BTreeSet<RowId>,
    recoverable: BTreeSet<RowId>,
    alive: BTreeSet<RowId>,
    d_deleted: usize,
    d_recoverable: usize,
}

fn ground_truth(nid: &str) -> GroundTruth {
    let mut deleted = BTreeSet::new();
    let mut recoverable = BTreeSet::new();
    let mut alive = BTreeSet::new();
    let mut d_deleted = 0usize;
    let mut d_recoverable = 0usize;
    for el in manifest().db(nid).elements() {
        for row in el.deleted() {
            d_deleted += 1;
            let c = row.cells();
            if c.len() >= 3 {
                let key = (c[1].clone(), c[2].clone());
                deleted.insert(key.clone());
                if row.substrate_recoverable() {
                    d_recoverable += 1;
                    recoverable.insert(key);
                }
            }
        }
        for row in el.alive() {
            if row.len() >= 3 {
                alive.insert((row[1].clone(), row[2].clone()));
            }
        }
    }
    GroundTruth {
        deleted,
        recoverable,
        alive,
        d_deleted,
        d_recoverable,
    }
}

/// Score a recovered identity set against an answer key.
fn score(recovered: &BTreeSet<RowId>, gt: &GroundTruth) -> ToolMatrix {
    let tp = recovered.iter().filter(|k| gt.deleted.contains(*k)).count();
    let tp_recoverable = recovered
        .iter()
        .filter(|k| gt.recoverable.contains(*k))
        .count();
    let live_reread = recovered
        .iter()
        .filter(|k| !gt.deleted.contains(*k) && gt.alive.contains(*k))
        .count();
    let fp = recovered
        .iter()
        .filter(|k| !gt.deleted.contains(*k) && !gt.alive.contains(*k))
        .count();
    ToolMatrix {
        tp,
        tp_recoverable,
        live_reread,
        fp,
        carved: recovered.len(),
    }
}

/// Minimal CSV split honoring `"..."` quoting (the corpus has no embedded escaped
/// quotes) — shared with `oracle_differential.rs`'s projection convention.
fn split_csv(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut in_q = false;
    for ch in line.chars() {
        match ch {
            '"' => in_q = !in_q,
            ',' if !in_q => fields.push(std::mem::take(&mut cur)),
            _ => cur.push(ch),
        }
    }
    fields.push(cur);
    fields
}

fn unquote(s: &str) -> String {
    s.trim().trim_matches('"').to_string()
}

/// Stringify a carved [`Value`] the way the answer key renders it (reals at 5 dp,
/// the corpus's export precision; ints decimal; text verbatim; NULL empty).
fn cell(v: Option<&Value>) -> String {
    match v {
        Some(Value::Null) | None => String::new(),
        Some(Value::Integer(n)) => n.to_string(),
        Some(Value::Real(r)) => format!("{r:.5}"),
        Some(Value::Text(t)) => t.clone(),
        Some(Value::Blob(_)) => "\u{0}<blob>".to_string(),
    }
}

/// Our carver's recovered `(col1,col2)` identity set for one database.
fn ours_recover(db: &Database) -> BTreeSet<RowId> {
    carve_all_deleted_records(db)
        .iter()
        .map(|r| (cell(r.values.get(1)), cell(r.values.get(2))))
        .collect()
}

/// undark's recovered `(col1,col2)` set. undark emits `rowid,addr,col1,col2,...`,
/// so the two identity columns are CSV fields 2 and 3 (same projection as
/// `oracle_differential.rs`). Whatever undark emits is taken verbatim — a mangled
/// row simply will not match the answer key (an honest miss/phantom, not hidden).
fn undark_recover(undark: &Path, db: &Path) -> BTreeSet<RowId> {
    let out = Command::new(undark)
        .arg("-i")
        .arg(db)
        .output()
        .expect("undark must execute");
    let text = String::from_utf8_lossy(&out.stdout);
    let mut set = BTreeSet::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let f = split_csv(line);
        if f.len() >= 4 {
            set.insert((unquote(&f[2]), unquote(&f[3])));
        }
    }
    set
}

/// fqlite's recovered `(col1,col2)` set via the headless tap. The tap emits
/// `rowid,offset,id,col1,col2,...` for data records (rowid is often `-1`) and
/// `n,[page|..],..,table|index|..,..` lines for the freed schema records — the
/// latter are skipped. The two identity columns are CSV fields 3 and 4.
fn fqlite_recover(tap: &Path, db: &Path) -> BTreeSet<RowId> {
    let out = Command::new(tap)
        .arg(db)
        .output()
        .expect("fqlite tap must execute");
    let text = String::from_utf8_lossy(&out.stdout);
    let mut set = BTreeSet::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let f = split_csv(line);
        // Skip freed-schema records: field 4 is the sqlite_master "type".
        if f.len() >= 5 && matches!(f[4].as_str(), "table" | "index" | "trigger" | "view") {
            continue;
        }
        if f.len() >= 5 {
            set.insert((unquote(&f[3]), unquote(&f[4])));
        }
    }
    set
}

/// The in-scope databases for the head-to-head: 0C/0D/0E minus the float-key
/// exclusions, in id order.
fn in_scope() -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = manifest()
        .databases()
        .into_iter()
        .filter(|(nid, cat)| {
            matches!(cat.as_str(), "0C" | "0D" | "0E")
                && !FLOAT_KEY_EXCLUSIONS.contains(&nid.as_str())
        })
        .filter(|(nid, cat)| {
            Path::new(&format!(
                "{}/../tests/data/nemetz/{cat}/{nid}.db",
                env!("CARGO_MANIFEST_DIR")
            ))
            .exists()
        })
        .collect();
    v.sort();
    v
}

fn db_path(nid: &str, cat: &str) -> PathBuf {
    PathBuf::from(format!(
        "{}/../tests/data/nemetz/{cat}/{nid}.db",
        env!("CARGO_MANIFEST_DIR")
    ))
}

/// Category totals for one tool. `None` for a tool means it was not run (gated
/// off); a `(matrix, d_deleted, d_recoverable)` triple otherwise.
struct CatTotals {
    matrix: ToolMatrix,
    d_deleted: usize,
    d_recoverable: usize,
}

fn recall_substrate(m: &ToolMatrix, d_recoverable: usize) -> f64 {
    if d_recoverable == 0 {
        1.0
    } else {
        m.tp_recoverable as f64 / d_recoverable as f64
    }
}

fn recall_e2e(m: &ToolMatrix, d_deleted: usize) -> f64 {
    if d_deleted == 0 {
        1.0
    } else {
        m.tp as f64 / d_deleted as f64
    }
}

fn precision(m: &ToolMatrix) -> f64 {
    let denom = m.tp + m.fp;
    if denom == 0 {
        1.0
    } else {
        m.tp as f64 / denom as f64
    }
}

/// Compute per-category totals for ours/undark/fqlite. The `undark`/`fqlite`
/// closures are `None` when the tool is gated off.
fn category_totals(
    cat: &str,
    undark: Option<&Path>,
    fqlite: Option<&Path>,
) -> (CatTotals, Option<CatTotals>, Option<CatTotals>) {
    let mut o = CatTotals {
        matrix: ToolMatrix::default(),
        d_deleted: 0,
        d_recoverable: 0,
    };
    let mut u = undark.map(|_| CatTotals {
        matrix: ToolMatrix::default(),
        d_deleted: 0,
        d_recoverable: 0,
    });
    let mut f = fqlite.map(|_| CatTotals {
        matrix: ToolMatrix::default(),
        d_deleted: 0,
        d_recoverable: 0,
    });

    for (nid, c) in in_scope().into_iter().filter(|(_, c)| c == cat) {
        let path = db_path(&nid, &c);
        let gt = ground_truth(&nid);
        let db = Database::open(std::fs::read(&path).unwrap()).unwrap();

        o.matrix.add(&score(&ours_recover(&db), &gt));
        o.d_deleted += gt.d_deleted;
        o.d_recoverable += gt.d_recoverable;

        if let (Some(bin), Some(tot)) = (undark, u.as_mut()) {
            tot.matrix.add(&score(&undark_recover(bin, &path), &gt));
            tot.d_deleted += gt.d_deleted;
            tot.d_recoverable += gt.d_recoverable;
        }
        if let (Some(tap), Some(tot)) = (fqlite, f.as_mut()) {
            tot.matrix.add(&score(&fqlite_recover(tap, &path), &gt));
            tot.d_deleted += gt.d_deleted;
            tot.d_recoverable += gt.d_recoverable;
        }
    }
    (o, u, f)
}

/// Emit the three-tool comparison table (visible with `--nocapture`) so the table
/// in `docs/recovery-comparison.md` is harness-computed, not hand-written.
#[test]
fn emit_three_tool_comparison() {
    let undark = undark_bin();
    let fqlite = fqlite_tap();
    if undark.is_none() {
        eprintln!("NOTE undark column omitted: set UNDARK_BIN to include it");
    }
    if fqlite.is_none() {
        eprintln!("NOTE fqlite column omitted: set FQLITE_TAP to include it");
    }

    println!(
        "\n{:<3} {:<6} {:>4} {:>5} {:>3} {:>3} {:>3} {:>4} {:>8} {:>8} {:>5}",
        "cat", "tool", "Ddel", "Drec", "TP", "FP", "FN", "live", "rec_sub", "rec_e2e", "prec"
    );
    let print_row = |cat: &str, tool: &str, t: &CatTotals| {
        let m = &t.matrix;
        let fn_ = t.d_recoverable.saturating_sub(m.tp_recoverable);
        println!(
            "{:<3} {:<6} {:>4} {:>5} {:>3} {:>3} {:>3} {:>4} {:>8.3} {:>8.3} {:>5.3}",
            cat,
            tool,
            t.d_deleted,
            t.d_recoverable,
            m.tp,
            m.fp,
            fn_,
            m.live_reread,
            recall_substrate(m, t.d_recoverable),
            recall_e2e(m, t.d_deleted),
            precision(m),
        );
    };
    for cat in ["0C", "0D", "0E"] {
        let (o, u, f) = category_totals(cat, undark.as_deref(), fqlite.as_deref());
        print_row(cat, "ours", &o);
        if let Some(u) = &u {
            print_row(cat, "undark", u);
        }
        if let Some(f) = &f {
            print_row(cat, "fqlite", f);
        }
    }
    println!("\nExcluded (FLOAT key columns, no cross-tool identity): {FLOAT_KEY_EXCLUSIONS:?}");
}

/// fqlite's freeblock-aware reconstruction leads on the clean in-page-deletion
/// category (0C): it recovers substantially more deleted rows than our
/// forward-parse carver, which the freeblock-prefix clobber holds back (task #56).
/// This pins that head-to-head relationship: fqlite's 0C true-positive total
/// clears a floor far above ours, and exceeds our carver's 0C total.
#[test]
fn fqlite_leads_on_0c_inpage_recall() {
    let Some(tap) = fqlite_tap() else {
        eprintln!("SKIP fqlite_leads_on_0c_inpage_recall: set FQLITE_TAP");
        return;
    };
    let (ours, _u, f) = category_totals("0C", None, Some(tap.as_path()));
    let f = f.expect("fqlite requested");
    // Measured: fqlite 67 TP on 0C (excl. 06/07) vs ours 23. Pinned as a floor and
    // a strict-lead relationship, robust to small tap variation.
    assert!(
        f.matrix.tp >= 60,
        "fqlite 0C true positives {} fell below the measured floor 60",
        f.matrix.tp
    );
    assert!(
        f.matrix.tp > ours.matrix.tp,
        "fqlite ({}) must lead ours ({}) on 0C in-page recall",
        f.matrix.tp,
        ours.matrix.tp
    );
}

/// undark mishandles the Nemetz in-page free-block deletions: on the
/// deleted-then-overwritten category (0D) it repeatedly re-surfaces **live** rows
/// as deleted (a precision failure our carver and fqlite do not exhibit). This
/// pins that honest, measured weakness: undark's 0D live-re-read count is large,
/// while ours stays at zero.
#[test]
fn undark_rereads_live_rows_on_0d() {
    let Some(bin) = undark_bin() else {
        eprintln!("SKIP undark_rereads_live_rows_on_0d: set UNDARK_BIN");
        return;
    };
    let (ours, u, _f) = category_totals("0D", Some(bin.as_path()), None);
    let u = u.expect("undark requested");
    // Measured: undark re-reads 56 live 0D rows as deleted; ours re-reads 0.
    assert!(
        u.matrix.live_reread >= 20,
        "undark 0D live-re-reads {} fell below the measured floor 20",
        u.matrix.live_reread
    );
    assert_eq!(
        ours.matrix.live_reread, 0,
        "our carver must never re-surface a live 0D row (got {})",
        ours.matrix.live_reread
    );
}

/// Our carver's edge is precision, not recall: across the in-scope corpus it emits
/// **zero** live-re-reads (a live row is never structurally re-surfaced as
/// deleted), the structural 0-false-positive guarantee — measured here against the
/// same ground truth that scores the other two tools.
#[test]
fn ours_never_rereads_a_live_row() {
    let mut live = 0usize;
    for (nid, cat) in in_scope() {
        let db = Database::open(std::fs::read(db_path(&nid, &cat)).unwrap()).unwrap();
        let gt = ground_truth(&nid);
        live += score(&ours_recover(&db), &gt).live_reread;
    }
    assert_eq!(
        live, 0,
        "our carver re-surfaced {live} live row(s) as deleted across the in-scope corpus"
    );
}
