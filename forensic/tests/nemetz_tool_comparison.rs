//! Direct head-to-head: **our carver vs `undark` vs `fqlite` vs `bring2lite` vs
//! the SQLite Deleted Records Parser (`sqlparse`/SQL-DRP)**, every tool scored
//! against the **same** independent Nemetz answer key — exactly as our own carver
//! is scored in `nemetz_metrics.rs`.
//!
//! # Why this test exists (a real head-to-head, not inter-tool concordance)
//!
//! `oracle_differential.rs` reconciles our output against undark/fqlite as
//! *oracles over our own fixture* — it answers "do we agree with them?", not "how
//! does each tool score against ground truth?". This harness answers the second
//! question: it runs the external tools over the Nemetz corpus and computes, **per
//! tool, per database**, a confusion matrix against the *same* `.xml` answer keys
//! the Nemetz authors shipped (`nemetz_ground_truth.json`). All tools pass
//! through the identical ground-truth comparison, so the recall/precision numbers
//! are directly comparable.
//!
//! # The two additional carving oracles (gated, mirror undark/fqlite)
//!
//! - **bring2lite** (Bring2lite, Python 3) — a freeblock / freelist / unallocated
//!   carver. Gated on `BRING2LITE_CMD` (the wrapper `scripts/run-bring2lite.sh`,
//!   which emits one recovered record per line as `col0,col1,col2,...` — the same
//!   row shape undark emits, so its `(col1,col2)` identity is at CSV fields 1/2).
//!   The wrapper emits bring2lite's carved-deleted output (freeblocks + freelists
//!   + unalloc) and suppresses its live-b-tree re-dump (`regular-page-parsing/`).
//! - **SQL-DRP / `sqlparse`** (Mari DeGrazia, Python 2 ported to 3) — gated on
//!   `SQLDRP_CMD` (`scripts/run-sqldrp.sh`). MEASURED CAPABILITY BOUNDARY: SQL-DRP
//!   is a printable-STRING carver. Its output is a TSV `Type/Offset/Length/Data`
//!   where `Data` is a single space-joined printable-ASCII blob per freed region,
//!   **not** a per-column `(col0,col1,col2)` record. It therefore exposes no
//!   format-stable `(col1,col2)` cross-tool identity of the kind this head-to-head
//!   scores, and recovers nothing at all from the integer-valued tables. Under the
//!   exact-tuple matcher every other tool passes through, SQL-DRP's scored set is
//!   structurally empty; the table reports this boundary explicitly rather than
//!   scoring a confounded key (the same discipline that excludes 0C-06/0C-07).
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
//! `FQLITE_TAP` is set (optionally `FQLITE_JAVA`); the bring2lite column skips
//! unless `BRING2LITE_CMD` is set; the SQL-DRP column skips unless `SQLDRP_CMD`
//! is set — identical pattern to `oracle_differential.rs`, so CI without any of
//! the tools still passes. The `ours` column needs no tool and is always
//! computed. Run with `--nocapture` to regenerate the table in
//! `docs/recovery-comparison.md`.

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

fn bring2lite_cmd() -> Option<PathBuf> {
    std::env::var_os("BRING2LITE_CMD").map(PathBuf::from)
}

fn sqldrp_cmd() -> Option<PathBuf> {
    std::env::var_os("SQLDRP_CMD").map(PathBuf::from)
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

/// bring2lite's recovered `(col1,col2)` set via `scripts/run-bring2lite.sh`. The
/// wrapper emits one carved-deleted record per line as `col0,col1,col2,...` (the
/// same row shape undark emits), so the two identity columns are CSV fields 1 and
/// 2 — the same projection our own carver uses (`values.get(1)`/`get(2)`).
/// Whatever the tool emits is taken verbatim: a row bring2lite could only decode
/// as Python `bytes` (e.g. `b'...'`) simply will not match the answer key (an
/// honest miss, not hidden).
fn bring2lite_recover(cmd: &Path, db: &Path) -> BTreeSet<RowId> {
    let out = Command::new(cmd)
        .arg(db)
        .output()
        .expect("bring2lite wrapper must execute");
    let text = String::from_utf8_lossy(&out.stdout);
    let mut set = BTreeSet::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let f = split_csv(line);
        if f.len() >= 3 {
            set.insert((unquote(&f[1]), unquote(&f[2])));
        }
    }
    set
}

/// SQL-DRP's recovered `(col1,col2)` set via `scripts/run-sqldrp.sh`. MEASURED
/// BOUNDARY (see the module header): SQL-DRP is a printable-STRING carver whose
/// output is a TSV `Type<TAB>Offset<TAB>Length<TAB>Data`, where `Data` is one
/// space-joined printable-ASCII blob per freed region — never a per-column
/// `(col0,col1,col2)` record. There is therefore no format-stable `(col1,col2)`
/// tuple to project, so under the exact-tuple matcher every other tool passes
/// through, this set is empty by construction. We still parse the output honestly
/// (skipping the `Type\tOffset\t...` header) so a future structured emitter would
/// be picked up; today every line is a `Data`-blob row that yields no tuple.
fn sqldrp_recover(cmd: &Path, db: &Path) -> BTreeSet<RowId> {
    let out = Command::new(cmd)
        .arg(db)
        .output()
        .expect("sqldrp wrapper must execute");
    let text = String::from_utf8_lossy(&out.stdout);
    let mut set = BTreeSet::new();
    for line in text.lines() {
        if line.trim().is_empty() || line.starts_with("Type\t") {
            continue;
        }
        // SQL-DRP is tab-delimited with a single `Data` blob field; it carries no
        // comma-separated `(col1,col2)` identity, so a comma split yields one
        // field and inserts nothing. Kept general: if a record ever exposed two
        // identity columns they would be picked up here.
        let f = split_csv(line);
        if f.len() >= 3 {
            set.insert((unquote(&f[1]), unquote(&f[2])));
        }
    }
    set
}

/// Parse the normalized `run-sqlite-dissect.sh` output --- one recovered record
/// per line as `rowid,col1,col2,...`, with an optional `rowid,...` header --- into
/// the cross-tool `(col1,col2)` identity set, the same projection every other
/// CSV-emitting oracle is scored on.
fn parse_sqlite_dissect(text: &str) -> BTreeSet<RowId> {
    let _ = text;
    BTreeSet::new() // RED stub: real body lands in the GREEN commit
}

#[test]
fn sqlite_dissect_output_parses_col1_col2() {
    // A header row (skipped), two records, and a blank line (ignored).
    let sample = "rowid,name,city,zip\n\
                  1,Alice,New York,10001\n\
                  \n\
                  2,Bob,Los Angeles,90001\n";
    let got = parse_sqlite_dissect(sample);
    let want: BTreeSet<RowId> = [
        ("Alice".to_string(), "New York".to_string()),
        ("Bob".to_string(), "Los Angeles".to_string()),
    ]
    .into_iter()
    .collect();
    assert_eq!(got, want);
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

/// The F-beta score over precision `p` and recall `r`. `beta < 1` weights
/// precision; `beta > 1` weights recall. Returns 0 when both inputs are 0 (the
/// harmonic mean of two zeros), the forensically correct "recovered nothing
/// useful" reading.
fn f_beta(p: f64, r: f64, beta: f64) -> f64 {
    let b2 = beta * beta;
    let denom = b2 * p + r;
    if denom == 0.0 {
        0.0
    } else {
        (1.0 + b2) * p * r / denom
    }
}

/// F1 = harmonic mean of precision and recall (`beta = 1`): `2PR / (P + R)`.
fn f1(p: f64, r: f64) -> f64 {
    f_beta(p, r, 1.0)
}

/// F0.5 = precision-weighted F-beta (`beta = 0.5`): `1.25PR / (0.25P + R)`.
fn f0_5(p: f64, r: f64) -> f64 {
    f_beta(p, r, 0.5)
}

/// Which external tools to run for a category, each gated independently.
#[derive(Default, Clone, Copy)]
struct Oracles<'a> {
    undark: Option<&'a Path>,
    fqlite: Option<&'a Path>,
    bring2lite: Option<&'a Path>,
    sqldrp: Option<&'a Path>,
}

/// Per-category totals for ours + each gated oracle. A `None` field means the
/// tool was gated off (its column is omitted from the table).
struct CategoryRun {
    ours: CatTotals,
    undark: Option<CatTotals>,
    fqlite: Option<CatTotals>,
    bring2lite: Option<CatTotals>,
    sqldrp: Option<CatTotals>,
}

fn empty_totals() -> CatTotals {
    CatTotals {
        matrix: ToolMatrix::default(),
        d_deleted: 0,
        d_recoverable: 0,
    }
}

/// Compute per-category totals for ours and every gated oracle.
fn category_totals(cat: &str, oracles: Oracles) -> CategoryRun {
    let mut o = empty_totals();
    let mut u = oracles.undark.map(|_| empty_totals());
    let mut f = oracles.fqlite.map(|_| empty_totals());
    let mut b = oracles.bring2lite.map(|_| empty_totals());
    let mut s = oracles.sqldrp.map(|_| empty_totals());

    for (nid, c) in in_scope().into_iter().filter(|(_, c)| c == cat) {
        let path = db_path(&nid, &c);
        let gt = ground_truth(&nid);
        let db = Database::open(std::fs::read(&path).unwrap()).unwrap();

        o.matrix.add(&score(&ours_recover(&db), &gt));
        o.d_deleted += gt.d_deleted;
        o.d_recoverable += gt.d_recoverable;

        let accumulate = |run: Option<&mut CatTotals>, recovered: BTreeSet<RowId>| {
            if let Some(tot) = run {
                tot.matrix.add(&score(&recovered, &gt));
                tot.d_deleted += gt.d_deleted;
                tot.d_recoverable += gt.d_recoverable;
            }
        };
        if let Some(bin) = oracles.undark {
            accumulate(u.as_mut(), undark_recover(bin, &path));
        }
        if let Some(tap) = oracles.fqlite {
            accumulate(f.as_mut(), fqlite_recover(tap, &path));
        }
        if let Some(cmd) = oracles.bring2lite {
            accumulate(b.as_mut(), bring2lite_recover(cmd, &path));
        }
        if let Some(cmd) = oracles.sqldrp {
            accumulate(s.as_mut(), sqldrp_recover(cmd, &path));
        }
    }
    CategoryRun {
        ours: o,
        undark: u,
        fqlite: f,
        bring2lite: b,
        sqldrp: s,
    }
}

/// Emit the head-to-head comparison table (visible with `--nocapture`) so the
/// table in `docs/recovery-comparison.md` is harness-computed, not hand-written.
/// Up to five tools per category: ours (always) plus undark / fqlite / bring2lite
/// / SQL-DRP, each included only when its gate env var is set.
#[test]
fn emit_tool_comparison() {
    let undark = undark_bin();
    let fqlite = fqlite_tap();
    let bring2lite = bring2lite_cmd();
    let sqldrp = sqldrp_cmd();
    if undark.is_none() {
        eprintln!("NOTE undark column omitted: set UNDARK_BIN to include it");
    }
    if fqlite.is_none() {
        eprintln!("NOTE fqlite column omitted: set FQLITE_TAP to include it");
    }
    if bring2lite.is_none() {
        eprintln!("NOTE bring2lite column omitted: set BRING2LITE_CMD to include it");
    }
    if sqldrp.is_none() {
        eprintln!("NOTE SQL-DRP column omitted: set SQLDRP_CMD to include it");
    }
    let oracles = Oracles {
        undark: undark.as_deref(),
        fqlite: fqlite.as_deref(),
        bring2lite: bring2lite.as_deref(),
        sqldrp: sqldrp.as_deref(),
    };

    println!(
        "\n{:<3} {:<10} {:>4} {:>5} {:>3} {:>3} {:>3} {:>4} {:>8} {:>8} {:>5}",
        "cat", "tool", "Ddel", "Drec", "TP", "FP", "FN", "live", "rec_sub", "rec_e2e", "prec"
    );
    let print_row = |cat: &str, tool: &str, t: &CatTotals| {
        let m = &t.matrix;
        let fn_ = t.d_recoverable.saturating_sub(m.tp_recoverable);
        println!(
            "{:<3} {:<10} {:>4} {:>5} {:>3} {:>3} {:>3} {:>4} {:>8.3} {:>8.3} {:>5.3}",
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
    // Rows accumulated for the committed CSV that drives `docs/plot_comparison.py`.
    // Each is `category,tool,recall_substrate,precision,f1,f0_5` — recall_substrate
    // and precision are the same numbers printed in the table, and f1/f0_5 are
    // derived from exactly those two so the chart and the table are provably the
    // same data.
    let mut csv_rows: Vec<String> = Vec::new();
    let mut push_csv = |cat: &str, tool: &str, t: &CatTotals| {
        let r = recall_substrate(&t.matrix, t.d_recoverable);
        let p = precision(&t.matrix);
        csv_rows.push(format!(
            "{cat},{tool},{r:.6},{p:.6},{:.6},{:.6}",
            f1(p, r),
            f0_5(p, r)
        ));
    };

    for cat in ["0C", "0D", "0E"] {
        let run = category_totals(cat, oracles);
        print_row(cat, "ours", &run.ours);
        push_csv(cat, "ours", &run.ours);
        for (tool, totals) in [
            ("undark", &run.undark),
            ("fqlite", &run.fqlite),
            ("bring2lite", &run.bring2lite),
            ("sqldrp", &run.sqldrp),
        ] {
            if let Some(t) = totals {
                print_row(cat, tool, t);
                push_csv(cat, tool, t);
            }
        }
    }
    println!("\nExcluded (FLOAT key columns, no cross-tool identity): {FLOAT_KEY_EXCLUSIONS:?}");

    // Only (re)write the committed CSV when the original ours/undark/fqlite matrix
    // is complete, so the file the chart consumes is never partial. The two newer
    // oracles (bring2lite, SQL-DRP) are appended when their gates are also set; CI
    // without any tool still passes — it just skips the write.
    if undark.is_some() && fqlite.is_some() {
        let csv_path = format!(
            "{}/../docs/img/comparison_metrics.csv",
            env!("CARGO_MANIFEST_DIR")
        );
        let mut body = String::from("category,tool,recall_substrate,precision,f1,f0_5\n");
        for row in &csv_rows {
            body.push_str(row);
            body.push('\n');
        }
        std::fs::write(&csv_path, body).expect("write comparison_metrics.csv");
        eprintln!("WROTE {csv_path}");
    } else {
        eprintln!("NOTE comparison_metrics.csv not rewritten: set both UNDARK_BIN and FQLITE_TAP");
    }
}

/// The F-beta family is computed by the harness (never hand-typed into the doc),
/// so it must be correct for a known precision/recall pair. With P = 0.8 and
/// R = 0.5: F1 = 2·0.8·0.5/(0.8+0.5) = 0.8/1.3 ≈ 0.6153846; F0.5 =
/// 1.25·0.8·0.5/(0.25·0.8+0.5) = 0.5/0.7 ≈ 0.7142857 (precision-weighted, so it
/// sits above F1 when precision exceeds recall). The degenerate all-zero case is
/// 0, and a perfect (1,1) tool scores 1 on both.
#[test]
fn f_beta_family_matches_known_values() {
    let (p, r) = (0.8_f64, 0.5_f64);
    assert!((f1(p, r) - 0.8 / 1.3).abs() < 1e-9, "F1 = {}", f1(p, r));
    assert!(
        (f0_5(p, r) - 0.5 / 0.7).abs() < 1e-9,
        "F0.5 = {}",
        f0_5(p, r)
    );
    // Precision-weighting: with P > R, F0.5 > F1 > R-weighted-low side.
    assert!(f0_5(p, r) > f1(p, r), "F0.5 must exceed F1 when P > R");
    // Degenerate and perfect anchors.
    assert_eq!(f1(0.0, 0.0), 0.0);
    assert_eq!(f0_5(0.0, 0.0), 0.0);
    assert!((f1(1.0, 1.0) - 1.0).abs() < 1e-12);
    assert!((f0_5(1.0, 1.0) - 1.0).abs() < 1e-12);
}

/// After span-walking freeblock reconstruction (task #66), OUR carver leads on the
/// clean in-page-deletion category (0C): it recovers more deleted rows than fqlite
/// while keeping the higher precision and re-reading no live row. This pins the
/// current head-to-head relationship — our 0C true-positive total clears a floor
/// and exceeds fqlite's — which superseded the earlier state (when the
/// freeblock-prefix clobber held our forward parser back and fqlite led).
#[test]
fn ours_leads_on_0c_inpage_recall() {
    let Some(tap) = fqlite_tap() else {
        eprintln!("SKIP ours_leads_on_0c_inpage_recall: set FQLITE_TAP");
        return;
    };
    let run = category_totals(
        "0C",
        Oracles {
            fqlite: Some(tap.as_path()),
            ..Oracles::default()
        },
    );
    let (ours, f) = (run.ours, run.fqlite.expect("fqlite requested"));
    // Measured: ours 70 TP on 0C (excl. 06/07) vs fqlite 67. Pinned as a floor and
    // a strict-lead relationship, robust to small tap variation.
    assert!(
        ours.matrix.tp >= 68,
        "our 0C true positives {} fell below the measured floor 68",
        ours.matrix.tp
    );
    assert!(
        ours.matrix.tp > f.matrix.tp,
        "ours ({}) must lead fqlite ({}) on 0C in-page recall",
        ours.matrix.tp,
        f.matrix.tp
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
    let run = category_totals(
        "0D",
        Oracles {
            undark: Some(bin.as_path()),
            ..Oracles::default()
        },
    );
    let (ours, u) = (run.ours, run.undark.expect("undark requested"));
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

/// bring2lite recovers a real but smaller slice of the deleted set than our carver
/// on the integer in-page-deletion category (0C): it carves the free-block records
/// but reaches fewer of them. Pins the measured relationship — bring2lite clears a
/// true-positive floor (so the column is genuinely exercised, not a no-op) while
/// our carver strictly leads it. Gated on `BRING2LITE_CMD`.
#[test]
fn ours_leads_bring2lite_on_0c_recall() {
    let Some(cmd) = bring2lite_cmd() else {
        eprintln!("SKIP ours_leads_bring2lite_on_0c_recall: set BRING2LITE_CMD");
        return;
    };
    let run = category_totals(
        "0C",
        Oracles {
            bring2lite: Some(cmd.as_path()),
            ..Oracles::default()
        },
    );
    let (ours, b) = (run.ours, run.bring2lite.expect("bring2lite requested"));
    // Measured: bring2lite 40 TP on 0C (excl. 06/07); ours 70. Floor at 30 so the
    // column is proven non-empty, with a strict-lead relationship for ours.
    assert!(
        b.matrix.tp >= 30,
        "bring2lite 0C true positives {} fell below the measured floor 30",
        b.matrix.tp
    );
    assert!(
        ours.matrix.tp > b.matrix.tp,
        "ours ({}) must lead bring2lite ({}) on 0C in-page recall",
        ours.matrix.tp,
        b.matrix.tp
    );
}

/// SQL-DRP's measured capability boundary on the cross-tool identity matcher. It
/// is a printable-STRING carver: its TSV `Data` field is a single space-joined
/// blob per freed region, never a per-column record, so under the exact
/// `(col1,col2)` tuple match every other tool passes through it recovers **zero**
/// answer-key identities across the whole in-scope corpus (and nothing at all from
/// the integer tables, whose values are not printable strings). This pins that
/// boundary as a measurement, not an assumption — a stray comma inside a carved
/// blob may still surface as an honest non-matching phantom (FP), but the true
/// positive count is structurally 0. Gated on `SQLDRP_CMD`.
#[test]
fn sqldrp_recovers_no_cross_tool_identity() {
    let Some(cmd) = sqldrp_cmd() else {
        eprintln!("SKIP sqldrp_recovers_no_cross_tool_identity: set SQLDRP_CMD");
        return;
    };
    let mut tp_total = 0usize;
    for (nid, cat) in in_scope() {
        let gt = ground_truth(&nid);
        tp_total += score(&sqldrp_recover(&cmd, &db_path(&nid, &cat)), &gt).tp;
    }
    assert_eq!(
        tp_total, 0,
        "SQL-DRP recovered {tp_total} answer-key identity(ies) — it is a string \
         carver with no format-stable (col1,col2) record, so 0 is the documented \
         boundary; a non-zero count means the output shape changed and the matcher \
         must be re-examined"
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

// --- live sqlite_master re-read measurement (per tool) -----------------------
//
// A *live `sqlite_master` re-read* is a carving tool emitting the database's
// CURRENT schema-table row (the `(type, name, tbl_name, rootpage, sql)` definition
// record that still lives on page 1) as if it were a recovered DELETED record.
// It is a pure precision artifact: the schema row was never deleted, so surfacing
// it as "recovered" mis-reports a live object as evidence. This is distinct from
// the user-row `live_reread` the confusion matrix already tracks (carved ∈ alive)
// — the schema row is not a user-table row and never enters the `alive` set.
//
// The detector is GENERAL, derived from the schema itself, not from any per-DB
// constant: each tool's recovered records are projected to the schema identity
// `(type, name, tbl_name)` and counted iff that identity equals a row returned by
// `Database::live_schema_rows()` (the currently-live page-1 schema). A genuinely
// deleted PRIOR schema version (e.g. a dropped table's old `CREATE TABLE`) has a
// different identity and is therefore NOT counted — only the LIVE row is.

/// The CURRENT live `sqlite_master` identities of a database, as
/// `(type, name, tbl_name)` strings rendered with the same `cell()` convention
/// used for every other tool projection. A recovered record matching one of these
/// is the live schema row re-surfaced.
fn live_schema_identities(db: &Database) -> BTreeSet<(String, String, String)> {
    db.live_schema_rows()
        .iter()
        .map(|row| (cell(row.first()), cell(row.get(1)), cell(row.get(2))))
        .collect()
}

/// Our carver's count of recovered records equal to a live `sqlite_master` row —
/// 0 after the precision fix that folds the live schema rows into the live filter.
fn ours_schema_rereads(db: &Database) -> usize {
    let live = live_schema_identities(db);
    carve_all_deleted_records(db)
        .iter()
        .filter(|r| {
            live.contains(&(
                cell(r.values.first()),
                cell(r.values.get(1)),
                cell(r.values.get(2)),
            ))
        })
        .count()
}

/// undark's count of recovered records equal to a live `sqlite_master` row.
/// undark emits raw `rowid,addr,col1,col2,...` cell rows; a re-read of the schema
/// row would surface its `(type, name, tbl_name)` as the first three data fields
/// (CSV fields 1/2/3 after the rowid+addr prefix). undark does not reconstruct
/// `sqlite_master`, so this is measured (not assumed) to be 0.
fn undark_schema_rereads(
    undark: &Path,
    db_file: &Path,
    live: &BTreeSet<(String, String, String)>,
) -> usize {
    let out = Command::new(undark)
        .arg("-i")
        .arg(db_file)
        .output()
        .expect("undark must execute");
    let text = String::from_utf8_lossy(&out.stdout);
    let mut n = 0;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let f = split_csv(line);
        if f.len() >= 4 && live.contains(&(unquote(&f[1]), unquote(&f[2]), unquote(&f[3]))) {
            n += 1;
        }
    }
    n
}

/// fqlite's count of recovered records equal to a live `sqlite_master` row.
/// fqlite emits the schema record as `rowid,offset,id,rootpage,type,name,tbl_name,
/// ncol,sql` — its `(type, name, tbl_name)` are CSV fields 4/5/6. Counted iff that
/// identity equals a currently-live page-1 schema row (so a genuinely-deleted
/// PRIOR schema version, which carries a different identity, is not miscounted).
fn fqlite_schema_rereads(
    tap: &Path,
    db_file: &Path,
    live: &BTreeSet<(String, String, String)>,
) -> usize {
    let out = Command::new(tap)
        .arg(db_file)
        .output()
        .expect("fqlite tap must execute");
    let text = String::from_utf8_lossy(&out.stdout);
    let mut n = 0;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let f = split_csv(line);
        if f.len() >= 7 && live.contains(&(unquote(&f[4]), unquote(&f[5]), unquote(&f[6]))) {
            n += 1;
        }
    }
    n
}

/// Per-tool live `sqlite_master` re-read totals across the in-scope (0C/0D/0E)
/// corpus, the precision artifact this measures: our carver re-reads the live
/// schema row **0** times (the live-schema precision filter), undark **0** times
/// (it never reconstructs `sqlite_master`), and fqlite **25** times (it emits the
/// live schema-table row as a recovered record on every in-scope database — one
/// per single-table DB, two per two-table DB). The scope is `in_scope()`, the
/// same 18 databases the head-to-head scores (0C/0D/0E minus the two FLOAT-key
/// exclusions 0C-06/0C-07); including those two would add 3 more fqlite re-reads
/// (0C-06 has one schema row, 0C-07 two), for 28 over all twenty 0C/0D/0E
/// databases. Pinned as exact
/// measurements; the undark/fqlite legs skip when their gate env var is unset (CI
/// stays green without the tools), while the `ours == 0` guarantee is always
/// asserted.
#[test]
fn live_sqlite_master_rereads_per_tool() {
    let undark = undark_bin();
    let fqlite = fqlite_tap();

    let mut ours_total = 0usize;
    let mut undark_total = 0usize;
    let mut fqlite_total = 0usize;

    for (nid, cat) in in_scope() {
        let path = db_path(&nid, &cat);
        let db = Database::open(std::fs::read(&path).unwrap()).unwrap();
        let live = live_schema_identities(&db);
        assert!(
            !live.is_empty(),
            "{nid}: a live (non-dropped) table DB must carry a live sqlite_master row to guard against"
        );
        ours_total += ours_schema_rereads(&db);
        if let Some(bin) = &undark {
            undark_total += undark_schema_rereads(bin, &path, &live);
        }
        if let Some(tap) = &fqlite {
            fqlite_total += fqlite_schema_rereads(tap, &path, &live);
        }
    }

    // Our carver: the structural guarantee — never re-read the live schema row.
    assert_eq!(
        ours_total, 0,
        "our carver re-read the live sqlite_master row {ours_total} time(s) across 0C/0D/0E"
    );

    if undark.is_some() {
        assert_eq!(
            undark_total, 0,
            "undark live sqlite_master re-reads {undark_total} (expected 0 — undark does not reconstruct the schema row)"
        );
    } else {
        eprintln!("SKIP undark schema-reread leg: set UNDARK_BIN");
    }

    if fqlite.is_some() {
        assert_eq!(
            fqlite_total, NEMETZ_FQLITE_SCHEMA_REREADS,
            "fqlite live sqlite_master re-reads {fqlite_total} (expected {NEMETZ_FQLITE_SCHEMA_REREADS})"
        );
    } else {
        eprintln!("SKIP fqlite schema-reread leg: set FQLITE_TAP");
    }
}

/// fqlite's measured live `sqlite_master` re-read total across the in-scope
/// (0C/0D/0E) corpus — the 18 databases the head-to-head scores (minus the two
/// FLOAT-key exclusions 0C-06/0C-07). fqlite emits the live schema-table row as a
/// recovered record on every in-scope database (one per single-table DB, two per
/// two-table DB), 25 in total. Pinned so a change in fqlite's schema-row behavior
/// surfaces as a test update.
const NEMETZ_FQLITE_SCHEMA_REREADS: usize = 25;
