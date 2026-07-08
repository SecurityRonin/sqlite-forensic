//! Foundation for index-b-tree reading (roadmap §1.4): parse the cells of an
//! index-b-tree LEAF page (type 0x0a) into their decoded key records.
//!
//! A regular index on a rowid table stores each entry as a record of the indexed
//! columns followed by the rowid; a `WITHOUT ROWID` table stores its rows the same
//! way (the row IS the index key). This reads the LIVE cells — the structural
//! parser every later index-carve / WITHOUT-ROWID recovery builds on.
//!
//! Tier-2 oracle: the database is minted by the real `sqlite3` engine and the
//! index root is resolved from `sqlite_master`, so the expected keys are derived
//! from the documented construction, not a hand-authored fixture. Env-gated on a
//! `sqlite3` binary (`SQLITE3_BIN`, else PATH); skips cleanly when absent.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

use sqlite_core::{Database, Value};

fn sqlite3_bin() -> Option<String> {
    let bin = std::env::var("SQLITE3_BIN").unwrap_or_else(|_| "sqlite3".to_string());
    Command::new(&bin)
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|_| bin)
}

/// Resolve the `rootpage` of the index named `name` from `sqlite_master`.
fn index_root(db: &Database, name: &str) -> Option<u32> {
    // sqlite_master: (type, name, tbl_name, rootpage, sql).
    let rows = db.read_table(1, 5).ok()?;
    rows.iter().find_map(|r| {
        let is_named_index = matches!(r.values.first(), Some(Value::Text(t)) if t == "index")
            && matches!(r.values.get(1), Some(Value::Text(n)) if n == name);
        if !is_named_index {
            return None;
        }
        match r.values.get(3) {
            Some(Value::Integer(p)) => u32::try_from(*p).ok(),
            _ => None,
        }
    })
}

#[test]
fn reads_live_index_leaf_entries() {
    let Some(bin) = sqlite3_bin() else {
        eprintln!("SKIP index_btree: no sqlite3 (set SQLITE3_BIN)");
        return;
    };
    let dir = std::env::temp_dir().join("sqlite4n6-index-btree");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db_path: PathBuf = dir.join("idx.db");

    // Few rows → the index fits on a single leaf page (type 0x0a).
    let sql = "PRAGMA page_size=4096; CREATE TABLE t(a TEXT, b INTEGER); \
               CREATE INDEX idx_b ON t(b); \
               INSERT INTO t VALUES('alpha',30),('bravo',10),('charlie',20);";
    assert!(
        Command::new(&bin)
            .arg(&db_path)
            .arg(sql)
            .status()
            .unwrap()
            .success(),
        "sqlite3 construction failed"
    );

    let db = Database::open(std::fs::read(&db_path).unwrap()).unwrap();
    let root = index_root(&db, "idx_b").expect("idx_b root resolves from sqlite_master");
    let page = db.raw_page(root).expect("index root page in range");

    let entries = db.index_leaf_cells(&page);

    // A regular index on a rowid table stores (b, rowid) per entry; sqlite orders
    // the leaf by the key, so the b-values are ascending: 10, 20, 30.
    let bvals: Vec<i64> = entries
        .iter()
        .filter_map(|cols| match cols.first() {
            Some(Value::Integer(n)) => Some(*n),
            _ => None,
        })
        .collect();
    assert_eq!(
        bvals,
        vec![10, 20, 30],
        "index keys, ascending: {entries:?}"
    );
    // Each entry carries the trailing rowid too (2 columns: b, rowid).
    assert!(
        entries.iter().all(|c| c.len() == 2),
        "each index entry is (key, rowid): {entries:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A non-index-leaf page (e.g. a table leaf, 0x0d) yields no index cells — the
/// parser is page-type gated and never mis-reads a table page as an index.
#[test]
fn table_leaf_page_yields_no_index_cells() {
    // A tiny table-only database: page 2 is the table leaf.
    let Some(bin) = sqlite3_bin() else {
        return;
    };
    let dir = std::env::temp_dir().join("sqlite4n6-index-btree-neg");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db_path = dir.join("t.db");
    assert!(Command::new(&bin)
        .arg(&db_path)
        .arg("PRAGMA page_size=4096; CREATE TABLE t(a); INSERT INTO t VALUES(1),(2);")
        .status()
        .unwrap()
        .success());
    let db = Database::open(std::fs::read(&db_path).unwrap()).unwrap();
    // Find the table leaf (0x0d) and confirm index_leaf_cells returns nothing.
    let mut checked = false;
    for pg in 2..=db.page_count() {
        if let Some(page) = db.raw_page(pg) {
            if page.first() == Some(&0x0d) {
                assert!(
                    db.index_leaf_cells(&page).is_empty(),
                    "a table-leaf page must yield no index cells"
                );
                checked = true;
            }
        }
    }
    assert!(checked, "expected at least one table-leaf page");
    let _ = std::fs::remove_dir_all(&dir);
}

// Silence unused-import warnings when the env gate skips both tests.
#[allow(dead_code)]
fn _uses(_: &Path) {}
