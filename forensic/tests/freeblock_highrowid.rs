//! Freeblock reconstruction of deleted rows with a **multi-byte rowid varint**
//! (rowid ≥ 128) — the common case the freeblock-template path silently dropped.
//!
//! When a table-leaf cell is freed, SQLite overwrites its first four bytes with
//! the freeblock header. Those four bytes cover the `payload-length` + `rowid`
//! varints and the record `header_len`. For a **1-byte** rowid the clobber also
//! eats the first serial type, leaving a "known leading serial" the template can
//! supply. For a **2-byte** rowid (any rowid ≥ 128) the prefix is one byte wider,
//! so the clobber stops at `header_len` and **no** serial type is destroyed — the
//! whole serial array survives. The template builder used to reject that case
//! (empty leading-serial list), so every freeblock-clobbered row past rowid 127
//! was lost — and most real tables run well past 127 rows.
//!
//! Fixture (`tests/data/freeblock_2byte_rowid.db`, Tier-2, built with the real
//! `sqlite3` engine; ground truth derivable from the construction):
//! ```sql
//! PRAGMA page_size=4096; PRAGMA secure_delete=0;
//! CREATE TABLE t(id INTEGER PRIMARY KEY, name TEXT, val INTEGER);
//! -- insert id 1..260 as ('name_'||id, id*7), then:
//! DELETE FROM t WHERE id IN (5, 137, 222);
//! ```
//! id 5 has a 1-byte rowid (recovered today); ids 137/222 have a 2-byte rowid in
//! separate (non-coalesced) freeblocks — recovered only once reconstruction can
//! handle a fully-surviving serial array (empty leading-serial template).
//!
//! KNOWN GAP — `#[ignore]`d: removing the `known_lead.is_empty()` template guard
//! recovers these rows but misparses mixed-rowid-width pages into phantoms
//! (off-by-one column shift, because a clobbered cell's own rowid width is
//! unrecoverable from a single live-cell template). The precision-preserving fix
//! disambiguates the clobbered-serial count against the freeblock's exact size
//! (a single freeblock's reconstructed record must tile it exactly). Un-ignore
//! when that lands. The independent sqlite-unhide 09.db (homogeneous high-rowid
//! page) already recovers under the naive fix; mixed pages are the hard case.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::pedantic)]

use sqlite_core::{Database, Value};
use sqlite_forensic::carve_all_deleted_records;

fn recovered_names(db: &Database) -> Vec<String> {
    carve_all_deleted_records(db)
        .into_iter()
        .flat_map(|r| r.values)
        .filter_map(|v| match v {
            Value::Text(t) => Some(t),
            _ => None,
        })
        .collect()
}

#[test]
#[ignore = "known gap: 2-byte-rowid freeblock recovery awaits the \
            precision-preserving (exact-tile) reconstruction; the naive fix \
            misparses mixed-rowid pages into phantoms"]
fn recovers_deleted_rows_with_two_byte_rowid() {
    let bytes = std::fs::read("../tests/data/freeblock_2byte_rowid.db")
        .or_else(|_| std::fs::read("tests/data/freeblock_2byte_rowid.db"))
        .expect("fixture readable");
    let db = Database::open(bytes).expect("fixture opens");
    let names = recovered_names(&db);

    // 1-byte rowid baseline — recovered today.
    assert!(
        names.iter().any(|n| n == "name_5"),
        "1-byte-rowid row name_5 should recover; got {names:?}"
    );

    // 2-byte rowid (≥ 128) in separate freeblocks — the recovery this test pins.
    assert!(
        names.iter().any(|n| n == "name_137"),
        "2-byte-rowid row name_137 must recover (freeblock-clobbered, all serials \
         survive); got {names:?}"
    );
    assert!(
        names.iter().any(|n| n == "name_222"),
        "2-byte-rowid row name_222 must recover; got {names:?}"
    );
}
