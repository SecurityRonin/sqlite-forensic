//! Real-artifact validation for the WebKit/Chrome Local Storage value-decode
//! convenience. A `.localstorage` file is a STANDARD SQLite database that this
//! crate already opens and dumps; the only artifact-specific quirk is that the
//! `ItemTable.value` column is a BLOB holding the string as **UTF-16-LE** (no
//! BOM, no type-prefix byte), so a plain dump surfaces it as opaque hex.
//!
//! The oracle is the real `sqlite3` engine: it builds the `.localstorage` file
//! and stores each value as a genuine UTF-16-LE BLOB, the native reader reads
//! the BLOB back, and [`decode_localstorage_value`] must recover the EXACT
//! original string — including a non-ASCII value that exercises surrogate pairs.
//! Gated on a `sqlite3` binary (PATH, or `SQLITE3_BIN`); skips gracefully when
//! absent so CI runners without `sqlite3` stay green (mirrors the
//! `rebuild_sqlite3_oracle` pattern).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::process::Command;

use sqlite_core::{decode_localstorage_value, is_local_storage_item_table, Database, Value};

/// Resolve a usable `sqlite3` binary, or `None` (test then skips).
fn sqlite3_bin() -> Option<String> {
    let bin = std::env::var("SQLITE3_BIN").unwrap_or_else(|_| "sqlite3".to_string());
    Command::new(&bin)
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|_| bin)
}

/// A unique temp path for a generated `.localstorage` file (caller cleans up).
fn temp_path(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    p.push(format!("sqlite4n6_localstorage_{tag}_{nonce}.localstorage"));
    p
}

/// Encode a string as the UTF-16-LE bytes WebKit stores, rendered as a `sqlite3`
/// `x'..'` BLOB hex literal.
fn utf16le_hex(s: &str) -> String {
    s.encode_utf16()
        .flat_map(u16::to_le_bytes)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Run `sqlite3 <db> "<sql>"`, asserting success.
fn run_sql(bin: &str, db: &PathBuf, sql: &str) {
    let out = Command::new(bin)
        .arg(db)
        .arg(sql)
        .output()
        .expect("sqlite3 must execute");
    assert!(
        out.status.success(),
        "sqlite3 failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn item_table_utf16le_blob_values_round_trip() {
    let Some(bin) = sqlite3_bin() else {
        eprintln!("SKIP item_table_utf16le_blob_values_round_trip: no sqlite3 (set SQLITE3_BIN)");
        return;
    };

    // The real WebKit/Chrome Local Storage schema, values stored as UTF-16-LE
    // BLOBs. The non-ASCII cases (CJK + emoji) exercise multi-code-unit and
    // surrogate-pair decoding, not just the ASCII fast path.
    let cases = [
        ("token", "hello"),
        ("accents", "héllo wörld"),
        ("cjk", "中文字符串"),
        ("emoji", "party 😀🎉 time"),
    ];

    let mut sql = String::from(
        "CREATE TABLE ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, \
         value BLOB NOT NULL ON CONFLICT FAIL);",
    );
    for (k, v) in cases {
        sql.push_str(&format!(
            "INSERT INTO ItemTable VALUES('{k}', x'{}');",
            utf16le_hex(v)
        ));
    }

    let path = temp_path("roundtrip");
    run_sql(&bin, &path, &sql);

    let bytes = std::fs::read(&path).unwrap();
    let db = Database::open(bytes).expect("a .localstorage is a standard SQLite db");
    let dumps = db.live_table_rows();
    let item = dumps
        .iter()
        .find(|d| is_local_storage_item_table(&d.name, &d.column_names))
        .expect("ItemTable schema recognized");

    let mut recovered = std::collections::BTreeMap::new();
    for row in &item.rows {
        let key = match &row.values[0] {
            Value::Text(s) => s.clone(),
            other => panic!("key column should be TEXT, got {other:?}"),
        };
        let decoded = match &row.values[1] {
            // SQLite sees the value as an opaque BLOB — this is the whole gap the
            // convenience fills.
            Value::Blob(b) => decode_localstorage_value(b),
            other => panic!("value column should be a BLOB, got {other:?}"),
        };
        assert!(
            !decoded.lossy,
            "a clean UTF-16-LE value must not be lossy: {key}"
        );
        recovered.insert(key, decoded.text);
    }

    for (k, v) in cases {
        assert_eq!(
            recovered.get(k).map(String::as_str),
            Some(v),
            "exact UTF-16-LE round-trip for key {k}"
        );
    }

    let _ = std::fs::remove_file(&path);
}

#[test]
fn item_table_null_value_reads_as_null_not_decoded() {
    let Some(bin) = sqlite3_bin() else {
        eprintln!(
            "SKIP item_table_null_value_reads_as_null_not_decoded: no sqlite3 (set SQLITE3_BIN)"
        );
        return;
    };

    // A NULL value stays a distinct `Value::Null` at the reader boundary, so a
    // caller never mis-applies the BLOB decode to it (graceful by construction).
    let path = temp_path("null");
    run_sql(
        &bin,
        &path,
        "CREATE TABLE ItemTable (key TEXT, value BLOB); \
         INSERT INTO ItemTable VALUES('present', x'6800690000'); \
         INSERT INTO ItemTable VALUES('missing', NULL);",
    );

    let bytes = std::fs::read(&path).unwrap();
    let db = Database::open(bytes).unwrap();
    let dumps = db.live_table_rows();
    let item = dumps
        .iter()
        .find(|d| is_local_storage_item_table(&d.name, &d.column_names))
        .expect("ItemTable schema recognized");

    let mut null_seen = false;
    for row in &item.rows {
        match &row.values[1] {
            Value::Null => null_seen = true,
            Value::Blob(b) => {
                let _ = decode_localstorage_value(b);
            }
            other => panic!("unexpected value class: {other:?}"),
        }
    }
    assert!(null_seen, "the NULL value must surface as Value::Null");

    let _ = std::fs::remove_file(&path);
}
