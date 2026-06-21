//! Dropped-table **schema** recovery: a `DROP TABLE` deletes the object's
//! `sqlite_master` row, but under `secure_delete=OFF` its bytes survive in
//! page-1 free space. `recover_dropped_schemas` surfaces that residue as a
//! structured [`RecoveredSchema`] — the dropped object's name + `CREATE`
//! statement — which a live-schema read (`live_tables`) can never show.
//!
//! Fixture (`tests/data/dropped_table_schema.db`, Tier-2, real `sqlite3`;
//! ground truth derivable from the construction):
//! ```sql
//! PRAGMA page_size=4096; PRAGMA secure_delete=0;
//! CREATE TABLE keep(id INTEGER PRIMARY KEY, x TEXT);
//! INSERT INTO keep VALUES (1,'a'),(2,'b');
//! CREATE TABLE secrets(id INTEGER PRIMARY KEY, account TEXT, password TEXT);
//! INSERT INTO secrets VALUES (1,'admin','hunter2'),(2,'root','toor');
//! DROP TABLE secrets;   -- only `keep` remains live
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use sqlite_core::Database;
use sqlite_forensic::{audit, recover_dropped_schemas, AnomalyKind};

fn open_fixture() -> Database {
    let bytes = std::fs::read("../tests/data/dropped_table_schema.db")
        .or_else(|_| std::fs::read("tests/data/dropped_table_schema.db"))
        .expect("fixture readable");
    Database::open(bytes).expect("fixture opens")
}

#[test]
fn recovers_dropped_table_create_statement() {
    let db = open_fixture();
    let schemas = recover_dropped_schemas(&db);

    let secrets = schemas
        .iter()
        .find(|s| s.name == "secrets")
        .expect("dropped table `secrets` schema recovered");
    assert_eq!(secrets.object_type, "table");
    assert_eq!(secrets.tbl_name, "secrets");
    assert!(
        secrets.sql.contains("CREATE TABLE secrets") && secrets.sql.contains("password"),
        "recovered CREATE statement must be the dropped table's: {:?}",
        secrets.sql
    );
}

#[test]
fn does_not_report_a_live_table_as_dropped() {
    let db = open_fixture();
    let schemas = recover_dropped_schemas(&db);
    assert!(
        schemas.iter().all(|s| s.name != "keep"),
        "live table `keep` must NOT be reported as a recovered (dropped) schema: {schemas:?}"
    );
}

#[test]
fn audit_surfaces_the_dropped_schema_as_a_finding() {
    let db = open_fixture();
    let found = audit(&db).into_iter().any(|a| {
        matches!(
            a.kind,
            AnomalyKind::DroppedSchemaRecovered { ref name, ref object_type }
                if name == "secrets" && object_type == "table"
        )
    });
    assert!(
        found,
        "audit must surface the dropped `secrets` table as a SQLITE-DROPPED-SCHEMA-RECOVERED finding"
    );
}
