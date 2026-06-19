//! Best-effort, **dependency-free** attribution primitives that reconnect a
//! carved deleted row to the live table it most plausibly belonged to.
//!
//! A deleted row in free space has lost its hard table linkage (the b-tree that
//! owned it no longer points at it). This module supplies the two structural
//! facts the forensic layer needs to reattach it honestly:
//!
//! 1. [`column_names`] — a hand-rolled `CREATE TABLE` column-name extractor (no
//!    SQL-parser dependency). It returns the declared column names when it can
//!    parse them with confidence, or `None` so the caller falls back to generic
//!    `c0..cN` rather than emit wrong names.
//! 2. [`column_affinity`] — each column's declared *affinity* (file-format
//!    §3.1), the shape used to match a freed row whose page linkage is gone.
//!
//! Pure string/structure work: panic-free, `forbid(unsafe)`, no new deps.

/// Column type **affinity** as defined by the `SQLite` file format (§3.1, "Type
/// Affinity"). Derived from a column's declared type by the documented
/// substring rules, in priority order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Affinity {
    /// Declared type contains "INT" → INTEGER affinity.
    Integer,
    /// Declared type contains "CHAR", "CLOB", or "TEXT" → TEXT affinity.
    Text,
    /// Declared type contains "BLOB", or no declared type → BLOB affinity.
    Blob,
    /// Declared type contains "REAL", "FLOA", or "DOUB" → REAL affinity.
    Real,
    /// Anything else → NUMERIC affinity.
    Numeric,
}

/// Compute a column's [`Affinity`] from its declared type string per the
/// file-format §3.1 rules.
#[must_use]
pub fn column_affinity(_declared_type: &str) -> Affinity {
    unimplemented!("RED")
}

/// Best-effort extraction of `(column_name, declared_type)` for each column
/// declared in a `CREATE TABLE` statement, without a SQL-parser dependency.
#[must_use]
pub fn column_defs(_create_sql: &str) -> Option<Vec<(String, String)>> {
    unimplemented!("RED")
}

/// Just the column **names** from [`column_defs`].
#[must_use]
pub fn column_names(_create_sql: &str) -> Option<Vec<String>> {
    unimplemented!("RED")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn affinity_rules_match_spec_priority() {
        assert_eq!(column_affinity("INTEGER"), Affinity::Integer);
        assert_eq!(column_affinity("BIGINT"), Affinity::Integer);
        assert_eq!(column_affinity("VARCHAR(255)"), Affinity::Text);
        assert_eq!(column_affinity("CLOB"), Affinity::Text);
        assert_eq!(column_affinity("TEXT"), Affinity::Text);
        assert_eq!(column_affinity("BLOB"), Affinity::Blob);
        assert_eq!(column_affinity(""), Affinity::Blob);
        assert_eq!(column_affinity("REAL"), Affinity::Real);
        assert_eq!(column_affinity("DOUBLE"), Affinity::Real);
        assert_eq!(column_affinity("FLOAT"), Affinity::Real);
        assert_eq!(column_affinity("NUMERIC"), Affinity::Numeric);
        assert_eq!(column_affinity("DATETIME"), Affinity::Numeric);
        assert_eq!(column_affinity("BOOLEAN"), Affinity::Numeric);
    }

    #[test]
    fn plain_columns() {
        let cols = column_names("CREATE TABLE t (id INTEGER, name TEXT, age INT)").unwrap();
        assert_eq!(cols, vec!["id", "name", "age"]);
    }

    #[test]
    fn quoted_bracketed_backtick_identifiers() {
        let sql = r#"CREATE TABLE "My Tbl" ("first name" TEXT, [second] INTEGER, `third` BLOB)"#;
        let cols = column_names(sql).unwrap();
        assert_eq!(cols, vec!["first name", "second", "third"]);
    }

    #[test]
    fn skips_table_level_constraints() {
        let sql = "CREATE TABLE t (\
            id INTEGER PRIMARY KEY, \
            a TEXT, \
            b REAL, \
            PRIMARY KEY (id), \
            UNIQUE (a), \
            CONSTRAINT fk FOREIGN KEY (b) REFERENCES other(x), \
            CHECK (a <> b))";
        let cols = column_names(sql).unwrap();
        assert_eq!(cols, vec!["id", "a", "b"]);
    }

    #[test]
    fn check_constraint_with_commas_does_not_oversplit() {
        let sql = "CREATE TABLE t (x INTEGER, y INTEGER, CHECK (x IN (1, 2, 3)))";
        let cols = column_names(sql).unwrap();
        assert_eq!(cols, vec!["x", "y"]);
    }

    #[test]
    fn typed_columns_with_parenthesized_and_multiword_types() {
        let sql = "CREATE TABLE t (a VARCHAR(20), b DOUBLE PRECISION, c DECIMAL(10,2))";
        let defs = column_defs(sql).unwrap();
        assert_eq!(defs[0], ("a".to_string(), "VARCHAR(20)".to_string()));
        assert_eq!(defs[1], ("b".to_string(), "DOUBLE PRECISION".to_string()));
        assert_eq!(defs[2], ("c".to_string(), "DECIMAL(10,2)".to_string()));
        assert_eq!(column_affinity(&defs[0].1), Affinity::Text);
        assert_eq!(column_affinity(&defs[1].1), Affinity::Real);
        assert_eq!(column_affinity(&defs[2].1), Affinity::Numeric);
    }

    #[test]
    fn no_parens_is_low_confidence_none() {
        assert_eq!(column_names("CREATE TABLE t"), None);
        assert_eq!(column_names("not even ddl"), None);
    }

    #[test]
    fn unterminated_quote_yields_none() {
        assert_eq!(column_names(r#"CREATE TABLE t ("oops)"#), None);
    }

    #[test]
    fn empty_column_list_is_none() {
        assert_eq!(column_names("CREATE TABLE t ()"), None);
    }
}
