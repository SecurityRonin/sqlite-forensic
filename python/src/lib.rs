//! Python bindings for the sqlite-forensic carver / auditor / timeline (roadmap
//! §3.2). A THIN pyo3 boundary: every function opens a database from a path (with
//! its `-wal` sidecar when present), calls the already-tested library function,
//! and marshals the result into native Python objects. All correctness lives in
//! `sqlite-forensic`; this crate only converts types across the FFI boundary.
//!
//! This is the one crate in the tree that links pyo3's `unsafe` glue, so it sits
//! in its own workspace outside the main tree's `unsafe_code = "forbid"`.

// pyo3 0.22's `#[pyfunction]` wrapper expands to an `.into()` on an already-`PyErr`
// result; the useless-conversion lint fires on that macro-generated code, not ours.
#![allow(clippy::useless_conversion)]

use pyo3::exceptions::{PyIOError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

use sqlite_core::{Database, Value};

/// Open a database from `path`, applying a conventional `<path>-wal` sidecar when
/// one exists. An unreadable file is an `IOError`; a malformed/non-SQLite file is
/// a `ValueError` — the failure is surfaced, never swallowed.
fn open_db(path: &str) -> PyResult<Database> {
    let bytes =
        std::fs::read(path).map_err(|e| PyIOError::new_err(format!("cannot read {path}: {e}")))?;
    let db = match std::fs::read(format!("{path}-wal")) {
        Ok(wal) => Database::open_with_wal(bytes, &wal),
        Err(_) => Database::open(bytes),
    };
    db.map_err(|e| PyValueError::new_err(format!("cannot open {path} as SQLite: {e:?}")))
}

/// Marshal a decoded SQLite [`Value`] into the natural Python object: NULL→None,
/// integer→int, real→float, text→str, blob→bytes (lossless).
fn value_to_py(py: Python<'_>, v: &Value) -> PyObject {
    match v {
        Value::Null => py.None(),
        Value::Integer(n) => n.into_py(py),
        Value::Real(r) => r.into_py(py),
        Value::Text(t) => t.into_py(py),
        Value::Blob(b) => PyBytes::new_bound(py, b).into_py(py),
    }
}

fn values_list<'py>(py: Python<'py>, values: &[Value]) -> Bound<'py, PyList> {
    let list = PyList::empty_bound(py);
    for v in values {
        // Append cannot fail for a freshly-built list of owned objects.
        let _ = list.append(value_to_py(py, v));
    }
    list
}

/// Recover deleted records from a database's free space. Returns a list of dicts:
/// `page`, `offset`, `rowid`, `confidence`, `recovery_source`, `values`.
#[pyfunction]
fn carve(py: Python<'_>, db_path: &str) -> PyResult<Py<PyList>> {
    let db = open_db(db_path)?;
    let records = sqlite_forensic::carve_all_deleted_records(&db);
    let out = PyList::empty_bound(py);
    for r in &records {
        let d = PyDict::new_bound(py);
        d.set_item("page", r.page)?;
        d.set_item("offset", r.offset)?;
        d.set_item("rowid", r.rowid)?;
        d.set_item("confidence", r.confidence)?;
        d.set_item("recovery_source", format!("{:?}", r.source))?;
        d.set_item("values", values_list(py, &r.values))?;
        out.append(d)?;
    }
    Ok(out.unbind())
}

/// Grade forensically-notable anomalies. Returns a list of dicts: `code`,
/// `severity`, `note`.
#[pyfunction]
fn audit(py: Python<'_>, db_path: &str) -> PyResult<Py<PyList>> {
    let db = open_db(db_path)?;
    let anomalies = sqlite_forensic::audit(&db);
    let out = PyList::empty_bound(py);
    for a in &anomalies {
        let d = PyDict::new_bound(py);
        d.set_item("code", a.code)?;
        d.set_item("severity", format!("{:?}", a.severity))?;
        d.set_item("note", &a.note)?;
        out.append(d)?;
    }
    Ok(out.unbind())
}

/// Reconstruct per-rowid version history over the WAL commit sequence (carved
/// residue folded in). Returns a list of dicts: `table`, `columns`, and
/// `versions` (each `rowid`, `values`, `is_deleted`, `reinserted_after_gap`).
#[pyfunction]
fn timeline(py: Python<'_>, db_path: &str) -> PyResult<Py<PyList>> {
    let db = open_db(db_path)?;
    let histories = sqlite_forensic::row_histories_with_residue(&db);
    let out = PyList::empty_bound(py);
    for h in &histories {
        let d = PyDict::new_bound(py);
        d.set_item("table", &h.table)?;
        d.set_item("columns", h.columns.clone())?;
        let versions = PyList::empty_bound(py);
        for v in &h.versions {
            let vd = PyDict::new_bound(py);
            vd.set_item("rowid", v.rowid)?;
            vd.set_item("values", values_list(py, &v.values))?;
            vd.set_item("is_deleted", v.is_deleted)?;
            vd.set_item("reinserted_after_gap", v.reinserted_after_gap)?;
            versions.append(vd)?;
        }
        d.set_item("versions", versions)?;
        out.append(d)?;
    }
    Ok(out.unbind())
}

/// The `sqlite4n6` Python module.
#[pymodule]
fn sqlite4n6(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(carve, m)?)?;
    m.add_function(wrap_pyfunction!(audit, m)?)?;
    m.add_function(wrap_pyfunction!(timeline, m)?)?;
    m.add(
        "__doc__",
        "Forensic recovery for SQLite: carve, audit, timeline.",
    )?;
    Ok(())
}
