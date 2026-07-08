# sqlite4n6 (Python bindings)

Python bindings for [`sqlite-forensic`](../forensic) — recover deleted records,
grade anomalies, and reconstruct per-rowid version history from a SQLite database,
from Python.

```python
import sqlite4n6

for rec in sqlite4n6.carve("evidence.db"):
    print(rec["rowid"], rec["recovery_source"], rec["values"])

for finding in sqlite4n6.audit("evidence.db"):
    print(finding["severity"], finding["code"], finding["note"])

for table in sqlite4n6.timeline("evidence.db"):
    print(table["table"], len(table["versions"]))
```

`carve`, `audit`, and `timeline` each take a database path (a conventional
`<path>-wal` sidecar is applied automatically when present) and return plain lists
of dicts. A missing file raises `IOError`; a non-SQLite file raises `ValueError`.

## Build

This crate is a thin pyo3 boundary over the Rust core; it is the only crate in the
tree that links `unsafe` glue, so it lives in its own workspace outside the main
tree's `unsafe_code = "forbid"`.

```sh
cd python
maturin develop      # build + install into the active venv
python -m pytest tests/
```

`abi3-py39` means one wheel works across CPython ≥ 3.9.
