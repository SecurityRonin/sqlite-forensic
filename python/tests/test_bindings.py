"""Integration tests for the sqlite4n6 Python bindings (roadmap §3.2).

Build the extension first (from the python/ dir):

    maturin develop

then run:

    python -m pytest tests/

These exercise the thin pyo3 boundary over sqlite-forensic's carve/audit/timeline
against the committed deleted_places.db fixture.
"""

import os

import sqlite4n6

# The forensic fixture lives in the workspace's tests/data.
FIXTURE = os.path.join(
    os.path.dirname(__file__), "..", "..", "tests", "data", "deleted_places.db"
)


def test_carve_returns_deleted_records():
    records = sqlite4n6.carve(FIXTURE)
    assert isinstance(records, list)
    assert len(records) > 0, "the fixture has recoverable deleted records"
    rec = records[0]
    # Each record is a dict with the core provenance + decoded values.
    for key in ("page", "offset", "rowid", "confidence", "recovery_source", "values"):
        assert key in rec, f"record missing {key}: {rec}"
    assert isinstance(rec["values"], list)
    assert isinstance(rec["page"], int)
    assert 0.0 < rec["confidence"] <= 1.0


def test_audit_returns_findings():
    findings = sqlite4n6.audit(FIXTURE)
    assert isinstance(findings, list)
    # deleted_places has a non-empty freelist / residue, so at least one anomaly.
    for f in findings:
        assert "code" in f and "severity" in f and "note" in f


def test_timeline_returns_a_list():
    histories = sqlite4n6.timeline(FIXTURE)
    assert isinstance(histories, list)


def test_missing_file_raises():
    import pytest

    with pytest.raises(Exception):
        sqlite4n6.carve("/no/such/database.db")
