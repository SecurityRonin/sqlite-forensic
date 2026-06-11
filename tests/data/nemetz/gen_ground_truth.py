#!/usr/bin/env python3
"""Generate nemetz_ground_truth.json from the vendored Nemetz answer-key XMLs.

The SQLite Forensic Corpus (Nemetz/Schmitt/Freiling, DFRWS-EU 2018, CC0) ships a
per-database `.xml` answer key tagging every deleted row with `deleted="1"` and
its full column content, plus a `.sql` build+DELETE provenance script. This
script parses those XMLs into a single machine-checkable manifest consumed by
`forensic/tests/nemetz_metrics.rs`.

It is committed (not run at test time) so the manifest is reproducible and
human-auditable. Re-run after re-vendoring:

    python3 tests/data/nemetz/gen_ground_truth.py

For each table element it records:
  - schema column names + declared SQLite type-affinity names (column order),
  - the deleted rows (the recall ground truth) and the alive rows (used to
    classify a carved row as a live-re-read FP rather than a phantom FP),
  - per deleted row, `substrate_recoverable`: whether the row's **full scored
    identity** still physically survives in the .db file (computed independently
    of our carver — it is a property of the corpus, telling D_recoverable from
    D_destroyed for the two-denominator recall).

Substrate-recoverable is decided by an honest **contiguous full-row-identity**
test for the in-page record-deletion categories (`0C`, `0D`): a row counts
recoverable only when its whole record body — every column's SQLite serial
encoding, concatenated in column order — survives as a single contiguous byte run
in the file. This mirrors exactly what the recall matcher scores (its key is the
full row, `normalize_row` over all cells), so a row whose scored identity was
destroyed by a later same-rowid overwrite — leaving only a coincidental single
surviving column — is correctly NOT counted.

The overflow category (`0E`) is a documented domain discontinuity: its record
bodies (here 1.3-4.1 KB) exceed the in-page payload limit and SQLite stores the
spill on a chain of overflow pages (file-format section "Cell payload overflow
pages"). The body is therefore non-contiguous in the flat file by construction,
so a contiguity test would understate recoverability there; `0E` (and the
dropped-table categories `0A`/`0B`, which carry no row-level recall denominator)
keep the legacy any-distinctive-column survival proxy. The contiguity rule is
applied exactly where the record is contiguous (in-page) and not where the format
itself makes it non-contiguous (overflow).
"""

from __future__ import annotations

import glob
import json
import os
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
CATEGORIES = ["0A", "0B", "0C", "0D", "0E"]


def parse_columns(element: ET.Element) -> list[dict]:
    sql = element.find("sql")
    cols = []
    if sql is not None:
        for cd in sql.findall("columnDefinition"):
            meta = cd.find("meta")
            cols.append(
                {
                    "name": meta.findtext("name") if meta is not None else None,
                    "type": cd.findtext("columnTypeName"),
                }
            )
    return cols


def row_cells(row: ET.Element) -> list[str]:
    return [c.findtext("content") or "" for c in row.findall("column")]


# Categories whose deletions are IN-PAGE (the freed cell, and any later overwrite,
# live entirely within one page), so the record body is a single contiguous run
# and the honest contiguous full-row-identity test is faithful. 0E is excluded —
# its records overflow onto a non-contiguous overflow-page chain (see module docs).
CONTIGUOUS_IDENTITY_CATEGORIES = ("0C", "0D")


def any_distinctive_column_present(
    raw: bytes, cells: list[str], coltypes: list[dict]
) -> bool:
    """Legacy proxy: does *any* distinctive column of this row survive anywhere?

    TEXT >= 4 chars is searched as UTF-8; INTEGER is searched as its 1/2/3/4/6/8
    byte big-endian two's-complement encodings (SQLite serial types 1-6); REAL is
    searched as its 8-byte big-endian IEEE-754 encoding (serial type 7). Used for
    the overflow category (0E) and the dropped-table categories (0A/0B), where the
    record body is non-contiguous (overflow chain) or absent from the recall
    denominator, so a contiguity test does not apply.
    """
    import struct

    for cell, col in zip(cells, coltypes):
        if cell is None or cell == "":
            continue
        ctype = col.get("type")
        if ctype == "TEXT" and len(cell) >= 4:
            if cell.encode("utf-8") in raw:
                return True
        elif ctype == "INTEGER":
            try:
                value = int(cell)
            except ValueError:
                continue
            for width in (1, 2, 3, 4, 6, 8):
                try:
                    if value.to_bytes(width, "big", signed=True) in raw:
                        return True
                except OverflowError:
                    pass
        elif ctype == "REAL":
            try:
                if struct.pack(">d", float(cell)) in raw:
                    return True
            except (ValueError, struct.error):
                pass
    return False


def _serial_body(cell: str, ctype: str | None) -> bytes | None:
    """The SQLite record-body bytes for one cell value, in the form a real record
    stores it — so concatenating these in column order reproduces the contiguous
    body a carver reads. NULL/empty -> zero bytes (serial type 0, header-only).
    Returns None for a value we cannot encode (the caller then declines to assert).

    INTEGER uses the *minimal* signed serial width SQLite would pick (types 1-6),
    REAL the 8-byte big-endian IEEE-754 (type 7), TEXT the verbatim UTF-8 (types
    13+), matching `carved_key`/`normalize_row` on the decode side.
    """
    import struct

    if cell is None or cell == "":
        return b""
    if ctype == "INTEGER":
        try:
            value = int(cell)
        except ValueError:
            return None
        for width in (1, 2, 3, 4, 6, 8):
            try:
                return value.to_bytes(width, "big", signed=True)
            except OverflowError:
                continue
        return None
    if ctype == "REAL":
        try:
            return struct.pack(">d", float(cell))
        except (ValueError, struct.error):
            return None
    # TEXT and any other declared affinity: stored verbatim as UTF-8.
    return cell.encode("utf-8")


def contiguous_identity_present(
    raw: bytes, cells: list[str], coltypes: list[dict]
) -> bool:
    """Does the row's FULL scored identity survive contiguously in the db bytes?

    Builds the record body the way SQLite stores it — each column's serial-body
    encoding concatenated in column order — and requires that whole byte run to
    appear contiguously in the file. This is the exact substrate counterpart of
    the recall matcher's full-row key (`normalize_row` over all cells): if the run
    survives, a carver could decode every column and reconstruct the scored
    identity; if a later same-rowid overwrite clobbered any scored column, the run
    is broken and the row is correctly NOT counted (even though a single column may
    still match somewhere — the inflation the old proxy suffered).
    """
    parts: list[bytes] = []
    for cell, col in zip(cells, coltypes):
        body = _serial_body(cell, col.get("type"))
        if body is None:
            # A column we cannot encode: do not assert contiguous survival.
            return any_distinctive_column_present(raw, cells, coltypes)
        parts.append(body)
    body = b"".join(parts)
    if not body:
        return False
    return body in raw


def substrate_recoverable(
    category: str, raw: bytes, cells: list[str], coltypes: list[dict]
) -> bool:
    """Whether the deleted row's bytes still permit reconstructing its scored
    identity — honest contiguous full-row-identity for the in-page categories,
    the legacy any-distinctive-column proxy for overflow / dropped-table ones.
    """
    if category in CONTIGUOUS_IDENTITY_CATEGORIES:
        return contiguous_identity_present(raw, cells, coltypes)
    return any_distinctive_column_present(raw, cells, coltypes)


def main() -> None:
    manifest: dict[str, dict] = {}
    for category in CATEGORIES:
        for xml_path in sorted(glob.glob(os.path.join(HERE, category, "*.xml"))):
            nid = os.path.basename(xml_path)[:-4]
            db_path = os.path.join(HERE, category, nid + ".db")
            raw = open(db_path, "rb").read()
            root = ET.parse(xml_path).getroot()
            elements = []
            for element in root.findall("element"):
                meta = element.find("meta")
                if meta is None or meta.findtext("type") != "table":
                    continue
                coltypes = parse_columns(element)
                deleted, alive = [], []
                for row in element.iter("row"):
                    cells = row_cells(row)
                    if row.get("deleted") == "1":
                        deleted.append(
                            {
                                "cells": cells,
                                "substrate_recoverable": substrate_recoverable(
                                    category, raw, cells, coltypes
                                ),
                            }
                        )
                    else:
                        alive.append(cells)
                elements.append(
                    {
                        "table": meta.findtext("name"),
                        "columns": coltypes,
                        "rows_total": int(meta.findtext("rowsTotal") or 0),
                        "rows_alive": int(meta.findtext("rowsAlive") or 0),
                        "rows_deleted": int(meta.findtext("rowsDeleted") or 0),
                        "deleted": deleted,
                        "alive": alive,
                    }
                )
            manifest[nid] = {"category": category, "elements": elements}

    out_path = os.path.join(HERE, "nemetz_ground_truth.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=1, sort_keys=True)
        f.write("\n")
    print(f"wrote {out_path}: {len(manifest)} databases")


if __name__ == "__main__":
    main()
