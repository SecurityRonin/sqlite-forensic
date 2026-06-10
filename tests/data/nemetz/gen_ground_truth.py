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
  - per deleted row, `substrate_recoverable`: whether a distinctive column's
    bytes still physically survive in the .db file (computed independently of
    our carver — it is a property of the corpus, telling D_recoverable from
    D_destroyed for the two-denominator recall).
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


def byte_present(raw: bytes, cells: list[str], coltypes: list[dict]) -> bool:
    """Does a distinctive column of this row physically survive in the db bytes?

    TEXT >= 4 chars is searched as UTF-8; INTEGER is searched as its 1/2/3/4/6/8
    byte big-endian two's-complement encodings (SQLite serial types 1-6); REAL is
    searched as its 8-byte big-endian IEEE-754 encoding (serial type 7).
    Conservative: a hit on any distinctive column counts the row as
    substrate-recoverable.
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
                                "substrate_recoverable": byte_present(
                                    raw, cells, coltypes
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
