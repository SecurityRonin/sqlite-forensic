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
test, applied **per record by body size** — never per category, so there is no
special-case exemption. A row counts recoverable only when its whole record body
— every column's SQLite serial encoding, concatenated in column order — survives
as a single contiguous byte run in the file. This mirrors exactly what the recall
matcher scores (its key is the full row, `normalize_row` over all cells), so a row
whose scored identity was destroyed by a later same-rowid overwrite — leaving only
a coincidental single surviving column — is correctly NOT counted.

The one documented domain branch is **genuine overflow**: a record whose payload
exceeds the page's in-page limit (`usable - 35`, where `usable = page_size -
reserved`) spills onto a chain of overflow pages (SQLite file format, "Cell
payload overflow pages"), so its body is non-contiguous in the flat file by
construction and a flat contiguity test cannot model it. Such a record is treated
conservatively as NOT contiguous-recoverable (chain-aware overflow recoverability
is future work). This is decided per record from the actual body size and the
DB-header page geometry — not by category. In this corpus most `0E` deleted bodies
are large-but-in-page and contiguous (so they ARE tested honestly); only the few
truly-overflowing records fall into the overflow branch. The dropped-table
categories `0A`/`0B` (no row-level recall denominator) are still computed with the
legacy any-distinctive-column proxy, which their flag is not used by any recall
matrix.
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


# Dropped-table categories: their deleted-row substrate flag feeds no recall matrix
# (the whole table is gone), so they keep the legacy any-distinctive-column proxy
# rather than the per-record contiguity rule the recall categories (0C/0D/0E) use.
DROPPED_TABLE_CATEGORIES = ("0A", "0B")


def page_geometry(raw: bytes) -> tuple[int, int]:
    """The (page_size, usable_size) of a SQLite DB from its file header.

    Page size is the big-endian u16 at offset 16 (the value 1 means 65536); the
    reserved-bytes-per-page count is the u8 at offset 20. usable = page_size -
    reserved (SQLite file format, "The database header").
    """
    import struct

    raw_ps = struct.unpack(">H", raw[16:18])[0]
    page_size = 65536 if raw_ps == 1 else raw_ps
    reserved = raw[20]
    return page_size, page_size - reserved


def _varint(n: int) -> bytes:
    """Minimal SQLite varint encoding of a non-negative integer (1-9 bytes)."""
    if n == 0:
        return b"\x00"
    out: list[int] = []
    while n > 0:
        out.append(n & 0x7F)
        n >>= 7
    out.reverse()
    return bytes((b | 0x80) if i < len(out) - 1 else b for i, b in enumerate(out))


def record_payload_len(cells: list[str], coltypes: list[dict]) -> int | None:
    """Total record payload length (header + body) for one row, the quantity SQLite
    compares against the in-page threshold to decide overflow. Returns None if any
    column cannot be encoded (the caller then declines the contiguity branch).
    """
    serials: list[int] = []
    body_len = 0
    for cell, col in zip(cells, coltypes):
        st = _serial_type(cell, col.get("type"))
        if st is None:
            return None
        serials.append(st)
        body_len += _serial_content_len(st)
    serial_bytes = b"".join(_varint(s) for s in serials)
    hdr = len(serial_bytes)
    # The header length is a varint that counts itself; solve the fixed point.
    header_len = hdr + 1
    while len(_varint(header_len)) + hdr != header_len:
        header_len += 1
    return header_len + body_len


def _serial_type(cell: str, ctype: str | None) -> int | None:
    """The SQLite serial type code for a cell value (None if not encodable)."""
    if cell is None or cell == "":
        return 0
    if ctype == "INTEGER":
        try:
            value = int(cell)
        except ValueError:
            return None
        body = _minimal_int_bytes(value)
        if body is None:
            return None
        return {1: 1, 2: 2, 3: 3, 4: 4, 6: 5, 8: 6}[len(body)]
    if ctype == "REAL":
        try:
            float(cell)
        except ValueError:
            return None
        return 7
    return 13 + 2 * len(cell.encode("utf-8"))  # TEXT (and other affinities verbatim)


def _serial_content_len(serial_type: int) -> int:
    """Body byte count for a serial type (SQLite file format, record format)."""
    if serial_type in (0, 8, 9):
        return 0
    if serial_type in (1, 2, 3, 4):
        return serial_type
    if serial_type == 5:
        return 6
    if serial_type in (6, 7):
        return 8
    return (serial_type - 12) // 2  # BLOB (even) / TEXT (odd) >= 12


def _minimal_int_bytes(value: int) -> bytes | None:
    for width in (1, 2, 3, 4, 6, 8):
        try:
            return value.to_bytes(width, "big", signed=True)
        except OverflowError:
            continue
    return None


def any_distinctive_column_present(
    raw: bytes, cells: list[str], coltypes: list[dict]
) -> bool:
    """Legacy proxy: does *any* distinctive column of this row survive anywhere?

    TEXT >= 4 chars is searched as UTF-8; INTEGER is searched as its 1/2/3/4/6/8
    byte big-endian two's-complement encodings (SQLite serial types 1-6); REAL is
    searched as its 8-byte big-endian IEEE-754 encoding (serial type 7). Used for
    the dropped-table categories (0A/0B), whose flag feeds no recall matrix, and as
    a conservative fallback when a row's columns cannot be serial-encoded.
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
    identity. Decided **per record by body size**, not by category:

      * the dropped-table categories (0A/0B) keep the legacy any-distinctive-column
        proxy — their flag feeds no recall matrix;
      * otherwise, if the record payload fits in-page (<= usable - 35) the body is
        a single contiguous run and the honest contiguous full-row-identity test
        applies;
      * if the payload exceeds that threshold the record overflows onto a
        non-contiguous overflow-page chain (SQLite "Cell payload overflow pages"),
        which a flat-file contiguity test cannot model, so it is treated
        conservatively as NOT recoverable (chain-aware overflow recovery is future
        work).
    """
    if category in DROPPED_TABLE_CATEGORIES:
        return any_distinctive_column_present(raw, cells, coltypes)

    payload = record_payload_len(cells, coltypes)
    if payload is None:
        # A column we cannot serial-encode: fall back to the conservative proxy
        # rather than assert a contiguous identity we cannot construct.
        return any_distinctive_column_present(raw, cells, coltypes)

    _page_size, usable = page_geometry(raw)
    in_page_threshold = usable - 35
    if payload > in_page_threshold:
        return False  # genuine overflow: body spans a non-contiguous chain
    return contiguous_identity_present(raw, cells, coltypes)


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
