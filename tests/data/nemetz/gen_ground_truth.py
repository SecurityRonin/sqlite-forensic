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
import struct
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))

# Every category whose `.xml` answer key tags one or more rows `deleted="1"` — the
# deleted-record ground truth this manifest exists to carry. The remaining
# vendored categories (01-06, 08, 09, 11-16, 19) describe only LIVE content; they
# are parse/format fixtures exercised by the panic-free robustness harness
# (`forensic/tests/nemetz_robustness.rs`) and are deliberately NOT scored as
# deleted-recall, so no fictitious deleted ground truth is invented for them.
#
#   07 Fragmented contents               (1 deleted row, in 07-03)
#   0A Deleted tables / 0B Overwritten tables  (dropped-table proxy)
#   0C Deleted records / 0D Overwritten records / 0E Deleted overflow pages
#   17 Manipulated Freeblock Structures  (anti-forensic; still ships deleted rows)
#   18 Manipulated Freelist Trunks       (anti-forensic; still ships deleted rows)
CATEGORIES = ["07", "0A", "0B", "0C", "0D", "0E", "17", "18"]


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


def _local_payload_len(total: int, usable: int) -> int:
    """SQLite's local-payload split for a table-leaf cell (file format §1.6).

    Port of the Rust `local_payload_len`: the number of payload bytes kept on the
    leaf page; when it equals `total` the record does not spill.
    """
    x = usable - 35
    if total <= x:
        return total
    m = (usable - 12) * 32 // 255 - 23
    k = m + (total - m) % (usable - 4)
    return k if k <= x else m


def _record_payload_bytes(cells: list[str], coltypes: list[dict]) -> bytes | None:
    """The full record payload (header ++ body) the way SQLite stores it, or None
    if any column cannot be serial-encoded. Mirrors `record_payload_len` but emits
    the actual bytes so the overflow chain can be assembled and byte-compared.
    """
    serials: list[int] = []
    body = b""
    for cell, col in zip(cells, coltypes):
        st = _serial_type(cell, col.get("type"))
        if st is None:
            return None
        serials.append(st)
        b = _serial_body(cell, col.get("type"))
        if b is None:
            return None
        body += b
    serial_bytes = b"".join(_varint(s) for s in serials)
    hdr = len(serial_bytes)
    header_len = hdr + 1
    while len(_varint(header_len)) + hdr != header_len:
        header_len += 1
    return _varint(header_len) + serial_bytes + body


def _freelist_leaves(raw: bytes, page_size: int) -> set[int]:
    """The set of freelist **leaf** page numbers (file format §"The Freelist").

    Only leaf pages preserve their former content byte-for-byte; a trunk page has
    its head (next-trunk pointer + leaf count + leaf-number array) written over the
    former content. So chain-followability requires every chain page to be a leaf.
    Bounded against a crafted cyclic trunk chain.
    """
    npages = len(raw) // page_size
    leaves: set[int] = set()
    trunk = int.from_bytes(raw[32:36], "big")
    visited = 0
    while trunk != 0 and visited <= npages:
        visited += 1
        base = (trunk - 1) * page_size
        nxt = int.from_bytes(raw[base : base + 4], "big")
        count = int.from_bytes(raw[base + 4 : base + 8], "big")
        if count > page_size // 4:
            break
        for i in range(count):
            off = base + 8 + i * 4
            leaf = int.from_bytes(raw[off : off + 4], "big")
            if 0 < leaf <= npages:
                leaves.add(leaf)
        trunk = nxt
    return leaves


def chain_followable(raw: bytes, cells: list[str], coltypes: list[dict]) -> bool:
    """Whether a deleted **overflow** row's scored identity physically survives and
    is structurally addressable through a freed overflow-page chain (task #73).

    The honest substrate criterion for the overflow class (Codex ruling #6),
    computed purely from the file bytes and independent of our carver: build the
    expected full payload, find EVERY occurrence of its local-payload prefix in the
    raw file, and for each read the 4-byte big-endian first-overflow pointer that
    follows it and walk the chain — accepting a page only when it is a freelist
    LEAF (content-preserving) — assembling local-prefix ++ chain content. The row
    is recoverable iff some occurrence assembles to byte-exactly the expected
    payload. A chain page reallocated as the freelist trunk (or off the freelist)
    breaks the walk, so a record whose chain bytes were overwritten is correctly
    NOT counted (e.g. 0E-01 rowid 3 'Matteo' -> page 5 trunk -> False).
    """
    payload = _record_payload_bytes(cells, coltypes)
    if payload is None:
        return False
    page_size, usable = page_geometry(raw)
    npages = len(raw) // page_size
    total = len(payload)
    local = _local_payload_len(total, usable)
    if local >= total:
        return False  # not actually spilled
    prefix = payload[:local]
    leaves = _freelist_leaves(raw, page_size)
    per_page = usable - 4
    expected = payload

    start = 0
    while True:
        idx = raw.find(prefix, start)
        if idx < 0:
            return False
        start = idx + 1
        ptr_off = idx + local
        if ptr_off + 4 > len(raw):
            continue
        page = int.from_bytes(raw[ptr_off : ptr_off + 4], "big")
        assembled = bytearray(prefix)
        remaining = total - local
        visited: set[int] = set()
        broke = False
        while remaining > 0:
            if page == 0 or page > npages or page not in leaves or page in visited:
                broke = True
                break
            visited.add(page)
            base = (page - 1) * page_size
            nxt = int.from_bytes(raw[base : base + 4], "big")
            take = min(remaining, per_page)
            assembled += raw[base + 4 : base + 4 + take]
            remaining -= take
            page = nxt
        if not broke and bytes(assembled) == expected:
            return True


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
        non-contiguous overflow-page chain (SQLite "Cell payload overflow pages").
        Chain-aware overflow recovery (task #73): the row is recoverable iff its
        chain is followable through freelist LEAVES to a byte-exact reassembly of
        the expected payload — i.e. the chain bytes physically survived AND are
        structurally addressable. A chain page reallocated as the freelist trunk
        (or otherwise reused) destroys the bytes, so the record is NOT counted.
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
        # Genuine overflow: the body is non-contiguous. Recoverable only when the
        # freed overflow chain is followable to a byte-exact reassembly.
        return chain_followable(raw, cells, coltypes)
    return contiguous_identity_present(raw, cells, coltypes)


def _distinctive_cell_body(cell: str, ctype: str | None) -> bytes | None:
    """The serial-body bytes of a cell ONLY when the cell is *distinctive* — the
    Tier-2 fragment rule (identical to the Rust extractor's `is_distinctive`):

      * TEXT with a UTF-8 body of >= 4 bytes, or
      * REAL (8-byte IEEE-754).

    INTEGER (and NULL/empty/BLOB) return None: a 1-8-byte integer serial pattern
    coincides far too often in a 4 KiB page to anchor identity, so it can ride
    along inside a fragment but never justify counting one. Using the *same*
    distinctiveness rule for the denominator as the extractor uses for emission
    keeps numerator and denominator measuring one concept.
    """
    if cell is None or cell == "":
        return None
    if ctype == "REAL":
        try:
            return struct.pack(">d", float(cell))
        except (ValueError, struct.error):
            return None
    if ctype == "INTEGER":
        return None  # bare integer: not distinctive (coincidence-prone)
    body = cell.encode("utf-8")  # TEXT / other affinities stored verbatim UTF-8
    return body if len(body) >= 4 else None


def fragment_recoverable(
    category: str, raw: bytes, cells: list[str], coltypes: list[dict], substrate: bool
) -> bool:
    """Whether the deleted row is **fragment-recoverable** (Tier-2): its full
    scored identity is destroyed (`not substrate`) yet at least one *distinctive*
    cell's whole serial body still survives contiguously somewhere in the .db
    bytes.

    Disjoint from `substrate_recoverable` by construction (a row is at most one
    of the two). The dropped-table categories (0A/0B) have no row-level recall
    denominator, so they are never fragment-counted. The denominator counts
    survival *anywhere in the file*, including inside live-cell extents the carver
    must never scan, so fragment recall < 1.0 is expected and honest — the
    extractor reaches only fragments at a freeblock/gap anchor with a usable
    template.
    """
    if substrate or category in DROPPED_TABLE_CATEGORIES:
        return False
    for cell, col in zip(cells, coltypes):
        body = _distinctive_cell_body(cell, col.get("type"))
        if body is not None and body in raw:
            return True
    return False


def main() -> None:
    manifest: dict[str, dict] = {}
    for category in CATEGORIES:
        for xml_path in sorted(glob.glob(os.path.join(HERE, category, "*.xml"))):
            stem = os.path.basename(xml_path)[:-4]
            # The deletion categories name their db `NN-MM.db`; the anti-forensic
            # categories (17, 18) name it `NN-MM_antifor.db` while keeping the
            # plain `NN-MM.xml` answer key. Resolve whichever exists and key the
            # manifest by the ACTUAL db stem, so every consumer that builds
            # `{nid}.db` (the metrics harness path construction) resolves the real
            # file rather than a phantom `NN-MM.db`.
            plain = os.path.join(HERE, category, stem + ".db")
            antifor = os.path.join(HERE, category, stem + "_antifor.db")
            if os.path.exists(plain):
                db_path, nid = plain, stem
            elif os.path.exists(antifor):
                db_path, nid = antifor, stem + "_antifor"
            else:
                raise FileNotFoundError(
                    f"no .db for {xml_path} (tried {plain} and {antifor})"
                )
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
                        substrate = substrate_recoverable(
                            category, raw, cells, coltypes
                        )
                        deleted.append(
                            {
                                "cells": cells,
                                "substrate_recoverable": substrate,
                                "fragment_recoverable": fragment_recoverable(
                                    category, raw, cells, coltypes, substrate
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
