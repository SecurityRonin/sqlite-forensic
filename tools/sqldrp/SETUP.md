# SQL-DRP (SQLite Deleted Records Parser / `sqlparse`) — reproducible setup

Oracle for the deleted-record head-to-head. Test gate: `SQLDRP_CMD`.

- Tool: SQLite Deleted Records Parser (`sqlparse`) v1.3, Mari DeGrazia. GPLv3.
- Upstream: <https://github.com/mdegrazia/SQLite-Deleted-Records-Parser>
- Pristine `sqlparse_v1.3.py` sha256:
  `e60b02e8a9a258109b06bdd32ce9f4a7ff05d879fdf0c069d2ebcbba638f9f16`

## Reproduce from a fresh clone

```sh
cd tools/sqldrp
# 1. Fetch the pristine v1.3 script (verify the sha256 above)
curl -sL https://raw.githubusercontent.com/mdegrazia/SQLite-Deleted-Records-Parser/master/sqlparse_v1.3.py \
  -o sqlparse_v1.3.py
shasum -a 256 sqlparse_v1.3.py   # must equal e60b02e8...f9f16

# 2. Apply our committed patch (2to3 Python-2->3 conversion + two bytes-aware fixes)
patch sqlparse_v1.3.py < sqlparse_v1.3.py.patch
```

`sqlparse_v1.3.py.patch` (committed, small) contains:

1. The `2to3 -w -n` result: `print` statements -> `print()`, etc.
2. Magic check made bytes-aware: `"SQLite" not in header` ->
   `b"SQLite" not in header` (the 16-byte header is `bytes` in Py3 since the file
   is opened `"rb"`).
3. `remove_ascii_non_printable` made bytes-aware: it now iterates raw byte values
   (Py3 `bytes` yields `int`s, so the original `ord(ch)` would raise), keeps
   printable ASCII + tab, then decodes to text.

## Run

```sh
python3 tools/sqldrp/sqlparse_v1.3.py -f <db> -o out.tsv   # TSV: Type/Offset/Length/Data
```

Harness gate:

```sh
SQLDRP_CMD=scripts/run-sqldrp.sh   # wrapper resolves tools/sqldrp/sqlparse_v1.3.py by default
```

## Measured capability boundary

`sqlparse` is a printable-**string** carver: its `Data` field is a single
space-joined printable-ASCII blob per freed region, NOT a per-column
`(col0,col1,col2)` record. Under the head-to-head's exact `(col1,col2)` matcher it
exposes no format-stable cross-tool identity and recovers 0 answer-key rows (and
nothing from the integer-valued tables) — reported explicitly, not scored against a
confounded key. Verified functional here: it does emit `Data` blobs (e.g. on
`tests/data/deleted_places.db` it carves the `https://site-NNN…` URLs from
unallocated space), confirming the carver runs; the 0 score is the documented
identity-projection boundary, not a build failure.
