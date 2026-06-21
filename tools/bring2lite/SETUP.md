# bring2lite (Python 3) — reproducible setup

Freeblock / freelist / unallocated-area carver oracle. Test gate: `BRING2LITE_CMD`.

- Tool: `bring2lite` (Bring2lite), Python 3.
- Upstream: <https://github.com/bring2lite/bring2lite>
- Commit pin: `e876bf28c1ba03fc598d92832374f72794760ca1`
- Identity sha256:
  - `bring2lite/main.py`
    `5654260c3c9131a70957b6375d6d86ffc6700c95cce0a813e81a7b989984fe94`
  - `bring2lite/classes/gui.py`
    `9273ea13001b96ef53255b084f58d27ebb6b6a69d1153039712bc48660280ea4`

## Reproduce from a fresh clone

```sh
cd tools/bring2lite
git clone https://github.com/bring2lite/bring2lite checkout
git -C checkout checkout e876bf28c1ba03fc598d92832374f72794760ca1
shasum -a 256 checkout/bring2lite/main.py        # must equal 5654260c...4fe94

# 1. Copy the bring2lite/ package to pkg/
cp -R checkout/bring2lite pkg
find pkg -name __pycache__ -type d -exec rm -rf {} +

# 2. Apply our committed patch: replace `is`/`is not` literal comparisons with
#    `==`/`!=` in classes/{gui,sqlite_parser,journal_parser,visualizer}.py
#    (clears every Py3 SyntaxWarning; behaviour-preserving).
( cd pkg && patch -p1 < ../bring2lite.patch )
```

`bring2lite.patch` is committed (small); `pkg/` itself stays gitignored (bulky
upstream source).

## Headless PyQt5 shim (committed under `shim/PyQt5/`)

`classes/visualizer.py` does `from PyQt5.QtWidgets import ...` and
`from PyQt5 import sip` at module load, but the `Visualizer` is only used in
`--gui 1` mode. In `--gui 0` (what the head-to-head runs) no Qt symbol is called.
The shim provides inert stub modules so that import succeeds on a host without
PyQt5:

- `shim/PyQt5/__init__.py`, `QtWidgets.py`, `sip.py`, `_stub.py` — any imported
  name resolves to a no-op stub class (PEP 562 module-level `__getattr__`).

`scripts/run-bring2lite.sh` prepends `shim/` to `PYTHONPATH` **only when a real
PyQt5 is absent** (`python3 -c 'import PyQt5'` probe) — a genuine install always
wins.

## Run / harness gate

```sh
# direct (CLI mode, no GUI):
python3 pkg/main.py --filename <db> --out <dir> --format CSV

# harness gate (the wrapper normalises output to col0,col1,col2,... per line,
# emitting freeblocks/ + freelists/ + unalloc-parsing/ and SUPPRESSING the live
# regular-page-parsing/ re-dump):
BRING2LITE_CMD=scripts/run-bring2lite.sh
```

Verified functional here: on `tests/data/nemetz/0C/0C-02.db` the wrapper emits
`col0,col1,col2,...` carved-deleted records. (bring2lite is documented to crash on
large DBs; the small Nemetz fixtures run fine.)
