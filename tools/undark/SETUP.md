# undark (C) — reproducible setup

Independent deleted-record carver oracle. Test gate: `UNDARK_BIN`.

- Tool: `undark` 0.7.1, Paul L. Daniels. BSD-Revised.
- Upstream: <https://github.com/inflex/undark>
- Source tarball (master):
  <https://github.com/inflex/undark/archive/refs/heads/master.tar.gz>
- Tarball sha256: `c0a9ee7ebd180727deef52fbafe0ef0e2b7c9b43c5604761bfeb86bc9306912a`

## Why a patch is needed (macOS / clang)

Upstream `undark.c` uses two GCC **nested function** definitions (`swap64`,
`ntohll`) inside `decode_row()`, which clang rejects, and names one of them
`ntohll`, which collides with the macOS `<sys/_endian.h>` `ntohll` macro. The
committed `undark.patch` makes two minimal, behavior-preserving changes:

1. Hoist `swap64` / `ntohll` out of `decode_row()` to file scope (`static`).
2. Rename `ntohll` -> `u_ntohll` (both the definition and its one call site,
   `nn = (double) u_ntohll(n);`) to dodge the macOS macro.

## Reproduce from a fresh clone

```sh
cd tools/undark
curl -sL https://github.com/inflex/undark/archive/refs/heads/master.tar.gz -o master.tar.gz
shasum -a 256 master.tar.gz    # must equal c0a9ee7e...912a
tar xzf master.tar.gz          # -> undark-master/

# Apply our committed patch (diff vs pristine undark.c), then build
patch undark-master/undark.c < undark.patch
make -C undark-master          # produces undark-master/undark
cp undark-master/undark ./undark
./undark -V                    # => undark version 0.7.1, by Paul L Daniels
```

(`undark.patch` is a unified diff against the pristine `undark.c`; it applies with
`patch -p0` from `tools/undark/`. The build emits 3 pre-existing
`-Wshift-negative-value` warnings from `varint`-decoding macros — benign, present
upstream, not introduced by the patch.)

## Run / harness gate

```sh
./undark -i <db>     # CSV: rowid,id,col1,col2,...  (reconstructable records)
UNDARK_BIN=tools/undark/undark   # the harness gate
```

Deleted rows = recovered rowids absent from the live b-tree. On the Nemetz
fixtures undark dumps clean CSV records (e.g. on `tests/data/deleted_places.db` it
emits `40,NULL,"https://site-40...","Title...",...`); on the `0C` integer-id tables
its column alignment is weaker, which is what produces its low `0C` recall in the
head-to-head.
