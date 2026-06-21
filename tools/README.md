# Independent oracle tools — reproduce the deleted-record head-to-head

`docs/recovery-comparison.md` scores `sqlite4n6` against four independent
deleted-record recovery tools on the same Nemetz answer key. This directory holds
everything needed to **reproduce that comparison from a fresh clone**.

## What is committed vs downloaded

We do **not** redistribute the third-party tool sources. We commit only the small
artifacts we authored — the patches (diffs against pristine upstream), the headless
shims/tap, and a per-tool `SETUP.md` recipe. You download each upstream yourself,
at the pinned version, under its own license, and apply our patch.

| Tool | Gate | Upstream | License | Our committed artifacts |
|---|---|---|---|---|
| **undark** 0.7.1 | `UNDARK_BIN` | [inflex/undark](https://github.com/inflex/undark) | BSD-Revised | `undark/undark.patch`, `undark/SETUP.md` |
| **fqlite** 4.22 | `FQLITE_TAP` + `FQLITE_JAVA` | [pawlaszczyk/fqlite](https://github.com/pawlaszczyk/fqlite) | see upstream | `fqlite/{SETUP.md, run-tap.sh, fqlite.patch, tap/, stubs/}` |
| **bring2lite** | `BRING2LITE_CMD` | [bring2lite/bring2lite](https://github.com/bring2lite/bring2lite) | see upstream | `bring2lite/{SETUP.md, bring2lite.patch, shim/}` |
| **SQL-DRP** `sqlparse` v1.3 | `SQLDRP_CMD` | [mdegrazia/SQLite-Deleted-Records-Parser](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser) | GPLv3 | `sqldrp/{SETUP.md, sqlparse_v1.3.py.patch}` |
| **sqlite_dissect** (DC3) | `SQLITE_DISSECT_CMD` | [dod-cyber-crime-center/sqlite-dissect](https://github.com/dod-cyber-crime-center/sqlite-dissect) | see upstream | `scripts/run-sqlite-dissect.sh` (install via `pip install sqlite-dissect`) |

The bulky upstream checkouts/builds (`*/checkout/`, `fqlite/{sdk,lib,build}`,
`*/pkg/`, downloaded scripts, built binaries) are gitignored — see `.gitignore`.

## Reproduce

Each tool has a self-contained recipe: download upstream at the pinned
version/commit, `git apply` (or `patch`) our diff, build. Follow them in any order:

- [`undark/SETUP.md`](undark/SETUP.md)
- [`fqlite/SETUP.md`](fqlite/SETUP.md)
- [`bring2lite/SETUP.md`](bring2lite/SETUP.md)
- [`sqldrp/SETUP.md`](sqldrp/SETUP.md)

The two Python tools are driven through the committed wrappers
`scripts/run-bring2lite.sh` and `scripts/run-sqldrp.sh` (the stable interface the
harness shells out to). fqlite is driven through `fqlite/run-tap.sh`, which runs
the committed `tap/HeadlessTap.java` against fqlite's carving engine with no GUI.

## Run the comparison

The harness is env-gated: it skips any tool whose gate is unset, so you can
reproduce one column at a time. Gates must be **absolute paths** (the harness runs
with the crate dir as its working directory). From the repo root:

```sh
W=$(pwd)
UNDARK_BIN="$W/tools/undark/undark" \
FQLITE_TAP="$W/tools/fqlite/run-tap.sh" FQLITE_JAVA="$(command -v java)" \
BRING2LITE_CMD="$W/scripts/run-bring2lite.sh" \
SQLDRP_CMD="$W/scripts/run-sqldrp.sh" \
cargo test -p sqlite-forensic --test nemetz_tool_comparison -- --nocapture
```

With every gate set, the harness rewrites `docs/img/comparison_metrics.csv` from
the live run. Full provenance (versions, commit pins, sha256s) lives in each
`SETUP.md` and in `docs/corpus-catalog.md` §F.
