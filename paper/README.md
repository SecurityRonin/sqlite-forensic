# Paper: Deleted-Record Recovery from SQLite Databases

A reference paper documenting SQLite deleted-data recovery — the storage model and
free-space conventions (rollback journal vs.\ WAL, `VACUUM`, `secure_delete`), the
recovery mechanisms, the structural false-positive-zero guarantee, and a
multi-oracle evaluation of `sqlite4n6` against `undark`, `fqlite`, `bring2lite`, and
the SQLite Deleted-Records Parser on independent third-party corpora.

## Files
- `sqlite-recovery.tex` — the paper source (XeLaTeX + xeCJK, two-column).
- `sqlite-recovery.bib` — bibliography (all entries verified against primary sources).
- `sqlite-recovery.pdf` — the built PDF (committed for convenience).
- `Makefile` — build target.

## Build
Requires a TeX distribution with XeLaTeX (the CJK terms, e.g. 微信, use `xeCJK` with
the `Songti TC` font) and BibTeX:

```sh
make            # xelatex -> bibtex -> xelatex x2
make clean      # remove build intermediates
```

## Provenance of the figures
Every accuracy/false-positive/throughput figure is reproducible from the
`sqlite-forensic` repository: the head-to-head numbers come from
`forensic/tests/nemetz_tool_comparison.rs` and `docs/recovery-comparison.md`, the
false-positive scenarios from `docs/competitive-landscape.md`, and the corpus
provenance from `docs/corpus-catalog.md` and `docs/validation.md`. Competitor tools
are run from the committed setup under `tools/`.
