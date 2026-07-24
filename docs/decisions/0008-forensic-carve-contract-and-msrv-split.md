# 8. Adopt the fleet `forensic-carve` Carver contract; MSRV split (libs 1.80 / CLI 1.96)

Date: 2026-07-24
Status: Accepted

## Context

Beyond its own file-level carving, the SQLite carver must plug into fleet-wide
unallocated-space and memory sweeps: a disk or memory scan hits the
`SQLite format 3\0` magic and needs a medium-agnostic carver to validate the
window and hand back a bounded byte range that re-enters the normal
classify→parse pipeline. The fleet defines this seam as the `forensic-carve`
`Carver` trait (referenced as "ADR 0001" in `forensic/Cargo.toml`). Separately,
the fleet MSRV policy (`~/src/ronin-issen/CLAUDE.md`, "Rust MSRV & Toolchain")
sets a low CI-verified floor for published *libraries* and the pinned dev
toolchain for *apps*.

## Decision

- **Implement the fleet `Carver` contract** with a whole-database `SqliteCarver`
  (`forensic/src/carve.rs`, commits `7ac5dac` RED → `f0491ea` GREEN). It
  advertises a single header-magic `Signature`, validates the 100-byte header,
  bounds the database to `page_size × page_count` (capped at `MAX_WINDOW = 1 GiB`
  against a lying header), echoes `CarveContext::recovery_method` so the *same*
  carver stamps `UnallocatedCarve` on a disk sweep and `MemoryCarve` on a memory
  sweep, and never touches a `Read`/`Seek`/VFS/memory-provider handle.
- **Register at link time** via `inventory::submit!` so any binary that
  force-links `sqlite-forensic` collects the carver (`forensic/Cargo.toml`:
  `inventory = "0.3"`).
- **Depend on the *published* `forensic-carve = "0.1"`**, not a path dep, once it
  shipped to crates.io (commit `74f44e8` migrated off the path dep — matching the
  fleet "prefer the published registry crate over a path dependency" rule).
- **MSRV split.** Both libraries declare `rust-version = "1.80"` — a deliberate,
  CI-verified low floor (`core/Cargo.toml`, `forensic/Cargo.toml`); adopting
  `forensic-carve` raises it to 1.80 (noted in `forensic/Cargo.toml`). The CLI
  declares `rust-version = "1.96"` = the pinned dev toolchain
  (`cli/Cargo.toml`; `rust-toolchain.toml` channel `1.96.0`), since nothing pins
  a library dependency against a binary.

## Consequences

- The SQLite carver is reusable by the fleet's disk-unallocated and memory sweeps
  through one medium-agnostic seam, with no dependency inversion (it imports no
  container/paging layer).
- The low library MSRV stays a trust signal and a real CI guarantee for
  third-party reuse of `sqlite-core`, decoupled from the drifting dev-toolchain
  pin the CLI tracks.
