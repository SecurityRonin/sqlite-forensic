# 3. `forbid(unsafe)`, panic-free by lint, and pyo3 isolated outside the workspace

Date: 2026-07-24
Status: Accepted

## Context

The reader parses untrusted, attacker-controllable SQLite databases — a malformed
header, a lying page count, a cyclic freelist, a cell pointer past the page end.
The fleet Paranoid-Gatekeeper standard (`~/src/ronin-issen/CLAUDE.md`) requires
these crates to never panic, never read out of bounds, and never trust a length
field, enforced by the panic-free lint recipe. Separately, the pyo3 Python
bindings link `unsafe` FFI glue that cannot live under a `forbid(unsafe)` crate.

## Decision

The workspace forbids unsafe and denies the panic lints for every member
(`Cargo.toml` `[workspace.lints]`): `unsafe_code = "forbid"`, plus
`unwrap_used = "deny"` and `expect_used = "deny"`, with `correctness`/`suspicious`
denied and the standard pedantic allow-list. Tests may unwrap via
`allow-unwrap-in-tests`/`allow-expect-in-tests` in `clippy.toml`. Integer fields
are read through local bounds-checked helpers that return `None`/`0` out of range
rather than indexing (e.g. `be_u16` in `forensic/src/carve.rs`; the reader's
bounded reads in `core/src/lib.rs`, whose `Error` enum enumerates every malformed
condition — `TooShort`, `TruncatedCell`, `MalformedFreelist`, …).

The pyo3 crate is a **standalone workspace** outside the main
`forbid(unsafe)` boundary (`python/Cargo.toml` → its own `[workspace]`,
`publish = false`; roadmap §3.2, commit `1cdb307`). The fuzz crate is likewise
excluded (`deny.toml` `[graph] exclude = ["sqlite-forensic-fuzz"]`), and four
libFuzzer targets exercise the parsers (`fuzz/fuzz_targets/{audit,carve,database_open,render}.rs`).

## Consequences

- The `unsafe forbidden` badge in the README is earned — every source crate is
  genuinely `unsafe_code = "forbid"`; only the isolated, unpublished pyo3 crate
  touches unsafe, and it never ships to crates.io.
- Panic-free-ness is defended two ways: statically by the lints, and empirically
  by fuzzing — matching the "input-fuzzed · panic-free by lint" wording the README
  uses (commit `1b146a5`). A real overflow bug this posture caught was the
  serial-body-length sum, fixed with a checked add (commits `7eb8cb1`→`88ebfd9`).
- The reader uses its own bounds-checked helpers rather than the fleet `safe-read`
  crate; adopting `safe-read` for the fixed-width integer reads would consolidate
  onto the single audited implementation the fleet standard prescribes. The
  original reason for the hand-rolled helpers is not recovered in the available
  history (the visible git log begins at an already-mature analyzer).
