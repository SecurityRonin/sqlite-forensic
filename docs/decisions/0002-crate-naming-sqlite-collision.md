# 2. Crate naming under the `sqlite` name collision

Date: 2026-07-24
Status: Accepted

## Context

The fleet crate naming grammar (`~/src/ronin-issen/CLAUDE.md`, "Crate naming
grammar") says the reader is `<x>-core` and, when the bare `<x>` name on crates.io
is a *popular* third-party crate, the import path stays `<x>_core` rather than
hijacking the bare name. The bare `sqlite` crate name is taken on crates.io by an
established third-party binding, so claiming `use sqlite::…` would collide with a
name analysts already associate with something else.

## Decision

Publish the reader as package **`sqlite-core`** with `[lib] name = "sqlite_core"`,
so consumers write `use sqlite_core::Database` (`core/Cargo.toml` lines 1–14;
README examples `use sqlite_core::Database`). The analyzer is **`sqlite-forensic`**
and the workspace repo is named `sqlite-forensic` (Pattern A: one reader + one
analyzer). The binary follows the `<x>4n6` convention as **`sqlite4n6`**
(`cli/Cargo.toml` → `name = "sqlite4n6"`, `[[bin]] name = "sqlite4n6"`).

## Consequences

- No import-path hijack of the popular `sqlite` name; the `sqlite_core` path is
  unambiguous and self-describing on crates.io.
- The three published names (`sqlite-core`, `sqlite-forensic`, `sqlite4n6`) map
  cleanly onto the reader / analyzer / CLI roles the grammar prescribes.
- The Python extension module reuses the `sqlite4n6` name for the import
  (`python/Cargo.toml` → `[lib] name = "sqlite4n6"`, `crate-type = ["cdylib"]`),
  matching the CLI's brand.
