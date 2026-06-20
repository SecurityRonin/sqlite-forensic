# SharifCTF 8 — "crashed db" (`tests/data/sharifctf/`)

A real damaged-header SQLite database from a public CTF forensics challenge, used
as an independent **robustness** artifact: opening it must fail with a typed error,
never a panic or a false "valid database" (`forensic/tests/cfreds_recovery.rs::corrupted_header_fails_typed_not_panicking`).

## Source

- **Origin:** SharifCTF 8 (Sharif University of Technology CTF), forensics
  challenge "Crashed DB".
- **Obtained from:** the public VoidHack write-ups mirror,
  `db0.db` at
  <https://github.com/VoidHack/write-ups/tree/master/SharifCTF%208/forensics/crashed-db>.
- **md5:** `fb94343db8d4874fdb8011fb15a87d7b` — 8092 bytes.
- **Identity:** the 100-byte SQLite file header is overwritten — the file begins
  `0d 00 00 00 01 0f a5 00 …` (a b-tree leaf page-type byte where the
  `"SQLite format 3\000"` magic should be), so `Database::open` returns
  `Err(BadMagic)`.

## Redistribution / licence

The upstream write-ups repository carries **no explicit licence**. This is a
small (8 KB) public CTF challenge artifact, retained here for research/testing
under fair-use/educational norms with attribution to SharifCTF. If unrestricted
redistribution is later required, replace this with a self-authored
header-damaged fixture (a `dd`-zeroed first 16 bytes of any small db reproduces
the same `BadMagic` robustness case).
