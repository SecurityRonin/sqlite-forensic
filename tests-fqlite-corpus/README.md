# Independent Validation Corpus — `tests-fqlite-corpus/`

These SQLite databases are **third-party, externally authored** test artifacts
used as independent INPUT for the deleted-record carving validation
(`forensic/tests/fqlite_oracle.rs`; methodology in `../docs/validation.md`). They
are paired with the independent `undark` oracle so that, for these cases, neither
the input DB nor the recovery oracle is ours — the strongest Doer-Checker form.

This directory is **gitignored** — the `.db` files are NOT committed. This README
is their provenance record (modelled on how `~/src/issen/tests/data/README.md`
documents large untracked artifacts). For the per-repo index see
[`../docs/corpus-catalog.md`](../docs/corpus-catalog.md) §G.

To reproduce locally, download the DC3 `sqlite_dissect` test files into
`tests-fqlite-corpus/dc3-sqlite-dissect/` (flatten `corpus/` with a `corpus_`
prefix to match the filenames below), e.g. fetch each from the raw base URL.

## dc3-sqlite-dissect/  (REAL-ext)

- **Source:** Department of Defense Cyber Crime Center (DC3), the `sqlite_dissect`
  project test corpus.
- **Repo:** <https://github.com/dod-cyber-crime-center/sqlite-dissect>
- **Path in repo:** `sqlite_dissect/tests/test_files/`
- **Raw base URL:**
  <https://raw.githubusercontent.com/dod-cyber-crime-center/sqlite-dissect/master/sqlite_dissect/tests/test_files/>
- **Identity:** crafted SQLite databases exercising deletion/recovery edge cases,
  authored by neither us nor undark's author.

### Files wired into the differential test (contain carvable deleted records)

| local filename | repo path | forensic case | sha256 | md5 | bytes |
|---|---|---|---|---|---|
| `corpus_01-01.db` | `corpus/01-01.db` | in-page free-block deletion (freelist_count 0) | `8438a5533586e7e0f38628330d615aeaa057ebb9698c1103424d8128e417875e` | `4ac52776c7d21f0beb38d456452ca2f6` | 8192 |
| `corpus_01-02.db` | `corpus/01-02.db` | in-page free-block deletion (freelist_count 0) | `508fb80ce083bc6ad79d2921b1d35d998724e808a72d05476671010b1265043b` | `57f88570e289df9919bd900f24b7a026` | 8192 |
| `corpus_03-02.db` | `corpus/03-02.db` | in-page free-block deletion (freelist_count 0) | `7ea933d7082d3ec0cdc9f5ca3e39624d80c0da495a365d520424a69a1937f138` | `9c0a90eeb78cd24d5b4004c157d8618f` | 12288 |
| `corpus_07-01.db` | `corpus/07-01.db` | in-page free-block deletion, multi-byte text | `6e110c0663be9500e817ab0d6153f0f1aaa7d8831e7e17a05e2565abbbf9e4da` | `7f8f9e9b4d6aa971b9f0c5d16b6c2419` | 81920 |
| `corpus_0A-01.db` | `corpus/0A-01.db` | dropped table (no table in sqlite_master) | `c640727d2fe3e269d196e64c25cf896e9fa21c2626d4f6b88398274c4e1691d1` | `a174174a3f98fe7733e4a32e7aab86b7` | 8192 |
| `corpus_0A-02.db` | `corpus/0A-02.db` | dropped table (no table in sqlite_master) | `030fd0a82fa37707f448e90a21bc178f120b018b009999daaefdc61d04b24d24` | `c1be2eb3388bc294ec0deecb334180b9` | 8192 |

> All six exercise scenarios our whole-freed-page fixture cannot reach. Our
> freelist-only carver recovers 0 from each (the documented scope boundary in
> `../docs/validation.md`); undark recovers them. The test asserts our carver
> produces no false positives and records the gap explicitly.

### Other DC3 files downloaded (no carvable deleted records / not wired in)

Recorded for completeness; not used by the test (undark finds no recoverable
deleted rows beyond the live set, or the DB is a header/version fixture).

| local filename | repo path | sha256 | md5 | bytes |
|---|---|---|---|---|
| `chinook.sqlite` | `chinook.sqlite` | `52707918134b4f3d14953861832b71e41d4921c8ba19a1ea5bb8f9f3a479795c` | `326025146c8ed4209bfc2628b06f1fd3` | 917504 |
| `corpus_02-01.db` | `corpus/02-01.db` | `019f27f8b0259c52681e4393983b0d7525e3411cddb31aedfaff8a4be351246c` | `82c33a157ed2866967497c18c61fc404` | 8192 |
| `corpus_02-02.db` | `corpus/02-02.db` | `d432c47d3a3226c286a425535465260c24ce04aeb464d6030221d63f2c78a454` | `f7eca4e60b7cd7398967c931eea80711` | 8192 |
| `corpus_03-01.db` | `corpus/03-01.db` | `a9a8dcb506c722081bc6e5483465c5f63add199a45b00b9495284690ef65def5` | `a3c31c979f6863327b335921836bdc1d` | 8192 |
| `corpus_04-01.db` | `corpus/04-01.db` | `26505b98942113d49637d71a31e63797fac2d822e618342febdee7b4a58bcab2` | `f40830438f5954ac92dfe563c4b7407e` | 8192 |
| `corpus_04-02.db` | `corpus/04-02.db` | `2b3fe564dd9ab4b1d4b0f7b008ac42cec8cafd0dd7899b5974a69fdcc771d136` | `9911da848c47d67996ab3297a1d2a92c` | 8192 |
| `corpus_07-02.db` | `corpus/07-02.db` | `96a4d031c192bfb6fd5575a28007b61e4f346001973fd6aea6125a52e5db46ca` | `51bcdd740cda8586bf9b5658291eaa2c` | 90112 |
| `corpus_08-01.db` | `corpus/08-01.db` | `6089df2e698de7e55bb88064dea83ed7c5cd313a466434b7e243a93ada7de5ad` | `239e100214c821e46bb56cc456f97321` | 8192 |
| `corpus_09-01.db` | `corpus/09-01.db` | `651f8c0e9aa5fed80bc11f4a1db95d233d5a1b49237c280f1ece0f9b0df06914` | `214df574ec06ad77bad9062d7e5c59ce` | 118784 |
| `version_history_test.sqlite` | `version_history_test.sqlite` | `a82aa11d0377e16ee14b7f7dab91c1570c239b5b5b6a6942fbb7e27326ca261a` | `67c33214a88fefec1d35e10ad6e86825` | 16384 |
