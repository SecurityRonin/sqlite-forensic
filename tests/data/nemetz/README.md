# Nemetz SQLite Forensic Corpus — full v2.0 corpus (`tests/data/nemetz/`)

Independent, third-party deleted-record **ground truth** for the carving metrics
harness (`forensic/tests/nemetz_metrics.rs`) and the panic-free real-data
robustness proof (`forensic/tests/nemetz_robustness.rs`). Unlike our own
`deleted_places.db` fixture (where we authored both the deleter and the carver —
Doer-Checker-weak), every database here was built and deleted-from (or
deliberately manipulated) by a third party who *also* shipped the answer key, so
a recall/precision number computed against it is real ground truth — and the
anti-forensic categories are genuine adversarial inputs we did not craft.

The **full** 141-database v2.0 corpus is vendored (CC0 public domain). It is the
real-world evidence that our `forbid(unsafe)`, panic-free parser degrades
gracefully on manipulated structures rather than aborting.

This is the co-located human-facing detail; the single machine index is
[`../../../docs/corpus-catalog.md`](../../../docs/corpus-catalog.md) §I — cross-reference, do not duplicate.

## Source

- **Dataset:** SQLite Forensic Corpus, version 2.0 (141 databases).
- **Authors:** Sebastian Nemetz, Sven Schmitt, Felix Freiling — Chair for IT
  Security Infrastructures, Friedrich-Alexander-University Erlangen-Nuremberg.
- **Publication:** *A Standardized Corpus for SQLite Database Forensics*,
  DFRWS-EU 2018 (Digital Investigation 24, S121–S130).
  <https://doi.org/10.1016/j.diin.2018.01.015>
- **Landing page:** <https://faui1-files.cs.fau.de/public/sqlite-forensic-corpus/>
  (mirrored on Digital Corpora).
- **Download URL (v2.0, used here):**
  <https://downloads.digitalcorpora.org/corpora/sql/sqlite_forensic_corpus_v2.0.zip>
  (HTTP 302 → `digitalcorpora.s3.amazonaws.com`; fetch with `curl -L`).
- **Downloaded zip md5:** `02aa205efa80757602a2911156db79a6` (5.1 MB).
- **Licence:** CC0 1.0 (public domain dedication — the authors disclaim
  copyright; see each `.xml`'s `<dc:rights>`). Redistribution of this vendored
  subset is therefore unrestricted.

## What is vendored

All **141 databases across 23 categories** (the 14-category standardized corpus
`01`–`0E` plus the 9-category anti-forensic extension `11`–`19`). Each `NN/NN-MM`
fixture ships three files:

- `NN-MM.db` — the database. The anti-forensic categories (`11`–`19`) name it
  `NN-MM_antifor.db`; every other category uses `NN-MM.db`.
- `NN-MM.sql` — the build + `DELETE`/`DROP`/manipulation provenance script. The
  `PRAGMA secure_delete` state and whether later `INSERT`s overwrote freed slack
  determine which deletes are *physically* recoverable.
- `NN-MM.xml` — the **answer key**: every row tagged `deleted="1"` carries its
  full decoded column content, plus per-table `rowsTotal`/`rowsAlive`/`rowsDeleted`.

The corpus's own `.log` and `.db_recovery` artifacts are **not** vendored, except
the pre-existing category-`11` `.log`/`.db_recovery` files kept verbatim from the
original 32-DB subset. New categories carry only `.db`+`.xml`+`.sql`.

### Category table (full v2.0 corpus)

| Cat | DBs | Subject | Deleted ground truth? |
|---|---:|---|---|
| `01` | 18 | Weird table names | parse-only |
| `02` | 7 | Encapsulated column definitions | parse-only |
| `03` | 5 | SQL separators & keywords | parse-only |
| `04` | 6 | Comments | parse-only |
| `05` | 4 | Triggers, views & indices | parse-only |
| `06` | 4 | Virtual & temporary tables | parse-only |
| `07` | 4 | Fragmented contents | **deleted** (1 row, in `07-03`) |
| `08` | 1 | Reserved bytes per page | parse-only |
| `09` | 1 | Pointer-map page | parse-only |
| `0A` | 5 | Deleted tables (`DROP TABLE`) | **deleted** (dropped-table proxy) |
| `0B` | 2 | Overwritten tables (`DROP` then re-`CREATE`) | **deleted** (dropped-table recovery) |
| `0C` | 10 | Deleted records (in-page free block) | **deleted** — cleanest recall test |
| `0D` | 8 | Overwritten records (slack reclaimed) | **deleted** (recoverable vs destroyed) |
| `0E` | 2 | Deleted overflow pages (long text) | **deleted** (incl. overflow chains) |
| `11` | 5 | Manipulated root-page pointers | parse-only (robustness) |
| `12` | 6 | Manipulated left-child page pointers | parse-only (robustness) |
| `13` | 8 | Manipulated overflow page chains | parse-only (robustness) |
| `14` | 8 | Manipulated cell-pointer array values | parse-only (robustness) |
| `15` | 13 | Manipulated cell metadata & serial types | parse-only (robustness) |
| `16` | 2 | Manipulated zero-terminated contents | parse-only (robustness) |
| `17` | 13 | Manipulated freeblock structures | **deleted** (15 rows/DB, anti-forensic) |
| `18` | 5 | Manipulated freelist trunks | **deleted** (7..240 rows/DB, anti-forensic) |
| `19` | 4 | Manipulated database-file size | parse-only (robustness) |

**Deleted-ground-truth categories** (scored for recall/precision by
`nemetz_metrics.rs`, manifested by `gen_ground_truth.py`):
`07`, `0A`, `0B`, `0C`, `0D`, `0E`, `17`, `18`.

**Parse/format categories** (no deleted rows; the `.xml` describes only LIVE
content): all others. These are NOT scored as deleted-recall — inventing a deleted
set where the answer key has none would be dishonest. Every vendored `.db`,
deleted-class or parse-class, is exercised by the **panic-free robustness harness**
(`forensic/tests/nemetz_robustness.rs`), which runs the full pipeline (open,
carve, audit, row-history, rebuild-to-bytes) over all 141 and asserts no panic.

> The anti-forensic categories `17`/`18` carry deleted answer keys, but their
> freeblock/freelist-trunk structures are manipulated, so a deleted row's full
> identity rarely survives contiguously — their substrate-recall denominator is
> legitimately small/zero. They are scored honestly (the carver never re-surfaces
> a live row as deleted; recovered records are degenerate content-free phantoms,
> never a real-content false positive — see `nemetz_metrics::phantom_fp_ceiling`).

## Ground-truth manifest (machine-checkable)

`nemetz_ground_truth.json` is generated from the `.xml` answer keys by the
committed `gen_ground_truth.py` (re-run after re-vendoring):

```sh
python3 tests/data/nemetz/gen_ground_truth.py
```

For each table it records the schema column order, the deleted rows (recall
ground truth), the alive rows (used to tell a live-re-read from a phantom FP),
and per deleted row `substrate_recoverable` — whether the row's **full scored
identity** still physically survives in the `.db` (computed independently of our
carver, partitioning `D_recoverable` from `D_destroyed` for the two-denominator
recall). This is the honest **contiguous full-row-identity** test, decided **per
record by body size** (never by category): the whole record body (every column's
SQLite serial encoding, in column order) must survive as one contiguous byte run,
mirroring the recall matcher's full-row key — so a row whose scored identity a
later same-rowid overwrite destroyed (only a coincidental single column surviving)
is correctly excluded. The one documented branch is genuine overflow: a record
whose payload exceeds the in-page limit (`usable − 35`) spills to a non-contiguous
overflow-page chain (SQLite "Cell payload overflow pages"), which a flat-file
contiguity test cannot model, so it is conservatively counted as not-recoverable
(chain-aware overflow recovery is future work). This branch is detected per record
from the body size and the DB-header page geometry — most `0E` deleted bodies are
large-but-in-page and so are tested honestly. The dropped-table categories
`0A`/`0B` (no recall denominator) keep the legacy any-distinctive-column proxy.
The harness reads this manifest, never the `.xml` at test time.

The generator processes only the eight deleted-ground-truth categories (it would
be dishonest to manifest a deleted set for a parse-only fixture). It resolves each
answer key's `.db` by trying `NN-MM.db` then `NN-MM_antifor.db`, keying the
manifest by the real db stem so every `{nid}.db` consumer resolves the actual
file (the anti-forensic `17`/`18` databases are `*_antifor.db`).

## MD5 manifest (all 141 vendored databases)

Regenerate with: `find tests/data/nemetz -name '*.db' | sort | xargs md5`.

| file (under `tests/data/nemetz/`) | md5 | bytes |
|---|---|---|
| `01/01-01.db` | `4ac52776c7d21f0beb38d456452ca2f6` | 8192 |
| `01/01-02.db` | `57f88570e289df9919bd900f24b7a026` | 8192 |
| `01/01-03.db` | `029cc2d90f56f4db2d55987b9399ca83` | 8192 |
| `01/01-04.db` | `93c288097a179a8133b2881a8da5d1a0` | 8192 |
| `01/01-05.db` | `f0677be473b1ee7bcafc0583a753f3ab` | 8192 |
| `01/01-06.db` | `ae44b0219681e34361f55db780f89e64` | 8192 |
| `01/01-07.db` | `e36a3213fac2d32ebbb06b52676e2053` | 8192 |
| `01/01-08.db` | `80e762661b6b3f642f04bb8f3f24ca35` | 8192 |
| `01/01-09.db` | `6b2956b06eab2e42c669d42403f42f29` | 8192 |
| `01/01-10.db` | `3126d7332161545b0a5aab36af22d039` | 8192 |
| `01/01-11.db` | `9df843fa4793370df2b5cb8fd26aa6ff` | 8192 |
| `01/01-12.db` | `e9e765261c72bdd0e9826a43e94ad662` | 8192 |
| `01/01-13.db` | `e56a69fb4ae4084bbe11f06540e10aca` | 8192 |
| `01/01-14.db` | `8bbc5ecfae696e03d33ffbb6fb96b82f` | 8192 |
| `01/01-15.db` | `a285e8f251ab0b6eff2c215cf35c5897` | 8192 |
| `01/01-16.db` | `719519e15502070c1a3d8566c9a979e7` | 8192 |
| `01/01-17.db` | `ce6c47f8ec2be40be2f776a6563d5712` | 8192 |
| `01/01-18.db` | `9d2c8e87c60c00b38d74fdadd96acaa4` | 8192 |
| `02/02-01.db` | `82c33a157ed2866967497c18c61fc404` | 8192 |
| `02/02-02.db` | `f7eca4e60b7cd7398967c931eea80711` | 8192 |
| `02/02-03.db` | `f152b0c0561d96e4f3d2e2576bf26762` | 8192 |
| `02/02-04.db` | `f728861261cdfa11e7878391b9738d57` | 8192 |
| `02/02-05.db` | `a41d43f7cf91a447424b46fc04ca6759` | 8192 |
| `02/02-06.db` | `ef9f76dc1c23efeac076049de717b8f5` | 8192 |
| `02/02-07.db` | `bb881d5ccdb3c286402e6e845874327a` | 8192 |
| `03/03-01.db` | `a3c31c979f6863327b335921836bdc1d` | 8192 |
| `03/03-02.db` | `9c0a90eeb78cd24d5b4004c157d8618f` | 12288 |
| `03/03-03.db` | `efa34af5a22933a9f3d4e94e530ddf86` | 8192 |
| `03/03-04.db` | `7053cfa49024642548d1b45bb8196135` | 12288 |
| `03/03-05.db` | `da62ecdc00cf7541069c0b5a509ed77f` | 12288 |
| `04/04-01.db` | `f40830438f5954ac92dfe563c4b7407e` | 8192 |
| `04/04-02.db` | `9911da848c47d67996ab3297a1d2a92c` | 8192 |
| `04/04-03.db` | `ab495fca932d07c321d2b764ae31210c` | 8192 |
| `04/04-04.db` | `bd05f52aecdb9fee4dc6e9833513b3cd` | 8192 |
| `04/04-05.db` | `abc6c312df2956045a346d4233e35efe` | 8192 |
| `04/04-06.db` | `cae81a93185b621c7c60949539b281f2` | 8192 |
| `05/05-01.db` | `5e9b67d199124e5182a700d36c9d218b` | 8192 |
| `05/05-02.db` | `4c143902df9eb9e83c28f35cffeb9db0` | 8192 |
| `05/05-03.db` | `00498aba01f46cb1a0ac032a516a9637` | 286720 |
| `05/05-04.db` | `78c7ff3b87074cee91a708fcc439ea36` | 12288 |
| `06/06-01.db` | `a376479be28b578c1ca8e47178405d78` | 16384 |
| `06/06-02.db` | `95a019281bf8b8c48cc21ed4b633dfeb` | 24576 |
| `06/06-03.db` | `357815564702687a4d9e9d428adb5c75` | 28672 |
| `06/06-04.db` | `3370cd31135ba544f8f49908254a318b` | 2048 |
| `07/07-01.db` | `7f8f9e9b4d6aa971b9f0c5d16b6c2419` | 81920 |
| `07/07-02.db` | `51bcdd740cda8586bf9b5658291eaa2c` | 90112 |
| `07/07-03.db` | `ea3d6a1aea0de264dcd3f74fd97290c5` | 12288 |
| `07/07-04.db` | `fb26a9602ac6783b193c60e8dc6f02a0` | 12288 |
| `08/08-01.db` | `239e100214c821e46bb56cc456f97321` | 8192 |
| `09/09-01.db` | `214df574ec06ad77bad9062d7e5c59ce` | 118784 |
| `0A/0A-01.db` | `a174174a3f98fe7733e4a32e7aab86b7` | 8192 |
| `0A/0A-02.db` | `c1be2eb3388bc294ec0deecb334180b9` | 8192 |
| `0A/0A-03.db` | `9565362072244d68631a0ba01bdf94d0` | 12288 |
| `0A/0A-04.db` | `ef9ad3652da810fe1090b63bf2bc5127` | 12288 |
| `0A/0A-05.db` | `c2846f857ecffafe0a42ef07f5a648d9` | 12288 |
| `0B/0B-01.db` | `ab8e7922647bbd6a7a398cc56800a584` | 8192 |
| `0B/0B-02.db` | `88daa0f36fb22327d7e5fba23eb62f99` | 16384 |
| `0C/0C-01.db` | `d34bc762b6cba175bae170fa7a606480` | 8192 |
| `0C/0C-02.db` | `164fac034c32308727cfd153e6f94620` | 12288 |
| `0C/0C-03.db` | `65d73454d6a09f6c448536b62ccbae35` | 8192 |
| `0C/0C-04.db` | `24dfdd07e36c415015f33f7f5b2deefc` | 12288 |
| `0C/0C-05.db` | `401317f6b02233952a27ee6c80dc954b` | 12288 |
| `0C/0C-06.db` | `ab323dbc2b07e1167adffc5a63142f18` | 8192 |
| `0C/0C-07.db` | `121ef02e980b85ac97d2beb8c209c211` | 12288 |
| `0C/0C-08.db` | `ceebbbe67a0d9d01d0271a919be01026` | 12288 |
| `0C/0C-09.db` | `35e93ae449d67327ee39855dcd91036e` | 8192 |
| `0C/0C-10.db` | `1604a028d1dad945caf341499d5b6ba2` | 12288 |
| `0D/0D-01.db` | `18bc00dafdea993310bee8941983f042` | 8192 |
| `0D/0D-02.db` | `0d469da01f6e716bfb7719c0ad8cfc9b` | 8192 |
| `0D/0D-03.db` | `7b7ae92bbd991404d67f37716492a16d` | 8192 |
| `0D/0D-04.db` | `d9f9b890ee943a8b6eb0d0747278a36f` | 8192 |
| `0D/0D-05.db` | `b095e7b237b4cbb883fe971dab996b86` | 8192 |
| `0D/0D-06.db` | `66702224c003f92a6815078414abc904` | 8192 |
| `0D/0D-07.db` | `897dd2e67ee25d2fdff3360160a9e375` | 12288 |
| `0D/0D-08.db` | `5201d14ff657e94256736211c54678a4` | 12288 |
| `0E/0E-01.db` | `3153d8a4062d2ddf34fd64ea6e0a0841` | 77824 |
| `0E/0E-02.db` | `2abda844f3f6844022ca628f91b6edcc` | 90112 |
| `11/11-01_antifor.db` | `2413516fa09f5203e94ab2dcc52b4976` | 20480 |
| `11/11-02_antifor.db` | `1186e5d9156ad557848b6d67735396bc` | 20480 |
| `11/11-03_antifor.db` | `fd268bf1647dc9cebb6073f0f90a4ac1` | 20480 |
| `11/11-04_antifor.db` | `7d1d58827bbb60b290c0512717d2a213` | 12288 |
| `11/11-05_antifor.db` | `1ee39cc8de2efbf080557f723c5bf703` | 86016 |
| `12/12-01_antifor.db` | `236d7c18c5bbc3cc55eb5c7eb4089281` | 45056 |
| `12/12-02_antifor.db` | `8688e872be9b10b5d41a4da4877638a0` | 45056 |
| `12/12-03_antifor.db` | `194fac07205193129619128abd3f52ac` | 45056 |
| `12/12-04_antifor.db` | `28d16531219355fcdb62ec8615b081e9` | 45056 |
| `12/12-05_antifor.db` | `a04c3f5bce9ef891bc4e879be0a43770` | 45056 |
| `12/12-06_antifor.db` | `8d11afa9e4f2be654c4313147b15e761` | 45056 |
| `13/13-01_antifor.db` | `2f49ecadc78d416c22916aff4d0ebe94` | 131072 |
| `13/13-02_antifor.db` | `00571fd5bab201081cddd7541a2086d6` | 131072 |
| `13/13-03_antifor.db` | `e2bfd280081121a3f6acb17543344fad` | 131072 |
| `13/13-04_antifor.db` | `f4dd63859db12b6d7517ced129c5f675` | 131072 |
| `13/13-05_antifor.db` | `e4499e7b8b676089123ae57170e09219` | 131072 |
| `13/13-06_antifor.db` | `c3b0b5e0690d06c1d5aeadffe7f3ce35` | 131072 |
| `13/13-07_antifor.db` | `f44129fa5e4da273d6a2ebbb613cb02b` | 131072 |
| `13/13-08_antifor.db` | `ab4c1b156f8cc9b808e04babf6bd31b4` | 131072 |
| `14/14-01_antifor.db` | `9287d9da22103edb287f28477ee11d6b` | 20480 |
| `14/14-02_antifor.db` | `944e95388c3fe7873d788e9edb279945` | 20480 |
| `14/14-03_antifor.db` | `55ceaf9c75a50f2cf2e0224956adfb65` | 20480 |
| `14/14-04_antifor.db` | `395a9f2176b848e4428cf724320f744e` | 20480 |
| `14/14-05_antifor.db` | `78a9d0587ff0712254eabab654aeb603` | 20480 |
| `14/14-06_antifor.db` | `0dc119cc2548baba550131bbde3a016c` | 20480 |
| `14/14-07_antifor.db` | `f0355b955698b3de8ba21e86b12388f3` | 20480 |
| `14/14-08_antifor.db` | `5b41e718f0addb802107a87ae4e7d6f9` | 20480 |
| `15/15-01_antifor.db` | `3f9ee1a5e9fe9fd95837a4a1b1b94de5` | 12288 |
| `15/15-02_antifor.db` | `06b6c305994f34fdeba0c9d144979994` | 12288 |
| `15/15-03_antifor.db` | `2fc04f3b2e9b6639eeba7496685b4cc1` | 12288 |
| `15/15-04_antifor.db` | `a2edb7cfacdc0e77406e3431377cb48b` | 12288 |
| `15/15-05_antifor.db` | `0969b6256ea8c09de7efd840f5bc270e` | 12288 |
| `15/15-06_antifor.db` | `189d9e135590b5e2ceb15aca0abd7d6f` | 12288 |
| `15/15-07_antifor.db` | `2370972df8e9ea4553a896b2dc1161a5` | 12288 |
| `15/15-08_antifor.db` | `54fbb248f3df6ddc21cc9747faca0ce7` | 12288 |
| `15/15-09_antifor.db` | `0557035796bfd5c341cfc4118d6d29ee` | 12288 |
| `15/15-10_antifor.db` | `a94285c05ba9d1777c8651cdb208521e` | 12288 |
| `15/15-11_antifor.db` | `047ef96b8051346b02616839e17e3887` | 12288 |
| `15/15-12_antifor.db` | `ad8da2807db960c39a56413eba348542` | 12288 |
| `15/15-13_antifor.db` | `a53204a93b64d39c47b7089240ac4c71` | 12288 |
| `16/16-01_antifor.db` | `e1352c5b588c95d1cf1e1988771303b1` | 12288 |
| `16/16-02_antifor.db` | `8f43e4d42240c358638f946c4d0f2331` | 12288 |
| `17/17-01_antifor.db` | `2be4d6068f0b7fc589f0695a89067575` | 20480 |
| `17/17-02_antifor.db` | `9f7d480c9b22351db20ab36bf108bd86` | 20480 |
| `17/17-03_antifor.db` | `d39e8c1b496fc9fa553c3ebf1483ebe6` | 20480 |
| `17/17-04_antifor.db` | `89b8b578bc34b2646619f082cfba0801` | 20480 |
| `17/17-05_antifor.db` | `1bab41f5bbcbaf5156e52f164b405de1` | 20480 |
| `17/17-06_antifor.db` | `7b9142896ba0acc67df15b93254a1840` | 20480 |
| `17/17-07_antifor.db` | `1e703bb668f1d1b2a7bec6f4d4fa44ba` | 20480 |
| `17/17-08_antifor.db` | `cc4ddcab98eee69bf06584f8fba50856` | 20480 |
| `17/17-09_antifor.db` | `a067bb20d9ca4e51c1c62a9bd2af1d4e` | 20480 |
| `17/17-10_antifor.db` | `fe150070448a72ef363bb9b94b95cc73` | 20480 |
| `17/17-11_antifor.db` | `063b939a7d45f75582b8a6cfa89d3ebf` | 20480 |
| `17/17-12_antifor.db` | `f5b185189dc46630d85985c55faf5ef7` | 20480 |
| `17/17-13_antifor.db` | `702935c6f3f36f8fbe06a939876547fe` | 20480 |
| `18/18-01_antifor.db` | `66dabf5b3903bc780991788794d72173` | 94208 |
| `18/18-02_antifor.db` | `b126ef4d4cd9fe1dcb4ac081fdc30c12` | 190464 |
| `18/18-03_antifor.db` | `c68f6825787d54c2a0857fba3ccdb934` | 190464 |
| `18/18-04_antifor.db` | `0476dfa4746af2cb7c220392f1ed508b` | 190464 |
| `18/18-05_antifor.db` | `3552cf20f31e4fa0c3900bdb5141e83d` | 190464 |
| `19/19-01_antifor.db` | `7f09ab8a3496208c823394074ac92bd5` | 42750 |
| `19/19-02_antifor.db` | `5a3d3fcdc3c9930b6fe4c1158283cd04` | 39943 |
| `19/19-03_antifor.db` | `bf399145f33352ccc3b6d1f165446972` | 28672 |
| `19/19-04_antifor.db` | `2ce2395fd1562fdfb6bf60a243572659` | 16384 |

(The co-located `.sql`/`.xml`, and the pre-existing category-`11`
`.log`/`.db_recovery`, are vendored verbatim from the same zip; their integrity is
implied by the zip md5 above.)
