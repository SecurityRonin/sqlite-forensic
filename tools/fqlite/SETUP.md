# fqlite headless tap — setup & reproduction

A non-GUI oracle around fqlite's carving engine. fqlite's CLI was removed at v2.0,
but the engine (`fqlite.base.Job`) is plain Java that populates a result list the GUI
merely reads. `HeadlessTap` constructs `Job`, runs `Job.run(path)`, and emits the
recovered **DELETED** rows as CSV — never launching a JavaFX window.

```
FQLITE_JAVA=<jdk25>/bin/java tools/fqlite/run-tap.sh <database.db>
# -> stdout CSV:  rowid,offset,id,col1,col2,...  (rowid -1 when the engine can't recover it)
```

Status: **built and validated** on the Nemetz fixtures (0C / 0D / 0E) — recovers the
deleted rows, matching the deleted-id set computed independently with `sqlite3`.

## Layout (all under `tools/fqlite/`)

| Path | Committable? | What |
|---|---|---|
| `tap/HeadlessTap.java` | yes (source) | the tap driver |
| `run-tap.sh` | yes (wrapper) | run wrapper; honours `FQLITE_JAVA` (default `java`) |
| `stubs/fqlite/{rag,erm}/*.java` | yes (source) | 6 compile-only stubs replacing the langchain4j/llama.cpp packages |
| `fqlite.patch` | yes | empty — no edits to the fqlite source are required (see below) |
| `SETUP.md` | yes | this file |
| `checkout/` | gitignored | fqlite source at the pinned commit (bulky) |
| `sdk/` | gitignored | OpenJFX 22.0.2 SDK (≈45 MB zip) |
| `lib/` | gitignored | Maven jars (≈19 MB) |
| `build/` | gitignored | compiled `.class` files + staged engine resources |

Note: this repo's top-level `.gitignore` ignores the whole `/tools/` tree, so by
default none of the above is tracked. The deliverable sources are deliberately small
and separate from the bulky downloads; if you want to track them, add un-ignore rules
for `tools/fqlite/{tap,stubs,run-tap.sh,fqlite.patch,SETUP.md}` (left to the repo owner;
this tap does not modify `.gitignore`).

## 1. Toolchain

- **OpenJDK 25** (Homebrew) for both `javac` and `java`. Validated build:
  `openjdk version "25.0.2" 2026-01-20`. The run wrapper honours `FQLITE_JAVA`
  (e.g. `/opt/homebrew/opt/openjdk@25/bin/java`).
- Compiled with `--release 21` (the engine targets Java 21 bytecode).

## 2. Clone fqlite at the pinned commit

```sh
git clone https://github.com/pawlaszczyk/fqlite tools/fqlite/checkout
( cd tools/fqlite/checkout && git checkout 26922bd9e3cdc60c93b72dfb1fb2f5972a0af6a6 )
# fqlite v4.22
```

(In this worktree the checkout already exists at that commit; `git -C tools/fqlite/checkout rev-parse HEAD`
== `26922bd9e3cdc60c93b72dfb1fb2f5972a0af6a6`.)

## 3. Download the OpenJFX SDK + Maven jars

```sh
cd tools/fqlite
mkdir -p sdk lib

# OpenJFX 22.0.2 SDK (macOS aarch64)
curl -sL -o sdk/openjfx.zip \
  https://download2.gluonhq.com/openjfx/22.0.2/openjfx-22.0.2_osx-aarch64_bin-sdk.zip
( cd sdk && unzip -q openjfx.zip )          # -> sdk/javafx-sdk-22.0.2/lib/*.jar

# Maven Central jars
cd lib
curl -sL -O https://repo1.maven.org/maven2/commons-codec/commons-codec/1.17.1/commons-codec-1.17.1.jar
curl -sL -O https://repo1.maven.org/maven2/org/jspecify/jspecify/1.0.0/jspecify-1.0.0.jar
curl -sL -O https://repo1.maven.org/maven2/org/antlr/antlr4-runtime/4.8/antlr4-runtime-4.8.jar
curl -sL -O https://repo1.maven.org/maven2/io/github/willena/sqlite-jdbc/3.51.1.0/sqlite-jdbc-3.51.1.0.jar
```

SHA-256 (validated build):

```
d1b1903814fc72fb97857562157f8769bc55fdcdc68d630624b6d3c22a236a23  sdk/openjfx.zip
f9f6cb103f2ddc3c99a9d80ada2ae7bf0685111fd6bffccb72033d1da4e6ff23  lib/commons-codec-1.17.1.jar
1fad6e6be7557781e4d33729d49ae1cdc8fdda6fe477bb0cc68ce351eafdfbab  lib/jspecify-1.0.0.jar
2337df5d81e715b39aeea07aac46ad47e4f1f9e9cd7c899f124f425913efdcf8  lib/antlr4-runtime-4.8.jar
ebab192d3bff1e8ed6ef04d84ef6ae52ce5da89f206116f39bcb9f7a2364bc51  lib/sqlite-jdbc-3.51.1.0.jar
```

## 4. Stub the `rag` / `erm` (LLM) packages — no source edits to the engine

`fqlite.rag.*` (langchain4j + `de.kherud.llama`) and `fqlite.erm.*` (langchain4j) are
heavy and irrelevant to carving. They are referenced **only** by `base/GUI.java`, which
the headless path never instantiates. So we **exclude the real `src/fqlite/rag/` and
`src/fqlite/erm/` from the source set** and compile six tiny compile-only stubs instead
(in `tools/fqlite/stubs/`), matching exactly the symbols `GUI.java` uses:

- `fqlite.rag.LLMWindow` (ctor `(GUI, TreeItem<NodeObject>)`, `getPrimaryStage()`,
  `start(Stage)`, `prepareRAG(String)`, `show()`)
- `fqlite.rag.LoadingPopup` (`show(Stage,String)`, `close()`)
- `fqlite.rag.LLMConfigDialog` (`start(Stage)`)
- `fqlite.erm.SchemaRetriever` (ctor `(Connection)`, `extractFullSchema(Connection)`)
- `fqlite.erm.SchemaToMermaidConverter` (`convertToMermaid(String)`)
- `fqlite.erm.MermaidHTMLGenerator` (`setMermaidLibraryPath`, `setPanzoomLibraryPath`,
  `generateHTMLFile`)

Each stub's body throws `UnsupportedOperationException` — they exist only to satisfy
`GUI.java` at compile time and are never invoked on the carving path.

## 5. The null-guard "patch" — empty by design

`fqlite.patch` contains **no hunks**. At commit `26922bd…`, all `gui.add_table(...)`,
`gui.update_table(...)`, and `gui.doLog(...)` calls in `Job.java` are **already** inside
`if (gui != null)` guards upstream, and `Job.info(...)` already routes to
`System.out.println` when `gui == null`. Because `HeadlessTap` leaves `job.gui == null`,
no GUI call executes — so no patch is needed. The checkout stays pristine
(`git -C tools/fqlite/checkout diff --stat HEAD` is empty). The real headless
instrumentation is the stubs (§4) + the driver (§7), both outside the checkout.

## 6. Compile

From `tools/fqlite/`:

```sh
SDK=sdk/javafx-sdk-22.0.2/lib
CP="lib/commons-codec-1.17.1.jar:lib/jspecify-1.0.0.jar:lib/antlr4-runtime-4.8.jar:lib/sqlite-jdbc-3.51.1.0.jar"
JAVAC=/opt/homebrew/opt/openjdk@25/bin/javac

rm -rf build && mkdir -p build

# (a) engine + GUI + stubs, EXCLUDING the real rag/erm packages
find checkout/src stubs -name '*.java' \
  | grep -v 'checkout/src/fqlite/rag/' \
  | grep -v 'checkout/src/fqlite/erm/' > /tmp/fqlite-srcs.txt

"$JAVAC" --release 21 \
  --add-modules javafx.base,javafx.graphics,javafx.controls,javafx.swing,javafx.web,javafx.fxml,javafx.media \
  -p "$SDK" -cp "$CP" -d build @/tmp/fqlite-srcs.txt

# (b) stage engine resources so AppLog's static init can load /icon24_copy.png etc.
cp -R checkout/resources/. build/

# (c) the tap driver
"$JAVAC" --release 21 \
  --add-modules javafx.base,javafx.graphics,javafx.controls,javafx.swing,javafx.web \
  -p "$SDK" -cp "build:$CP" -d build tap/HeadlessTap.java
```

`javafx.swing` and `javafx.web` are on the module path because `util/Auxiliary.java`
imports `javafx.embed.swing.SwingFXUtils` and `ui/SchemaBrowser.java` imports
`javafx.scene.web.{WebEngine,WebView}`. Staging `checkout/resources/` into `build/` is
required: `fqlite.log.AppLog`'s static initializer loads `/icon24_copy.png` and
`/icon32_exit.png` via `getResource(...)` with `Objects.requireNonNull`, and also opens
`<GUI.baseDir>/fqlite.log` — both must succeed before the first `Job()` constructs.

## 7. Run

```sh
FQLITE_JAVA=/opt/homebrew/opt/openjdk@25/bin/java \
  tools/fqlite/run-tap.sh tests/data/nemetz/0C/0C-01.db
```

`run-tap.sh` launches the JVM with `-Djava.awt.headless=true -Dprism.order=sw`
(software rasteriser, no GPU/display) and `--add-modules
javafx.base,javafx.graphics,javafx.controls,javafx.swing,javafx.web`. `HeadlessTap`:

1. sets `fqlite.base.GUI.baseDir` to a fresh temp dir;
2. boots the JavaFX **toolkit** with `Platform.startup(...)` (no `Stage`, no window —
   the default macOS Glass backend initialises offscreen; the Monocle headless
   platform is **not** bundled in the stock OpenJFX SDK, so its
   `-Dglass.platform=Monocle` flags are intentionally NOT used);
3. constructs `Job`, `setPath`, and `run(path)` synchronously (`job.gui` stays null);
4. drains `job.resultlist` and emits only the DELETED rows as CSV.

### Row projection (verified against the engine source at the pinned commit)

Each row in `resultlist` (`ConcurrentHashMap<String, ObservableList<ObservableList<String>>>`,
keyed by table name) is an `ObservableList<String>`:

| index | meaning |
|---|---|
| 0 | table name (also the map key) |
| 1 | `"[pll\|headerlen]"` payload-length info |
| 2 | **rowid** (`"-1"` when unrecoverable) |
| 3 | **status** — `Global.DELETED_RECORD_IN_PAGE` (`"D"`) = deleted, `Global.REGULAR_RECORD` (`" "`) = live, `"F"` = freelist |
| 4 | physical byte offset |
| 5+ | the actual table column values |

### Output contract (matches the comparison harness)

`forensic/tests/nemetz_tool_comparison.rs` consumes the tap with **two** leading
metadata fields before the data, so the decoded tuple starts at CSV **field index 2**:

| record | emitted line | harness reads |
|---|---|---|
| deleted **data** row | `rowid,offset,id,col1,col2,...` | identity `(col1,col2)` at fields **3,4** (`fqlite_recover`) |
| freed **sqlite_master** carve | `rowid,offset,id,rootpage,type,name,tbl_name,rootpage,sql` | `(type,name,tbl_name)` at fields **4,5,6** (`fqlite_schema_rereads`); the data parser skips any line whose field 4 is `table`/`index`/`trigger`/`view` |

Mapping from the `resultlist` row to the emitted line:

- **Data row** (status `"D"` at index 3, layout `[table,pll,rowid,"D",offset,id,col1,...]`):
  emit `row[2]`(rowid), `row[4]`(offset), then `row[5..]`(id,col1,col2,…). So
  `(col1,col2)` land at output fields 3,4 — e.g. 0C-01 rowid 20017 →
  `-1,7713,20017,4292717334,1848777144,…`, fields 3,4 = `4292717334,1848777144` =
  the answer-key identity cells `[1],[2]`.
- **Schema carve** (the engine's unmatched bucket, map key `"D"`, layout
  `["D",pll,rowid,offset,type,name,tbl_name,rootpage,sql]` with a sqlite_master type
  token at index 4): emit `rowid,offset,id,rootpage` then `row[4..]`(type,name,tbl_name,
  rootpage,sql), so `(type,name,tbl_name)` land at fields 4,5,6. The two filler fields
  (id,rootpage) reproduce fqlite's native schema-record shape; the harness reads only
  fields 4/5/6 here, and counts the carve as a live-sqlite_master re-read.

This shape is load-bearing: the harness's `(col1,col2)` projection is off-by-one if the
data tuple starts at field 1 instead of field 2.

Engine `info()` chatter (it prints to stdout when `gui == null`) is silenced during the
run by temporarily swapping `System.out`, so only the CSV reaches the caller's stdout.

## 8. Validation (Doer-Checker)

### Tap output (0C-01.db, `users` table, integer columns)

```
1,3824,1,2,table,users,users,2,"CREATE TABLE users (…)"
-1,7713,20017,4292717334,1848777144,1237429869,-659062187
-1,7769,20015,360853708,1440875318,1510736587,-1094609833
-1,7881,20011,624324220,3585552096,525994445,448647659
-1,7935,20009,2231280006,3658390848,881591422,1145553
-1,8052,20005,3780322152,3909007646,120462986,1290558629
-1,8142,20002,251894444,4034649640,-488066367,-44564254
-1,8170,20001,602075650,564125138,1823987023,73199275
```

The first line is the freed `sqlite_master` carve (`type,name,tbl_name` = `table,users,
users` at fields 4/5/6 — skipped by the data parser, counted as a live-schema re-read).
The seven data lines carry the deleted user rows: `rowid,offset,id,col1,…`. Cross-checked
with `sqlite3`, the live `users` ids are 20003,20004,20006,20007,20008,20010,20012,20013,
20014,20016,20018,20019,20020 — so 20001,20002,20005,20009,20011,20015,20017 are exactly
the **deleted** ids recovered.

### Full comparison harness (the real validation)

```sh
ROOT=$PWD
cp docs/img/comparison_metrics.csv /tmp/csv.bak          # the run rewrites this
UNDARK_BIN=$ROOT/tools/undark/undark \
FQLITE_TAP=$ROOT/tools/fqlite/run-tap.sh \
FQLITE_JAVA=$(which java) \
  cargo test -p sqlite-forensic --test nemetz_tool_comparison -- --nocapture
cp /tmp/csv.bak docs/img/comparison_metrics.csv          # restore — docs stay pristine
```

All **8 tests pass** (incl. `live_sqlite_master_rereads_per_tool`, which pins fqlite's
live `sqlite_master` re-reads at exactly **25** across the in-scope 0C/0D/0E corpus, and
`emit_tool_comparison`). Measured fqlite rows from that run:

```
cat tool     Ddel Drec  TP  FP  FN live  rec_sub rec_e2e prec
0C  fqlite     84   84  67  17  17    0   0.798   0.798 0.798
0D  fqlite     45   19  20   0   0    0   1.000   0.444 1.000
0E  fqlite     12    4   2   8   2    0   0.500   0.167 0.200
```

The `0C fqlite` row (TP 67, recall 0.798) matches the chart's headline. fqlite's exact
`FP`/`precision` are not hard-pinned (the harness pins only `ours.tp >= 68` and
`ours.tp > fqlite.tp`, robust to small tap variation); the value above is the genuine
measured output, not adjusted to a target. The tap never opens a window.
