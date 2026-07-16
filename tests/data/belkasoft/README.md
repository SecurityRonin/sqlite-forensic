# Belkasoft "SQLite Exercises" corpus — provenance

Real-world mobile/desktop **messenger and app** SQLite databases used as a
**robustness sweep** (no-panic over real vendor data) and as a **recovery
demonstration** for the messenger-deletion scenario the paper's WeChat case study
discusses. It is **not** a known-answer recall/precision oracle — there is no
committed per-row deletion key (Belkasoft's answers live in the paid course, not
the archive), so it validates *robustness and plausibility*, not *recall*.

## ⚠️ Not committed — redistribution prohibited

The archive and everything extracted from it are **gitignored and never
committed**. Belkasoft's [Terms of Use](https://belkasoft.com/terms) expressly
prohibit redistribution ("Copying or reproduction … to any other server or
location for further reproduction or redistribution is expressly prohibited").
This file is the provenance record only; download the archive yourself to
reproduce.

## Source

- **Provider:** Belkasoft (© 2002–2026 Belkasoft®).
- **Origin:** the "Advanced SQLite Queries with Belkasoft" on-demand training,
  <https://belkasoft.com/advanced-sqlite-queries-with-belkasoft-training>.
- **Downloaded:** 2026-07-16, as `SQLite Exercises.zip`.
- **Archive hashes** (verify before use — beware fake-200 downloads):
  - SHA-256 `cf0c5485b39b609d3655529a20250b47e33b3b8d35377411e62171ed3e9d106b`
  - MD5 `f70e270be1dbcb04cf1062e7e469653d`
  - size 34,224,418 bytes (zip, stored/uncompressed).
- **License / redistribution:** Belkasoft-copyrighted training material;
  redistribution prohibited (see above). Personal/authorized use only.

## Identity

An extraction tree of genuine application data directories from real devices —
`SQLite Exercises/<App>/…` — one subtree per app, mirroring the on-device paths:

| App subtree | SQLite DBs | live `-wal` | non-empty `-journal` | notable DBs |
|---|---:|---:|---:|---|
| `Android_WhatsApp/com.whatsapp/databases/` | 17 | 15 | 1 | `msgstore.db` (messages), `wa.db`, `axolotl.db` |
| `iOS_WhatsApp/…/` | 12 | 10 | 0 | `ChatStorage.sqlite`, `ContactsV2.sqlite`, `CallHistory.sqlite` |
| `Android_Viber/com.viber.voip/databases/` | 14 | 2 | 10 | `viber_messages`, `viber_data`, `viber_prefs` |
| `Skype/belkasofttest/` | 2 | 0 | 0 | `main.db`, `dc.db` |
| `Facebook/com.facebook.orca/databases/` | 3 | 0 | 2 | `threads_db2`, `contacts_db2` |
| `Safari/` | 3 | 0 | 0 | `History.db`, `BrowserState.db`, `Bookmarks.db` |
| `CarPlay/locationd/` | 1 | 1 | 0 | `cache_encryptedB.db` |
| **total** | **52** | **28** | **~16** | 28 `-shm` also present |

- **Encodings:** 44 UTF-8, 8 with an unset (default-UTF-8) encoding field. No
  UTF-16 databases; **no `WITHOUT ROWID` tables**; no encrypted *main* databases
  (SQLCipher/SEE not present — the `-wal`/`-shm` sidecars have their own magic,
  which is normal, not encryption).

## What it validates (and what it does not)

- **Robustness (primary).** The full `open → audit → carve` pipeline survives all
  **52** real vendor databases with **0 panics and 0 errors** — with live `-wal`
  sidecars auto-applied and real, quirky vendor schemas. Genuine third-party input
  the way `undark`/`fqlite` never exercise it. (The Josh Hickman iOS-17 sweep, §P,
  is the same class of check on a different corpus.)
- **WAL + rollback-journal recovery (demonstration).** 28 live WAL sidecars and
  ~16 non-empty rollback journals exercise both temporal paths: e.g. WhatsApp
  `msgstore.db` yields ~49 WAL commit-snapshot records; Skype `main.db` ~75 carved
  records; Viber `viber_messages` recovers via its `-journal`. This is the
  real-world analogue of the paper's messenger-deletion case study.
- **NOT a recall/precision oracle.** No committed ground-truth deletion key, so
  recovered rows are **not** scored against an answer set here — they are
  robustness + plausibility evidence, never a recall figure. For scored recall use
  the Nemetz corpus (§I) and NIST CFReDS (§K); this corpus complements those with
  real-device breadth.

## Reproduce

1. Download `SQLite Exercises.zip` from the training link above; verify the SHA-256.
2. Extract to a scratch dir **outside the repo** (`/tmp`, per the test-data
   provenance standard — never under `~/src`):
   `unzip "SQLite Exercises.zip" -d /tmp/belka-ex`.
3. Point the env-gated robustness test at it:
   `SQLITE_FORENSIC_BELKASOFT_CORPUS=/tmp/belka-ex cargo test -p sqlite-forensic --test belkasoft_robustness`.
   It opens every SQLite db under the root and asserts the pipeline never panics;
   it **skips cleanly** when the var is unset, so a plain `cargo test` stays green.

See [`../../../docs/corpus-catalog.md`](../../../docs/corpus-catalog.md) §R for the
fleet-wide catalog entry.
