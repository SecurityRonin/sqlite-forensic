# sqlite-forensic

Forensic anomaly auditor and deleted-record carver for SQLite databases.

`sqlite-forensic` builds on [`sqlite-core`](../core) to do two things over a
read-only database:

- **Carve deleted records** out of free (unallocated) space — freelist pages,
  in-page free blocks, dropped-table pages, and an uncheckpointed `-wal`
  overlay — including lower-confidence partial fragments salvaged where a full
  row could not be reconstructed.
- **Audit anomalies**, grading forensically-notable header- and structure-level
  findings into severity-ranked `forensicnomicon::report` observations.

It opens the evidence file read-only and never writes the file or its sidecars.

## Use

```rust
use sqlite_core::Database;
use sqlite_forensic::{audit, carve_all_deleted_records};

let db = Database::open(std::fs::read("evidence.db")?)?;
let anomalies = audit(&db);
let recovered = carve_all_deleted_records(&db);
```

[Privacy Policy](https://securityronin.github.io/sqlite-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/sqlite-forensic/terms/) · © 2026 Security Ronin Ltd
