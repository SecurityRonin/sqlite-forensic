# sqlite4n6

Read-only SQLite forensic CLI — carve deleted records and grade anomalies, as a
single static binary.

`sqlite4n6` is the command-line front end over [`sqlite-core`](../core) and
[`sqlite-forensic`](../forensic). It opens the evidence file read-only and never
writes the file or its sidecars.

## Use

```console
$ sqlite4n6 carve evidence.db                 # rebuild recovered rows → evidence.recovered.db
$ sqlite4n6 carve evidence.db --out out.db    # choose the rebuilt-db path
$ sqlite4n6 carve evidence.db --format jsonl  # stream rows to stdout (or: table, csv)
$ sqlite4n6 carve evidence.db --rowid-only    # just the recovered rowids
$ sqlite4n6 audit evidence.db                 # severity-ranked anomaly findings
```

`carve` recovers deleted records from free (unallocated) space — freelist pages,
in-page free blocks, dropped-table pages, and an uncheckpointed `-wal` overlay —
plus lower-confidence partial fragments in a structurally separate tier. By
default it **rebuilds a queryable SQLite database** (`<name>.recovered.db`): a
`recovered_records` table and a separate `recovered_fragments` table, with carved
cells in their native types so a recovered `BLOB` is stored losslessly.
`--no-fragments` writes the full-row table only; `--format table|csv|jsonl`
streams to stdout instead (JSONL encodes BLOBs as base64). `audit` grades
forensically-notable anomalies into severity-ranked findings.

The rebuilt database is a **new** file; the evidence database and its sidecars
are still never written.

[Privacy Policy](https://securityronin.github.io/sqlite-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/sqlite-forensic/terms/) · © 2026 Security Ronin Ltd
