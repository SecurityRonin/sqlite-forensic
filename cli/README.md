# sqlite4n6

Read-only SQLite forensic CLI — carve deleted records and grade anomalies, as a
single static binary.

`sqlite4n6` is the command-line front end over [`sqlite-core`](../core) and
[`sqlite-forensic`](../forensic). It opens the evidence file read-only and never
writes the file or its sidecars.

## Use

```console
$ sqlite4n6 carve evidence.db            # recover deleted records (table/csv/jsonl)
$ sqlite4n6 carve evidence.db --rowid-only
$ sqlite4n6 audit evidence.db            # severity-ranked anomaly findings
```

`carve` recovers deleted records from free (unallocated) space — freelist pages,
in-page free blocks, dropped-table pages, and an uncheckpointed `-wal` overlay —
and shows lower-confidence partial fragments in a structurally separate tier.
`audit` grades forensically-notable anomalies into severity-ranked findings.

[Privacy Policy](https://securityronin.github.io/sqlite-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/sqlite-forensic/terms/) · © 2026 Security Ronin Ltd
