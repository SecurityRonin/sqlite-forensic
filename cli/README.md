# sqlite4n6

Read-only SQLite forensic CLI — carve deleted records and grade anomalies, as a
single static binary.

`sqlite4n6` is the command-line front end over [`sqlite-core`](../core) and
[`sqlite-forensic`](../forensic). It opens the evidence file read-only and never
writes the file or its sidecars.

## Use

```console
$ sqlite4n6 carve evidence.db                 # combined live + recovered workbook → evidence.recovered.xlsx
$ sqlite4n6 carve evidence.db --db            # also write a queryable evidence.carved.db
$ sqlite4n6 carve evidence.db --out out       # set the output stem (→ out.recovered.xlsx)
$ sqlite4n6 carve evidence.db --format jsonl  # stream rows to stdout (or: table, csv)
$ sqlite4n6 carve evidence.db --rowid-only    # just the recovered rowids
$ sqlite4n6 audit evidence.db                 # severity-ranked anomaly findings
```

`carve` recovers deleted records from free (unallocated) space — freelist pages,
in-page free blocks, dropped-table pages, and an uncheckpointed `-wal` overlay —
plus lower-confidence partial fragments in a structurally separate tier. By
default it writes a **combined workbook** `<name>.recovered.xlsx` — the source
database dumped **one sheet per live table** (its real column names) with the
recovered (deleted) rows **folded back into their table by rowid**, tinted pale
red and carrying three trailing flag columns: `is_deleted`, `is_guessed` (1 when
attributed by shape — consistent with that table, not hard-linked) and
`table_match_ambiguous`. Destroyed-rowid rows sink to the bottom of their sheet;
unattributed rows and partial fragments keep their own `recovered_unattributed` /
`recovered_fragments` tabs. Image BLOBs — live and recovered — show as in-cell
thumbnails and video BLOBs as a typed `video/<ext> · <size>` placeholder
(first-frame extraction deferred); a sheet past Excel's 1,048,576-row limit is
truncated with a warning.

`--db` additionally writes a **queryable SQLite database** (`<name>.carved.db`,
stem honored from `--out`) holding the raw carved records with each row
**attributed to its source table in three honest tiers**: `recovered_<table>`
(CERTAIN — carved from a live table's page, with that table's real column names,
or generic `c0..cN` when the names can't be parsed confidently),
`recovered_inferred` (INFERRED — shape-matched to a surviving table, carrying a
`_table_guess` and a `_table_match_ambiguous` 0/1 flag; a "consistent with"
forensic inference, never asserted), and `recovered_unattributed` (UNKNOWN —
dropped-table residue or a shape matching no surviving table), plus a separate
`recovered_fragments` table. Carved cells keep their native types so a recovered
`BLOB` is stored losslessly. `--no-fragments` drops the fragment table. `--db` is
file-output mode only and conflicts with `--format` / `--rowid-only`;
`--format table|csv|jsonl` streams to stdout instead (JSONL encodes BLOBs as
base64). `audit` grades forensically-notable anomalies into severity-ranked
findings.

Both outputs are **new** files; the evidence database and its sidecars are still
never written.

[Privacy Policy](https://securityronin.github.io/sqlite-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/sqlite-forensic/terms/) · © 2026 Security Ronin Ltd
