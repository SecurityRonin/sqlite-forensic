# Reference papers (`docs/references/`)

Local copies of the papers/specs cited by the design docs live in this directory
for offline reading. **The PDFs are gitignored** — they are copyrighted academic
works and must not be committed or redistributed. This README records the
citations (the provenance), which IS committed; drop the PDFs here locally.

Pattern matches the rest of the repo: ignore the artifact, commit the provenance.

## Cited works

- **SQLite Database File Format** — the authoritative rollback-journal + db format
  spec. <https://sqlite.org/fileformat.html> and
  <https://sqlite.org/tempfiles.html>. Journal header offsets cross-checked against
  SQLite `pager.c` (`writeJournalHdr`/`readJournalHdr`).
- **D. Pawlaszczyk & C. Hummert**, *Making the Invisible Visible — Techniques for
  Recovering Deleted SQLite Data Records*, International Journal of Cyber Forensics
  and Advanced Threat Investigations (IJCFATI), 2021.
  <https://conceptechint.net/index.php/CFATI/article/view/17> (open access).
- *A comprehensive analysis and evaluation of SQLite deleted record recovery
  techniques: A survey*, Forensic Science International: Digital Investigation
  (FSI:DI), 2025.
  <https://www.sciencedirect.com/science/article/abs/pii/S2666281725001714>
  (paywalled — do not commit the PDF).
- **NIST CFTT** — *SQLite Data Recovery: Specification, Test Assertions and Test
  Cases* + *SQLite Recovery Readme*.
  <https://www.nist.gov/itl/ssd/software-quality-group/computer-forensics-tool-testing-program-cftt/cftt-technical/sqlite>
  (NIST works are U.S. Government public domain).

Consumed by: [`design/journal-recovery.md`](../design/journal-recovery.md),
[`validation.md`](../validation.md).
