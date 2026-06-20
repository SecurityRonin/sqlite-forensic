//! `sqlite-forensic` — Tier-2 anomaly auditor over [`sqlite_core`].
//!
//! WS-C skeleton. The reader (`sqlite-core`) answers "what does this database
//! header show?"; this crate grades the forensically-notable observations into
//! severity-ranked [`forensicnomicon::report::Finding`]s, so a `SQLite`
//! evidence database's anomalies aggregate uniformly with the partition /
//! container / filesystem layers.
//!
//! Each anomaly is an *observation* ("consistent with …"); the examiner draws
//! the conclusions.
//!
//! # Capabilities
//!
//! - [`carve_deleted_records`] — recover deleted rows from free (unallocated)
//!   pages, the headline capability rusqlite structurally cannot provide. Each
//!   recovered row is confidence-graded, flagged `allocated: false`, and carries
//!   page/offset/rowid provenance.
//! - [`audit`] grades header reserved-space, a non-empty freelist (prior
//!   deletions), an active WAL overlay (uncheckpointed state), and a header/file
//!   page-count mismatch into severity-ranked
//!   [`forensicnomicon::report::Finding`]s.
//! - [`audit_journal`] grades the rollback-`-journal` design-§6 observations
//!   (hot journal, recoverable PERSIST pre-images, checksum mismatch, journaled
//!   schema page, duplicate page record, db-size delta) — additive to [`audit`].
//!
//! Deferred: a full anomaly suite (overflow-chain integrity, schema-format /
//! text-encoding checks) and a fuzz harness.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use forensicnomicon::report::{
    Confidence, Evidence, Finding, Location, Observation, Severity, Source,
};
use sqlite_core::{CommitId, Database, JournalHeader, RollbackJournal, Value, WalTimeline};

/// The classified `SQLite` forensic anomalies this auditor can grade.
///
/// `#[non_exhaustive]` so WS-E can add carving / WAL / freelist variants without
/// a breaking change; downstream `match` arms must carry a `_` arm.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnomalyKind {
    /// The header's reserved-space-per-page field is non-zero. Standard
    /// `SQLite` leaves this at 0; a non-zero value is used by page-level
    /// extensions (e.g. encryption such as SQLCipher/SEE, or checksum VFS) and
    /// is worth flagging on an evidence database.
    NonZeroReservedSpace {
        /// The reserved bytes per page reported by the header.
        reserved: u8,
    },
    /// A record-shaped cell was recovered from unallocated / free space —
    /// consistent with a deleted row that has not yet been overwritten.
    DeletedRecordRecovered {
        /// 1-based page the residue was carved from.
        page: u32,
        /// Byte offset of the cell within that page.
        offset: usize,
        /// Recovered rowid.
        rowid: i64,
    },
    /// The freelist is non-empty: the database holds free (unallocated) pages.
    /// Consistent with prior deletions (`DELETE` without `VACUUM`); those pages
    /// may retain recoverable deleted records.
    NonEmptyFreelist {
        /// Number of free pages on the freelist.
        free_pages: u32,
    },
    /// A `-wal` sidecar carried committed-but-unflushed page versions that the
    /// main database file does not yet reflect. Consistent with an evidence
    /// database captured while a write transaction was checkpoint-pending; the
    /// main file alone would under-report the true state.
    WalUncheckpointedState {
        /// Number of pages the WAL overlay superseded in the main file.
        overlaid_pages: u32,
    },
    /// The in-header page count disagrees with the page count implied by the
    /// file length. Consistent with truncation, carving, or out-of-band
    /// modification of the database file.
    PageCountMismatch {
        /// Page count recorded in the file header (offset 28).
        header_pages: u32,
        /// Page count implied by `file_len / page_size`.
        file_pages: u32,
    },
    /// A `-journal` with an intact header (valid magic) sits beside the database
    /// — a *hot journal*. Consistent with an interrupted or in-progress write
    /// transaction (crash, power loss, process kill, or acquisition captured
    /// mid-write); `SQLite` would roll it back on next open, so the main db may
    /// require rollback. The journal holds the pre-interruption state. (Design §6
    /// item 1 — state the observation; never assert "anti-forensic".)
    HotJournal,
    /// A committed PERSIST `-journal` (header zeroed, bodies intact) carries
    /// recoverable pre-images. Consistent with a normally-committed transaction
    /// whose deleted/modified rows remain recoverable (design §6 item 2).
    JournalRecoverable {
        /// Number of pre-transaction page images the journal carries.
        images: usize,
    },
    /// One or more journal page records failed the `pager.c` checksum (Tier A
    /// only — Tier B has no nonce to verify against). Consistent with corruption,
    /// a torn page (power-loss mid-sector), or post-write modification of the
    /// journal (design §6 item 3).
    JournalChecksumMismatch {
        /// The page numbers whose stored checksum did not match, ascending.
        pgnos: Vec<u32>,
        /// Total page records the journal carries (the denominator).
        total: usize,
    },
    /// The journal's prior **page-1 image** carries a different schema cookie
    /// (file-header offset 40, 4-byte BE) than the live database. The cookie
    /// advances only on `CREATE`/`DROP`/`ALTER`, so a difference is consistent
    /// with a DDL change in the last transaction; the prior schema is recoverable
    /// (design §6 item 6). Page 1 alone is NOT sufficient — it is journaled on
    /// nearly every write (the change-counter / freelist-count / db-size header
    /// fields update routinely), so the cookie comparison, not page-1 presence,
    /// is the DDL signal.
    JournalSchemaChange {
        /// Schema cookie in the journal's prior page-1 image (offset 40, BE).
        journal_cookie: u32,
        /// Schema cookie in the live database's page 1 (offset 40, BE).
        db_cookie: u32,
    },
    /// A `pgno` appeared more than once across the journal's page records. The
    /// spec journals a page at most once, so a repeat is consistent with
    /// corruption, a savepoint/super-journal artifact, or tampering (design §6
    /// item 9).
    JournalDuplicatePage,
    /// The database page count recorded at transaction start (`mxPage`, Tier A
    /// only) differs from the current page count: the last transaction changed
    /// the db size. `mxPage < current` ⇒ growth (INSERTs); `mxPage > current` ⇒
    /// shrink, consistent with auto-vacuum/incremental-vacuum or truncation — NOT
    /// an ordinary `DELETE` (design §6 item 5).
    JournalDbSizeDelta {
        /// Database page count at transaction start (`mxPage`, journal header).
        mx_page: u32,
        /// Current database page count.
        current_pages: u32,
    },
}

impl AnomalyKind {
    /// Severity, derived from the kind.
    #[must_use]
    pub fn severity(&self) -> Severity {
        match self {
            AnomalyKind::NonZeroReservedSpace { .. } | AnomalyKind::NonEmptyFreelist { .. } => {
                Severity::Low
            }
            AnomalyKind::DeletedRecordRecovered { .. }
            | AnomalyKind::WalUncheckpointedState { .. }
            | AnomalyKind::JournalRecoverable { .. }
            | AnomalyKind::JournalSchemaChange { .. }
            | AnomalyKind::JournalDuplicatePage => Severity::Medium,
            AnomalyKind::PageCountMismatch { .. }
            | AnomalyKind::HotJournal
            | AnomalyKind::JournalChecksumMismatch { .. } => Severity::High,
            AnomalyKind::JournalDbSizeDelta { .. } => Severity::Low,
        }
    }

    /// Stable, scheme-prefixed machine code (a published contract).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            AnomalyKind::NonZeroReservedSpace { .. } => "SQLITE-RESERVED-SPACE-NONZERO",
            AnomalyKind::DeletedRecordRecovered { .. } => "SQLITE-DELETED-RECORD-RECOVERED",
            AnomalyKind::NonEmptyFreelist { .. } => "SQLITE-FREELIST-NONEMPTY",
            AnomalyKind::WalUncheckpointedState { .. } => "SQLITE-WAL-UNCHECKPOINTED",
            AnomalyKind::PageCountMismatch { .. } => "SQLITE-PAGECOUNT-MISMATCH",
            AnomalyKind::HotJournal => "SQLITE-JOURNAL-HOT",
            AnomalyKind::JournalRecoverable { .. } => "SQLITE-JOURNAL-RECOVERABLE",
            AnomalyKind::JournalChecksumMismatch { .. } => "SQLITE-JOURNAL-CHECKSUM-MISMATCH",
            AnomalyKind::JournalSchemaChange { .. } => "SQLITE-JOURNAL-SCHEMA-CHANGE",
            AnomalyKind::JournalDuplicatePage => "SQLITE-JOURNAL-DUPLICATE-PAGE",
            AnomalyKind::JournalDbSizeDelta { .. } => "SQLITE-JOURNAL-DBSIZE-DELTA",
        }
    }

    /// Human-readable, "consistent with" note.
    #[must_use]
    pub fn note(&self) -> String {
        match self {
            AnomalyKind::NonZeroReservedSpace { reserved } => format!(
                "file header reserves {reserved} byte(s) per page — non-standard; \
                 consistent with a page-level extension such as encryption \
                 (SQLCipher/SEE) or a checksum VFS"
            ),
            AnomalyKind::DeletedRecordRecovered {
                page,
                offset,
                rowid,
            } => format!(
                "recovered a record-shaped cell (rowid {rowid}) from unallocated \
                 space at page {page} offset {offset} — consistent with a deleted \
                 row not yet overwritten"
            ),
            AnomalyKind::NonEmptyFreelist { free_pages } => format!(
                "{free_pages} free page(s) on the freelist — consistent with prior \
                 deletions (DELETE without VACUUM); free pages may retain \
                 recoverable deleted records"
            ),
            AnomalyKind::WalUncheckpointedState { overlaid_pages } => format!(
                "the -wal sidecar carries {overlaid_pages} committed page version(s) \
                 the main file does not reflect — consistent with capture while a \
                 write transaction was checkpoint-pending; the main file alone \
                 under-reports the true state"
            ),
            AnomalyKind::PageCountMismatch {
                header_pages,
                file_pages,
            } => format!(
                "in-header page count ({header_pages}) disagrees with the file \
                 length ({file_pages} pages) — consistent with truncation, \
                 carving, or out-of-band modification"
            ),
            AnomalyKind::HotJournal => "a hot rollback journal (valid header magic) sits beside \
                 the database — consistent with an interrupted or in-progress write transaction \
                 (crash, power loss, process kill, or acquisition captured mid-write); SQLite \
                 would roll it back on next open, so the main database may require rollback"
                .to_string(),
            AnomalyKind::JournalRecoverable { images } => format!(
                "the rollback journal carries {images} pre-transaction page \
                 image(s) (PERSIST post-commit) — consistent with a committed \
                 transaction whose pre-images (deleted/modified rows) remain \
                 recoverable"
            ),
            AnomalyKind::JournalChecksumMismatch { pgnos, total } => {
                let list = pgnos
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(
                    "{} of {total} journal page record(s) failed the page \
                     checksum (page(s) {list}) — consistent with corruption, a \
                     torn page write (power-loss mid-sector), or post-write \
                     modification of the journal",
                    pgnos.len()
                )
            }
            AnomalyKind::JournalSchemaChange {
                journal_cookie,
                db_cookie,
            } => format!(
                "the journal's prior schema cookie ({journal_cookie}) differs from the \
                 database's ({db_cookie}) — consistent with a DDL change (CREATE/DROP/ALTER) \
                 in the last transaction; the prior schema is recoverable"
            ),
            AnomalyKind::JournalDuplicatePage => "a page number appears more than once across the \
                 journal's page records — the spec journals a page at most once, so this is \
                 consistent with corruption, a savepoint/super-journal artifact, or tampering"
                .to_string(),
            AnomalyKind::JournalDbSizeDelta {
                mx_page,
                current_pages,
            } => {
                let direction = if *mx_page < *current_pages {
                    "the database grew (consistent with INSERTs adding pages)"
                } else {
                    "the database shrank (consistent with auto-vacuum / \
                     incremental-vacuum or truncation, NOT an ordinary DELETE)"
                };
                format!(
                    "the journal records a transaction-start page count \
                     (mxPage = {mx_page}) that differs from the current page \
                     count ({current_pages}) — the last transaction changed the \
                     database size: {direction}"
                )
            }
        }
    }
}

/// A `SQLite` forensic anomaly: an observation graded by severity, with a stable
/// code and note derived from its [`AnomalyKind`] so they cannot drift.
#[derive(Debug, Clone, PartialEq)]
pub struct Anomaly {
    /// Severity, derived from `kind`.
    pub severity: Severity,
    /// Stable machine-readable code, derived from `kind`.
    pub code: &'static str,
    /// The classified anomaly.
    pub kind: AnomalyKind,
    /// Human-readable note, derived from `kind`.
    pub note: String,
    /// Heuristic confidence, present for inferential findings (e.g. a carved
    /// deleted record); `None` for structurally-certain header observations.
    pub confidence: Option<f32>,
}

impl Anomaly {
    /// Build an [`Anomaly`], deriving severity/code/note from `kind`.
    #[must_use]
    pub fn new(kind: AnomalyKind) -> Self {
        Anomaly {
            severity: kind.severity(),
            code: kind.code(),
            note: kind.note(),
            kind,
            confidence: None,
        }
    }

    /// Attach a heuristic confidence (used for carved deleted records).
    #[must_use]
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = Some(confidence);
        self
    }
}

impl Observation for Anomaly {
    fn severity(&self) -> Option<Severity> {
        Some(self.severity)
    }
    fn code(&self) -> &'static str {
        self.code
    }
    fn note(&self) -> String {
        self.note.clone()
    }

    fn confidence(&self) -> Option<Confidence> {
        self.confidence.and_then(Confidence::new)
    }

    fn category(&self) -> forensicnomicon::report::Category {
        use forensicnomicon::report::Category;
        match &self.kind {
            // Deleted-record residue and free (deallocated) pages are recoverability
            // findings; the code keywords don't trip Category::from_code's Residue
            // classifier, so classify them explicitly.
            // Deleted-record residue and free pages are recoverability findings;
            // so are a recoverable PERSIST journal and a journaled schema page
            // (the prior schema/rows are recoverable from the journal images).
            AnomalyKind::DeletedRecordRecovered { .. }
            | AnomalyKind::NonEmptyFreelist { .. }
            | AnomalyKind::JournalRecoverable { .. }
            | AnomalyKind::JournalSchemaChange { .. } => Category::Residue,
            // A WAL-only/uncheckpointed state, a header/file page-count mismatch,
            // and the journal integrity observations (hot journal, checksum /
            // duplicate corruption, db-size delta) are integrity-of-state.
            AnomalyKind::WalUncheckpointedState { .. }
            | AnomalyKind::PageCountMismatch { .. }
            | AnomalyKind::HotJournal
            | AnomalyKind::JournalChecksumMismatch { .. }
            | AnomalyKind::JournalDuplicatePage
            | AnomalyKind::JournalDbSizeDelta { .. } => Category::Integrity,
            other => Category::from_code(other.code()),
        }
    }

    fn evidence(&self) -> Vec<Evidence> {
        match &self.kind {
            AnomalyKind::DeletedRecordRecovered {
                page,
                offset,
                rowid,
            } => vec![
                Evidence {
                    field: "rowid".to_string(),
                    value: rowid.to_string(),
                    location: Some(Location::RecordId(u64::try_from(*rowid).unwrap_or(0))),
                },
                Evidence {
                    field: "source_page".to_string(),
                    value: page.to_string(),
                    location: Some(Location::Other {
                        space: "sqlite:page".to_string(),
                        value: u64::from(*page),
                    }),
                },
                Evidence {
                    field: "cell_offset".to_string(),
                    value: offset.to_string(),
                    location: Some(Location::ByteOffset(*offset as u64)),
                },
            ],
            AnomalyKind::NonEmptyFreelist { free_pages } => vec![Evidence {
                field: "free_pages".to_string(),
                value: free_pages.to_string(),
                location: None,
            }],
            AnomalyKind::WalUncheckpointedState { overlaid_pages } => vec![Evidence {
                field: "overlaid_pages".to_string(),
                value: overlaid_pages.to_string(),
                location: None,
            }],
            AnomalyKind::PageCountMismatch {
                header_pages,
                file_pages,
            } => vec![
                Evidence {
                    field: "header_pages".to_string(),
                    value: header_pages.to_string(),
                    location: Some(Location::Field("in_header_db_size".to_string())),
                },
                Evidence {
                    field: "file_pages".to_string(),
                    value: file_pages.to_string(),
                    location: None,
                },
            ],
            AnomalyKind::JournalRecoverable { images } => vec![Evidence {
                field: "page_images".to_string(),
                value: images.to_string(),
                location: None,
            }],
            AnomalyKind::JournalChecksumMismatch { pgnos, total } => {
                let mut ev: Vec<Evidence> = pgnos
                    .iter()
                    .map(|pgno| Evidence {
                        field: "checksum_mismatch_pgno".to_string(),
                        value: pgno.to_string(),
                        location: Some(Location::Other {
                            space: "sqlite:page".to_string(),
                            value: u64::from(*pgno),
                        }),
                    })
                    .collect();
                ev.push(Evidence {
                    field: "page_records".to_string(),
                    value: total.to_string(),
                    location: None,
                });
                ev
            }
            AnomalyKind::JournalDbSizeDelta {
                mx_page,
                current_pages,
            } => vec![
                Evidence {
                    field: "mx_page".to_string(),
                    value: mx_page.to_string(),
                    location: None,
                },
                Evidence {
                    field: "current_pages".to_string(),
                    value: current_pages.to_string(),
                    location: None,
                },
            ],
            AnomalyKind::JournalSchemaChange {
                journal_cookie,
                db_cookie,
            } => vec![
                Evidence {
                    field: "journal_schema_cookie".to_string(),
                    value: journal_cookie.to_string(),
                    location: None,
                },
                Evidence {
                    field: "db_schema_cookie".to_string(),
                    value: db_cookie.to_string(),
                    location: None,
                },
            ],
            AnomalyKind::NonZeroReservedSpace { .. }
            | AnomalyKind::HotJournal
            | AnomalyKind::JournalDuplicatePage => Vec::new(),
        }
    }
}

/// Which class of free space a deleted record was carved from. Records the
/// recovery provenance so the examiner can weigh reliability by class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecoverySource {
    /// A whole page that was freed onto the freelist (the strongest case: the
    /// page holds only deallocated content).
    FreelistPage,
    /// The in-page free space (unallocated gap / freeblock slack) of a page that
    /// is still allocated. The record is genuinely deleted but more likely to be
    /// partially overwritten, so it is graded lower.
    InPageFreeBlock,
    /// A page whose table was `DROP`ped — on the freelist with no `sqlite_master`
    /// schema, so the column count was inferred from the record itself.
    DroppedTable,
    /// A **prior version** of a still-live row: an `UPDATE` freed the old version
    /// of the row into slack while the new version kept the same rowid. The
    /// recovered values DIFFER from the current live row (e.g. an edited message
    /// or a changed amount), so it is genuine deleted content — the edit history.
    PriorVersion,
    /// A record rebuilt by **freeblock reconstruction**: the freed cell's first
    /// four bytes (payload-length + rowid varints, `header_len`, and the leading
    /// serial type) were overwritten by SQLite's freeblock header, so the record
    /// was rebuilt from its surviving serial-type tail plus a schema template. The
    /// rowid is destroyed (surfaced as `0`), so this is the weakest in-page class
    /// — a low-confidence "consistent with a deleted row" lead.
    FreeblockReconstructed,
    /// Residue carved from an **uncheckpointed WAL frame's page image** rather
    /// than the on-disk pages. A `-wal` frame holds a committed page version the
    /// main file does not yet reflect; deleted cells freed within that version
    /// survive in the frame's slack and exist NOWHERE on disk. The record carries
    /// the `(salt1, salt2, frame_index)` log-sequence provenance in
    /// [`CarvedRecord::wal`].
    WalFrame,
    /// Residue carved from a **materialized commit snapshot** — the database state
    /// replayed up to one COMMIT frame of the `-wal` (base image ∪ committed frames
    /// to that commit). A row that is a live cell at this commit but deleted by a
    /// later commit survives ONLY in this snapshot's page images. The record
    /// carries the commit's `(salt1, salt2, commit_frame_index)` LSN in
    /// [`CarvedRecord::wal`] — the per-commit temporal coordinate, distinct from a
    /// raw [`RecoverySource::WalFrame`] residue's frame index.
    CommitSnapshot,
    /// A **prior allocated row from the rollback journal** (design §5). The row
    /// was LIVE in the pre-transaction state the `-journal` preserves and the last
    /// transaction deleted or modified it — it is NOT a free-space residue, so
    /// downstream reports must not relabel it as unallocated. Carries the page /
    /// segment / header-state / checksum provenance in [`RollbackJournalSource`].
    RollbackJournal(RollbackJournalSource),
}

/// Whether a rollback-journal header was parsed intact (Tier A) or reconstructed
/// from a zeroed (PERSIST post-commit) header (Tier B). A reconstructed header
/// could not verify page checksums (the nonce was zeroed), so its recoveries
/// rest on cross-record structural consistency — a graded distinction the
/// examiner weighs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalHeaderState {
    /// Tier A: header magic present; the checksum nonce was known and verified.
    Valid,
    /// Tier B: header zeroed (PERSIST post-commit); parameters reconstructed,
    /// checksums unverifiable.
    ReconstructedZeroed,
}

/// Provenance for a record recovered from a rollback journal (design §5):
/// where in the journal its page image lived and how trustworthy the parse was.
/// `Copy` (all fields are scalar) so it threads through the existing
/// attribution → output pipeline exactly like [`WalProvenance`]; the journal's
/// path is supplied once at the API boundary, not duplicated per row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RollbackJournalSource {
    /// 0-based journal segment the page image came from.
    pub segment: usize,
    /// 1-based database page number the prior image restored.
    pub pgno: u32,
    /// Whether the header was intact (Tier A) or reconstructed (Tier B).
    pub header_state: JournalHeaderState,
    /// `Some(true/false)` when the page checksum could be verified (Tier A);
    /// `None` in Tier B (nonce zeroed).
    pub checksum_valid: Option<bool>,
}

/// Provenance for a record carved from a `-wal` frame: the
/// `(salt1, salt2, frame_index)` log-sequence identity of the frame it came from
/// (the LSN task #55 will formalize).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalProvenance {
    /// 0-based position of the source frame within the `-wal` file.
    pub frame_index: usize,
    /// WAL header salt-1 (checkpoint generation) of the source frame.
    pub salt1: u32,
    /// WAL header salt-2 (checkpoint generation) of the source frame.
    pub salt2: u32,
}

/// Provenance for a record reassembled across an **overflow-page chain** (task
/// #73): the pages whose bytes were concatenated to recover the row. An examiner
/// citing the row as evidence can name exactly where its bytes came from. Present
/// only on chain-reassembled rows; `None` for every contiguous recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverflowProvenance {
    /// First overflow page of the chain (the page the local-prefix pointer named).
    pub first_page: u32,
    /// Ordered overflow pages whose content was assembled into the payload.
    pub chain: Vec<u32>,
}

/// A deleted record recovered from unallocated space — the headline capability
/// rusqlite cannot provide. Carries the decoded row plus provenance so the
/// examiner can weigh it as a "consistent with a deleted row" observation.
#[derive(Debug, Clone, PartialEq)]
pub struct CarvedRecord {
    /// 1-based page the record was carved from.
    pub page: u32,
    /// Byte offset of the cell within that page.
    pub offset: usize,
    /// Recovered rowid.
    pub rowid: i64,
    /// Decoded column values, in column order.
    pub values: Vec<Value>,
    /// Heuristic confidence in `(0.0, 1.0]` that these bytes are a real record.
    pub confidence: f32,
    /// Always `false`: a carved record lives in unallocated space, never in the
    /// live b-tree. Present so callers cannot mistake it for an allocated row.
    pub allocated: bool,
    /// Which class of free space this record was recovered from.
    pub source: RecoverySource,
    /// WAL log-sequence provenance, present **only** for
    /// [`RecoverySource::WalFrame`] records (the frame the residue was carved
    /// from); `None` for every on-disk class.
    pub wal: Option<WalProvenance>,
    /// Overflow-chain provenance, present **only** for rows reassembled across a
    /// freed overflow-page chain (task #73); `None` for every contiguous recovery.
    pub overflow: Option<OverflowProvenance>,
}

/// A **Tier-2 partial recovery**: a freed cell whose full row could not be
/// reconstructed but at least one *distinctive* cell (TEXT ≥ 4 bytes of valid
/// UTF-8, or REAL) survived at a structural anchor.
///
/// Deliberately NOT a [`CarvedRecord`]: it has no rowid (clobbered) and an
/// incomplete column set, and it does **not** share the full-row
/// 0-false-positive guarantee — it is a lead-generation surface with an expected
/// non-zero false-positive rate. The type system keeps it out of the full-row
/// output so a fragment can never be silently rendered as a recovered row
/// (secure by design). Returned only by [`carve_with_fragments`] in the opt-in
/// [`CarveTiers::fragments`] bucket. A fragment is "consistent with a partial
/// deleted row" — the examiner draws the conclusion.
#[derive(Debug, Clone, PartialEq)]
pub struct CarvedFragment {
    /// 1-based page the fragment was salvaged from.
    pub page: u32,
    /// Byte offset of the failed cell's anchor within that page.
    pub offset: usize,
    /// `(column_index, value)` for each column that decoded cleanly, ascending by
    /// index — meaningful against the table's column order.
    pub surviving: Vec<(usize, Value)>,
    /// Number of the row's columns that did NOT decode.
    pub missing: usize,
    /// Always the flat Tier-2 fragment confidence (0.2) for now — strictly below
    /// every full-row class.
    pub confidence: f32,
    /// Which class of free space the fragment was salvaged from
    /// ([`RecoverySource::FreeblockReconstructed`] for chain-pass fragments,
    /// [`RecoverySource::InPageFreeBlock`] for gap-pass fragments).
    pub source: RecoverySource,
    /// WAL log-sequence provenance. `None` in v1 (no WAL fragment pass yet).
    pub wal: Option<WalProvenance>,
}

/// The two strictly-separated recovery tiers returned by [`carve_with_fragments`].
///
/// `full` is **byte-identical** to [`carve_all_deleted_records`] and keeps its
/// structural 0-false-positive guarantee — the zero-config, high-precision
/// output. `fragments` is the opt-in Tier-2 lead surface (see [`CarvedFragment`]).
#[derive(Debug, Clone, PartialEq)]
pub struct CarveTiers {
    /// Tier-1 full rows — identical to [`carve_all_deleted_records`].
    pub full: Vec<CarvedRecord>,
    /// Tier-2 partial recoveries (opt-in; expected non-zero false-positive rate).
    pub fragments: Vec<CarvedFragment>,
}

/// Recover deleted records by carving the database's free (unallocated) pages.
///
/// Each free page from [`Database::freelist_pages`] is scanned with
/// [`Database::carve_cells`] for record-shaped cells of `column_count` columns.
/// Free pages hold only deallocated content, so the recovered rows are deleted
/// ones — the carver never re-surfaces a live (allocated) row. Recovered rows
/// are **confidence-graded observations**, not certainties: a carved record is
/// "consistent with a deleted row", and the examiner draws the conclusion.
///
/// Read-only and panic-free: a malformed freelist simply yields fewer (or no)
/// carved records rather than an error.
#[must_use]
pub fn carve_deleted_records(db: &Database, column_count: usize) -> Vec<CarvedRecord> {
    let mut out = Vec::new();
    let Ok(free) = db.freelist_pages() else {
        return out;
    };
    for page in free {
        let Some(page_bytes) = db.raw_page(page) else {
            continue; // cov:unreachable: freelist_pages only yields in-range pages
        };
        for cell in db.carve_cells(page_bytes, column_count) {
            out.push(CarvedRecord {
                page,
                offset: cell.offset,
                rowid: cell.rowid,
                values: cell.values,
                confidence: cell.confidence,
                allocated: false,
                source: RecoverySource::FreelistPage,
                wal: None,
                overflow: None,
            });
        }
    }
    out
}

/// Recover deleted records across **every** free-space class — the full-coverage
/// carver. Drives, in order:
///
/// 1. **Freelist pages** (whole pages freed onto the freelist), with the column
///    count inferred per record so it also recovers **dropped-table** pages whose
///    `sqlite_master` schema is gone (e.g. a `DROP TABLE` left the page on the
///    freelist with no recorded column count).
/// 2. **In-page free space** of still-allocated table-leaf pages (the unallocated
///    gap and inter-cell slack), via [`Database::carve_free_regions`], which
///    carves only the complement of the live cells — so a live (allocated) row is
///    **never** re-surfaced (the 0-false-positive guarantee, enforced
///    structurally).
///
/// Records are de-duplicated by `(rowid, values)` keeping the highest-confidence
/// copy, since a row can survive in more than one place. Every record is graded:
/// freelist-page recovery highest, dropped-table next, in-page residue lowest.
///
/// Read-only and panic-free; a malformed structure yields fewer records, never an
/// error or panic.
#[must_use]
pub fn carve_all_deleted_records(db: &Database) -> Vec<CarvedRecord> {
    let mut out: Vec<CarvedRecord> = Vec::new();

    // (1) Freelist pages, inferring the column count per record. Inference makes
    // this recover both normal freed pages AND schema-gone dropped-table pages
    // (a `DROP TABLE` leaves the page on the freelist with no recorded column
    // count). When the database has no live user table at all, the freed content
    // is necessarily from a dropped table, so mark those records accordingly.
    let dropped_table_db = !db.has_user_table();
    if let Ok(free) = db.freelist_pages() {
        for page in free {
            let Some(page_bytes) = db.raw_page(page) else {
                continue; // cov:unreachable: freelist_pages yields in-range pages
            };
            let source = if dropped_table_db {
                RecoverySource::DroppedTable
            } else {
                RecoverySource::FreelistPage
            };
            for cell in db.carve_cells_inferred(page_bytes) {
                out.push(CarvedRecord {
                    page,
                    offset: cell.offset,
                    rowid: cell.rowid,
                    values: cell.values,
                    confidence: cell.confidence,
                    allocated: false,
                    source,
                    wal: None,
                    overflow: None,
                });
            }
        }
    }

    // (2) In-page free space of every still-allocated table-leaf page.
    let page_count = db.page_count();
    for page in 1..=page_count {
        let Some(page_bytes) = db.raw_page(page) else {
            continue; // cov:unreachable: 1..=page_count is in range
        };
        for cell in db.carve_free_regions(page_bytes, 0) {
            out.push(CarvedRecord {
                page,
                offset: cell.offset,
                rowid: cell.rowid,
                values: cell.values,
                confidence: cell.confidence,
                allocated: false,
                source: RecoverySource::InPageFreeBlock,
                wal: None,
                overflow: None,
            });
        }
        // (2b) Freeblock reconstruction: the freed cells whose first four bytes
        // were clobbered by freeblock conversion, rebuilt from their surviving
        // serial tail plus the page's schema template. These carry an unknown
        // (destroyed) rowid, so the value-collision pass below — not the
        // rowid-keyed filter — is what guarantees no live row is re-surfaced.
        for cell in db.reconstruct_freeblock_records(page_bytes) {
            out.push(CarvedRecord {
                page,
                offset: cell.offset,
                rowid: cell.rowid,
                values: cell.values,
                confidence: cell.confidence,
                allocated: false,
                source: RecoverySource::FreeblockReconstructed,
                wal: None,
                overflow: None,
            });
        }
        // (2c) Chain-aware overflow recovery (task #73): a freed cell whose
        // payload spilled onto an overflow-page chain, reassembled when every
        // chain page survives as a freelist leaf. Graded below the in-page
        // full-row tier (NOT part of the structural 0-FP guarantee — Codex
        // ruling #1); a broken chain (e.g. a trunk-clobbered page) is rejected
        // here and degrades to a Tier-2 fragment elsewhere.
        for (cell, chain) in db.carve_overflow_records(page_bytes) {
            let first_page = chain.first().copied().unwrap_or(0);
            out.push(CarvedRecord {
                page,
                offset: cell.offset,
                rowid: cell.rowid,
                values: cell.values,
                confidence: cell.confidence,
                allocated: false,
                source: RecoverySource::InPageFreeBlock,
                wal: None,
                overflow: Some(OverflowProvenance { first_page, chain }),
            });
        }
        // (2d) Freeblock-clobbered spilled cells (task #73, Codex ruling #5;
        // UNPROVEN-BY-CORPUS — synthetic validation only). A spilled cell whose
        // prefix was also freeblock-clobbered: P re-derived from the surviving
        // serial array, chain resolved through freelist leaves, rowid destroyed.
        for (cell, chain) in db.carve_overflow_template_records(page_bytes) {
            let first_page = chain.first().copied().unwrap_or(0);
            out.push(CarvedRecord {
                page,
                offset: cell.offset,
                rowid: cell.rowid,
                values: cell.values,
                confidence: cell.confidence,
                allocated: false,
                source: RecoverySource::FreeblockReconstructed,
                wal: None,
                overflow: Some(OverflowProvenance { first_page, chain }),
            });
        }
    }

    // (3) WAL-frame carving (additive — runs ONLY when a `-wal` overlay is in
    // effect). The on-disk path above reads only the main file's pages, so it
    // finds the SAME residue whether or not a WAL was supplied; the genuinely-
    // different deleted records live in the uncheckpointed WAL frames.
    //
    // A `-wal` frame is a FULL page snapshot at one point in the transaction
    // history. A row deleted late in that history is still a live cell in an
    // EARLIER frame's image; it exists nowhere on disk and in no later frame.
    // Three primitives over each committed frame's page image surface it:
    //
    //   * `carve_leaf_cells` — every cell the frame records as allocated. A cell
    //     that is allocated in a superseded frame but ABSENT from the final
    //     WAL-applied live view is exactly such a deleted row (recovered as a
    //     clean, intact record — the strongest WAL case).
    //   * `carve_free_regions` / `reconstruct_freeblock_records` — residue freed
    //     WITHIN a frame (e.g. the DELETE-commit frame's own freeblocks), matching
    //     the on-disk in-page classes.
    //
    // Every candidate is tagged `WalFrame` with the (salt1, salt2, frame_index)
    // LSN provenance, and the shared live-row precision filter below drops any
    // whose values match a currently-live row — so a surviving row is never
    // re-surfaced (the 0-false-positive guarantee, against the WAL-applied view).
    for frame in db.wal_frame_pages() {
        let prov = WalProvenance {
            frame_index: frame.frame_index,
            salt1: frame.salt1,
            salt2: frame.salt2,
        };
        let cells = db
            .carve_leaf_cells(&frame.page)
            .into_iter()
            .chain(db.carve_free_regions(&frame.page, 0))
            .chain(db.reconstruct_freeblock_records(&frame.page));
        for cell in cells {
            out.push(CarvedRecord {
                page: frame.page_no,
                offset: cell.offset,
                rowid: cell.rowid,
                values: cell.values,
                confidence: cell.confidence,
                allocated: false,
                source: RecoverySource::WalFrame,
                wal: Some(prov),
                overflow: None,
            });
        }
    }

    // VALUE-AWARE classification for carved records whose rowid is currently
    // LIVE. Two very different cases share a live rowid:
    //
    //   * Stale rebalance copy — a b-tree rebalance moved a still-live row to
    //     another page, leaving a byte-identical copy in the old page's slack.
    //     SAME rowid, SAME values → NOT deleted → drop (the 0-false-positive
    //     precision win we must preserve).
    //   * Prior version — an UPDATE freed the OLD version of the row into slack
    //     while the new version kept the same rowid. SAME rowid, DIFFERENT values
    //     → genuinely-deleted content (the edited message / changed amount, often
    //     THE evidence) → recover, tagged `PriorVersion`.
    //
    // A rowid-only filter cannot tell these apart and drops both (a false
    // negative on prior versions). Comparing decoded values does.
    let live = db.live_rows();
    // Value-level identity of every live row, for collision-checking records whose
    // rowid is unknown (freeblock reconstructions have a destroyed rowid, so the
    // rowid-keyed filter below cannot protect against re-surfacing a live row).
    // The live set also includes the CURRENT `sqlite_master` rows: a record carved
    // from a materialized page 1 (the schema table) whose values equal a live
    // schema entry is that live row re-surfaced, not deleted residue — drop it.
    // (Value-based, so a genuinely-deleted PRIOR schema version is still recovered.)
    let live_value_keys: std::collections::HashSet<String> = live
        .values()
        .chain(db.live_schema_rows().iter())
        .map(|v| format!("{v:?}"))
        .collect();
    out.retain_mut(|rec| {
        // Freeblock reconstructions carry an unknown rowid → guard by value: drop
        // any whose decoded values match a currently-live row (never re-surface a
        // live row), even though we cannot key it by rowid.
        if rec.source == RecoverySource::FreeblockReconstructed {
            return !live_value_keys.contains(&format!("{:?}", rec.values));
        }
        // WAL-frame residue is guarded the same way and KEEPS its WalFrame tag:
        // drop any record whose values match a currently-live row (the WAL-applied
        // view's live set), so a row that survived the deletion is never
        // re-surfaced; a genuinely-deleted WAL row has no live match and is kept
        // with its frame provenance intact (not reclassified to PriorVersion).
        if rec.source == RecoverySource::WalFrame {
            return !live_value_keys.contains(&format!("{:?}", rec.values));
        }
        match live.get(&rec.rowid) {
            // rowid not live → an ordinary deleted record (keep, source unchanged).
            None => true,
            // Same rowid: a byte-identical copy is a stale rebalance artifact (drop);
            // differing values are a deleted prior version (keep, reclassified).
            Some(live_values) => {
                if &rec.values == live_values {
                    false
                } else {
                    rec.source = RecoverySource::PriorVersion;
                    true
                }
            }
        }
    });

    dedup_keep_best(out)
}

/// Two-tier deleted-record recovery: Tier-1 full rows **plus** Tier-2 partial
/// fragments, in one pass.
///
/// [`CarveTiers::full`] is byte-identical to [`carve_all_deleted_records`] (the
/// high-precision, structurally-0-false-positive output). [`CarveTiers::fragments`]
/// is the opt-in lead surface: at every freeblock/gap anchor where full
/// reconstruction failed but ≥ 1 distinctive cell (TEXT ≥ 4 bytes of valid UTF-8,
/// or REAL) survived, the maximal decodable column prefix is salvaged as a
/// [`CarvedFragment`]. Three suppression layers keep the fragment bucket honest:
///
/// 1. **By construction** — a fragment is emitted only where full reconstruction
///    failed, so an anchor yields a full cell or a fragment, never both.
/// 2. **Full-row value suppression** — a fragment whose every surviving
///    `(column, value)` matches the corresponding column of a Tier-1 record in
///    `full` is dropped (the row was already recovered another way).
/// 3. **Live-row suppression** — a fragment whose every surviving `(column, value)`
///    matches the corresponding columns of a currently-live row is dropped (never
///    re-surface a live row, the fragment analog of the rebalance-copy drop).
///
/// Read-only and panic-free, identically to [`carve_all_deleted_records`].
#[must_use]
pub fn carve_with_fragments(db: &Database) -> CarveTiers {
    let full = carve_all_deleted_records(db);

    // Salvage Tier-2 fragments from every on-disk table-leaf page. The core
    // walker emits a fragment only where full reconstruction failed (layer 1).
    let mut fragments: Vec<CarvedFragment> = Vec::new();
    let page_count = db.page_count();
    for page in 1..=page_count {
        let Some(page_bytes) = db.raw_page(page) else {
            continue; // cov:unreachable: 1..=page_count is in range
        };
        for frag in db.reconstruct_freeblock_fragments(page_bytes) {
            fragments.push(CarvedFragment {
                page,
                offset: frag.offset,
                surviving: frag.surviving,
                missing: frag.missing,
                confidence: frag.confidence,
                source: RecoverySource::FreeblockReconstructed,
                wal: None,
            });
        }
        // Broken-chain overflow fragments (task #73, Codex ruling #4): a spilled
        // cell whose overflow chain was destroyed (e.g. a trunk-clobbered chain
        // page) still has an intact local prefix; salvage its locally-decodable
        // columns. The chain-resident columns are lost (untrusted), so this is a
        // Tier-2 lead, never a full row.
        for frag in db.carve_overflow_fragments(page_bytes) {
            fragments.push(CarvedFragment {
                page,
                offset: frag.offset,
                surviving: frag.surviving,
                missing: frag.missing,
                confidence: frag.confidence,
                source: RecoverySource::InPageFreeBlock,
                wal: None,
            });
        }
    }

    // Layer 3: live-row suppression. A fragment whose surviving set matches the
    // corresponding columns of a live row is a stale partial copy of a live row.
    let live = db.live_rows();
    fragments.retain(|frag| !live.values().any(|lv| fragment_matches_columns(frag, lv)));

    // Layer 2: full-row value suppression. A fragment already covered by a
    // recovered full row in this carve is a duplicate — drop it.
    fragments.retain(|frag| {
        !full
            .iter()
            .any(|rec| fragment_matches_columns(frag, &rec.values))
    });

    // Fragment dedup: one fragment per (page, offset) anchor by construction,
    // then collapse value-level duplicates keeping the copy with more surviving
    // columns (mirrors dedup_keep_best for the full tier).
    fragments = dedup_fragments(fragments);

    CarveTiers { full, fragments }
}

/// Whether a fragment's every surviving `(column_index, value)` pair equals the
/// corresponding column of `row` — the projection test shared by the full-row
/// (layer 2) and live-row (layer 3) suppression passes. Equality of the **whole**
/// surviving set is required: a fragment that coincides with a row on only some
/// cells is kept (it may be genuine residue), mirroring the full-row rule's
/// whole-values comparison.
fn fragment_matches_columns(frag: &CarvedFragment, row: &[Value]) -> bool {
    !frag.surviving.is_empty()
        && frag
            .surviving
            .iter()
            .all(|(idx, v)| row.get(*idx) == Some(v))
}

/// De-duplicate fragments: first by `(page, offset)` anchor (one fragment per
/// anchor by construction), then collapse value-level duplicates keeping the copy
/// with the most surviving columns. Mirrors [`dedup_keep_best`] for the full tier.
fn dedup_fragments(mut frags: Vec<CarvedFragment>) -> Vec<CarvedFragment> {
    use std::collections::HashSet;
    // More surviving columns first, so the kept copy of each identity is richest.
    frags.sort_by_key(|f| std::cmp::Reverse(f.surviving.len()));
    let mut seen_anchor: HashSet<(u32, usize)> = HashSet::new();
    let mut seen_values: HashSet<String> = HashSet::new();
    let mut kept = Vec::new();
    for frag in frags {
        if !seen_anchor.insert((frag.page, frag.offset)) {
            continue;
        }
        let vkey = format!("{:?}", frag.surviving);
        if !seen_values.insert(vkey) {
            continue;
        }
        kept.push(frag);
    }
    kept
}

/// Carve the deleted residue of **one materialized commit snapshot** of the
/// `-wal`, the per-commit temporal building block of the N-snapshot carve.
///
/// `id` addresses a [`CommitId`] in `timeline`; the snapshot it resolves to is the
/// database state replayed up to that COMMIT (base image ∪ every committed frame to
/// that commit, capped to `db_size_after_commit`). This runs the same three
/// carving primitives the on-disk path uses — [`Database::carve_leaf_cells`]
/// (intact cells the snapshot records as allocated, the strongest case),
/// [`Database::carve_free_regions`], and [`Database::reconstruct_freeblock_records`]
/// — over each of the snapshot's materialized page images, then applies the SAME
/// live-row precision filter: a record whose decoded values match a currently-live
/// row (the WAL-applied view) is dropped, so a row that survived to the final state
/// is **never** re-surfaced as deleted. Surviving records are tagged
/// [`RecoverySource::CommitSnapshot`] and carry the commit's
/// `(salt1, salt2, commit_frame_index)` LSN in [`CarvedRecord::wal`].
///
/// An unknown [`CommitId`] (absent from `timeline`) yields an empty vector, never a
/// panic. Read-only throughout.
#[must_use]
pub fn carve_at_commit(db: &Database, timeline: &WalTimeline, id: CommitId) -> Vec<CarvedRecord> {
    let Some(snapshot) = timeline.snapshot_at(id) else {
        return Vec::new();
    };
    let lsn = snapshot.lsn();
    let prov = WalProvenance {
        frame_index: lsn.frame_index,
        salt1: lsn.salt1,
        salt2: lsn.salt2,
    };

    let mut out: Vec<CarvedRecord> = Vec::new();
    for page_no in snapshot.page_numbers() {
        let Some(image) = snapshot.page_version(page_no) else {
            continue; // cov:unreachable: page_numbers only yields materialized pages
        };
        let cells = db
            .carve_leaf_cells(&image.bytes)
            .into_iter()
            .chain(db.carve_free_regions(&image.bytes, 0))
            .chain(db.reconstruct_freeblock_records(&image.bytes));
        for cell in cells {
            out.push(CarvedRecord {
                page: page_no,
                offset: cell.offset,
                rowid: cell.rowid,
                values: cell.values,
                confidence: cell.confidence,
                allocated: false,
                source: RecoverySource::CommitSnapshot,
                wal: Some(prov),
                overflow: None,
            });
        }
    }

    // Live-row precision filter (the WAL-applied view): drop any record whose
    // decoded values match a currently-live row, so a row that survives to the
    // final state is never re-surfaced as "deleted at an earlier commit". The
    // live set includes the CURRENT `sqlite_master` rows, because a snapshot's
    // materialized page 1 (the schema table) still holds the live schema cell —
    // value-based, so a deleted PRIOR schema version is still recovered.
    let live = db.live_rows();
    let live_value_keys: std::collections::HashSet<String> = live
        .values()
        .chain(db.live_schema_rows().iter())
        .map(|v| format!("{v:?}"))
        .collect();
    out.retain(|rec| !live_value_keys.contains(&format!("{:?}", rec.values)));

    dedup_keep_best(out)
}

/// De-duplicate carved records by content identity, keeping the
/// highest-confidence copy of each (a row can survive in several free regions).
///
/// `Value` carries an `f64` (`Real`) so it is not `Hash`/`Eq`; the identity key
/// is the record's `rowid` plus a stable `Debug` rendering of its values, which
/// is sufficient to collapse byte-identical recoveries.
fn dedup_keep_best(mut records: Vec<CarvedRecord>) -> Vec<CarvedRecord> {
    use std::collections::HashSet;
    let mut seen: HashSet<String> = HashSet::new();
    let mut kept: Vec<CarvedRecord> = Vec::new();
    // Highest confidence first, so the kept copy of each identity is the best one.
    records.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    for rec in records.drain(..) {
        let key = format!("{}:{:?}", rec.rowid, rec.values);
        if seen.insert(key) {
            kept.push(rec);
        }
    }
    kept
}

/// A row recovered from the prior (pre-transaction) snapshot of a rollback
/// journal (design §5). In the prior state it was a LIVE allocated row that the
/// last transaction DELETED — so it is recovered at full fidelity and is NOT a
/// free-space carve (`allocated` was true in the prior state). Carries full
/// journal provenance in [`RollbackJournalSource`].
#[derive(Debug, Clone, PartialEq)]
pub struct PriorRow {
    /// The table the row belonged to (prior schema).
    pub table: String,
    /// The row's rowid (its INTEGER PRIMARY KEY for a rowid table).
    pub rowid: i64,
    /// The decoded prior column values, in column order.
    pub values: Vec<Value>,
    /// Journal provenance: page / segment / header-state / checksum status.
    pub source: RecoverySource,
}

/// A row present in BOTH the prior snapshot and the live db with DIFFERENT values
/// — the last transaction modified it (design §4). Carries the PRIOR (pre-edit)
/// values and the CURRENT values. `replaced_rowid` is set because a delete +
/// insert reusing the same rowid is indistinguishable from an in-place UPDATE
/// here, so identity may differ — never asserted as "UPDATE".
#[derive(Debug, Clone, PartialEq)]
pub struct PriorVersionRecord {
    /// The table the row belonged to (prior schema).
    pub table: String,
    /// The rowid present in both states.
    pub rowid: i64,
    /// The decoded PRIOR (pre-transaction) column values.
    pub prior_values: Vec<Value>,
    /// The decoded CURRENT (live) column values.
    pub current_values: Vec<Value>,
    /// Always `true`: the rowid is shared but identity may differ (delete+insert
    /// reusing a rowid is indistinguishable from an UPDATE), so the prior value is
    /// edit history, not an asserted in-place update.
    pub replaced_rowid: bool,
    /// Journal provenance for the prior image.
    pub source: RecoverySource,
}

/// Structured counts of what the rollback-journal recovery found — the NIST
/// SFT-03 "number of deleted/modified records" report (design §5/§6.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct JournalCounts {
    /// Rows deleted by the last transaction (prior \ current by rowid).
    pub deleted: usize,
    /// Rows modified by the last transaction (present in both, values differ).
    pub modified: usize,
}

/// The result of recovering deletions + modifications from a rollback journal
/// (design §5). Deleted rows are full-fidelity prior allocated rows (NOT
/// free-space carves); modified rows carry the prior and current values.
#[derive(Debug, Clone, PartialEq)]
pub struct JournalRecovery {
    /// Rows present in the prior snapshot but absent now — deleted by the last
    /// transaction, recovered at full fidelity.
    pub deleted: Vec<PriorRow>,
    /// Rows present in both, values differ — prior (pre-edit) + current values.
    pub modified: Vec<PriorVersionRecord>,
    /// Structured counts (the NIST source-file report).
    pub counts: JournalCounts,
}

/// Recover the last transaction's **deletions and modifications** from a rollback
/// `-journal` by diffing the pre-transaction snapshot against the live database
/// (design §4) — the temporal inverse of WAL recovery.
///
/// For each prior rowid table, the prior rows (read through [`PriorSnapshot`])
/// are diffed against the current rows by rowid:
/// - **deleted** = rowid in prior but not current → a full-fidelity [`PriorRow`];
/// - **modified** = rowid in both with different values → a [`PriorVersionRecord`]
///   flagged `replaced_rowid` (identity may differ; never asserted as UPDATE);
/// - **inserted** (rowid only in current) is a timeline fact, not a recovery target.
///
/// `WITHOUT ROWID` tables are excluded (no integer rowid key; design §4 limit).
/// Read-only and panic-free: a malformed/truncated journal, or a WAL-applied db
/// (the modes are exclusive), yields an empty recovery rather than an error or
/// panic — the journal source is bound to THIS database via
/// [`Database::rollback_prior`].
#[must_use]
pub fn carve_rollback_journal(db: &Database, journal: &[u8]) -> JournalRecovery {
    let mut deleted = Vec::new();
    let mut modified = Vec::new();

    let Ok(prior) = db.rollback_prior(journal) else {
        return JournalRecovery {
            deleted,
            modified,
            counts: JournalCounts::default(),
        };
    };
    // Header state + checksum status are uniform across a single journal; carry
    // them on every recovered row's provenance.
    let Some(header_state) = prior_header_state(journal, db) else {
        // cov:unreachable: rollback_prior above already parsed the same journal,
        // so a re-parse here cannot fail; the arm degrades to an empty recovery.
        return JournalRecovery {
            deleted,
            modified,
            counts: JournalCounts::default(),
        };
    };
    // Per-row checksum status is not threaded through PriorSnapshot in v1, so the
    // verifiable fact recorded here is the journal-level one: Tier A could verify
    // checksums (nonce known), Tier B could not (nonce zeroed). A finer per-image
    // status is a later enhancement; `header_state` carries the Tier either way.
    let checksum_valid = match header_state {
        JournalHeaderState::Valid => Some(true),
        JournalHeaderState::ReconstructedZeroed => None,
    };

    // Index the current (live) rows per table by rowid, so the diff is O(rows).
    let live = db.live_table_rows();

    for ptable in prior.tables() {
        if ptable.without_rowid {
            continue; // design §4 limit: WITHOUT ROWID excluded from the rowid diff.
        }
        let col_count = ptable.columns.len();
        let Ok(prior_rows) = prior.read_table_with_pages(ptable.rootpage, col_count) else {
            continue;
        };
        // Current rows of the same-named table (live schema), by rowid.
        let current: std::collections::BTreeMap<i64, Vec<Value>> = live
            .iter()
            .find(|d| d.name == ptable.name)
            .map(|d| d.rows.iter().map(|r| (r.rowid, r.values.clone())).collect())
            .unwrap_or_default();

        for (rowid, values, leaf_page) in prior_rows {
            let source = RecoverySource::RollbackJournal(RollbackJournalSource {
                segment: 0,
                pgno: leaf_page,
                header_state,
                checksum_valid,
            });
            match current.get(&rowid) {
                None => deleted.push(PriorRow {
                    table: ptable.name.clone(),
                    rowid,
                    values,
                    source,
                }),
                Some(cur) if *cur != values => modified.push(PriorVersionRecord {
                    table: ptable.name.clone(),
                    rowid,
                    prior_values: values,
                    current_values: cur.clone(),
                    replaced_rowid: true,
                    source,
                }),
                Some(_) => {} // unchanged: the page was journaled for another row.
            }
        }
    }

    let counts = JournalCounts {
        deleted: deleted.len(),
        modified: modified.len(),
    };
    JournalRecovery {
        deleted,
        modified,
        counts,
    }
}

/// Determine whether the journal header was intact (Tier A) or zeroed (Tier B),
/// by re-parsing it against the db's authoritative page size.
fn prior_header_state(journal: &[u8], db: &Database) -> Option<JournalHeaderState> {
    let parsed = RollbackJournal::parse(journal, db.header().page_size).ok()?;
    Some(match parsed.header() {
        JournalHeader::Valid { .. } => JournalHeaderState::Valid,
        JournalHeader::ReconstructedZeroed { .. } => JournalHeaderState::ReconstructedZeroed,
    })
}

/// Audit an opened [`Database`] for forensically-notable anomalies.
///
/// Covers the header reserved-space field, a non-empty freelist (prior
/// deletions), an active WAL overlay (uncheckpointed state), and a header/file
/// page-count mismatch. Deleted-record recovery is offered separately via
/// [`carve_deleted_records`] / [`audit_carved_findings`] because it requires the
/// table's column count.
#[must_use]
pub fn audit(db: &Database) -> Vec<Anomaly> {
    let mut out = Vec::new();

    let reserved = db.header().reserved;
    if reserved != 0 {
        out.push(Anomaly::new(AnomalyKind::NonZeroReservedSpace { reserved }));
    }

    let free_pages = db.freelist_count();
    if free_pages != 0 {
        out.push(Anomaly::new(AnomalyKind::NonEmptyFreelist { free_pages }));
    }

    if db.wal_applied() {
        // The overlay supersedes at least one page; report it as uncheckpointed
        // state. (The exact page count is not separately exposed; report ≥1.)
        out.push(Anomaly::new(AnomalyKind::WalUncheckpointedState {
            overlaid_pages: 1,
        }));
    }

    let header_pages = db.header_page_count();
    let file_pages = db.file_page_count();
    if header_pages != 0 && header_pages != file_pages {
        out.push(Anomaly::new(AnomalyKind::PageCountMismatch {
            header_pages,
            file_pages,
        }));
    }

    out
}

/// Audit an opened [`Database`] and convert each anomaly to the canonical
/// [`Finding`] under the supplied [`Source`], ready to merge into a `Report`.
#[must_use]
pub fn audit_findings(db: &Database, source: &Source) -> Vec<Finding> {
    audit(db)
        .into_iter()
        .map(|a| a.to_finding(source.clone()))
        .collect()
}

/// The database schema cookie: file-header bytes `40..44` as a big-endian `u32`
/// (file-format §1.3). Returns `None` when the page is too short to hold the
/// field — bounded and panic-free, so a truncated page-1 image degrades to "no
/// cookie" rather than indexing out of range.
fn schema_cookie(page: &[u8]) -> Option<u32> {
    let bytes = page.get(40..44)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Audit a rollback `-journal` (raw bytes) bound to `db` for the design-§6
/// observations, additive to [`audit`] (which covers main-db anomalies only).
///
/// The journal is parsed with the database's authoritative page size and graded
/// into observations, each derivable from the parser API and each "consistent
/// with …" (the examiner draws the conclusion):
/// - a **hot journal** (valid header magic) — an interrupted/in-progress write;
/// - a **recoverable** PERSIST journal (zeroed header, page images intact);
/// - **checksum mismatch(es)** (Tier A) — corruption / torn page / modification;
/// - a **schema-cookie advance** (journal page-1 image vs live db, offset 40) — a
///   DDL change, prior schema recoverable;
/// - a **duplicate page record** — corruption / savepoint / tampering;
/// - a **db-size delta** (Tier A `mxPage` vs current) — growth or shrink.
///
/// Read-only and panic-free: an unparsable/garbage journal simply yields no
/// observations rather than an error or panic.
#[must_use]
pub fn audit_journal(db: &Database, journal: &[u8]) -> Vec<Anomaly> {
    let mut out = Vec::new();

    let Ok(parsed) = RollbackJournal::parse(journal, db.header().page_size) else {
        // A page size outside [512, 65536] / non-power-of-two is the only parse
        // error; a database that opened cannot have one, so this degrades to no
        // observations rather than masking a real failure.
        return out;
    };

    let images = parsed.page_images();

    match parsed.header() {
        JournalHeader::Valid { mx_page, .. } => {
            // A valid-magic header is a hot journal (interrupted/in-progress).
            out.push(Anomaly::new(AnomalyKind::HotJournal));

            // mxPage (db size at txn start) vs the current page count. 0 is the
            // "size unknown" sentinel, so only a non-zero, differing value is a
            // reportable size delta.
            let current_pages = db.page_count();
            if *mx_page != 0 && *mx_page != current_pages {
                out.push(Anomaly::new(AnomalyKind::JournalDbSizeDelta {
                    mx_page: *mx_page,
                    current_pages,
                }));
            }
        }
        JournalHeader::ReconstructedZeroed { .. } => {
            // A zeroed (PERSIST post-commit) header with >=1 page image carries
            // recoverable pre-images.
            if !images.is_empty() {
                out.push(Anomaly::new(AnomalyKind::JournalRecoverable {
                    images: images.len(),
                }));
            }
        }
    }

    // Checksum mismatches (Tier A only — Tier B's checksum_valid is None).
    let bad: Vec<u32> = images
        .iter()
        .filter(|i| i.checksum_valid == Some(false))
        .map(|i| i.pgno)
        .collect();
    if !bad.is_empty() {
        out.push(Anomaly::new(AnomalyKind::JournalChecksumMismatch {
            pgnos: bad,
            total: images.len(),
        }));
    }

    // A DDL change is signalled by the schema cookie (file-header offset 40, BE)
    // advancing — NOT merely by page 1 being journaled. Page 1 carries the
    // change-counter / freelist-count / db-size header fields that update on
    // nearly every write, so it is present in almost every rollback journal; only
    // a cookie that differs between the journal's prior page-1 image and the live
    // database indicates CREATE/DROP/ALTER. Read both cookies defensively: if the
    // page-1 image is absent or the live page 1 is unreadable, do not fire.
    //
    // Caveat: for an UNCOMMITTED hot journal the live main-db file may not yet
    // carry the new cookie, so a DDL in a hot journal can be undetectable here.
    // That is acceptable — the detector never false-positives; it just cannot
    // always observe the committed-cookie case mid-flight.
    if let (Some(journal_cookie), Some(db_cookie)) = (
        images
            .iter()
            .find(|i| i.pgno == 1)
            .and_then(|i| schema_cookie(&i.bytes)),
        db.raw_page(1).and_then(schema_cookie),
    ) {
        if journal_cookie != db_cookie {
            out.push(Anomaly::new(AnomalyKind::JournalSchemaChange {
                journal_cookie,
                db_cookie,
            }));
        }
    }

    // A page journaled more than once (the spec forbids it).
    if parsed.has_duplicate_pgno() {
        out.push(Anomaly::new(AnomalyKind::JournalDuplicatePage));
    }

    out
}

/// Audit a rollback `-journal` and convert each design-§6 observation to the
/// canonical [`Finding`] under `source`, ready to merge into a `Report`. The
/// additive counterpart to [`audit_findings`] for the journal sidecar.
#[must_use]
pub fn audit_journal_findings(db: &Database, journal: &[u8], source: &Source) -> Vec<Finding> {
    audit_journal(db, journal)
        .into_iter()
        .map(|a| a.to_finding(source.clone()))
        .collect()
}

/// Carve deleted records and convert each to a canonical [`Finding`] under
/// `source`. The per-record confidence is threaded into the finding's context so
/// downstream consumers can filter low-confidence recoveries.
#[must_use]
pub fn audit_carved_findings(db: &Database, column_count: usize, source: &Source) -> Vec<Finding> {
    carve_deleted_records(db, column_count)
        .into_iter()
        .map(|rec| {
            Anomaly::new(AnomalyKind::DeletedRecordRecovered {
                page: rec.page,
                offset: rec.offset,
                rowid: rec.rowid,
            })
            .with_confidence(rec.confidence)
            .to_finding(source.clone())
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Table attribution: reattach a carved deleted row to its source table in three
// honest tiers (CERTAIN / INFERRED / UNATTRIBUTED).
// ---------------------------------------------------------------------------

/// How confidently a carved deleted row has been reattached to a live table.
///
/// The three tiers encode distinct epistemic strengths (observed fact / forensic
/// inference / unattributed), and the renderer keeps them honest: a Tier-2 guess
/// is "consistent with" a table, never asserted as the table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attribution {
    /// **Tier 1 — CERTAIN.** The record was carved from a page still part of a
    /// live table's b-tree, so the owning table is known for sure. Carries that
    /// table's name.
    Known(String),
    /// **Tier 2 — INFERRED.** The whole page was freed (linkage cut); the
    /// record's *shape* (column count + per-column affinity) matched one or more
    /// surviving tables. A forensic inference, never asserted as fact.
    Inferred {
        /// The candidate table whose shape the record matches.
        guess: String,
        /// `true` when more than one surviving table matched the shape, so the
        /// guess is one of several equally-consistent candidates.
        ambiguous: bool,
    },
    /// **Tier 3 — UNATTRIBUTED.** Dropped-table residue, or a shape matching no
    /// surviving table.
    Unattributed,
}

/// Whether a carved value is **storage-compatible** with a column of the given
/// declared affinity — the per-cell test the shape matcher applies.
///
/// Rules (permissive enough to survive `SQLite`'s numeric coercions, strict
/// enough to discriminate tables of equal arity but different type layout):
/// a NULL is compatible with anything; INTEGER/REAL are mutually compatible and
/// also satisfy NUMERIC; TEXT requires a text-leaning affinity (TEXT) or the
/// catch-all BLOB/NUMERIC; a BLOB requires BLOB. The BLOB affinity (or a column
/// with no declared type) accepts any value, matching SQLite's "no datatype"
/// semantics.
#[must_use]
pub fn value_fits_affinity(value: &Value, affinity: sqlite_core::attribution::Affinity) -> bool {
    use sqlite_core::attribution::Affinity;
    // BLOB affinity (incl. no-declared-type columns) is SQLite's catch-all: a
    // value of any storage class can live there.
    if affinity == Affinity::Blob {
        return true;
    }
    match value {
        // A NULL fits any column.
        Value::Null => true,
        Value::Integer(_) | Value::Real(_) => matches!(
            affinity,
            Affinity::Integer | Affinity::Real | Affinity::Numeric
        ),
        // NUMERIC accepts text too (SQLite stores a non-numeric string as text in
        // a NUMERIC column), so a TEXT value is consistent with TEXT or NUMERIC.
        Value::Text(_) => matches!(affinity, Affinity::Text | Affinity::Numeric),
        // A BLOB only sits in a BLOB column (handled above) — never a typed one.
        Value::Blob(_) => false,
    }
}

/// Whether a carved record's values match a live table's shape: equal column
/// count AND every value storage-compatible with the corresponding column
/// affinity ([`value_fits_affinity`]).
#[must_use]
pub fn shape_matches(values: &[Value], table: &sqlite_core::attribution::LiveTable) -> bool {
    if values.len() != table.affinities.len() {
        return false;
    }
    values
        .iter()
        .zip(&table.affinities)
        .all(|(v, &aff)| value_fits_affinity(v, aff))
}

/// The names of every live table whose shape a record's values match, in the
/// order the tables were listed. Zero matches → unattributable shape; one →
/// a clean guess; more than one → ambiguous.
#[must_use]
pub fn matching_tables(
    values: &[Value],
    tables: &[sqlite_core::attribution::LiveTable],
) -> Vec<String> {
    tables
        .iter()
        .filter(|t| shape_matches(values, t))
        .map(|t| t.name.clone())
        .collect()
}

/// Attribute one carved record to a tier given the live tables and the
/// page→table map. Pure (no DB access) so it is directly unit-testable.
///
/// - Tier 1 (CERTAIN): `source` is an in-page class ([`RecoverySource::InPageFreeBlock`]
///   or [`RecoverySource::FreeblockReconstructed`]) AND the record's page is in
///   `page_table_map` → [`Attribution::Known`].
/// - Tier 2 (INFERRED): `source` is [`RecoverySource::FreelistPage`] → match the
///   record's shape against `tables`; exactly one match → a guess, more than one
///   → ambiguous, none → [`Attribution::Unattributed`].
/// - Tier 3 (UNATTRIBUTED): [`RecoverySource::DroppedTable`], any other source,
///   or a shape matching no surviving table.
#[must_use]
pub fn attribute_record(
    rec: &CarvedRecord,
    tables: &[sqlite_core::attribution::LiveTable],
    page_table_map: &std::collections::BTreeMap<u32, String>,
) -> Attribution {
    // Tier 1 — CERTAIN: an in-page record on a page still owned by a live
    // table's b-tree. The page→table map is the hard linkage.
    if matches!(
        rec.source,
        RecoverySource::InPageFreeBlock | RecoverySource::FreeblockReconstructed
    ) {
        if let Some(name) = page_table_map.get(&rec.page) {
            return Attribution::Known(name.clone());
        }
        // In-page residue on a page that is NOT a live-table page (e.g. the
        // owning table itself was freed): no certain linkage, and in-page is not
        // the freelist class, so it is unattributed rather than inferred.
        return Attribution::Unattributed;
    }

    // Tier 2 — INFERRED: a whole-page freelist record; the linkage is cut, so
    // attribute by shape against the surviving tables.
    if rec.source == RecoverySource::FreelistPage {
        let mut matches = matching_tables(&rec.values, tables);
        return match matches.len() {
            0 => Attribution::Unattributed,
            1 => Attribution::Inferred {
                guess: matches.remove(0),
                ambiguous: false,
            },
            _ => Attribution::Inferred {
                guess: matches.remove(0),
                ambiguous: true,
            },
        };
    }

    // Tier 3 — UNATTRIBUTED: dropped-table residue or any other source.
    Attribution::Unattributed
}

/// Attribute every carved record, reading the live tables and page→table map
/// from `db` once. The returned vector is parallel to `records`.
#[must_use]
pub fn attribute_records(db: &Database, records: &[CarvedRecord]) -> Vec<Attribution> {
    let tables = db.live_tables();
    let page_table_map = db.page_to_table_map();
    records
        .iter()
        .map(|rec| attribute_record(rec, &tables, &page_table_map))
        .collect()
}

/// The core per-rowid VERSION HISTORY ([`Database::row_histories`]) augmented with
/// free-space CARVED RESIDUE — the forensic-layer completion of Phase 1.
///
/// Carved residue is ORDER-UNKNOWN: a freeblock persists across commits, so
/// [`carve_at_commit`] / [`carve_with_fragments`] tag where residue was OBSERVED,
/// not where the row was deleted. Each carved record is therefore emitted as a
/// [`CarvedResidue`](sqlite_core::row_history::VersionOrigin::CarvedResidue) /
/// [`CarvedResidue`](sqlite_core::row_history::ViewState::CarvedResidue) version with
/// `commit_seq: None` (never a fabricated commit position), `is_deleted: true`,
/// and `is_guessed` set when its [`Attribution`] is `Inferred`. Residue is
/// attributed to a table via [`attribute_records`] and DEDUPED against any WAL
/// `AbsentInFinalView` version of the same rowid + values (the WAL holds it at
/// higher fidelity), so a row is never double-listed.
#[must_use]
pub fn row_histories_with_residue(db: &Database) -> Vec<sqlite_core::row_history::TableHistory> {
    use sqlite_core::row_history::{RowVersion, VersionOrigin, ViewState};

    let mut histories = db.row_histories();

    // Gather every carved residue record: the on-disk free space (Tier-1 full
    // rows) plus each materialized commit snapshot of the WAL. carve_at_commit /
    // carve_with_fragments already de-duplicate within their own pass; we collect
    // across passes and de-duplicate by content identity below.
    let mut records: Vec<CarvedRecord> = carve_with_fragments(db).full;
    if let Some(timeline) = db.wal_timeline() {
        for snapshot in timeline.commit_snapshots() {
            records.extend(carve_at_commit(db, &timeline, snapshot.id()));
        }
    }
    // Collapse byte-identical carves (a row can recur across commits / regions).
    let records = dedup_keep_best(records);

    // Attribute each carved record to a table. The strongest signal is page
    // linkage: a record carved from a page still owned by a live table's b-tree
    // (e.g. a PRIOR-version remnant in that table's slack) belongs to THAT table
    // for certain — stronger than, and independent of, the source-class tiering in
    // `attribute_record`. We consult the page→table map first, then fall back to
    // the shape-based `attribute_records` for off-table (freelist-page) residue.
    let page_table_map = db.page_to_table_map();
    let attributions = attribute_records(db, &records);

    // A residue carve is deduped against a WAL `AbsentInFinalView` version of the
    // SAME rowid + values already in that table's history (the WAL holds it at
    // higher fidelity). Build the set of those (table, rowid, values) keys.
    let absent_keys: std::collections::HashSet<String> = histories
        .iter()
        .flat_map(|h| {
            h.versions
                .iter()
                .filter(|v| v.view_state == ViewState::AbsentInFinalView)
                .map(move |v| residue_key(&h.table, v.rowid, &v.values))
        })
        .collect();

    // Group new residue versions by target table name.
    let mut to_add: std::collections::BTreeMap<String, Vec<RowVersion>> =
        std::collections::BTreeMap::new();
    for (rec, attr) in records.iter().zip(attributions.iter()) {
        // Page linkage (CERTAIN) wins; else the shape-based tier.
        let (table, is_guessed) = if let Some(name) = page_table_map.get(&rec.page) {
            (name.clone(), false)
        } else {
            match attr {
                Attribution::Known(name) => (name.clone(), false),
                Attribution::Inferred { guess, .. } => (guess.clone(), true),
                // No surviving table to attach the residue to — skip rather than
                // invent a home for it (no fabricated attribution).
                Attribution::Unattributed => continue,
            }
        };
        // A clobbered rowid (carving surfaces it as 0) is genuinely unknown.
        let rowid = if rec.rowid == 0 {
            None
        } else {
            Some(rec.rowid)
        };
        let key = residue_key(&table, rowid, &rec.values);
        if absent_keys.contains(&key) {
            continue; // already listed as a higher-fidelity WAL AbsentInFinalView
        }
        to_add.entry(table).or_default().push(RowVersion {
            rowid,
            values: rec.values.clone(),
            origin: VersionOrigin::CarvedResidue,
            // Order-unknown: a freeblock persists across commits, so a carve has
            // no trustworthy commit position. NEVER fabricate one.
            commit_seq: None,
            view_state: ViewState::CarvedResidue,
            is_deleted: true,
            is_guessed,
            rowid_reused: false,
            // An inferred (shape-matched) attribution is uncertain by nature.
            attribution_uncertain: is_guessed,
        });
    }

    // Merge the residue versions into their tables, de-duplicating residue that is
    // byte-identical to a version already present, then re-sort.
    for h in &mut histories {
        if let Some(extra) = to_add.remove(&h.table) {
            let existing: std::collections::HashSet<String> = h
                .versions
                .iter()
                .map(|v| residue_key(&h.table, v.rowid, &v.values))
                .collect();
            for v in extra {
                if existing.contains(&residue_key(&h.table, v.rowid, &v.values)) {
                    continue;
                }
                h.versions.push(v);
            }
            sqlite_core::row_history::sort_table_versions(&mut h.versions);
        }
    }
    histories
}

/// A content-identity key for residue de-duplication: table + rowid + a stable
/// `Debug` rendering of the values (`Value` carries an `f64`, so it is not
/// `Hash`/`Eq` directly).
fn residue_key(table: &str, rowid: Option<i64>, values: &[Value]) -> String {
    format!("{table}:{rowid:?}:{values:?}")
}

#[cfg(test)]
mod attribution_tests {
    use super::{
        attribute_record, attribute_records, matching_tables, shape_matches, value_fits_affinity,
        Attribution, CarvedRecord, RecoverySource,
    };
    use sqlite_core::attribution::{Affinity, LiveTable};
    use sqlite_core::Value;

    fn table(name: &str, root: u32, affinities: Vec<Affinity>) -> LiveTable {
        LiveTable {
            name: name.to_string(),
            rootpage: root,
            column_names: None,
            affinities,
        }
    }

    fn rec(page: u32, source: RecoverySource, values: Vec<Value>) -> CarvedRecord {
        CarvedRecord {
            page,
            offset: 0,
            rowid: 1,
            values,
            confidence: 0.9,
            allocated: false,
            source,
            wal: None,
            overflow: None,
        }
    }

    #[test]
    fn value_affinity_compatibility() {
        assert!(value_fits_affinity(&Value::Null, Affinity::Integer));
        assert!(value_fits_affinity(&Value::Integer(1), Affinity::Integer));
        assert!(value_fits_affinity(&Value::Integer(1), Affinity::Real));
        assert!(value_fits_affinity(&Value::Real(1.0), Affinity::Numeric));
        assert!(value_fits_affinity(
            &Value::Text("x".into()),
            Affinity::Text
        ));
        assert!(value_fits_affinity(&Value::Blob(vec![1]), Affinity::Blob));
        // A text value does NOT fit an integer column.
        assert!(!value_fits_affinity(
            &Value::Text("x".into()),
            Affinity::Integer
        ));
        // A blob does not fit a text column.
        assert!(!value_fits_affinity(&Value::Blob(vec![1]), Affinity::Text));
        // BLOB (or no-type) affinity is the catch-all: any value fits.
        assert!(value_fits_affinity(
            &Value::Text("x".into()),
            Affinity::Blob
        ));
        assert!(value_fits_affinity(&Value::Integer(1), Affinity::Blob));
    }

    #[test]
    fn shape_match_requires_equal_arity_and_compatible_cells() {
        let t = table("people", 2, vec![Affinity::Integer, Affinity::Text]);
        assert!(shape_matches(
            &[Value::Integer(1), Value::Text("a".into())],
            &t
        ));
        // Wrong arity.
        assert!(!shape_matches(&[Value::Integer(1)], &t));
        // Incompatible cell (text in an integer column).
        assert!(!shape_matches(
            &[Value::Text("a".into()), Value::Text("b".into())],
            &t
        ));
    }

    #[test]
    fn clean_single_match() {
        let tables = vec![
            table("people", 2, vec![Affinity::Integer, Affinity::Text]),
            table("amounts", 3, vec![Affinity::Real, Affinity::Real]),
        ];
        let m = matching_tables(&[Value::Integer(1), Value::Text("a".into())], &tables);
        assert_eq!(m, vec!["people"]);
    }

    #[test]
    fn ambiguous_two_tables_same_shape() {
        let tables = vec![
            table("a", 2, vec![Affinity::Integer, Affinity::Text]),
            table("b", 3, vec![Affinity::Integer, Affinity::Text]),
        ];
        let m = matching_tables(&[Value::Integer(1), Value::Text("x".into())], &tables);
        assert_eq!(m, vec!["a", "b"]);
    }

    #[test]
    fn no_match_is_unattributed_shape() {
        let tables = vec![table("a", 2, vec![Affinity::Integer, Affinity::Text])];
        let m = matching_tables(&[Value::Blob(vec![1]), Value::Blob(vec![2])], &tables);
        assert!(m.is_empty());
    }

    #[test]
    fn tier1_inpage_page_in_map_is_known() {
        let tables = vec![table("people", 2, vec![Affinity::Integer, Affinity::Text])];
        let mut map = std::collections::BTreeMap::new();
        map.insert(5u32, "people".to_string());
        let r = rec(
            5,
            RecoverySource::InPageFreeBlock,
            vec![Value::Integer(1), Value::Text("a".into())],
        );
        assert_eq!(
            attribute_record(&r, &tables, &map),
            Attribution::Known("people".to_string())
        );
    }

    #[test]
    fn tier1_freeblock_reconstructed_in_map_is_known() {
        let tables = vec![table("people", 2, vec![Affinity::Integer, Affinity::Text])];
        let mut map = std::collections::BTreeMap::new();
        map.insert(7u32, "people".to_string());
        let r = rec(7, RecoverySource::FreeblockReconstructed, vec![Value::Null]);
        assert_eq!(
            attribute_record(&r, &tables, &map),
            Attribution::Known("people".to_string())
        );
    }

    #[test]
    fn tier2_freelist_single_match_is_inferred_unambiguous() {
        let tables = vec![
            table("people", 2, vec![Affinity::Integer, Affinity::Text]),
            table("amounts", 3, vec![Affinity::Real, Affinity::Real]),
        ];
        let map = std::collections::BTreeMap::new();
        let r = rec(
            9,
            RecoverySource::FreelistPage,
            vec![Value::Integer(1), Value::Text("a".into())],
        );
        assert_eq!(
            attribute_record(&r, &tables, &map),
            Attribution::Inferred {
                guess: "people".to_string(),
                ambiguous: false
            }
        );
    }

    #[test]
    fn tier2_freelist_multi_match_is_ambiguous() {
        let tables = vec![
            table("a", 2, vec![Affinity::Integer, Affinity::Text]),
            table("b", 3, vec![Affinity::Integer, Affinity::Text]),
        ];
        let map = std::collections::BTreeMap::new();
        let r = rec(
            9,
            RecoverySource::FreelistPage,
            vec![Value::Integer(1), Value::Text("x".into())],
        );
        assert_eq!(
            attribute_record(&r, &tables, &map),
            Attribution::Inferred {
                guess: "a".to_string(),
                ambiguous: true
            }
        );
    }

    #[test]
    fn tier2_freelist_no_match_is_unattributed() {
        let tables = vec![table("a", 2, vec![Affinity::Integer, Affinity::Text])];
        let map = std::collections::BTreeMap::new();
        let r = rec(
            9,
            RecoverySource::FreelistPage,
            vec![Value::Blob(vec![1]), Value::Blob(vec![2])],
        );
        assert_eq!(
            attribute_record(&r, &tables, &map),
            Attribution::Unattributed
        );
    }

    #[test]
    fn tier3_dropped_table_is_unattributed() {
        let tables = vec![table("a", 2, vec![Affinity::Integer, Affinity::Text])];
        let map = std::collections::BTreeMap::new();
        let r = rec(
            9,
            RecoverySource::DroppedTable,
            vec![Value::Integer(1), Value::Text("x".into())],
        );
        assert_eq!(
            attribute_record(&r, &tables, &map),
            Attribution::Unattributed
        );
    }

    #[test]
    fn tier1_inpage_page_not_in_map_falls_through_to_unattributed() {
        // An in-page record on a page that is NOT a live-table page (e.g. its
        // table was the one freed): no Tier-1 certainty, and in-page is not the
        // freelist class, so it is unattributed rather than inferred.
        let tables = vec![table("people", 2, vec![Affinity::Integer, Affinity::Text])];
        let map = std::collections::BTreeMap::new();
        let r = rec(
            42,
            RecoverySource::InPageFreeBlock,
            vec![Value::Integer(1), Value::Text("a".into())],
        );
        assert_eq!(
            attribute_record(&r, &tables, &map),
            Attribution::Unattributed
        );
    }

    #[test]
    fn attribute_records_reads_schema_from_a_real_database() {
        // Mint a tiny valid db via the writer (no sqlite3 needed), open it, and
        // drive the db-backed attribute_records wrapper end to end.
        use sqlite_core::rebuild::{build_recovered_db_tables, RecoveredTable};
        use sqlite_core::Database;
        let seed = vec![RecoveredTable {
            name: "people".to_string(),
            columns: vec!["id".to_string(), "name".to_string()],
            rows: vec![vec![Value::Integer(1), Value::Text("a".into())]],
        }];
        let db = Database::open(build_recovered_db_tables(&seed)).expect("minted db opens");
        let records = vec![super::CarvedRecord {
            page: 99,
            offset: 0,
            rowid: 0,
            values: vec![Value::Integer(2), Value::Text("b".into())],
            confidence: 0.9,
            allocated: false,
            source: RecoverySource::FreelistPage,
            wal: None,
            overflow: None,
        }];
        let attrs = attribute_records(&db, &records);
        assert_eq!(attrs.len(), 1);
        // (INTEGER, TEXT) freelist row matches the people table's shape.
        assert!(matches!(attrs[0], Attribution::Inferred { .. }));
    }
}

#[cfg(test)]
mod tests {
    use super::{dedup_fragments, CarvedFragment, RecoverySource};
    use sqlite_core::Value;

    fn frag(page: u32, offset: usize, surviving: Vec<(usize, Value)>) -> CarvedFragment {
        let missing = 3usize.saturating_sub(surviving.len());
        CarvedFragment {
            page,
            offset,
            surviving,
            missing,
            confidence: 0.2,
            source: RecoverySource::InPageFreeBlock,
            wal: None,
        }
    }

    /// `dedup_fragments` orders by survivor count (richest kept), drops a repeated
    /// `(page, offset)` anchor, and collapses a value-level duplicate at a fresh
    /// anchor — exercising both dedup arms and the survivor-count sort over a
    /// multi-element input (a single-element vector never invokes the comparator).
    #[test]
    fn dedup_keeps_richest_and_drops_duplicates() {
        let rich = frag(
            1,
            10,
            vec![(0, Value::Integer(1)), (1, Value::Text("a".into()))],
        );
        let poor_same_anchor = frag(1, 10, vec![(0, Value::Integer(1))]);
        let value_dup_new_anchor = frag(
            2,
            20,
            vec![(0, Value::Integer(1)), (1, Value::Text("a".into()))],
        );

        let out = dedup_fragments(vec![poor_same_anchor, rich, value_dup_new_anchor]);

        // The richest copy of the shared identity survives; the poorer same-anchor
        // copy and the value-identical fresh-anchor copy are both dropped.
        assert_eq!(
            out.len(),
            1,
            "duplicates collapse to the richest single copy"
        );
        assert_eq!(
            out[0].surviving.len(),
            2,
            "the 2-column copy is the one kept"
        );
    }
}
