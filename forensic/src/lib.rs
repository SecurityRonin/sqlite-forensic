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
//!
//! Deferred: a full anomaly suite (overflow-chain integrity, schema-format /
//! text-encoding checks) and a fuzz harness.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use forensicnomicon::report::{
    Confidence, Evidence, Finding, Location, Observation, Severity, Source,
};
use sqlite_core::{Database, Value};

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
            | AnomalyKind::WalUncheckpointedState { .. } => Severity::Medium,
            AnomalyKind::PageCountMismatch { .. } => Severity::High,
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
            AnomalyKind::DeletedRecordRecovered { .. } | AnomalyKind::NonEmptyFreelist { .. } => {
                Category::Residue
            }
            // A WAL-only/uncheckpointed state and a header/file page-count mismatch
            // are integrity-of-state observations.
            AnomalyKind::WalUncheckpointedState { .. } | AnomalyKind::PageCountMismatch { .. } => {
                Category::Integrity
            }
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
            AnomalyKind::NonZeroReservedSpace { .. } => Vec::new(),
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
            });
        }
    }

    // 0-FALSE-POSITIVE: a b-tree rebalance can move a still-LIVE row to another
    // page, leaving a stale byte-copy of it in the old page's free space. That
    // copy parses as a clean record but is NOT a deleted row — reporting it would
    // be a false positive. Drop any carved record whose rowid is currently live.
    // (carve_free_regions already excludes live *cells* structurally; this
    // additionally excludes live *content* lingering in free space.)
    let live = db.live_rowids();
    out.retain(|rec| !live.contains(&rec.rowid));

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
