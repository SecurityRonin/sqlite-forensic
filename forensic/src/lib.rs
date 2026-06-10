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
//! # Scope
//!
//! This skeleton grades exactly one anomaly the spike reader can already
//! surface from the 100-byte file header: a non-zero **reserved-space-per-page**
//! field. WS-E (`sqlite-forensic` proper) expands this into the real analyzer —
//! b-tree free-cell / unallocated carving, deleted-record recovery, freelist
//! anomalies, WAL-overlay honesty, and overflow-chain validation — on top of an
//! expanded `sqlite-core` reader surface.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use forensicnomicon::report::{Finding, Observation, Severity, Source};
use sqlite_core::Database;

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
}

impl AnomalyKind {
    /// Severity, derived from the kind.
    #[must_use]
    pub fn severity(&self) -> Severity {
        match self {
            AnomalyKind::NonZeroReservedSpace { .. } => Severity::Low,
        }
    }

    /// Stable, scheme-prefixed machine code (a published contract).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            AnomalyKind::NonZeroReservedSpace { .. } => "SQLITE-RESERVED-SPACE-NONZERO",
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
        }
    }
}

/// A `SQLite` forensic anomaly: an observation graded by severity, with a stable
/// code and note derived from its [`AnomalyKind`] so they cannot drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anomaly {
    /// Severity, derived from `kind`.
    pub severity: Severity,
    /// Stable machine-readable code, derived from `kind`.
    pub code: &'static str,
    /// The classified anomaly.
    pub kind: AnomalyKind,
    /// Human-readable note, derived from `kind`.
    pub note: String,
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
        }
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
}

/// Audit an opened [`Database`] for header-integrity anomalies.
///
/// Side-effect free and exact over the already-parsed header — the spike reader
/// has validated magic + page size by the time a [`Database`] exists, so the
/// remaining gradable header observation is the reserved-space field.
#[must_use]
pub fn audit(_db: &Database) -> Vec<Anomaly> {
    // RED: not yet implemented — the GREEN commit grades the reserved-space field.
    Vec::new()
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
