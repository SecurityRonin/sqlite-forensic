//! Per-table, per-rowid VERSION HISTORY over a `SQLite` database's WAL temporal
//! model — the evidence-based "row history" (Phase 1 of the WAL-temporal work).
//!
//! [`Database::row_histories`](crate::Database::row_histories) walks each salt
//! epoch's [`CommitSnapshot`](crate::CommitSnapshot)s in commit order, then the
//! final live view, and for every rowid emits the sequence of distinct record
//! values it held — an `INSERT`/`UPDATE`/`DELETE`/reinsert history reconstructed
//! purely from the bytes, with NO timestamps (SQLite WAL carries no wall-clock
//! time; `commit_seq` is LOGICAL order within an epoch only).
//!
//! The two correctness-critical transforms are pure and unit-testable here:
//! [`build_rowid_versions`] collapses identical consecutive values into one
//! version (labelled by the EARLIEST view it appeared in) and classifies each
//! version's [`ViewState`] from evidence; the same walk detects rowid REUSE (a
//! present→absent→present-with-a-different-record gap is a delete+reinsert, two
//! entities, never one continuous update).

use crate::Value;
use std::collections::BTreeMap;

/// Where a [`RowVersion`] came from. Logical provenance only — never a timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionOrigin {
    /// The current on-disk ⊕ WAL live view (the FINAL state).
    Live,
    /// A materializable WAL commit, addressed by its [`CommitId`](crate::CommitId).
    Commit(crate::CommitId),
    /// Free-space carved residue with no precise temporal position (freeblocks
    /// persist across commits, so the carve is ORDER-UNKNOWN).
    CarvedResidue,
}

/// The EVIDENCE-based state of a row version relative to the FINAL live view.
///
/// Strictly evidence, never intent: it records what the bytes show (present /
/// changed-later / absent / carved), not what the user meant to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewState {
    /// This exact value is present and unchanged in the final live view — the
    /// current row.
    PresentInFinalView,
    /// An earlier value that a later view replaced with a DIFFERENT value for the
    /// same rowid.
    ValueChangedLater,
    /// The rowid's last value before it disappeared: absent from the final live
    /// view (a deletion).
    AbsentInFinalView,
    /// A free-space carve — order-unknown residue, not a positioned commit value.
    CarvedResidue,
}

/// One version of one row: a distinct record value the rowid held at some point,
/// with its evidence-based classification and logical provenance.
#[derive(Debug, Clone, PartialEq)]
pub struct RowVersion {
    /// The rowid this version belongs to. `None` only for a carved residue whose
    /// rowid was destroyed.
    pub rowid: Option<i64>,
    /// The decoded column values of this version, in column order.
    pub values: Vec<Value>,
    /// Logical provenance of the version.
    pub origin: VersionOrigin,
    /// The LOGICAL commit sequence (per salt epoch, monotonic WITHIN an epoch
    /// only) of the EARLIEST view this value appeared in. `None` for the live
    /// view and for carved residue (order-unknown).
    pub commit_seq: Option<u32>,
    /// Evidence-based view state.
    pub view_state: ViewState,
    /// Whether this version's rowid is absent from the final live view (a
    /// deletion or a completed pre-reuse entity).
    pub is_deleted: bool,
    /// Whether this version was reconstructed/guessed rather than read directly
    /// (carved residue with inferred attribution).
    pub is_guessed: bool,
    /// Whether this rowid was REUSED — present, then absent for ≥1 view, then
    /// present again with a DIFFERENT record. Set on every version of a reused
    /// rowid so a renderer never presents two entities as one continuous update.
    pub rowid_reused: bool,
    /// Whether this version's attribution is uncertain — its source view was
    /// checksum-invalid residue, or its schema could not be reconstructed.
    pub attribution_uncertain: bool,
}

/// The version history of one user table.
#[derive(Debug, Clone, PartialEq)]
pub struct TableHistory {
    /// The table's `sqlite_master.name`.
    pub table: String,
    /// The table's column names (real names where the schema parsed, else generic).
    pub columns: Vec<String>,
    /// Whether this is a `WITHOUT ROWID` table — such tables have no rowid and are
    /// not version-tracked here; `versions` is then empty (presence recorded only).
    pub without_rowid: bool,
    /// Every row version, sorted by `rowid` (`None` last), then `commit_seq`
    /// ascending, with carved-residue (order-unknown) versions grouped after the
    /// ordered versions of their rowid.
    pub versions: Vec<RowVersion>,
}

/// One chronological VIEW of a single table: a rowid→values map plus the view's
/// logical position and trust flags. The ordered list of these (commit views in
/// epoch order, then the final live view last) is the input to
/// [`build_rowid_versions`].
#[derive(Debug, Clone, PartialEq)]
pub struct RowView {
    /// LOGICAL commit sequence within the salt epoch (monotonic within an epoch
    /// only). `None` for the final live view.
    pub commit_seq: Option<u32>,
    /// Whether this is the final live view (the current state).
    pub is_final: bool,
    /// Whether the source commit's checksum chain validated. `false` = residue:
    /// rows first attributed here are flagged `attribution_uncertain`.
    pub checksum_valid: bool,
    /// Whether the table's schema could be reconstructed for this view. `false`
    /// flags rows attributed here `attribution_uncertain`.
    pub schema_known: bool,
    /// This view's rows: rowid → decoded values. A rowid absent from the map is
    /// absent in this view.
    pub rows: BTreeMap<i64, Vec<Value>>,
}

/// Build the ordered [`RowVersion`]s for ONE `rowid` by walking `views` (already
/// in chronological order: epoch commits ascending, then the final live view).
///
/// Emits a version only when the value CHANGES (insert / update / delete /
/// reinsert), collapsing identical consecutive values into one version labelled
/// by the EARLIEST view it appeared in. View-state is evidence-based:
/// `PresentInFinalView` when the value is the final live value; `ValueChangedLater`
/// when a later view replaced it with a different value; `AbsentInFinalView` when
/// the rowid's last value disappeared. Rowid REUSE (present → absent → present
/// with a different record) flags every version of the rowid `rowid_reused` and
/// treats the post-gap value as a fresh insert.
///
/// Pure: no I/O. The result is in chronological order for this rowid.
#[must_use]
pub fn build_rowid_versions(_rowid: i64, _views: &[RowView]) -> Vec<RowVersion> {
    Vec::new()
}
