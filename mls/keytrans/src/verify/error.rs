// SPDX-License-Identifier: MIT
//! What the verifier refuses, one variant per failure a client must tell
//! apart, grouped by [`FailureKind`].
//!
//! Like the crate's [`Error`], no variant names a label, an account or a key
//! of a person: a verdict may end up in a device's log. The one exception is
//! [`VerifyError::UnknownAuditorKeys`], whose keys are auditor instance keys
//! (public, and logged under the `k` label) that the caller must go and read.

use crate::error::Error;

/// How a caller acts on a [`VerifyError`].
///
/// The channel matters too: every failure of a response the client asked the
/// log for is the log's fault, while a transparency proof that a peer handed
/// over and that fails as [`FailureKind::BadProof`] may be the peer's doing
/// (treated as missing, and fetched from the log instead).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// Evidence against the log: a bad signature, a failed consistency proof,
    /// a missing or stale auditor head, a head outside the clock window,
    /// timestamps out of order, or a view that forks from one the client
    /// retained. The client keeps its last good view.
    LogFault,
    /// A proof that does not verify: malformed bytes, the wrong number of
    /// entries, a prefix or log tree proof that does not reach its root, a
    /// VRF proof or commitment that fails, a version claim the ladders
    /// contradict.
    BadProof,
    /// A verified answer that the version asked for does not exist (draft
    /// §7.2 step 6).
    NotFound,
    /// A verified answer that the version asked for has expired (draft §7.2).
    Expired,
    /// A head signed for an auditor key the client has not accepted: read the
    /// live auditor's key from its attested service once, hand it to
    /// [`ClientState::accept_auditor_key`](super::ClientState::accept_auditor_key),
    /// then retry.
    NeedAuditorKey,
    /// A transparency proof anchored at a distinguished entry the client does
    /// not hold. Not a prompt to fetch a head (draft §14 step 1): the proof
    /// waits, or the sender is asked for a newer one.
    NeedDistinguished,
    /// The caller passed state or a request that does not fit the response:
    /// a bug on this side, not evidence about the log.
    Usage,
}

/// Everything the verifier refuses.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VerifyError {
    /// Bytes or a structure the crate's shared code refused.
    #[error("malformed: {0}")]
    Malformed(Error),
    /// A proof that is well formed but wrong: a count off, a root not
    /// reached, two proofs for one entry that disagree.
    #[error("bad proof: {0}")]
    Proof(&'static str),
    /// A response whose log tree disagrees with what the client retained:
    /// the log showed this client two different histories.
    #[error("inconsistent with the retained view: {0}")]
    Inconsistent(&'static str),
    /// Log entry timestamps that go backwards (draft §4, §12.3).
    #[error("log entry timestamps out of order")]
    TimestampOrder,
    /// A VRF proof that does not verify.
    #[error("bad VRF proof")]
    BadVrfProof,
    /// A value that does not open its commitment.
    #[error("commitment does not open to the value")]
    BadCommitment,
    /// Ladders that contradict the version the response claims (a version
    /// above the claimed greatest included, or one at or below it missing).
    #[error("version claim contradicted: {0}")]
    VersionMismatch(&'static str),
    /// The fixed version asked for does not exist (draft §7.2 step 6).
    #[error("version does not exist")]
    VersionNotFound,
    /// The fixed version asked for has expired (draft §7.2).
    #[error("version expired")]
    VersionExpired,

    /// A `same` head when the request advertised no tree size (§11.4).
    #[error("`same` tree head without an advertised one")]
    UnadvertisedSame,
    /// An `updated` head no larger than the one advertised (§11.4).
    #[error("tree head is not newer than the advertised one")]
    HeadNotNewer,
    /// A tree of no entries.
    #[error("empty tree head")]
    EmptyTree,
    /// The log's signature for an auditor's configuration does not verify.
    #[error("bad tree head signature (auditor {slot})")]
    BadTreeHeadSignature {
        /// The auditor slot's index in the deployment.
        slot: usize,
    },
    /// No auditor head (or no log signature) for a slot the build carries.
    #[error("no head from auditor {slot}")]
    MissingAuditor {
        /// The auditor slot's index in the deployment.
        slot: usize,
    },
    /// Some slot has no accepted head, and the head carries keys this client
    /// has not accepted: read the live auditor's key and retry.
    #[error("tree head signed for auditor keys this client has not accepted")]
    UnknownAuditorKeys(Vec<[u8; 32]>),
    /// An auditor head whose signature does not verify.
    #[error("bad auditor head signature (auditor {slot})")]
    BadAuditorSignature {
        /// The auditor slot's index in the deployment.
        slot: usize,
    },
    /// An auditor head over more entries than the log's head (§11.3 step 3).
    #[error("auditor head ahead of the log (auditor {slot})")]
    AuditorAheadOfLog {
        /// The auditor slot's index in the deployment.
        slot: usize,
    },
    /// An auditor head timestamped after the log's rightmost entry, or more
    /// than `max_auditor_lag` behind it (§11.3 step 2).
    #[error("auditor head too far behind the log (auditor {slot})")]
    AuditorLag {
        /// The auditor slot's index in the deployment.
        slot: usize,
    },
    /// The previous head's auditor coverage ends before this auditor
    /// instance started (§11.3 step 1).
    #[error("auditor started after the previous head's coverage (auditor {slot})")]
    AuditorStartPosition {
        /// The auditor slot's index in the deployment.
        slot: usize,
    },
    /// The rightmost entry's timestamp is more than `max_ahead` after the
    /// device clock.
    #[error("tree head is {by} ms ahead of the clock")]
    TooFarAhead {
        /// Milliseconds beyond `now`.
        by: u64,
    },
    /// The rightmost entry's timestamp is more than `max_behind` before the
    /// device clock.
    #[error("tree head is {by} ms behind the clock")]
    TooFarBehind {
        /// Milliseconds before `now`.
        by: u64,
    },

    /// A transparency proof anchored at a distinguished entry this client
    /// does not hold as recent (draft §14 step 1).
    #[error("unknown distinguished entry {position}")]
    UnknownDistinguished {
        /// The proof's anchor.
        position: u64,
    },
    /// A provisional proof whose search ends at or before its anchor: a
    /// standard proof could have been made (draft §14.2 step 2).
    #[error("provisional proof does not end after its anchor")]
    ProvisionalNotAfterAnchor,
    /// A proof update anchored at an entry that is not the first
    /// distinguished entry after the search's terminal entry (§14.2 step 2).
    #[error("proof update anchored at the wrong distinguished entry")]
    WrongUpdateAnchor,

    /// The operation needs a verified tree head and the client has none.
    #[error("no verified tree head")]
    NoView,
    /// The operation is for a label this client does not own (no owner
    /// state), or already owns.
    #[error("owner state: {0}")]
    OwnerState(&'static str),
    /// The request and the response (or the state) do not belong together.
    #[error("request does not fit: {0}")]
    RequestMismatch(&'static str),
    /// No auditor slot by that id in the deployment.
    #[error("no such auditor slot")]
    NoSuchSlot,
    /// Client state bytes that do not decode.
    #[error("bad client state: {0}")]
    BadState(&'static str),
}

impl VerifyError {
    /// How the caller acts on this failure.
    pub fn kind(&self) -> FailureKind {
        use VerifyError::*;
        match self {
            Inconsistent(_)
            | TimestampOrder
            | UnadvertisedSame
            | HeadNotNewer
            | EmptyTree
            | BadTreeHeadSignature { .. }
            | MissingAuditor { .. }
            | BadAuditorSignature { .. }
            | AuditorAheadOfLog { .. }
            | AuditorLag { .. }
            | AuditorStartPosition { .. }
            | TooFarAhead { .. }
            | TooFarBehind { .. } => FailureKind::LogFault,
            Malformed(_)
            | Proof(_)
            | BadVrfProof
            | BadCommitment
            | VersionMismatch(_)
            | ProvisionalNotAfterAnchor
            | WrongUpdateAnchor => FailureKind::BadProof,
            VersionNotFound => FailureKind::NotFound,
            VersionExpired => FailureKind::Expired,
            UnknownAuditorKeys(_) => FailureKind::NeedAuditorKey,
            UnknownDistinguished { .. } => FailureKind::NeedDistinguished,
            NoView | OwnerState(_) | RequestMismatch(_) | NoSuchSlot | BadState(_) => {
                FailureKind::Usage
            }
        }
    }
}

impl From<Error> for VerifyError {
    fn from(err: Error) -> Self {
        match err {
            Error::ProofMismatch("log tree disagrees with a retained subtree") => {
                VerifyError::Inconsistent("log tree disagrees with a retained subtree")
            }
            Error::ProofMismatch(what) => VerifyError::Proof(what),
            Error::MalformedProof(what) => VerifyError::Proof(what),
            Error::BadVrfProof => VerifyError::BadVrfProof,
            other => VerifyError::Malformed(other),
        }
    }
}

/// The verifier's result type.
pub type VerifyResult<T> = core::result::Result<T, VerifyError>;
