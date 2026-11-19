// SPDX-License-Identifier: MIT
//! The client's side: verifying every response and transparency proof.
//!
//! Always compiled: this is what the MLS core links. No clock and no
//! randomness: every operation that checks a tree head's age takes the
//! current time as `now`, in milliseconds since the Unix epoch.
//!
//! # Using it
//!
//! A client build holds one [`Verifier`], made from its [`Deployment`], and
//! keeps one [`ClientState`] (plus an [`OwnerState`] per label it owns and a
//! [`ContactMonitor`] per label it monitors), persisted with their
//! `to_bytes` and `from_bytes`. Each operation builds its request from the
//! state, sends it, and hands request and response to the matching
//! `verify_` method:
//!
//! | Draft    | Request built by                    | Verified by                           |
//! |----------|-------------------------------------|---------------------------------------|
//! | §13.1    | the caller (`SearchRequest`)        | [`Verifier::verify_search`]           |
//! | §13.2    | [`ContactMonitor::request`]         | [`Verifier::verify_contact_monitor`]  |
//! | §13.3    | the caller (`OwnerInitRequest`)     | [`Verifier::verify_owner_init`]       |
//! | §13.4    | [`OwnerState::monitor_request`]     | [`Verifier::verify_owner_monitor`]    |
//! | §13.5    | [`OwnerState::update_request`]      | [`Verifier::verify_update`]           |
//! | §13.6    | [`ClientState::distinguished_request`] | [`Verifier::verify_distinguished`] |
//! | §14      | (a peer's transparency proof)       | [`Verifier::verify_credential`]       |
//! | §14.2    | (a peer's or the log's update)      | [`Verifier::verify_credential_update`] |
//!
//! A `verify_` method changes its state arguments only when the response
//! verified in full; on any [`VerifyError`] they are as they were, and the
//! error's [`kind`](VerifyError::kind) says what to do next.
//!
//! # The prover's half
//!
//! A response's `CombinedTreeProof` lists timestamps and prefix proofs in
//! the order the user's algorithm asks for them (§12.3), so this module
//! writes each algorithm once ([`walk`]) over an [`Oracle`]: the verifier
//! reads a response through it, and a log answers it from its own trees
//! through a [`ProofRecorder`] over a [`LogSource`], producing exactly the
//! proof the verifier will read.

pub mod config;
mod credential;
mod distinguished;
pub mod error;
mod head;
mod owner;
mod reader;
pub mod recorder;
mod search;
mod session;
pub mod state;
pub mod walk;

pub use config::{AuditorKey, AuditorSlot, Deployment, Recency};
pub use credential::CredentialResult;
pub use error::{FailureKind, VerifyError, VerifyResult};
pub use owner::{OwnerMonitorResult, UpdateResult};
pub use recorder::{LogSource, OwnerPolicy, ProofRecorder};
pub use search::SearchResult;
pub use state::{
    AcceptedAuditor, ClientState, ContactMonitor, DistinguishedEntry, Insertion, KnownVersion,
    OwnerState, PendingCredential, SlotHead, VersionTable, View,
};
pub use walk::{base_ladder, FixedEnd, Oracle, UpdateClaims, Walk};

use crate::vrf::VrfPublicKey;

/// Verifies responses for one deployment of the log.
#[derive(Debug, Clone)]
pub struct Verifier {
    deployment: Deployment,
    vrf: VrfPublicKey,
}

impl Verifier {
    /// A verifier for `deployment`, whose keys and parameters it checks.
    pub fn new(deployment: Deployment) -> VerifyResult<Self> {
        deployment.validate()?;
        let vrf = deployment.vrf()?;
        Ok(Verifier { deployment, vrf })
    }

    /// The deployment it verifies for.
    pub fn deployment(&self) -> &Deployment {
        &self.deployment
    }
}
