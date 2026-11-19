// SPDX-License-Identifier: MIT
//! What a client build carries about the log: its keys, its parameters, and
//! one slot per auditor.
//!
//! The draft's `Configuration` (§11.2) names one auditor. This profile signs
//! one tree head per auditor, each under that auditor's own `Configuration`
//! ([`crate::wire`] explains the extension), so a [`Deployment`] is the
//! shared part plus a list of [`AuditorSlot`]s, and
//! [`Deployment::configuration`] builds the exact `Configuration` a signature
//! was computed under.

use crate::suite::{CipherSuite, PublicKey, PUBLIC_KEY_LEN};
use crate::verify::error::{VerifyError, VerifyResult};
use crate::vrf::VrfPublicKey;
use crate::wire::{Configuration, ModeConfig};

/// The application's definition of a "recent" distinguished entry (draft
/// §10.1). Credentials anchored at an entry that stops being recent expire
/// (draft §14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recency {
    /// Recent while the rightmost entry's timestamp minus the entry's is
    /// less than this many milliseconds.
    Window(u64),
    /// Recent while fewer than this many distinguished entries lie to its
    /// right.
    Count(u32),
}

/// How a client accepts an auditor's key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditorKey {
    /// A long-lived key carried in the build, with the log position its
    /// auditing starts from (`auditor_start_pos`).
    Pinned {
        /// The auditor's Ed25519 public key.
        public_key: [u8; PUBLIC_KEY_LEN],
        /// `auditor_start_pos`.
        start_position: u64,
    },
    /// An auditor whose key is made fresh at each launch and read by the
    /// client at run time from the auditor's attested service. The client
    /// hands each key it read to
    /// [`ClientState::accept_auditor_key`](super::ClientState::accept_auditor_key),
    /// with the start position the auditor logged for that instance.
    Live,
}

/// One auditor the build requires a valid head from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditorSlot {
    /// `max_auditor_lag`, in milliseconds.
    pub max_auditor_lag: u64,
    /// How its key is accepted.
    pub key: AuditorKey,
}

/// The log as a client build knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deployment {
    /// The log's tree head signing key.
    pub signature_public_key: [u8; PUBLIC_KEY_LEN],
    /// The log's VRF public key.
    pub vrf_public_key: [u8; 32],
    /// `max_ahead`, in milliseconds.
    pub max_ahead: u64,
    /// `max_behind`, in milliseconds.
    pub max_behind: u64,
    /// `reasonable_monitoring_window`, in milliseconds.
    pub reasonable_monitoring_window: u64,
    /// `maximum_lifetime`, in milliseconds, if the log prunes.
    pub maximum_lifetime: Option<u64>,
    /// Which distinguished entries are recent.
    pub recency: Recency,
    /// Every auditor the build carries; a head must carry a valid auditor
    /// head for each. At least one, at most 255.
    pub auditors: Vec<AuditorSlot>,
}

impl Deployment {
    /// Checks the keys and parameters once, so verification can rely on them.
    pub fn validate(&self) -> VerifyResult<()> {
        PublicKey::from_bytes(&self.signature_public_key)?;
        VrfPublicKey::from_bytes(&self.vrf_public_key)?;
        if self.auditors.is_empty() || self.auditors.len() > 0xff {
            return Err(VerifyError::RequestMismatch(
                "a deployment carries 1 to 255 auditors",
            ));
        }
        for slot in &self.auditors {
            if let AuditorKey::Pinned { public_key, .. } = &slot.key {
                PublicKey::from_bytes(public_key)?;
            }
        }
        if let Some(lifetime) = self.maximum_lifetime {
            // Draft §7.1: greater than zero and greater than the window.
            if lifetime == 0 || lifetime <= self.reasonable_monitoring_window {
                return Err(VerifyError::RequestMismatch(
                    "maximum lifetime must exceed the monitoring window",
                ));
            }
        }
        Ok(())
    }

    /// The `Configuration` the log signs under for one auditor instance.
    pub fn configuration(
        &self,
        slot: usize,
        auditor_public_key: &[u8],
        auditor_start_pos: u64,
    ) -> VerifyResult<Configuration> {
        let s = self.auditors.get(slot).ok_or(VerifyError::NoSuchSlot)?;
        Ok(Configuration {
            ciphersuite: CipherSuite::Kt128Sha256Ed25519,
            signature_public_key: self.signature_public_key.to_vec(),
            vrf_public_key: self.vrf_public_key.to_vec(),
            mode: ModeConfig::ThirdPartyAuditing {
                max_auditor_lag: s.max_auditor_lag,
                auditor_start_pos,
                auditor_public_key: auditor_public_key.to_vec(),
            },
            max_ahead: self.max_ahead,
            max_behind: self.max_behind,
            reasonable_monitoring_window: self.reasonable_monitoring_window,
            maximum_lifetime: self.maximum_lifetime,
        })
    }

    /// The VRF key, parsed.
    pub(crate) fn vrf(&self) -> VerifyResult<VrfPublicKey> {
        Ok(VrfPublicKey::from_bytes(&self.vrf_public_key)?)
    }
}
