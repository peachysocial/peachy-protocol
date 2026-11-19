// SPDX-License-Identifier: MIT
//! What a client retains between responses, and its encoding.
//!
//! - [`ClientState`]: the shared view (draft §4.2: the last tree size, its
//!   full subtrees and its frontier entries; §13: the last tree head and
//!   auditor heads), the auditor keys accepted at run time, and the recent
//!   distinguished entries with what §14.2.1 says to keep at each.
//! - [`OwnerState`]: one per label the client owns (§8.3, §9).
//! - [`ContactMonitor`]: the monitoring map of a label the client looked up
//!   (§8.2).
//! - [`PendingCredential`]: a verified provisional credential awaiting its
//!   update (§14.2).
//!
//! Every one encodes with `to_bytes` and decodes with `from_bytes`: one
//! format byte, then the TLS presentation-language encoding. The verifier
//! changes these only after a response verified in full (§13).

use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::codec::{b8, decode, encode, v16, v32, v8};
use crate::implicit::frontier;
use crate::suite::{Hash, VrfOutput, PUBLIC_KEY_LEN};
use crate::verify::config::{AuditorKey, Deployment};
use crate::verify::error::{VerifyError, VerifyResult};
use crate::wire::{KeyedAuditorTreeHead, LogEntry, MonitorMapEntry, TreeHead};

/// The format byte every encoding here starts with.
const FORMAT: u8 = 1;

fn to_bytes<T: tls_codec::Serialize>(value: &T) -> VerifyResult<Vec<u8>> {
    let mut out = vec![FORMAT];
    out.extend(encode(value)?);
    Ok(out)
}

fn from_bytes<T: tls_codec::Deserialize>(bytes: &[u8]) -> VerifyResult<T> {
    match bytes.split_first() {
        Some((&FORMAT, rest)) => decode(rest).map_err(|_| VerifyError::BadState("does not decode")),
        Some(_) => Err(VerifyError::BadState("unknown format")),
        None => Err(VerifyError::BadState("empty")),
    }
}

/// One version of a label: its VRF output and, when it exists, its
/// commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct KnownVersion {
    /// The version.
    pub version: u32,
    /// Its VRF output (its prefix tree search key).
    pub vrf_output: VrfOutput,
    /// The commitment to its value, if it exists.
    pub commitment: Option<Hash>,
}

/// The versions of one label a client knows the VRF outputs of, ascending.
#[derive(Debug, Clone, Default, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct VersionTable {
    #[tls_codec(with = "v32")]
    entries: Vec<KnownVersion>,
}

impl VersionTable {
    /// The entry for `version`.
    pub fn get(&self, version: u32) -> Option<&KnownVersion> {
        self.entries
            .binary_search_by_key(&version, |e| e.version)
            .ok()
            .and_then(|i| self.entries.get(i))
    }

    /// Every entry, ascending.
    pub fn entries(&self) -> &[KnownVersion] {
        &self.entries
    }

    /// Adds what a response showed about `version`. A VRF output or
    /// commitment that differs from one already known is refused.
    pub fn insert(
        &mut self,
        version: u32,
        vrf_output: VrfOutput,
        commitment: Option<Hash>,
    ) -> VerifyResult<()> {
        match self.entries.binary_search_by_key(&version, |e| e.version) {
            Ok(i) => {
                let e = &mut self.entries[i];
                if e.vrf_output != vrf_output {
                    return Err(VerifyError::Proof("two VRF outputs for one version"));
                }
                match (e.commitment, commitment) {
                    (Some(a), Some(b)) if a != b => {
                        return Err(VerifyError::Inconsistent("two commitments for one version"))
                    }
                    (None, Some(b)) => e.commitment = Some(b),
                    _ => {}
                }
            }
            Err(i) => self.entries.insert(
                i,
                KnownVersion {
                    version,
                    vrf_output,
                    commitment,
                },
            ),
        }
        Ok(())
    }

    /// Merges another table into this one.
    pub fn merge(&mut self, other: &VersionTable) -> VerifyResult<()> {
        for e in &other.entries {
            self.insert(e.version, e.vrf_output, e.commitment)?;
        }
        Ok(())
    }
}

/// The last head this client verified from one auditor slot.
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct SlotHead {
    /// The auditor key that signed it.
    pub auditor_public_key: [u8; PUBLIC_KEY_LEN],
    /// Its `tree_size`.
    pub tree_size: u64,
    /// Its `timestamp`.
    pub timestamp: u64,
}

/// The view of the log a client holds (draft §4.2, §13).
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct View {
    /// The tree size; what requests advertise as `last`.
    pub tree_size: u64,
    /// The values of its full subtrees, left to right.
    #[tls_codec(with = "v8")]
    pub full_subtrees: Vec<Hash>,
    /// The log entries along its frontier, in frontier order.
    #[tls_codec(with = "v8")]
    pub frontier: Vec<LogEntry>,
    /// The signed tree head, kept as evidence.
    pub tree_head: TreeHead,
    /// The auditor heads that came with it, kept as evidence.
    #[tls_codec(with = "v8")]
    pub auditor_tree_heads: Vec<KeyedAuditorTreeHead>,
    /// Per slot of the deployment, the head that slot was verified with.
    #[tls_codec(with = "v8")]
    pub slots: Vec<SlotHead>,
}

impl View {
    /// The rightmost entry's timestamp.
    pub fn rightmost_timestamp(&self) -> u64 {
        self.frontier.last().map_or(0, |e| e.timestamp)
    }

    /// The frontier entries by position.
    pub(crate) fn frontier_entries(&self) -> Vec<(u64, LogEntry)> {
        frontier(self.tree_size)
            .into_iter()
            .zip(self.frontier.iter().copied())
            .collect()
    }
}

/// An auditor key accepted at run time for a [`AuditorKey::Live`] slot.
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct AcceptedAuditor {
    /// The slot's index in the deployment.
    pub slot: u8,
    /// The instance's key.
    pub public_key: [u8; PUBLIC_KEY_LEN],
    /// The position its auditing starts from (`auditor_start_pos`).
    pub start_position: u64,
}

/// A recent distinguished entry and what draft §14.2.1 says to keep there:
/// the log tree as it stood with this entry rightmost.
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct DistinguishedEntry {
    /// Its position.
    pub position: u64,
    /// Its log entry.
    pub entry: LogEntry,
    /// The full subtrees of the tree of `position + 1` entries.
    #[tls_codec(with = "v8")]
    pub full_subtrees: Vec<Hash>,
    /// The frontier entries of that tree, in frontier order (the last is
    /// this entry).
    #[tls_codec(with = "v8")]
    pub frontier: Vec<LogEntry>,
}

/// Everything a client retains about the log itself.
#[derive(Debug, Clone, Default, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct ClientState {
    /// The verified view, once there is one.
    pub view: Option<View>,
    /// Auditor keys accepted at run time.
    #[tls_codec(with = "v16")]
    pub accepted: Vec<AcceptedAuditor>,
    /// The recent distinguished entries, ascending by position.
    #[tls_codec(with = "v16")]
    pub distinguished: Vec<DistinguishedEntry>,
}

impl ClientState {
    /// A client that has seen nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// What requests advertise as `last`.
    pub fn last(&self) -> Option<u64> {
        self.view.as_ref().map(|v| v.tree_size)
    }

    /// Records an auditor key for a [`AuditorKey::Live`] slot, read by the
    /// caller from the auditor's attested service, with the start position
    /// the log holds for that instance. Heads that slot's other keys signed
    /// are refused.
    pub fn accept_auditor_key(
        &mut self,
        deployment: &Deployment,
        slot: usize,
        public_key: [u8; PUBLIC_KEY_LEN],
        start_position: u64,
    ) -> VerifyResult<()> {
        let s = deployment
            .auditors
            .get(slot)
            .ok_or(VerifyError::NoSuchSlot)?;
        if s.key != AuditorKey::Live {
            return Err(VerifyError::RequestMismatch("the slot's key is pinned"));
        }
        crate::suite::PublicKey::from_bytes(&public_key)?;
        let slot = u8::try_from(slot).map_err(|_| VerifyError::NoSuchSlot)?;
        if let Some(a) = self
            .accepted
            .iter_mut()
            .find(|a| a.slot == slot && a.public_key == public_key)
        {
            a.start_position = start_position;
        } else {
            self.accepted.push(AcceptedAuditor {
                slot,
                public_key,
                start_position,
            });
        }
        Ok(())
    }

    /// The recent distinguished entry at `position`.
    pub fn distinguished_at(&self, position: u64) -> Option<&DistinguishedEntry> {
        self.distinguished.iter().find(|d| d.position == position)
    }

    /// Encodes the state.
    pub fn to_bytes(&self) -> VerifyResult<Vec<u8>> {
        to_bytes(self)
    }

    /// Decodes a state.
    pub fn from_bytes(bytes: &[u8]) -> VerifyResult<Self> {
        from_bytes(bytes)
    }
}

/// An entry where new versions of an owned label were inserted, and the
/// greatest version after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct Insertion {
    /// The entry.
    pub position: u64,
    /// The greatest version there (`None`: the label did not exist).
    pub greatest: Option<u32>,
}

/// A label owner's state (draft §8.3, §9).
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct OwnerState {
    /// The label.
    #[tls_codec(with = "b8")]
    pub label: Vec<u8>,
    /// The rightmost distinguished entry verified as correct: what owner
    /// monitoring requests advertise as `start`.
    pub start: u64,
    /// Ascending by position. The first is the starting entry with the
    /// greatest version there; each later one an update's insertion entry.
    #[tls_codec(with = "v32")]
    pub insertions: Vec<Insertion>,
    /// The VRF outputs and commitments of the label's versions.
    pub versions: VersionTable,
    /// The §8.2 map for updates inserted at non-distinguished entries.
    #[tls_codec(with = "v8")]
    pub contact_map: Vec<MonitorMapEntry>,
}

impl OwnerState {
    /// The greatest version the owner knows of.
    pub fn greatest(&self) -> Option<u32> {
        self.insertions.last().and_then(|i| i.greatest)
    }

    /// Where the greatest version was inserted (or the starting entry).
    pub fn greatest_position(&self) -> u64 {
        self.insertions.last().map_or(self.start, |i| i.position)
    }

    /// The greatest version the owner expects at entry `x`.
    pub fn expected_at(&self, x: u64) -> Option<u32> {
        self.insertions
            .iter()
            .rev()
            .find(|i| i.position <= x)
            .and_then(|i| i.greatest)
    }

    /// Encodes the state.
    pub fn to_bytes(&self) -> VerifyResult<Vec<u8>> {
        to_bytes(self)
    }

    /// Decodes a state.
    pub fn from_bytes(bytes: &[u8]) -> VerifyResult<Self> {
        from_bytes(bytes)
    }
}

/// A looked-up label's monitoring map (draft §8.2). Optional in third-party
/// auditing mode (§8), which the profile runs in.
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct ContactMonitor {
    /// The label.
    #[tls_codec(with = "b8")]
    pub label: Vec<u8>,
    /// Position → version, ascending by position.
    #[tls_codec(with = "v8")]
    pub entries: Vec<MonitorMapEntry>,
    /// The VRF outputs and commitments the monitoring ladders need.
    pub versions: VersionTable,
}

impl ContactMonitor {
    /// Whether nothing is left to monitor.
    pub fn is_done(&self) -> bool {
        self.entries.is_empty()
    }

    /// Encodes the map.
    pub fn to_bytes(&self) -> VerifyResult<Vec<u8>> {
        to_bytes(self)
    }

    /// Decodes a map.
    pub fn from_bytes(bytes: &[u8]) -> VerifyResult<Self> {
        from_bytes(bytes)
    }
}

/// A verified provisional credential, retained until a
/// [`CredentialUpdate`](crate::wire::CredentialUpdate) completes it (draft
/// §14.2). It never touches the [`ClientState`].
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct PendingCredential {
    /// The label.
    #[tls_codec(with = "b8")]
    pub label: Vec<u8>,
    /// The version.
    pub version: u32,
    /// The VRF outputs and commitments from the credential.
    pub versions: VersionTable,
    /// The distinguished entry it was anchored at.
    pub position: u64,
    /// The search's terminal entry (right of `position`).
    pub terminal: u64,
    /// The credential's tree size.
    pub tree_size: u64,
    /// The full subtrees of that tree.
    #[tls_codec(with = "v8")]
    pub full_subtrees: Vec<Hash>,
    /// Its frontier entries, in frontier order.
    #[tls_codec(with = "v8")]
    pub frontier: Vec<LogEntry>,
}

impl PendingCredential {
    /// Encodes the record.
    pub fn to_bytes(&self) -> VerifyResult<Vec<u8>> {
        to_bytes(self)
    }

    /// Decodes a record.
    pub fn from_bytes(bytes: &[u8]) -> VerifyResult<Self> {
        from_bytes(bytes)
    }
}
