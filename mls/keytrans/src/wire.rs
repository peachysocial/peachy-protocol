// SPDX-License-Identifier: MIT
//! Every structure of draft-ietf-keytrans-protocol-05, in the TLS
//! presentation language (§2.1), with the Peachy profile's one extension.
//!
//! Field names follow the draft; each structure cites its section. Encoding
//! notes that apply throughout:
//!
//! - **Vector lengths count elements** ([`crate::codec`] says why).
//! - **Mode-dependent selects take the third-party auditing branch.** The
//!   Peachy profile runs in `thirdPartyAuditing` mode (spec §5.2), so
//!   `UpdateSuffix` is empty: [`UpdateValue`] is just its value and
//!   [`UpdateInfo`] just its opening. [`Configuration`] itself encodes every
//!   mode, since it is what gets signed. `ManagerUpdateRequest` (§15.1),
//!   which only a third-party manager receives, is not implemented.
//! - **The response to a search depends on its request.** `SearchResponse`
//!   carries `version` only when the request named none (§13.1), so it has
//!   its own [`SearchResponse::encode`] and [`SearchResponse::decode`].
//!
//! # The profile's extension: one signature per auditor
//!
//! The draft's `Configuration` names one auditor and its `TreeHead` carries
//! one signature. The profile carries a list of auditors (spec §5.2), and a
//! client must see a valid auditor head for every auditor its build carries.
//! Each auditor gets its own `Configuration`, the draft's structure with that
//! auditor's key in `auditor_public_key`, and the log signs one
//! `TreeHeadTBS` per auditor. So:
//!
//! - [`TreeHead`] carries a list of [`TreeHeadSignature`]s, each naming the
//!   auditor key whose configuration it was computed under, where the draft
//!   has one `signature`;
//! - [`FullTreeHead`]'s `updated` case carries a list of
//!   [`KeyedAuditorTreeHead`]s where the draft has one `AuditorTreeHead`.
//!
//! Every signed structure ([`TreeHeadTbs`], [`AuditorTreeHeadTbs`]) is the
//! draft's, byte for byte. A build that carries a new auditor only needs the
//! log to add one more signature; builds without it are unaffected.

use std::io::{Read, Write};

use tls_codec::{Deserialize, Serialize, Size, TlsDeserialize, TlsSerialize, TlsSize};

use crate::codec::{b16, b32, b8, v16, v8};
use crate::error::{Error, Result};
use crate::suite::{CipherSuite, Hash, Opening, VrfOutput, VrfProof};

/// `opaque HashValue[Hash.Nh]` (§12.1).
pub type HashValue = Hash;

// ---------------------------------------------------------------------------
// §11.2 Configuration and tree heads
// ---------------------------------------------------------------------------

/// `enum DeploymentMode` (§11.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub enum DeploymentMode {
    /// `contactMonitoring(1)`.
    ContactMonitoring = 1,
    /// `thirdPartyManagement(2)`.
    ThirdPartyManagement = 2,
    /// `thirdPartyAuditing(3)`: the profile's mode.
    ThirdPartyAuditing = 3,
}

/// The mode-dependent part of a [`Configuration`] (§11.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModeConfig {
    /// `contactMonitoring`, with the operator's leaf signing key.
    ContactMonitoring {
        /// `opaque leaf_public_key<0..2^16-1>`.
        leaf_public_key: Vec<u8>,
    },
    /// `thirdPartyManagement`, with the operator's leaf signing key.
    ThirdPartyManagement {
        /// `opaque leaf_public_key<0..2^16-1>`.
        leaf_public_key: Vec<u8>,
    },
    /// `thirdPartyAuditing`.
    ThirdPartyAuditing {
        /// `uint64 max_auditor_lag`, in milliseconds.
        max_auditor_lag: u64,
        /// `uint64 auditor_start_pos`.
        auditor_start_pos: u64,
        /// `opaque auditor_public_key<0..2^16-1>`.
        auditor_public_key: Vec<u8>,
    },
}

impl ModeConfig {
    /// The [`DeploymentMode`] this branch encodes as.
    pub fn mode(&self) -> DeploymentMode {
        match self {
            ModeConfig::ContactMonitoring { .. } => DeploymentMode::ContactMonitoring,
            ModeConfig::ThirdPartyManagement { .. } => DeploymentMode::ThirdPartyManagement,
            ModeConfig::ThirdPartyAuditing { .. } => DeploymentMode::ThirdPartyAuditing,
        }
    }
}

/// `struct Configuration` (§11.2): the log's long-term configuration, signed
/// into every tree head. Durations are milliseconds.
///
/// The draft's field order puts `mode` second and its select after the two
/// keys; this type keeps the select's data in [`ModeConfig`] and encodes in
/// the draft's order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Configuration {
    /// `CipherSuite ciphersuite`.
    pub ciphersuite: CipherSuite,
    /// `opaque signature_public_key<0..2^16-1>`: the log's tree head key.
    pub signature_public_key: Vec<u8>,
    /// `opaque vrf_public_key<0..2^16-1>`.
    pub vrf_public_key: Vec<u8>,
    /// `DeploymentMode mode` and its select.
    pub mode: ModeConfig,
    /// `uint64 max_ahead`.
    pub max_ahead: u64,
    /// `uint64 max_behind`.
    pub max_behind: u64,
    /// `uint64 reasonable_monitoring_window`.
    pub reasonable_monitoring_window: u64,
    /// `optional<uint64> maximum_lifetime`.
    pub maximum_lifetime: Option<u64>,
}

impl Size for Configuration {
    fn tls_serialized_len(&self) -> usize {
        let mode_len = match &self.mode {
            ModeConfig::ContactMonitoring { leaf_public_key }
            | ModeConfig::ThirdPartyManagement { leaf_public_key } => {
                b16::tls_serialized_len(leaf_public_key)
            }
            ModeConfig::ThirdPartyAuditing {
                auditor_public_key, ..
            } => 16 + b16::tls_serialized_len(auditor_public_key),
        };
        2 + 1
            + b16::tls_serialized_len(&self.signature_public_key)
            + b16::tls_serialized_len(&self.vrf_public_key)
            + mode_len
            + 24
            + self.maximum_lifetime.tls_serialized_len()
    }
}

impl Serialize for Configuration {
    fn tls_serialize<W: Write>(
        &self,
        writer: &mut W,
    ) -> core::result::Result<usize, tls_codec::Error> {
        let mut n = self.ciphersuite.tls_serialize(writer)?;
        n += self.mode.mode().tls_serialize(writer)?;
        n += b16::tls_serialize(&self.signature_public_key, writer)?;
        n += b16::tls_serialize(&self.vrf_public_key, writer)?;
        match &self.mode {
            ModeConfig::ContactMonitoring { leaf_public_key }
            | ModeConfig::ThirdPartyManagement { leaf_public_key } => {
                n += b16::tls_serialize(leaf_public_key, writer)?;
            }
            ModeConfig::ThirdPartyAuditing {
                max_auditor_lag,
                auditor_start_pos,
                auditor_public_key,
            } => {
                n += max_auditor_lag.tls_serialize(writer)?;
                n += auditor_start_pos.tls_serialize(writer)?;
                n += b16::tls_serialize(auditor_public_key, writer)?;
            }
        }
        n += self.max_ahead.tls_serialize(writer)?;
        n += self.max_behind.tls_serialize(writer)?;
        n += self.reasonable_monitoring_window.tls_serialize(writer)?;
        n += self.maximum_lifetime.tls_serialize(writer)?;
        Ok(n)
    }
}

impl Deserialize for Configuration {
    fn tls_deserialize<R: Read>(reader: &mut R) -> core::result::Result<Self, tls_codec::Error> {
        let ciphersuite = CipherSuite::tls_deserialize(reader)?;
        let mode = DeploymentMode::tls_deserialize(reader)?;
        let signature_public_key = b16::tls_deserialize(reader)?;
        let vrf_public_key = b16::tls_deserialize(reader)?;
        let mode = match mode {
            DeploymentMode::ContactMonitoring => ModeConfig::ContactMonitoring {
                leaf_public_key: b16::tls_deserialize(reader)?,
            },
            DeploymentMode::ThirdPartyManagement => ModeConfig::ThirdPartyManagement {
                leaf_public_key: b16::tls_deserialize(reader)?,
            },
            DeploymentMode::ThirdPartyAuditing => ModeConfig::ThirdPartyAuditing {
                max_auditor_lag: u64::tls_deserialize(reader)?,
                auditor_start_pos: u64::tls_deserialize(reader)?,
                auditor_public_key: b16::tls_deserialize(reader)?,
            },
        };
        Ok(Configuration {
            ciphersuite,
            signature_public_key,
            vrf_public_key,
            mode,
            max_ahead: u64::tls_deserialize(reader)?,
            max_behind: u64::tls_deserialize(reader)?,
            reasonable_monitoring_window: u64::tls_deserialize(reader)?,
            maximum_lifetime: Option::<u64>::tls_deserialize(reader)?,
        })
    }
}

/// `struct TreeHeadTBS` (§11.2): what the log signs.
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct TreeHeadTbs {
    /// `Configuration config`.
    pub config: Configuration,
    /// `uint64 tree_size`.
    pub tree_size: u64,
    /// `opaque root[Hash.Nh]`.
    pub root: HashValue,
}

/// One of the log's signatures in a [`TreeHead`] (profile extension): the
/// signature over the `TreeHeadTBS` whose configuration names
/// `auditor_public_key`.
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct TreeHeadSignature {
    /// The auditor key of the configuration this signature was computed under.
    #[tls_codec(with = "b16")]
    pub auditor_public_key: Vec<u8>,
    /// `opaque signature<0..2^16-1>`.
    #[tls_codec(with = "b16")]
    pub signature: Vec<u8>,
}

/// `struct TreeHead` (§11.2), with one signature per auditor (profile).
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct TreeHead {
    /// `uint64 tree_size`: the number of log entries.
    pub tree_size: u64,
    /// Where the draft has one `signature`.
    #[tls_codec(with = "v8")]
    pub signatures: Vec<TreeHeadSignature>,
}

// ---------------------------------------------------------------------------
// §11.3 Auditor tree heads, §11.4 full tree heads
// ---------------------------------------------------------------------------

/// `struct AuditorTreeHead` (§11.3).
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct AuditorTreeHead {
    /// `uint64 timestamp`, milliseconds since the Unix epoch.
    pub timestamp: u64,
    /// `uint64 tree_size`.
    pub tree_size: u64,
    /// `opaque signature<0..2^16-1>`.
    #[tls_codec(with = "b16")]
    pub signature: Vec<u8>,
}

/// `struct AuditorTreeHeadTBS` (§11.3): what an auditor signs.
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct AuditorTreeHeadTbs {
    /// `Configuration config`, naming this auditor's key.
    pub config: Configuration,
    /// `uint64 timestamp`.
    pub timestamp: u64,
    /// `uint64 tree_size`.
    pub tree_size: u64,
    /// `opaque root[Hash.Nh]`: the log tree's root at `tree_size`.
    pub root: HashValue,
}

/// An [`AuditorTreeHead`] and the auditor it is from (profile extension).
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct KeyedAuditorTreeHead {
    /// The auditor's public key.
    #[tls_codec(with = "b16")]
    pub auditor_public_key: Vec<u8>,
    /// Its head.
    pub auditor_tree_head: AuditorTreeHead,
}

/// `enum FullTreeHeadType` (§11.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub enum FullTreeHeadType {
    /// `same(1)`.
    Same = 1,
    /// `updated(2)`.
    Updated = 2,
}

/// `struct FullTreeHead` (§11.4), the `head_type` and its select as one enum,
/// with one auditor head per auditor (profile).
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub enum FullTreeHead {
    /// `same`: the head the user advertised still stands.
    #[tls_codec(discriminant = 1)]
    Same,
    /// `updated`: a newer head.
    #[tls_codec(discriminant = 2)]
    Updated {
        /// `TreeHead tree_head`.
        tree_head: TreeHead,
        /// Where the draft has one `AuditorTreeHead auditor_tree_head`.
        #[tls_codec(with = "v8")]
        auditor_tree_heads: Vec<KeyedAuditorTreeHead>,
    },
}

impl FullTreeHead {
    /// The `head_type` this value encodes with.
    pub fn head_type(&self) -> FullTreeHeadType {
        match self {
            FullTreeHead::Same => FullTreeHeadType::Same,
            FullTreeHead::Updated { .. } => FullTreeHeadType::Updated,
        }
    }
}

// ---------------------------------------------------------------------------
// §11.5 to §11.8 values, commitments, VRF input, log entries
// ---------------------------------------------------------------------------

/// `struct UpdateValue` (§11.5) in third-party auditing mode, where
/// `UpdateSuffix` is empty.
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct UpdateValue {
    /// `opaque value<0..2^32-1>`.
    #[tls_codec(with = "b32")]
    pub value: Vec<u8>,
}

/// `struct UpdateTBS` (§11.5): signed by a service operator in third-party
/// management mode only. Defined for completeness; the profile does not use
/// it.
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct UpdateTbs {
    /// `Configuration config`.
    pub config: Configuration,
    /// `opaque label<0..2^8-1>`.
    #[tls_codec(with = "b8")]
    pub label: Vec<u8>,
    /// `uint32 version`.
    pub version: u32,
    /// `opaque value<0..2^32-1>`.
    #[tls_codec(with = "b32")]
    pub value: Vec<u8>,
}

/// `struct CommitmentValue` (§11.6): what a commitment is the HMAC of.
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct CommitmentValue {
    /// `opaque opening[Nc]`.
    pub opening: Opening,
    /// `opaque label<0..2^8-1>`.
    #[tls_codec(with = "b8")]
    pub label: Vec<u8>,
    /// `uint32 version`.
    pub version: u32,
    /// `UpdateValue update`.
    pub update: UpdateValue,
}

/// `struct VrfInput` (§11.7): the VRF's input for a label's version.
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct VrfInput {
    /// `opaque label<0..2^8-1>`.
    #[tls_codec(with = "b8")]
    pub label: Vec<u8>,
    /// `uint32 version`.
    pub version: u32,
}

/// `struct LogEntry` (§11.8): a log tree leaf's value is its hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct LogEntry {
    /// `uint64 timestamp`, milliseconds since the Unix epoch.
    pub timestamp: u64,
    /// `opaque prefix_tree[Hash.Nh]`: the prefix tree's root after the entry.
    pub prefix_tree: HashValue,
}

// ---------------------------------------------------------------------------
// §12 tree proofs
// ---------------------------------------------------------------------------

/// `struct InclusionProof` (§12.1): a batch of log tree inclusion and
/// consistency proofs, heads of balanced subtrees in left-to-right order.
/// [`crate::log_tree`] computes which subtrees they are.
#[derive(Debug, Clone, Default, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct InclusionProof {
    /// `HashValue elements<0..2^16-1>`.
    #[tls_codec(with = "v16")]
    pub elements: Vec<HashValue>,
}

/// `enum PrefixSearchResultType` (§12.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub enum PrefixSearchResultType {
    /// `inclusion(1)`.
    Inclusion = 1,
    /// `nonInclusionLeaf(2)`.
    NonInclusionLeaf = 2,
    /// `nonInclusionParent(3)`.
    NonInclusionParent = 3,
}

/// `struct PrefixLeaf` (§12.2): a prefix tree leaf's contents.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct PrefixLeaf {
    /// `opaque vrf_output[VRF.Nh]`.
    pub vrf_output: VrfOutput,
    /// `opaque commitment[Hash.Nh]`.
    pub commitment: HashValue,
}

/// The `result_type` of a [`PrefixSearchResult`] and its select.
#[derive(Debug, Clone, Copy, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub enum PrefixSearchOutcome {
    /// `inclusion`: the search ended at the leaf for the key searched for.
    #[tls_codec(discriminant = 1)]
    Inclusion,
    /// `nonInclusionLeaf`: it ended at the leaf of another key.
    #[tls_codec(discriminant = 2)]
    NonInclusionLeaf {
        /// `PrefixLeaf leaf`.
        leaf: PrefixLeaf,
    },
    /// `nonInclusionParent`: it ended where a parent lacks the child.
    #[tls_codec(discriminant = 3)]
    NonInclusionParent,
}

impl PrefixSearchOutcome {
    /// The `result_type` this outcome encodes with.
    pub fn result_type(&self) -> PrefixSearchResultType {
        match self {
            PrefixSearchOutcome::Inclusion => PrefixSearchResultType::Inclusion,
            PrefixSearchOutcome::NonInclusionLeaf { .. } => {
                PrefixSearchResultType::NonInclusionLeaf
            }
            PrefixSearchOutcome::NonInclusionParent => PrefixSearchResultType::NonInclusionParent,
        }
    }
}

/// `struct PrefixSearchResult` (§12.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct PrefixSearchResult {
    /// `result_type` and, for `nonInclusionLeaf`, the leaf.
    pub outcome: PrefixSearchOutcome,
    /// `uint8 depth` of the search's terminal node; [`crate::prefix_proof`]
    /// says how it is read.
    pub depth: u8,
}

/// `struct PrefixProof` (§12.2): a batch search proof in one prefix tree.
#[derive(Debug, Clone, Default, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct PrefixProof {
    /// `PrefixSearchResult results<0..2^8-1>`, in the order searched.
    #[tls_codec(with = "v8")]
    pub results: Vec<PrefixSearchResult>,
    /// `HashValue elements<0..2^16-1>`, copath values left to right, all
    /// zeros for a missing node.
    #[tls_codec(with = "v16")]
    pub elements: Vec<HashValue>,
}

/// `struct CombinedTreeProof` (§12.3).
#[derive(Debug, Clone, Default, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct CombinedTreeProof {
    /// `uint64 timestamps<0..2^8-1>`.
    #[tls_codec(with = "v8")]
    pub timestamps: Vec<u64>,
    /// `PrefixProof prefix_proofs<0..2^8-1>`.
    #[tls_codec(with = "v8")]
    pub prefix_proofs: Vec<PrefixProof>,
    /// `HashValue prefix_roots<0..2^8-1>`.
    #[tls_codec(with = "v8")]
    pub prefix_roots: Vec<HashValue>,
    /// `InclusionProof inclusion`.
    pub inclusion: InclusionProof,
}

// ---------------------------------------------------------------------------
// §13.1 search
// ---------------------------------------------------------------------------

/// `struct SearchRequest` (§13.1).
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct SearchRequest {
    /// `optional<uint64> last`: the tree size of the last head verified.
    pub last: Option<u64>,
    /// `opaque label<0..2^8-1>`.
    #[tls_codec(with = "b8")]
    pub label: Vec<u8>,
    /// `optional<uint32> version`: absent for the greatest version.
    pub version: Option<u32>,
}

/// `struct BinaryLadderStep` (§13.1).
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct BinaryLadderStep {
    /// `opaque proof[VRF.Np]`.
    pub proof: VrfProof,
    /// `optional<HashValue> commitment`.
    pub commitment: Option<HashValue>,
}

/// `struct SearchResponse` (§13.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchResponse {
    /// `FullTreeHead full_tree_head`.
    pub full_tree_head: FullTreeHead,
    /// `uint32 version`: present exactly when the request named no version.
    pub version: Option<u32>,
    /// `opaque opening[Nc]`.
    pub opening: Opening,
    /// `UpdateValue value`.
    pub value: UpdateValue,
    /// `BinaryLadderStep binary_ladder<0..2^8-1>`.
    pub binary_ladder: Vec<BinaryLadderStep>,
    /// `CombinedTreeProof search`.
    pub search: CombinedTreeProof,
}

impl SearchResponse {
    /// Encodes the response; `version` is written when present.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut write = || -> core::result::Result<(), tls_codec::Error> {
            self.full_tree_head.tls_serialize(&mut out)?;
            if let Some(v) = self.version {
                v.tls_serialize(&mut out)?;
            }
            self.opening.tls_serialize(&mut out)?;
            self.value.tls_serialize(&mut out)?;
            v8::tls_serialize(&self.binary_ladder, &mut out)?;
            self.search.tls_serialize(&mut out)?;
            Ok(())
        };
        write().map_err(|_| Error::Encode("search response does not fit its length prefixes"))?;
        Ok(out)
    }

    /// Decodes a response to a request that did (`version_requested`) or did
    /// not name a version.
    pub fn decode(bytes: &[u8], version_requested: bool) -> Result<Self> {
        let mut r = bytes;
        let full_tree_head = FullTreeHead::tls_deserialize(&mut r)?;
        let version = if version_requested {
            None
        } else {
            Some(u32::tls_deserialize(&mut r)?)
        };
        let out = SearchResponse {
            full_tree_head,
            version,
            opening: Opening::tls_deserialize(&mut r)?,
            value: UpdateValue::tls_deserialize(&mut r)?,
            binary_ladder: v8::tls_deserialize(&mut r)?,
            search: CombinedTreeProof::tls_deserialize(&mut r)?,
        };
        if !r.is_empty() {
            return Err(Error::Decode("trailing bytes".into()));
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// §13.2 to §13.4 monitoring
// ---------------------------------------------------------------------------

/// `struct MonitorMapEntry` (§13.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct MonitorMapEntry {
    /// `uint64 position`.
    pub position: u64,
    /// `uint32 version`.
    pub version: u32,
}

/// `struct ContactMonitorRequest` (§13.2).
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct ContactMonitorRequest {
    /// `optional<uint64> last`.
    pub last: Option<u64>,
    /// `opaque label<0..2^8-1>`.
    #[tls_codec(with = "b8")]
    pub label: Vec<u8>,
    /// `MonitorMapEntry entries<0..2^8-1>`.
    #[tls_codec(with = "v8")]
    pub entries: Vec<MonitorMapEntry>,
}

/// `struct ContactMonitorResponse` (§13.2).
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct ContactMonitorResponse {
    /// `FullTreeHead full_tree_head`.
    pub full_tree_head: FullTreeHead,
    /// `CombinedTreeProof monitor`.
    pub monitor: CombinedTreeProof,
}

/// `struct OwnerInitRequest` (§13.3).
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct OwnerInitRequest {
    /// `optional<uint64> last`.
    pub last: Option<u64>,
    /// `opaque label<0..2^8-1>`.
    #[tls_codec(with = "b8")]
    pub label: Vec<u8>,
    /// `uint64 start`: an unexpired, distinguished log entry.
    pub start: u64,
}

/// `struct OwnerInitResponse` (§13.3).
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct OwnerInitResponse {
    /// `FullTreeHead full_tree_head`.
    pub full_tree_head: FullTreeHead,
    /// `uint32 greatest_versions<0..2^8-1>`.
    #[tls_codec(with = "v8")]
    pub greatest_versions: Vec<u32>,
    /// `BinaryLadderStep binary_ladder<0..2^16-1>`.
    #[tls_codec(with = "v16")]
    pub binary_ladder: Vec<BinaryLadderStep>,
    /// `CombinedTreeProof init`.
    pub init: CombinedTreeProof,
}

/// `struct OwnerMonitorRequest` (§13.4).
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct OwnerMonitorRequest {
    /// `optional<uint64> last`.
    pub last: Option<u64>,
    /// `opaque label<0..2^8-1>`.
    #[tls_codec(with = "b8")]
    pub label: Vec<u8>,
    /// `MonitorMapEntry entries<0..2^8-1>`.
    #[tls_codec(with = "v8")]
    pub entries: Vec<MonitorMapEntry>,
    /// `uint64 start`: the rightmost distinguished entry verified.
    pub start: u64,
    /// `optional<uint32> greatest_version`.
    pub greatest_version: Option<u32>,
}

/// `struct OwnerMonitorResponse` (§13.4).
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct OwnerMonitorResponse {
    /// `FullTreeHead full_tree_head`.
    pub full_tree_head: FullTreeHead,
    /// `CombinedTreeProof monitor`.
    pub monitor: CombinedTreeProof,
}

// ---------------------------------------------------------------------------
// §13.5 updates, §13.6 distinguished heads
// ---------------------------------------------------------------------------

/// `struct LabelValue` (§13.5).
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct LabelValue {
    /// `opaque value<0..2^32-1>`.
    #[tls_codec(with = "b32")]
    pub value: Vec<u8>,
}

/// `struct UpdateRequest` (§13.5).
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct UpdateRequest {
    /// `optional<uint64> last`.
    pub last: Option<u64>,
    /// `opaque label<0..2^8-1>`.
    #[tls_codec(with = "b8")]
    pub label: Vec<u8>,
    /// `optional<uint32> greatest_version`.
    pub greatest_version: Option<u32>,
    /// `LabelValue values<0..2^8-1>`.
    #[tls_codec(with = "v8")]
    pub values: Vec<LabelValue>,
}

/// `struct UpdateInfo` (§13.5) in third-party auditing mode, where the
/// suffix is empty.
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct UpdateInfo {
    /// `opaque opening[Nc]`.
    pub opening: Opening,
}

/// `struct UpdateResponse` (§13.5).
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct UpdateResponse {
    /// `FullTreeHead full_tree_head`.
    pub full_tree_head: FullTreeHead,
    /// `uint64 position`.
    pub position: u64,
    /// `LabelValue values<0..2^8-1>`.
    #[tls_codec(with = "v8")]
    pub values: Vec<LabelValue>,
    /// `UpdateInfo info<0..2^8-1>`.
    #[tls_codec(with = "v8")]
    pub info: Vec<UpdateInfo>,
    /// `BinaryLadderStep binary_ladder<0..2^8-1>`.
    #[tls_codec(with = "v8")]
    pub binary_ladder: Vec<BinaryLadderStep>,
    /// `CombinedTreeProof update`.
    pub update: CombinedTreeProof,
}

/// `struct DistinguishedRequest` (§13.6).
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct DistinguishedRequest {
    /// `optional<uint64> last`.
    pub last: Option<u64>,
    /// `optional<uint64> stop`.
    pub stop: Option<u64>,
}

/// `struct DistinguishedResponse` (§13.6).
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct DistinguishedResponse {
    /// `FullTreeHead full_tree_head`.
    pub full_tree_head: FullTreeHead,
    /// `CombinedTreeProof distinguished`.
    pub distinguished: CombinedTreeProof,
}

// ---------------------------------------------------------------------------
// §14 credentials (the spec's "transparency proofs")
// ---------------------------------------------------------------------------

/// `enum CredentialType` (§14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub enum CredentialType {
    /// `standard(1)`.
    Standard = 1,
    /// `provisional(2)`.
    Provisional = 2,
}

/// The `credential_type` of a [`Credential`] and its select.
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub enum CredentialBody {
    /// `standard`: the version is in the distinguished entry at `position`.
    #[tls_codec(discriminant = 1)]
    Standard {
        /// `PrefixProof distinguished`.
        distinguished: PrefixProof,
    },
    /// `provisional`: not yet in a distinguished entry.
    #[tls_codec(discriminant = 2)]
    Provisional {
        /// `TreeHead tree_head` (one signature per auditor, profile).
        tree_head: TreeHead,
        /// `CombinedTreeProof search`.
        search: CombinedTreeProof,
    },
}

impl CredentialBody {
    /// The `credential_type` this body encodes with.
    pub fn credential_type(&self) -> CredentialType {
        match self {
            CredentialBody::Standard { .. } => CredentialType::Standard,
            CredentialBody::Provisional { .. } => CredentialType::Provisional,
        }
    }
}

/// `struct Credential` (§14): what the spec calls a transparency proof.
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct Credential {
    /// `opaque label<0..2^8-1>`.
    #[tls_codec(with = "b8")]
    pub label: Vec<u8>,
    /// `uint32 version`.
    pub version: u32,
    /// `opaque opening[Nc]`.
    pub opening: Opening,
    /// `UpdateValue value`.
    pub value: UpdateValue,
    /// `BinaryLadderStep binary_ladder<0..2^8-1>`.
    #[tls_codec(with = "v8")]
    pub binary_ladder: Vec<BinaryLadderStep>,
    /// `uint64 position`: the distinguished entry it is anchored at.
    pub position: u64,
    /// `CredentialType credential_type` and its select.
    pub body: CredentialBody,
}

/// `struct CredentialUpdate` (§14.2).
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct CredentialUpdate {
    /// `uint64 position`.
    pub position: u64,
    /// `CombinedTreeProof monitor`.
    pub monitor: CombinedTreeProof,
}

// ---------------------------------------------------------------------------
// §15.2 auditing
// ---------------------------------------------------------------------------

/// `struct AuditorUpdate` (§15.2): one log entry, as an auditor sees it.
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct AuditorUpdate {
    /// `uint64 timestamp`.
    pub timestamp: u64,
    /// `PrefixLeaf added<0..2^16-1>`.
    #[tls_codec(with = "v16")]
    pub added: Vec<PrefixLeaf>,
    /// `PrefixLeaf removed<0..2^16-1>`.
    #[tls_codec(with = "v16")]
    pub removed: Vec<PrefixLeaf>,
    /// `PrefixProof proof`, in the previous entry's prefix tree.
    pub proof: PrefixProof,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{decode, encode};

    fn rt<T>(value: &T) -> Vec<u8>
    where
        T: Serialize + Deserialize + PartialEq + core::fmt::Debug,
    {
        let bytes = encode(value).unwrap();
        assert_eq!(&decode::<T>(&bytes).unwrap(), value);
        assert_eq!(bytes.len(), value.tls_serialized_len());
        // Every proper prefix fails to decode.
        for cut in 0..bytes.len() {
            assert!(decode::<T>(&bytes[..cut]).is_err(), "prefix {cut}");
        }
        bytes
    }

    fn h(b: u8) -> Hash {
        [b; 32]
    }

    fn config() -> Configuration {
        Configuration {
            ciphersuite: CipherSuite::Kt128Sha256Ed25519,
            signature_public_key: vec![0x11; 2],
            vrf_public_key: vec![0x22; 3],
            mode: ModeConfig::ThirdPartyAuditing {
                max_auditor_lag: 7,
                auditor_start_pos: 1,
                auditor_public_key: vec![0x33],
            },
            max_ahead: 0x0100,
            max_behind: 0x0200,
            reasonable_monitoring_window: 86_400_000,
            maximum_lifetime: None,
        }
    }

    #[test]
    fn configuration_vector() {
        let bytes = rt(&config());
        let expected = concat!(
            "0002",             // ciphersuite KT_128_SHA256_Ed25519
            "03",               // thirdPartyAuditing
            "00021111",         // signature_public_key<0..2^16-1>
            "0003222222",       // vrf_public_key
            "0000000000000007", // max_auditor_lag
            "0000000000000001", // auditor_start_pos
            "000133",           // auditor_public_key
            "0000000000000100", // max_ahead
            "0000000000000200", // max_behind
            "0000000005265c00", // reasonable_monitoring_window: 1 day in ms
            "00",               // maximum_lifetime absent
        );
        assert_eq!(hex::encode(bytes), expected);
    }

    #[test]
    fn configuration_other_modes_and_lifetime() {
        let mut c = config();
        c.mode = ModeConfig::ContactMonitoring {
            leaf_public_key: vec![0x44],
        };
        c.maximum_lifetime = Some(5);
        let bytes = rt(&c);
        assert_eq!(
            hex::encode(bytes),
            concat!(
                "0002",
                "01",
                "00021111",
                "0003222222",
                "000144",
                "0000000000000100",
                "0000000000000200",
                "0000000005265c00",
                "010000000000000005",
            )
        );
        c.mode = ModeConfig::ThirdPartyManagement {
            leaf_public_key: vec![],
        };
        let bytes = rt(&c);
        assert_eq!(bytes[2], 0x02);
        // Mode 0 (reserved) and 4 are refused.
        let mut bad = bytes.clone();
        bad[2] = 0;
        assert!(decode::<Configuration>(&bad).is_err());
        bad[2] = 4;
        assert!(decode::<Configuration>(&bad).is_err());
    }

    #[test]
    fn tree_head_tbs_and_signatures() {
        let tbs = TreeHeadTbs {
            config: config(),
            tree_size: 9,
            root: h(0xab),
        };
        let bytes = rt(&tbs);
        let cfg = encode(&config()).unwrap();
        assert_eq!(bytes[..cfg.len()], cfg[..]);
        assert_eq!(
            hex::encode(&bytes[cfg.len()..cfg.len() + 8]),
            "0000000000000009"
        );
        assert_eq!(bytes[cfg.len() + 8..], h(0xab)[..]);

        let head = TreeHead {
            tree_size: 9,
            signatures: vec![TreeHeadSignature {
                auditor_public_key: vec![0x33],
                signature: vec![0x55, 0x66],
            }],
        };
        assert_eq!(
            hex::encode(rt(&head)),
            concat!("0000000000000009", "01", "000133", "00025566")
        );

        let ath = AuditorTreeHeadTbs {
            config: config(),
            timestamp: 3,
            tree_size: 4,
            root: h(1),
        };
        rt(&ath);
    }

    #[test]
    fn full_tree_head_vectors() {
        assert_eq!(hex::encode(rt(&FullTreeHead::Same)), "01");
        let full = FullTreeHead::Updated {
            tree_head: TreeHead {
                tree_size: 2,
                signatures: vec![],
            },
            auditor_tree_heads: vec![KeyedAuditorTreeHead {
                auditor_public_key: vec![0x33],
                auditor_tree_head: AuditorTreeHead {
                    timestamp: 1,
                    tree_size: 2,
                    signature: vec![0x77],
                },
            }],
        };
        assert_eq!(full.head_type(), FullTreeHeadType::Updated);
        assert_eq!(
            hex::encode(rt(&full)),
            concat!(
                "02", // updated
                "0000000000000002",
                "00", // tree_head, no signatures
                "01",
                "000133", // one auditor head
                "0000000000000001",
                "0000000000000002",
                "000177",
            )
        );
        assert!(decode::<FullTreeHead>(&[0x00]).is_err());
        assert!(decode::<FullTreeHead>(&[0x03]).is_err());
    }

    #[test]
    fn commitment_value_and_vrf_input_vectors() {
        let cv = CommitmentValue {
            opening: [0x0f; 16],
            label: b"ab".to_vec(),
            version: 1,
            update: UpdateValue { value: vec![0xcc] },
        };
        assert_eq!(
            hex::encode(rt(&cv)),
            concat!(
                "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f", // opening[16]
                "026162",                           // label<0..2^8-1>
                "00000001",                         // version
                "00000001cc",                       // value<0..2^32-1>
            )
        );
        let vi = VrfInput {
            label: vec![],
            version: 0xffff_ffff,
        };
        assert_eq!(hex::encode(rt(&vi)), "00ffffffff");
        let le = LogEntry {
            timestamp: 0x0102,
            prefix_tree: h(0),
        };
        assert_eq!(
            hex::encode(rt(&le)),
            format!("0000000000000102{}", "00".repeat(32))
        );
        let tbs = UpdateTbs {
            config: config(),
            label: vec![1],
            version: 2,
            value: vec![],
        };
        rt(&tbs);
    }

    #[test]
    fn prefix_proof_vectors() {
        let leaf = PrefixLeaf {
            vrf_output: h(0x01),
            commitment: h(0x02),
        };
        let proof = PrefixProof {
            results: vec![
                PrefixSearchResult {
                    outcome: PrefixSearchOutcome::Inclusion,
                    depth: 3,
                },
                PrefixSearchResult {
                    outcome: PrefixSearchOutcome::NonInclusionLeaf { leaf },
                    depth: 4,
                },
                PrefixSearchResult {
                    outcome: PrefixSearchOutcome::NonInclusionParent,
                    depth: 5,
                },
            ],
            elements: vec![h(0x09)],
        };
        assert_eq!(
            proof.results[1].outcome.result_type(),
            PrefixSearchResultType::NonInclusionLeaf
        );
        let expected = [
            "03".to_string(),                                      // three results
            "0103".to_string(),                                    // inclusion, depth 3
            format!("02{}{}04", "01".repeat(32), "02".repeat(32)), // leaf, depth 4
            "0305".to_string(),                                    // nonInclusionParent, depth 5
            format!("0001{}", "09".repeat(32)),                    // one element
        ]
        .concat();
        assert_eq!(hex::encode(rt(&proof)), expected);
        assert!(decode::<PrefixSearchResult>(&[0x00, 0x00]).is_err());
    }

    #[test]
    fn combined_proof_and_search_messages() {
        let ctp = CombinedTreeProof {
            timestamps: vec![1, 2],
            prefix_proofs: vec![PrefixProof::default()],
            prefix_roots: vec![h(3)],
            inclusion: InclusionProof {
                elements: vec![h(4), h(5)],
            },
        };
        let bytes = rt(&ctp);
        assert_eq!(
            hex::encode(&bytes[..19]),
            concat!("02", "0000000000000001", "0000000000000002", "01", "00")
        );

        let req = SearchRequest {
            last: Some(10),
            label: b"x".to_vec(),
            version: None,
        };
        assert_eq!(
            hex::encode(rt(&req)),
            concat!("01000000000000000a", "0178", "00")
        );

        let step = BinaryLadderStep {
            proof: [0xee; 80],
            commitment: None,
        };
        assert_eq!(hex::encode(rt(&step)), format!("{}00", "ee".repeat(80)));

        for version in [None, Some(4u32)] {
            let resp = SearchResponse {
                full_tree_head: FullTreeHead::Same,
                version,
                opening: [1; 16],
                value: UpdateValue { value: vec![9] },
                binary_ladder: vec![
                    step.clone(),
                    BinaryLadderStep {
                        proof: [1; 80],
                        commitment: Some(h(7)),
                    },
                ],
                search: ctp.clone(),
            };
            let bytes = resp.encode().unwrap();
            let requested = version.is_none();
            assert_eq!(SearchResponse::decode(&bytes, requested).unwrap(), resp);
            // With the version field, the bytes after the head start 00000004.
            if version.is_some() {
                assert_eq!(hex::encode(&bytes[1..5]), "00000004");
            }
            assert!(SearchResponse::decode(&bytes, !requested).is_err());
            let mut long = bytes.clone();
            long.push(0);
            assert!(SearchResponse::decode(&long, requested).is_err());
        }
    }

    #[test]
    fn monitoring_and_update_messages_round_trip() {
        let entries = vec![MonitorMapEntry {
            position: 3,
            version: 1,
        }];
        assert_eq!(hex::encode(rt(&entries[0])), "000000000000000300000001");
        rt(&ContactMonitorRequest {
            last: None,
            label: vec![1],
            entries: entries.clone(),
        });
        rt(&ContactMonitorResponse {
            full_tree_head: FullTreeHead::Same,
            monitor: CombinedTreeProof::default(),
        });
        rt(&OwnerInitRequest {
            last: Some(1),
            label: vec![2],
            start: 7,
        });
        rt(&OwnerInitResponse {
            full_tree_head: FullTreeHead::Same,
            greatest_versions: vec![3, 2],
            binary_ladder: vec![BinaryLadderStep {
                proof: [2; 80],
                commitment: Some(h(1)),
            }],
            init: CombinedTreeProof::default(),
        });
        rt(&OwnerMonitorRequest {
            last: None,
            label: vec![],
            entries,
            start: 4,
            greatest_version: Some(2),
        });
        rt(&OwnerMonitorResponse {
            full_tree_head: FullTreeHead::Same,
            monitor: CombinedTreeProof::default(),
        });
        rt(&UpdateRequest {
            last: None,
            label: vec![5],
            greatest_version: None,
            values: vec![LabelValue { value: vec![1, 2] }],
        });
        rt(&UpdateResponse {
            full_tree_head: FullTreeHead::Same,
            position: 8,
            values: vec![],
            info: vec![UpdateInfo { opening: [3; 16] }],
            binary_ladder: vec![],
            update: CombinedTreeProof::default(),
        });
        assert_eq!(
            hex::encode(rt(&DistinguishedRequest {
                last: None,
                stop: Some(2)
            })),
            "00010000000000000002"
        );
        rt(&DistinguishedResponse {
            full_tree_head: FullTreeHead::Same,
            distinguished: CombinedTreeProof::default(),
        });
    }

    #[test]
    fn credentials_and_auditor_updates_round_trip() {
        let standard = Credential {
            label: vec![0x61, 1],
            version: 0,
            opening: [4; 16],
            value: UpdateValue { value: vec![] },
            binary_ladder: vec![],
            position: 6,
            body: CredentialBody::Standard {
                distinguished: PrefixProof::default(),
            },
        };
        let bytes = rt(&standard);
        assert_eq!(standard.body.credential_type(), CredentialType::Standard);
        // ... position, then credential_type 1 and an empty PrefixProof (no
        // results, a two-byte count of no elements).
        assert_eq!(
            hex::encode(&bytes[bytes.len() - 12..]),
            "000000000000000601000000"
        );
        let provisional = Credential {
            body: CredentialBody::Provisional {
                tree_head: TreeHead {
                    tree_size: 7,
                    signatures: vec![],
                },
                search: CombinedTreeProof::default(),
            },
            ..standard
        };
        rt(&provisional);
        rt(&CredentialUpdate {
            position: 9,
            monitor: CombinedTreeProof::default(),
        });
        rt(&AuditorUpdate {
            timestamp: 5,
            added: vec![PrefixLeaf {
                vrf_output: h(1),
                commitment: h(2),
            }],
            removed: vec![],
            proof: PrefixProof::default(),
        });
    }
}
