// SPDX-License-Identifier: MIT
//! The third-party auditor (draft-ietf-keytrans-protocol-05 §15.2): it
//! replays each log entry's [`AuditorUpdate`], refuses any that does not
//! extend the entries before it, and signs [`AuditorTreeHead`]s for the one
//! lineage it has verified.
//!
//! Compiled with the `auditor` feature (and in tests). It runs as wasm in
//! Node, so it takes its key seed and its inputs as arguments and keeps its
//! state in memory: no clock, no randomness, no storage.
//!
//! # What an [`Auditor`] holds
//!
//! The log as far as it has verified it, and nothing about any label: the
//! tree size, the rightmost entry (its timestamp and prefix tree root) and
//! the full subtrees of the log tree before it. That is enough to check the
//! next entry and to compute the log's root. Its state only moves forward,
//! one verified entry at a time; there is no way to set it back, so every
//! head it signs extends every head it signed before.
//!
//! # Checking one entry (§15.2)
//!
//! [`Auditor::apply`] takes the entry's position, its update and, when the
//! host has it, the entry the log claims to have written. It refuses, and
//! keeps its state, unless:
//!
//! 1. the position is the next one (a replayed, skipped or reordered entry
//!    names the wrong one);
//! 2. the timestamp is not before the previous entry's;
//! 3. `added` is sorted by VRF output, with no output twice;
//! 4. `removed` is empty: the configuration sets no maximum lifetime, so
//!    the log may never remove a leaf (§7.1), which also makes step 5 of
//!    §15.2, a removed leaf having been in a distinguished entry, moot;
//! 5. the proof searches the previous prefix tree for every added key, in
//!    order, and none of them is there;
//! 6. the proof evaluates to the previous entry's prefix tree root, the one
//!    this auditor computed (for the first entry, the empty tree's);
//! 7. inserting the added leaves into what the proof reveals gives the new
//!    prefix tree root, and, when the host passed the log's entry, that
//!    entry has this timestamp and this root.
//!
//! Then it adds the entry's leaf to its log tree. An update carries no new
//! prefix tree root, so a changed commitment, or an added leaf dropped
//! together with its search, only changes the root the auditor computes:
//! without the log's entry to compare with, it would sign a head the log
//! cannot use (the log checks every auditor head against its own root),
//! but not a head over a history it did not verify.
//!
//! [`Auditor::sign_head`] signs the current state (§15.2 step 8): the
//! timestamp of the rightmost entry, the tree size and the log tree root,
//! under the auditor's [`Configuration`].
//!
//! # Instances, handoffs and cold starts
//!
//! The key is made from a seed the host draws at launch and is never
//! exported. Each launch is a new instance with a new key:
//!
//! - **The first instance** starts on the empty log ([`Auditor::new`]) and
//!   verifies every entry from the first.
//! - **A handoff.** The running instance signs a head at its current state
//!   and a [`Handoff`] naming the successor's key ([`Auditor::hand_off`]),
//!   and then retires: it signs nothing more, so the two keys never sign
//!   two continuations of one head. The successor checks both signatures
//!   and the [`Checkpoint`] they cover, and resumes from there
//!   ([`Auditor::resume`]).
//! - **A cold start**, with no predecessor running to hand off: the new
//!   instance starts on the empty log, verifies every entry up to the
//!   predecessor's latest head, and checks that head's signature over the
//!   root it computed ([`Auditor::confirm_predecessor`]).
//!
//! [`Auditor::instance`] gives the instance's
//! [`AuditorInstance`] value for the log's `k` label.
//!
//! # The start position
//!
//! A client rebuilds the configuration an auditor head is signed under from
//! the instance's logged `start_position`, so the configuration's
//! `auditor_start_pos` is the instance's `start_position`. Every instance
//! that verified the log from its first entry uses 0. A successor may use 0
//! too, since its lineage verified everything, or anything up to the
//! checkpoint's size, but never less than its predecessor's.

use crate::codec::{decode, encode, v8};
use crate::error::Error;
use crate::head::{auditor_key, sign_auditor_tree_head, verify_auditor_tree_head};
use crate::log_tree::{full_subtrees, leaf_hash, parent_hash, root_from_full_subtrees, Subtree};
use crate::prefix_proof::{bit, evaluate_skeleton, PrefixSearch, Skeleton, EMPTY};
use crate::profile::values::AuditorInstance;
use crate::suite::{Hash, PublicKey, SecretKey, PUBLIC_KEY_LEN, SIGNATURE_LEN};
use crate::wire::{
    AuditorTreeHead, AuditorUpdate, Configuration, KeyedAuditorTreeHead, LogEntry, ModeConfig,
    PrefixLeaf, PrefixSearchOutcome,
};
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

/// The deepest a prefix tree leaf can sit: a search result's depth is a
/// `uint8` on the wire, so a deeper leaf could never be proved.
const MAX_DEPTH: usize = 255;

/// The context string that opens the bytes of a handoff signature. An
/// `AuditorTreeHeadTBS` opens with the cipher suite (`0x0002`), and this
/// opens with its own length byte, so neither can be read as the other.
const HANDOFF_CONTEXT: &[u8] = b"peachy keytrans auditor handoff v1";

/// Everything the auditor refuses, one variant per check.
///
/// No variant names a label or a value: the auditor never sees one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AuditError {
    /// The configuration is not one this auditor can sign under: not in
    /// third-party auditing mode, naming another auditor key, setting a
    /// maximum lifetime, or with an `auditor_start_pos` this instance cannot
    /// claim.
    #[error("unusable configuration: {0}")]
    Configuration(&'static str),
    /// This instance handed off to a successor and signs nothing more.
    #[error("the auditor has handed off")]
    Retired,
    /// The update is not for the next position: a replayed, skipped or
    /// reordered entry.
    #[error("update for position {got}, expected {expected}")]
    WrongPosition {
        /// The next position, the auditor's tree size.
        expected: u64,
        /// The position the update was given for.
        got: u64,
    },
    /// The timestamp is before the previous entry's (§15.2 step 1).
    #[error("timestamp before the previous entry's")]
    TimestampBackwards,
    /// `added` is not sorted by VRF output, or has one twice (step 2).
    #[error("added leaves not in strictly ascending order")]
    AddedNotSorted,
    /// The update removes leaves, and the configuration sets no maximum
    /// lifetime (steps 4 and 5).
    #[error("a leaf removed from a log that keeps every entry")]
    RemovalNotAllowed,
    /// The proof shows an added key already in the previous prefix tree
    /// (step 3).
    #[error("an added key is already in the prefix tree")]
    AddedAlreadyPresent,
    /// The proof does not evaluate to the previous prefix tree root this
    /// auditor holds (step 6): the update was made against another tree.
    #[error("the update does not extend the previous entry")]
    PreviousRootMismatch,
    /// The entry the log claims to have written differs from the one the
    /// update gives: another timestamp or another prefix tree root (step 7).
    #[error("the log's entry differs from the update's")]
    ClaimedEntryMismatch,
    /// The proof is malformed: results that do not match the searches, the
    /// wrong number of elements, searches that disagree.
    #[error("malformed update: {0}")]
    Malformed(Error),
    /// Nothing to sign or hand off: the auditor has verified no entry.
    #[error("the auditor has verified no entry")]
    Empty,
    /// A checkpoint whose parts do not fit together.
    #[error("inconsistent checkpoint: {0}")]
    Checkpoint(&'static str),
    /// The predecessor's head does not cover the state it is checked against,
    /// or its signature does not verify.
    #[error("the predecessor's head does not verify: {0}")]
    PredecessorHead(&'static str),
    /// The handoff names another successor, or its signature does not verify.
    #[error("the handoff does not verify: {0}")]
    Handoff(&'static str),
}

/// The auditor's result type.
pub type AuditResult<T> = core::result::Result<T, AuditError>;

impl From<Error> for AuditError {
    fn from(err: Error) -> Self {
        AuditError::Malformed(err)
    }
}

/// The state a successor resumes from: the log at `tree_size` entries, as
/// the full subtrees of the entries before the rightmost one, and the
/// rightmost entry itself. Built by [`Auditor::checkpoint`]; a successor
/// trusts it only as far as its predecessor's signatures cover it.
///
/// ```text
/// struct {
///   uint64 tree_size;
///   LogEntry last;
///   HashValue preceding<0..2^8-1>;
/// } Checkpoint;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct Checkpoint {
    /// The number of entries verified.
    pub tree_size: u64,
    /// The rightmost entry.
    pub last: LogEntry,
    /// The values of the full subtrees of the first `tree_size - 1` entries,
    /// left to right.
    #[tls_codec(with = "v8")]
    pub preceding: Vec<Hash>,
}

impl Checkpoint {
    /// The checkpoint's bytes.
    pub fn to_bytes(&self) -> AuditResult<Vec<u8>> {
        Ok(encode(self)?)
    }

    /// Parses a checkpoint, refusing trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> AuditResult<Self> {
        Ok(decode(bytes)?)
    }

    /// The state the checkpoint describes, after checking that the parts
    /// fit: at least one entry, and one value per full subtree of the
    /// entries before the last.
    fn state(&self) -> AuditResult<State> {
        let before = self
            .tree_size
            .checked_sub(1)
            .ok_or(AuditError::Checkpoint("no entries"))?;
        let shape = full_subtrees(before);
        if shape.len() != self.preceding.len() {
            return Err(AuditError::Checkpoint(
                "wrong number of full subtree values",
            ));
        }
        let preceding: Vec<(Subtree, Hash)> = shape
            .into_iter()
            .zip(self.preceding.iter().copied())
            .collect();
        let mut frontier = preceding.clone();
        push_leaf(&mut frontier, before, leaf_hash(&self.last)?)?;
        Ok(State {
            size: self.tree_size,
            last: Some(self.last),
            preceding,
            frontier,
        })
    }
}

/// What a retiring instance gives its successor: a head at its last state,
/// the state itself, and its signature over the handoff.
///
/// The signature is over the TLS encoding of
///
/// ```text
/// struct {
///   opaque context<0..2^8-1>;      // "peachy keytrans auditor handoff v1"
///   opaque successor_key[32];
///   uint64 tree_size;
///   uint64 timestamp;
///   HashValue root;                // the log tree root at tree_size
/// } AuditorHandoffTBS;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct Handoff {
    /// The successor's public key.
    pub successor_key: [u8; PUBLIC_KEY_LEN],
    /// The predecessor's head at the checkpoint.
    pub head: AuditorTreeHead,
    /// The state the head covers.
    pub checkpoint: Checkpoint,
    /// The predecessor's signature over the handoff.
    pub signature: [u8; SIGNATURE_LEN],
}

impl Handoff {
    /// The handoff's bytes.
    pub fn to_bytes(&self) -> AuditResult<Vec<u8>> {
        Ok(encode(self)?)
    }

    /// Parses a handoff, refusing trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> AuditResult<Self> {
        Ok(decode(bytes)?)
    }
}

/// The bytes a handoff signature covers.
fn handoff_tbs(
    successor_key: &[u8; PUBLIC_KEY_LEN],
    tree_size: u64,
    timestamp: u64,
    root: &Hash,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + HANDOFF_CONTEXT.len() + 32 + 16 + 32);
    // The context is shorter than 256 bytes, so its length is one byte.
    out.push(HANDOFF_CONTEXT.len() as u8);
    out.extend_from_slice(HANDOFF_CONTEXT);
    out.extend_from_slice(successor_key);
    out.extend_from_slice(&tree_size.to_be_bytes());
    out.extend_from_slice(&timestamp.to_be_bytes());
    out.extend_from_slice(root);
    out
}

/// The log as the auditor has verified it.
#[derive(Clone)]
struct State {
    /// The number of entries.
    size: u64,
    /// The rightmost entry, if any.
    last: Option<LogEntry>,
    /// The full subtrees of the log tree at `size - 1`, left to right (empty
    /// while `size` is 0): what a [`Checkpoint`] carries.
    preceding: Vec<(Subtree, Hash)>,
    /// The full subtrees of the log tree at `size`, left to right.
    frontier: Vec<(Subtree, Hash)>,
}

impl State {
    fn empty() -> Self {
        State {
            size: 0,
            last: None,
            preceding: Vec::new(),
            frontier: Vec::new(),
        }
    }

    fn prefix_root(&self) -> Hash {
        self.last.map_or(EMPTY, |e| e.prefix_tree)
    }

    fn root(&self) -> AuditResult<Hash> {
        if self.size == 0 {
            return Err(AuditError::Empty);
        }
        Ok(root_from_full_subtrees(&self.frontier)?)
    }
}

/// Adds the leaf at `index` (the tree's size before it) to a tree's full
/// subtrees, merging equal neighbours as the log tree does.
fn push_leaf(frontier: &mut Vec<(Subtree, Hash)>, index: u64, value: Hash) -> AuditResult<()> {
    frontier.push((Subtree::leaf(index), value));
    while let [.., (left, lv), (right, rv)] = frontier.as_slice() {
        if left.size != right.size {
            break;
        }
        let merged = (
            Subtree::new(left.start, left.size * 2)?,
            parent_hash(lv, left.is_leaf(), rv, right.is_leaf()),
        );
        frontier.truncate(frontier.len() - 2);
        frontier.push(merged);
    }
    Ok(())
}

/// Inserts `leaf` under `node`, which sits `depth` deep, keeping every leaf
/// at the shallowest depth no other key shares its path.
fn insert(node: &mut Skeleton, leaf: PrefixLeaf, depth: usize) -> AuditResult<()> {
    match node {
        Skeleton::Empty => {
            *node = Skeleton::Leaf(leaf);
            Ok(())
        }
        Skeleton::Leaf(other) => {
            if other.vrf_output == leaf.vrf_output {
                return Err(AuditError::AddedAlreadyPresent);
            }
            *node = split(*other, leaf, depth)?;
            Ok(())
        }
        Skeleton::Parent(l, r) => {
            let child = if bit(&leaf.vrf_output, depth) { r } else { l };
            insert(child, leaf, depth + 1)
        }
        Skeleton::Copath(_) | Skeleton::Unknown => Err(AuditError::Malformed(
            Error::MalformedProof("an added key's path is not in the proof"),
        )),
    }
}

/// The subtree `depth` deep holding two leaves with distinct keys that share
/// their first `depth` bits.
fn split(a: PrefixLeaf, b: PrefixLeaf, depth: usize) -> AuditResult<Skeleton> {
    if depth >= MAX_DEPTH {
        return Err(AuditError::Malformed(Error::MalformedProof(
            "two keys share every provable bit",
        )));
    }
    let (ab, bb) = (bit(&a.vrf_output, depth), bit(&b.vrf_output, depth));
    let (left, right) = match (ab, bb) {
        (false, true) => (Skeleton::Leaf(a), Skeleton::Leaf(b)),
        (true, false) => (Skeleton::Leaf(b), Skeleton::Leaf(a)),
        (false, false) => (split(a, b, depth + 1)?, Skeleton::Empty),
        (true, true) => (Skeleton::Empty, split(a, b, depth + 1)?),
    };
    Ok(Skeleton::Parent(Box::new(left), Box::new(right)))
}

/// The prefix tree root after `update`, if it extends a tree whose root is
/// `previous` (§15.2 steps 2 to 7).
fn next_prefix_root(previous: &Hash, update: &AuditorUpdate) -> AuditResult<Hash> {
    if !update
        .added
        .windows(2)
        .all(|p| p[0].vrf_output < p[1].vrf_output)
    {
        return Err(AuditError::AddedNotSorted);
    }
    if !update.removed.is_empty() {
        return Err(AuditError::RemovalNotAllowed);
    }
    let searches: Vec<PrefixSearch> = update
        .added
        .iter()
        .map(|l| PrefixSearch {
            vrf_output: l.vrf_output,
            commitment: None,
        })
        .collect();
    if update.proof.results.len() == searches.len()
        && update
            .proof
            .results
            .iter()
            .any(|r| r.outcome == PrefixSearchOutcome::Inclusion)
    {
        return Err(AuditError::AddedAlreadyPresent);
    }
    let mut skeleton = evaluate_skeleton(&searches, &update.proof)?;
    if skeleton.hash()? != *previous {
        return Err(AuditError::PreviousRootMismatch);
    }
    for leaf in &update.added {
        insert(&mut skeleton, *leaf, 0)?;
    }
    Ok(skeleton.hash()?)
}

/// The auditor key and start position `config` names, after checking that
/// this auditor can sign under it.
fn check_config(config: &Configuration, key: &SecretKey) -> AuditResult<u64> {
    config
        .ciphersuite
        .require_supported()
        .map_err(|_| AuditError::Configuration("unsupported cipher suite"))?;
    let ModeConfig::ThirdPartyAuditing {
        auditor_start_pos,
        auditor_public_key,
        ..
    } = &config.mode
    else {
        return Err(AuditError::Configuration(
            "not in third-party auditing mode",
        ));
    };
    if auditor_public_key[..] != key.public_key().to_bytes() {
        return Err(AuditError::Configuration("names another auditor key"));
    }
    if config.maximum_lifetime.is_some() {
        return Err(AuditError::Configuration(
            "a maximum lifetime is not supported",
        ));
    }
    Ok(*auditor_start_pos)
}

/// The auditor key `config` names.
fn named_key(config: &Configuration) -> AuditResult<[u8; PUBLIC_KEY_LEN]> {
    auditor_key(config)
        .ok()
        .and_then(|k| k.try_into().ok())
        .ok_or(AuditError::Configuration(
            "the predecessor's configuration names no auditor key",
        ))
}

/// `config` with its auditor key and start position cleared, to compare two
/// instances' configurations on everything else.
fn without_instance(config: &Configuration) -> Configuration {
    let mut c = config.clone();
    if let ModeConfig::ThirdPartyAuditing {
        auditor_start_pos,
        auditor_public_key,
        ..
    } = &mut c.mode
    {
        *auditor_start_pos = 0;
        auditor_public_key.clear();
    }
    c
}

/// One auditor instance: its key, the configuration it signs under, and the
/// log as far as it has verified it.
pub struct Auditor {
    key: SecretKey,
    config: Configuration,
    state: State,
    last_signed: Option<AuditorTreeHead>,
    predecessor_key: Option<[u8; PUBLIC_KEY_LEN]>,
    handoff_sig: Option<[u8; SIGNATURE_LEN]>,
    retired: bool,
}

impl core::fmt::Debug for Auditor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Auditor")
            .field("public_key", &self.public_key())
            .field("tree_size", &self.state.size)
            .field("retired", &self.retired)
            .finish_non_exhaustive()
    }
}

impl Auditor {
    /// An instance on the empty log, with the key made from `seed` (32 random
    /// bytes the host draws and then forgets). `config` must name that key,
    /// be in third-party auditing mode, set no maximum lifetime, and have
    /// `auditor_start_pos` 0: this instance verifies every entry.
    pub fn new(seed: &[u8; 32], config: Configuration) -> AuditResult<Self> {
        let key = SecretKey::from_seed(seed);
        if check_config(&config, &key)? != 0 {
            return Err(AuditError::Configuration(
                "an instance on the empty log starts at 0",
            ));
        }
        Ok(Auditor {
            key,
            config,
            state: State::empty(),
            last_signed: None,
            predecessor_key: None,
            handoff_sig: None,
            retired: false,
        })
    }

    /// A successor resuming from `handoff`, with the key made from `seed`.
    ///
    /// `predecessor` is the configuration the predecessor signed under. The
    /// handoff must name this instance's key, its head must cover its
    /// checkpoint (same size, the rightmost entry's timestamp, a valid
    /// signature over the checkpoint's root), and its signature must verify
    /// under the predecessor's key. `config` must be the predecessor's but
    /// for the auditor key and the start position, which must lie between
    /// the predecessor's and the checkpoint's size.
    pub fn resume(
        seed: &[u8; 32],
        config: Configuration,
        predecessor: &Configuration,
        handoff: &Handoff,
    ) -> AuditResult<Self> {
        let key = SecretKey::from_seed(seed);
        let start = check_config(&config, &key)?;
        if without_instance(&config) != without_instance(predecessor) {
            return Err(AuditError::Configuration(
                "differs from the predecessor's beyond the auditor key and start",
            ));
        }
        let predecessor_key = named_key(predecessor)?;
        let predecessor_start = match &predecessor.mode {
            ModeConfig::ThirdPartyAuditing {
                auditor_start_pos, ..
            } => *auditor_start_pos,
            _ => {
                return Err(AuditError::Configuration(
                    "the predecessor is not in third-party auditing mode",
                ))
            }
        };
        if handoff.successor_key != key.public_key().to_bytes() {
            return Err(AuditError::Handoff("names another successor"));
        }
        let checkpoint = &handoff.checkpoint;
        let state = checkpoint.state()?;
        let root = state.root()?;
        let head = &handoff.head;
        if head.tree_size != checkpoint.tree_size {
            return Err(AuditError::PredecessorHead("covers another tree size"));
        }
        if head.timestamp != checkpoint.last.timestamp {
            return Err(AuditError::PredecessorHead(
                "not the rightmost entry's timestamp",
            ));
        }
        verify_auditor_tree_head(head, predecessor, &root)
            .map_err(|_| AuditError::PredecessorHead("bad signature"))?;
        PublicKey::from_bytes(&predecessor_key)
            .and_then(|k| {
                k.verify(
                    &handoff_tbs(
                        &handoff.successor_key,
                        head.tree_size,
                        head.timestamp,
                        &root,
                    ),
                    &handoff.signature,
                )
            })
            .map_err(|_| AuditError::Handoff("bad signature"))?;
        if start < predecessor_start || start > checkpoint.tree_size {
            return Err(AuditError::Configuration(
                "a successor starts between its predecessor's start and the checkpoint",
            ));
        }
        Ok(Auditor {
            key,
            config,
            state,
            last_signed: None,
            predecessor_key: Some(predecessor_key),
            handoff_sig: Some(handoff.signature),
            retired: false,
        })
    }

    /// The instance's public key.
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.key.public_key().to_bytes()
    }

    /// The configuration it signs under.
    pub fn config(&self) -> &Configuration {
        &self.config
    }

    /// The number of entries verified.
    pub fn tree_size(&self) -> u64 {
        self.state.size
    }

    /// The rightmost verified entry, if any.
    pub fn last_entry(&self) -> Option<LogEntry> {
        self.state.last
    }

    /// The log tree's root over the verified entries.
    pub fn root(&self) -> AuditResult<Hash> {
        self.state.root()
    }

    /// The last head this instance signed, if any.
    pub fn last_signed(&self) -> Option<&AuditorTreeHead> {
        self.last_signed.as_ref()
    }

    /// Whether this instance has handed off.
    pub fn is_retired(&self) -> bool {
        self.retired
    }

    /// Verifies the update for the entry at `position` and, if it extends
    /// the log, adds the entry (the module docs list the checks). `claimed`
    /// is the entry the log says it wrote there, when the host has it; it
    /// must match the entry the update gives. Returns that entry. On any
    /// refusal the state is unchanged.
    pub fn apply(
        &mut self,
        position: u64,
        update: &AuditorUpdate,
        claimed: Option<&LogEntry>,
    ) -> AuditResult<LogEntry> {
        if self.retired {
            return Err(AuditError::Retired);
        }
        if position != self.state.size {
            return Err(AuditError::WrongPosition {
                expected: self.state.size,
                got: position,
            });
        }
        if self
            .state
            .last
            .is_some_and(|e| update.timestamp < e.timestamp)
        {
            return Err(AuditError::TimestampBackwards);
        }
        let entry = LogEntry {
            timestamp: update.timestamp,
            prefix_tree: next_prefix_root(&self.state.prefix_root(), update)?,
        };
        if claimed.is_some_and(|c| *c != entry) {
            return Err(AuditError::ClaimedEntryMismatch);
        }
        let size = position
            .checked_add(1)
            .ok_or(AuditError::Malformed(Error::InvalidArgument("log full")))?;
        let preceding = self.state.frontier.clone();
        let mut frontier = preceding.clone();
        push_leaf(&mut frontier, position, leaf_hash(&entry)?)?;
        self.state = State {
            size,
            last: Some(entry),
            preceding,
            frontier,
        };
        Ok(entry)
    }

    /// Signs a head over every entry verified so far (§15.2 step 8), keyed
    /// by this instance's public key, ready for the log.
    pub fn sign_head(&mut self) -> AuditResult<KeyedAuditorTreeHead> {
        if self.retired {
            return Err(AuditError::Retired);
        }
        let last = self.state.last.ok_or(AuditError::Empty)?;
        let head = sign_auditor_tree_head(
            &self.key,
            &self.config,
            last.timestamp,
            self.state.size,
            &self.state.root()?,
        )?;
        self.last_signed = Some(head.clone());
        Ok(KeyedAuditorTreeHead {
            auditor_public_key: self.public_key().to_vec(),
            auditor_tree_head: head,
        })
    }

    /// The state a successor would resume from.
    pub fn checkpoint(&self) -> AuditResult<Checkpoint> {
        let last = self.state.last.ok_or(AuditError::Empty)?;
        Ok(Checkpoint {
            tree_size: self.state.size,
            last,
            preceding: self.state.preceding.iter().map(|(_, v)| *v).collect(),
        })
    }

    /// Hands off to the successor whose public key is `successor_key`: signs
    /// a head at the current state and a [`Handoff`] covering it, then
    /// retires. Refused on the empty log (a successor then starts with
    /// [`Auditor::new`]) and after a handoff.
    pub fn hand_off(&mut self, successor_key: &[u8; PUBLIC_KEY_LEN]) -> AuditResult<Handoff> {
        if self.retired {
            return Err(AuditError::Retired);
        }
        if *successor_key == self.public_key() {
            return Err(AuditError::Handoff("a successor needs a key of its own"));
        }
        PublicKey::from_bytes(successor_key)
            .map_err(|_| AuditError::Handoff("the successor key is not a valid key"))?;
        let checkpoint = self.checkpoint()?;
        let head = self.sign_head()?.auditor_tree_head;
        let root = self.state.root()?;
        let signature = self.key.sign(&handoff_tbs(
            successor_key,
            head.tree_size,
            head.timestamp,
            &root,
        ));
        self.retired = true;
        Ok(Handoff {
            successor_key: *successor_key,
            head,
            checkpoint,
            signature,
        })
    }

    /// For a cold start: checks the predecessor's latest head against the
    /// entries this instance has verified, from the first, up to exactly the
    /// head's size, and records the predecessor. `predecessor` is the
    /// configuration it signed under. Refused once this instance has signed
    /// a head: the check comes before it signs anything.
    pub fn confirm_predecessor(
        &mut self,
        predecessor: &Configuration,
        head: &AuditorTreeHead,
    ) -> AuditResult<()> {
        if self.retired {
            return Err(AuditError::Retired);
        }
        if self.last_signed.is_some() || self.predecessor_key.is_some() {
            return Err(AuditError::PredecessorHead(
                "checked after this instance signed or resumed",
            ));
        }
        if without_instance(&self.config) != without_instance(predecessor) {
            return Err(AuditError::Configuration(
                "differs from the predecessor's beyond the auditor key and start",
            ));
        }
        let predecessor_key = named_key(predecessor)?;
        if predecessor_key == self.public_key() {
            return Err(AuditError::PredecessorHead("names this instance's own key"));
        }
        if head.tree_size != self.state.size {
            return Err(AuditError::PredecessorHead("covers another tree size"));
        }
        let last = self.state.last.ok_or(AuditError::Empty)?;
        if head.timestamp != last.timestamp {
            return Err(AuditError::PredecessorHead(
                "not the rightmost entry's timestamp",
            ));
        }
        verify_auditor_tree_head(head, predecessor, &self.state.root()?)
            .map_err(|_| AuditError::PredecessorHead("bad signature"))?;
        self.predecessor_key = Some(predecessor_key);
        Ok(())
    }

    /// The instance's value for the log's `k` label: its start position, its predecessor's key (after a
    /// handoff or a confirmed cold start) and the handoff signature (after a
    /// handoff only). `boot_time` is the host's launch time in milliseconds.
    pub fn instance(&self, boot_time: u64) -> AuditorInstance {
        let start_position = match &self.config.mode {
            ModeConfig::ThirdPartyAuditing {
                auditor_start_pos, ..
            } => *auditor_start_pos,
            _ => 0,
        };
        AuditorInstance {
            boot_time,
            start_position,
            predecessor_key: self.predecessor_key,
            handoff_sig: self.handoff_sig,
        }
    }
}
