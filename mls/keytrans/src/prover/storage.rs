// SPDX-License-Identifier: MIT
//! What the prover stores, behind a trait the host implements.
//!
//! The prover runs as wasm, so the trait is synchronous and its reads are
//! point lookups the host can answer from tables or a cache: a log entry, a
//! balanced subtree head of the log tree, a prefix tree node by its value, a
//! label's versions, the signed head, the auditor heads. Writes arrive as one
//! [`WriteBatch`] per appended entry (or per auditor head), which the host
//! applies atomically: a batch is either all there or not at all.
//!
//! Everything only grows. Entries, subtree heads, nodes and versions are
//! never rewritten, so a reader that holds no lock sees a consistent log as
//! long as it reads [`Storage::entry_count`] first and nothing past it.
//!
//! Every record has a byte encoding (TLS presentation language, like the
//! wire) so a host can keep them as opaque columns: [`LogEntry`] and
//! [`PrefixLeaf`] from [`crate::wire`], [`PrefixNode::to_bytes`], and
//! [`VersionRecord`] here.

use std::collections::BTreeMap;

use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::codec::{b8, decode, encode};
use crate::error::{Error, Result};
use crate::log_tree::Subtree;
use crate::prefix_tree::{NodeSource, PrefixNode};
use crate::suite::{Hash, Opening, VrfOutput};
use crate::wire::{KeyedAuditorTreeHead, LogEntry, PrefixLeaf, TreeHead, UpdateValue};

/// One version of one label, as the log keeps it.
#[derive(Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct VersionRecord {
    /// The label.
    #[tls_codec(with = "b8")]
    pub label: Vec<u8>,
    /// The version: versions of a label run 0, 1, 2, ... with no gaps.
    pub version: u32,
    /// The log entry that added it.
    pub position: u64,
    /// The commitment opening drawn for it.
    pub opening: Opening,
    /// Its value.
    pub value: UpdateValue,
    /// Its search key in the prefix tree.
    pub vrf_output: VrfOutput,
    /// Its commitment, the leaf's other half.
    pub commitment: Hash,
}

impl VersionRecord {
    /// The record's storage encoding.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        encode(self)
    }

    /// Decodes [`VersionRecord::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        decode(bytes)
    }

    /// Its prefix tree leaf.
    pub fn leaf(&self) -> PrefixLeaf {
        PrefixLeaf {
            vrf_output: self.vrf_output,
            commitment: self.commitment,
        }
    }
}

/// A new log entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewEntry {
    /// Its position: the entry count before it.
    pub position: u64,
    /// The log tree leaf: its timestamp and prefix tree root.
    pub entry: LogEntry,
    /// The leaves it added to the prefix tree, sorted by VRF output (what its
    /// [`AuditorUpdate`](crate::wire::AuditorUpdate) lists).
    pub added: Vec<PrefixLeaf>,
}

/// Everything one write stores, applied atomically.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WriteBatch {
    /// A new log entry, at position [`Storage::entry_count`].
    pub entry: Option<NewEntry>,
    /// Balanced subtree heads of the log tree that the new entry completes.
    pub log_nodes: Vec<(Subtree, Hash)>,
    /// New prefix tree nodes, each under its value.
    pub prefix_nodes: Vec<(Hash, PrefixNode)>,
    /// New label versions.
    pub versions: Vec<VersionRecord>,
    /// The signed head over the log including the new entry; replaces the
    /// stored one.
    pub tree_head: Option<TreeHead>,
    /// An auditor's newer head; replaces that auditor's stored one.
    pub auditor_head: Option<KeyedAuditorTreeHead>,
}

/// The prover's storage. Reads of something the log must hold and does not
/// fail with [`Error::Storage`].
pub trait Storage {
    /// The number of log entries.
    fn entry_count(&self) -> Result<u64>;
    /// The log entry at `position`.
    fn entry(&self, position: u64) -> Result<LogEntry>;
    /// The leaves the entry at `position` added, sorted by VRF output.
    fn entry_added(&self, position: u64) -> Result<Vec<PrefixLeaf>>;
    /// The head of a balanced subtree lying wholly inside the log.
    fn log_node(&self, subtree: Subtree) -> Result<Hash>;
    /// The prefix tree node stored under `hash`.
    fn prefix_node(&self, hash: &Hash) -> Result<PrefixNode>;
    /// Every version of `label`, ascending; empty if it has none.
    fn label_versions(&self, label: &[u8]) -> Result<Vec<VersionRecord>>;
    /// The signed head over every entry, if there is one.
    fn tree_head(&self) -> Result<Option<TreeHead>>;
    /// The latest head from each auditor that has signed one.
    fn auditor_heads(&self) -> Result<Vec<KeyedAuditorTreeHead>>;
    /// Applies `batch` atomically.
    fn apply(&mut self, batch: WriteBatch) -> Result<()>;
}

/// Reads a storage's prefix nodes as a [`NodeSource`].
pub(crate) struct Nodes<'a, S: Storage + ?Sized>(pub &'a S);

impl<S: Storage + ?Sized> NodeSource for Nodes<'_, S> {
    fn prefix_node(&self, hash: &Hash) -> Result<PrefixNode> {
        self.0.prefix_node(hash)
    }
}

/// An in-memory [`Storage`], for tests, tools and small hosts.
#[derive(Debug, Clone, Default)]
pub struct MemoryStore {
    entries: Vec<(LogEntry, Vec<PrefixLeaf>)>,
    log_nodes: BTreeMap<Subtree, Hash>,
    prefix_nodes: BTreeMap<Hash, PrefixNode>,
    versions: BTreeMap<Vec<u8>, Vec<VersionRecord>>,
    tree_head: Option<TreeHead>,
    auditor_heads: Vec<KeyedAuditorTreeHead>,
}

impl MemoryStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many prefix tree nodes it holds.
    pub fn prefix_node_count(&self) -> usize {
        self.prefix_nodes.len()
    }
}

fn index(position: u64) -> Result<usize> {
    usize::try_from(position).map_err(|_| Error::Storage("position out of range".into()))
}

impl Storage for MemoryStore {
    fn entry_count(&self) -> Result<u64> {
        Ok(self.entries.len() as u64)
    }

    fn entry(&self, position: u64) -> Result<LogEntry> {
        self.entries
            .get(index(position)?)
            .map(|(e, _)| *e)
            .ok_or_else(|| Error::Storage("log entry missing".into()))
    }

    fn entry_added(&self, position: u64) -> Result<Vec<PrefixLeaf>> {
        self.entries
            .get(index(position)?)
            .map(|(_, a)| a.clone())
            .ok_or_else(|| Error::Storage("log entry missing".into()))
    }

    fn log_node(&self, subtree: Subtree) -> Result<Hash> {
        self.log_nodes
            .get(&subtree)
            .copied()
            .ok_or_else(|| Error::Storage("log tree node missing".into()))
    }

    fn prefix_node(&self, hash: &Hash) -> Result<PrefixNode> {
        self.prefix_nodes.prefix_node(hash)
    }

    fn label_versions(&self, label: &[u8]) -> Result<Vec<VersionRecord>> {
        Ok(self.versions.get(label).cloned().unwrap_or_default())
    }

    fn tree_head(&self) -> Result<Option<TreeHead>> {
        Ok(self.tree_head.clone())
    }

    fn auditor_heads(&self) -> Result<Vec<KeyedAuditorTreeHead>> {
        Ok(self.auditor_heads.clone())
    }

    fn apply(&mut self, batch: WriteBatch) -> Result<()> {
        // Check everything before changing anything.
        if let Some(new) = &batch.entry {
            if new.position != self.entries.len() as u64 {
                return Err(Error::Storage("entry out of order".into()));
            }
        }
        let mut next: BTreeMap<&[u8], usize> = BTreeMap::new();
        for v in &batch.versions {
            let slot = next
                .entry(v.label.as_slice())
                .or_insert_with(|| self.versions.get(&v.label).map_or(0, Vec::len));
            if index(u64::from(v.version))? != *slot {
                return Err(Error::Storage("label version out of order".into()));
            }
            *slot += 1;
        }
        if let Some(new) = batch.entry {
            self.entries.push((new.entry, new.added));
        }
        self.log_nodes.extend(batch.log_nodes);
        self.prefix_nodes.extend(batch.prefix_nodes);
        for v in batch.versions {
            self.versions.entry(v.label.clone()).or_default().push(v);
        }
        if let Some(head) = batch.tree_head {
            self.tree_head = Some(head);
        }
        if let Some(head) = batch.auditor_head {
            self.auditor_heads
                .retain(|h| h.auditor_public_key != head.auditor_public_key);
            self.auditor_heads.push(head);
        }
        Ok(())
    }
}
