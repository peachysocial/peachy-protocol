// SPDX-License-Identifier: MIT
//! The prover's side of the walkers: a [`ProofRecorder`] answers each
//! request from a [`LogSource`] and writes the `CombinedTreeProof` down in
//! the order the verifier will read it.
//!
//! A log builds a response by running the same [`Walk`](super::walk::Walk)
//! methods the verifier runs, over a recorder:
//!
//! ```text
//! let mut rec = ProofRecorder::new(&mut log, last)?;
//! let mut walk = Walk::new(&mut rec, n, window, lifetime);
//! walk.update_view(last)?;
//! walk.greatest_search(g)?;
//! let proof = rec.finish(n, last, &auditor_head_sizes)?;
//! ```
//!
//! so the two sides cannot disagree on which entry a timestamp or prefix
//! proof belongs to.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::Result;
use crate::implicit::frontier;
use crate::log_tree::{prove_batch, BatchSpec, Subtree};
use crate::suite::Hash;
use crate::verify::error::{VerifyError, VerifyResult};
use crate::verify::walk::Oracle;
use crate::wire::{CombinedTreeProof, LogEntry, PrefixProof};

/// What a recorder reads from the log, for one label.
pub trait LogSource {
    /// The log entry at `position`.
    fn log_entry(&mut self, position: u64) -> Result<LogEntry>;
    /// Whether `version` of the label is in that entry's prefix tree.
    fn includes(&mut self, position: u64, version: u32) -> Result<bool>;
    /// The label's greatest version in that entry's prefix tree.
    fn greatest(&mut self, position: u64) -> Result<Option<u32>>;
    /// A prefix proof from that entry for `versions` of the label, in order.
    fn prefix_proof(&mut self, position: u64, versions: &[u32]) -> Result<PrefixProof>;
    /// A balanced subtree's value in the log tree.
    fn subtree(&mut self, subtree: Subtree) -> Result<Hash>;
}

/// When a log stops owner monitoring (draft §8.3 step 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerPolicy {
    /// The owner's advertised greatest version: the log stops at an entry
    /// whose greatest version is above it.
    pub advertised: Option<u32>,
    /// At most this many owner ladders per response.
    pub max_ladders: usize,
}

/// Records one `CombinedTreeProof`.
pub struct ProofRecorder<'s, S: LogSource> {
    source: &'s mut S,
    known: BTreeMap<u64, u64>,
    listed: Vec<u64>,
    proofs: Vec<PrefixProof>,
    proved: BTreeSet<u64>,
    current: Option<(u64, Vec<u32>)>,
    owner: Option<OwnerPolicy>,
    owner_ladders: usize,
    owner_stopped: bool,
}

impl<'s, S: LogSource> ProofRecorder<'s, S> {
    /// A recorder for a user who advertised `last` (and so retains the
    /// frontier entries of that size).
    pub fn new(source: &'s mut S, last: Option<u64>) -> VerifyResult<Self> {
        let mut known = BTreeMap::new();
        for x in last.map(frontier).unwrap_or_default() {
            known.insert(x, source.log_entry(x)?.timestamp);
        }
        Ok(ProofRecorder {
            source,
            known,
            listed: Vec::new(),
            proofs: Vec::new(),
            proved: BTreeSet::new(),
            current: None,
            owner: None,
            owner_ladders: 0,
            owner_stopped: false,
        })
    }

    /// Sets when owner monitoring stops.
    pub fn with_owner_policy(mut self, policy: OwnerPolicy) -> Self {
        self.owner = Some(policy);
        self
    }

    /// The proof, with its inclusion proof for a tree of `tree_size`
    /// entries, the user's `retained_size`, and the auditor heads' sizes.
    pub fn finish(
        self,
        tree_size: u64,
        retained_size: Option<u64>,
        extra_sizes: &[u64],
    ) -> VerifyResult<CombinedTreeProof> {
        let mut sorted: Vec<u64> = self.listed.clone();
        sorted.sort_unstable();
        let mut prefix_roots = Vec::new();
        for &x in &sorted {
            if !self.proved.contains(&x) {
                prefix_roots.push(self.source.log_entry(x)?.prefix_tree);
            }
        }
        let timestamps = self
            .listed
            .iter()
            .map(|x| self.known.get(x).copied().unwrap_or(0))
            .collect();
        let spec = BatchSpec {
            tree_size,
            leaves: sorted,
            retained_size,
            extra_sizes: extra_sizes.to_vec(),
        };
        let source = self.source;
        let inclusion = prove_batch(&spec, |s| source.subtree(s))?;
        Ok(CombinedTreeProof {
            timestamps,
            prefix_proofs: self.proofs,
            prefix_roots,
            inclusion,
        })
    }
}

impl<S: LogSource> Oracle for ProofRecorder<'_, S> {
    fn timestamp(&mut self, position: u64) -> VerifyResult<u64> {
        if let Some(ts) = self.known.get(&position) {
            return Ok(*ts);
        }
        let ts = self.source.log_entry(position)?.timestamp;
        self.known.insert(position, ts);
        self.listed.push(position);
        Ok(ts)
    }

    fn begin_proof(&mut self, position: u64) -> VerifyResult<()> {
        if self.current.is_some() {
            return Err(VerifyError::Proof("prefix proofs overlap"));
        }
        self.current = Some((position, Vec::new()));
        Ok(())
    }

    fn lookup(&mut self, version: u32) -> VerifyResult<bool> {
        let (position, versions) = self
            .current
            .as_mut()
            .ok_or(VerifyError::Proof("a lookup outside a prefix proof"))?;
        versions.push(version);
        Ok(self.source.includes(*position, version)?)
    }

    fn end_proof(&mut self) -> VerifyResult<()> {
        let (position, versions) = self
            .current
            .take()
            .ok_or(VerifyError::Proof("no prefix proof open"))?;
        self.proofs
            .push(self.source.prefix_proof(position, &versions)?);
        self.proved.insert(position);
        Ok(())
    }

    fn owner_step(
        &mut self,
        position: u64,
        _expected: Option<u32>,
    ) -> VerifyResult<Option<Option<u32>>> {
        if self.owner_stopped {
            return Ok(None);
        }
        let greatest = self.source.greatest(position)?;
        if let Some(policy) = self.owner {
            let above = match (greatest, policy.advertised) {
                (Some(g), Some(a)) => g > a,
                (Some(_), None) => true,
                (None, _) => false,
            };
            if above || self.owner_ladders >= policy.max_ladders {
                self.owner_stopped = true;
                return Ok(None);
            }
        }
        self.owner_ladders += 1;
        Ok(Some(greatest))
    }
}
