// SPDX-License-Identifier: MIT
//! The verifier's [`Oracle`]: reads a `CombinedTreeProof` (draft §12.3) in
//! the order the walkers request it, then checks what is left over.

use std::collections::{BTreeMap, BTreeSet};

use crate::log_tree::{leaf_hash, verify_batch, BatchRoots, BatchSpec};
use crate::prefix_proof::{evaluate, PrefixSearch};
use crate::suite::Hash;
use crate::verify::error::{VerifyError, VerifyResult};
use crate::verify::state::VersionTable;
use crate::verify::walk::Oracle;
use crate::wire::{CombinedTreeProof, LogEntry, PrefixSearchOutcome};

/// What a fully read proof established.
#[derive(Debug, Clone)]
pub(crate) struct Finished {
    /// The log tree's roots (and full subtrees) from the inclusion proof.
    pub roots: BatchRoots,
    /// Every entry the proof listed or the client retained.
    pub entries: BTreeMap<u64, LogEntry>,
}

struct Current {
    position: u64,
    index: usize,
    searches: Vec<PrefixSearch>,
}

/// Reads one `CombinedTreeProof`.
pub(crate) struct ProofReader<'a> {
    proof: &'a CombinedTreeProof,
    versions: &'a VersionTable,
    retained: BTreeMap<u64, LogEntry>,
    timestamps: BTreeMap<u64, u64>,
    listed: Vec<u64>,
    next_proof: usize,
    roots: BTreeMap<u64, Hash>,
    current: Option<Current>,
}

impl<'a> ProofReader<'a> {
    /// A reader for `proof`, where the client retains `retained` entries
    /// (the frontier of the tree size it advertised) and knows the VRF
    /// outputs and commitments in `versions`.
    pub fn new(
        proof: &'a CombinedTreeProof,
        retained: impl IntoIterator<Item = (u64, LogEntry)>,
        versions: &'a VersionTable,
    ) -> Self {
        let retained: BTreeMap<u64, LogEntry> = retained.into_iter().collect();
        let timestamps = retained.iter().map(|(p, e)| (*p, e.timestamp)).collect();
        ProofReader {
            proof,
            versions,
            retained,
            timestamps,
            listed: Vec::new(),
            next_proof: 0,
            roots: BTreeMap::new(),
            current: None,
        }
    }

    /// Checks that every timestamp and prefix proof was read.
    pub fn consumed(&self) -> VerifyResult<()> {
        if self.current.is_some() {
            return Err(VerifyError::Proof("a prefix proof left open"));
        }
        if self.listed.len() != self.proof.timestamps.len() {
            return Err(VerifyError::Proof("timestamps left over"));
        }
        if self.next_proof != self.proof.prefix_proofs.len() {
            return Err(VerifyError::Proof("prefix proofs left over"));
        }
        Ok(())
    }

    /// Checks that everything was consumed, fills in the prefix roots, and
    /// verifies the inclusion proof for a tree of `tree_size` entries.
    pub fn finish(
        self,
        tree_size: u64,
        retained_size: Option<u64>,
        retained_full_subtrees: &[Hash],
        extra_sizes: &[u64],
    ) -> VerifyResult<Finished> {
        let proof = self.proof;
        self.consumed()?;
        // Monotonic, across listed and retained (§12.3).
        let mut previous = 0u64;
        for ts in self.timestamps.values() {
            if *ts < previous {
                return Err(VerifyError::TimestampOrder);
            }
            previous = *ts;
        }
        let listed: BTreeSet<u64> = self.listed.iter().copied().collect();
        let mut prefix_roots = proof.prefix_roots.iter();
        let mut entries = self.retained.clone();
        let mut leaves = Vec::with_capacity(listed.len());
        for &x in &listed {
            let prefix_tree = match self.roots.get(&x) {
                Some(r) => *r,
                None => *prefix_roots
                    .next()
                    .ok_or(VerifyError::Proof("too few prefix roots"))?,
            };
            let timestamp = *self
                .timestamps
                .get(&x)
                .ok_or(VerifyError::Proof("listed entry without a timestamp"))?;
            let entry = LogEntry {
                timestamp,
                prefix_tree,
            };
            leaves.push((x, leaf_hash(&entry)?));
            entries.insert(x, entry);
        }
        if prefix_roots.next().is_some() {
            return Err(VerifyError::Proof("too many prefix roots"));
        }
        let spec = BatchSpec {
            tree_size,
            leaves: listed.iter().copied().collect(),
            retained_size,
            extra_sizes: extra_sizes.to_vec(),
        };
        let roots = verify_batch(&spec, &leaves, retained_full_subtrees, &proof.inclusion)?;
        Ok(Finished { roots, entries })
    }
}

impl Oracle for ProofReader<'_> {
    fn timestamp(&mut self, position: u64) -> VerifyResult<u64> {
        if let Some(ts) = self.timestamps.get(&position) {
            return Ok(*ts);
        }
        let ts = *self
            .proof
            .timestamps
            .get(self.listed.len())
            .ok_or(VerifyError::Proof("too few timestamps"))?;
        self.listed.push(position);
        self.timestamps.insert(position, ts);
        Ok(ts)
    }

    fn begin_proof(&mut self, position: u64) -> VerifyResult<()> {
        if self.current.is_some() {
            return Err(VerifyError::Proof("prefix proofs overlap"));
        }
        if self.next_proof >= self.proof.prefix_proofs.len() {
            return Err(VerifyError::Proof("too few prefix proofs"));
        }
        self.current = Some(Current {
            position,
            index: self.next_proof,
            searches: Vec::new(),
        });
        self.next_proof += 1;
        Ok(())
    }

    fn lookup(&mut self, version: u32) -> VerifyResult<bool> {
        let current = self
            .current
            .as_mut()
            .ok_or(VerifyError::Proof("a lookup outside a prefix proof"))?;
        let proof = &self.proof.prefix_proofs[current.index];
        let result = proof
            .results
            .get(current.searches.len())
            .ok_or(VerifyError::Proof("too few prefix search results"))?;
        let known = self.versions.get(version).ok_or(VerifyError::Proof(
            "a lookup of a version without a VRF output",
        ))?;
        let included = matches!(result.outcome, PrefixSearchOutcome::Inclusion);
        let commitment = if included {
            Some(known.commitment.ok_or(VerifyError::VersionMismatch(
                "an inclusion of a version claimed absent",
            ))?)
        } else {
            None
        };
        current.searches.push(PrefixSearch {
            vrf_output: known.vrf_output,
            commitment,
        });
        Ok(included)
    }

    fn end_proof(&mut self) -> VerifyResult<()> {
        let current = self
            .current
            .take()
            .ok_or(VerifyError::Proof("no prefix proof open"))?;
        let proof = &self.proof.prefix_proofs[current.index];
        let root = evaluate(&current.searches, proof)?;
        if let Some(previous) = self.roots.get(&current.position) {
            if *previous != root {
                return Err(VerifyError::Proof(
                    "two prefix proofs for one entry disagree",
                ));
            }
        }
        if let Some(kept) = self.retained.get(&current.position) {
            if kept.prefix_tree != root {
                return Err(VerifyError::Inconsistent(
                    "a prefix proof disagrees with a retained entry",
                ));
            }
        }
        self.roots.insert(current.position, root);
        Ok(())
    }

    fn owner_step(
        &mut self,
        _position: u64,
        expected: Option<u32>,
    ) -> VerifyResult<Option<Option<u32>>> {
        // §8.3: from a user's perspective, the only stop condition is having
        // consumed all of the response.
        if self.next_proof >= self.proof.prefix_proofs.len() {
            Ok(None)
        } else {
            Ok(Some(expected))
        }
    }
}
