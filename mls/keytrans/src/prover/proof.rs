// SPDX-License-Identifier: MIT
//! Building a [`CombinedTreeProof`] (§12.3, Appendix C) the way a verifier
//! consumes it, and the per-label helpers every algorithm shares.
//!
//! [`Builder`] is Appendix C's two queues run backwards: the algorithms call
//! [`Builder::timestamp`] and [`Builder::ladder`] in the order the verifier
//! will, and the builder records what the verifier has to be given. The
//! rules (the module docs of [`crate::prover`] list them for verifiers):
//!
//! - a timestamp is listed the first time it is asked for, unless the entry
//!   is on the frontier of the size the user advertised (retained);
//! - a prefix proof at an entry first asks for the entry's timestamp, so
//!   every proof is tied to a leaf the inclusion proof covers, or to a
//!   retained entry;
//! - `prefix_roots` lists, in ascending position, every listed entry that
//!   got no prefix proof;
//! - the inclusion proof covers the listed entries, given the retained full
//!   subtrees, and also yields the root at each auditor head's size.

use std::collections::{BTreeMap, BTreeSet};

use super::storage::{Nodes, Storage, VersionRecord};
use super::Prover;
use crate::error::{Error, Result};
use crate::implicit::{ancestors, frontier, root as tree_root, spans_window, update_view};
use crate::ladder::{drive, versions as ladder_versions, LadderEnd, LadderKind};
use crate::log_tree::{prove_batch, BatchSpec};
use crate::prefix_tree::prove;
use crate::suite::{VrfOutput, VrfProof};
use crate::wire::{BinaryLadderStep, CombinedTreeProof, PrefixProof};

/// The most elements a `<0..2^8-1>` vector holds.
const MAX_V8: usize = 0xff;

/// Records what a response's [`CombinedTreeProof`] carries.
pub(crate) struct Builder<'p, S: Storage> {
    store: &'p S,
    window: u64,
    /// The tree size the proof is against.
    n: u64,
    last: Option<u64>,
    retained: BTreeSet<u64>,
    listed: Vec<u64>,
    listed_set: BTreeSet<u64>,
    proofs: Vec<PrefixProof>,
    proved: BTreeSet<u64>,
    timestamps: BTreeMap<u64, u64>,
}

impl<'p, S: Storage> Builder<'p, S> {
    /// A proof against `n` entries for a user who retained `last`'s
    /// frontier.
    pub(crate) fn new(prover: &'p Prover<S>, n: u64, last: Option<u64>) -> Result<Self> {
        if n == 0 {
            return Err(Error::InvalidArgument("the log is empty"));
        }
        if last.is_some_and(|m| m > n) {
            return Err(Error::InvalidArgument("advertised size beyond the tree"));
        }
        let retained = match last {
            Some(m) if m > 0 => frontier(m).into_iter().collect(),
            _ => BTreeSet::new(),
        };
        Ok(Builder {
            store: prover.store(),
            window: prover.window(),
            n,
            last,
            retained,
            listed: Vec::new(),
            listed_set: BTreeSet::new(),
            proofs: Vec::new(),
            proved: BTreeSet::new(),
            timestamps: BTreeMap::new(),
        })
    }

    /// The tree size.
    pub(crate) fn n(&self) -> u64 {
        self.n
    }

    /// Reads a timestamp without giving it to the verifier: for the
    /// prover's own decisions about entries the verifier already has.
    pub(crate) fn peek(&mut self, x: u64) -> Result<u64> {
        if x >= self.n {
            return Err(Error::InvalidArgument("entry outside the tree"));
        }
        if let Some(t) = self.timestamps.get(&x) {
            return Ok(*t);
        }
        let t = self.store.entry(x)?.timestamp;
        self.timestamps.insert(x, t);
        Ok(t)
    }

    /// Appendix C's `get_timestamp(x)`.
    pub(crate) fn timestamp(&mut self, x: u64) -> Result<u64> {
        let t = self.peek(x)?;
        if !self.retained.contains(&x) && self.listed_set.insert(x) {
            self.listed.push(x);
        }
        Ok(t)
    }

    /// The timestamps of updating the user's view (§4.2, §12.3.1).
    pub(crate) fn update_view(&mut self) -> Result<()> {
        for x in update_view(self.n, self.last)? {
            self.timestamp(x)?;
        }
        Ok(())
    }

    /// A prefix proof from `x`'s prefix tree for `keys`, in order.
    pub(crate) fn prefix(&mut self, x: u64, keys: &[VrfOutput]) -> Result<()> {
        self.timestamp(x)?;
        let root = self.store.entry(x)?.prefix_tree;
        self.proofs.push(prove(&Nodes(self.store), &root, keys)?);
        self.proved.insert(x);
        Ok(())
    }

    /// Whether `x` is distinguished (§6.1), asking for timestamps the way
    /// §12.3.4 and §12.3.7 give them: down the path from the root, each
    /// entry's timestamp once it is known to be distinguished and is not
    /// `x`, stopping at the first entry that is not distinguished.
    pub(crate) fn is_distinguished(&mut self, x: u64) -> Result<bool> {
        let mut path = ancestors(x, self.n)?;
        path.reverse();
        path.push(x);
        let mut lt = 0u64;
        let mut rt = self.peek(self.n - 1)?;
        for (i, &y) in path.iter().enumerate() {
            if !spans_window(lt, rt, self.window) {
                return Ok(false);
            }
            if y == x {
                return Ok(true);
            }
            let ty = self.timestamp(y)?;
            match path.get(i + 1) {
                Some(&next) if next < y => rt = ty,
                Some(_) => lt = ty,
                None => {}
            }
        }
        Ok(false)
    }

    /// The prefix proofs given so far, for a caller that wants them alone.
    pub(crate) fn into_proofs(self) -> Vec<PrefixProof> {
        self.proofs
    }

    /// The finished proof. `extra_sizes` are the auditor heads' tree sizes,
    /// in the order the full tree head lists them.
    pub(crate) fn finish(self, extra_sizes: &[u64]) -> Result<CombinedTreeProof> {
        if self.listed.len() > MAX_V8 || self.proofs.len() > MAX_V8 {
            return Err(Error::Encode("combined tree proof too long"));
        }
        let mut timestamps = Vec::with_capacity(self.listed.len());
        for x in &self.listed {
            timestamps.push(
                *self
                    .timestamps
                    .get(x)
                    .ok_or_else(|| Error::Storage("timestamp not read".into()))?,
            );
        }
        let mut unproved: Vec<u64> = self
            .listed
            .iter()
            .copied()
            .filter(|x| !self.proved.contains(x))
            .collect();
        unproved.sort_unstable();
        if unproved.len() > MAX_V8 {
            return Err(Error::Encode("combined tree proof too long"));
        }
        let prefix_roots = unproved
            .iter()
            .map(|&x| self.store.entry(x).map(|e| e.prefix_tree))
            .collect::<Result<Vec<_>>>()?;
        let spec = BatchSpec {
            tree_size: self.n,
            leaves: self.listed.clone(),
            retained_size: self.last,
            extra_sizes: extra_sizes.to_vec(),
        };
        let store = self.store;
        let inclusion = prove_batch(&spec, |s| store.log_node(s))?;
        Ok(CombinedTreeProof {
            timestamps,
            prefix_proofs: self.proofs,
            prefix_roots,
            inclusion,
        })
    }
}

/// What lookups a ladder may leave out (§6.2): an inclusion already shown
/// at an entry to the left, and, where the context allows, a non-inclusion
/// already shown at an entry to the right. It records what each ladder
/// established, omitted lookups included (an omitted lookup's outcome is
/// known, so recording it changes nothing).
#[derive(Debug, Default)]
pub(crate) struct Omission {
    right_too: bool,
    included: BTreeMap<u32, BTreeSet<u64>>,
    excluded: BTreeMap<u32, BTreeSet<u64>>,
}

impl Omission {
    /// Leaves out inclusions shown to the left only (greatest-version
    /// search, §6.3; updates, §9.1).
    pub(crate) fn left_inclusions() -> Self {
        Omission::default()
    }

    /// Also leaves out non-inclusions shown to the right (fixed-version
    /// search, §7.2).
    pub(crate) fn both() -> Self {
        Omission {
            right_too: true,
            ..Omission::default()
        }
    }

    fn omitted(&self, v: u32, x: u64, included: bool) -> bool {
        if included {
            self.included
                .get(&v)
                .is_some_and(|s| s.range(..x).next().is_some())
        } else {
            self.right_too
                && self
                    .excluded
                    .get(&v)
                    .is_some_and(|s| s.range(x + 1..).next().is_some())
        }
    }

    fn record(&mut self, v: u32, x: u64, included: bool) {
        let map = if included {
            &mut self.included
        } else {
            &mut self.excluded
        };
        map.entry(v).or_default().insert(x);
    }
}

/// One label's versions as of a tree size, and its VRF outputs.
pub(crate) struct Label<'p, S: Storage> {
    prover: &'p Prover<S>,
    pub(crate) label: Vec<u8>,
    /// Ascending by version, and so by position.
    pub(crate) versions: Vec<VersionRecord>,
    vrf: BTreeMap<u32, (VrfProof, VrfOutput)>,
}

impl<'p, S: Storage> Label<'p, S> {
    /// `label` as of the first `n` entries.
    pub(crate) fn load(prover: &'p Prover<S>, label: &[u8], n: u64) -> Result<Self> {
        if label.len() > 0xff {
            return Err(Error::InvalidArgument("label longer than 255 bytes"));
        }
        let mut versions = prover.store().label_versions(label)?;
        versions.retain(|v| v.position < n);
        let numbered = versions
            .iter()
            .enumerate()
            .all(|(i, v)| u64::from(v.version) == i as u64);
        let ordered = versions
            .windows(2)
            .all(|w| matches!(w, [a, b] if a.position <= b.position));
        if !numbered || !ordered {
            return Err(Error::Storage("label versions out of order".into()));
        }
        Ok(Label {
            prover,
            label: label.to_vec(),
            versions,
            vrf: BTreeMap::new(),
        })
    }

    /// The greatest version in the entry at `x`, if any.
    pub(crate) fn greatest_at(&self, x: u64) -> Option<u32> {
        let count = self.versions.partition_point(|v| v.position <= x);
        count.checked_sub(1).and_then(|i| u32::try_from(i).ok())
    }

    /// The greatest version in the whole tree.
    pub(crate) fn greatest(&self) -> Option<u32> {
        self.versions
            .len()
            .checked_sub(1)
            .and_then(|i| u32::try_from(i).ok())
    }

    /// Whether version `v` is in the entry at `x`'s prefix tree.
    pub(crate) fn included(&self, v: u32, x: u64) -> bool {
        usize::try_from(v)
            .ok()
            .and_then(|i| self.versions.get(i))
            .is_some_and(|r| r.position <= x)
    }

    /// A version's record.
    pub(crate) fn record(&self, v: u32) -> Result<&VersionRecord> {
        usize::try_from(v)
            .ok()
            .and_then(|i| self.versions.get(i))
            .ok_or(Error::InvalidArgument("no such version"))
    }

    fn proved(&mut self, v: u32) -> Result<(VrfProof, VrfOutput)> {
        if let Some(p) = self.vrf.get(&v) {
            return Ok(*p);
        }
        let p = self.prover.vrf_key().prove_label(&self.label, v)?;
        if let Ok(r) = self.record(v) {
            if r.vrf_output != p.1 {
                return Err(Error::Storage("stored VRF output disagrees".into()));
            }
        }
        self.vrf.insert(v, p);
        Ok(p)
    }

    /// Version `v`'s search key.
    pub(crate) fn output(&mut self, v: u32) -> Result<VrfOutput> {
        if let Ok(r) = self.record(v) {
            return Ok(r.vrf_output);
        }
        Ok(self.proved(v)?.1)
    }

    /// A binary ladder step for `v`, with its commitment when asked.
    pub(crate) fn step(&mut self, v: u32, with_commitment: bool) -> Result<BinaryLadderStep> {
        let (proof, _) = self.proved(v)?;
        let commitment = if with_commitment {
            Some(self.record(v)?.commitment)
        } else {
            None
        };
        Ok(BinaryLadderStep { proof, commitment })
    }

    /// Steps for `versions`, in that order, each with its commitment when
    /// `commit(v)` says so.
    pub(crate) fn steps(
        &mut self,
        versions: &[u32],
        commit: impl Fn(u32) -> bool,
    ) -> Result<Vec<BinaryLadderStep>> {
        if versions.len() > 0xffff {
            return Err(Error::Encode("binary ladder too long"));
        }
        versions.iter().map(|&v| self.step(v, commit(v))).collect()
    }

    /// Runs a ladder at `x`: decides each lookup from the log, leaves out
    /// what `omit` allows, and gives the rest as one prefix proof, in ladder
    /// order. A ladder whose lookups are all omitted still gives a proof,
    /// with no results: it carries the entry's prefix root.
    pub(crate) fn ladder(
        &mut self,
        b: &mut Builder<'_, S>,
        x: u64,
        kind: LadderKind,
        mut omit: Option<&mut Omission>,
    ) -> Result<LadderEnd> {
        let mut wanted: Vec<u32> = Vec::new();
        let end = drive(kind, |v| {
            let included = self.included(v, x);
            let skip = omit.as_ref().is_some_and(|o| o.omitted(v, x, included));
            if !skip {
                wanted.push(v);
            }
            if let Some(o) = omit.as_mut() {
                o.record(v, x, included);
            }
            Ok(included)
        })?;
        let keys = wanted
            .iter()
            .map(|&v| self.output(v))
            .collect::<Result<Vec<_>>>()?;
        b.prefix(x, &keys)?;
        Ok(end)
    }
}

/// Appendix B's `base_binary_ladder(t)`: the lookups that establish `t` as
/// the greatest version, in ladder order.
pub(crate) fn base_ladder(t: u32) -> Vec<u32> {
    ladder_versions(LadderKind::Greatest, Some(t))
}

/// The root of the implicit tree of `n` entries.
pub(crate) fn root_of(n: u64) -> Result<u64> {
    tree_root(n)
}
