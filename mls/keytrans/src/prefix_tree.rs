// SPDX-License-Identifier: MIT
//! The prefix tree itself: storage-backed insertion and proof generation
//! (draft-ietf-keytrans-protocol-05 §3.3, §12.2).
//!
//! Compiled with the `prover` feature (and in tests). Proof *evaluation*,
//! which clients and the auditor share, is [`crate::prefix_proof`]: a proof
//! this module produces evaluates there to the tree's root.
//!
//! # A persistent, content-addressed tree
//!
//! Every node is stored under its own value ([`PrefixNode::hash`]), and a
//! node is never changed once written: inserting leaves writes a new path
//! from each new leaf up to a new root and leaves every older node where it
//! was. So each log entry's prefix tree is just its root value, every older
//! tree stays provable, and the storage behind a [`NodeSource`] is a plain
//! key-value map that only grows. A missing child is
//! [`EMPTY`](crate::prefix_proof::EMPTY) and is never stored.
//!
//! The shape is the one [`crate::prefix_proof`] evaluates: a leaf sits at the
//! shallowest depth where no other key shares its path, so every parent has
//! at least two leaves beneath it. Insertion keeps that shape. Removal, which
//! only a log with a maximum lifetime needs (§7.1), is not implemented: a
//! log built on this module keeps every entry.

use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::prefix_proof::{bit, leaf_hash, parent_hash, EMPTY};
use crate::suite::{Hash, VrfOutput, HASH_LEN, VRF_OUTPUT_LEN};
use crate::wire::{PrefixLeaf, PrefixProof, PrefixSearchOutcome, PrefixSearchResult};

/// The deepest a leaf can sit: a result's depth is a `uint8` on the wire.
const MAX_DEPTH: usize = 255;

/// One stored node of the prefix tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefixNode {
    /// A leaf: one key and its commitment.
    Leaf(PrefixLeaf),
    /// A parent, by its children's values ([`EMPTY`] for a missing child).
    Parent {
        /// The left child's value.
        left: Hash,
        /// The right child's value.
        right: Hash,
    },
}

impl PrefixNode {
    /// The node's value (§11.9), the key it is stored under.
    pub fn hash(&self) -> Hash {
        match self {
            PrefixNode::Leaf(leaf) => leaf_hash(leaf),
            PrefixNode::Parent { left, right } => parent_hash(left, right),
        }
    }

    /// The node's storage encoding, which is also the input its value hashes:
    /// `0x02 || vrf_output || commitment` for a leaf, `0x03 || left || right`
    /// for a parent.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 2 * HASH_LEN);
        match self {
            PrefixNode::Leaf(leaf) => {
                out.push(0x02);
                out.extend_from_slice(&leaf.vrf_output);
                out.extend_from_slice(&leaf.commitment);
            }
            PrefixNode::Parent { left, right } => {
                out.push(0x03);
                out.extend_from_slice(left);
                out.extend_from_slice(right);
            }
        }
        out
    }

    /// Decodes [`PrefixNode::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (tag, rest) = bytes
            .split_first()
            .ok_or_else(|| Error::Decode("empty prefix node".into()))?;
        if rest.len() != VRF_OUTPUT_LEN + HASH_LEN {
            return Err(Error::Decode("prefix node of the wrong length".into()));
        }
        let (a, b) = rest.split_at(HASH_LEN);
        let a: Hash = a
            .try_into()
            .map_err(|_| Error::Decode("prefix node".into()))?;
        let b: Hash = b
            .try_into()
            .map_err(|_| Error::Decode("prefix node".into()))?;
        match tag {
            0x02 => Ok(PrefixNode::Leaf(PrefixLeaf {
                vrf_output: a,
                commitment: b,
            })),
            0x03 => Ok(PrefixNode::Parent { left: a, right: b }),
            _ => Err(Error::Decode("unknown prefix node tag".into())),
        }
    }
}

/// Where the prefix tree's nodes are read from.
pub trait NodeSource {
    /// The node stored under `hash`. Never asked for [`EMPTY`]. A node the
    /// source should hold and does not is [`Error::Storage`].
    fn prefix_node(&self, hash: &Hash) -> Result<PrefixNode>;
}

impl NodeSource for BTreeMap<Hash, PrefixNode> {
    fn prefix_node(&self, hash: &Hash) -> Result<PrefixNode> {
        self.get(hash)
            .copied()
            .ok_or_else(|| Error::Storage("prefix node missing".into()))
    }
}

/// What inserting a batch of leaves produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Insertion {
    /// The new tree's root.
    pub root: Hash,
    /// Every node the new tree has and the old one did not, each once, to be
    /// stored under its value.
    pub nodes: Vec<(Hash, PrefixNode)>,
}

/// Inserts `leaves` into the tree whose root is `root` ([`EMPTY`] for an
/// empty tree), in any order. Refuses a key already in the tree or given
/// twice, and (with negligible probability for VRF outputs) two keys that
/// share their first 255 bits.
pub fn insert(source: &impl NodeSource, root: &Hash, leaves: &[PrefixLeaf]) -> Result<Insertion> {
    let mut sorted = leaves.to_vec();
    sorted.sort_by_key(|a| a.vrf_output);
    if sorted
        .windows(2)
        .any(|w| matches!(w, [a, b] if a.vrf_output == b.vrf_output))
    {
        return Err(Error::InvalidArgument("one key inserted twice"));
    }
    let mut out = BTreeMap::new();
    let root = insert_at(source, *root, 0, &sorted, &mut out)?;
    Ok(Insertion {
        root,
        nodes: out.into_iter().collect(),
    })
}

fn emit(node: PrefixNode, out: &mut BTreeMap<Hash, PrefixNode>) -> Hash {
    let h = node.hash();
    out.insert(h, node);
    h
}

/// Splits keys that share their first `depth` bits by bit `depth`. They are
/// sorted, so the zeros come first.
fn split(leaves: &[PrefixLeaf], depth: usize) -> (&[PrefixLeaf], &[PrefixLeaf]) {
    let at = leaves
        .iter()
        .position(|l| bit(&l.vrf_output, depth))
        .unwrap_or(leaves.len());
    leaves.split_at(at)
}

fn insert_at(
    source: &impl NodeSource,
    node: Hash,
    depth: usize,
    leaves: &[PrefixLeaf],
    out: &mut BTreeMap<Hash, PrefixNode>,
) -> Result<Hash> {
    if leaves.is_empty() {
        return Ok(node);
    }
    if node == EMPTY {
        return build(depth, leaves, out);
    }
    match source.prefix_node(&node)? {
        PrefixNode::Leaf(old) => {
            if leaves.iter().any(|l| l.vrf_output == old.vrf_output) {
                return Err(Error::InvalidArgument("key already in the prefix tree"));
            }
            let mut all = leaves.to_vec();
            let at = all.partition_point(|l| l.vrf_output < old.vrf_output);
            all.insert(at, old);
            build(depth, &all, out)
        }
        PrefixNode::Parent { left, right } => {
            let (l, r) = split(leaves, depth);
            let left = insert_at(source, left, depth + 1, l, out)?;
            let right = insert_at(source, right, depth + 1, r, out)?;
            Ok(emit(PrefixNode::Parent { left, right }, out))
        }
    }
}

/// A fresh subtree at `depth` holding exactly `leaves` (sorted, distinct,
/// sharing their first `depth` bits, at least one).
fn build(
    depth: usize,
    leaves: &[PrefixLeaf],
    out: &mut BTreeMap<Hash, PrefixNode>,
) -> Result<Hash> {
    if depth > MAX_DEPTH {
        return Err(Error::InvalidArgument("prefix tree leaf too deep"));
    }
    match leaves {
        [] => Ok(EMPTY),
        [leaf] => Ok(emit(PrefixNode::Leaf(*leaf), out)),
        _ => {
            let (l, r) = split(leaves, depth);
            let left = build(depth + 1, l, out)?;
            let right = build(depth + 1, r, out)?;
            Ok(emit(PrefixNode::Parent { left, right }, out))
        }
    }
}

/// The leaf for `key` in the tree whose root is `root`, if the key is there.
pub fn lookup(
    source: &impl NodeSource,
    root: &Hash,
    key: &VrfOutput,
) -> Result<Option<PrefixLeaf>> {
    let mut node = *root;
    let mut depth = 0usize;
    loop {
        if node == EMPTY {
            return Ok(None);
        }
        match source.prefix_node(&node)? {
            PrefixNode::Leaf(leaf) => {
                return Ok((leaf.vrf_output == *key).then_some(leaf));
            }
            PrefixNode::Parent { left, right } => {
                node = if bit(key, depth) { right } else { left };
                depth += 1;
                if depth > MAX_DEPTH + 1 {
                    return Err(Error::Storage("prefix tree deeper than its keys".into()));
                }
            }
        }
    }
}

/// The batch search proof (§12.2) for `keys`, in that order, in the tree
/// whose root is `root`: what [`crate::prefix_proof::evaluate`] turns back
/// into `root`. A key may repeat; its results then repeat.
pub fn prove(source: &impl NodeSource, root: &Hash, keys: &[VrfOutput]) -> Result<PrefixProof> {
    let mut results: Vec<Option<PrefixSearchResult>> = vec![None; keys.len()];
    let mut elements = Vec::new();
    let all: Vec<usize> = (0..keys.len()).collect();
    prove_at(source, *root, 0, keys, &all, &mut results, &mut elements)?;
    let results = results
        .into_iter()
        .map(|r| r.ok_or_else(|| Error::Storage("prefix search left unresolved".into())))
        .collect::<Result<Vec<_>>>()?;
    Ok(PrefixProof { results, elements })
}

fn depth_u8(depth: usize) -> Result<u8> {
    u8::try_from(depth)
        .map_err(|_| Error::Storage("prefix tree deeper than a result can say".into()))
}

fn prove_at(
    source: &impl NodeSource,
    node: Hash,
    depth: usize,
    keys: &[VrfOutput],
    here: &[usize],
    results: &mut [Option<PrefixSearchResult>],
    elements: &mut Vec<Hash>,
) -> Result<()> {
    if here.is_empty() {
        // Off every search's path: the proof carries the node's value.
        elements.push(node);
        return Ok(());
    }
    let mut set = |outcome: PrefixSearchOutcome| -> Result<()> {
        let d = depth_u8(depth)?;
        for &i in here {
            let outcome = match outcome {
                PrefixSearchOutcome::NonInclusionLeaf { leaf }
                    if keys.get(i).is_some_and(|k| *k == leaf.vrf_output) =>
                {
                    PrefixSearchOutcome::Inclusion
                }
                other => other,
            };
            if let Some(slot) = results.get_mut(i) {
                *slot = Some(PrefixSearchResult { outcome, depth: d });
            }
        }
        Ok(())
    };
    if node == EMPTY {
        return set(PrefixSearchOutcome::NonInclusionParent);
    }
    match source.prefix_node(&node)? {
        PrefixNode::Leaf(leaf) => set(PrefixSearchOutcome::NonInclusionLeaf { leaf }),
        PrefixNode::Parent { left, right } => {
            let (r, l): (Vec<usize>, Vec<usize>) = here
                .iter()
                .partition(|&&i| keys.get(i).is_some_and(|k| bit(k, depth)));
            prove_at(source, left, depth + 1, keys, &l, results, elements)?;
            prove_at(source, right, depth + 1, keys, &r, results, elements)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prefix_proof::{evaluate, PrefixSearch};
    use crate::suite::hash;

    fn leaf(i: u32) -> PrefixLeaf {
        PrefixLeaf {
            vrf_output: hash(&[b"key", &i.to_be_bytes()]),
            commitment: hash(&[b"commitment", &i.to_be_bytes()]),
        }
    }

    fn key(i: u32) -> VrfOutput {
        leaf(i).vrf_output
    }

    fn searches(keys: &[VrfOutput], tree: &[PrefixLeaf]) -> Vec<PrefixSearch> {
        keys.iter()
            .map(|k| PrefixSearch {
                vrf_output: *k,
                commitment: tree
                    .iter()
                    .find(|l| l.vrf_output == *k)
                    .map(|l| l.commitment),
            })
            .collect()
    }

    #[test]
    fn empty_tree_proves_to_empty() {
        let store = BTreeMap::new();
        let proof = prove(&store, &EMPTY, &[key(1), key(2)]).unwrap();
        assert!(proof
            .results
            .iter()
            .all(|r| r.outcome == PrefixSearchOutcome::NonInclusionParent && r.depth == 0));
        assert_eq!(
            evaluate(&searches(&[key(1), key(2)], &[]), &proof).unwrap(),
            EMPTY
        );
        let none = prove(&store, &EMPTY, &[]).unwrap();
        assert_eq!(none.elements, vec![EMPTY]);
    }

    #[test]
    fn batches_and_one_at_a_time_agree_and_every_proof_evaluates() {
        let mut store = BTreeMap::new();
        let mut one = EMPTY;
        let mut all = Vec::new();
        let mut roots = vec![EMPTY];
        for i in 0..60u32 {
            let ins = insert(&store, &one, &[leaf(i)]).unwrap();
            store.extend(ins.nodes);
            one = ins.root;
            all.push(leaf(i));
            roots.push(one);
        }
        let mut store2 = BTreeMap::new();
        let batched = insert(&store2, &EMPTY, &all[..25]).unwrap();
        store2.extend(batched.nodes);
        let batched = insert(&store2, &batched.root, &all[25..]).unwrap();
        store2.extend(batched.nodes);
        assert_eq!(batched.root, one);

        // Every older tree is still provable, for members and non-members.
        for (size, root) in roots.iter().enumerate() {
            let keys: Vec<VrfOutput> = (0..70u32).step_by(3).map(key).collect();
            let proof = prove(&store, root, &keys).unwrap();
            let got = evaluate(&searches(&keys, &all[..size]), &proof).unwrap();
            assert_eq!(&got, root, "size {size}");
            for (k, r) in keys.iter().zip(&proof.results) {
                let member = all[..size].iter().any(|l| l.vrf_output == *k);
                assert_eq!(r.outcome == PrefixSearchOutcome::Inclusion, member);
                assert_eq!(lookup(&store, root, k).unwrap().is_some(), member);
            }
        }
    }

    #[test]
    fn refuses_duplicates() {
        let mut store = BTreeMap::new();
        let ins = insert(&store, &EMPTY, &[leaf(1), leaf(2)]).unwrap();
        store.extend(ins.nodes);
        assert!(insert(&store, &ins.root, &[leaf(2)]).is_err());
        assert!(insert(&store, &ins.root, &[leaf(3), leaf(3)]).is_err());
    }

    #[test]
    fn node_bytes_round_trip_and_hash_their_encoding() {
        let nodes = [
            PrefixNode::Leaf(leaf(7)),
            PrefixNode::Parent {
                left: EMPTY,
                right: leaf_hash(&leaf(8)),
            },
        ];
        for n in nodes {
            let bytes = n.to_bytes();
            assert_eq!(PrefixNode::from_bytes(&bytes).unwrap(), n);
            assert_eq!(hash(&[&bytes]), n.hash());
        }
        assert!(PrefixNode::from_bytes(&[0x04; 65]).is_err());
        assert!(PrefixNode::from_bytes(&[0x02; 64]).is_err());
    }
}
