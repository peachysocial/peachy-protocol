// SPDX-License-Identifier: MIT
//! Evaluating a prefix tree search proof (draft-ietf-keytrans-protocol-05
//! §3.3, §11.9, §12.2): from the keys searched for and a [`PrefixProof`],
//! the root the proof commits to.
//!
//! The prefix tree is keyed by 256-bit VRF outputs, read most significant bit
//! first; bit `d` picks the child at depth `d` (0 left, 1 right). A leaf sits
//! at the shallowest depth where no other key shares its path, so a tree of
//! one leaf is that leaf, and an empty tree's root is 32 zero bytes. Each
//! [`PrefixSearchResult`] names where a search ended and at what depth:
//!
//! - `inclusion`: at the searched key's own leaf, `depth` deep;
//! - `nonInclusionLeaf`: at another key's leaf, which shares the searched
//!   key's first `depth` bits;
//! - `nonInclusionParent`: at a missing child `depth` deep (depth 0 for an
//!   empty tree).
//!
//! Evaluation builds the part of the tree the searches walk (a
//! [`Skeleton`]), fills every node off those paths with the proof's
//! elements, left to right, and hashes. Two searches that end at one node
//! must agree on it. The skeleton is public so the auditor can recompute a
//! root after adding and removing leaves (package A4).

use crate::error::{Error, Result};
use crate::suite::{hash, Hash, VrfOutput, HASH_LEN};
use crate::wire::{PrefixLeaf, PrefixProof, PrefixSearchOutcome, PrefixSearchResult};

/// The value standing in for a missing node.
pub const EMPTY: Hash = [0; HASH_LEN];

/// Bit `i` of a key, most significant first.
pub fn bit(key: &VrfOutput, i: usize) -> bool {
    key.get(i / 8)
        .is_some_and(|b| (b >> (7 - (i % 8))) & 1 == 1)
}

/// A leaf's value: `Hash(0x02 || vrf_output || commitment)`.
pub fn leaf_hash(leaf: &PrefixLeaf) -> Hash {
    hash(&[&[0x02], &leaf.vrf_output, &leaf.commitment])
}

/// A parent's value: `Hash(0x03 || left || right)`, a missing child being
/// [`EMPTY`].
pub fn parent_hash(left: &Hash, right: &Hash) -> Hash {
    hash(&[&[0x03], left, right])
}

/// One key searched for in a batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefixSearch {
    /// The VRF output searched for.
    pub vrf_output: VrfOutput,
    /// Its commitment, needed when the search proves inclusion (the leaf's
    /// value covers it). `None` for a search the caller expects to fail.
    pub commitment: Option<Hash>,
}

/// The part of a prefix tree a proof reveals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Skeleton {
    /// A missing node.
    Empty,
    /// A leaf.
    Leaf(PrefixLeaf),
    /// A parent on some search's path.
    Parent(Box<Skeleton>, Box<Skeleton>),
    /// A node off every search's path, known only by its value (never
    /// [`EMPTY`]: an all-zero element becomes [`Skeleton::Empty`]).
    Copath(Hash),
    /// A node the proof has not filled yet (only during evaluation).
    Unknown,
}

impl Skeleton {
    /// The node's value. An unfilled node has none.
    pub fn hash(&self) -> Result<Hash> {
        match self {
            Skeleton::Empty => Ok(EMPTY),
            Skeleton::Leaf(leaf) => Ok(leaf_hash(leaf)),
            Skeleton::Parent(l, r) => Ok(parent_hash(&l.hash()?, &r.hash()?)),
            Skeleton::Copath(h) => Ok(*h),
            Skeleton::Unknown => Err(Error::MalformedProof("prefix tree node left unfilled")),
        }
    }
}

/// The skeleton `proof` describes for `searches`.
pub fn evaluate_skeleton(searches: &[PrefixSearch], proof: &PrefixProof) -> Result<Skeleton> {
    if searches.len() != proof.results.len() {
        return Err(Error::MalformedProof(
            "prefix results do not match the searches",
        ));
    }
    let mut root = Skeleton::Unknown;
    for (search, result) in searches.iter().zip(&proof.results) {
        place(&mut root, search, result)?;
    }
    let mut elements = proof.elements.iter();
    fill(&mut root, &mut elements)?;
    if elements.next().is_some() {
        return Err(Error::MalformedProof("too many prefix tree elements"));
    }
    Ok(root)
}

/// The root `proof` commits to for `searches`.
pub fn evaluate(searches: &[PrefixSearch], proof: &PrefixProof) -> Result<Hash> {
    evaluate_skeleton(searches, proof)?.hash()
}

/// What a result says ends its search.
fn terminal(search: &PrefixSearch, result: &PrefixSearchResult) -> Result<Skeleton> {
    match result.outcome {
        PrefixSearchOutcome::Inclusion => {
            let commitment = search.commitment.ok_or(Error::MalformedProof(
                "inclusion of a key with no commitment",
            ))?;
            Ok(Skeleton::Leaf(PrefixLeaf {
                vrf_output: search.vrf_output,
                commitment,
            }))
        }
        PrefixSearchOutcome::NonInclusionLeaf { leaf } => {
            let depth = usize::from(result.depth);
            if leaf.vrf_output == search.vrf_output {
                return Err(Error::MalformedProof(
                    "non-inclusion leaf is the searched key",
                ));
            }
            if (0..depth).any(|i| bit(&leaf.vrf_output, i) != bit(&search.vrf_output, i)) {
                return Err(Error::MalformedProof(
                    "non-inclusion leaf is off the searched path",
                ));
            }
            Ok(Skeleton::Leaf(leaf))
        }
        PrefixSearchOutcome::NonInclusionParent => Ok(Skeleton::Empty),
    }
}

fn place(root: &mut Skeleton, search: &PrefixSearch, result: &PrefixSearchResult) -> Result<()> {
    let end = terminal(search, result)?;
    let target = usize::from(result.depth);
    let mut node = root;
    let mut depth = 0usize;
    loop {
        match node {
            Skeleton::Unknown if depth == target => {
                *node = end;
                return Ok(());
            }
            Skeleton::Unknown => {
                *node = Skeleton::Parent(Box::new(Skeleton::Unknown), Box::new(Skeleton::Unknown));
            }
            Skeleton::Parent(l, r) => {
                if depth >= target {
                    return Err(Error::MalformedProof("prefix searches disagree on depth"));
                }
                node = if bit(&search.vrf_output, depth) { r } else { l };
                depth += 1;
            }
            Skeleton::Empty | Skeleton::Leaf(_) => {
                if depth != target || *node != end {
                    return Err(Error::MalformedProof("prefix searches disagree on a node"));
                }
                return Ok(());
            }
            Skeleton::Copath(_) => {
                return Err(Error::MalformedProof("prefix search into a copath node"));
            }
        }
    }
}

fn fill<'a>(node: &mut Skeleton, elements: &mut impl Iterator<Item = &'a Hash>) -> Result<()> {
    match node {
        Skeleton::Parent(l, r) => {
            fill(l, elements)?;
            fill(r, elements)
        }
        Skeleton::Unknown => {
            let value = elements
                .next()
                .ok_or(Error::MalformedProof("too few prefix tree elements"))?;
            *node = if *value == EMPTY {
                Skeleton::Empty
            } else {
                Skeleton::Copath(*value)
            };
            Ok(())
        }
        Skeleton::Empty | Skeleton::Leaf(_) | Skeleton::Copath(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::PrefixSearchResult as R;

    /// A reference prefix tree, built by inserting leaves as §3.3 describes,
    /// that also answers searches with proofs.
    #[derive(Clone)]
    enum Tree {
        Empty,
        Leaf(PrefixLeaf),
        Parent(Box<Tree>, Box<Tree>),
    }

    impl Tree {
        fn insert(self, leaf: PrefixLeaf, depth: usize) -> Tree {
            match self {
                Tree::Empty => Tree::Leaf(leaf),
                Tree::Leaf(other) if other.vrf_output == leaf.vrf_output => Tree::Leaf(leaf),
                Tree::Leaf(other) => {
                    let parent = Tree::Parent(Box::new(Tree::Empty), Box::new(Tree::Empty));
                    parent.insert(other, depth).insert(leaf, depth)
                }
                Tree::Parent(l, r) => {
                    if bit(&leaf.vrf_output, depth) {
                        Tree::Parent(l, Box::new(r.insert(leaf, depth + 1)))
                    } else {
                        Tree::Parent(Box::new(l.insert(leaf, depth + 1)), r)
                    }
                }
            }
        }

        fn hash(&self) -> Hash {
            match self {
                Tree::Empty => EMPTY,
                Tree::Leaf(l) => leaf_hash(l),
                Tree::Parent(l, r) => parent_hash(&l.hash(), &r.hash()),
            }
        }

        /// One search's result.
        fn search(&self, key: &VrfOutput) -> R {
            let mut node = self;
            let mut depth = 0u8;
            loop {
                match node {
                    Tree::Empty => {
                        return R {
                            outcome: PrefixSearchOutcome::NonInclusionParent,
                            depth,
                        }
                    }
                    Tree::Leaf(l) if l.vrf_output == *key => {
                        return R {
                            outcome: PrefixSearchOutcome::Inclusion,
                            depth,
                        }
                    }
                    Tree::Leaf(l) => {
                        return R {
                            outcome: PrefixSearchOutcome::NonInclusionLeaf { leaf: *l },
                            depth,
                        }
                    }
                    Tree::Parent(l, r) => {
                        node = if bit(key, usize::from(depth)) { r } else { l };
                        depth += 1;
                    }
                }
            }
        }

        /// The batch proof for `keys`: copath values left to right.
        fn prove(&self, keys: &[VrfOutput]) -> PrefixProof {
            let results = keys.iter().map(|k| self.search(k)).collect();
            let mut elements = Vec::new();
            self.copath(keys, 0, &mut elements);
            PrefixProof { results, elements }
        }

        fn copath(&self, keys: &[VrfOutput], depth: usize, out: &mut Vec<Hash>) {
            if keys.is_empty() {
                out.push(self.hash());
                return;
            }
            if let Tree::Parent(l, r) = self {
                let (right, left): (Vec<VrfOutput>, Vec<VrfOutput>) =
                    keys.iter().partition(|k| bit(k, depth));
                l.copath(&left, depth + 1, out);
                r.copath(&right, depth + 1, out);
            }
        }
    }

    fn key(first: u8, rest: u8) -> VrfOutput {
        let mut k = [rest; 32];
        k[0] = first;
        k
    }

    fn leaf(k: VrfOutput) -> PrefixLeaf {
        PrefixLeaf {
            vrf_output: k,
            commitment: hash(&[b"c", &k]),
        }
    }

    fn found(k: VrfOutput) -> PrefixSearch {
        PrefixSearch {
            vrf_output: k,
            commitment: Some(leaf(k).commitment),
        }
    }

    fn missing(k: VrfOutput) -> PrefixSearch {
        PrefixSearch {
            vrf_output: k,
            commitment: None,
        }
    }

    #[test]
    fn bits_are_msb_first() {
        let k = key(0b1010_0000, 0x01);
        assert!(bit(&k, 0));
        assert!(!bit(&k, 1));
        assert!(bit(&k, 2));
        assert!(bit(&k, 15));
        assert!(!bit(&k, 256));
    }

    #[test]
    fn hash_vectors() {
        let l = PrefixLeaf {
            vrf_output: [1; 32],
            commitment: [2; 32],
        };
        let mut input = vec![0x02];
        input.extend([1u8; 32]);
        input.extend([2u8; 32]);
        assert_eq!(leaf_hash(&l), hash(&[&input]));
        let mut input = vec![0x03];
        input.extend([0u8; 64]);
        assert_eq!(parent_hash(&EMPTY, &EMPTY), hash(&[&input]));
    }

    #[test]
    fn empty_and_single_leaf_trees() {
        let k = key(0x80, 0);
        // An empty tree: non-inclusion at depth 0, root of zeros.
        let proof = PrefixProof {
            results: vec![R {
                outcome: PrefixSearchOutcome::NonInclusionParent,
                depth: 0,
            }],
            elements: vec![],
        };
        assert_eq!(evaluate(&[missing(k)], &proof).unwrap(), EMPTY);
        // One leaf: the root is the leaf.
        let tree = Tree::Empty.insert(leaf(k), 0);
        assert_eq!(tree.hash(), leaf_hash(&leaf(k)));
        let proof = tree.prove(&[k]);
        assert_eq!(proof.results[0].depth, 0);
        assert_eq!(evaluate(&[found(k)], &proof).unwrap(), tree.hash());
        // Another key against that tree ends at the leaf, depth 0.
        let other = key(0x00, 0);
        let proof = tree.prove(&[other]);
        assert_eq!(evaluate(&[missing(other)], &proof).unwrap(), tree.hash());
    }

    #[test]
    fn figure_5_shape() {
        // Keys starting 00010, 00101, 10001, 10111, 11011.
        let keys: Vec<VrfOutput> = [
            0b0001_0000u8,
            0b0010_1000,
            0b1000_1000,
            0b1011_1000,
            0b1101_1000,
        ]
        .iter()
        .map(|&b| key(b, 0))
        .collect();
        let mut tree = Tree::Empty;
        for k in &keys {
            tree = tree.insert(leaf(*k), 0);
        }
        // 00010 sits at depth 3 (it parts from 00101 at bit 2); 11011 at depth 2.
        assert_eq!(tree.search(&keys[0]).depth, 3);
        assert_eq!(tree.search(&keys[4]).depth, 2);
        // A key starting 01 ends at the root's left child's missing right child.
        let k01 = key(0b0110_1000, 0);
        let r = tree.search(&k01);
        assert_eq!(r.outcome, PrefixSearchOutcome::NonInclusionParent);
        assert_eq!(r.depth, 2);
        let mut searches: Vec<PrefixSearch> = keys.iter().map(|k| found(*k)).collect();
        searches.push(missing(k01));
        let mut all = keys.clone();
        all.push(k01);
        let proof = tree.prove(&all);
        assert_eq!(evaluate(&searches, &proof).unwrap(), tree.hash());
    }

    /// Deterministic pseudo-random keys.
    fn keys(seed: u64, n: usize) -> Vec<VrfOutput> {
        (0..n)
            .map(|i| hash(&[&seed.to_be_bytes(), &(i as u64).to_be_bytes()]))
            .collect()
    }

    #[test]
    fn random_trees_and_batches() {
        for size in [0usize, 1, 2, 3, 5, 17, 64, 200] {
            let present = keys(size as u64, size);
            let mut tree = Tree::Empty;
            for k in &present {
                tree = tree.insert(leaf(*k), 0);
            }
            let absent = keys(1000 + size as u64, 8);
            // Batches: every present key alone, all present keys, mixtures
            // with absent keys, a duplicated key.
            let mut batches: Vec<Vec<(VrfOutput, bool)>> =
                present.iter().map(|k| vec![(*k, true)]).collect();
            batches.push(present.iter().map(|k| (*k, true)).collect());
            batches.push(absent.iter().map(|k| (*k, false)).collect());
            let mut mixed: Vec<(VrfOutput, bool)> =
                present.iter().take(4).map(|k| (*k, true)).collect();
            mixed.extend(absent.iter().take(4).map(|k| (*k, false)));
            if let Some(first) = present.first() {
                mixed.push((*first, true));
            }
            batches.push(mixed);
            for batch in batches {
                let ks: Vec<VrfOutput> = batch.iter().map(|(k, _)| *k).collect();
                let searches: Vec<PrefixSearch> = batch
                    .iter()
                    .map(|(k, p)| if *p { found(*k) } else { missing(*k) })
                    .collect();
                let proof = tree.prove(&ks);
                assert_eq!(
                    evaluate(&searches, &proof).unwrap(),
                    tree.hash(),
                    "size {size}"
                );
            }
        }
    }

    #[test]
    fn malformed_proofs_fail() {
        let present = keys(7, 20);
        let mut tree = Tree::Empty;
        for k in &present {
            tree = tree.insert(leaf(*k), 0);
        }
        let ks = vec![present[0], present[5]];
        let searches = vec![found(present[0]), found(present[5])];
        let proof = tree.prove(&ks);
        let root = tree.hash();
        assert_eq!(evaluate(&searches, &proof).unwrap(), root);

        // Wrong number of elements or results.
        let mut p = proof.clone();
        p.elements.pop();
        assert_eq!(
            evaluate(&searches, &p),
            Err(Error::MalformedProof("too few prefix tree elements"))
        );
        let mut p = proof.clone();
        p.elements.push([1; 32]);
        assert_eq!(
            evaluate(&searches, &p),
            Err(Error::MalformedProof("too many prefix tree elements"))
        );
        assert!(evaluate(&searches[..1], &proof).is_err());
        // A changed element, commitment or depth moves the root or fails.
        let mut p = proof.clone();
        p.elements[0][0] ^= 1;
        assert_ne!(evaluate(&searches, &p).unwrap(), root);
        let mut s = searches.clone();
        s[0].commitment = Some([9; 32]);
        assert_ne!(evaluate(&s, &proof).unwrap(), root);
        let mut p = proof.clone();
        p.results[0].depth += 1;
        assert!(evaluate(&searches, &p).map(|r| r != root).unwrap_or(true));
        // Inclusion without a commitment.
        assert!(evaluate(&[missing(present[0]), found(present[5])], &proof).is_err());
        // A non-inclusion leaf that is the key itself, or off its path.
        let k = present[0];
        let bad = PrefixProof {
            results: vec![R {
                outcome: PrefixSearchOutcome::NonInclusionLeaf { leaf: leaf(k) },
                depth: 0,
            }],
            elements: vec![],
        };
        assert!(evaluate(&[missing(k)], &bad).is_err());
        let mut off = leaf(k);
        off.vrf_output[0] ^= 0x80;
        let bad = PrefixProof {
            results: vec![R {
                outcome: PrefixSearchOutcome::NonInclusionLeaf { leaf: off },
                depth: 1,
            }],
            elements: vec![],
        };
        assert!(evaluate(&[missing(k)], &bad).is_err());
        // Two searches for one key that disagree.
        let disagree = PrefixProof {
            results: vec![
                R {
                    outcome: PrefixSearchOutcome::NonInclusionParent,
                    depth: 0,
                },
                R {
                    outcome: PrefixSearchOutcome::NonInclusionParent,
                    depth: 1,
                },
            ],
            elements: vec![],
        };
        assert!(evaluate(&[missing(k), missing(k)], &disagree).is_err());
        let disagree = PrefixProof {
            results: vec![
                R {
                    outcome: PrefixSearchOutcome::Inclusion,
                    depth: 0,
                },
                R {
                    outcome: PrefixSearchOutcome::NonInclusionParent,
                    depth: 0,
                },
            ],
            elements: vec![],
        };
        assert!(evaluate(&[found(k), missing(k)], &disagree).is_err());
    }

    #[test]
    fn the_skeleton_exposes_what_was_proved() {
        let present = keys(3, 6);
        let mut tree = Tree::Empty;
        for k in &present {
            tree = tree.insert(leaf(*k), 0);
        }
        let proof = tree.prove(&[present[2]]);
        let skeleton = evaluate_skeleton(&[found(present[2])], &proof).unwrap();
        assert_eq!(skeleton.hash().unwrap(), tree.hash());
        assert!(Skeleton::Unknown.hash().is_err());
    }
}
