// SPDX-License-Identifier: MIT
//! The log tree (draft-ietf-keytrans-protocol-05 §3.2, §11.8, §12.1): a
//! left-balanced binary tree over log entries, and the batch proofs that
//! combine inclusion and consistency.
//!
//! # Subtrees
//!
//! Proofs only ever carry the heads of *balanced* subtrees, which this module
//! names by [`Subtree`]: a power-of-two run of leaves starting at a multiple
//! of its size. A tree of `n` leaves has one balanced subtree per set bit of
//! `n`, its [`full_subtrees`]; its root is their right fold.
//!
//! # Batch proofs
//!
//! An [`InclusionProof`] carries the fewest balanced-subtree heads that, with
//! the values the verifier already has, compute every root it needs. What
//! the verifier has: the leaves whose log entries it was given, and the full
//! subtrees of the last tree size it verified (when it advertised one). What
//! it needs: the root of the current tree, plus the root at each auditor's
//! tree size (spec §5.2 has one auditor head per auditor).
//!
//! Both sides compute the same list of subtrees from a [`BatchSpec`] with
//! [`batch_positions`]: the prover fills it with values, the verifier zips it
//! with the proof's elements. The walk: for each full subtree of the current
//! tree, left to right, a subtree is split in two if any leaf, retained
//! subtree or target lies strictly inside it; otherwise a retained subtree or
//! leaf supplies its own value, and anything else is the next element. When a
//! retained subtree is split, the verifier recomputes it and requires the
//! retained value (the §12.1 MUST).

use std::collections::BTreeMap;

use crate::codec::encode;
use crate::error::{Error, Result};
use crate::suite::{hash, Hash};
use crate::wire::{InclusionProof, LogEntry};

/// A balanced subtree of the log tree: `size` leaves (a power of two)
/// starting at `start` (a multiple of `size`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Subtree {
    /// The index of its leftmost leaf.
    pub start: u64,
    /// Its number of leaves.
    pub size: u64,
}

impl Subtree {
    /// The subtree, if `size` is a power of two and `start` a multiple of it.
    pub fn new(start: u64, size: u64) -> Result<Self> {
        if !size.is_power_of_two()
            || !start.is_multiple_of(size)
            || start.checked_add(size).is_none()
        {
            return Err(Error::InvalidArgument("not a balanced subtree"));
        }
        Ok(Subtree { start, size })
    }

    /// The single leaf at `index`.
    pub fn leaf(index: u64) -> Self {
        Subtree {
            start: index,
            size: 1,
        }
    }

    /// One past its rightmost leaf.
    pub fn end(&self) -> u64 {
        self.start + self.size
    }

    /// Whether it is a single leaf (hashed with the leaf prefix as a child).
    pub fn is_leaf(&self) -> bool {
        self.size == 1
    }

    /// Its two halves, unless it is a leaf.
    pub fn children(&self) -> Option<(Subtree, Subtree)> {
        if self.is_leaf() {
            return None;
        }
        let half = self.size / 2;
        Some((
            Subtree {
                start: self.start,
                size: half,
            },
            Subtree {
                start: self.start + half,
                size: half,
            },
        ))
    }

    /// Whether `other` lies inside it and is not it.
    pub fn strictly_contains(&self, other: &Subtree) -> bool {
        self != other && self.start <= other.start && other.end() <= self.end()
    }
}

/// The full subtrees of a tree of `n` leaves, left to right: the largest
/// balanced subtrees whose parents are not balanced (§4.2). Empty for 0.
pub fn full_subtrees(n: u64) -> Vec<Subtree> {
    let mut out = Vec::with_capacity(n.count_ones() as usize);
    let mut start = 0;
    for bit in (0..64).rev() {
        let size = 1u64 << bit;
        if n & size != 0 {
            out.push(Subtree { start, size });
            start += size;
        }
    }
    out
}

/// A leaf's value: the hash of its encoded [`LogEntry`] (§11.8).
pub fn leaf_hash(entry: &LogEntry) -> Result<Hash> {
    Ok(hash(&[&encode(entry)?]))
}

/// A parent's value from its children's (§11.8): each child's value is
/// prefixed 0x00 if the child is a leaf, 0x01 if it is a parent.
pub fn parent_hash(left: &Hash, left_is_leaf: bool, right: &Hash, right_is_leaf: bool) -> Hash {
    let tag = |leaf: bool| if leaf { [0x00u8] } else { [0x01u8] };
    hash(&[&tag(left_is_leaf), left, &tag(right_is_leaf), right])
}

/// The root of a tree from the values of its full subtrees, in the order
/// [`full_subtrees`] gives them.
pub fn root_from_full_subtrees(full: &[(Subtree, Hash)]) -> Result<Hash> {
    let mut iter = full.iter().rev();
    let (last, last_value) = iter
        .next()
        .ok_or(Error::InvalidArgument("an empty tree has no root"))?;
    let mut acc = *last_value;
    let mut acc_is_leaf = last.is_leaf();
    for (subtree, value) in iter {
        acc = parent_hash(value, subtree.is_leaf(), &acc, acc_is_leaf);
        acc_is_leaf = false;
    }
    Ok(acc)
}

/// What a batch proof covers. Prover and verifier must build the same one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BatchSpec {
    /// The number of leaves in the tree the proof is against. At least 1.
    pub tree_size: u64,
    /// The leaves whose values the verifier has, in any order: every log
    /// entry whose timestamp the response carries.
    pub leaves: Vec<u64>,
    /// The tree size the verifier advertised; it holds that size's full
    /// subtrees. At most `tree_size`.
    pub retained_size: Option<u64>,
    /// More tree sizes whose roots the proof must also yield: each auditor
    /// head's `tree_size`. Each in `1..=tree_size`.
    pub extra_sizes: Vec<u64>,
}

impl BatchSpec {
    fn check(&self) -> Result<()> {
        let n = self.tree_size;
        if n == 0 {
            return Err(Error::InvalidArgument("a proof needs a non-empty tree"));
        }
        if self.leaves.iter().any(|&leaf| leaf >= n) {
            return Err(Error::InvalidArgument("leaf outside the tree"));
        }
        if self.retained_size.is_some_and(|m| m > n) {
            return Err(Error::InvalidArgument("retained size beyond the tree"));
        }
        if self.extra_sizes.iter().any(|&s| s == 0 || s > n) {
            return Err(Error::InvalidArgument("extra size outside the tree"));
        }
        Ok(())
    }

    fn retained(&self) -> Vec<Subtree> {
        self.retained_size.map(full_subtrees).unwrap_or_default()
    }

    /// Every subtree the verifier has or needs.
    fn interesting(&self) -> Vec<Subtree> {
        let mut out: Vec<Subtree> = self.leaves.iter().map(|&l| Subtree::leaf(l)).collect();
        out.extend(self.retained());
        for &size in &self.extra_sizes {
            out.extend(full_subtrees(size));
        }
        out.sort();
        out.dedup();
        out
    }
}

/// The balanced subtrees whose heads a proof for `spec` carries, in the
/// order its elements list them.
pub fn batch_positions(spec: &BatchSpec) -> Result<Vec<Subtree>> {
    spec.check()?;
    let interesting = spec.interesting();
    let mut leaves: Vec<u64> = spec.leaves.clone();
    leaves.sort_unstable();
    leaves.dedup();
    let retained = spec.retained();
    let mut out = Vec::new();
    for top in full_subtrees(spec.tree_size) {
        walk(top, &interesting, &leaves, &retained, &mut out);
    }
    Ok(out)
}

fn walk(
    r: Subtree,
    interesting: &[Subtree],
    leaves: &[u64],
    retained: &[Subtree],
    out: &mut Vec<Subtree>,
) {
    if let Some((left, right)) = r.children() {
        if interesting.iter().any(|s| r.strictly_contains(s)) {
            walk(left, interesting, leaves, retained, out);
            walk(right, interesting, leaves, retained, out);
            return;
        }
    }
    let known = (r.is_leaf() && leaves.binary_search(&r.start).is_ok()) || retained.contains(&r);
    if !known {
        out.push(r);
    }
}

/// Builds the proof for `spec`, asking `value_of` for each subtree head it
/// carries.
pub fn prove_batch(
    spec: &BatchSpec,
    mut value_of: impl FnMut(Subtree) -> Result<Hash>,
) -> Result<InclusionProof> {
    let positions = batch_positions(spec)?;
    if positions.len() > 0xffff {
        return Err(Error::Encode(
            "inclusion proof longer than its length prefix",
        ));
    }
    let elements = positions
        .into_iter()
        .map(&mut value_of)
        .collect::<Result<Vec<_>>>()?;
    Ok(InclusionProof { elements })
}

/// What a verified batch proof establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchRoots {
    /// The root of the tree at `tree_size`.
    pub root: Hash,
    /// The root at each of `extra_sizes`, in that order.
    pub extra_roots: Vec<Hash>,
    /// The full subtrees' values at each of `extra_sizes`, in that order:
    /// what a verifier retains for a tree size it may later be shown a
    /// consistency proof from (a distinguished entry's, draft §14.2.1).
    pub extra_full_subtrees: Vec<Vec<Hash>>,
    /// The values of the tree's full subtrees, in order: what the verifier
    /// retains for the next consistency proof.
    pub full_subtrees: Vec<Hash>,
}

/// Verifies `proof` for `spec`.
///
/// `leaf_values` gives the value ([`leaf_hash`]) of every leaf in
/// `spec.leaves`; `retained` the values of `spec.retained_size`'s full
/// subtrees, in order. Fails if the proof has the wrong number of elements,
/// or recomputes a retained subtree to anything but its retained value.
pub fn verify_batch(
    spec: &BatchSpec,
    leaf_values: &[(u64, Hash)],
    retained: &[Hash],
    proof: &InclusionProof,
) -> Result<BatchRoots> {
    let positions = batch_positions(spec)?;
    if positions.len() != proof.elements.len() {
        return Err(Error::MalformedProof("wrong number of log tree elements"));
    }

    let retained_subtrees = spec.retained();
    if retained_subtrees.len() != retained.len() {
        return Err(Error::InvalidArgument(
            "retained values do not match the retained size",
        ));
    }
    let retained: BTreeMap<Subtree, Hash> = retained_subtrees
        .iter()
        .copied()
        .zip(retained.iter().copied())
        .collect();

    let mut leaves: BTreeMap<u64, Hash> = BTreeMap::new();
    for (index, value) in leaf_values {
        if let Some(previous) = leaves.insert(*index, *value) {
            if previous != *value {
                return Err(Error::InvalidArgument("two values for one leaf"));
            }
        }
    }
    let mut wanted = spec.leaves.clone();
    wanted.sort_unstable();
    wanted.dedup();
    if !wanted.iter().copied().eq(leaves.keys().copied()) {
        return Err(Error::InvalidArgument(
            "leaf values do not match the spec's leaves",
        ));
    }

    let elements: BTreeMap<Subtree, Hash> = positions
        .into_iter()
        .zip(proof.elements.iter().copied())
        .collect();
    let mut eval = Evaluator {
        interesting: spec.interesting(),
        leaves: &leaves,
        retained: &retained,
        elements: &elements,
        values: BTreeMap::new(),
    };

    let full = full_subtrees(spec.tree_size);
    let mut full_values = Vec::with_capacity(full.len());
    for top in &full {
        full_values.push((*top, eval.value(*top)?));
    }
    let root = root_from_full_subtrees(&full_values)?;
    let mut extra_roots = Vec::with_capacity(spec.extra_sizes.len());
    let mut extra_full_subtrees = Vec::with_capacity(spec.extra_sizes.len());
    for &size in &spec.extra_sizes {
        let pairs = full_subtrees(size)
            .into_iter()
            .map(|s| {
                eval.values
                    .get(&s)
                    .map(|v| (s, *v))
                    .ok_or(Error::MalformedProof("extra root not reached"))
            })
            .collect::<Result<Vec<_>>>()?;
        extra_roots.push(root_from_full_subtrees(&pairs)?);
        extra_full_subtrees.push(pairs.into_iter().map(|(_, v)| v).collect());
    }
    Ok(BatchRoots {
        root,
        extra_roots,
        extra_full_subtrees,
        full_subtrees: full_values.into_iter().map(|(_, v)| v).collect(),
    })
}

struct Evaluator<'a> {
    interesting: Vec<Subtree>,
    leaves: &'a BTreeMap<u64, Hash>,
    retained: &'a BTreeMap<Subtree, Hash>,
    elements: &'a BTreeMap<Subtree, Hash>,
    values: BTreeMap<Subtree, Hash>,
}

impl Evaluator<'_> {
    fn value(&mut self, r: Subtree) -> Result<Hash> {
        let split = r
            .children()
            .filter(|_| self.interesting.iter().any(|s| r.strictly_contains(s)));
        let computed = match split {
            Some((left, right)) => {
                let l = self.value(left)?;
                let rv = self.value(right)?;
                Some(parent_hash(&l, left.is_leaf(), &rv, right.is_leaf()))
            }
            None if r.is_leaf() => self.leaves.get(&r.start).copied(),
            None => None,
        };
        let value = match (computed, self.retained.get(&r)) {
            (Some(v), Some(kept)) if v != *kept => {
                return Err(Error::ProofMismatch(
                    "log tree disagrees with a retained subtree",
                ));
            }
            (Some(v), _) => v,
            (None, Some(kept)) => *kept,
            (None, None) => *self
                .elements
                .get(&r)
                .ok_or(Error::MalformedProof("log tree element missing"))?,
        };
        self.values.insert(r, value);
        Ok(value)
    }
}

/// An in-memory log tree of leaf values, for tests and small tools: computes
/// any balanced subtree's head, memoized.
#[derive(Debug, Clone, Default)]
pub struct MemoryLog {
    leaves: Vec<Hash>,
    memo: BTreeMap<Subtree, Hash>,
}

impl MemoryLog {
    /// An empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a leaf value.
    pub fn push(&mut self, leaf: Hash) {
        self.leaves.push(leaf);
    }

    /// The number of leaves.
    pub fn len(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// Whether the log has no leaves.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// The value of a leaf.
    pub fn leaf(&self, index: u64) -> Result<Hash> {
        usize::try_from(index)
            .ok()
            .and_then(|i| self.leaves.get(i))
            .copied()
            .ok_or(Error::InvalidArgument("leaf outside the log"))
    }

    /// The head of a balanced subtree inside the log.
    pub fn subtree(&mut self, s: Subtree) -> Result<Hash> {
        if s.end() > self.len() {
            return Err(Error::InvalidArgument("subtree outside the log"));
        }
        if let Some(v) = self.memo.get(&s) {
            return Ok(*v);
        }
        let v = match s.children() {
            None => self.leaf(s.start)?,
            Some((l, r)) => {
                let lv = self.subtree(l)?;
                let rv = self.subtree(r)?;
                parent_hash(&lv, l.is_leaf(), &rv, r.is_leaf())
            }
        };
        self.memo.insert(s, v);
        Ok(v)
    }

    /// The values of the full subtrees of the first `n` leaves.
    pub fn full_subtree_values(&mut self, n: u64) -> Result<Vec<Hash>> {
        full_subtrees(n)
            .into_iter()
            .map(|s| self.subtree(s))
            .collect()
    }

    /// The root of the first `n` leaves.
    pub fn root(&mut self, n: u64) -> Result<Hash> {
        let pairs = full_subtrees(n)
            .into_iter()
            .map(|s| self.subtree(s).map(|v| (s, v)))
            .collect::<Result<Vec<_>>>()?;
        root_from_full_subtrees(&pairs)
    }

    /// The proof for `spec` from this log.
    pub fn prove(&mut self, spec: &BatchSpec) -> Result<InclusionProof> {
        prove_batch(spec, |s| self.subtree(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small deterministic generator, so tests need no random crate.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    fn log_of(n: u64) -> MemoryLog {
        let mut log = MemoryLog::new();
        for i in 0..n {
            log.push(hash(&[b"leaf", &i.to_be_bytes()]));
        }
        log
    }

    /// The root by the draft's recursive definition, independent of the
    /// full-subtree fold.
    fn reference_root(leaves: &[Hash]) -> (Hash, bool) {
        if leaves.len() == 1 {
            return (leaves[0], true);
        }
        let mut split = 1;
        while split * 2 < leaves.len() {
            split *= 2;
        }
        let (l, ll) = reference_root(&leaves[..split]);
        let (r, rl) = reference_root(&leaves[split..]);
        (parent_hash(&l, ll, &r, rl), false)
    }

    fn check(log: &mut MemoryLog, spec: &BatchSpec) -> BatchRoots {
        let proof = log.prove(spec).unwrap();
        let leaf_values: Vec<(u64, Hash)> = spec
            .leaves
            .iter()
            .map(|&i| (i, log.leaf(i).unwrap()))
            .collect();
        let retained = spec
            .retained_size
            .map(|m| log.full_subtree_values(m).unwrap())
            .unwrap_or_default();
        let roots = verify_batch(spec, &leaf_values, &retained, &proof).unwrap();
        assert_eq!(roots.root, log.root(spec.tree_size).unwrap());
        assert_eq!(
            roots.full_subtrees,
            log.full_subtree_values(spec.tree_size).unwrap()
        );
        for (size, root) in spec.extra_sizes.iter().zip(&roots.extra_roots) {
            assert_eq!(*root, log.root(*size).unwrap());
        }
        for (size, full) in spec.extra_sizes.iter().zip(&roots.extra_full_subtrees) {
            assert_eq!(*full, log.full_subtree_values(*size).unwrap());
        }
        roots
    }

    #[test]
    fn subtree_shapes() {
        assert_eq!(full_subtrees(0), vec![]);
        assert_eq!(
            full_subtrees(13),
            vec![
                Subtree { start: 0, size: 8 },
                Subtree { start: 8, size: 4 },
                Subtree { start: 12, size: 1 }
            ]
        );
        assert_eq!(full_subtrees(u64::MAX).len(), 64);
        assert!(Subtree::new(4, 4).is_ok());
        assert!(Subtree::new(2, 4).is_err());
        assert!(Subtree::new(0, 3).is_err());
        assert!(Subtree::new(0, 0).is_err());
        assert!(Subtree::new(u64::MAX - 1, 2).is_err());
        let s = Subtree { start: 4, size: 4 };
        assert!(s.strictly_contains(&Subtree::leaf(7)));
        assert!(!s.strictly_contains(&s));
        assert!(!s.strictly_contains(&Subtree::leaf(8)));
    }

    #[test]
    fn hash_vectors() {
        // SHA-256(0000000000000102 || 00*32), and of 00 a*32 || 01 b*32.
        let entry = LogEntry {
            timestamp: 0x0102,
            prefix_tree: [0; 32],
        };
        let mut input = 0x0102u64.to_be_bytes().to_vec();
        input.extend([0u8; 32]);
        assert_eq!(leaf_hash(&entry).unwrap(), hash(&[&input]));
        let a = [0xaa; 32];
        let b = [0xbb; 32];
        assert_eq!(
            parent_hash(&a, true, &b, false),
            hash(&[&[0], &a, &[1], &b])
        );
        // Two zero leaves: SHA-256 of 66 zero bytes.
        assert_eq!(
            hex::encode(parent_hash(&[0; 32], true, &[0; 32], true)),
            "efbb03b7a7f6fd3c29391d4d0281e1830a85caadd831c3f04716faca4107a42e"
        );
    }

    #[test]
    fn fold_matches_the_recursive_definition() {
        let mut log = log_of(300);
        let leaves: Vec<Hash> = (0..300).map(|i| log.leaf(i).unwrap()).collect();
        for n in 1..=300u64 {
            assert_eq!(
                log.root(n).unwrap(),
                reference_root(&leaves[..n as usize]).0,
                "n={n}"
            );
        }
        // One leaf: the root is the leaf's value itself.
        assert_eq!(log.root(1).unwrap(), leaves[0]);
    }

    #[test]
    fn figure_3_and_figure_4_shapes() {
        // Figure 3: leaf 2 of 6 needs leaf 3, the subtree of 0..2 and 4..6.
        let spec = BatchSpec {
            tree_size: 6,
            leaves: vec![2],
            ..Default::default()
        };
        assert_eq!(
            batch_positions(&spec).unwrap(),
            vec![
                Subtree { start: 0, size: 2 },
                Subtree::leaf(3),
                Subtree { start: 4, size: 2 }
            ]
        );
        // Figure 4: from 5 to 7 the verifier holds 0..4 and 4; it gets 5 and 6.
        let spec = BatchSpec {
            tree_size: 7,
            retained_size: Some(5),
            ..Default::default()
        };
        assert_eq!(
            batch_positions(&spec).unwrap(),
            vec![Subtree::leaf(5), Subtree::leaf(6)]
        );
        // Same size: nothing to send.
        let spec = BatchSpec {
            tree_size: 7,
            retained_size: Some(7),
            ..Default::default()
        };
        assert_eq!(batch_positions(&spec).unwrap(), vec![]);
    }

    #[test]
    fn inclusion_for_every_leaf_of_every_size_to_300() {
        let mut log = log_of(300);
        for n in 1..=300u64 {
            for leaf in 0..n {
                check(
                    &mut log,
                    &BatchSpec {
                        tree_size: n,
                        leaves: vec![leaf],
                        ..Default::default()
                    },
                );
            }
        }
    }

    #[test]
    fn consistency_for_every_pair_of_sizes_to_300() {
        let mut log = log_of(300);
        for n in 1..=300u64 {
            for m in 1..=n {
                let spec = BatchSpec {
                    tree_size: n,
                    retained_size: Some(m),
                    ..Default::default()
                };
                check(&mut log, &spec);
                // The proof never carries more than two heads per level.
                assert!(batch_positions(&spec).unwrap().len() <= 2 * 64);
            }
        }
    }

    #[test]
    fn auditor_sizes_for_every_pair_to_200() {
        let mut log = log_of(200);
        for n in 1..=200u64 {
            for a in 1..=n {
                check(
                    &mut log,
                    &BatchSpec {
                        tree_size: n,
                        extra_sizes: vec![a],
                        ..Default::default()
                    },
                );
            }
        }
    }

    #[test]
    fn random_combined_batches() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let mut log = log_of(5000);
        for _ in 0..400 {
            let n = 1 + rng.below(5000);
            let leaves = (0..rng.below(12)).map(|_| rng.below(n)).collect();
            let retained_size = if rng.below(3) == 0 {
                None
            } else {
                Some(1 + rng.below(n))
            };
            let extra_sizes = (0..rng.below(4)).map(|_| 1 + rng.below(n)).collect();
            check(
                &mut log,
                &BatchSpec {
                    tree_size: n,
                    leaves,
                    retained_size,
                    extra_sizes,
                },
            );
        }
    }

    #[test]
    fn a_leaf_inside_a_retained_subtree_is_checked_against_it() {
        let mut log = log_of(20);
        let spec = BatchSpec {
            tree_size: 20,
            leaves: vec![3],
            retained_size: Some(9),
            extra_sizes: vec![],
        };
        let proof = log.prove(&spec).unwrap();
        let leaf = vec![(3, log.leaf(3).unwrap())];
        let mut retained = log.full_subtree_values(9).unwrap();
        verify_batch(&spec, &leaf, &retained, &proof).unwrap();
        // The retained head of 0..8 is redundant for the root, but a proof
        // that computes another value for it must fail.
        retained[0][0] ^= 1;
        assert_eq!(
            verify_batch(&spec, &leaf, &retained, &proof),
            Err(Error::ProofMismatch(
                "log tree disagrees with a retained subtree"
            ))
        );
    }

    #[test]
    fn a_leaf_that_is_a_retained_subtree_is_checked_against_it() {
        let mut log = log_of(10);
        // Retained size 9: its last full subtree is leaf 8.
        let spec = BatchSpec {
            tree_size: 10,
            leaves: vec![8],
            retained_size: Some(9),
            extra_sizes: vec![],
        };
        let proof = log.prove(&spec).unwrap();
        let retained = log.full_subtree_values(9).unwrap();
        let wrong_leaf = vec![(8, [0x42; 32])];
        assert!(matches!(
            verify_batch(&spec, &wrong_leaf, &retained, &proof),
            Err(Error::ProofMismatch(_))
        ));
    }

    #[test]
    fn tampered_proofs_fail() {
        let mut log = log_of(100);
        let spec = BatchSpec {
            tree_size: 100,
            leaves: vec![17, 64],
            retained_size: Some(37),
            extra_sizes: vec![50],
        };
        let roots = check(&mut log, &spec);
        let proof = log.prove(&spec).unwrap();
        let leaves: Vec<(u64, Hash)> = spec
            .leaves
            .iter()
            .map(|&i| (i, log.leaf(i).unwrap()))
            .collect();
        let retained = log.full_subtree_values(37).unwrap();

        for i in 0..proof.elements.len() {
            let mut bad = proof.clone();
            bad.elements[i][5] ^= 0x10;
            let out = verify_batch(&spec, &leaves, &retained, &bad);
            // Either a retained subtree catches it, or a root moves.
            match out {
                Err(Error::ProofMismatch(_)) => {}
                Ok(r) => assert!(r.root != roots.root || r.extra_roots != roots.extra_roots),
                Err(e) => panic!("unexpected {e:?}"),
            }
        }
        let mut short = proof.clone();
        short.elements.pop();
        assert_eq!(
            verify_batch(&spec, &leaves, &retained, &short),
            Err(Error::MalformedProof("wrong number of log tree elements"))
        );
        let mut long = proof.clone();
        long.elements.push([0; 32]);
        assert!(verify_batch(&spec, &leaves, &retained, &long).is_err());
        // A wrong leaf value moves the root (leaf 64), or contradicts a
        // retained subtree (leaf 17, inside the retained 0..32).
        let mut wrong = leaves.clone();
        wrong[1].1[0] ^= 1;
        assert_ne!(
            verify_batch(&spec, &wrong, &retained, &proof).unwrap().root,
            roots.root
        );
        let mut wrong = leaves.clone();
        wrong[0].1[0] ^= 1;
        assert!(matches!(
            verify_batch(&spec, &wrong, &retained, &proof),
            Err(Error::ProofMismatch(_))
        ));
        // Missing or extra leaf values, and retained values of the wrong count.
        assert!(verify_batch(&spec, &leaves[..1], &retained, &proof).is_err());
        assert!(verify_batch(&spec, &leaves, &retained[..1], &proof).is_err());
    }

    #[test]
    fn bad_specs_are_refused() {
        let base = BatchSpec {
            tree_size: 10,
            ..Default::default()
        };
        assert!(batch_positions(&BatchSpec {
            tree_size: 0,
            ..base.clone()
        })
        .is_err());
        assert!(batch_positions(&BatchSpec {
            leaves: vec![10],
            ..base.clone()
        })
        .is_err());
        assert!(batch_positions(&BatchSpec {
            retained_size: Some(11),
            ..base.clone()
        })
        .is_err());
        assert!(batch_positions(&BatchSpec {
            extra_sizes: vec![0],
            ..base.clone()
        })
        .is_err());
        assert!(batch_positions(&BatchSpec {
            extra_sizes: vec![11],
            ..base.clone()
        })
        .is_err());
        // Retained size 0 means nothing retained.
        assert!(batch_positions(&BatchSpec {
            retained_size: Some(0),
            ..base
        })
        .is_ok());
    }
}
