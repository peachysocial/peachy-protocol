// SPDX-License-Identifier: MIT
//! The tree facts the verifier's retained state rests on, checked
//! exhaustively over small trees.

use peachy_keytrans::implicit::{ancestors, frontier};
use peachy_keytrans::log_tree::{batch_positions, full_subtrees, BatchSpec};

/// A distinguished entry's tree (`d + 1` entries) has a frontier that a
/// walk to `d` in any later tree passes through, so its timestamps are in
/// any response that walks there.
#[test]
fn frontier_of_the_next_size_lies_on_the_entrys_path() {
    for n in 1..=300u64 {
        for d in 0..n {
            let path = ancestors(d, n).unwrap();
            for f in frontier(d + 1) {
                assert!(
                    f == d || path.contains(&f),
                    "n={n} d={d}: frontier entry {f} not on the path"
                );
            }
        }
    }
}

/// For an entry on the frontier of a retained size, the tree it ends has
/// full subtrees that are a prefix of the retained ones.
#[test]
fn a_retained_frontier_entrys_subtrees_prefix_the_retained_ones() {
    for m in 1..=300u64 {
        let retained = full_subtrees(m);
        for d in frontier(m) {
            let ours = full_subtrees(d + 1);
            assert_eq!(&retained[..ours.len()], &ours[..], "m={m} d={d}");
        }
    }
}

/// Asking an inclusion proof for one more size, `d + 1` for a leaf `d` it
/// already covers, adds no element: a verifier can read a distinguished
/// entry's tree out of a proof the log made without knowing it would.
#[test]
fn one_more_size_for_a_covered_leaf_adds_no_element() {
    for n in 1..=80u64 {
        for retained in [None, Some(n / 2), Some(n.saturating_sub(1))] {
            let retained = retained.filter(|&m| m > 0);
            for d in 0..n {
                if retained.is_some_and(|m| frontier(m).contains(&d)) {
                    continue;
                }
                let mut leaves: Vec<u64> = ancestors(d, n).unwrap();
                leaves.push(d);
                let base = BatchSpec {
                    tree_size: n,
                    leaves: leaves.clone(),
                    retained_size: retained,
                    extra_sizes: vec![],
                };
                let more = BatchSpec {
                    extra_sizes: vec![d + 1],
                    ..base.clone()
                };
                assert_eq!(
                    batch_positions(&base).unwrap(),
                    batch_positions(&more).unwrap(),
                    "n={n} d={d} retained={retained:?}"
                );
            }
        }
    }
}
