// SPDX-License-Identifier: MIT
//! The auditor feed (§15.2): replaying every entry's `AuditorUpdate` into
//! a shadow log rebuilds the log's roots, each update's proof shows its
//! added keys absent from the previous prefix tree, and the update rebuilt
//! from storage is the one the append returned. The shadow prefix tree is
//! recomputed from scratch with the verifier-side hashes, independent of
//! the prover's persistent tree.

#![cfg(feature = "prover")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod prover_support;

use peachy_keytrans::log_tree::{leaf_hash as log_leaf_hash, MemoryLog};
use peachy_keytrans::prefix_proof::{bit, evaluate, leaf_hash, parent_hash, PrefixSearch, EMPTY};
use peachy_keytrans::prover::{LabelUpdate, Storage};
use peachy_keytrans::suite::Hash;
use peachy_keytrans::wire::{LogEntry, PrefixLeaf, PrefixSearchOutcome, UpdateValue};
use prover_support::{label, Rng, World, WINDOW};

/// A prefix tree's root from its leaves, by the definition: a subtree of
/// no leaves is empty, of one leaf is that leaf, else a parent of the
/// subtrees split on the next bit.
fn naive_root(leaves: &[PrefixLeaf], depth: usize) -> Hash {
    match leaves {
        [] => EMPTY,
        [one] => leaf_hash(one),
        _ => {
            let (l, r): (Vec<PrefixLeaf>, Vec<PrefixLeaf>) =
                leaves.iter().partition(|x| !bit(&x.vrf_output, depth));
            parent_hash(&naive_root(&l, depth + 1), &naive_root(&r, depth + 1))
        }
    }
}

#[test]
fn replaying_the_feed_rebuilds_the_log() {
    let mut w = World::new();
    let mut rng = Rng::new(31);
    let mut shadow: Vec<PrefixLeaf> = Vec::new();
    let mut log = MemoryLog::new();
    let mut counter = 0u64;
    for _ in 0..30 {
        let count = rng.below(4);
        let updates: Vec<LabelUpdate> = (0..count)
            .map(|_| {
                counter += 1;
                let mut opening = [7u8; 16];
                opening[..8].copy_from_slice(&counter.to_be_bytes());
                LabelUpdate {
                    label: label(rng.below(5)),
                    value: UpdateValue {
                        value: counter.to_be_bytes().to_vec(),
                    },
                    opening,
                }
            })
            .collect();
        w.now += 1 + rng.below(2 * WINDOW);
        let appended = w.prover.append(w.now, &updates).unwrap();
        let position = appended.position;
        let feed = appended.auditor_update;

        // Rebuilt from storage, the same update.
        assert_eq!(w.prover.auditor_update(position).unwrap(), feed);

        assert_eq!(feed.timestamp, w.now);
        assert!(feed.removed.is_empty());
        assert_eq!(feed.added.len(), updates.len());
        assert!(feed
            .added
            .windows(2)
            .all(|p| p[0].vrf_output < p[1].vrf_output));

        // The proof is in the previous tree, and shows every key absent.
        let searches: Vec<PrefixSearch> = feed
            .added
            .iter()
            .map(|l| PrefixSearch {
                vrf_output: l.vrf_output,
                commitment: None,
            })
            .collect();
        assert_eq!(
            evaluate(&searches, &feed.proof).unwrap(),
            naive_root(&shadow, 0)
        );
        assert!(feed
            .proof
            .results
            .iter()
            .all(|r| r.outcome != PrefixSearchOutcome::Inclusion));

        shadow.extend(feed.added.iter().copied());
        let root = naive_root(&shadow, 0);
        let entry = w.prover.store().entry(position).unwrap();
        assert_eq!(entry.prefix_tree, root);
        log.push(
            log_leaf_hash(&LogEntry {
                timestamp: feed.timestamp,
                prefix_tree: root,
            })
            .unwrap(),
        );
        assert_eq!(
            log.root(position + 1).unwrap(),
            w.prover.root(position + 1).unwrap()
        );
        assert_eq!(
            appended.tree_head.tree_size,
            position + 1,
            "the head signed with the append covers it"
        );
    }
    // Every older root is still provable from the persistent store.
    for x in 0..w.n() {
        assert_eq!(w.prover.auditor_update(x).unwrap().timestamp, w.ts(x));
    }
}

#[test]
fn the_first_entry_is_proved_against_the_empty_tree() {
    let mut w = World::new();
    w.append(1, &[0, 1]);
    let feed = w.prover.auditor_update(0).unwrap();
    let searches: Vec<PrefixSearch> = feed
        .added
        .iter()
        .map(|l| PrefixSearch {
            vrf_output: l.vrf_output,
            commitment: None,
        })
        .collect();
    assert_eq!(evaluate(&searches, &feed.proof).unwrap(), EMPTY);
    assert!(w.prover.auditor_update(1).is_err());
}
