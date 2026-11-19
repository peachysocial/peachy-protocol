// SPDX-License-Identifier: MIT
//! The auditor against the prover's feed (§15.2): an honest feed is
//! accepted and every head the auditor signs is one the log accepts, while
//! every tampered, replayed, reordered, forked or equivocating entry is
//! refused with the check it breaks, and leaves the auditor where it was.
//! Handoffs and cold starts resume one lineage only.

#![cfg(all(feature = "prover", feature = "auditor"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod prover_support;

use std::collections::BTreeMap;

use peachy_keytrans::auditor::{AuditError, Auditor, Checkpoint, Handoff};
use peachy_keytrans::codec::{decode, encode};
use peachy_keytrans::head::verify_auditor_tree_head;
use peachy_keytrans::prefix_proof::EMPTY;
use peachy_keytrans::prefix_tree::{insert, prove, PrefixNode};
use peachy_keytrans::profile::values::AuditorInstance;
use peachy_keytrans::prover::Storage;
use peachy_keytrans::suite::{Hash, SecretKey};
use peachy_keytrans::wire::{
    AuditorUpdate, Configuration, LogEntry, ModeConfig, PrefixLeaf, PrefixSearchOutcome,
};
use prover_support::{World, WINDOW};

const SEED: [u8; 32] = [3; 32]; // auditor 0 of the test world
const SUCCESSOR_SEED: [u8; 32] = [9; 32];

/// The update and the log's entry at `x`.
fn feed(w: &World, x: u64) -> (AuditorUpdate, LogEntry) {
    (
        w.prover.auditor_update(x).unwrap(),
        w.prover.store().entry(x).unwrap(),
    )
}

/// An auditor on `w`'s first configuration, caught up to `upto` entries.
fn caught_up(w: &World, upto: u64) -> Auditor {
    let mut a = Auditor::new(&SEED, w.configs[0].clone()).unwrap();
    for x in 0..upto {
        let (u, e) = feed(w, x);
        assert_eq!(a.apply(x, &u, Some(&e)).unwrap(), e);
    }
    a
}

/// `config` naming the key made from `seed`, starting at `start`.
fn config_for(config: &Configuration, seed: &[u8; 32], start: u64) -> Configuration {
    let mut c = config.clone();
    if let ModeConfig::ThirdPartyAuditing {
        auditor_start_pos,
        auditor_public_key,
        ..
    } = &mut c.mode
    {
        *auditor_start_pos = start;
        *auditor_public_key = SecretKey::from_seed(seed).public_key().to_bytes().to_vec();
    }
    c
}

/// A small fixed history: two entries of several leaves, a heartbeat, a
/// three-leaf entry, a one-leaf entry, another heartbeat at the same
/// timestamp, and one more.
fn fixed() -> World {
    let mut w = World::new();
    w.append(10, &[0, 1]);
    w.append(10, &[2, 3]);
    w.append(10, &[]);
    w.append(10, &[4, 5, 6]);
    w.append(10, &[1]);
    w.append(0, &[]);
    w.append(10, &[7]);
    w
}

/// The log's prefix trees rebuilt from the feed, so a test can prove
/// anything against them.
struct Shadow {
    nodes: BTreeMap<Hash, PrefixNode>,
    roots: Vec<Hash>,
}

impl Shadow {
    fn of(w: &World) -> Self {
        let mut s = Shadow {
            nodes: BTreeMap::new(),
            roots: Vec::new(),
        };
        for x in 0..w.n() {
            let (u, e) = feed(w, x);
            let ins = insert(&s.nodes, &s.root_before(x), &u.added).unwrap();
            s.nodes.extend(ins.nodes);
            assert_eq!(ins.root, e.prefix_tree);
            s.roots.push(ins.root);
        }
        s
    }

    /// The prefix root before entry `x`.
    fn root_before(&self, x: u64) -> Hash {
        match x.checked_sub(1) {
            Some(p) => self.roots[p as usize],
            None => EMPTY,
        }
    }

    /// Every leaf in the tree after entry `x`.
    fn leaves_at(&self, w: &World, x: u64) -> Vec<PrefixLeaf> {
        (0..=x).flat_map(|i| feed(w, i).0.added).collect()
    }
}

// ---------------------------------------------------------------------------
// An honest feed
// ---------------------------------------------------------------------------

#[test]
fn an_honest_feed_is_accepted_and_every_head_is_one_the_log_accepts() {
    for seed in [1u64, 2, 3] {
        let mut w = World::random(seed, 90, 12);
        let mut a = Auditor::new(&SEED, w.configs[0].clone()).unwrap();
        let mut bare = Auditor::new(&SEED, w.configs[0].clone()).unwrap();
        for x in 0..w.n() {
            let (u, e) = feed(&w, x);
            // Through the wire encoding, as the host hands it over.
            let u: AuditorUpdate = decode(&encode(&u).unwrap()).unwrap();
            assert_eq!(a.apply(x, &u, Some(&e)).unwrap(), e);
            // Without the log's entry, the same result.
            assert_eq!(bare.apply(x, &u, None).unwrap(), e);
            assert_eq!(a.tree_size(), x + 1);
            assert_eq!(a.root().unwrap(), w.prover.root(x + 1).unwrap());
            assert_eq!(a.last_entry(), Some(e));
        }
        // Heads at the end and the log keeps them.
        let head = a.sign_head().unwrap();
        assert_eq!(head.auditor_tree_head.tree_size, w.n());
        assert_eq!(head.auditor_tree_head.timestamp, w.ts(w.n() - 1));
        verify_auditor_tree_head(
            &head.auditor_tree_head,
            &w.configs[0],
            &w.prover.root(w.n()).unwrap(),
        )
        .unwrap();
        w.prover.add_auditor_head(head.clone()).unwrap();
        assert_eq!(a.last_signed(), Some(&head.auditor_tree_head));
    }
}

#[test]
fn heads_signed_along_the_way_are_accepted_by_the_log_in_order() {
    let mut w = fixed();
    let mut a = Auditor::new(&SEED, w.configs[0].clone()).unwrap();
    for x in 0..w.n() {
        let (u, e) = feed(&w, x);
        a.apply(x, &u, Some(&e)).unwrap();
        let head = a.sign_head().unwrap();
        w.prover.add_auditor_head(head).unwrap();
    }
    // The heartbeat at an equal timestamp (entry 5) was accepted too.
    assert_eq!(w.ts(4), w.ts(5));
}

#[test]
fn the_empty_auditor_signs_nothing() {
    let w = fixed();
    let mut a = Auditor::new(&SEED, w.configs[0].clone()).unwrap();
    assert_eq!(a.sign_head(), Err(AuditError::Empty));
    assert_eq!(a.checkpoint(), Err(AuditError::Empty));
    let other = SecretKey::from_seed(&SUCCESSOR_SEED)
        .public_key()
        .to_bytes();
    assert_eq!(a.hand_off(&other).unwrap_err(), AuditError::Empty);
    assert_eq!(a.root(), Err(AuditError::Empty));
}

// ---------------------------------------------------------------------------
// Tampered entries
// ---------------------------------------------------------------------------

/// Applies `bad` at `x` on an auditor caught up to `x`, expects `want`, then
/// checks the auditor is unchanged by applying the honest entry.
fn refused(w: &World, x: u64, bad: &AuditorUpdate, claimed: Option<&LogEntry>, want: AuditError) {
    let mut a = caught_up(w, x);
    let before = (a.tree_size(), a.last_entry());
    assert_eq!(a.apply(x, bad, claimed), Err(want));
    assert_eq!((a.tree_size(), a.last_entry()), before, "state moved");
    let (u, e) = feed(w, x);
    assert_eq!(a.apply(x, &u, Some(&e)).unwrap(), e);
}

#[test]
fn a_timestamp_before_the_previous_entrys_is_refused() {
    let w = fixed();
    let (mut u, _) = feed(&w, 3);
    u.timestamp = w.ts(2) - 1;
    refused(&w, 3, &u, None, AuditError::TimestampBackwards);
}

#[test]
fn unsorted_or_repeated_added_leaves_are_refused() {
    let w = fixed();
    let (u, _) = feed(&w, 3);
    assert_eq!(u.added.len(), 3);
    // Swapped, with their results swapped too, so only the order is wrong.
    let mut swapped = u.clone();
    swapped.added.swap(0, 1);
    swapped.proof.results.swap(0, 1);
    refused(&w, 3, &swapped, None, AuditError::AddedNotSorted);
    // One leaf twice, with its result twice.
    let mut twice = u.clone();
    twice.added.insert(1, u.added[0]);
    twice.proof.results.insert(1, u.proof.results[0]);
    refused(&w, 3, &twice, None, AuditError::AddedNotSorted);
    // One key twice under two commitments.
    let mut two_values = twice.clone();
    two_values.added[1].commitment[0] ^= 1;
    two_values.added.sort();
    refused(&w, 3, &two_values, None, AuditError::AddedNotSorted);
}

#[test]
fn a_removal_is_refused() {
    let w = fixed();
    let s = Shadow::of(&w);
    // Entry 4, plus removing a leaf entry 0 added, laid out as the draft
    // says: the searches for added, then for removed.
    let (mut u, _) = feed(&w, 4);
    let gone = feed(&w, 0).0.added[0];
    u.removed = vec![gone];
    let mut keys: Vec<_> = u.added.iter().map(|l| l.vrf_output).collect();
    keys.push(gone.vrf_output);
    u.proof = prove(&s.nodes, &s.root_before(4), &keys).unwrap();
    refused(&w, 4, &u, None, AuditError::RemovalNotAllowed);
    // A removal alone, with nothing added.
    let lone = AuditorUpdate {
        timestamp: w.ts(4),
        added: vec![],
        removed: vec![gone],
        proof: prove(&s.nodes, &s.root_before(4), &[gone.vrf_output]).unwrap(),
    };
    refused(&w, 4, &lone, None, AuditError::RemovalNotAllowed);
}

#[test]
fn rewriting_a_leaf_already_in_the_tree_is_refused() {
    // The log tries to give an existing label version a new commitment,
    // proving honestly that its key is there.
    let w = fixed();
    let s = Shadow::of(&w);
    let mut old = feed(&w, 1).0.added[0];
    old.commitment[5] ^= 0x40;
    let u = AuditorUpdate {
        timestamp: w.ts(4),
        added: vec![old],
        removed: vec![],
        proof: prove(&s.nodes, &s.root_before(4), &[old.vrf_output]).unwrap(),
    };
    assert_eq!(u.proof.results[0].outcome, PrefixSearchOutcome::Inclusion);
    refused(&w, 4, &u, None, AuditError::AddedAlreadyPresent);
}

#[test]
fn a_proof_against_another_tree_is_refused() {
    let w = fixed();
    let s = Shadow::of(&w);
    // Entry 4's leaf, proved against the tree before entry 1 (an older
    // root): a forged absence.
    let (mut u, _) = feed(&w, 4);
    let keys: Vec<_> = u.added.iter().map(|l| l.vrf_output).collect();
    u.proof = prove(&s.nodes, &s.root_before(1), &keys).unwrap();
    refused(&w, 4, &u, None, AuditError::PreviousRootMismatch);
    // Against a tree built from scratch without one of the leaves, so the
    // added key's absence is "proved" where it was hidden.
    let mut leaves = s.leaves_at(&w, 3);
    leaves.remove(2);
    let mut fake = BTreeMap::new();
    let ins = insert(&fake, &EMPTY, &leaves).unwrap();
    fake.extend(ins.nodes);
    let (mut u, _) = feed(&w, 4);
    u.proof = prove(&fake, &ins.root, &keys).unwrap();
    refused(&w, 4, &u, None, AuditError::PreviousRootMismatch);
}

#[test]
fn every_changed_proof_element_or_result_is_refused() {
    let w = fixed();
    for x in [0u64, 1, 3, 4, 6] {
        let (u, _) = feed(&w, x);
        let mut cases: Vec<(String, AuditorUpdate)> = Vec::new();
        for i in 0..u.proof.elements.len() {
            let mut b = u.clone();
            b.proof.elements[i][0] ^= 1;
            cases.push((format!("element {i} changed"), b));
            let mut b = u.clone();
            b.proof.elements.remove(i);
            cases.push((format!("element {i} removed"), b));
        }
        let mut b = u.clone();
        b.proof.elements.push([7; 32]);
        cases.push(("an element added".into(), b));
        for i in 0..u.proof.results.len() {
            let mut b = u.clone();
            b.proof.results[i].depth = b.proof.results[i].depth.wrapping_add(1);
            cases.push((format!("result {i} deeper"), b));
            let mut b = u.clone();
            b.proof.results.remove(i);
            cases.push((format!("result {i} removed"), b));
            let mut b = u.clone();
            b.proof.results[i].outcome = match b.proof.results[i].outcome {
                PrefixSearchOutcome::NonInclusionParent => PrefixSearchOutcome::Inclusion,
                _ => PrefixSearchOutcome::NonInclusionParent,
            };
            cases.push((format!("result {i} outcome changed"), b));
        }
        let mut b = u.clone();
        b.proof
            .results
            .push(u.proof.results.first().copied().unwrap_or(
                peachy_keytrans::wire::PrefixSearchResult {
                    outcome: PrefixSearchOutcome::NonInclusionParent,
                    depth: 0,
                },
            ));
        cases.push(("a result added".into(), b));
        assert!(!cases.is_empty());
        for (name, bad) in cases {
            let mut a = caught_up(&w, x);
            let got = a.apply(x, &bad, None);
            assert!(got.is_err(), "entry {x}, {name}: accepted");
            assert_eq!(a.tree_size(), x, "entry {x}, {name}: state moved");
        }
    }
}

#[test]
fn a_changed_or_hidden_leaf_is_refused_against_the_logs_entry() {
    let w = fixed();
    let s = Shadow::of(&w);
    let (u, e) = feed(&w, 3);

    // A commitment changed in the feed: the proof only searches keys, so
    // the auditor computes another root, which the log's entry contradicts.
    let mut changed = u.clone();
    changed.added[1].commitment[0] ^= 1;
    refused(&w, 3, &changed, Some(&e), AuditError::ClaimedEntryMismatch);

    // A leaf the log wrote but left out of the feed, with a proof made for
    // the rest.
    let mut hidden = u.clone();
    hidden.added.remove(0);
    let keys: Vec<_> = hidden.added.iter().map(|l| l.vrf_output).collect();
    hidden.proof = prove(&s.nodes, &s.root_before(3), &keys).unwrap();
    refused(&w, 3, &hidden, Some(&e), AuditError::ClaimedEntryMismatch);

    // A leaf in the feed the log never wrote.
    let mut extra = u.clone();
    let mut planted = u.added[0];
    planted.vrf_output = [0xee; 32];
    extra.added.push(planted);
    extra.added.sort();
    let keys: Vec<_> = extra.added.iter().map(|l| l.vrf_output).collect();
    extra.proof = prove(&s.nodes, &s.root_before(3), &keys).unwrap();
    refused(&w, 3, &extra, Some(&e), AuditError::ClaimedEntryMismatch);

    // The log's entry with another timestamp.
    let mut later = e;
    later.timestamp += 1;
    refused(&w, 3, &u, Some(&later), AuditError::ClaimedEntryMismatch);

    // Without the log's entry the auditor cannot tell, and signs its own
    // root, but the log refuses that head: no history it did not verify.
    for bad in [&changed, &hidden, &extra] {
        let mut w = fixed();
        let mut a = caught_up(&w, 3);
        a.apply(3, bad, None).unwrap();
        assert_ne!(a.root().unwrap(), w.prover.root(4).unwrap());
        let head = a.sign_head().unwrap();
        assert!(w.prover.add_auditor_head(head).is_err());
    }
}

// ---------------------------------------------------------------------------
// Replayed, skipped, reordered, equivocating and forked feeds
// ---------------------------------------------------------------------------

#[test]
fn a_replayed_skipped_or_reordered_entry_is_refused() {
    let w = fixed();
    // Named by its real position: only the next one is taken.
    let mut a = caught_up(&w, 2);
    let (u1, _) = feed(&w, 1);
    let (u3, _) = feed(&w, 3);
    assert_eq!(
        a.apply(1, &u1, None),
        Err(AuditError::WrongPosition {
            expected: 2,
            got: 1
        })
    );
    assert_eq!(
        a.apply(3, &u3, None),
        Err(AuditError::WrongPosition {
            expected: 2,
            got: 3
        })
    );
    // Passed off as the next position, the update's proof is for another
    // tree: a replay of entry 1 at 2, and entry 4 before entry 3.
    refused(&w, 2, &u1, None, AuditError::PreviousRootMismatch);
    let (u4, _) = feed(&w, 4);
    refused(&w, 3, &u4, None, AuditError::PreviousRootMismatch);
    // A heartbeat replayed in place of the next entry has the shape of a new
    // heartbeat (same tree, same timestamp), so only the log's entry tells.
    let (u2, _) = feed(&w, 2);
    let (_, e3) = feed(&w, 3);
    refused(&w, 3, &u2, Some(&e3), AuditError::ClaimedEntryMismatch);
    // Entry 3 skipped: entry 4 at position 3 (as above), and entry 3 then
    // out of order behind entry 4 is refused too.
    let mut b = caught_up(&w, 3);
    let (u3, _) = feed(&w, 3);
    assert_eq!(
        b.apply(4, &u3, None),
        Err(AuditError::WrongPosition {
            expected: 3,
            got: 4
        })
    );
}

#[test]
fn a_second_update_for_a_position_is_refused() {
    // Equivocation: the log offers two updates for one position. The first
    // taken fixes the lineage; the other can never be applied there.
    let w = fixed();
    let mut a = caught_up(&w, 4);
    let (u, e) = feed(&w, 4);
    a.apply(4, &u, Some(&e)).unwrap();
    let mut other = u.clone();
    other.added[0].commitment[3] ^= 1;
    assert_eq!(
        a.apply(4, &other, None),
        Err(AuditError::WrongPosition {
            expected: 5,
            got: 4
        })
    );
    // And at the next position it extends the wrong tree.
    assert_eq!(
        a.apply(5, &other, None),
        Err(AuditError::PreviousRootMismatch)
    );
}

/// Two logs with the same keys and the same first `shared` entries, then
/// different ones.
fn forked(shared: u64) -> (World, World) {
    let mut a = World::new();
    let mut b = World::new();
    for i in 0..shared {
        a.append(10, &[i % 5, 10 + i]);
        b.append(10, &[i % 5, 10 + i]);
    }
    a.append(10, &[100]);
    b.append(10, &[200]);
    a.append(10, &[101]);
    b.append(10, &[201]);
    for x in 0..shared {
        assert_eq!(feed(&a, x), feed(&b, x));
    }
    assert_ne!(a.prover.root(shared + 1), b.prover.root(shared + 1));
    (a, b)
}

#[test]
fn a_fork_is_refused_and_only_one_lineage_is_ever_signed() {
    let (mut wa, wb) = forked(5);
    let mut aud = caught_up(&wa, 6);
    let head = aud.sign_head().unwrap();
    wa.prover.add_auditor_head(head.clone()).unwrap();
    // The other branch's entries, at any position, are refused.
    let (b5, e5) = feed(&wb, 5);
    let (b6, e6) = feed(&wb, 6);
    assert!(matches!(
        aud.apply(5, &b5, Some(&e5)),
        Err(AuditError::WrongPosition { .. })
    ));
    assert_eq!(
        aud.apply(6, &b6, Some(&e6)),
        Err(AuditError::PreviousRootMismatch)
    );
    // Its own branch goes on, and every head extends the first.
    let (a6, ea6) = feed(&wa, 6);
    aud.apply(6, &a6, Some(&ea6)).unwrap();
    let later = aud.sign_head().unwrap();
    wa.prover.add_auditor_head(later).unwrap();

    // The branch point itself: an auditor that saw the shared entries takes
    // whichever branch comes first, and then refuses the other.
    let mut first_b = caught_up(&wa, 5);
    first_b.apply(5, &b5, Some(&e5)).unwrap();
    let (a5, ea5) = feed(&wa, 5);
    assert_eq!(
        first_b.apply(6, &a5, Some(&ea5)),
        Err(AuditError::PreviousRootMismatch)
    );
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[test]
fn a_configuration_the_auditor_cannot_sign_under_is_refused() {
    let w = fixed();
    let base = w.configs[0].clone();
    // Another auditor's key.
    assert!(matches!(
        Auditor::new(&SEED, w.configs[1].clone()),
        Err(AuditError::Configuration(_))
    ));
    // A start past 0 for an instance on the empty log.
    assert!(matches!(
        Auditor::new(&SEED, config_for(&base, &SEED, 1)),
        Err(AuditError::Configuration(_))
    ));
    // A maximum lifetime.
    let mut c = base.clone();
    c.maximum_lifetime = Some(100 * WINDOW);
    assert!(matches!(
        Auditor::new(&SEED, c),
        Err(AuditError::Configuration(_))
    ));
    // Another mode.
    let mut c = base.clone();
    c.mode = ModeConfig::ContactMonitoring {
        leaf_public_key: vec![1; 32],
    };
    assert!(matches!(
        Auditor::new(&SEED, c),
        Err(AuditError::Configuration(_))
    ));
}

// ---------------------------------------------------------------------------
// Handoffs
// ---------------------------------------------------------------------------

fn successor_key() -> [u8; 32] {
    SecretKey::from_seed(&SUCCESSOR_SEED)
        .public_key()
        .to_bytes()
}

#[test]
fn a_successor_resumes_from_a_handoff_at_every_size() {
    let w = World::random(9, 40, 8);
    for size in 1..w.n() {
        let mut old = caught_up(&w, size);
        let handoff = old.hand_off(&successor_key()).unwrap();
        // Through its encoding.
        let handoff = Handoff::from_bytes(&handoff.to_bytes().unwrap()).unwrap();
        let cp = Checkpoint::from_bytes(&handoff.checkpoint.to_bytes().unwrap()).unwrap();
        assert_eq!(cp, handoff.checkpoint);
        assert_eq!(cp.tree_size, size);
        for start in [0, size] {
            let config = config_for(&w.configs[0], &SUCCESSOR_SEED, start);
            let mut new =
                Auditor::resume(&SUCCESSOR_SEED, config.clone(), &w.configs[0], &handoff).unwrap();
            assert_eq!(new.tree_size(), size);
            assert_eq!(new.root().unwrap(), w.prover.root(size).unwrap());
            for x in size..w.n() {
                let (u, e) = feed(&w, x);
                new.apply(x, &u, Some(&e)).unwrap();
            }
            let head = new.sign_head().unwrap();
            verify_auditor_tree_head(
                &head.auditor_tree_head,
                &config,
                &w.prover.root(w.n()).unwrap(),
            )
            .unwrap();
            assert_eq!(
                new.instance(77),
                AuditorInstance {
                    boot_time: 77,
                    start_position: start,
                    predecessor_key: Some(SecretKey::from_seed(&SEED).public_key().to_bytes()),
                    handoff_sig: Some(handoff.signature),
                }
            );
        }
    }
}

#[test]
fn a_retired_instance_signs_and_applies_nothing() {
    let mut w = fixed();
    let mut old = caught_up(&w, 4);
    let handoff = old.hand_off(&successor_key()).unwrap();
    // The head the handoff carries is one the log accepts.
    w.prover
        .add_auditor_head(peachy_keytrans::wire::KeyedAuditorTreeHead {
            auditor_public_key: old.public_key().to_vec(),
            auditor_tree_head: handoff.head.clone(),
        })
        .unwrap();
    assert!(old.is_retired());
    let (u, e) = feed(&w, 4);
    assert_eq!(old.apply(4, &u, Some(&e)), Err(AuditError::Retired));
    assert_eq!(old.sign_head(), Err(AuditError::Retired));
    let third = SecretKey::from_seed(&[10; 32]).public_key().to_bytes();
    assert_eq!(old.hand_off(&third).unwrap_err(), AuditError::Retired);
    assert_eq!(old.tree_size(), 4);
}

#[test]
fn a_tampered_handoff_is_refused() {
    let w = fixed();
    let mut old = caught_up(&w, 5);
    let good = old.hand_off(&successor_key()).unwrap();
    let pred = &w.configs[0];
    let config = config_for(pred, &SUCCESSOR_SEED, 0);
    Auditor::resume(&SUCCESSOR_SEED, config.clone(), pred, &good).unwrap();

    let resume =
        |h: &Handoff| Auditor::resume(&SUCCESSOR_SEED, config.clone(), pred, h).unwrap_err();

    // For another successor.
    let other_seed = [11u8; 32];
    assert_eq!(
        Auditor::resume(&other_seed, config_for(pred, &other_seed, 0), pred, &good).unwrap_err(),
        AuditError::Handoff("names another successor")
    );
    // The handoff signature changed.
    let mut h = good.clone();
    h.signature[0] ^= 1;
    assert_eq!(resume(&h), AuditError::Handoff("bad signature"));
    // The successor key changed to match a different seed's, signature kept.
    let mut h = good.clone();
    h.successor_key = SecretKey::from_seed(&other_seed).public_key().to_bytes();
    assert_eq!(
        Auditor::resume(&other_seed, config_for(pred, &other_seed, 0), pred, &h).unwrap_err(),
        AuditError::Handoff("bad signature")
    );
    // The checkpoint's last entry changed: another root.
    let mut h = good.clone();
    h.checkpoint.last.prefix_tree[0] ^= 1;
    assert_eq!(resume(&h), AuditError::PredecessorHead("bad signature"));
    // A preceding subtree value changed.
    let mut h = good.clone();
    h.checkpoint.preceding[0][0] ^= 1;
    assert_eq!(resume(&h), AuditError::PredecessorHead("bad signature"));
    // A preceding value dropped or added.
    let mut h = good.clone();
    h.checkpoint.preceding.pop();
    assert!(matches!(resume(&h), AuditError::Checkpoint(_)));
    let mut h = good.clone();
    h.checkpoint.preceding.push([1; 32]);
    assert!(matches!(resume(&h), AuditError::Checkpoint(_)));
    // The checkpoint moved to another size, with the head's size kept.
    let mut h = good.clone();
    h.checkpoint.tree_size += 2;
    assert!(matches!(resume(&h), AuditError::Checkpoint(_)));
    // The head's size or timestamp changed.
    let mut h = good.clone();
    h.head.tree_size -= 1;
    assert_eq!(
        resume(&h),
        AuditError::PredecessorHead("covers another tree size")
    );
    let mut h = good.clone();
    h.head.timestamp -= 1;
    assert_eq!(
        resume(&h),
        AuditError::PredecessorHead("not the rightmost entry's timestamp")
    );
    // The head's signature changed.
    let mut h = good.clone();
    h.head.signature[0] ^= 1;
    assert_eq!(resume(&h), AuditError::PredecessorHead("bad signature"));
    // A handoff checked against another predecessor's configuration.
    assert_eq!(
        Auditor::resume(&SUCCESSOR_SEED, config.clone(), &w.configs[1], &good).unwrap_err(),
        AuditError::PredecessorHead("bad signature")
    );
    // A handoff for a forked checkpoint, signed by a key that is not the
    // predecessor's: made by an impostor auditor on a fork.
    let (wa, _) = forked(3);
    let mut impostor = Auditor::new(&[12; 32], config_for(pred, &[12; 32], 0)).unwrap();
    for x in 0..5 {
        let (u, e) = feed(&wa, x);
        impostor.apply(x, &u, Some(&e)).unwrap();
    }
    let forged = impostor.hand_off(&successor_key()).unwrap();
    assert_eq!(
        resume(&forged),
        AuditError::PredecessorHead("bad signature")
    );
}

#[test]
fn a_successor_configuration_outside_the_rules_is_refused() {
    let w = fixed();
    let pred_start = 2;
    // A predecessor that itself started at 2 (as a successor would).
    let mut first = caught_up(&w, 2);
    let mid_seed = [13u8; 32];
    let mid_key = SecretKey::from_seed(&mid_seed).public_key().to_bytes();
    let h0 = first.hand_off(&mid_key).unwrap();
    let pred = config_for(&w.configs[0], &mid_seed, pred_start);
    let mut mid = Auditor::resume(&mid_seed, pred.clone(), &w.configs[0], &h0).unwrap();
    for x in 2..5 {
        let (u, e) = feed(&w, x);
        mid.apply(x, &u, Some(&e)).unwrap();
    }
    let handoff = mid.hand_off(&successor_key()).unwrap();
    let try_start = |start: u64| {
        Auditor::resume(
            &SUCCESSOR_SEED,
            config_for(&w.configs[0], &SUCCESSOR_SEED, start),
            &pred,
            &handoff,
        )
    };
    // Below its predecessor's start, or past the checkpoint.
    assert!(matches!(try_start(1), Err(AuditError::Configuration(_))));
    assert!(matches!(try_start(6), Err(AuditError::Configuration(_))));
    for start in 2..=5 {
        try_start(start).unwrap();
    }
    // A configuration naming another log key.
    let mut c = config_for(&w.configs[0], &SUCCESSOR_SEED, 3);
    c.signature_public_key = vec![5; 32];
    assert!(matches!(
        Auditor::resume(&SUCCESSOR_SEED, c, &pred, &handoff),
        Err(AuditError::Configuration(_))
    ));
    // A handoff to oneself is never signed.
    let mut again = caught_up(&w, 3);
    assert_eq!(
        again.hand_off(&again.public_key()).unwrap_err(),
        AuditError::Handoff("a successor needs a key of its own")
    );
    assert!(!again.is_retired());
}

// ---------------------------------------------------------------------------
// Cold starts
// ---------------------------------------------------------------------------

#[test]
fn a_cold_start_replays_from_the_first_entry_and_checks_the_predecessor() {
    let w = World::random(4, 30, 6);
    let mut old = caught_up(&w, 20);
    let head = old.sign_head().unwrap().auditor_tree_head;
    let config = config_for(&w.configs[0], &SUCCESSOR_SEED, 0);

    let mut new = Auditor::new(&SUCCESSOR_SEED, config.clone()).unwrap();
    for x in 0..20 {
        let (u, e) = feed(&w, x);
        new.apply(x, &u, Some(&e)).unwrap();
    }
    new.confirm_predecessor(&w.configs[0], &head).unwrap();
    assert_eq!(
        new.instance(5),
        AuditorInstance {
            boot_time: 5,
            start_position: 0,
            predecessor_key: Some(old.public_key()),
            handoff_sig: None,
        }
    );
    for x in 20..w.n() {
        let (u, e) = feed(&w, x);
        new.apply(x, &u, Some(&e)).unwrap();
    }
    let h = new.sign_head().unwrap();
    verify_auditor_tree_head(
        &h.auditor_tree_head,
        &config,
        &w.prover.root(w.n()).unwrap(),
    )
    .unwrap();

    // Short of the head, past it, or after signing: refused.
    let mut short = Auditor::new(&SUCCESSOR_SEED, config.clone()).unwrap();
    for x in 0..19 {
        let (u, e) = feed(&w, x);
        short.apply(x, &u, Some(&e)).unwrap();
    }
    assert_eq!(
        short.confirm_predecessor(&w.configs[0], &head),
        Err(AuditError::PredecessorHead("covers another tree size"))
    );
    let (u, e) = feed(&w, 19);
    short.apply(19, &u, Some(&e)).unwrap();
    short.sign_head().unwrap();
    assert!(matches!(
        short.confirm_predecessor(&w.configs[0], &head),
        Err(AuditError::PredecessorHead(_))
    ));
    // A changed head.
    let mut fresh = caught_up_as(&w, 20, &SUCCESSOR_SEED, &config);
    let mut bad = head.clone();
    bad.signature[1] ^= 1;
    assert_eq!(
        fresh.confirm_predecessor(&w.configs[0], &bad),
        Err(AuditError::PredecessorHead("bad signature"))
    );
    // Its own key as its predecessor.
    assert_eq!(
        fresh.confirm_predecessor(&config, &head),
        Err(AuditError::PredecessorHead("names this instance's own key"))
    );
    // A predecessor that signed for another log.
    let mut elsewhere = w.configs[0].clone();
    elsewhere.signature_public_key = vec![5; 32];
    assert!(matches!(
        fresh.confirm_predecessor(&elsewhere, &head),
        Err(AuditError::Configuration(_))
    ));
    // None of the refusals recorded a predecessor: the real one still checks.
    fresh.confirm_predecessor(&w.configs[0], &head).unwrap();
}

fn caught_up_as(w: &World, upto: u64, seed: &[u8; 32], config: &Configuration) -> Auditor {
    let mut a = Auditor::new(seed, config.clone()).unwrap();
    for x in 0..upto {
        let (u, e) = feed(w, x);
        a.apply(x, &u, Some(&e)).unwrap();
    }
    a
}

#[test]
fn a_cold_start_fed_a_fork_fails_the_predecessors_head() {
    // The predecessor signed the real lineage; the operator restarts the
    // auditor and replays a fork of the same length.
    let (wa, wb) = forked(4);
    let mut old = caught_up(&wa, 6);
    let head = old.sign_head().unwrap().auditor_tree_head;
    let config = config_for(&wa.configs[0], &SUCCESSOR_SEED, 0);
    let mut new = caught_up_as(&wb, 6, &SUCCESSOR_SEED, &config);
    assert_eq!(new.tree_size(), head.tree_size);
    // The fork's timestamps are the same, so only the signature catches it.
    assert_eq!(new.last_entry().unwrap().timestamp, head.timestamp);
    assert_eq!(
        new.confirm_predecessor(&wa.configs[0], &head),
        Err(AuditError::PredecessorHead("bad signature"))
    );
}
