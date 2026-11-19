// SPDX-License-Identifier: MIT
//! A framed Welcome is one length whichever member makes the add
//! (`mls/core/src/welcome_frame.rs`): in fresh groups, after every leaf has
//! rotated, around a removed leaf, on a reseat, and whichever members
//! committed since the last add.

#![cfg(feature = "test-forgery")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use std::collections::BTreeSet;

use peachy_mls_core::issuer::TestIssuer;
use peachy_mls_core::welcome_frame::{
    unframe_welcome, WELCOME_FRAME_BLOCK, WELCOME_FRAME_GAP_MAGIC, WELCOME_FRAME_HEADER_BYTES,
    WELCOME_FRAME_MAGIC, WELCOME_GAP_BLOCK_BYTES,
};
use peachy_mls_core::Client;
use support::{client, issuer};

const G: &[u8] = b"5e0b6c1d-2f3a-4b5c-8d6e-7f8091a2b3c4";

fn actor(i: u8) -> String {
    format!("a{i:07x}-0000-4000-8000-{i:012x}")
}

fn device(i: u8) -> String {
    format!("d{i:07x}-1111-4111-8111-{i:012x}")
}

/// A group whose leaves are, in order, the `(tag, person)` given. The first
/// founds it and adds each later one, so every leaf but the founder's is
/// still sourced from its key package and the parents carry unmerged leaves.
fn group(s: &TestIssuer, leaves: &[(u8, u8)]) -> Vec<Client> {
    let mut m: Vec<Client> = leaves
        .iter()
        .map(|&(tag, who)| client(s, tag, &actor(who), &device(tag)))
        .collect();
    m[0].create_group(G).unwrap();
    for i in 1..m.len() {
        let kp = m[i].generate_key_package().unwrap();
        let b = m[0].add_member(G, &kp).unwrap();
        m[0].merge_pending_commit(G).unwrap();
        for x in m.iter_mut().take(i).skip(1) {
            x.process_commit(G, &b.commit).unwrap();
        }
        m[i].join_from_welcome(&b.welcome.unwrap()).unwrap();
    }
    m
}

/// Every member commits once, in order: no leaf is key-package-sourced and
/// no parent left blank by the founding stays blank.
fn rotate_all(m: &mut [Client]) {
    for by in 0..m.len() {
        let c = m[by].self_update(G).unwrap().commit;
        m[by].merge_pending_commit(G).unwrap();
        for (i, x) in m.iter_mut().enumerate() {
            if i != by {
                x.process_commit(G, &c).unwrap();
            }
        }
    }
}

/// `m[by]` removes the leaf at `leaf`, and everybody else follows.
fn remove(m: &mut Vec<Client>, by: usize, leaf: u32, gone: usize) {
    let c = m[by].remove_leaf(G, leaf).unwrap().commit;
    m[by].merge_pending_commit(G).unwrap();
    for (i, x) in m.iter_mut().enumerate() {
        if i != by && i != gone {
            x.process_commit(G, &c).unwrap();
        }
    }
    m.remove(gone);
}

/// The raw Welcome inside each of `framed`.
fn unframed(framed: &[Vec<u8>]) -> Vec<Vec<u8>> {
    framed
        .iter()
        .map(|bytes| unframe_welcome(bytes).unwrap().to_vec())
        .collect()
}

/// Each member in turn, from the same epoch, adds a fresh key package of
/// `joiner` and drops the commit again: the Welcome each one sends, and the
/// bound it padded to.
fn welcomes_and_bounds(m: &mut [Client], joiner: &Client) -> (Vec<Vec<u8>>, Vec<Option<usize>>) {
    m.iter_mut()
        .map(|x| {
            let kp = joiner.generate_key_package().unwrap();
            let b = x.add_member(G, &kp).unwrap();
            x.clear_pending_commit(G).unwrap();
            (b.welcome.unwrap(), x.welcome_bound_seen())
        })
        .unzip()
}

/// The frame's length for the largest of `raw`.
fn tightest(raw: &[Vec<u8>]) -> usize {
    let largest = raw.iter().map(Vec::len).max().unwrap();
    (WELCOME_FRAME_HEADER_BYTES + largest).div_ceil(WELCOME_FRAME_BLOCK) * WELCOME_FRAME_BLOCK
}

/// [`tightest`] for a reseat's frame, which carries a gap block of one
/// length whatever it holds (`welcome_frame.rs` §The gap block).
fn tightest_with_gap(raw: &[Vec<u8>]) -> usize {
    let largest = raw.iter().map(Vec::len).max().unwrap();
    (WELCOME_FRAME_HEADER_BYTES + largest + WELCOME_GAP_BLOCK_BYTES).div_ceil(WELCOME_FRAME_BLOCK)
        * WELCOME_FRAME_BLOCK
}

/// The heart of it: every member's framed Welcome is one length, padded to
/// one bound every adder computes alike, which no member's raw Welcome
/// exceeds; and the frame opens to the raw Welcome its adder built.
fn assert_one_length(label: &str, m: &mut [Client], joiner: &Client) -> usize {
    let (framed, bounds) = welcomes_and_bounds(m, joiner);
    let raw = unframed(&framed);
    let bounds: BTreeSet<Option<usize>> = bounds.into_iter().collect();
    assert_eq!(
        bounds.len(),
        1,
        "{label}: adders' bounds differ: {bounds:?}"
    );
    let bound = bounds.into_iter().next().unwrap().unwrap();
    let raw_lens: Vec<usize> = raw.iter().map(Vec::len).collect();
    assert!(
        raw_lens.iter().all(|&len| len <= bound),
        "{label}: a raw Welcome {raw_lens:?} is past the bound {bound}"
    );
    let lens: BTreeSet<usize> = framed.iter().map(Vec::len).collect();
    eprintln!("{label}: bound {bound}, framed {lens:?}");
    assert_eq!(
        lens.len(),
        1,
        "{label}: framed lengths differ by adder: {lens:?}"
    );
    let len = *lens.iter().next().unwrap();
    assert!(len >= tightest(&raw), "{label}: padded below a Welcome");
    for (adder, bytes) in framed.iter().enumerate() {
        assert_eq!(bytes[..4], WELCOME_FRAME_MAGIC, "{label}: adder {adder}");
        let inner = unframe_welcome(bytes).unwrap();
        assert_eq!(
            inner.len(),
            raw_lens[adder],
            "{label}: adder {adder}'s Welcome"
        );
    }
    len
}

#[test]
fn a_three_leaf_dm_framed_welcome_is_one_length() {
    let s = issuer();
    // Ada's phone, Bo, Ada's laptop.
    let mut m = group(&s, &[(1, 1), (2, 2), (3, 1)]);
    let joiner = client(&s, 4, &actor(2), &device(4));
    assert_one_length("3-leaf DM, fresh", &mut m, &joiner);
    rotate_all(&mut m);
    assert_one_length("3-leaf DM, after rotations", &mut m, &joiner);

    // And the frame seats the joiner, from whichever member made it.
    let mut joiner = joiner;
    let kp = joiner.generate_key_package().unwrap();
    let b = m[2].add_member(G, &kp).unwrap();
    m[2].merge_pending_commit(G).unwrap();
    for x in m.iter_mut().take(2) {
        x.process_commit(G, &b.commit).unwrap();
    }
    let welcome = b.welcome.unwrap();
    assert_eq!(welcome[..4], WELCOME_FRAME_MAGIC);
    assert_eq!(joiner.join_from_welcome(&welcome).unwrap(), G.to_vec());
    let sent = m[0].encrypt(G, b"hello").unwrap();
    assert!(joiner.process_message(G, &sent).is_ok());
}

#[test]
fn groups_of_two_to_nine_send_one_length_whoever_adds() {
    let s = issuer();
    for n in [2u8, 4, 5, 6, 7, 9] {
        let leaves: Vec<(u8, u8)> = (1..=n).map(|i| (i, i)).collect();
        let mut m = group(&s, &leaves);
        let joiner = client(&s, 100 + n, &actor(100 + n), &device(100 + n));
        let fresh = assert_one_length(&format!("{n} leaves, fresh"), &mut m, &joiner);
        rotate_all(&mut m);
        let rotated = assert_one_length(&format!("{n} leaves, after rotations"), &mut m, &joiner);
        assert_eq!(
            fresh, rotated,
            "{n} leaves: the rotations show in the Welcome"
        );
    }
}

#[test]
fn a_blank_leaf_and_its_blank_path_change_nothing() {
    let s = issuer();
    let leaves: Vec<(u8, u8)> = (1..=6).map(|i| (i, i)).collect();
    let mut m = group(&s, &leaves);
    rotate_all(&mut m);
    // Leaf 1 goes: the joiner takes its slot, and its path is blank.
    remove(&mut m, 0, 1, 1);
    let joiner = client(&s, 120, &actor(120), &device(120));
    assert_one_length("6 leaves, leaf 1 removed", &mut m, &joiner);
    // The rightmost goes too: the tree may shrink.
    remove(&mut m, 0, 5, 4);
    assert_one_length("6 leaves, leaves 1 and 5 removed", &mut m, &joiner);
}

#[test]
fn a_reseat_sends_one_length_whoever_answers() {
    let s = issuer();
    let mut m = group(&s, &[(1, 1), (2, 2), (3, 1)]);
    rotate_all(&mut m);
    // Bo's device (leaf 1) lost its state and asks back in; Ada's phone and
    // Ada's laptop could each answer.
    let mut returning = client(&s, 2, &actor(2), &device(2));
    let mut framed_lens = BTreeSet::new();
    let mut raw = Vec::new();
    for adder in [0usize, 2] {
        let kp = returning.generate_key_package().unwrap();
        let b = m[adder].replace_member(G, 1, &kp).unwrap();
        m[adder].clear_pending_commit(G).unwrap();
        let welcome = b.welcome.unwrap();
        framed_lens.insert(welcome.len());
        let inner = unframe_welcome(&welcome).unwrap().to_vec();
        raw.push(inner);
    }
    eprintln!("reseat in a 3-leaf DM: framed {framed_lens:?}");
    assert_eq!(framed_lens.len(), 1, "{framed_lens:?}");
    assert!(*framed_lens.iter().next().unwrap() >= tightest_with_gap(&raw));

    // And the returning device takes its seat from a frame.
    let kp = returning.generate_key_package().unwrap();
    let b = m[2].replace_member(G, 1, &kp).unwrap();
    m[2].merge_pending_commit(G).unwrap();
    m[0].process_commit(G, &b.commit).unwrap();
    let welcome = b.welcome.unwrap();
    assert_eq!(welcome[..4], WELCOME_FRAME_GAP_MAGIC, "a reseat's frame");
    returning.join_from_welcome(&welcome).unwrap();
    let sent = m[0].encrypt(G, b"back").unwrap();
    assert!(returning.process_message(G, &sent).is_ok());
}

/// `m[by]` makes one sessionless leaf rotation, and everybody follows.
fn rotate(m: &mut [Client], by: usize) {
    let c = m[by].self_update(G).unwrap().commit;
    m[by].merge_pending_commit(G).unwrap();
    for (i, x) in m.iter_mut().enumerate() {
        if i != by {
            x.process_commit(G, &c).unwrap();
        }
    }
}

/// The framed Welcome every member sends adding `joiner` now: one length,
/// whoever adds.
fn framed_len(m: &mut [Client], joiner: &Client) -> usize {
    let (framed, _) = welcomes_and_bounds(m, joiner);
    let lens: BTreeSet<usize> = framed.iter().map(Vec::len).collect();
    assert_eq!(lens.len(), 1, "framed lengths differ by adder: {lens:?}");
    lens.into_iter().next().unwrap()
}

/// A commit between two adds leaves the next framed Welcome's length as it was.
#[test]
fn the_next_framed_welcome_is_one_length_whoever_committed_before() {
    let s = issuer();
    for n in 3u8..=9 {
        let people: Vec<(u8, u8)> = (1..=n).map(|i| (i, i)).collect();
        let joiner = client(&s, 200, &actor(200), &device(200));
        let baseline = framed_len(&mut group(&s, &people), &joiner);
        for by in 0..n as usize {
            let mut m = group(&s, &people);
            rotate(&mut m, by);
            assert_eq!(
                framed_len(&mut m, &joiner),
                baseline,
                "n={n}: a rotation by leaf {by} shows in the next Welcome"
            );
        }
    }
    let people: Vec<(u8, u8)> = (1..=8).map(|i| (i, i)).collect();
    let joiner = client(&s, 201, &actor(201), &device(201));
    let baseline = framed_len(&mut group(&s, &people), &joiner);
    for a in 0..8 {
        for b in a + 1..8 {
            let mut m = group(&s, &people);
            rotate(&mut m, a);
            rotate(&mut m, b);
            assert_eq!(
                framed_len(&mut m, &joiner),
                baseline,
                "n=8: rotations by leaves {a} and {b} show in the next Welcome"
            );
        }
    }
}
