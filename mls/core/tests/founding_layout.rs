// SPDX-License-Identifier: MIT
//! Where a founding seats its joiners says nothing of who founded
//! (docs/delivery.md §Founding a conversation).
//!
//! The founder's device is leaf 0, and the server knows every device a
//! founding seats and, from the next recipient list, which one a removal
//! took out. Were the joiners seated in an order the server can work out
//! (by device id), a removed device's leaf would say on which side of it
//! the founder's id sorts, and any length that depends on where the removed
//! leaf sat would say it to the server. So:
//!
//! - **The joiners take their leaves in an order drawn at random**, not the
//!   order the founder's client passed them, and not by device id.
//! - **A commit's padded length depends only on the tree's width and how
//!   many members it holds**, never on where its blanks and filled parents
//!   sit: the Remove of any device, and the commits after it, are one length
//!   whoever founded. The one thing a removal can still show is a tree that
//!   halves, which happens only when the rightmost leaf goes, and the
//!   founder's leaf 0 is never rightmost while anyone else is seated.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use std::collections::{BTreeMap, BTreeSet};

use peachy_mls_core::issuer::TestIssuer;
use peachy_mls_core::Client;
use support::{client, issuer};

fn actor(k: usize) -> String {
    format!("{:08x}-0000-4000-8000-{:012x}", k + 1, k + 1)
}

fn device(k: usize) -> String {
    format!("{:08x}-1111-4111-8111-{:012x}", k + 1, k + 1)
}

fn group_id(k: usize) -> Vec<u8> {
    format!("3c1f6e0a-7b2d-4c8e-9a5f-{k:012x}").into_bytes()
}

fn clients(s: &TestIssuer, n: usize) -> Vec<Client> {
    (0..n)
        .map(|k| client(s, u8::try_from(k + 1).unwrap(), &actor(k), &device(k)))
        .collect()
}

/// The documented founding (docs/delivery.md §Founding a
/// conversation): the refusals read on the group of one, the state commit,
/// one seating commit, merged.
fn found(clients: &mut [Client], g: &[u8], f: usize) {
    let others: Vec<Vec<u8>> = (0..clients.len())
        .filter(|&k| k != f)
        .map(|k| clients[k].generate_key_package().unwrap())
        .collect();
    let founder = &mut clients[f];
    let own = founder.generate_key_package().unwrap();
    founder.create_group(g).unwrap();
    assert!(founder.founding_refusals(g, &others).unwrap().is_empty());
    let state = format!(r#"{{"v":1,"n":"","adm":["{}"]}}"#, actor(f));
    founder.set_group_meta(g, state.as_bytes()).unwrap();
    founder.merge_pending_commit(g).unwrap();
    founder.seat_founding(g, &others, &own).unwrap();
    founder.merge_pending_commit(g).unwrap();
}

/// The order the joiners took their leaves in, by device index.
fn seating(founder: &Client, g: &[u8], n: usize, f: usize) -> Vec<usize> {
    let mut by_leaf: Vec<(u32, usize)> = (0..n)
        .filter(|&k| k != f)
        .map(|k| (founder.leaf_of_device(g, &device(k)).unwrap(), k))
        .collect();
    by_leaf.sort_unstable();
    assert_eq!(
        founder.leaf_of_device(g, &device(f)).unwrap(),
        0,
        "the founder is leaf 0"
    );
    by_leaf.into_iter().map(|(_, k)| k).collect()
}

#[test]
fn a_founding_seats_its_joiners_in_an_order_nobody_chose() {
    let s = issuer();
    let n = 5;
    let mut members = clients(&s, n);
    let mut orders = BTreeSet::new();
    for round in 0..12 {
        let g = group_id(round);
        found(&mut members, &g, 0);
        orders.insert(seating(&members[0], &g, n, 0));
    }
    // Twelve foundings of the same four joiners, passed in device-id order
    // every time. A fixed order (theirs, or by device id) would give one; a
    // random one gives all twelve alike once in 24^11.
    assert!(
        orders.len() > 1,
        "every founding seated them alike: {orders:?}"
    );
}

/// The Remove's length and the two rotations' after it.
type Lengths = (usize, usize, usize);

/// Device `f` founds a group of `n`, then removes device `r` and rotates its
/// leaf twice: the three commits' lengths, and whether `r` sat at the leaf
/// whose removal halves the tree.
fn lengths(members: &mut [Client], g: &[u8], f: usize, r: usize) -> (Lengths, bool) {
    let n = members.len();
    found(members, g, f);
    let founder = &mut members[f];
    let leaf = founder.leaf_of_device(g, &device(r)).unwrap();
    let last = u32::try_from(n - 1).unwrap();
    let halves = leaf == last && (n - 1).is_power_of_two();
    let key = support::leaf_key_at(founder, g, leaf);
    let remove = founder.remove_member(g, leaf, &key).unwrap();
    founder.merge_pending_commit(g).unwrap();
    let rotate = founder.self_update(g).unwrap();
    founder.merge_pending_commit(g).unwrap();
    let rotate2 = founder.self_update(g).unwrap();
    founder.merge_pending_commit(g).unwrap();
    (
        (
            remove.commit.len(),
            rotate.commit.len(),
            rotate2.commit.len(),
        ),
        halves,
    )
}

#[test]
fn after_a_removal_every_length_is_the_same_whoever_founded() {
    let s = issuer();
    let mut round = 0;
    for n in 3..=9 {
        let mut members = clients(&s, n);
        // (whether the removal halved the tree) -> the lengths, and who
        // founded and was removed the first time they were seen.
        let mut seen: BTreeMap<bool, (Lengths, (usize, usize))> = BTreeMap::new();
        for f in 0..n {
            for r in (0..n).filter(|&r| r != f) {
                round += 1;
                let (got, halves) = lengths(&mut members, &group_id(round), f, r);
                let (want, first) = *seen.entry(halves).or_insert((got, (f, r)));
                assert_eq!(
                    got, want,
                    "n={n}: founded by #{f}, #{r} removed, against founded by #{}, #{} removed \
                     (the tree halved: {halves})",
                    first.0, first.1,
                );
            }
        }
    }
}
