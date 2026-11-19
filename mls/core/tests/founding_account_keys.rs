// SPDX-License-Identifier: MIT
//! A FOUNDING NAMES THE PACKAGE THAT WOULD PUT ONE PERSON UNDER TWO ACCOUNT
//! KEYS (docs/delivery.md §Founding a conversation).
//!
//! `founding_refusals` judges each package by the rule the founding commit is
//! judged by (one person, one account key), against the founder's own leaf
//! and the packages accepted before it, first come first seated. So a package
//! the commit would refuse is left out by name, and the rest are seated in
//! the one commit, rather than one package failing the whole founding.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use peachy_mls_core::issuer::{device_key_pair, TestIssuer};
use peachy_mls_core::{account_identity_public_key, Client, ClientConfig, Error, PeachyStorage};
use support::{client, device_seed, issuer, DAY, HOUR, NOW};

const G: &[u8] = b"3c1f6e0a-7b2d-4c8e-9a5f-1e0d2c4b6a88";

const ALICE: &str = "aaaaaaaa-0000-4000-8000-000000000001";
const BOB: &str = "bbbbbbbb-0000-4000-8000-000000000002";
const CAROL: &str = "cccccccc-0000-4000-8000-000000000003";
const ALICE_PHONE: &str = "aaaaaaaa-1111-4111-8111-000000000001";
const ALICE_OTHER: &str = "aaaaaaaa-1111-4111-8111-000000000009";
const BOB_PHONE: &str = "bbbbbbbb-1111-4111-8111-000000000003";
const BOB_OTHER: &str = "bbbbbbbb-1111-4111-8111-000000000008";
const CAROL_PHONE: &str = "cccccccc-1111-4111-8111-000000000004";

/// A device of `actor` the server certified under an account key of its own,
/// which it can do (docs/identity.md §One account key per person).
fn under_the_servers_key(s: &TestIssuer, tag: u8, actor: &str, device: &str) -> Client {
    let server_account = [0x5au8; 32];
    let seed = device_seed(tag);
    let (_, public) = device_key_pair(&seed);
    let token = s
        .issue_for_account(
            actor,
            device,
            &public,
            Some(&server_account),
            NOW - HOUR,
            NOW + 30 * DAY,
        )
        .unwrap();
    let mut config = ClientConfig::new(token, seed, s.trusted_keys().unwrap())
        .with_storage(PeachyStorage::in_memory())
        .with_own_account_identity(Some(account_identity_public_key(&server_account).unwrap()));
    config.clock = Some(Box::new(support::TestClock));
    Client::new(config).unwrap()
}

/// The door names `index`, the founding of every package refuses as the
/// commit would, and the founding of the rest seats them in one commit.
fn names_and_seats_the_rest(alice: &mut Client, all: &[Vec<u8>], index: u32) {
    assert_eq!(alice.founding_refusals(G, all).unwrap(), vec![index]);
    let own = alice.generate_key_package().unwrap();
    let err = alice.seat_founding(G, all, &own).unwrap_err();
    assert!(matches!(err, Error::PolicyRefused(_)), "{err:?}");
    assert!(!alice.has_pending_commit(G).unwrap());
    let rest: Vec<Vec<u8>> = all
        .iter()
        .enumerate()
        .filter(|(i, _)| *i as u32 != index)
        .map(|(_, package)| package.clone())
        .collect();
    let own = alice.generate_key_package().unwrap();
    alice
        .seat_founding(G, &rest, &own)
        .expect("the rest are seated in one commit");
}

/// A package of the founder's own person under another account key: refused
/// at any add of hers, so the door names it.
#[test]
fn a_package_of_the_founder_under_another_key_is_named() {
    let s = issuer();
    let mut alice = client(&s, 1, ALICE, ALICE_PHONE);
    let bob = client(&s, 2, BOB, BOB_PHONE);
    let carol = client(&s, 3, CAROL, CAROL_PHONE);
    let other = under_the_servers_key(&s, 9, ALICE, ALICE_OTHER);
    alice.create_group(G).unwrap();
    let all = vec![
        bob.generate_key_package().unwrap(),
        carol.generate_key_package().unwrap(),
        other.generate_key_package().unwrap(),
    ];
    names_and_seats_the_rest(&mut alice, &all, 2);
}

/// Two packages of one other person under two account keys: the later one is
/// named, whichever of the two comes first.
#[test]
fn a_second_key_for_one_person_is_named_first_come_first_seated() {
    let s = issuer();
    let bob = client(&s, 12, BOB, BOB_PHONE);
    let carol = client(&s, 13, CAROL, CAROL_PHONE);
    let other = under_the_servers_key(&s, 18, BOB, BOB_OTHER);

    let mut alice = client(&s, 11, ALICE, ALICE_PHONE);
    alice.create_group(G).unwrap();
    let all = vec![
        bob.generate_key_package().unwrap(),
        carol.generate_key_package().unwrap(),
        other.generate_key_package().unwrap(),
    ];
    names_and_seats_the_rest(&mut alice, &all, 2);

    let mut alice = client(&s, 11, ALICE, ALICE_PHONE);
    alice.create_group(G).unwrap();
    let all = vec![
        other.generate_key_package().unwrap(),
        carol.generate_key_package().unwrap(),
        bob.generate_key_package().unwrap(),
    ];
    names_and_seats_the_rest(&mut alice, &all, 2);
}
