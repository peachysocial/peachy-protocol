// SPDX-License-Identifier: MIT
//! Nothing a founding submits singles out who founded the conversation
//! (docs/delivery.md §Founding a conversation,
//! `peachy_mls_core::founding`). The server still sees which devices a
//! founding takes KeyPackages from, the founder's own among them, and when
//! and from where each request came; these tests hold the rest.
//!
//! Each test models the server's whole view of a founding: the recipients,
//! Welcomes and access keys of every `SubmitCommit`, the KeyPackages it
//! handed out, and the refs in the Welcome's clear `secrets` list, which it
//! can match to those packages. It asserts no field and no leftover device
//! singles out the founder, even when the server spoils or withholds a
//! package.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use std::cell::Cell;
use std::collections::BTreeSet;

use openmls::prelude::{
    BasicCredential, Capabilities, Ciphersuite, Credential, CredentialType, CredentialWithKey,
    KeyPackage, Lifetime, MlsMessageBodyIn, MlsMessageIn, MlsMessageOut,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::{MemoryStorage, RustCrypto};
use openmls_traits::random::OpenMlsRand;
use openmls_traits::types::SignatureScheme;
use openmls_traits::OpenMlsProvider;
use peachy_mls_core::group_meta::group_meta_extension_type;
use peachy_mls_core::welcome_frame::unframe_welcome;
use peachy_mls_core::{Client, Error, PEACHY_CIPHERSUITE, SEND_KEY_LABEL};
use sha2::{Digest as _, Sha256};
use support::{client, device_seed, issuer, other_issuer, DAY, HOUR, NOW};
use tls_codec::Deserialize as _;

const G: &[u8] = b"3c1f6e0a-7b2d-4c8e-9a5f-1e0d2c4b6a88";

const ALICE: &str = "aaaaaaaa-0000-4000-8000-000000000001";
const BOB: &str = "bbbbbbbb-0000-4000-8000-000000000002";
const CAROL: &str = "cccccccc-0000-4000-8000-000000000003";
const ALICE_PHONE: &str = "aaaaaaaa-1111-4111-8111-000000000001";
const ALICE_LAPTOP: &str = "aaaaaaaa-1111-4111-8111-000000000002";
const BOB_PHONE: &str = "bbbbbbbb-1111-4111-8111-000000000003";
const CAROL_PHONE: &str = "cccccccc-1111-4111-8111-000000000004";
const GHOST: &str = "dddddddd-1111-4111-8111-000000000005";
const MALLORY: &str = "ffffffff-0000-4000-8000-000000000006";
const MALLORY_PHONE: &str = "ffffffff-1111-4111-8111-000000000006";
const MALLORY_LAPTOP: &str = "ffffffff-1111-4111-8111-000000000007";

/// One `SubmitCommit` as the server receives it: each recipient and Welcome
/// with its device and account, and the accounts of `access_keys` in the
/// order sent.
struct Submitted {
    recipients: Vec<(String, String)>,
    welcomes: Vec<(String, String, Vec<u8>)>,
    access_keys: Vec<String>,
}

impl Submitted {
    /// As docs/delivery.md §Sending has a client list them:
    /// `access_keys` in the order their accounts first appear in
    /// `recipients`, then in `welcomes`.
    fn new(recipients: Vec<(String, String)>, welcomes: Vec<(String, String, Vec<u8>)>) -> Self {
        let mut access_keys: Vec<String> = Vec::new();
        let accounts = recipients
            .iter()
            .map(|(_, a)| a)
            .chain(welcomes.iter().map(|(_, a, _)| a));
        for account in accounts {
            if !access_keys.contains(account) {
                access_keys.push(account.clone());
            }
        }
        Submitted {
            recipients,
            welcomes,
            access_keys,
        }
    }
}

/// A package the directory handed out: the device and the account it was
/// listed under, and its bytes.
type Handed = (String, String, Vec<u8>);

/// The tree's devices, with their accounts, in leaf order.
fn tree_of(member: &Client) -> Vec<(String, String)> {
    member
        .roster(G)
        .unwrap()
        .into_iter()
        .map(|e| {
            let id = e.identity.unwrap();
            (id.device_id, id.actor_id)
        })
        .collect()
}

/// As docs/delivery.md §Sending has a client list `recipients`:
/// every device of the tree once, sorted bytewise by device id, never in
/// leaf order.
fn recipients_of(member: &Client) -> Vec<(String, String)> {
    let mut out = tree_of(member);
    out.sort();
    out.dedup_by(|a, b| a.0 == b.0);
    out
}

/// The KeyPackageRefs a Welcome's clear `secrets` list names, in order.
fn refs_in(welcome: &[u8]) -> Vec<Vec<u8>> {
    let raw = unframe_welcome(welcome).unwrap();
    let MlsMessageBodyIn::Welcome(w) = MlsMessageIn::tls_deserialize_exact(raw).unwrap().extract()
    else {
        panic!("not a Welcome");
    };
    w.secrets()
        .iter()
        .map(|s| s.new_member().as_slice().to_vec())
        .collect()
}

fn head_of(member: &Client) -> (u64, Vec<u8>) {
    let key = member.export_secret(G, SEND_KEY_LABEL, G, 32).unwrap();
    (member.epoch(G).unwrap(), Sha256::digest(key).to_vec())
}

/// The documented founding (docs/delivery.md §Founding a
/// conversation, founding seats on), from its one fetch: this device's own
/// package checked as a valid KeyPackage of this device, and the core's
/// refusals (`founding_refusals`) read on the group of one, both before
/// anything is sent; then the state commit, then one commit seating every
/// handed-out package the core does not refuse, each submitted with no
/// recipients, the Welcome to every device in device-id order, the
/// founder's included; then an ordinary add for each package left out, its
/// set the whole tree. With no own package, no other person's package left
/// when the founding seats another person, or the founding still refused, it
/// fails: nothing is fetched again, and nothing falls back to one add per
/// commit. Every founding here means to seat another person. Returns what
/// the server saw, and the founding's Welcome unless it failed.
fn found(
    founder: &mut Client,
    handed_out: &[Handed],
    own_package: Option<&[u8]>,
) -> (Vec<Submitted>, Option<Vec<u8>>) {
    let mut seen = Vec::new();
    let me = founder.identity().clone();
    let Some(own_package) = own_package else {
        return (seen, None);
    };
    let own_is_mine = matches!(
        founder.key_package_identity(own_package),
        Ok(Ok(id)) if id.device_id == me.device_id && id.device_key == me.device_key
    );
    if !own_is_mine {
        return (seen, None);
    }
    founder.create_group(G).unwrap();

    // Decided on the group of one, before the conversation is opened.
    let all: Vec<Vec<u8>> = handed_out.iter().map(|(_, _, kp)| kp.clone()).collect();
    let refused = founder.founding_refusals(G, &all).unwrap();
    let left_out = |i: usize| refused.iter().any(|&r| r as usize == i);
    let seating: Vec<&Handed> = handed_out
        .iter()
        .enumerate()
        .filter(|(i, _)| !left_out(*i))
        .map(|(_, h)| h)
        .collect();
    if !seating
        .iter()
        .any(|(_, account, _)| *account != me.actor_id)
    {
        return (seen, None);
    }

    let state = format!(r#"{{"v":1,"n":"","adm":["{ALICE}","{BOB}"],"dm":true}}"#);
    founder.set_group_meta(G, state.as_bytes()).unwrap();
    founder.merge_pending_commit(G).unwrap();
    seen.push(Submitted::new(vec![], vec![]));

    let packages: Vec<Vec<u8>> = seating.iter().map(|(_, _, kp)| kp.clone()).collect();
    let Ok(bundle) = founder.seat_founding(G, &packages, own_package) else {
        return (seen, None);
    };
    founder.merge_pending_commit(G).unwrap();
    let welcome = bundle.welcome.unwrap();
    let mut devices: Vec<(String, String)> = seating
        .iter()
        .map(|(d, a, _)| (d.clone(), a.clone()))
        .collect();
    devices.push((me.device_id, me.actor_id));
    devices.sort();
    let welcomes = devices
        .into_iter()
        .map(|(d, a)| (d, a, welcome.clone()))
        .collect();
    seen.push(Submitted::new(vec![], welcomes));

    // Every package left out: an ordinary add once the founding is merged.
    for (i, (device, account, kp)) in handed_out.iter().enumerate() {
        if !left_out(i) {
            continue;
        }
        let recipients = recipients_of(founder);
        let Ok(add) = founder.add_member(G, kp) else {
            continue;
        };
        founder.merge_pending_commit(G).unwrap();
        let welcomes = vec![(device.clone(), account.clone(), add.welcome.unwrap())];
        seen.push(Submitted::new(recipients, welcomes));
    }
    (seen, Some(welcome))
}

/// No founding commit names a recipient, and the founder is Welcomed like
/// everyone else, so no device of the tree is left over for later sets.
#[test]
fn founding_commits_name_nobody_in_their_recipients() {
    let s = issuer();
    let mut alice = client(&s, 1, ALICE, ALICE_PHONE);
    let mut bob = client(&s, 2, BOB, BOB_PHONE);

    // What the directory handed out: one package per device, the founder's
    // own included, each with the ref it was published under.
    let (bob_kp, bob_ref) = bob.generate_key_package_with_ref().unwrap();
    let (own_kp, own_ref) = alice.generate_key_package_with_ref().unwrap();
    let (seen, welcome) = found(
        &mut alice,
        &[(BOB_PHONE.into(), BOB.into(), bob_kp)],
        Some(&own_kp),
    );
    let welcome = welcome.unwrap();

    // No founding commit names anybody as a recipient.
    for submitted in &seen {
        assert!(submitted.recipients.is_empty());
    }
    // The founder is Welcomed like Bob, with the same bytes.
    let add = &seen[1];
    let welcomed: BTreeSet<&str> = add.welcomes.iter().map(|(d, _, _)| d.as_str()).collect();
    assert_eq!(welcomed, BTreeSet::from([ALICE_PHONE, BOB_PHONE]));
    assert!(add.welcomes.iter().all(|(_, _, w)| *w == welcome));
    // Every package the directory handed out has one entry, and nothing else
    // does: no Welcome recipient is short of a seat.
    let refs = refs_in(&welcome);
    assert_eq!(
        refs.iter().cloned().collect::<BTreeSet<_>>(),
        BTreeSet::from([bob_ref, own_ref])
    );
    assert_eq!(refs.len(), 2);
    // And every device the tree holds afterwards came in on a Welcome, so the
    // set every later send names has no device left over.
    let tree: BTreeSet<String> = alice
        .roster(G)
        .unwrap()
        .into_iter()
        .map(|e| e.identity.unwrap().device_id)
        .collect();
    assert_eq!(tree, welcomed.iter().map(|d| d.to_string()).collect());

    // Bob joins, at the head; the conversation works.
    let (h, v) = head_of(&alice);
    bob.join_from_welcome_at_head(&welcome, h, &v).unwrap();
    let wire = alice.encrypt(G, b"hi").unwrap();
    assert!(bob.process_message(G, &wire).is_ok());
}

/// The founder on two devices, plus Bob. One commit seats both, so there is
/// no sequence of sets to read an order from, and the Welcome's entries are
/// in ref order.
#[test]
fn one_commit_seats_everyone_with_no_order_to_read() {
    let s = issuer();
    let mut phone = client(&s, 1, ALICE, ALICE_PHONE);
    let mut laptop = client(&s, 4, ALICE, ALICE_LAPTOP);
    let mut bob = client(&s, 2, BOB, BOB_PHONE);

    let (bob_kp, _) = bob.generate_key_package_with_ref().unwrap();
    let (laptop_kp, _) = laptop.generate_key_package_with_ref().unwrap();
    let (own_kp, _) = phone.generate_key_package_with_ref().unwrap();
    let (seen, welcome) = found(
        &mut phone,
        &[
            (BOB_PHONE.into(), BOB.into(), bob_kp),
            (ALICE_LAPTOP.into(), ALICE.into(), laptop_kp),
        ],
        Some(&own_kp),
    );
    let welcome = welcome.unwrap();

    // The state commit and ONE seating commit: the epoch moves 0, 1, 2.
    assert_eq!(seen.len(), 2);
    assert_eq!(phone.epoch(G).unwrap(), 2);
    let refs = refs_in(&welcome);
    let mut sorted = refs.clone();
    sorted.sort();
    assert_eq!(refs, sorted, "entries are in ref order, not seating order");
    assert_eq!(refs.len(), 3);

    let (h, v) = head_of(&phone);
    bob.join_from_welcome_at_head(&welcome, h, &v).unwrap();
    laptop.join_from_welcome_at_head(&welcome, h, &v).unwrap();
    assert_eq!(bob.epoch(G).unwrap(), 2);
    assert_eq!(laptop.epoch(G).unwrap(), 2);
}

/// The founder's own copy of the Welcome opens nothing and leaves her group
/// as it was, whether her seat was a one-time package or her last-resort one.
#[test]
fn the_founders_own_copy_opens_nothing() {
    for last_resort in [false, true] {
        let s = issuer();
        let mut alice = client(&s, 1, ALICE, ALICE_PHONE);
        let bob = client(&s, 2, BOB, BOB_PHONE);
        let (bob_kp, _) = bob.generate_key_package_with_ref().unwrap();
        let (own_kp, _) = if last_resort {
            alice.generate_last_resort_key_package_with_ref().unwrap()
        } else {
            alice.generate_key_package_with_ref().unwrap()
        };
        let (_, welcome) = found(
            &mut alice,
            &[(BOB_PHONE.into(), BOB.into(), bob_kp)],
            Some(&own_kp),
        );
        let welcome = welcome.unwrap();

        // Refused as an MLS failure: not a storage fault and not "settle
        // first", the two every client's drain holds the mailbox for, so the
        // copy is acked and gone.
        assert!(matches!(alice.welcome_group(&welcome), Err(Error::Mls(_))));
        let (h, v) = head_of(&alice);
        assert!(matches!(
            alice.join_from_welcome_at_head(&welcome, h, &v),
            Err(Error::Mls(_))
        ));
        assert!(matches!(
            alice.join_from_welcome(&welcome),
            Err(Error::Mls(_))
        ));
        assert!(alice.is_active(G).unwrap());
        assert_eq!(alice.epoch(G).unwrap(), 2);
        assert_eq!(alice.roster(G).unwrap().len(), 2);
    }
}

/// A founding seats only a group whose one leaf is the founder, and only
/// with a seat of the founder's own device.
#[test]
fn a_founding_is_refused_outside_its_shape() {
    let s = issuer();
    let mut alice = client(&s, 1, ALICE, ALICE_PHONE);
    let mut bob = client(&s, 2, BOB, BOB_PHONE);
    let laptop = client(&s, 4, ALICE, ALICE_LAPTOP);
    alice.create_group(G).unwrap();

    // Somebody else's package as the founder's seat.
    let bob_kp = bob.generate_key_package().unwrap();
    let laptop_kp = laptop.generate_key_package().unwrap();
    assert!(alice
        .seat_founding(G, std::slice::from_ref(&bob_kp), &laptop_kp)
        .is_err());
    assert!(!alice.has_pending_commit(G).unwrap());
    // Nobody to seat.
    let own_kp = alice.generate_key_package().unwrap();
    assert!(alice.seat_founding(G, &[], &own_kp).is_err());

    // Once anybody else holds a leaf, it is no founding.
    let bundle = alice.add_member(G, &bob_kp).unwrap();
    alice.merge_pending_commit(G).unwrap();
    bob.join_from_welcome(&bundle.welcome.unwrap()).unwrap();
    let own_kp = alice.generate_key_package().unwrap();
    assert!(alice.seat_founding(G, &[laptop_kp], &own_kp).is_err());
}

/// The founder's entry is as long as every other, and the Welcome works in a
/// padded frame too.
#[cfg(feature = "test-forgery")]
#[test]
fn the_founders_seat_is_as_long_as_any_other() {
    use tls_codec::Serialize as _;
    let s = issuer();
    let mut alice = client(&s, 1, ALICE, ALICE_PHONE);
    let mut joiners: Vec<(String, String, Client)> = (0..6u8)
        .map(|i| {
            let actor = format!("cccccccc-0000-4000-8000-00000000001{i}");
            let device = format!("cccccccc-1111-4111-8111-00000000001{i}");
            let c = client(&s, 10 + i, &actor, &device);
            (device, actor, c)
        })
        .collect();
    let handed: Vec<Handed> = joiners
        .iter()
        .map(|(d, a, c)| (d.clone(), a.clone(), c.generate_key_package().unwrap()))
        .collect();
    let own_kp = alice.generate_key_package().unwrap();
    let welcome = found(&mut alice, &handed, Some(&own_kp)).1.unwrap();
    eprintln!("a founding Welcome for 7 devices: {} bytes", welcome.len());

    let raw = unframe_welcome(&welcome).unwrap();
    let MlsMessageBodyIn::Welcome(w) = MlsMessageIn::tls_deserialize_exact(raw).unwrap().extract()
    else {
        panic!("not a Welcome");
    };
    let lengths: BTreeSet<usize> = w
        .secrets()
        .iter()
        .map(|e| e.tls_serialize_detached().unwrap().len())
        .collect();
    assert_eq!(lengths.len(), 1, "every entry is one length: {lengths:?}");
    assert_eq!(w.secrets().len(), 7);

    let (h, v) = head_of(&alice);
    for (_, _, joiner) in &mut joiners {
        joiner.join_from_welcome_at_head(&welcome, h, &v).unwrap();
        assert_eq!(joiner.epoch(G).unwrap(), 2);
    }
}

fn devices_of(member: &Client) -> BTreeSet<String> {
    tree_of(member).into_iter().map(|(d, _)| d).collect()
}

/// A package the core refuses (here under a key nobody trusts, listed as a
/// device of Carol's) refuses a founding over all of them, so it is left
/// out: everybody else is seated in the one commit that names nobody, and
/// no set the server sees is the founder's.
#[test]
fn a_spoiled_package_is_left_out_and_the_founding_still_names_nobody() {
    let s = issuer();
    let mut alice = client(&s, 1, ALICE, ALICE_PHONE);
    let mut bob = client(&s, 2, BOB, BOB_PHONE);
    let mut carol = client(&s, 3, CAROL, CAROL_PHONE);
    let ghost = client(&other_issuer(), 9, CAROL, GHOST);

    let bob_kp = bob.generate_key_package().unwrap();
    let carol_kp = carol.generate_key_package().unwrap();
    let ghost_kp = ghost.generate_key_package().unwrap();
    let own_kp = alice.generate_key_package().unwrap();
    let handed_out: Vec<Handed> = vec![
        (BOB_PHONE.into(), BOB.into(), bob_kp.clone()),
        (GHOST.into(), CAROL.into(), ghost_kp.clone()),
        (CAROL_PHONE.into(), CAROL.into(), carol_kp.clone()),
    ];

    // The read-only door names exactly the spoiled one, and a founding over
    // all three is still refused as a whole, with nothing staged.
    {
        let mut probe = client(&s, 11, ALICE, ALICE_PHONE);
        probe.create_group(G).unwrap();
        let all = vec![bob_kp, ghost_kp, carol_kp];
        assert_eq!(probe.founding_refusals(G, &all).unwrap(), vec![1]);
        let probe_own = probe.generate_key_package().unwrap();
        assert!(probe.seat_founding(G, &all, &probe_own).is_err());
        assert!(!probe.has_pending_commit(G).unwrap());
    }

    let (seen, welcome) = found(&mut alice, &handed_out, Some(&own_kp));
    let welcome = welcome.expect("the founding went ahead without the spoiled package");
    // The state commit and ONE seating commit. The ghost's add after it is
    // refused too, so nothing more is sent.
    assert_eq!(seen.len(), 2);
    assert!(seen.iter().all(|s| s.recipients.is_empty()));
    let welcomed: Vec<&str> = seen[1]
        .welcomes
        .iter()
        .map(|(d, _, _)| d.as_str())
        .collect();
    assert_eq!(welcomed, vec![ALICE_PHONE, BOB_PHONE, CAROL_PHONE]);
    assert_eq!(
        devices_of(&alice),
        BTreeSet::from([ALICE_PHONE.into(), BOB_PHONE.into(), CAROL_PHONE.into()])
    );
    let (h, v) = head_of(&alice);
    bob.join_from_welcome_at_head(&welcome, h, &v).unwrap();
    carol.join_from_welcome_at_head(&welcome, h, &v).unwrap();
}

/// With no package of this device in the answer, the founding fails before
/// the conversation is opened, and the server sees no commit at all.
#[test]
fn a_withheld_own_package_fails_the_founding() {
    let s = issuer();
    let mut alice = client(&s, 1, ALICE, ALICE_PHONE);
    let bob = client(&s, 2, BOB, BOB_PHONE);
    let bob_kp = bob.generate_key_package().unwrap();
    let handed_out: Vec<Handed> = vec![(BOB_PHONE.into(), BOB.into(), bob_kp.clone())];
    let (seen, welcome) = found(&mut alice, &handed_out, None);
    assert!(welcome.is_none());
    assert!(seen.is_empty(), "nothing was sent");
    // A package of somebody else's in its place fails at the same step.
    let (seen, welcome) = found(&mut alice, &handed_out, Some(&bob_kp));
    assert!(welcome.is_none());
    assert!(seen.is_empty(), "nothing was sent");

    // And the core takes no stand-in for the founder's own seat.
    alice.create_group(G).unwrap();
    assert!(alice
        .seat_founding(G, std::slice::from_ref(&bob_kp), &bob_kp)
        .is_err());
    assert!(!alice.has_pending_commit(G).unwrap());
}

/// Two packages under one device id: each alone passes against the
/// founder's tree of one, but one device, one leaf, holds inside one
/// founding too.
#[test]
fn a_founding_refuses_a_second_package_for_one_device_id() {
    let s = issuer();
    let mut alice = client(&s, 1, ALICE, ALICE_PHONE);
    let mut bob = client(&s, 2, BOB, BOB_PHONE);
    // A second key certified under Bob's phone's device id.
    let squatter = client(&s, 8, BOB, BOB_PHONE);
    let bob_kp = bob.generate_key_package().unwrap();
    let squat_kp = squatter.generate_key_package().unwrap();
    let own_kp = alice.generate_key_package().unwrap();
    alice.create_group(G).unwrap();

    let both = vec![bob_kp.clone(), squat_kp];
    assert_eq!(alice.founding_refusals(G, &both).unwrap(), vec![1]);
    assert!(alice.seat_founding(G, &both, &own_kp).is_err());
    assert!(!alice.has_pending_commit(G).unwrap());

    let bundle = alice
        .seat_founding(G, std::slice::from_ref(&bob_kp), &own_kp)
        .unwrap();
    alice.merge_pending_commit(G).unwrap();
    let bob_leaves = tree_of(&alice)
        .into_iter()
        .filter(|(d, _)| d == BOB_PHONE)
        .count();
    assert_eq!(bob_leaves, 1);
    let (h, v) = head_of(&alice);
    bob.join_from_welcome_at_head(&bundle.welcome.unwrap(), h, &v)
        .unwrap();
}

/// A founding's `recipients` is empty, so its `access_keys` take their
/// order from its `welcomes`, which are in device-id order: the founder's
/// account sits where her device id falls, not first.
#[test]
fn a_foundings_access_keys_follow_its_welcomes() {
    let s = issuer();
    // The founder's device id sorts last, so a founder-first list would show.
    let erin = "eeeeeeee-0000-4000-8000-000000000009";
    let erin_phone = "eeeeeeee-1111-4111-8111-000000000009";
    let mut founder = client(&s, 5, erin, erin_phone);
    let bob = client(&s, 2, BOB, BOB_PHONE);
    let carol = client(&s, 3, CAROL, CAROL_PHONE);
    let handed_out: Vec<Handed> = vec![
        (
            CAROL_PHONE.into(),
            CAROL.into(),
            carol.generate_key_package().unwrap(),
        ),
        (
            BOB_PHONE.into(),
            BOB.into(),
            bob.generate_key_package().unwrap(),
        ),
    ];
    let own_kp = founder.generate_key_package().unwrap();
    let (seen, welcome) = found(&mut founder, &handed_out, Some(&own_kp));
    assert!(welcome.is_some());
    assert!(seen[1].recipients.is_empty());
    assert_eq!(seen[1].access_keys, vec![BOB, CAROL, erin]);
}

/// After a founding, every later list is in device-id order. The founder's
/// device is leaf 0 (she made the group), and a list in leaf order would put
/// her first and the rest in the order she seated them, from every sender,
/// for the life of her leaf. Sorted, the list is the same whoever sends and
/// shows neither; the joiners' leaves are in an order drawn at random, not
/// the order her client passed their packages.
#[test]
fn every_later_list_is_in_device_id_order() {
    let s = issuer();
    // The founder's device ids sort last, so only leaf order could put her
    // first.
    let erin = "eeeeeeee-0000-4000-8000-000000000009";
    let erin_phone = "eeeeeeee-1111-4111-8111-000000000009";
    let erin_laptop = "eeeeeeee-1111-4111-8111-00000000000a";
    let mut founder = client(&s, 5, erin, erin_phone);
    let mut laptop = client(&s, 6, erin, erin_laptop);
    let mut bob = client(&s, 2, BOB, BOB_PHONE);
    let mut carol = client(&s, 3, CAROL, CAROL_PHONE);

    // Passed in the order she happened to pick: Carol, her laptop, Bob.
    let handed_out: Vec<Handed> = vec![
        (
            CAROL_PHONE.into(),
            CAROL.into(),
            carol.generate_key_package().unwrap(),
        ),
        (
            erin_laptop.into(),
            erin.into(),
            laptop.generate_key_package().unwrap(),
        ),
        (
            BOB_PHONE.into(),
            BOB.into(),
            bob.generate_key_package().unwrap(),
        ),
    ];
    let own_kp = founder.generate_key_package().unwrap();
    let (_, welcome) = found(&mut founder, &handed_out, Some(&own_kp));
    let welcome = welcome.unwrap();

    // Hers is leaf 0; the joiners took the rest in an order drawn at
    // random (tests/founding_layout.rs).
    let leaves: Vec<String> = tree_of(&founder).into_iter().map(|(d, _)| d).collect();
    assert_eq!(leaves[0], erin_phone);
    let mut joiners = leaves[1..].to_vec();
    joiners.sort();
    assert_eq!(joiners, vec![BOB_PHONE, CAROL_PHONE, erin_laptop]);

    let (h, v) = head_of(&founder);
    bob.join_from_welcome_at_head(&welcome, h, &v).unwrap();
    carol.join_from_welcome_at_head(&welcome, h, &v).unwrap();
    laptop.join_from_welcome_at_head(&welcome, h, &v).unwrap();

    let sorted: Vec<(String, String)> = vec![
        (BOB_PHONE.into(), BOB.into()),
        (CAROL_PHONE.into(), CAROL.into()),
        (erin_phone.into(), erin.into()),
        (erin_laptop.into(), erin.into()),
    ];
    for sender in [&founder, &bob, &carol, &laptop] {
        let list = recipients_of(sender);
        assert_eq!(
            list, sorted,
            "the same list from every sender, by device id"
        );
        assert_ne!(list[0].0, erin_phone, "the founder's device is not first");
        let submitted = Submitted::new(list, vec![]);
        assert_eq!(submitted.access_keys, vec![BOB, CAROL, erin]);
    }
}

// ---- No invitee can veto a founding -----------------------------------------
//
// Every field of a package below is the device's own signed choice: its own
// credential, signature key and signature, with leaf capabilities, HPKE keys,
// a cipher suite or a lifetime a modified client picked. No server power is
// needed to publish one. The founding commit's own MLS checks refuse each, so
// `founding_refusals` names it, and the founding seats everybody else.

/// A modified client's randomness: a replayable stream, so two devices
/// started on the same stream derive the same init and leaf encryption keys.
struct Replayed {
    counter: Cell<u64>,
}

impl Replayed {
    fn fill(&self, out: &mut [u8]) {
        let call = self.counter.get();
        self.counter.set(call + 1);
        for (block, chunk) in out.chunks_mut(32).enumerate() {
            let mut h = Sha256::new();
            h.update(call.to_be_bytes());
            h.update((block as u64).to_be_bytes());
            let digest = h.finalize();
            chunk.copy_from_slice(&digest[..chunk.len()]);
        }
    }
}

impl OpenMlsRand for Replayed {
    type Error = std::convert::Infallible;
    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        let mut out = [0u8; N];
        self.fill(&mut out);
        Ok(out)
    }
    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        let mut out = vec![0u8; len];
        self.fill(&mut out);
        Ok(out)
    }
}

struct Rigged {
    crypto: RustCrypto,
    rand: Replayed,
    storage: MemoryStorage,
}

impl OpenMlsProvider for Rigged {
    type CryptoProvider = RustCrypto;
    type RandProvider = Replayed;
    type StorageProvider = MemoryStorage;
    fn storage(&self) -> &MemoryStorage {
        &self.storage
    }
    fn crypto(&self) -> &RustCrypto {
        &self.crypto
    }
    fn rand(&self) -> &Replayed {
        &self.rand
    }
}

/// How a modified client shapes its own package.
struct Shape {
    suite: Ciphersuite,
    listed_suites: Vec<Ciphersuite>,
    meta_capability: bool,
    credential_types: Option<Vec<CredentialType>>,
    lifetime: Option<Lifetime>,
    /// Where its randomness starts; two packages on one stream share HPKE
    /// keys.
    stream: u64,
}

impl Shape {
    /// As the core shapes one.
    fn honest(stream: u64) -> Self {
        Shape {
            suite: PEACHY_CIPHERSUITE,
            listed_suites: vec![PEACHY_CIPHERSUITE],
            meta_capability: true,
            credential_types: None,
            lifetime: None,
            stream,
        }
    }
}

/// A KeyPackage of Mallory's device `device` (seed `tag`), in `shape`.
fn mallory_package(tag: u8, device: &str, shape: Shape) -> Vec<u8> {
    let s = issuer();
    let seed = device_seed(tag);
    let (_, public) = peachy_mls_core::issuer::device_key_pair(&seed);
    let token = s
        .issue(MALLORY, device, &public, NOW - HOUR, NOW + 30 * DAY)
        .unwrap();
    let signer =
        SignatureKeyPair::from_raw(SignatureScheme::ED25519, seed.to_vec(), public.to_vec());
    let credential_with_key = CredentialWithKey {
        credential: Credential::from(BasicCredential::new(token)),
        signature_key: public.to_vec().into(),
    };
    let provider = Rigged {
        crypto: RustCrypto::default(),
        rand: Replayed {
            counter: Cell::new(shape.stream),
        },
        storage: MemoryStorage::default(),
    };
    let meta = [group_meta_extension_type()];
    let mut builder = KeyPackage::builder().leaf_node_capabilities(Capabilities::new(
        None,
        Some(&shape.listed_suites),
        shape.meta_capability.then_some(&meta[..]),
        None,
        shape.credential_types.as_deref(),
    ));
    if let Some(lifetime) = shape.lifetime {
        builder = builder.key_package_lifetime(lifetime);
    }
    let bundle = builder
        .build(shape.suite, &provider, &signer, credential_with_key)
        .unwrap();
    MlsMessageOut::from(bundle.key_package().clone())
        .to_bytes()
        .unwrap()
}

/// Mallory's packages among Bob's, in `order` (`None` is Bob's slot). The
/// door names exactly `refused`, on the group of one where a client reads it
/// and again after the state commit, where the founding commit is built; a
/// founding over every package is still refused whole, with nothing staged;
/// and the documented founding leaves those out and seats everybody else in
/// its one commit: the founder, Bob, and `seated` of Mallory's devices.
fn an_invitee_vetoes_nothing(
    order: Vec<Option<(&str, Vec<u8>)>>,
    refused: &[u32],
    seated: &[&'static str],
) {
    let s = issuer();
    let mut bob = client(&s, 2, BOB, BOB_PHONE);
    let handed_out: Vec<Handed> = order
        .into_iter()
        .map(|slot| match slot {
            None => (
                BOB_PHONE.into(),
                BOB.into(),
                bob.generate_key_package().unwrap(),
            ),
            Some((device, kp)) => (device.into(), MALLORY.into(), kp),
        })
        .collect();
    let all: Vec<Vec<u8>> = handed_out.iter().map(|(_, _, kp)| kp.clone()).collect();

    {
        let mut probe = client(&s, 11, ALICE, ALICE_PHONE);
        probe.create_group(G).unwrap();
        assert_eq!(
            probe.founding_refusals(G, &all).unwrap(),
            refused,
            "on the group of one"
        );
        probe
            .set_group_meta(G, br#"{"v":1,"n":"","adm":[],"dm":false}"#)
            .unwrap();
        probe.merge_pending_commit(G).unwrap();
        assert_eq!(
            probe.founding_refusals(G, &all).unwrap(),
            refused,
            "after the state commit"
        );
        if !refused.is_empty() {
            let own = probe.generate_key_package().unwrap();
            assert!(probe.seat_founding(G, &all, &own).is_err());
            assert!(!probe.has_pending_commit(G).unwrap());
        }
    }

    let mut alice = client(&s, 1, ALICE, ALICE_PHONE);
    let own_kp = alice.generate_key_package().unwrap();
    let (seen, welcome) = found(&mut alice, &handed_out, Some(&own_kp));
    let welcome = welcome.expect("the founding went ahead without the refused packages");
    // The state commit and ONE seating commit; each left-out device's add
    // after it is refused too, so nothing more is sent.
    assert_eq!(seen.len(), 2);
    let mut expected: Vec<&str> = vec![ALICE_PHONE, BOB_PHONE];
    expected.extend_from_slice(seated);
    expected.sort_unstable();
    let welcomed: Vec<&str> = seen[1]
        .welcomes
        .iter()
        .map(|(d, _, _)| d.as_str())
        .collect();
    assert_eq!(welcomed, expected);
    let (h, v) = head_of(&alice);
    bob.join_from_welcome_at_head(&welcome, h, &v).unwrap();
}

/// A leaf that does not list the group-state extension. The group of one
/// carries no state yet, so the commit's own check cannot see it there; the
/// core refuses it by name.
#[test]
fn a_package_without_the_group_state_capability_is_left_out() {
    let shape = Shape {
        meta_capability: false,
        ..Shape::honest(1_000)
    };
    let mallory = mallory_package(5, MALLORY_PHONE, shape);
    an_invitee_vetoes_nothing(vec![None, Some((MALLORY_PHONE, mallory))], &[1], &[]);
}

/// Two of one invitee's devices whose packages share HPKE keys. Each alone
/// is a valid package; together the commit refuses them, so the later one,
/// in the order passed, is left out, whatever that order.
#[test]
fn packages_sharing_hpke_keys_leave_out_the_later_one() {
    let phone = mallory_package(5, MALLORY_PHONE, Shape::honest(0));
    let laptop = mallory_package(6, MALLORY_LAPTOP, Shape::honest(0));
    for (device, kp) in [(MALLORY_PHONE, &phone), (MALLORY_LAPTOP, &laptop)] {
        an_invitee_vetoes_nothing(vec![None, Some((device, kp.clone()))], &[], &[device]);
    }
    an_invitee_vetoes_nothing(
        vec![
            None,
            Some((MALLORY_PHONE, phone.clone())),
            Some((MALLORY_LAPTOP, laptop.clone())),
        ],
        &[2],
        &[MALLORY_PHONE],
    );
    an_invitee_vetoes_nothing(
        vec![
            Some((MALLORY_LAPTOP, laptop)),
            None,
            Some((MALLORY_PHONE, phone)),
        ],
        &[2],
        &[MALLORY_LAPTOP],
    );
}

/// A package in another cipher suite.
#[test]
fn a_package_in_another_cipher_suite_is_left_out() {
    let other = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let shape = Shape {
        suite: other,
        listed_suites: vec![other, PEACHY_CIPHERSUITE],
        ..Shape::honest(2_000)
    };
    let mallory = mallory_package(5, MALLORY_PHONE, shape);
    an_invitee_vetoes_nothing(vec![Some((MALLORY_PHONE, mallory)), None], &[0], &[]);
}

/// A leaf whose capabilities do not list the group's cipher suite.
#[test]
fn a_leaf_not_listing_the_groups_suite_is_left_out() {
    let shape = Shape {
        listed_suites: vec![Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519],
        ..Shape::honest(3_000)
    };
    let mallory = mallory_package(5, MALLORY_PHONE, shape);
    an_invitee_vetoes_nothing(vec![None, Some((MALLORY_PHONE, mallory))], &[1], &[]);
}

/// A leaf whose capabilities list only X.509 credentials, under its own
/// basic one.
#[test]
fn a_leaf_listing_only_x509_credentials_is_left_out() {
    let shape = Shape {
        credential_types: Some(vec![CredentialType::X509]),
        ..Shape::honest(4_000)
    };
    let mallory = mallory_package(5, MALLORY_PHONE, shape);
    an_invitee_vetoes_nothing(vec![None, Some((MALLORY_PHONE, mallory))], &[1], &[]);
}

/// A package whose leaf lifetime has passed. The package's own check
/// already refuses it, before any commit is built.
#[test]
fn a_package_past_its_lifetime_is_left_out() {
    let shape = Shape {
        lifetime: Some(Lifetime::init(1, 2)),
        ..Shape::honest(5_000)
    };
    let mallory = mallory_package(5, MALLORY_PHONE, shape);
    an_invitee_vetoes_nothing(vec![None, Some((MALLORY_PHONE, mallory))], &[1], &[]);
}
