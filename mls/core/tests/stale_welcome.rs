// SPDX-License-Identifier: MIT
//! A group only moves forward on a device.
//!
//! A Welcome sealed to a LAST-RESORT key package keeps opening for as long as
//! the package's private half is kept (2 days of rotation plus 30 in the
//! archive). The delivery service keeps every Welcome it relayed and every
//! head members submitted, so it could hand the same Welcome back later, with
//! the head of the epoch it sealed, and walk a member back to that epoch: a
//! member removed since, who simply never applied its removal, would then read
//! everything the rolled-back member sends, and messages already read would
//! open again.
//!
//! The core refuses that: a Welcome at or below the highest epoch this device
//! has held the group at is refused (`AlreadyAMember`), held, removed from or
//! forgotten alike, and never kept as contested; and a Welcome taken through a
//! last-resort package is never taken twice. docs/delivery.md §Two
//! seats under one group id.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use peachy_mls_core::welcome_frame::{frame_welcome, unframe_welcome};
use peachy_mls_core::{Client, Error, Incoming, SEND_KEY_LABEL};
use sha2::{Digest, Sha256};
use support::{client, issuer};

const GROUP: &[u8] = b"88888888-8888-4888-8888-888888888888";

fn head_of(client: &Client, group: &[u8]) -> (u64, [u8; 32]) {
    let epoch = client.epoch(group).unwrap();
    let verifier: [u8; 32] = Sha256::digest(
        client
            .export_secret(group, SEND_KEY_LABEL, group, 32)
            .unwrap(),
    )
    .into();
    (epoch, verifier)
}

fn opens(reader: &mut Client, wire: &[u8], text: &[u8]) -> bool {
    matches!(
        reader.process_message(GROUP, wire),
        Ok(Incoming::Application { plaintext, .. }) if plaintext == text
    )
}

/// Ada founds the group and adds Eve, then Bo through Bo's LAST-RESORT key
/// package (his one-time pool was empty). Returns the three clients, the
/// Welcome the server delivered to Bo, and the head the server recorded for
/// the epoch that Welcome seals.
fn setup() -> (Client, Client, Client, Vec<u8>, (u64, [u8; 32])) {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    let mut eve = client(&server, 3, "actor-eve", "device-eve");
    ada.create_group(GROUP).unwrap();

    let eve_kp = eve.generate_key_package().unwrap();
    let add_eve = ada.add_member(GROUP, &eve_kp).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    support::join_at_head(&mut eve, &add_eve.welcome.unwrap(), head_of(&ada, GROUP)).unwrap();

    let (bo_last_resort, _reference) = bo.generate_last_resort_key_package_with_ref().unwrap();
    let add_bo = ada.add_member(GROUP, &bo_last_resort).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    let welcome = add_bo.welcome.unwrap();
    support::join_at_head(&mut bo, &welcome, head_of(&ada, GROUP)).unwrap();
    eve.process_commit(GROUP, &add_bo.commit).unwrap();
    let old_head = head_of(&ada, GROUP);
    assert_eq!(head_of(&bo, GROUP), old_head);
    (ada, bo, eve, welcome, old_head)
}

/// Ada removes Eve, then rotates; Bo applies both. Eve, colluding with the
/// server, never applies her removal.
fn remove_eve(ada: &mut Client, bo: &mut Client) {
    let eve_leaf = ada.leaf_of_device(GROUP, "device-eve").unwrap();
    let removal = ada.remove_leaf(GROUP, eve_leaf).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    bo.process_commit(GROUP, &removal.commit).unwrap();
    let rotate = ada.self_update(GROUP).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    bo.process_commit(GROUP, &rotate.commit).unwrap();
}

/// Control: without any replay, Eve's removal holds.
#[test]
fn without_a_replay_the_removal_holds() {
    let (mut ada, mut bo, mut eve, _welcome, (old_epoch, _)) = setup();
    remove_eve(&mut ada, &mut bo);
    assert!(eve.is_active(GROUP).unwrap());
    assert_eq!(eve.epoch(GROUP).unwrap(), old_epoch);

    let text = b"the gate code changed after eve left";
    let wire = bo.encrypt(GROUP, text).unwrap();
    assert!(opens(&mut ada, &wire, text));
    assert!(!opens(&mut eve, &wire, text));
}

/// The server hands an active member the same last-resort Welcome again and
/// reports the head it recorded for the epoch that Welcome seals. Refused,
/// never kept as contested, and the head changes nothing: Bo stays at his
/// live epoch and removed Eve reads nothing.
#[test]
fn a_replayed_last_resort_welcome_cannot_roll_an_active_member_back() {
    let (mut ada, mut bo, mut eve, welcome, (old_epoch, old_verifier)) = setup();
    remove_eve(&mut ada, &mut bo);
    let live_epoch = bo.epoch(GROUP).unwrap();
    assert!(live_epoch > old_epoch);

    assert!(matches!(
        bo.join_from_welcome(&welcome),
        Err(Error::AlreadyAMember)
    ));
    assert_eq!(
        bo.contested_welcome_group_id(),
        None,
        "a stale Welcome is never contested"
    );
    assert!(matches!(
        bo.join_contested_welcome(old_epoch, &old_verifier),
        Err(Error::InvalidArgument(_))
    ));
    assert_eq!(bo.epoch(GROUP).unwrap(), live_epoch);
    assert!(bo.is_active(GROUP).unwrap());
    assert_eq!(
        bo.take_rejoin_report(GROUP).unwrap(),
        None,
        "no false rejoin notice"
    );

    let text = b"the gate code changed after eve left";
    let wire = bo.encrypt(GROUP, text).unwrap();
    assert!(opens(&mut ada, &wire, text));
    assert!(!opens(&mut eve, &wire, text), "removed Eve reads nothing");
}

/// The same replay in a frame of another length, so two framings are one
/// Welcome to the core; and the raw Welcome out of its frame is refused.
#[test]
fn a_replayed_welcome_is_refused_reframed_as_well() {
    let (mut ada, mut bo, _eve, welcome, _) = setup();
    remove_eve(&mut ada, &mut bo);
    let live_epoch = bo.epoch(GROUP).unwrap();
    let raw = unframe_welcome(&welcome).unwrap().to_vec();
    let framed = frame_welcome(&raw, welcome.len() + 1024).unwrap();
    assert!(matches!(
        bo.join_from_welcome(&framed),
        Err(Error::AlreadyAMember)
    ));
    let err = bo.join_from_welcome(&raw).expect_err("a raw Welcome");
    assert!(err.to_string().contains("in a frame"), "{err}");
    assert_eq!(bo.contested_welcome_group_id(), None);
    assert_eq!(bo.epoch(GROUP).unwrap(), live_epoch);
}

/// The replay against a member who was REMOVED, which needs no head at all:
/// refused, and Bo stays out.
#[test]
fn a_replayed_last_resort_welcome_cannot_reseat_a_removed_member() {
    let (mut ada, mut bo, mut eve, welcome, _) = setup();
    let bo_leaf = ada.leaf_of_device(GROUP, "device-bo").unwrap();
    let removal = ada.remove_leaf(GROUP, bo_leaf).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    bo.process_commit(GROUP, &removal.commit).unwrap();
    eve.process_commit(GROUP, &removal.commit).unwrap();
    assert!(!bo.is_active(GROUP).unwrap());

    assert!(matches!(
        bo.join_from_welcome(&welcome),
        Err(Error::AlreadyAMember)
    ));
    assert!(!bo.is_active(GROUP).unwrap());
    assert_eq!(bo.take_rejoin_report(GROUP).unwrap(), None);
}

/// Bo rotates his last-resort leaf first, as the core marks it due at once,
/// and only then is Eve removed. The replay is refused all the same: the
/// rotation replaced the leaf, not the package's init key.
#[test]
fn an_earlier_leaf_rotation_and_a_replay_still_roll_nothing_back() {
    let (mut ada, mut bo, mut eve, welcome, (old_epoch, old_verifier)) = setup();
    assert!(
        bo.leaf_rotation_due(GROUP).unwrap(),
        "a last-resort seat is due at once"
    );
    let rotation = bo.self_update(GROUP).unwrap();
    bo.merge_pending_commit(GROUP).unwrap();
    ada.process_commit(GROUP, &rotation.commit).unwrap();
    eve.process_commit(GROUP, &rotation.commit).unwrap();
    remove_eve(&mut ada, &mut bo);
    let live_epoch = bo.epoch(GROUP).unwrap();

    assert!(matches!(
        bo.join_from_welcome(&welcome),
        Err(Error::AlreadyAMember)
    ));
    assert!(bo.join_contested_welcome(old_epoch, &old_verifier).is_err());
    assert_eq!(bo.epoch(GROUP).unwrap(), live_epoch);
    assert!(
        !bo.leaf_rotation_due(GROUP).unwrap(),
        "the replay re-seated nothing"
    );
}

/// A message Bo already read stays read: the replay that would have restored
/// the secrets it was sealed under is refused.
#[test]
fn a_replay_does_not_reopen_messages_already_read() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    ada.create_group(GROUP).unwrap();
    let (bo_last_resort, _) = bo.generate_last_resort_key_package_with_ref().unwrap();
    let add_bo = ada.add_member(GROUP, &bo_last_resort).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    let welcome = add_bo.welcome.unwrap();
    bo.join_from_welcome(&welcome).unwrap();
    let (old_epoch, old_verifier) = head_of(&ada, GROUP);
    let text = b"old words";
    let wire = ada.encrypt(GROUP, text).unwrap();
    assert!(opens(&mut bo, &wire, text));
    let rotate = ada.self_update(GROUP).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    bo.process_commit(GROUP, &rotate.commit).unwrap();

    assert!(matches!(
        bo.join_from_welcome(&welcome),
        Err(Error::AlreadyAMember)
    ));
    assert!(bo.join_contested_welcome(old_epoch, &old_verifier).is_err());
    assert!(
        !opens(&mut bo, &wire, text),
        "an already-read message stays spent"
    );
}

/// The mark survives `forget_group`: the epochs of a copy the head vouched
/// for (here, a seat at the head). Ada's first add of Bo, through his
/// last-resort package, is withheld by the server; Ada re-seats him with a
/// one-time package at a later epoch, and Bo later forgets the group. The
/// withheld Welcome, which Bo never took, is then refused by the mark alone.
#[test]
fn the_mark_survives_forget_and_refuses_a_welcome_never_taken() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    ada.create_group(GROUP).unwrap();
    let (bo_last_resort, _) = bo.generate_last_resort_key_package_with_ref().unwrap();
    let withheld = ada.add_member(GROUP, &bo_last_resort).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    let withheld = withheld.welcome.unwrap();

    let bo_leaf = ada.leaf_of_device(GROUP, "device-bo").unwrap();
    ada.remove_leaf(GROUP, bo_leaf).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    let readd = ada
        .add_member(GROUP, &bo.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    support::join_at_head(&mut bo, &readd.welcome.unwrap(), head_of(&ada, GROUP)).unwrap();
    let held = bo.epoch(GROUP).unwrap();
    bo.forget_group(GROUP).unwrap();

    assert!(matches!(
        bo.join_from_welcome(&withheld),
        Err(Error::AlreadyAMember)
    ));
    assert!(bo.epoch(GROUP).is_err(), "nothing was seated");
    assert!(held > 1);
}

/// A last-resort Welcome is taken once: forgotten and handed back, it is
/// refused (by the mark and by the record of the taking).
#[test]
fn a_last_resort_welcome_is_taken_once_even_after_forget() {
    let (_ada, mut bo, _eve, welcome, _) = setup();
    bo.forget_group(GROUP).unwrap();
    assert!(matches!(
        bo.join_from_welcome(&welcome),
        Err(Error::AlreadyAMember)
    ));
    assert!(bo.epoch(GROUP).is_err());
}

/// What still works: a real re-add at a later epoch, after a removal and
/// after a forget, through the very same last-resort package.
#[test]
fn a_real_re_add_at_a_later_epoch_is_still_taken() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    ada.create_group(GROUP).unwrap();
    let (bo_last_resort, _) = bo.generate_last_resort_key_package_with_ref().unwrap();
    let add = ada.add_member(GROUP, &bo_last_resort).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    support::join_at_head(&mut bo, &add.welcome.unwrap(), head_of(&ada, GROUP)).unwrap();

    // Removed, then re-added through the same last-resort package.
    let bo_leaf = ada.leaf_of_device(GROUP, "device-bo").unwrap();
    let removal = ada.remove_leaf(GROUP, bo_leaf).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    bo.process_commit(GROUP, &removal.commit).unwrap();
    assert!(!bo.is_active(GROUP).unwrap());
    let readd = ada.add_member(GROUP, &bo_last_resort).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    assert_eq!(
        support::join_at_head(&mut bo, &readd.welcome.unwrap(), head_of(&ada, GROUP)).unwrap(),
        GROUP
    );
    assert_eq!(head_of(&bo, GROUP), head_of(&ada, GROUP));

    // Forgotten (it fell behind), then re-added with a fresh package.
    bo.forget_group(GROUP).unwrap();
    let bo_leaf = ada.leaf_of_device(GROUP, "device-bo").unwrap();
    ada.remove_leaf(GROUP, bo_leaf).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    let again = ada
        .add_member(GROUP, &bo.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    assert_eq!(
        support::join_at_head(&mut bo, &again.welcome.unwrap(), head_of(&ada, GROUP)).unwrap(),
        GROUP
    );
    let text = b"back for real";
    let wire = ada.encrypt(GROUP, text).unwrap();
    assert!(opens(&mut bo, &wire, text));
}
