// SPDX-License-Identifier: MIT
//! A replayed application message is a DUPLICATE, not a loss.
//!
//! The delivery service can hand a device the same sealed message twice, under
//! a fresh envelope id each time, so the client's envelope-id dedupe never sees
//! it. Opening a message spends its ratchet key, so the copy cannot open, and
//! without this a client could not tell it from a message it lost: it drew a
//! placeholder, asked the group to resend it, and could buzz the phone.
//!
//! The core answers [`Error::Duplicate`] exactly when its own record says this
//! device opened these very bytes; a spent key (OpenMLS's
//! `SecretTreeError::SecretReuseError`) the record does not vouch for is a
//! loss, not a duplicate (docs/mls-core.md §Receiving).
//! These tests replay the latest message, an earlier one after later ones, one
//! across a restart over the same store, and one from an epoch the group has
//! since left, and prove that a message never opened before is not taken for a
//! duplicate, and that a copy refused at any step (a tag that fails, a
//! signature that fails) spends nothing: the real message still opens.

mod support;

use peachy_mls_core::{Client, Error, Incoming, MemoryKv, PeachyStorage};
use support::{client, client_on, issuer};

const GROUP: &[u8] = b"00000000-0000-4000-8000-00000000f00d";

fn pair(bo_kv: Option<MemoryKv>) -> (Client, Client) {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut bo = match bo_kv {
        Some(kv) => client_on(
            &server,
            2,
            "actor-bo",
            "device-bo",
            PeachyStorage::open(Box::new(kv)).expect("store"),
        ),
        None => client(&server, 2, "actor-bo", "device-bo"),
    };
    ada.create_group(GROUP).expect("create");
    let kp = bo.generate_key_package().expect("key package");
    let added = ada.add_member(GROUP, &kp).expect("add");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.join_from_welcome(&added.welcome.expect("welcome"))
        .expect("join");
    (ada, bo)
}

fn opens_to(bo: &mut Client, message: &[u8], words: &[u8]) {
    match bo.process_message(GROUP, message).expect("opens") {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, words),
        other => panic!("not an application message: {other:?}"),
    }
}

fn is_duplicate(result: peachy_mls_core::Result<Incoming>) {
    match result {
        Err(Error::Duplicate(_)) => {}
        other => panic!("a replay was not a duplicate: {other:?}"),
    }
}

#[test]
fn the_latest_message_replayed_is_a_duplicate() {
    let (mut ada, mut bo) = pair(None);
    let m = ada.encrypt(GROUP, b"hello").expect("encrypt");
    opens_to(&mut bo, &m, b"hello");
    is_duplicate(bo.process_message(GROUP, &m));
    // And again: a duplicate changes nothing, so it stays one.
    is_duplicate(bo.process_message(GROUP, &m));
    // The ratchet is untouched: the next message still opens.
    let next = ada.encrypt(GROUP, b"next").expect("encrypt");
    opens_to(&mut bo, &next, b"next");
}

#[test]
fn an_earlier_message_replayed_after_later_ones_is_a_duplicate() {
    let (mut ada, mut bo) = pair(None);
    let first = ada.encrypt(GROUP, b"first").expect("encrypt");
    let second = ada.encrypt(GROUP, b"second").expect("encrypt");
    let third = ada.encrypt(GROUP, b"third").expect("encrypt");
    // Out of order: the third first, then the first, leaving the second's key
    // held in the window.
    opens_to(&mut bo, &third, b"third");
    opens_to(&mut bo, &first, b"first");
    is_duplicate(bo.process_message(GROUP, &first));
    is_duplicate(bo.process_message(GROUP, &third));
    // A message skipped over is not a duplicate: its key is still held.
    opens_to(&mut bo, &second, b"second");
    is_duplicate(bo.process_message(GROUP, &second));
}

#[test]
fn a_replay_after_a_restart_over_the_same_store_is_a_duplicate() {
    let kv = MemoryKv::default();
    let (mut ada, mut bo) = pair(Some(kv.clone()));
    let m = ada.encrypt(GROUP, b"before the restart").expect("encrypt");
    opens_to(&mut bo, &m, b"before the restart");
    drop(bo);
    let server = issuer();
    let mut bo = client_on(
        &server,
        2,
        "actor-bo",
        "device-bo",
        PeachyStorage::open(Box::new(kv)).expect("store"),
    );
    is_duplicate(bo.process_message(GROUP, &m));
}

#[test]
fn a_replay_from_an_epoch_the_group_has_left_is_a_duplicate() {
    let (mut ada, mut bo) = pair(None);
    let m = ada.encrypt(GROUP, b"old epoch").expect("encrypt");
    opens_to(&mut bo, &m, b"old epoch");
    let update = ada.self_update(GROUP).expect("update");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.process_commit(GROUP, &update.commit)
        .expect("bo applies the commit");
    is_duplicate(bo.process_message(GROUP, &m));
}

#[test]
fn a_message_that_does_not_open_for_another_reason_is_not_a_duplicate() {
    let (mut ada, mut bo) = pair(None);
    let m = ada.encrypt(GROUP, b"hello").expect("encrypt");
    // A flipped byte in the ciphertext: the key is there, the tag is wrong.
    let mut tampered = m.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    match bo.process_message(GROUP, &tampered) {
        Err(Error::Duplicate(_)) => panic!("a tampered message read as a duplicate"),
        Err(_) => {}
        Ok(other) => panic!("a tampered message opened: {other:?}"),
    }
    // And the real one still opens: the failed open spent nothing.
    opens_to(&mut bo, &m, b"hello");
}

#[test]
fn a_spent_key_the_record_does_not_vouch_for_is_a_loss_not_a_duplicate() {
    // The engine says the key is spent, but this device has no record of
    // opening these bytes: a build that kept none, or a message older than
    // the record keeps. Read as a message that would not open, so its content
    // hint can ask for it again.
    let (mut ada, mut bo) = pair(None);
    let m = ada.encrypt(GROUP, b"hello").expect("encrypt");
    opens_to(&mut bo, &m, b"hello");
    bo.forge_forget_opened(GROUP).expect("forget the record");
    match bo.process_message(GROUP, &m) {
        Err(Error::Mls(text)) => assert!(text.contains("spent"), "{text}"),
        other => panic!("an unvouched spent key was not a loss: {other:?}"),
    }
}

#[test]
fn a_copy_that_does_not_decrypt_leaves_the_real_message_its_key() {
    // A tampered copy handed over first takes the key from the ratchet in
    // memory before its tag fails; the group is reloaded from the store,
    // which never saw that, so the real message opens.
    let (mut ada, mut bo) = pair(None);
    let first = ada.encrypt(GROUP, b"first").expect("encrypt");
    let second = ada.encrypt(GROUP, b"second").expect("encrypt");
    for m in [&first, &second] {
        let mut tampered = m.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x80;
        assert!(bo.process_message(GROUP, &tampered).is_err());
    }
    opens_to(&mut bo, &second, b"second");
    opens_to(&mut bo, &first, b"first");
}

/// A forged copy is refused, and is neither the message nor a duplicate.
fn is_refused_forgery(result: peachy_mls_core::Result<Incoming>) {
    match result {
        Err(Error::Duplicate(_)) => panic!("a forged copy read as a duplicate"),
        Err(_) => {}
        Ok(other) => panic!("a forged copy opened: {other:?}"),
    }
}

#[test]
fn a_forged_copy_with_a_good_tag_and_a_bad_signature_spends_nothing() {
    // Any member can derive every member's sending keys, so one can seal a
    // copy under Ada's next key: its tag holds, its signature does not.
    // OpenMLS spends and saves the key before it checks the signature; the
    // refusal rolls all of it back, so the real message still opens.
    let (mut ada, mut bo) = pair(None);
    let forged = ada
        .forge_badly_signed_application(GROUP, b"not from ada")
        .expect("forge");
    let real = ada.encrypt(GROUP, b"from ada").expect("encrypt");
    is_refused_forgery(bo.process_message(GROUP, &forged));
    is_refused_forgery(bo.process_message(GROUP, &forged));
    opens_to(&mut bo, &real, b"from ada");
    is_duplicate(bo.process_message(GROUP, &real));
    let next = ada.encrypt(GROUP, b"next").expect("encrypt");
    opens_to(&mut bo, &next, b"next");
}

#[test]
fn a_forged_copy_spends_nothing_in_the_store_either() {
    // The same, with a restart between the forgery and the real message: the
    // real one opens against what the store committed for the refused copy,
    // not only against the group in memory.
    let kv = MemoryKv::default();
    let (mut ada, mut bo) = pair(Some(kv.clone()));
    let forged = ada
        .forge_badly_signed_application(GROUP, b"not from ada")
        .expect("forge");
    let real = ada.encrypt(GROUP, b"from ada").expect("encrypt");
    is_refused_forgery(bo.process_message(GROUP, &forged));
    drop(bo);
    let server = issuer();
    let mut bo = client_on(
        &server,
        2,
        "actor-bo",
        "device-bo",
        PeachyStorage::open(Box::new(kv)).expect("store"),
    );
    opens_to(&mut bo, &real, b"from ada");
}
