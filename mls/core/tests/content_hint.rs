// SPDX-License-Identifier: MIT
//! Content hints (docs/sealed-messages.md §Content hints), asserted.
//!
//! 1. A hinted message still opens, to exactly its words.
//! 2. Its epoch and hint are readable with no key at all — which is the point:
//!    the receiver that needs them is the one whose ratchet will not open it.
//! 3. A message sealed without a hint peeks as "no hint", and the hint does
//!    not stick to the next message the group sends.
//! 4. A value that is not a hint is refused before anything is sealed.

mod support;

use peachy_mls_core::hint::{
    peek_message, CONTENT_HINT_DEFAULT, CONTENT_HINT_IMPLICIT, CONTENT_HINT_RESENDABLE,
};
use peachy_mls_core::{Client, Incoming};
use support::{client, issuer};

const GROUP: &[u8] = b"peachy-group-content-hint";

fn pair() -> (Client, Client) {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(&server, 2, "actor-bo", "device-bo-phone");
    ada.create_group(GROUP).expect("create");
    let bo_kp = bo.generate_key_package().expect("bo key package");
    let added = ada.add_member(GROUP, &bo_kp).expect("add bo");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.join_from_welcome(&added.welcome.expect("welcome"))
        .expect("bo joins");
    (ada, bo)
}

fn opens_to(receiver: &mut Client, ciphertext: &[u8], expected: &[u8]) {
    match receiver
        .process_message(GROUP, ciphertext)
        .expect("process")
    {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, expected),
        other => panic!("expected an application message, got {other:?}"),
    }
}

#[test]
fn a_hinted_message_opens_and_peeks_without_a_key() {
    let (mut ada, mut bo) = pair();
    let epoch = ada.epoch(GROUP).expect("epoch");
    for hint in [
        CONTENT_HINT_DEFAULT,
        CONTENT_HINT_RESENDABLE,
        CONTENT_HINT_IMPLICIT,
    ] {
        let ciphertext = ada
            .encrypt_with_hint(GROUP, b"see you at eight", hint)
            .expect("encrypt");
        let peek = peek_message(&ciphertext).expect("a group message");
        assert_eq!(peek.epoch, epoch);
        assert_eq!(peek.hint, Some(hint));
        opens_to(&mut bo, &ciphertext, b"see you at eight");
    }
}

#[test]
fn an_unhinted_message_has_no_hint_and_the_hint_does_not_stick() {
    let (mut ada, mut bo) = pair();
    let hinted = ada
        .encrypt_with_hint(GROUP, b"first", CONTENT_HINT_IMPLICIT)
        .expect("encrypt");
    // As a build before hints sent it.
    let plain = ada.encrypt_without_hint(GROUP, b"second").expect("encrypt");
    assert_eq!(
        peek_message(&hinted).expect("peek").hint,
        Some(CONTENT_HINT_IMPLICIT)
    );
    assert_eq!(peek_message(&plain).expect("peek").hint, None);
    opens_to(&mut bo, &hinted, b"first");
    opens_to(&mut bo, &plain, b"second");
}

#[test]
fn the_plain_encrypt_door_carries_the_default_hint() {
    // No door sends a message without a hint, which the server
    // could tell from every other client's by its shorter authenticated data.
    let (mut ada, mut bo) = pair();
    let plain = ada.encrypt(GROUP, b"plain").expect("encrypt");
    let hinted = ada
        .encrypt_with_hint(GROUP, b"plain", CONTENT_HINT_DEFAULT)
        .expect("encrypt");
    assert_eq!(
        peek_message(&plain).expect("peek").hint,
        Some(CONTENT_HINT_DEFAULT)
    );
    assert_eq!(plain.len(), hinted.len());
    opens_to(&mut bo, &plain, b"plain");
    opens_to(&mut bo, &hinted, b"plain");
}

#[test]
fn a_value_that_is_not_a_hint_is_refused() {
    let (mut ada, _bo) = pair();
    assert!(ada.encrypt_with_hint(GROUP, b"x", 7).is_err());
}

#[test]
fn a_commit_peeks_its_epoch_and_no_hint() {
    let (mut ada, mut bo) = pair();
    let epoch = ada.epoch(GROUP).expect("epoch");
    let update = bo.self_update(GROUP).expect("update");
    let peek = peek_message(&update.commit).expect("a group message");
    assert_eq!(peek.epoch, epoch);
    assert_eq!(peek.hint, None);
    let _ = &mut ada;
}
