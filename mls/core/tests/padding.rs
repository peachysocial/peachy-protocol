// SPDX-License-Identifier: MIT
//! Size-hiding padding (docs/sealed-messages.md §Size-hiding padding), asserted.
//!
//! Two claims, and a third that keeps them honest:
//!
//! 1. Texts of different short lengths are the SAME length on the wire, and a
//!    long one grows in whole `APPLICATION_PADDING_BLOCK`s — so a ciphertext
//!    says which block its message fits in and nothing finer.
//! 2. A message from a build that never padded still opens, and a receiver
//!    hands back exactly the words either way — the padding is the protocol's
//!    own field, stripped below the message door, never a suffix a client has to trim.
//! 3. The unpadded door really is unpadded (its lengths DO differ), so claim 2
//!    is not passing over two padded messages; and a sender whose stored group
//!    config predates padding pads again from its next ordinary `encrypt`.

mod support;

use peachy_mls_core::{Client, Incoming, APPLICATION_PADDING_BLOCK};
use support::{client, issuer};

const GROUP: &[u8] = b"peachy-group-padding";

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
        Incoming::Application { plaintext, .. } => assert_eq!(
            plaintext, expected,
            "the receiver must hand back the words exactly, padding stripped"
        ),
        other => panic!("expected an application message, got {other:?}"),
    }
}

#[test]
fn short_messages_of_different_lengths_are_one_length_on_the_wire() {
    let (mut ada, mut bo) = pair();
    let texts: [&[u8]; 5] = [
        b"k",
        b"ok",
        b"on my way",
        b"running ten minutes late, save me a seat by the window please",
        &[b'x'; 100],
    ];
    let mut lengths = Vec::new();
    for text in texts {
        let ciphertext = ada.encrypt(GROUP, text).expect("encrypt");
        lengths.push(ciphertext.len());
        opens_to(&mut bo, &ciphertext, text);
    }
    assert!(
        lengths.iter().all(|len| *len == lengths[0]),
        "every short text should be one ciphertext length, got {lengths:?}"
    );
}

#[test]
fn a_long_message_grows_in_whole_blocks() {
    let (mut ada, mut bo) = pair();
    let base = ada.encrypt(GROUP, b"k").expect("encrypt").len();
    // Sizes that straddle several block boundaries, all short of the 16 KiB
    // where the ciphertext's own varint length prefix would grow a byte.
    for size in [200, 300, 511, 700, 1_000, 2_048, 4_000] {
        let text = vec![b'y'; size];
        let ciphertext = ada.encrypt(GROUP, &text).expect("encrypt");
        let grown = ciphertext.len() - base;
        assert_eq!(
            grown % APPLICATION_PADDING_BLOCK,
            0,
            "a {size}-byte text grew the ciphertext by {grown}, not a whole number of blocks"
        );
        opens_to(&mut bo, &ciphertext, &text);
    }
}

#[test]
fn an_unpadded_message_still_opens_and_the_sender_pads_again() {
    let (mut ada, mut bo) = pair();

    let old_short = ada.encrypt_unpadded(GROUP, b"ok").expect("old encrypt");
    let old_longer = ada
        .encrypt_unpadded(GROUP, b"on my way")
        .expect("old encrypt");
    assert_eq!(
        old_longer.len() - old_short.len(),
        b"on my way".len() - b"ok".len(),
        "the old-build door must really be unpadded, or this test proves nothing"
    );
    opens_to(&mut bo, &old_short, b"ok");
    opens_to(&mut bo, &old_longer, b"on my way");

    // The door left Ada's stored config at padding 0 — exactly the state of a
    // group created before padding existed. Her next ordinary send upgrades it.
    let new_short = ada.encrypt(GROUP, b"ok").expect("encrypt");
    let new_longer = ada.encrypt(GROUP, b"on my way").expect("encrypt");
    assert_eq!(new_short.len(), new_longer.len());
    assert!(new_short.len() > old_short.len());
    opens_to(&mut bo, &new_short, b"ok");
    opens_to(&mut bo, &new_longer, b"on my way");
}
