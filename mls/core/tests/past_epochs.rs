// SPDX-License-Identifier: MIT
//! How far back a message still opens: the current epoch and
//! `RETAINED_PAST_EPOCHS` (four) before it, and no further.
//!
//! A past epoch's keys are what a seized device gives up for messages it has
//! not opened yet, so the bound is kept to what the one unordered case needs
//! (a message sealed just before its sender heard of a commit, placed after
//! it), not to how long a device can be away: its mailbox comes back in
//! order. These tests pin the line on both sides, and that a group stored
//! with a bound of 32 is cut down when the client opens.
//!
//! docs/mls-core.md §Group configuration

mod support;

use peachy_mls_core::{Client, Incoming, RETAINED_PAST_EPOCHS};
use support::{client, issuer};

const GROUP: &[u8] = b"peachy-group-past-epochs";

fn pair(ada: &mut Client, bo: &mut Client) {
    ada.create_group(GROUP).expect("create");
    let added = ada
        .add_member(GROUP, &bo.generate_key_package().expect("kp"))
        .expect("add bo");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.join_from_welcome(&added.welcome.expect("welcome"))
        .expect("bo joins");
}

/// `ada` moves the group on `n` epochs by herself. The messages in flight to
/// her were sealed before any of it.
fn advance(ada: &mut Client, n: usize) {
    for _ in 0..n {
        ada.self_update(GROUP).expect("self update");
        ada.merge_pending_commit(GROUP).expect("merge");
    }
}

fn opens(ada: &mut Client, wire: &[u8], words: &[u8]) -> bool {
    match ada.process_message(GROUP, wire) {
        Ok(Incoming::Application { plaintext, .. }) => {
            assert_eq!(plaintext, words);
            true
        }
        Ok(other) => panic!("expected an application message, got {other:?}"),
        Err(_) => false,
    }
}

#[test]
fn the_bound_is_four_past_epochs() {
    assert_eq!(RETAINED_PAST_EPOCHS, 4);
}

#[test]
fn a_message_four_epochs_back_opens_and_five_back_does_not() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(&server, 2, "actor-bo", "device-bo-phone");
    pair(&mut ada, &mut bo);
    let four = bo.encrypt(GROUP, b"four back").expect("encrypt");
    let five = bo.encrypt(GROUP, b"five back").expect("encrypt");

    advance(&mut ada, RETAINED_PAST_EPOCHS);
    assert!(
        opens(&mut ada, &four, b"four back"),
        "a message from the oldest retained epoch must still open"
    );
    advance(&mut ada, 1);
    assert!(
        !opens(&mut ada, &five, b"five back"),
        "the epoch before the retained ones must be gone"
    );
}

#[cfg(feature = "test-forgery")]
#[test]
fn a_group_stored_with_the_old_bound_is_cut_down_when_it_is_opened() {
    use peachy_mls_core::{MemoryKv, PeachyStorage};
    use support::client_on;

    let server = issuer();
    let kv = MemoryKv::new();
    let store = |kv: &MemoryKv| PeachyStorage::open(Box::new(kv.clone())).expect("store");
    let mut ada = client_on(&server, 1, "actor-ada", "device-ada-phone", store(&kv));
    let mut bo = client(&server, 2, "actor-bo", "device-bo-phone");
    pair(&mut ada, &mut bo);
    // A store that keeps 32 past epochs for the group.
    ada.forge_stored_past_epochs(GROUP, 32).expect("forge");

    let before = bo
        .encrypt(GROUP, b"read before the upgrade")
        .expect("encrypt");
    let after = bo
        .encrypt(GROUP, b"read after the upgrade")
        .expect("encrypt");
    // Bo follows all but the last of Ada's commits, and says something at
    // the epoch just before her last one.
    for _ in 0..RETAINED_PAST_EPOCHS + 1 {
        let update = ada.self_update(GROUP).expect("self update");
        ada.merge_pending_commit(GROUP).expect("merge");
        bo.process_commit(GROUP, &update.commit)
            .expect("bo applies");
    }
    let recent = bo.encrypt(GROUP, b"one epoch back").expect("encrypt");
    advance(&mut ada, 1);
    // The wide store really kept the old one.
    assert!(opens(&mut ada, &before, b"read before the upgrade"));
    drop(ada);

    // The next build opens the same store: the epochs past the bound go, and
    // the newest stay. (OpenMLS's own resize, run alone, keeps the oldest.)
    let mut ada = client_on(&server, 1, "actor-ada", "device-ada-phone", store(&kv));
    assert!(
        !opens(&mut ada, &after, b"read after the upgrade"),
        "the reopened group must hold no more than RETAINED_PAST_EPOCHS past epochs"
    );
    assert!(
        opens(&mut ada, &recent, b"one epoch back"),
        "the cut must keep the NEWEST past epochs"
    );
}
