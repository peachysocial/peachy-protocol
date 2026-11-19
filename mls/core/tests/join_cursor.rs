// SPDX-License-Identifier: MIT
//! Where a joining device starts reading, and what happens when it starts in
//! the wrong place.
//!
//! A Welcome does not hand its recipient the group's history. It hands them a
//! sealed state at ONE epoch: the epoch produced by the commit that minted the
//! Welcome. So the joiner has effectively applied everything up to and
//! including that commit, and the commits it must replay are the ones made
//! strictly AFTER it — which, on the wire, are the commits that follow the
//! Welcome in the device's mailbox, as written down in
//! docs/delivery.md §Welcome semantics.
//!
//! Starting from anywhere else is wrong, and this file is the protocol-level
//! half of why.
//! There is no seq here and no delivery service — a commit's position is its
//! index in an ordinary `Vec`, kept by the test the way `rejoin.rs` keeps one —
//! because the number is not the point. The point is what a member's ratchet
//! does when a commit is skipped: nothing at all announces it, and the failure
//! surfaces one message later as an epoch mismatch, i.e. as a decryption error
//! that reads like a fault in the cryptography.
//!
//! The pair of tests is deliberate. The first builds a group the way a group is
//! built — one commit per person — and skips exactly one commit. The second
//! builds a two-person DM and shows that the same wrong cursor is *correct*
//! there, by arithmetic and not by luck: one commit means the head IS the
//! joining point. That is why sealed DMs shipped on four clients with this bug
//! in them and no test, no journey and no user could see it.

mod support;

use peachy_mls_core::{Error, Incoming};
use support::{client, issuer};

const GROUP: &[u8] = b"peachy-group-join-cursor";

#[test]
fn a_joiner_that_starts_at_the_head_skips_the_commit_that_added_the_third_member() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut ava = client(&server, 2, "actor-ava", "device-ava-phone");
    let mut cal = client(&server, 3, "actor-cal", "device-cal-phone");

    // The group's whole history, in order — what a client would read out of
    // its mailbox. A `Vec` and an index, nothing more: this is a position
    // in a list, not a delivery service.
    let mut stream: Vec<Vec<u8>> = Vec::new();

    // --- commit 0: Ada adds Ava ------------------------------------------
    ada.create_group(GROUP).expect("create");
    let ava_kp = ava.generate_key_package().expect("ava key package");
    let add_ava = ada.add_member(GROUP, &ava_kp).expect("add ava");
    assert_eq!(ada.merge_pending_commit(GROUP).expect("merge"), 1);
    stream.push(add_ava.commit.clone());
    // WHERE AVA CAME IN. The Welcome she is handed was minted by the commit at
    // this index, and it seals her into the epoch that commit produced.
    let ava_joined_at = stream.len() - 1;
    ava.join_from_welcome(&add_ava.welcome.clone().expect("adding produces a Welcome"))
        .expect("ava joins");
    assert_eq!(ava.epoch(GROUP).expect("epoch"), 1);

    // --- commit 1: Ada adds Cal ------------------------------------------
    // A second commit, because that is how a group grows. MLS has no "add two
    // members atomically" a client is obliged to use, and Peachy's clients add
    // one person at a time; a DM's history stops at the commit above, a group's
    // does not.
    let cal_kp = cal.generate_key_package().expect("cal key package");
    let add_cal = ada.add_member(GROUP, &cal_kp).expect("add cal");
    assert_eq!(ada.merge_pending_commit(GROUP).expect("merge"), 2);
    stream.push(add_cal.commit.clone());
    cal.join_from_welcome(&add_cal.welcome.clone().expect("adding produces a Welcome"))
        .expect("cal joins");
    assert_eq!(cal.epoch(GROUP).expect("epoch"), 2);

    // THE OLD CURSOR, spelled out. "Start at the head" means replaying
    // everything after the last entry in the stream — which is empty. Ava is
    // handed nothing to apply and is told nothing is wrong.
    let head = stream.len();
    let from_head = &stream[head..];
    assert!(
        from_head.is_empty(),
        "starting at the head gives the joiner nothing to apply — THAT is the bug",
    );
    for commit in from_head {
        ava.process_commit(GROUP, commit).expect("ava replays");
    }

    // She is a member. Her roster is right for the epoch she is in. Nothing has
    // failed, nothing has warned, and she is one commit behind the group.
    assert!(ava.is_active(GROUP).expect("active"));
    assert_eq!(ava.epoch(GROUP).expect("epoch"), 1);
    assert_eq!(ada.epoch(GROUP).expect("epoch"), 2);
    assert_eq!(
        ava.roster(GROUP).expect("roster").len(),
        2,
        "Ava cannot see Cal, because she never applied the commit that added him",
    );

    // --- and then somebody speaks ----------------------------------------
    let sealed = ada
        .encrypt(GROUP, b"three of us now")
        .expect("ada encrypts at the head epoch");

    // THE SYMPTOM. Not a policy refusal: a message sealed past Ava's copy.
    // It used to be an MLS error in OpenMLS' own words, "Message epoch
    // differs from the group's epoch", which a reader who has not been told
    // about cursors takes for the crypto being broken. It is `StaleCopy` now,
    // naming both epochs, and the recovery driver says what to do about it
    // (tests/recovery.rs).
    match ava.process_message(GROUP, &sealed) {
        Err(Error::StaleCopy {
            message_epoch,
            copy_epoch,
        }) => {
            assert_eq!((message_epoch, copy_epoch), (2, 1));
        }
        other => panic!("a member one commit behind must fail to read, got {other:?}"),
    }

    // The ciphertext itself is fine — Cal, who joined at the head and is at the
    // head, opens it. So the fault is in one member's cursor and in nothing
    // else, which is exactly what makes it so hard to see from a bug report.
    match cal.process_message(GROUP, &sealed).expect("cal reads") {
        Incoming::Application {
            sender, plaintext, ..
        } => {
            assert_eq!(sender.actor_id, "actor-ada");
            assert_eq!(plaintext, b"three of us now");
        }
        other => panic!("expected an application message, got {other:?}"),
    }

    // --- the cursor the Welcome should have carried -----------------------
    // Replay from strictly after the commit that minted Ava's Welcome. This is
    // what `commit_seq` buys, and it is a non-empty set — the commit that added
    // Cal, the one the head cursor silently dropped.
    let from_join = &stream[ava_joined_at + 1..];
    assert_eq!(
        from_join.len(),
        1,
        "the joiner has exactly the commits made after she came in",
    );
    for commit in from_join {
        match ava.process_commit(GROUP, commit).expect("ava catches up") {
            Incoming::Commit(_) => {}
            other => panic!("expected a commit, got {other:?}"),
        }
    }
    assert_eq!(ava.epoch(GROUP).expect("epoch"), 2);
    assert_eq!(
        ava.roster(GROUP).expect("roster").len(),
        3,
        "and now she can see Cal"
    );

    // THE SAME ciphertext, unchanged, now opens. The failed attempt above
    // consumed nothing: framing is validated before any ratchet is touched, so
    // a client that catches up after a rejection does not need the message
    // re-sent. Nothing about the sealed bytes was ever wrong.
    match ava
        .process_message(GROUP, &sealed)
        .expect("ava reads after catching up")
    {
        Incoming::Application {
            sender, plaintext, ..
        } => {
            assert_eq!(sender.actor_id, "actor-ada");
            assert_eq!(plaintext, b"three of us now");
        }
        other => panic!("expected an application message, got {other:?}"),
    }

    // And she can speak back, which is the other half of "in the group".
    let reply = ava.encrypt(GROUP, b"hello cal").expect("ava encrypts");
    match cal
        .process_message(GROUP, &reply)
        .expect("cal reads the reply")
    {
        Incoming::Application {
            sender, plaintext, ..
        } => {
            assert_eq!(sender.actor_id, "actor-ava");
            assert_eq!(plaintext, b"hello cal");
        }
        other => panic!("expected an application message, got {other:?}"),
    }
}

#[test]
fn a_two_person_dm_is_one_commit_so_the_head_and_the_joining_point_are_the_same() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut ava = client(&server, 2, "actor-ava", "device-ava-phone");

    let mut stream: Vec<Vec<u8>> = Vec::new();

    ada.create_group(GROUP).expect("create");
    let ava_kp = ava.generate_key_package().expect("ava key package");
    let add_ava = ada.add_member(GROUP, &ava_kp).expect("add ava");
    assert_eq!(ada.merge_pending_commit(GROUP).expect("merge"), 1);
    stream.push(add_ava.commit.clone());
    let ava_joined_at = stream.len() - 1;
    ava.join_from_welcome(&add_ava.welcome.clone().expect("adding produces a Welcome"))
        .expect("ava joins");

    // THE WHOLE HISTORY of a two-person DM: creation is not a commit, and one
    // Add is all there is. So "after the head" and "after the commit that
    // minted my Welcome" are the same empty set — not by luck, by arithmetic,
    // and for every DM there will ever be.
    assert_eq!(stream.len(), 1, "a DM is built by exactly one commit");
    assert_eq!(
        ava_joined_at + 1,
        stream.len(),
        "the joining commit IS the head, which is why the wrong cursor was invisible here",
    );
    assert!(stream[ava_joined_at + 1..].is_empty());

    // Both cursors therefore leave her at the group's epoch with a full roster,
    // and the DM works either way.
    assert_eq!(
        ava.epoch(GROUP).expect("epoch"),
        ada.epoch(GROUP).expect("epoch")
    );
    assert_eq!(ava.roster(GROUP).expect("roster").len(), 2);

    let sealed = ada.encrypt(GROUP, b"just the two of us").expect("encrypt");
    match ava.process_message(GROUP, &sealed).expect("ava reads") {
        Incoming::Application {
            sender, plaintext, ..
        } => {
            assert_eq!(sender.actor_id, "actor-ada");
            assert_eq!(plaintext, b"just the two of us");
        }
        other => panic!("expected an application message, got {other:?}"),
    }
}
