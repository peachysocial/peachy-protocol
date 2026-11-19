// SPDX-License-Identifier: MIT
//! THE TWO DOORS: a commit is taken only through `process_commit`, and an
//! application message only through `process_message`.
//!
//! Every client drains its mailbox through two paths. The commit path runs
//! the bookkeeping a commit needs: the roster rows ("Ada added Cy"), the
//! account-key comparison, the group-meta re-read. The message path files
//! words. When both called the one `process`, a commit wrapped as a message
//! was merged on the message path: the epoch and the roster moved with no
//! line in the transcript and no key check, and since a message skips the
//! arbiter, a member could hand different commits for one epoch to different
//! devices.
//!
//! So the core keeps the doors apart, and refuses at the wrong one BEFORE the
//! engine reads the bytes. That second half is what these tests pin: a
//! refusal that came after the merge, or after the ratchet was spent, would
//! be the same bug with an error on top.

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use peachy_mls_core::{Error, Incoming};
use support::{client, issuer};

const GROUP: &[u8] = b"peachy-group-doors";

/// Ada (admin) and Bo, both at the epoch Bo's add made.
fn two_members() -> (peachy_mls_core::Client, peachy_mls_core::Client) {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(&server, 2, "actor-bo", "device-bo-phone");
    ada.create_group(GROUP).expect("create");
    let bo_kp = bo.generate_key_package().expect("bo key package");
    let added = ada.add_member(GROUP, &bo_kp).expect("add bo");
    ada.merge_pending_commit(GROUP).expect("merge the add");
    bo.join_from_welcome(&added.welcome.expect("welcome"))
        .expect("bo joins");
    (ada, bo)
}

fn assert_wrong_door(result: peachy_mls_core::Result<Incoming>) {
    match result {
        Err(Error::WrongDoor(_)) => {}
        other => panic!("expected a wrong-door refusal, got {other:?}"),
    }
}

/// A commit on the wrong door. Ada adds Cy and hands Bo the commit as a
/// MESSAGE. Bo's message door refuses it and nothing moves: same epoch, same
/// roster. The same bytes through the commit door then merge, with the outcome the
/// commit path's bookkeeping reads (who committed, who was added).
#[test]
fn a_commit_on_the_message_door_is_refused_and_moves_nothing() {
    let server = issuer();
    let (mut ada, mut bo) = two_members();
    let cy = client(&server, 3, "actor-cy", "device-cy-phone");

    let cy_kp = cy.generate_key_package().expect("cy key package");
    let added_cy = ada.add_member(GROUP, &cy_kp).expect("add cy");
    ada.merge_pending_commit(GROUP).expect("merge the add");

    let epoch_before = bo.epoch(GROUP).expect("epoch");
    let roster_before = bo.roster(GROUP).expect("roster").len();

    assert_wrong_door(bo.process_message(GROUP, &added_cy.commit));
    assert_eq!(
        bo.epoch(GROUP).expect("epoch"),
        epoch_before,
        "the epoch did not move"
    );
    assert_eq!(
        bo.roster(GROUP).expect("roster").len(),
        roster_before,
        "nobody was added"
    );

    match bo
        .process_commit(GROUP, &added_cy.commit)
        .expect("the commit door takes it")
    {
        Incoming::Commit(outcome) => {
            assert_eq!(outcome.sender.actor_id, "actor-ada");
            assert_eq!(outcome.added.len(), 1);
            assert_eq!(outcome.added[0].actor_id, "actor-cy");
            assert!(!outcome.removed_self);
            assert_eq!(outcome.epoch, epoch_before + 1);
        }
        other => panic!("expected a commit, got {other:?}"),
    }
    assert_eq!(bo.roster(GROUP).expect("roster").len(), roster_before + 1);

    // And the group still works afterwards, for everybody: the refusal left
    // Bo's state exactly where the rest of the group expects it.
    let hello = ada.encrypt(GROUP, b"hello cy").expect("encrypt");
    match bo.process_message(GROUP, &hello).expect("bo reads") {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"hello cy"),
        other => panic!("expected an application message, got {other:?}"),
    }
}

/// THE MAILBOX DOOR takes both kinds, so a client that routes by the kind
/// sealed inside the envelope alone cannot merge a commit that skipped the
/// arbiter: a commit sealed into an MLS entry (a `SendSealed` to this device)
/// is refused and moves nothing; the same bytes in a COMMIT entry merge.
#[test]
fn the_mailbox_door_takes_a_commit_only_from_a_commit_entry() {
    use peachy_mls_core::envelope::{
        envelope_door, EnvelopeDoor, ENVELOPE_KIND_CALL, ENVELOPE_KIND_COMMIT,
        ENVELOPE_KIND_LINK_PREVIEW, ENVELOPE_KIND_MESSAGE, ENVELOPE_KIND_SEAT_ASK,
        ENVELOPE_KIND_TYPING, MAILBOX_KIND_COMMIT, MAILBOX_KIND_MLS,
    };
    // The table every client's router follows
    // (docs/delivery.md §MailboxKind).
    for (mailbox, envelope, door) in [
        (
            MAILBOX_KIND_MLS,
            ENVELOPE_KIND_MESSAGE,
            EnvelopeDoor::Message,
        ),
        (MAILBOX_KIND_MLS, ENVELOPE_KIND_COMMIT, EnvelopeDoor::Drop),
        (
            MAILBOX_KIND_MLS,
            ENVELOPE_KIND_SEAT_ASK,
            EnvelopeDoor::SeatAsk,
        ),
        (MAILBOX_KIND_MLS, ENVELOPE_KIND_TYPING, EnvelopeDoor::Drop),
        (
            MAILBOX_KIND_MLS,
            ENVELOPE_KIND_LINK_PREVIEW,
            EnvelopeDoor::Drop,
        ),
        (MAILBOX_KIND_MLS, ENVELOPE_KIND_CALL, EnvelopeDoor::Call),
        (MAILBOX_KIND_MLS, 0, EnvelopeDoor::Drop),
        (MAILBOX_KIND_MLS, 9, EnvelopeDoor::Drop),
        (
            MAILBOX_KIND_COMMIT,
            ENVELOPE_KIND_COMMIT,
            EnvelopeDoor::Commit,
        ),
        (
            MAILBOX_KIND_COMMIT,
            ENVELOPE_KIND_MESSAGE,
            EnvelopeDoor::Drop,
        ),
        (
            MAILBOX_KIND_COMMIT,
            ENVELOPE_KIND_SEAT_ASK,
            EnvelopeDoor::Drop,
        ),
        (MAILBOX_KIND_COMMIT, ENVELOPE_KIND_CALL, EnvelopeDoor::Drop),
        (2, ENVELOPE_KIND_COMMIT, EnvelopeDoor::Drop),
        (4, ENVELOPE_KIND_MESSAGE, EnvelopeDoor::Drop),
    ] {
        assert_eq!(
            envelope_door(mailbox, envelope),
            door,
            "{mailbox}/{envelope}"
        );
    }

    let server = issuer();
    let (mut ada, mut bo) = two_members();
    let cy = client(&server, 3, "actor-cy", "device-cy-phone");
    let added_cy = ada
        .add_member(GROUP, &cy.generate_key_package().expect("cy key package"))
        .expect("add cy");
    ada.merge_pending_commit(GROUP).expect("merge the add");
    let epoch_before = bo.epoch(GROUP).expect("epoch");

    // Sealed as a commit, but delivered in an MLS entry: refused unread.
    assert_wrong_door(bo.process_mailbox_entry(
        GROUP,
        MAILBOX_KIND_MLS,
        ENVELOPE_KIND_COMMIT,
        &added_cy.commit,
        0,
    ));
    // A COMMIT entry claiming a message: refused unread.
    assert_wrong_door(bo.process_mailbox_entry(
        GROUP,
        MAILBOX_KIND_COMMIT,
        ENVELOPE_KIND_MESSAGE,
        &added_cy.commit,
        0,
    ));
    assert_eq!(bo.epoch(GROUP).expect("epoch"), epoch_before);
    match bo
        .process_mailbox_entry(
            GROUP,
            MAILBOX_KIND_COMMIT,
            ENVELOPE_KIND_COMMIT,
            &added_cy.commit,
            0,
        )
        .expect("a commit entry's commit merges")
    {
        Incoming::Commit(outcome) => assert_eq!(outcome.epoch, epoch_before + 1),
        other => panic!("expected a commit, got {other:?}"),
    }
    // A message in an MLS entry reads; a seat ask is not a group message.
    let hello = ada.encrypt(GROUP, b"hello").expect("encrypt");
    match bo
        .process_mailbox_entry(GROUP, MAILBOX_KIND_MLS, ENVELOPE_KIND_MESSAGE, &hello, 0)
        .expect("bo reads")
    {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"hello"),
        other => panic!("expected an application message, got {other:?}"),
    }
    assert_wrong_door(bo.process_mailbox_entry(
        GROUP,
        MAILBOX_KIND_MLS,
        ENVELOPE_KIND_SEAT_ASK,
        b"{}",
        0,
    ));
}

/// A REMOVAL, the case the transcript row matters most for: on the message
/// door it is refused, and Bo is still a member who can read; on the commit
/// door it removes Bo and says so (`removed_self`), which is what makes the
/// commit path draw "you were removed" and ask back in.
#[test]
fn a_removal_on_the_message_door_does_not_remove() {
    let (mut ada, mut bo) = two_members();
    let bo_leaf = bo
        .roster(GROUP)
        .expect("roster")
        .into_iter()
        .find(|m| {
            m.identity
                .as_ref()
                .map(|i| i.actor_id == "actor-bo")
                .unwrap_or(false)
        })
        .expect("bo is in the roster")
        .leaf_index;
    let removal = ada.remove_leaf(GROUP, bo_leaf).expect("remove bo");
    ada.merge_pending_commit(GROUP).expect("merge the removal");

    assert_wrong_door(bo.process_message(GROUP, &removal.commit));
    assert!(
        bo.encrypt(GROUP, b"still here").is_ok(),
        "Bo was not removed by the message door"
    );

    match bo
        .process_commit(GROUP, &removal.commit)
        .expect("the commit door takes it")
    {
        Incoming::Commit(outcome) => assert!(outcome.removed_self),
        other => panic!("expected a commit, got {other:?}"),
    }
}

/// THE OTHER DIRECTION: an application message wrapped as a commit is
/// refused at the commit door BEFORE it is decrypted. The proof is that the
/// message door can still open it afterwards: a spent ratchet would refuse.
#[test]
fn an_application_message_on_the_commit_door_is_refused_unspent() {
    let (mut ada, mut bo) = two_members();
    let words = ada.encrypt(GROUP, b"not a commit").expect("encrypt");

    assert_wrong_door(bo.process_commit(GROUP, &words));

    match bo.process_message(GROUP, &words).expect("still opens") {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"not a commit"),
        other => panic!("expected an application message, got {other:?}"),
    }
}

/// A commit at the message door is refused whatever it is and whoever made
/// it, so the refusal is no oracle: a no-op self-update by the admin is
/// refused exactly as an add is.
#[test]
fn every_commit_kind_is_refused_on_the_message_door() {
    let (mut ada, mut bo) = two_members();
    let update = ada.self_update(GROUP).expect("self update");
    ada.merge_pending_commit(GROUP).expect("merge the update");
    let epoch = bo.epoch(GROUP).expect("epoch");
    assert_wrong_door(bo.process_message(GROUP, &update.commit));
    assert_eq!(bo.epoch(GROUP).expect("epoch"), epoch);
    assert!(matches!(
        bo.process_commit(GROUP, &update.commit)
            .expect("the commit door takes it"),
        Incoming::Commit(_)
    ));
}

/// Bytes that are not a group message are the codec's refusal on either door,
/// not a wrong door: the door is about a message's kind, and these have none.
#[test]
fn garbage_is_not_a_wrong_door() {
    let (_ada, mut bo) = two_members();
    for result in [
        bo.process_message(GROUP, b"not mls"),
        bo.process_commit(GROUP, b"not mls"),
    ] {
        match result {
            Err(Error::WrongDoor(_)) => panic!("garbage read as a wrong door"),
            Err(_) => {}
            Ok(other) => panic!("garbage was accepted: {other:?}"),
        }
    }
}
