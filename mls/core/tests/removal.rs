// SPDX-License-Identifier: MIT
//! WHAT A REMOVED MEMBER CAN STILL DO WITH THE STATE IT KEPT.
//!
//! `end_to_end.rs` already removes somebody and proves they cannot read the
//! next message — but it hands them the removal commit first, so the client
//! under test has been TOLD it is out and has marked its own group inactive.
//! That is the polite case, and it is not the one the product produces.
//!
//! In Peachy, the members who remove a person stop addressing that person's
//! devices (delivery is sender-addressed, and nobody addresses a removed
//! leaf), so the removed device can NEVER RECEIVE the commit that removed it. It sits there believing it is a
//! member of a group at the epoch it last reached, holding a complete, valid,
//! unexpired MLS state — and this file is the claim that the belief buys
//! nothing.
//!
//! What the clients do on a removal is docs/sealed-messages.md
//! §Removal. This file proves the property with no server, no network and no
//! product anywhere in the path: if it ever goes red, no amount of server-side
//! access control is the answer.

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use peachy_mls_core::{Error, Incoming};
use support::{client, issuer};

const GROUP: &[u8] = b"peachy-group-removal";

/// Build a three-member group and hand back the three clients, all merged to
/// the same epoch.
///
/// Ada is the admin who will do the removing, Bo the member who stays, Cy the
/// member who goes.
fn three_members() -> (
    peachy_mls_core::Client,
    peachy_mls_core::Client,
    peachy_mls_core::Client,
) {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(&server, 2, "actor-bo", "device-bo-phone");
    let mut cy = client(&server, 3, "actor-cy", "device-cy-phone");

    ada.create_group(GROUP).expect("create");

    let bo_kp = bo.generate_key_package().expect("bo key package");
    let added_bo = ada.add_member(GROUP, &bo_kp).expect("add bo");
    ada.merge_pending_commit(GROUP).expect("merge the add");
    bo.join_from_welcome(&added_bo.welcome.clone().expect("welcome"))
        .expect("bo joins");

    let cy_kp = cy.generate_key_package().expect("cy key package");
    let added_cy = ada.add_member(GROUP, &cy_kp).expect("add cy");
    ada.merge_pending_commit(GROUP).expect("merge the add");
    match bo
        .process_commit(GROUP, &added_cy.commit)
        .expect("bo follows")
    {
        Incoming::Commit(outcome) => assert_eq!(outcome.added.len(), 1),
        other => panic!("expected a commit, got {other:?}"),
    }
    cy.join_from_welcome(&added_cy.welcome.clone().expect("welcome"))
        .expect("cy joins");

    (ada, bo, cy)
}

/// THE ONE THIS FILE EXISTS FOR.
///
/// The removed member is never shown the commit that removed it. Its state is
/// intact, it still believes it is active, and it is handed — by hand, not by
/// any server — two ciphertexts: one from before the removal that it had never
/// been given, and one from after.
///
/// The first opens. That is not a formality: without it, the refusal below
/// would be satisfiable by a client whose store was broken, whose credential
/// had expired, or that had simply been handed rubbish. It is the control that
/// makes the refusal mean "there is no key for this epoch" rather than "this
/// client cannot read anything".
#[test]
fn a_removed_member_that_never_saw_the_commit_still_cannot_read_what_came_after() {
    let (mut ada, mut bo, mut cy) = three_members();

    // A pre-removal message Cy is NOT given yet. Held back deliberately: an
    // MLS application message decrypts exactly once, so a ciphertext Cy has
    // already opened could never serve as the control below.
    let retained = ada
        .encrypt(GROUP, b"we meet at the north gate at six")
        .expect("encrypt before the removal");

    // --- the removal, which Cy is never told about ------------------------
    let cy_leaf = ada
        .leaf_of_device(GROUP, "device-cy-phone")
        .expect("cy is in the roster");
    let removal = ada.remove_leaf(GROUP, cy_leaf).expect("remove cy");
    ada.merge_pending_commit(GROUP).expect("merge the removal");
    // Bo is a real member and does follow it. Somebody has to, or "the epoch
    // moved" would be a claim about one client's private arithmetic.
    match bo
        .process_commit(GROUP, &removal.commit)
        .expect("bo follows")
    {
        Incoming::Commit(outcome) => {
            assert!(!outcome.removed_self);
            assert_eq!(outcome.removed, vec![cy_leaf]);
        }
        other => panic!("expected a commit, got {other:?}"),
    }
    assert_eq!(ada.roster(GROUP).expect("roster").len(), 2);

    // AND CY STILL THINKS IT IS IN. This is the state the product really
    // produces — the Delivery Service stopped answering it the moment the
    // removed device's membership was closed, so the commit above is one it can never
    // fetch — and it is the whole reason this test is not the one in
    // `end_to_end.rs`.
    assert!(
        cy.is_active(GROUP).expect("cy still knows the group"),
        "the point of this test is a removed member that has NOT been told"
    );

    // --- the post-removal message -----------------------------------------
    let after = ada
        .encrypt(GROUP, b"the new gate code is nine nine zero two")
        .expect("encrypt after the removal");
    match bo.process_message(GROUP, &after).expect("bo reads") {
        Incoming::Application { plaintext, .. } => {
            assert_eq!(plaintext, b"the new gate code is nine nine zero two");
        }
        other => panic!("expected an application message, got {other:?}"),
    }

    // --- THE CONTROL: the retained state is alive -------------------------
    match cy
        .process_message(GROUP, &retained)
        .expect("cy opens the pre-removal message")
    {
        Incoming::Application {
            sender, plaintext, ..
        } => {
            assert_eq!(sender.actor_id, "actor-ada");
            assert_eq!(plaintext, b"we meet at the north gate at six");
        }
        other => panic!("expected an application message, got {other:?}"),
    }

    // --- THE CLAIM --------------------------------------------------------
    let refused = cy.process_message(GROUP, &after);
    assert!(
        refused.is_err(),
        "a removed member opened a message sealed after its removal: {refused:?}"
    );

    // ...and it cannot get back in by asking twice, which is worth stating
    // because a retry is exactly what a client that thinks it is a member
    // does. The refusal is not a transient.
    assert!(cy.process_message(GROUP, &after).is_err());
}

/// The removed member cannot SPEAK into the group either, once it knows.
///
/// Separated from the case above because it needs the opposite precondition:
/// `encrypt` asks whether this client is active, so a client that was never
/// told will happily produce a ciphertext — one addressed to an epoch that no
/// longer exists, which every remaining member refuses. Both halves are worth
/// pinning: the refusal a told client gets, and the fact that an untold one's
/// output is inert.
#[test]
fn a_removed_member_cannot_speak_into_the_group_it_left() {
    let (mut ada, mut bo, mut cy) = three_members();

    let cy_leaf = ada
        .leaf_of_device(GROUP, "device-cy-phone")
        .expect("cy is in the roster");
    let removal = ada.remove_leaf(GROUP, cy_leaf).expect("remove cy");
    ada.merge_pending_commit(GROUP).expect("merge the removal");
    bo.process_commit(GROUP, &removal.commit)
        .expect("bo follows");

    // UNTOLD: the ciphertext is produced, and it is worth nothing. Neither of
    // the two members who are still there can open it, because it names the
    // epoch Cy last reached and the group is past it.
    let shouting = cy
        .encrypt(GROUP, b"let me back in")
        .expect("an untold client still encrypts");
    assert!(
        ada.process_message(GROUP, &shouting).is_err(),
        "a message from a removed member was accepted by the group"
    );
    assert!(bo.process_message(GROUP, &shouting).is_err());

    // TOLD: the core refuses at the door.
    match cy
        .process_commit(GROUP, &removal.commit)
        .expect("cy processes")
    {
        Incoming::Commit(outcome) => assert!(outcome.removed_self),
        other => panic!("expected a commit, got {other:?}"),
    }
    assert!(matches!(
        cy.encrypt(GROUP, b"let me back in"),
        Err(Error::NotAMember)
    ));
}

/// THE WAY BACK. A member evicted by somebody else's commit — who is still in
/// the conversation, so the next reconcile re-adds them — must be able to take
/// the Welcome that re-add sends.
///
/// If the inactive state the removal left behind made `join_from_welcome`
/// answer `AlreadyAMember`, the Welcome would be consumed by the fetch and the
/// device would stay out for good. A held group that is no longer
/// ACTIVE is not one this client is in, so the Welcome replaces it.
#[test]
fn an_evicted_member_takes_the_welcome_that_re_adds_it() {
    let (mut ada, mut bo, mut cy) = three_members();

    let cy_leaf = ada
        .leaf_of_device(GROUP, "device-cy-phone")
        .expect("cy is in the roster");
    let removal = ada.remove_leaf(GROUP, cy_leaf).expect("remove cy");
    ada.merge_pending_commit(GROUP).expect("merge the removal");
    bo.process_commit(GROUP, &removal.commit)
        .expect("bo follows");
    match cy
        .process_commit(GROUP, &removal.commit)
        .expect("cy processes")
    {
        Incoming::Commit(outcome) => assert!(outcome.removed_self),
        other => panic!("expected a commit, got {other:?}"),
    }

    // Somebody's next reconcile re-seats Cy on a fresh key package.
    let cy_kp = cy.generate_key_package().expect("cy key package");
    let readd = ada.add_member(GROUP, &cy_kp).expect("re-add cy");
    ada.merge_pending_commit(GROUP).expect("merge the re-add");
    bo.process_commit(GROUP, &readd.commit)
        .expect("bo follows the re-add");

    cy.join_from_welcome(&readd.welcome.clone().expect("welcome"))
        .expect("an evicted member must be able to take the seat it was given back");
    assert_eq!(
        cy.epoch(GROUP).expect("epoch"),
        ada.epoch(GROUP).expect("epoch")
    );

    // And it is really back: it reads the next message and can speak.
    let hello = ada.encrypt(GROUP, b"welcome back").expect("ada speaks");
    match cy.process_message(GROUP, &hello).expect("cy reads") {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"welcome back"),
        other => panic!("expected an application message, got {other:?}"),
    }
    let reply = cy.encrypt(GROUP, b"thanks").expect("cy speaks again");
    match bo.process_message(GROUP, &reply).expect("bo reads cy") {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"thanks"),
        other => panic!("expected an application message, got {other:?}"),
    }
}

/// And the replacement is for an INACTIVE group only: an evicted member that
/// was never told it was removed still holds an active group, and a Welcome
/// into it is still refused — the duplicate-Welcome rule, unchanged.
#[test]
fn a_welcome_into_a_group_still_held_active_is_still_refused() {
    let (mut ada, _bo, mut cy) = three_members();

    let cy_leaf = ada
        .leaf_of_device(GROUP, "device-cy-phone")
        .expect("cy is in the roster");
    ada.remove_leaf(GROUP, cy_leaf).expect("remove cy");
    ada.merge_pending_commit(GROUP).expect("merge the removal");
    // Cy is NOT shown the removal, so its group is still active.
    let epoch_before = cy.epoch(GROUP).expect("epoch");

    let cy_kp = cy.generate_key_package().expect("cy key package");
    let readd = ada.add_member(GROUP, &cy_kp).expect("re-add cy");
    ada.merge_pending_commit(GROUP).expect("merge the re-add");

    let err = cy
        .join_from_welcome(&readd.welcome.clone().expect("welcome"))
        .expect_err("an active group must not be replaced by a Welcome");
    assert!(matches!(err, Error::AlreadyAMember), "got {err:?}");
    assert_eq!(cy.epoch(GROUP).expect("epoch"), epoch_before);
}

/// A removal names the leaf it read, not whoever sits at its index later.
///
/// A roster read, then "remove Cy, add Dee": Dee takes Cy's empty leaf. A
/// removal that still holds the index it read from the first roster must
/// not remove Dee; the leaf key read beside the index no longer matches,
/// so the core refuses with nothing staged and the caller reads again.
#[test]
fn a_removal_from_a_stale_roster_read_does_not_remove_who_moved_into_the_leaf() {
    let (mut ada, _bo, _cy) = three_members();
    let server = issuer();
    let dee = client(&server, 4, "actor-dee", "device-dee-phone");

    // The read the removal is decided on.
    let stale = ada
        .roster(GROUP)
        .expect("roster")
        .into_iter()
        .find(|entry| {
            entry
                .identity
                .as_ref()
                .is_ok_and(|identity| identity.device_id == "device-cy-phone")
        })
        .expect("cy is in the roster");

    // Then the group moves on under it: Cy goes and Dee lands on Cy's leaf.
    ada.remove_leaf(GROUP, stale.leaf_index).expect("remove cy");
    ada.merge_pending_commit(GROUP).expect("merge the removal");
    let dee_kp = dee.generate_key_package().expect("dee key package");
    ada.add_member(GROUP, &dee_kp).expect("add dee");
    ada.merge_pending_commit(GROUP).expect("merge the add");
    assert_eq!(
        ada.leaf_of_device(GROUP, "device-dee-phone")
            .expect("dee is in"),
        stale.leaf_index,
        "the test needs Dee on Cy's old leaf"
    );

    let err = ada
        .remove_member(GROUP, stale.leaf_index, &stale.leaf_key)
        .expect_err("a removal read for Cy must not remove Dee");
    assert!(matches!(err, Error::NoSuchMember), "got {err:?}");
    assert!(
        !ada.has_pending_commit(GROUP).expect("pending"),
        "nothing staged"
    );
    assert!(
        ada.leaf_of_device(GROUP, "device-dee-phone").is_ok(),
        "Dee stays"
    );
}
