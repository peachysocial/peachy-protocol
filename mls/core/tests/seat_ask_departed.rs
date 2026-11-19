// SPDX-License-Identifier: MIT
//! A caller's `pending_actors` never re-seats somebody who left.
//!
//! `verify_join_request` judges a signed seat ask's membership last: the
//! asker's person holds a leaf in this device's copy of the group, is this
//! device's own person, or is among the people the caller names as still
//! being added. That last list is the caller's own invitations. A member that
//! filled it from the ask (the asker's own claimed actor) would make the
//! membership step always pass, and a removed member, who keeps the group id
//! and their own signing key, would sign their way back in and read the next
//! message.
//!
//! So the core remembers whose last leaf it saw leave each group, and a
//! pending list naming one of those people is not honoured for them. People
//! a device admits by its own rule (a group link it approved, an open group's
//! join inbox) go through `verify_admitted_join_request`, which judges
//! everything but membership, so a person who left can still come back that
//! way. Nothing changes for the asks a member's devices legitimately send: a
//! person who still holds a leaf, a device of the verifier's own person, a
//! device re-seated after it fell off the ratchet, and a person the caller
//! invited who never held a leaf.
//!
//! Docs: docs/delivery.md §Rejoin with a sealed seat ask,
//! docs/sealed-messages.md §The member's answer.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use peachy_mls_core::{Client, Incoming, JoinRequestVerdict, MemoryKv, PeachyStorage};
use support::{client, client_on, issuer};

const GROUP: &[u8] = b"66666666-6666-4666-8666-666666666666";

fn add(adder: &mut Client, joiner: &mut Client, group: &[u8]) -> Vec<u8> {
    let key_package = joiner.generate_key_package().expect("key package");
    let bundle = adder.add_member(group, &key_package).expect("add");
    adder.merge_pending_commit(group).expect("merge");
    // Through the head, as the apps take a Welcome: the adder's commit was
    // the last the delivery service took.
    support::join_at_head(
        joiner,
        &bundle.welcome.expect("welcome"),
        support::head_of(adder, group),
    )
    .expect("join");
    bundle.commit
}

fn reads(sender: &mut Client, reader: &mut Client, group: &[u8], text: &[u8]) -> bool {
    let Ok(wire) = sender.encrypt(group, text) else {
        return false;
    };
    match reader.process_message(group, &wire) {
        Ok(Incoming::Application { plaintext, .. }) => plaintext == text,
        _ => false,
    }
}

/// `remover` removes `device`'s leaf; every client in `others` applies it.
fn remove_device(remover: &mut Client, group: &[u8], device: &str, others: &mut [&mut Client]) {
    let leaf = remover.leaf_of_device(group, device).expect("leaf");
    let removal = remover.remove_leaf(group, leaf).expect("remove");
    remover.merge_pending_commit(group).expect("merge");
    for other in others.iter_mut() {
        other
            .process_commit(group, &removal.commit)
            .expect("apply removal");
    }
}

/// `verifier`'s verdict on a fresh, honestly signed seat ask from `asker`.
fn verdict(
    verifier: &Client,
    asker: &Client,
    actor: &str,
    device: &str,
    pending: &[&str],
) -> JoinRequestVerdict {
    let proof = asker.sign_join_request(GROUP).unwrap();
    let key_package = asker.generate_key_package().unwrap();
    verifier.verify_join_request(GROUP, actor, device, &proof, &key_package, pending)
}

/// Ada founds the group with Bo and Eve, then removes Eve. Ada saw the
/// removal through her own commit, Bo through the commit door.
fn ada_bo_and_removed_eve() -> (Client, Client, Client) {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    let mut eve = client(&server, 3, "actor-eve", "device-eve");
    ada.create_group(GROUP).unwrap();
    add(&mut ada, &mut bo, GROUP);
    let seat = add(&mut ada, &mut eve, GROUP);
    bo.process_commit(GROUP, &seat).unwrap();
    remove_device(&mut ada, GROUP, "device-eve", &mut [&mut bo, &mut eve]);
    assert!(!eve.is_active(GROUP).unwrap());
    (ada, bo, eve)
}

// ---------------------------------------------------------------------------
// Refused
// ---------------------------------------------------------------------------

/// A member who names the asker's own claimed actor as `pending_actors` (the
/// owner read off the ask when no leaf holds the asking device) still seats
/// no ex-member: the verdict is `NotAMember`, so nobody adds Eve and she
/// cannot read what comes next.
#[test]
fn naming_a_removed_member_as_pending_does_not_reseat_them() {
    let (mut ada, mut bo, mut eve) = ada_bo_and_removed_eve();

    let proof = eve.sign_join_request(GROUP).unwrap();
    let eve_kp = eve.generate_key_package().unwrap();
    assert!(bo.first_sight_of_join_request(GROUP, &proof).unwrap());

    // With no caller list, and with the asker's own actor as the caller list.
    for pending in [&[][..], &["actor-eve"][..], &["actor-cy", "actor-eve"][..]] {
        assert_eq!(
            bo.verify_join_request(GROUP, "actor-eve", "device-eve", &proof, &eve_kp, pending),
            JoinRequestVerdict::NotAMember,
            "Bo, who applied the removal, with pending {pending:?}"
        );
        assert_eq!(
            ada.verify_join_request(GROUP, "actor-eve", "device-eve", &proof, &eve_kp, pending),
            JoinRequestVerdict::NotAMember,
            "Ada, who committed the removal, with pending {pending:?}"
        );
    }

    // A second device of Eve's is no better off: the person left, not a device.
    let server = issuer();
    let eve_laptop = client(&server, 4, "actor-eve", "device-eve-laptop");
    assert_eq!(
        verdict(
            &bo,
            &eve_laptop,
            "actor-eve",
            "device-eve-laptop",
            &["actor-eve"]
        ),
        JoinRequestVerdict::NotAMember
    );

    // The group goes on without her.
    assert!(reads(&mut ada, &mut bo, GROUP, b"eve is gone, right?"));
    let wire = ada.encrypt(GROUP, b"just us").unwrap();
    assert!(eve.process_message(GROUP, &wire).is_err());
}

/// The record lives in the store: a client reopened over the same store
/// still refuses the pending escape for the person it saw leave.
#[test]
fn the_record_of_who_left_survives_a_reopen() {
    let server = issuer();
    let kv = MemoryKv::new();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let store = || PeachyStorage::open(Box::new(kv.clone())).expect("open");
    let mut bo = client_on(&server, 2, "actor-bo", "device-bo", store());
    let mut eve = client(&server, 3, "actor-eve", "device-eve");
    ada.create_group(GROUP).unwrap();
    add(&mut ada, &mut bo, GROUP);
    let seat = add(&mut ada, &mut eve, GROUP);
    bo.process_commit(GROUP, &seat).unwrap();
    remove_device(&mut ada, GROUP, "device-eve", &mut [&mut bo, &mut eve]);
    drop(bo);

    let bo = client_on(&server, 2, "actor-bo", "device-bo", store());
    assert_eq!(
        verdict(&bo, &eve, "actor-eve", "device-eve", &["actor-eve"]),
        JoinRequestVerdict::NotAMember
    );
}

/// A device that fell off the ratchet and was brought back by a Welcome
/// learns who left while it was away: the roster it kept, minus the new tree.
#[test]
fn a_device_brought_back_by_a_welcome_knows_who_left_while_it_was_away() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut cy = client(&server, 5, "actor-cy", "device-cy");
    let mut eve = client(&server, 3, "actor-eve", "device-eve");
    ada.create_group(GROUP).unwrap();
    add(&mut ada, &mut cy, GROUP);
    let seat = add(&mut ada, &mut eve, GROUP);
    cy.process_commit(GROUP, &seat).unwrap();

    // Cy falls off and forgets the group, keeping its roster (Ada and Eve).
    cy.forget_group(GROUP).unwrap();
    // Meanwhile Eve is removed; Cy never sees that commit.
    remove_device(&mut ada, GROUP, "device-eve", &mut [&mut eve]);
    // Ada re-seats Cy: Cy's leaf goes, and a fresh one comes in by Welcome.
    let cy_leaf = ada.leaf_of_device(GROUP, "device-cy").unwrap();
    let bundle = ada
        .replace_member(GROUP, cy_leaf, &cy.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    cy.join_from_welcome(&bundle.welcome.unwrap()).unwrap();

    assert_eq!(
        verdict(&cy, &eve, "actor-eve", "device-eve", &["actor-eve"]),
        JoinRequestVerdict::NotAMember
    );
    // Ada, still seated, is still somebody whose ask holds.
    assert_eq!(
        verdict(&cy, &ada, "actor-ada", "device-ada", &[]),
        JoinRequestVerdict::Accepted
    );
}

// ---------------------------------------------------------------------------
// Still accepted
// ---------------------------------------------------------------------------

/// A current member's new device: their person holds a leaf, whatever the
/// caller's list says, and whether or not one of their devices was removed.
#[test]
fn a_current_members_new_device_is_still_accepted() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    let mut bo_old = client(&server, 6, "actor-bo", "device-bo-old");
    ada.create_group(GROUP).unwrap();
    add(&mut ada, &mut bo, GROUP);
    let seat = add(&mut ada, &mut bo_old, GROUP);
    bo.process_commit(GROUP, &seat).unwrap();
    // One of Bo's devices is revoked and its leaf removed; Bo stays.
    remove_device(
        &mut ada,
        GROUP,
        "device-bo-old",
        &mut [&mut bo, &mut bo_old],
    );

    let bo_laptop = client(&server, 7, "actor-bo", "device-bo-laptop");
    for pending in [&[][..], &["actor-bo"][..]] {
        assert_eq!(
            verdict(&ada, &bo_laptop, "actor-bo", "device-bo-laptop", pending),
            JoinRequestVerdict::Accepted,
            "pending {pending:?}"
        );
    }
}

/// A member's device that lost its state forgets the group, asks, and is
/// re-seated by a replace (its leaf out and back in, one commit). Its person
/// never left, so its next ask holds on every member's device.
#[test]
fn a_member_rejoining_after_losing_state_is_still_accepted() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    let mut cy = client(&server, 5, "actor-cy", "device-cy");
    ada.create_group(GROUP).unwrap();
    add(&mut ada, &mut bo, GROUP);
    let seat = add(&mut ada, &mut cy, GROUP);
    bo.process_commit(GROUP, &seat).unwrap();

    bo.forget_group(GROUP).unwrap();
    assert_eq!(
        verdict(&ada, &bo, "actor-bo", "device-bo", &["actor-bo"]),
        JoinRequestVerdict::Accepted
    );
    let leaf = ada.leaf_of_device(GROUP, "device-bo").unwrap();
    let bundle = ada
        .replace_member(GROUP, leaf, &bo.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    cy.process_commit(GROUP, &bundle.commit).unwrap();
    bo.join_from_welcome(&bundle.welcome.unwrap()).unwrap();
    assert!(reads(&mut cy, &mut bo, GROUP, b"welcome back"));

    // The replace took Bo's leaf out and put one back in the same commit:
    // nobody recorded him as gone, on the committer or on another member.
    for verifier in [&ada, &cy] {
        for pending in [&[][..], &["actor-bo"][..]] {
            assert_eq!(
                verdict(verifier, &bo, "actor-bo", "device-bo", pending),
                JoinRequestVerdict::Accepted,
                "pending {pending:?}"
            );
        }
    }
}

/// This device's own person, and somebody the caller invited who never held
/// a leaf (picked when the group was made, with no device then), still hold.
#[test]
fn own_person_and_a_never_seated_invitee_are_still_accepted() {
    let (ada, _bo, _eve) = ada_bo_and_removed_eve();
    let server = issuer();

    let ada_laptop = client(&server, 8, "actor-ada", "device-ada-laptop");
    assert_eq!(
        verdict(&ada, &ada_laptop, "actor-ada", "device-ada-laptop", &[]),
        JoinRequestVerdict::Accepted
    );

    let cy = client(&server, 5, "actor-cy", "device-cy");
    assert_eq!(
        verdict(&ada, &cy, "actor-cy", "device-cy", &[]),
        JoinRequestVerdict::NotAMember
    );
    assert_eq!(
        verdict(&ada, &cy, "actor-cy", "device-cy", &["actor-cy"]),
        JoinRequestVerdict::Accepted
    );
}

/// A person who left can come back through a door the member's own rule
/// opens (a group link it approved, an open group's join inbox):
/// `verify_admitted_join_request` checks the proof and not membership. Once
/// re-seated they hold a leaf, and their later rejoin asks hold too.
#[test]
fn a_person_who_left_can_be_admitted_again_by_the_callers_own_rule() {
    let (mut ada, mut bo, mut eve) = ada_bo_and_removed_eve();

    let proof = eve.sign_join_request(GROUP).unwrap();
    let eve_kp = eve.generate_key_package().unwrap();
    assert_eq!(
        bo.verify_admitted_join_request(GROUP, "actor-eve", "device-eve", &proof, &eve_kp),
        JoinRequestVerdict::Accepted
    );
    // Still a proof check: an ask written for Eve by somebody else, or one
    // checked against another device's package, holds nowhere.
    let forged = bo.sign_join_request(GROUP).unwrap();
    assert_eq!(
        bo.verify_admitted_join_request(GROUP, "actor-eve", "device-eve", &forged, &eve_kp),
        JoinRequestVerdict::BadSignature
    );
    assert_eq!(
        bo.verify_admitted_join_request(
            GROUP,
            "actor-eve",
            "device-eve",
            &proof,
            &bo.generate_key_package().unwrap()
        ),
        JoinRequestVerdict::IdentityMismatch
    );

    // Bo admits her; Ada applies the add.
    let bundle = bo.add_member(GROUP, &eve_kp).unwrap();
    bo.merge_pending_commit(GROUP).unwrap();
    ada.process_commit(GROUP, &bundle.commit).unwrap();
    eve.join_from_welcome(&bundle.welcome.unwrap()).unwrap();
    assert!(reads(&mut ada, &mut eve, GROUP, b"hello again"));

    // Seated again, her rejoin asks are judged by the tree.
    assert_eq!(
        verdict(&ada, &eve, "actor-eve", "device-eve", &[]),
        JoinRequestVerdict::Accepted
    );
}

/// A person who leaves on purpose drops what their device kept of the
/// group's people, the record of who left included.
#[test]
fn leaving_on_purpose_drops_the_record_of_who_left() {
    let (_ada, mut bo, eve) = ada_bo_and_removed_eve();
    bo.forget_group(GROUP).unwrap();
    assert_eq!(
        verdict(&bo, &eve, "actor-eve", "device-eve", &["actor-eve"]),
        JoinRequestVerdict::NotAMember,
        "kept while Bo may still be brought back"
    );
    bo.forget_remembered_roster(GROUP).unwrap();
    assert_eq!(
        verdict(&bo, &eve, "actor-eve", "device-eve", &["actor-eve"]),
        JoinRequestVerdict::Accepted,
        "a device holding nothing of the group judges only the caller's list"
    );
}
