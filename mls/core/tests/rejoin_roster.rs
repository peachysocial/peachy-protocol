// SPDX-License-Identifier: MIT
//! A group id names a conversation, not a secret. A removed member keeps it,
//! and the delivery service writes the group's head. Together they can move
//! a device that fell out of a group into a group of the removed member's
//! making; what they cannot do is do it quietly, or keep the real group out.
//!
//! - **What the new tree brought is told.** A Welcome that restores or
//!   replaces a known group leaves a `RejoinReport`, drawn against the roster
//!   the device last saw there: who re-added this device, who is in the
//!   group now that was not, and who is gone
//!   (docs/delivery.md §A Welcome into a group this device knew).
//! - **The real group's Welcome at the head replaces a copy.** A device moved
//!   into somebody's own group under the id is taken back by the real
//!   group's next re-add.
//! - **A signed seat ask proves who is asking, not that they belong.**
//!   `verify_join_request` answers `NotAMember` for an asker who holds no
//!   leaf here, unless the caller names them as someone it is still trying to
//!   add (docs/sealed-messages.md §The member's answer).

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use peachy_mls_core::issuer::{device_key_pair, TestIssuer};
use peachy_mls_core::{
    Client, ClientConfig, Error, FixedClock, Incoming, JoinRequestVerdict, PeachyStorage,
    RejoinReport, SEND_KEY_LABEL,
};
use sha2::{Digest, Sha256};
use support::{client, device_seed, issuer, past_the_mark, DAY, HOUR, NOW};

const GROUP: &[u8] = b"33333333-3333-4333-8333-333333333333";

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

/// Ada founds the group with Bo and Eve, then removes Eve. Eve keeps her
/// inactive copy, and with it the group id.
fn ada_bo_and_removed_eve(server: &TestIssuer) -> (Client, Client, Client) {
    let mut ada = client(server, 1, "actor-ada", "device-ada");
    let mut bo = client(server, 2, "actor-bo", "device-bo");
    let mut eve = client(server, 3, "actor-eve", "device-eve");
    ada.create_group(GROUP).unwrap();
    add(&mut ada, &mut bo, GROUP);
    let commit = add(&mut ada, &mut eve, GROUP);
    bo.process_commit(GROUP, &commit).unwrap();
    let eve_leaf = ada.leaf_of_device(GROUP, "device-eve").unwrap();
    let removal = ada.remove_leaf(GROUP, eve_leaf).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    bo.process_commit(GROUP, &removal.commit).unwrap();
    match eve.process_commit(GROUP, &removal.commit).unwrap() {
        Incoming::Commit(outcome) => assert!(outcome.removed_self),
        other => panic!("{other:?}"),
    }
    assert!(!eve.is_active(GROUP).unwrap());
    (ada, bo, eve)
}

// ---------------------------------------------------------------------------
// An ex-member's seat ask seats nobody
// ---------------------------------------------------------------------------

#[test]
fn an_ex_members_seat_ask_is_not_a_member_and_seats_nobody() {
    let server = issuer();
    let (_ada, mut bo, eve) = ada_bo_and_removed_eve(&server);

    // Eve kept the group id, so she can still sign a seat ask for it.
    let proof = eve.sign_join_request(GROUP).unwrap();
    let key_package = eve.generate_key_package().unwrap();
    assert!(bo.first_sight_of_join_request(GROUP, &proof).unwrap());

    // Every other check holds; membership does not.
    assert_eq!(
        bo.verify_join_request(GROUP, "actor-eve", "device-eve", &proof, &key_package, &[]),
        JoinRequestVerdict::NotAMember
    );
    // A pending list naming somebody else changes nothing.
    assert_eq!(
        bo.verify_join_request(
            GROUP,
            "actor-eve",
            "device-eve",
            &proof,
            &key_package,
            &["actor-cy"]
        ),
        JoinRequestVerdict::NotAMember
    );
    // A device that holds no copy of the group judges her the same way.
    assert_eq!(
        bo.verify_join_request(
            b"another-group",
            "actor-eve",
            "device-eve",
            &eve.sign_join_request(b"another-group").unwrap(),
            &key_package,
            &[]
        ),
        JoinRequestVerdict::NotAMember
    );
}

#[test]
fn a_seat_ask_from_a_member_or_from_somebody_the_caller_is_adding_still_holds() {
    let server = issuer();
    let (ada, bo, _eve) = ada_bo_and_removed_eve(&server);

    // Bo's phone fell off the ratchet and asks back in: Bo holds a leaf.
    let proof = bo.sign_join_request(GROUP).unwrap();
    let key_package = bo.generate_key_package().unwrap();
    assert_eq!(
        ada.verify_join_request(GROUP, "actor-bo", "device-bo", &proof, &key_package, &[]),
        JoinRequestVerdict::Accepted
    );

    // Ada's own new laptop: her own person, seated or not.
    let mut laptop = client(&server, 4, "actor-ada", "device-ada-laptop");
    let proof = laptop.sign_join_request(GROUP).unwrap();
    let key_package = laptop.generate_key_package().unwrap();
    assert_eq!(
        ada.verify_join_request(
            GROUP,
            "actor-ada",
            "device-ada-laptop",
            &proof,
            &key_package,
            &[]
        ),
        JoinRequestVerdict::Accepted
    );

    // Cy, whom Ada picked when she made the group but who had no device then,
    // or who came through a link Ada's device admitted: the caller says so.
    let mut cy = client(&server, 5, "actor-cy", "device-cy");
    let proof = cy.sign_join_request(GROUP).unwrap();
    let key_package = cy.generate_key_package().unwrap();
    assert_eq!(
        ada.verify_join_request(GROUP, "actor-cy", "device-cy", &proof, &key_package, &[]),
        JoinRequestVerdict::NotAMember
    );
    assert_eq!(
        ada.verify_join_request(
            GROUP,
            "actor-cy",
            "device-cy",
            &proof,
            &key_package,
            &["actor-cy"]
        ),
        JoinRequestVerdict::Accepted
    );
    let _ = &mut laptop;
    let _ = &mut cy;
}

// ---------------------------------------------------------------------------
// An ex-member and a lying head cannot move the group
// ---------------------------------------------------------------------------

#[test]
fn an_ex_member_and_a_lying_head_move_the_group_only_loudly() {
    let server = issuer();
    let (_ada, mut bo, mut eve) = ada_bo_and_removed_eve(&server);

    // Eve founds her own group under the real id and seats Bo from a key
    // package any signed-in account may fetch.
    eve.forget_group(GROUP).unwrap();
    eve.create_group(GROUP).unwrap();
    past_the_mark(&mut eve, GROUP);
    let bundle = eve
        .add_member(GROUP, &bo.generate_key_package().unwrap())
        .unwrap();
    eve.merge_pending_commit(GROUP).unwrap();

    // Bo holds the real group, so the Welcome is contested...
    assert!(matches!(
        bo.join_from_welcome(&bundle.welcome.unwrap()),
        Err(Error::AlreadyAMember)
    ));
    assert_eq!(bo.contested_welcome_group_id().as_deref(), Some(GROUP));

    // ...and the server reports Eve's group as the head. Bo cannot tell it
    // from the real group by anything he held: it is taken, and drawn as
    // Eve's, with Ada gone. The real group, whose head the server moved,
    // finds itself forked and asks back in.
    let (head_epoch, head_verifier) = head_of(&eve, GROUP);
    assert_eq!(
        bo.join_contested_welcome(head_epoch, &head_verifier)
            .unwrap(),
        GROUP
    );
    assert_eq!(
        bo.take_rejoin_report(GROUP).unwrap(),
        Some(RejoinReport {
            readded_by: "actor-eve".into(),
            readded_by_device: "device-eve".into(),
            added_actors: vec!["actor-eve".into()],
            departed_actors: vec!["actor-ada".into()],
            ..Default::default()
        })
    );
}

#[test]
fn a_credential_naming_a_member_under_another_account_key_is_somebody_else() {
    let server = issuer();
    let (mut ada, _bo, _eve) = ada_bo_and_removed_eve(&server);
    ada.forget_group(GROUP).unwrap();

    // The delivery service issues device credentials, so it can mint one
    // that says "actor-bo". It cannot sign under Bo's account key.
    let seed = device_seed(0x66);
    let (_, public) = device_key_pair(&seed);
    let not_bos_key = TestIssuer::test_account_key("actor-mallory");
    let token = server
        .issue_for_account(
            "actor-bo",
            "device-bo-forged",
            &public,
            Some(&not_bos_key),
            NOW - HOUR,
            NOW + 30 * DAY,
        )
        .unwrap();
    // The server's device holds the key the server made.
    let mut config = ClientConfig::new(token, seed, server.trusted_keys().unwrap())
        .with_storage(PeachyStorage::in_memory())
        .with_own_account_identity(Some(
            peachy_mls_core::account_identity_public_key(&not_bos_key).unwrap(),
        ));
    config.clock = Some(Box::new(FixedClock(NOW)));
    let mut forged_bo = Client::new(config).unwrap();

    forged_bo.create_group(GROUP).unwrap();
    past_the_mark(&mut forged_bo, GROUP);
    let bundle = forged_bo
        .add_member(GROUP, &ada.generate_key_package().unwrap())
        .unwrap();
    forged_bo.merge_pending_commit(GROUP).unwrap();
    // Taken, and drawn as one "Bo" gone and another added.
    assert_eq!(
        ada.join_from_welcome(&bundle.welcome.unwrap()).unwrap(),
        GROUP
    );
    let report = ada.take_rejoin_report(GROUP).unwrap().expect("a report");
    assert_eq!(report.readded_by, "actor-bo");
    assert_eq!(report.readded_by_device, "device-bo-forged");
    assert_eq!(report.added_actors, vec!["actor-bo"]);
    assert_eq!(report.departed_actors, vec!["actor-bo"]);
}

#[test]
fn a_rejoin_says_who_re_added_this_device_and_who_came_in_meanwhile() {
    let server = issuer();
    let (mut ada, mut bo, _eve) = ada_bo_and_removed_eve(&server);
    let mut cy = client(&server, 5, "actor-cy", "device-cy");

    // Ada's copy forks; she forgets it to rejoin. While she is away Bo adds Cy.
    ada.forget_group(GROUP).unwrap();
    add(&mut bo, &mut cy, GROUP);

    // Bo answers her seat ask.
    let leaf = bo.leaf_of_device(GROUP, "device-ada").unwrap();
    let bundle = bo
        .replace_member(GROUP, leaf, &ada.generate_key_package().unwrap())
        .unwrap();
    bo.merge_pending_commit(GROUP).unwrap();
    cy.process_commit(GROUP, &bundle.commit).unwrap();
    ada.join_from_welcome(&bundle.welcome.unwrap()).unwrap();

    let report = RejoinReport {
        readded_by: "actor-bo".into(),
        readded_by_device: "device-bo".into(),
        readded_by_untrusted: false,
        added_actors: vec!["actor-cy".into()],
        ..Default::default()
    };
    assert_eq!(ada.take_rejoin_report(GROUP).unwrap(), Some(report));
    // Told once.
    assert_eq!(ada.take_rejoin_report(GROUP).unwrap(), None);
    assert!(reads(&mut cy, &mut ada, GROUP, b"hi ada"));
}

#[test]
fn a_person_who_left_on_purpose_takes_a_later_welcome_as_a_new_invitation() {
    let server = issuer();
    let (mut ada, mut bo, mut eve) = ada_bo_and_removed_eve(&server);
    let mut cy = client(&server, 5, "actor-cy", "device-cy");

    // Bo leaves: his device forgets the group and drops the roster it kept.
    bo.forget_group(GROUP).unwrap();
    bo.forget_remembered_roster(GROUP).unwrap();
    // His leaf is evicted as a leaver's is, and Cy joins.
    let leaf = ada.leaf_of_device(GROUP, "device-bo").unwrap();
    ada.remove_leaf(GROUP, leaf).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    add(&mut ada, &mut cy, GROUP);

    // Cy, who joined after Bo left, adds him back. No claim, no judgement,
    // nothing to report: it is an invitation from Cy.
    let bundle = cy
        .add_member(GROUP, &bo.generate_key_package().unwrap())
        .unwrap();
    cy.merge_pending_commit(GROUP).unwrap();
    ada.process_commit(GROUP, &bundle.commit).unwrap();
    assert_eq!(
        bo.join_from_welcome(&bundle.welcome.unwrap()).unwrap(),
        GROUP
    );
    assert_eq!(
        bo.welcome_sender(GROUP).unwrap().as_deref(),
        Some("actor-cy")
    );
    assert!(bo.take_rejoin_report(GROUP).unwrap().is_none());
    let _ = &mut eve;
}

#[test]
fn a_device_removed_alone_is_taken_back_by_the_group_it_knew() {
    // A commit removed Ada's laptop while her phone stays: the laptop keeps
    // its inactive copy and asks back in without forgetting
    // (docs/delivery.md §Rejoin with a sealed seat ask). Eve, removed
    // earlier, answers that ask with a group of her own: drawn as hers.
    let server = issuer();
    let (mut ada, mut bo, mut eve) = ada_bo_and_removed_eve(&server);
    let mut laptop = client(&server, 4, "actor-ada", "device-ada-laptop");
    // The phone let the laptop in: it is on the laptop's approval chain.
    laptop
        .remember_own_approver("device-ada", &device_key_pair(&device_seed(1)).1)
        .unwrap();
    let commit = add(&mut ada, &mut laptop, GROUP);
    bo.process_commit(GROUP, &commit).unwrap();
    let leaf = bo.leaf_of_device(GROUP, "device-ada-laptop").unwrap();
    let removal = bo.remove_leaf(GROUP, leaf).unwrap();
    bo.merge_pending_commit(GROUP).unwrap();
    ada.process_commit(GROUP, &removal.commit).unwrap();
    laptop.process_commit(GROUP, &removal.commit).unwrap();
    assert!(!laptop.is_active(GROUP).unwrap());

    eve.forget_group(GROUP).unwrap();
    eve.create_group(GROUP).unwrap();
    past_the_mark(&mut eve, GROUP);
    let bundle = eve
        .add_member(GROUP, &laptop.generate_key_package().unwrap())
        .unwrap();
    eve.merge_pending_commit(GROUP).unwrap();
    assert_eq!(
        laptop.join_from_welcome(&bundle.welcome.unwrap()).unwrap(),
        GROUP
    );
    let report = laptop.take_rejoin_report(GROUP).unwrap().expect("a report");
    assert_eq!(report.readded_by, "actor-eve");
    assert_eq!(report.departed_actors, vec!["actor-bo"]);

    // Her own phone, on the laptop's chain, re-seats it at the real head.
    let bundle = ada
        .add_member(GROUP, &laptop.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    bo.process_commit(GROUP, &bundle.commit).unwrap();
    assert_eq!(
        support::join_at_head(&mut laptop, &bundle.welcome.unwrap(), head_of(&ada, GROUP)).unwrap(),
        GROUP
    );
    let report = laptop.take_rejoin_report(GROUP).unwrap().expect("a report");
    assert_eq!(report.readded_by_device, "device-ada");
    assert!(!report.readded_by_untrusted, "{report:?}");
    assert!(reads(&mut bo, &mut laptop, GROUP, b"laptop's back"));
}

#[test]
fn a_member_removed_with_their_person_takes_a_later_welcome_as_a_new_invitation() {
    // Eve's removal was real: her inactive copy is no claim on the group, and
    // whoever adds her later is simply inviting her.
    let server = issuer();
    let (mut ada, mut bo, mut eve) = ada_bo_and_removed_eve(&server);
    let mut cy = client(&server, 5, "actor-cy", "device-cy");
    let commit = add(&mut ada, &mut cy, GROUP);
    bo.process_commit(GROUP, &commit).unwrap();
    let bundle = cy
        .add_member(GROUP, &eve.generate_key_package().unwrap())
        .unwrap();
    cy.merge_pending_commit(GROUP).unwrap();
    assert_eq!(
        eve.join_from_welcome(&bundle.welcome.unwrap()).unwrap(),
        GROUP
    );
    assert!(eve.take_rejoin_report(GROUP).unwrap().is_none());
}

#[test]
fn the_kept_roster_survives_a_restart() {
    let server = issuer();
    let kv = peachy_mls_core::MemoryKv::new();
    let mut ada = support::client_on(
        &server,
        1,
        "actor-ada",
        "device-ada",
        PeachyStorage::open(Box::new(kv.clone())).unwrap(),
    );
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    let mut eve = client(&server, 3, "actor-eve", "device-eve");
    ada.create_group(GROUP).unwrap();
    add(&mut ada, &mut bo, GROUP);
    ada.forget_group(GROUP).unwrap();
    drop(ada);

    let mut ada = support::client_on(
        &server,
        1,
        "actor-ada",
        "device-ada",
        PeachyStorage::open(Box::new(kv)).unwrap(),
    );
    eve.create_group(GROUP).unwrap();
    past_the_mark(&mut eve, GROUP);
    let bundle = eve
        .add_member(GROUP, &ada.generate_key_package().unwrap())
        .unwrap();
    eve.merge_pending_commit(GROUP).unwrap();
    assert_eq!(
        ada.join_from_welcome(&bundle.welcome.unwrap()).unwrap(),
        GROUP
    );
    let report = ada
        .take_rejoin_report(GROUP)
        .unwrap()
        .expect("drawn, not new");
    assert_eq!(report.readded_by, "actor-eve");
    assert_eq!(report.departed_actors, vec!["actor-bo"]);
}

#[test]
fn a_rejoin_by_somebody_added_while_this_device_was_away_is_taken_and_named() {
    // A Welcome from outside the kept roster is taken, and the report names
    // who sent it and who it brought, so the conversation says so.
    let server = issuer();
    let (mut ada, mut bo, mut eve) = ada_bo_and_removed_eve(&server);
    let mut cy = client(&server, 5, "actor-cy", "device-cy");
    ada.forget_group(GROUP).unwrap();
    add(&mut bo, &mut cy, GROUP);
    // Cy, who joined while Ada was away, re-seats her: taken.
    let leaf = cy.leaf_of_device(GROUP, "device-ada").unwrap();
    let bundle = cy
        .replace_member(GROUP, leaf, &ada.generate_key_package().unwrap())
        .unwrap();
    cy.merge_pending_commit(GROUP).unwrap();
    bo.process_commit(GROUP, &bundle.commit).unwrap();
    assert_eq!(
        ada.join_from_welcome(&bundle.welcome.unwrap()).unwrap(),
        GROUP
    );
    assert_eq!(
        ada.take_rejoin_report(GROUP).unwrap(),
        Some(RejoinReport {
            readded_by: "actor-cy".into(),
            readded_by_device: "device-cy".into(),
            readded_by_untrusted: false,
            added_actors: vec!["actor-cy".into()],
            ..Default::default()
        })
    );
    assert!(reads(&mut bo, &mut ada, GROUP, b"back"));

    // Even Eve's impostor group is taken, and drawn by her name.
    ada.forget_group(GROUP).unwrap();
    eve.forget_group(GROUP).unwrap();
    eve.create_group(GROUP).unwrap();
    past_the_mark(&mut eve, GROUP);
    let bundle = eve
        .add_member(GROUP, &ada.generate_key_package().unwrap())
        .unwrap();
    eve.merge_pending_commit(GROUP).unwrap();
    assert_eq!(
        ada.join_from_welcome(&bundle.welcome.unwrap()).unwrap(),
        GROUP
    );
    let report = ada.take_rejoin_report(GROUP).unwrap().unwrap();
    assert_eq!(report.readded_by, "actor-eve");
    assert!(!report.readded_by_untrusted);
}
