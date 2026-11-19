// SPDX-License-Identifier: MIT
//! One person, one account key, at the group layer
//! (`peachy_mls_core::policy::judge_account_keys`; docs/identity.md
//! §One account key per person).
//!
//! The server certifies devices. It cannot make an account certificate under
//! a person's real account identity key, but it can make a key of its own and
//! certify a device of its own under that key and the person's actor id. A
//! device pins no key for its own actor, so before this rule the person's own
//! devices seated such a device in their groups when handed its key package,
//! and nothing told them. Each test here was an attack that worked; each now
//! proves the commit is refused by whoever would build or merge it.
//!
//! And a reseat is the same seat (`peachy_mls_core::policy`, the reseat rule):
//! a member who may not remove somebody cannot take that person's leaf out
//! and put another device, or a device under another key, in its place in one
//! commit.

#![cfg(feature = "test-forgery")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use peachy_mls_core::issuer::{device_key_pair, TestIssuer};
use peachy_mls_core::{
    account_identity_public_key, Client, ClientConfig, DenyReason, Error, FixedClock, Incoming,
    PeachyStorage,
};
use support::{client, device_seed, head_of, issuer, DAY, HOUR, NOW};

const GROUP: &[u8] = b"22222222-2222-4222-8222-222222222222";
const NOTE_TO_SELF: &[u8] = b"peachy-account-key-binding-self";

/// An account key the server made: not the one `client` certifies under.
const SERVERS_ACCOUNT_KEY: [u8; 32] = [0x99; 32];

fn client_for_account(
    server: &TestIssuer,
    tag: u8,
    actor: &str,
    device: &str,
    account: &[u8],
) -> Client {
    let seed = device_seed(tag);
    let (_, public) = device_key_pair(&seed);
    let token = server
        .issue_for_account(
            actor,
            device,
            &public,
            Some(account),
            NOW - HOUR,
            NOW + 30 * DAY,
        )
        .expect("mint");
    // The device holds the account key it is certified under: the server's
    // own device holds the key the server made.
    let mut config = ClientConfig::new(token, seed, server.trusted_keys().expect("keys"))
        .with_storage(PeachyStorage::in_memory())
        .with_own_account_identity(Some(account_identity_public_key(account).expect("derive")));
    config.clock = Some(Box::new(FixedClock(NOW)));
    Client::new(config).expect("client")
}

fn ghost_of(server: &TestIssuer, actor: &str) -> Client {
    client_for_account(server, 9, actor, "device-ghost", &SERVERS_ACCOUNT_KEY)
}

fn add(adder: &mut Client, joiner: &mut Client, group: &[u8]) -> Vec<u8> {
    let key_package = joiner.generate_key_package().expect("key package");
    let bundle = adder.add_member(group, &key_package).expect("add");
    adder.merge_pending_commit(group).expect("merge");
    joiner
        .join_from_welcome(&bundle.welcome.expect("welcome"))
        .expect("join");
    bundle.commit
}

fn refused<T: std::fmt::Debug>(result: Result<T, Error>) -> DenyReason {
    match result {
        Err(Error::PolicyRefused(reason)) => reason,
        other => panic!("expected a policy refusal, got {other:?}"),
    }
}

/// Ada (phone) and Bo, in a two-person group with no policy.
fn ada_and_bo(server: &TestIssuer) -> (Client, Client) {
    let mut ada = client(server, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(server, 2, "actor-bo", "device-bo-phone");
    ada.create_group(GROUP).unwrap();
    add(&mut ada, &mut bo, GROUP);
    (ada, bo)
}

#[test]
fn a_persons_own_device_refuses_to_seat_a_device_under_another_account_key() {
    let server = issuer();
    let (mut ada, mut bo) = ada_and_bo(&server);
    let ghost = ghost_of(&server, "actor-ada");
    let key_package = ghost.generate_key_package().unwrap();

    assert_eq!(
        refused(ada.add_member(GROUP, &key_package)),
        DenyReason::AccountKeyConflict
    );
    assert!(
        !ada.has_pending_commit(GROUP).unwrap(),
        "nothing is left staged"
    );
    // So is the person's peer, handed the same package.
    assert_eq!(
        refused(bo.add_member(GROUP, &key_package)),
        DenyReason::AccountKeyConflict
    );
    assert!(!bo.has_pending_commit(GROUP).unwrap());

    // A real second device of Ada's is still seated as ever.
    let mut laptop = client(&server, 3, "actor-ada", "device-ada-laptop");
    add(&mut ada, &mut laptop, GROUP);
}

#[test]
fn every_member_refuses_a_commit_that_seats_one() {
    // A modified client builds the commit anyway: the person's own device
    // and their peer each refuse to merge it.
    let server = issuer();
    let (mut ada, mut bo) = ada_and_bo(&server);
    let mut cy = client(&server, 4, "actor-cy", "device-cy-phone");
    let commit = add(&mut ada, &mut cy, GROUP);
    bo.process_commit(GROUP, &commit).unwrap();
    let ghost = ghost_of(&server, "actor-ada");
    let key_package = ghost.generate_key_package().unwrap();

    let forged = cy.forge_commit(GROUP, &[], &[&key_package]).unwrap();
    assert_eq!(
        refused(ada.process_commit(GROUP, &forged.commit)),
        DenyReason::AccountKeyConflict
    );
    assert_eq!(
        refused(bo.process_commit(GROUP, &forged.commit)),
        DenyReason::AccountKeyConflict
    );
}

#[test]
fn a_note_to_self_does_not_seat_one() {
    let server = issuer();
    let mut phone = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut laptop = client(&server, 3, "actor-ada", "device-ada-laptop");
    phone.create_group(NOTE_TO_SELF).unwrap();
    add(&mut phone, &mut laptop, NOTE_TO_SELF);
    let ghost = ghost_of(&server, "actor-ada");
    let key_package = ghost.generate_key_package().unwrap();

    assert_eq!(
        refused(phone.add_member(NOTE_TO_SELF, &key_package)),
        DenyReason::AccountKeyConflict
    );
    let forged = phone
        .forge_commit(NOTE_TO_SELF, &[], &[&key_package])
        .unwrap();
    assert_eq!(
        refused(laptop.process_commit(NOTE_TO_SELF, &forged.commit)),
        DenyReason::AccountKeyConflict
    );
}

#[test]
fn the_person_refuses_being_swapped_out_for_one() {
    // A commit that removes Ada's only leaf and seats the server's device of
    // Ada leaves no leaf of hers to compare with. Ada's device refuses it on
    // its own key, so it does not go quietly: it stays at the old epoch and
    // asks back in. A peer in a group with no policy accepts it, as a group
    // with no policy accepts any change, and is told Ada's security code
    // changed.
    let server = issuer();
    let (mut ada, mut bo) = ada_and_bo(&server);
    let mut cy = client(&server, 4, "actor-cy", "device-cy-phone");
    let commit = add(&mut ada, &mut cy, GROUP);
    bo.process_commit(GROUP, &commit).unwrap();
    assert!(cy.observe_account_keys(GROUP).unwrap().is_empty());

    let ghost = ghost_of(&server, "actor-ada");
    let key_package = ghost.generate_key_package().unwrap();
    let ada_leaf = bo.leaf_of_device(GROUP, "device-ada-phone").unwrap();
    let forged = bo
        .forge_commit(GROUP, &[ada_leaf], &[&key_package])
        .unwrap();
    assert_eq!(
        refused(ada.process_commit(GROUP, &forged.commit)),
        DenyReason::AccountKeyConflict
    );
    assert!(ada.is_active(GROUP).unwrap());
    assert!(matches!(
        cy.process_commit(GROUP, &forged.commit).unwrap(),
        Incoming::Commit(_)
    ));
    assert_eq!(
        cy.observe_account_keys(GROUP).unwrap(),
        vec!["actor-ada".to_owned()]
    );
}

#[test]
fn a_welcome_into_a_tree_holding_one_is_refused() {
    let server = issuer();
    let (_ada, mut bo) = ada_and_bo(&server);
    // Bo, modified, seats the server's device of Ada, then Ada's laptop.
    let ghost = ghost_of(&server, "actor-ada");
    let ghost_package = ghost.generate_key_package().unwrap();
    bo.forge_commit(GROUP, &[], &[&ghost_package]).unwrap();
    bo.merge_pending_commit(GROUP).unwrap();
    let mut laptop = client(&server, 3, "actor-ada", "device-ada-laptop");
    let laptop_package = laptop.generate_key_package().unwrap();
    assert_eq!(
        refused(bo.add_member(GROUP, &laptop_package)),
        DenyReason::AccountKeyConflict,
        "an honest committer refuses to add beside a conflict it would be judged by"
    );
    let forged = bo.forge_commit(GROUP, &[], &[&laptop_package]).unwrap();
    assert_eq!(
        refused(laptop.join_from_welcome(&forged.welcome.unwrap())),
        DenyReason::AccountKeyConflict
    );
}

#[test]
fn a_welcome_seating_one_beside_the_person_is_refused_by_anybody() {
    // A member's group of her own under the real group's id keeps everyone,
    // the real Ada included, and seats the server's device of Ada BESIDE
    // her: no commit could, and no Welcome may. Yara, with roster
    // enforcement on, is handed it at the head the member's commit names,
    // and refuses it as a commit would be refused, whoever signed it.
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut mal = client(&server, 3, "actor-mal", "device-mal-phone");
    let mut yara = client(&server, 4, "actor-yara", "device-yara-phone");
    let mut mal2 = client(&server, 5, "actor-mal", "device-mal-laptop");
    let ghost = ghost_of(&server, "actor-ada");
    ada.create_group(GROUP).unwrap();
    add(&mut ada, &mut mal, GROUP);
    let bundle = ada
        .add_member(GROUP, &yara.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    mal.process_commit(GROUP, &bundle.commit).unwrap();
    let (h, v) = head_of(&ada, GROUP);
    yara.join_from_welcome_at_head(&bundle.welcome.unwrap(), h, &v)
        .unwrap();
    assert!(yara.confirm_head(GROUP, h, &v).unwrap());

    // Mallory's modified client seats Ada's real key package and the
    // server's device of Ada, brings the group to the head's epoch, and
    // adds Yara.
    mal2.create_group(GROUP).unwrap();
    mal2.add_member(GROUP, &ada.generate_key_package().unwrap())
        .unwrap();
    mal2.merge_pending_commit(GROUP).unwrap();
    mal2.forge_commit(GROUP, &[], &[&ghost.generate_key_package().unwrap()])
        .unwrap();
    mal2.merge_pending_commit(GROUP).unwrap();
    while mal2.epoch(GROUP).unwrap() < h {
        mal2.self_update(GROUP).unwrap();
        mal2.merge_pending_commit(GROUP).unwrap();
    }
    let add_yara = mal2
        .add_member(GROUP, &yara.generate_key_package().unwrap())
        .unwrap();
    mal2.merge_pending_commit(GROUP).unwrap();
    let (head, verifier) = head_of(&mal2, GROUP);
    assert_eq!(head, h + 1);

    assert_eq!(
        refused(yara.join_from_welcome_at_head(&add_yara.welcome.unwrap(), head, &verifier)),
        DenyReason::AccountKeyConflict
    );
    assert_eq!(yara.epoch(GROUP).unwrap(), h, "still in the real group");
    let wire = yara.encrypt(GROUP, b"meet at 8").unwrap();
    assert!(matches!(
        ada.process_message(GROUP, &wire),
        Ok(Incoming::Application { .. })
    ));
}

#[test]
fn an_account_started_over_is_seated_once_its_old_leaves_are_gone() {
    // ClaimSoleDevice: the person's new device carries a new account key.
    // While a leaf under the old key is seated, adding the new device is
    // refused; once the old leaf is removed, it is an ordinary add, and the
    // peer is told the person's security code changed.
    let server = issuer();
    let (mut ada, mut bo) = ada_and_bo(&server);
    assert!(bo.observe_account_keys(GROUP).unwrap().is_empty());
    let mut fresh = client_for_account(&server, 5, "actor-ada", "device-ada-new", &[0x77; 32]);
    let key_package = fresh.generate_key_package().unwrap();
    assert_eq!(
        refused(bo.add_member(GROUP, &key_package)),
        DenyReason::AccountKeyConflict
    );

    let old_leaf = bo.leaf_of_device(GROUP, "device-ada-phone").unwrap();
    let removal = bo.remove_leaf(GROUP, old_leaf).unwrap();
    bo.merge_pending_commit(GROUP).unwrap();
    match ada.process_commit(GROUP, &removal.commit).unwrap() {
        Incoming::Commit(outcome) => assert!(outcome.removed_self),
        other => panic!("{other:?}"),
    }
    let bundle = bo.add_member(GROUP, &key_package).unwrap();
    bo.merge_pending_commit(GROUP).unwrap();
    fresh.join_from_welcome(&bundle.welcome.unwrap()).unwrap();
    assert_eq!(
        bo.observe_account_keys(GROUP).unwrap(),
        vec!["actor-ada".to_owned()]
    );
}

/// Ada (admin), Bo and Cy in a group where only admins add and remove.
fn admin_group(server: &TestIssuer) -> [Client; 3] {
    let mut ada = client(server, 1, "actor-ada", "device-ada");
    let mut bo = client(server, 2, "actor-bo", "device-bo");
    let mut cy = client(server, 3, "actor-cy", "device-cy");
    ada.create_group(GROUP).unwrap();
    ada.set_group_meta(
        GROUP,
        br#"{"v":1,"n":"Walk","adm":["actor-ada"],"pol":{"add":"adm","rm":"adm"}}"#,
    )
    .unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    add(&mut ada, &mut bo, GROUP);
    let commit = add(&mut ada, &mut cy, GROUP);
    bo.process_commit(GROUP, &commit).unwrap();
    [ada, bo, cy]
}

#[test]
fn a_member_cannot_swap_an_admins_device_for_one_of_the_servers() {
    let server = issuer();
    let [mut ada, mut bo, mut cy] = admin_group(&server);
    let ghost = ghost_of(&server, "actor-ada");
    let key_package = ghost.generate_key_package().unwrap();
    let ada_leaf = bo.leaf_of_device(GROUP, "device-ada").unwrap();
    let forged = bo
        .forge_commit(GROUP, &[ada_leaf], &[&key_package])
        .unwrap();
    // Not a reseat: another device, under another key. Both halves are
    // judged on their own, and adding here takes an admin, which Bo is not.
    assert_eq!(
        refused(cy.process_commit(GROUP, &forged.commit)),
        DenyReason::AddNeedsAdmin
    );
    assert!(ada.process_commit(GROUP, &forged.commit).is_err());
    assert!(cy.is_active(GROUP).unwrap());
    assert!(ada.is_active(GROUP).unwrap());
}

#[test]
fn a_member_cannot_swap_somebodys_device_for_another_of_theirs() {
    let server = issuer();
    let [mut ada, mut bo, mut cy] = admin_group(&server);
    let cy_laptop = client(&server, 4, "actor-cy", "device-cy-laptop");
    let key_package = cy_laptop.generate_key_package().unwrap();
    let cy_leaf = bo.leaf_of_device(GROUP, "device-cy").unwrap();
    assert!(bo.replace_member(GROUP, cy_leaf, &key_package).is_err());
    let forged = bo.forge_commit(GROUP, &[cy_leaf], &[&key_package]).unwrap();
    assert!(matches!(
        cy.process_commit(GROUP, &forged.commit),
        Err(Error::PolicyRefused(_))
    ));
    assert!(matches!(
        ada.process_commit(GROUP, &forged.commit),
        Err(Error::PolicyRefused(_))
    ));
    assert!(cy.is_active(GROUP).unwrap());
}

#[test]
fn a_member_still_reseats_somebodys_own_device() {
    // The rejoin a reseat exists for: the same device, back in its own seat,
    // by a member who is no admin.
    let server = issuer();
    let [mut ada, mut bo, mut cy] = admin_group(&server);
    cy.forget_group(GROUP).unwrap();
    let key_package = cy.generate_key_package().unwrap();
    let cy_leaf = bo.leaf_of_device(GROUP, "device-cy").unwrap();
    let bundle = bo.replace_member(GROUP, cy_leaf, &key_package).unwrap();
    bo.merge_pending_commit(GROUP).unwrap();
    assert!(matches!(
        ada.process_commit(GROUP, &bundle.commit).unwrap(),
        Incoming::Commit(_)
    ));
    cy.join_from_welcome(&bundle.welcome.unwrap()).unwrap();
}
