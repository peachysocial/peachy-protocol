// SPDX-License-Identifier: MIT
//! The account identity key at the group layer, per
//! docs/identity.md §The account identity key: a device its account
//! never let in is refused by every peer, the account key survives a renewal, and a peer notices when an
//! account's key changes.
//!
//! The pure halves — derivation, signing, verifying and the credential verdicts
//! — are pinned by `mls/fixtures/device-link.json` and
//! `mls/fixtures/credentials.json`; this file is about what a `Client` does
//! with them.

#![cfg(feature = "test-forgery")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use peachy_mls_core::issuer::{device_key_pair, TestIssuer};
use peachy_mls_core::{
    account_identity_public_key, Client, ClientConfig, CredentialRejection, DenyReason, Error,
    FixedClock, KvStore, MemoryKv, PeachyStorage,
};
use support::{client, device_seed, issuer, DAY, HOUR, NOW};

const GROUP: &[u8] = b"peachy-account-identity";
const OTHER_GROUP: &[u8] = b"peachy-account-identity-2";

fn rejection<T: std::fmt::Debug>(result: Result<T, Error>) -> CredentialRejection {
    match result {
        Err(Error::CredentialRejected(reason)) => reason,
        other => panic!("expected a credential rejection, got {other:?}"),
    }
}

/// A client whose credential carries the account certificate `account` signs,
/// or none at all. A certified device holds the account key it is certified
/// under; an uncertified one holds none.
fn client_for_account(
    server: &TestIssuer,
    tag: u8,
    actor: &str,
    device: &str,
    account: Option<&[u8]>,
    storage: PeachyStorage,
) -> Client {
    client_issued(server, tag, actor, device, account, storage, NOW - HOUR)
}

/// [`client_for_account`], its credential issued at `issued_at`.
fn client_issued(
    server: &TestIssuer,
    tag: u8,
    actor: &str,
    device: &str,
    account: Option<&[u8]>,
    storage: PeachyStorage,
    issued_at: i64,
) -> Client {
    let seed = device_seed(tag);
    let (_, public) = device_key_pair(&seed);
    let token = server
        .issue_for_account(
            actor,
            device,
            &public,
            account,
            issued_at,
            issued_at + 30 * DAY,
        )
        .expect("mint");
    let held = account.map(|account| account_identity_public_key(account).expect("derive"));
    let mut config = ClientConfig::new(token, seed, server.trusted_keys().expect("keys"))
        .with_storage(storage)
        .with_own_account_identity(held);
    // A device whose credential is dated ahead runs on a clock that agrees
    // with it: what a server minting it could give that device.
    config.clock = Some(Box::new(FixedClock(NOW.max(issued_at + HOUR))));
    Client::new(config).expect("a device's own client opens with or without a certificate")
}

fn add(adder: &mut Client, joiner: &mut Client, group: &[u8]) {
    let key_package = joiner.generate_key_package().expect("key package");
    let bundle = adder.add_member(group, &key_package).expect("add");
    adder.merge_pending_commit(group).expect("merge");
    joiner
        .join_from_welcome(&bundle.welcome.expect("welcome"))
        .expect("join");
}

#[test]
fn a_device_its_account_never_let_in_opens_but_joins_nothing() {
    let server = issuer();
    let mut waiting = client_for_account(
        &server,
        1,
        "actor-ada",
        "device-ada-laptop",
        None,
        PeachyStorage::in_memory(),
    );
    assert_eq!(waiting.identity().account_key, None);

    // It cannot found a group or publish a key package: every peer would
    // refuse the leaf, so both are refused here first.
    assert_eq!(
        rejection(waiting.generate_key_package()),
        CredentialRejection::NotApproved
    );
    assert_eq!(
        rejection(waiting.create_group(GROUP)),
        CredentialRejection::NotApproved
    );

    // And a package forged anyway — the device a server adds on its own — is
    // refused by the adder, whose group is left exactly as it was.
    let forged = waiting.forge_unapproved_key_package().expect("forge");
    let mut bo = client(&server, 2, "actor-bo", "device-bo-phone");
    bo.create_group(GROUP).expect("create");
    assert_eq!(
        bo.key_package_identity(&forged)
            .expect("reads")
            .unwrap_err(),
        CredentialRejection::NotApproved
    );
    assert_eq!(
        rejection(bo.add_member(GROUP, &forged)),
        CredentialRejection::NotApproved
    );
    assert!(!bo.has_pending_commit(GROUP).expect("pending"));
    assert_eq!(bo.roster(GROUP).expect("roster").len(), 1);
}

#[test]
fn the_approval_arrives_once_and_then_never_changes() {
    let server = issuer();
    let account = TestIssuer::test_account_key("actor-ada");
    let seed = device_seed(1);
    let (_, public) = device_key_pair(&seed);
    let mut laptop = client_for_account(
        &server,
        1,
        "actor-ada",
        "device-ada-laptop",
        None,
        PeachyStorage::in_memory(),
    );

    // From none to Ada's account: the approval.
    let approved = server
        .issue_for_account(
            "actor-ada",
            "device-ada-laptop",
            &public,
            Some(&account),
            NOW,
            NOW + 30 * DAY,
        )
        .expect("mint");
    // Installed naming the key that has just arrived, as every client does.
    laptop
        .update_credential(
            &approved,
            Some(account_identity_public_key(&account).expect("derive")),
        )
        .expect("approved");
    assert!(laptop.identity().account_key.is_some());
    laptop.generate_key_package().expect("now it can publish");

    // From Ada's account to another: refused (under a key the device does not
    // hold), and the client keeps what it had.
    let other = server
        .issue_for_account(
            "actor-ada",
            "device-ada-laptop",
            &public,
            Some(&[0xa2; 32]),
            NOW,
            NOW + 30 * DAY,
        )
        .expect("mint");
    assert_eq!(
        rejection(laptop.update_credential(&other, None)),
        CredentialRejection::NotOwnAccountKey
    );
    // And back to none: refused too.
    let none = server
        .issue_for_account(
            "actor-ada",
            "device-ada-laptop",
            &public,
            None,
            NOW,
            NOW + 30 * DAY,
        )
        .expect("mint");
    assert!(matches!(
        laptop.update_credential(&none, None),
        Err(Error::PolicyRefused(DenyReason::UpdateOfAnotherLeaf))
    ));
}

#[test]
fn a_peer_pins_an_account_key_and_notices_it_change_once_per_conversation() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(&server, 2, "actor-bo", "device-bo-phone");
    ada.create_group(GROUP).expect("create");
    ada.create_group(OTHER_GROUP).expect("create");
    add(&mut ada, &mut bo, GROUP);
    add(&mut ada, &mut bo, OTHER_GROUP);

    // First sight is trust on first use, in silence; so is seeing it again.
    assert!(ada.observe_account_keys(GROUP).expect("observe").is_empty());
    assert!(ada
        .observe_account_keys(OTHER_GROUP)
        .expect("observe")
        .is_empty());
    assert!(ada.observe_account_keys(GROUP).expect("observe").is_empty());
    // Bo sees Ada; his own account is never reported to himself.
    assert!(bo.observe_account_keys(GROUP).expect("observe").is_empty());

    // Bo loses every device and comes back under a new account key. His old
    // leaf goes, his new device comes in.
    let mut bo_again = client_issued(
        &server,
        3,
        "actor-bo",
        "device-bo-new-phone",
        Some(&[0xb1; 32]),
        PeachyStorage::in_memory(),
        NOW - 60,
    );
    for group in [GROUP, OTHER_GROUP] {
        let old = ada
            .leaf_of_device(group, "device-bo-phone")
            .expect("bo's old leaf");
        ada.remove_leaf(group, old).expect("remove");
        ada.merge_pending_commit(group).expect("merge");
        add(&mut ada, &mut bo_again, group);
    }

    // Each conversation says so once, and only once.
    assert_eq!(
        ada.observe_account_keys(GROUP).expect("observe"),
        vec!["actor-bo".to_string()]
    );
    assert!(ada.observe_account_keys(GROUP).expect("observe").is_empty());
    assert_eq!(
        ada.observe_account_keys(OTHER_GROUP).expect("observe"),
        vec!["actor-bo".to_string()]
    );
    assert!(ada
        .observe_account_keys(OTHER_GROUP)
        .expect("observe")
        .is_empty());
}

#[test]
fn a_pin_outlives_the_client_that_made_it() {
    let server = issuer();
    let kv = MemoryKv::new();
    let shared = || PeachyStorage::open(Box::new(kv.clone())).expect("open");
    let mut ada = client_for_account(
        &server,
        1,
        "actor-ada",
        "device-ada-phone",
        Some(&TestIssuer::test_account_key("actor-ada")),
        shared(),
    );
    let mut bo = client(&server, 2, "actor-bo", "device-bo-phone");
    ada.create_group(GROUP).expect("create");
    add(&mut ada, &mut bo, GROUP);
    assert!(ada.observe_account_keys(GROUP).expect("observe").is_empty());
    drop(ada);

    // A new group with Bo under a different account key, seen by a reopened
    // client: the pin from before is what makes this a change and not a
    // first sight.
    let mut ada = client_for_account(
        &server,
        1,
        "actor-ada",
        "device-ada-phone",
        Some(&TestIssuer::test_account_key("actor-ada")),
        shared(),
    );
    let mut bo_again = client_for_account(
        &server,
        3,
        "actor-bo",
        "device-bo-new-phone",
        Some(&[0xb1; 32]),
        PeachyStorage::in_memory(),
    );
    ada.create_group(OTHER_GROUP).expect("create");
    add(&mut ada, &mut bo_again, OTHER_GROUP);
    assert_eq!(
        ada.observe_account_keys(OTHER_GROUP).expect("observe"),
        vec!["actor-bo".to_string()]
    );
}

#[test]
fn a_group_holding_two_keys_for_one_person_reports_the_new_one_once() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(&server, 2, "actor-bo", "device-bo-phone");
    ada.create_group(GROUP).expect("create");
    add(&mut ada, &mut bo, GROUP);
    assert!(ada.observe_account_keys(GROUP).expect("observe").is_empty());

    // A tree that shows two keys for Bo at once: his old leaf beside a new
    // device under a new account key. The one-key rule refuses this add
    // today; a tree from before the rule, or a forged commit, still holds it.
    let bo_again = client_issued(
        &server,
        3,
        "actor-bo",
        "device-bo-new-phone",
        Some(&[0xb1; 32]),
        PeachyStorage::in_memory(),
        NOW - 60,
    );
    let package = bo_again.generate_key_package().expect("key package");
    ada.forge_commit(GROUP, &[], &[&package]).expect("forge");
    ada.merge_pending_commit(GROUP).expect("merge");
    assert_eq!(ada.roster(GROUP).expect("roster").len(), 3);

    // The new key is reported once; reading the same tree again says nothing,
    // however often, and the pin stays on the new key.
    assert_eq!(
        ada.observe_account_keys(GROUP).expect("observe"),
        vec!["actor-bo".to_string()]
    );
    for _ in 0..3 {
        assert!(ada.observe_account_keys(GROUP).expect("observe").is_empty());
    }
    // So a conversation showing only the new key is first sight of the pin,
    // in silence.
    ada.create_group(OTHER_GROUP).expect("create");
    let mut bo_third = client_issued(
        &server,
        4,
        "actor-bo",
        "device-bo-tablet",
        Some(&[0xb1; 32]),
        PeachyStorage::in_memory(),
        NOW - 60,
    );
    add(&mut ada, &mut bo_third, OTHER_GROUP);
    assert!(ada
        .observe_account_keys(OTHER_GROUP)
        .expect("observe")
        .is_empty());

    // The old leaf going changes nothing to report.
    let old = ada
        .leaf_of_device(GROUP, "device-bo-phone")
        .expect("bo's old leaf");
    ada.remove_leaf(GROUP, old).expect("remove");
    ada.merge_pending_commit(GROUP).expect("merge");
    assert!(ada.observe_account_keys(GROUP).expect("observe").is_empty());
}

#[test]
fn a_replace_gives_a_seat_back_only_to_the_same_approved_device() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(&server, 2, "actor-bo", "device-bo-phone");
    ada.create_group(GROUP).expect("create");
    add(&mut ada, &mut bo, GROUP);
    let bo_leaf = ada.leaf_of_device(GROUP, "device-bo-phone").expect("leaf");

    // Bo's laptop, genuinely his and approved, is still not his phone.
    let laptop = client(&server, 3, "actor-bo", "device-bo-laptop");
    let refused = ada.replace_member(GROUP, bo_leaf, &laptop.generate_key_package().expect("kp"));
    assert!(
        matches!(refused, Err(Error::InvalidArgument(_))),
        "{refused:?}"
    );

    // Bo's phone under an account key that is not the one its seat carries.
    let rekeyed = client_for_account(
        &server,
        2,
        "actor-bo",
        "device-bo-phone",
        Some(&[0xb1; 32]),
        PeachyStorage::in_memory(),
    );
    let refused = ada.replace_member(GROUP, bo_leaf, &rekeyed.generate_key_package().expect("kp"));
    assert!(
        matches!(refused, Err(Error::InvalidArgument(_))),
        "{refused:?}"
    );

    // Bo's phone with no certificate at all: refused as an add would be.
    let bare = client_for_account(
        &server,
        2,
        "actor-bo",
        "device-bo-phone",
        None,
        PeachyStorage::in_memory(),
    );
    assert_eq!(
        rejection(ada.replace_member(
            GROUP,
            bo_leaf,
            &bare.forge_unapproved_key_package().expect("forge"),
        )),
        CredentialRejection::NotApproved
    );
    assert!(!ada.has_pending_commit(GROUP).expect("pending"));

    // The phone itself, as it is: the repair goes through.
    let again = client(&server, 2, "actor-bo", "device-bo-phone");
    ada.replace_member(GROUP, bo_leaf, &again.generate_key_package().expect("kp"))
        .expect("the same device takes its own seat back");
}

const THIRD_GROUP: &[u8] = b"peachy-account-identity-3";
const FOURTH_GROUP: &[u8] = b"peachy-account-identity-4";

/// Seat `joiner` in `group` beside whatever keys its person already has
/// there, with none of the committer's checks: a tree from before the
/// one-key rule, as an old conversation still holds.
fn forge_add(adder: &mut Client, joiner: &Client, group: &[u8]) {
    let package = joiner.generate_key_package().expect("key package");
    adder.forge_commit(group, &[], &[&package]).expect("forge");
    adder.merge_pending_commit(group).expect("merge");
}

fn forge_remove(adder: &mut Client, group: &[u8], device: &str) {
    let leaf = adder.leaf_of_device(group, device).expect("leaf");
    adder.forge_commit(group, &[leaf], &[]).expect("forge");
    adder.merge_pending_commit(group).expect("merge");
}

/// A device of Bo's under `account`, its credential issued a minute ago:
/// after his first key's devices, as a new key's devices are.
fn bo_under(server: &TestIssuer, tag: u8, device: &str, account: [u8; 32]) -> Client {
    bo_at(server, tag, device, &account, NOW - 60)
}

/// A device of Bo's under `account`, its credential issued at `issued_at`.
fn bo_at(server: &TestIssuer, tag: u8, device: &str, account: &[u8], issued_at: i64) -> Client {
    client_issued(
        server,
        tag,
        "actor-bo",
        device,
        Some(account),
        PeachyStorage::in_memory(),
        issued_at,
    )
}

/// Bo's default account key, the one [`client`] certifies him under.
fn bo_first_key() -> Vec<u8> {
    TestIssuer::test_account_key("actor-bo").to_vec()
}

/// Bo's old phone, under his first key, its credential ten days old.
fn bo_phone(server: &TestIssuer) -> Client {
    bo_at(
        server,
        2,
        "device-bo-phone",
        &bo_first_key(),
        NOW - 10 * DAY,
    )
}

fn says_bo(ada: &mut Client, group: &[u8]) {
    assert_eq!(
        ada.observe_account_keys(group).expect("observe"),
        vec!["actor-bo".to_string()]
    );
}

fn says_nothing(ada: &mut Client, group: &[u8]) {
    assert!(ada.observe_account_keys(group).expect("observe").is_empty());
}

/// Ada, who met Bo under his first key on his phone, and saw him move to a
/// new key on a new phone (issued a minute ago) in GROUP, where the phone's
/// leaf stays behind: reported once, there.
fn ada_after_bos_move(server: &TestIssuer) -> Client {
    let mut ada = client(server, 1, "actor-ada", "device-ada-phone");
    let mut phone = bo_phone(server);
    ada.create_group(GROUP).expect("create");
    add(&mut ada, &mut phone, GROUP);
    says_nothing(&mut ada, GROUP);
    let new_phone = bo_under(server, 3, "device-bo-new-phone", [0xb1; 32]);
    forge_add(&mut ada, &new_phone, GROUP);
    says_bo(&mut ada, GROUP);
    says_nothing(&mut ada, GROUP);
    ada
}

/// Cy's conversation holding `bo` as its only leaf of Bo's, with Ada seated
/// into it by a Welcome.
fn seat_ada_in_cys_group(server: &TestIssuer, ada: &mut Client, bo: &Client) -> Client {
    let mut cy = client(server, 7, "actor-cy", "device-cy-phone");
    cy.create_group(FOURTH_GROUP).expect("create");
    forge_add(&mut cy, bo, FOURTH_GROUP);
    add(&mut cy, ada, FOURTH_GROUP);
    cy
}

#[test]
fn a_first_sight_of_two_keys_pins_the_newest_and_a_new_device_under_the_other_says_so() {
    // Ada first meets Bo in a conversation that still holds a leaf of his
    // under an older account key beside his live one. Neither says anything
    // there, and a later conversation showing only the live one is silent.
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(&server, 2, "actor-bo", "device-bo-phone");
    ada.create_group(GROUP).expect("create");
    add(&mut ada, &mut bo, GROUP);
    let live = bo_under(&server, 3, "device-bo-new-phone", [0xb1; 32]);
    forge_add(&mut ada, &live, GROUP);
    says_nothing(&mut ada, GROUP);

    ada.create_group(OTHER_GROUP).expect("create");
    let mut live_tablet = bo_under(&server, 4, "device-bo-tablet", [0xb1; 32]);
    add(&mut ada, &mut live_tablet, OTHER_GROUP);
    says_nothing(&mut ada, OTHER_GROUP);

    // A new device under the older key, seated by a commit: that key coming
    // back, said once.
    ada.create_group(THIRD_GROUP).expect("create");
    let mut old_laptop = client(&server, 5, "actor-bo", "device-bo-laptop");
    add(&mut ada, &mut old_laptop, THIRD_GROUP);
    says_bo(&mut ada, THIRD_GROUP);

    // The old leaf going, and every conversation read again: nothing.
    forge_remove(&mut ada, GROUP, "device-bo-phone");
    for group in [GROUP, OTHER_GROUP, THIRD_GROUP] {
        says_nothing(&mut ada, group);
    }
}

#[test]
fn a_device_seen_before_under_a_retired_key_coming_back_says_so() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(&server, 2, "actor-bo", "device-bo-phone");
    ada.create_group(GROUP).expect("create");
    add(&mut ada, &mut bo, GROUP);
    says_nothing(&mut ada, GROUP);

    // Bo's code genuinely changes: said once.
    let new_phone = bo_under(&server, 3, "device-bo-new-phone", [0xb1; 32]);
    forge_add(&mut ada, &new_phone, GROUP);
    says_bo(&mut ada, GROUP);

    // The new key's leaf goes and another device under it comes: nothing.
    forge_remove(&mut ada, GROUP, "device-bo-new-phone");
    says_nothing(&mut ada, GROUP);
    let tablet = bo_under(&server, 4, "device-bo-tablet", [0xb1; 32]);
    forge_add(&mut ada, &tablet, GROUP);
    says_nothing(&mut ada, GROUP);

    // The old phone's leaf goes, and the phone comes back under the key Bo
    // moved away from: whoever holds it, that is the old key back. Said
    // once, though Ada saw that very device under it before.
    forge_remove(&mut ada, GROUP, "device-bo-phone");
    says_nothing(&mut ada, GROUP);
    let old_phone = client(&server, 2, "actor-bo", "device-bo-phone");
    forge_add(&mut ada, &old_phone, GROUP);
    says_bo(&mut ada, GROUP);
    says_nothing(&mut ada, GROUP);

    // And in a new conversation of its own: said there too.
    ada.create_group(OTHER_GROUP).expect("create");
    let mut old_phone = client(&server, 2, "actor-bo", "device-bo-phone");
    add(&mut ada, &mut old_phone, OTHER_GROUP);
    says_bo(&mut ada, OTHER_GROUP);

    // His live key was never moved off: a new conversation under it is
    // silent.
    ada.create_group(THIRD_GROUP).expect("create");
    let mut watch = bo_under(&server, 6, "device-bo-watch", [0xb1; 32]);
    add(&mut ada, &mut watch, THIRD_GROUP);
    says_nothing(&mut ada, THIRD_GROUP);
}

#[test]
fn a_genuinely_new_key_after_a_two_key_first_sight_is_said_once_per_conversation() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(&server, 2, "actor-bo", "device-bo-phone");
    ada.create_group(GROUP).expect("create");
    add(&mut ada, &mut bo, GROUP);
    let live = bo_under(&server, 3, "device-bo-new-phone", [0xb1; 32]);
    forge_add(&mut ada, &live, GROUP);
    ada.create_group(OTHER_GROUP).expect("create");
    let mut tablet = bo_under(&server, 4, "device-bo-tablet", [0xb1; 32]);
    add(&mut ada, &mut tablet, OTHER_GROUP);
    for group in [GROUP, OTHER_GROUP] {
        says_nothing(&mut ada, group);
    }

    // Bo loses every device and starts over under a key Ada never saw.
    let restarted = bo_at(&server, 7, "device-bo-restored", &[0xb2; 32], NOW - 30);
    for group in [GROUP, OTHER_GROUP] {
        forge_add(&mut ada, &restarted, group);
    }
    for group in [GROUP, OTHER_GROUP] {
        says_bo(&mut ada, group);
        says_nothing(&mut ada, group);
    }

    // His old leaves going says nothing more anywhere.
    forge_remove(&mut ada, GROUP, "device-bo-phone");
    forge_remove(&mut ada, GROUP, "device-bo-new-phone");
    forge_remove(&mut ada, OTHER_GROUP, "device-bo-tablet");
    for group in [GROUP, OTHER_GROUP] {
        says_nothing(&mut ada, group);
    }

    // A conversation begun after the change, under the new key: silent.
    ada.create_group(THIRD_GROUP).expect("create");
    let mut laptop = bo_under(&server, 9, "device-bo-laptop", [0xb2; 32]);
    add(&mut ada, &mut laptop, THIRD_GROUP);
    says_nothing(&mut ada, THIRD_GROUP);
}

#[test]
fn a_leftover_leaf_under_a_retired_key_is_said_once_in_a_tree_this_device_was_seated_into() {
    let server = issuer();
    let mut ada = ada_after_bos_move(&server);

    // Cy's conversation, not yet reseated, holds only Bo's old phone (a
    // Welcome into a tree showing one person under two keys is refused,
    // AccountKeyConflict). Whoever composed that Welcome chose the tree, and
    // the conversation encrypts to the phone: said once, there.
    let mut cy = seat_ada_in_cys_group(&server, &mut ada, &bo_phone(&server));
    says_bo(&mut ada, FOURTH_GROUP);
    says_nothing(&mut ada, FOURTH_GROUP);

    // A rejoin: Ada forgets her copy and comes back in from a Welcome. The
    // leaf was already said there: not again.
    let ada_leaf = cy
        .leaf_of_device(FOURTH_GROUP, "device-ada-phone")
        .expect("ada's leaf");
    let fresh = ada.generate_key_package().expect("key package");
    let replaced = cy
        .replace_member(FOURTH_GROUP, ada_leaf, &fresh)
        .expect("replace");
    cy.merge_pending_commit(FOURTH_GROUP).expect("merge");
    ada.forget_group(FOURTH_GROUP).expect("forget");
    ada.join_from_welcome(&replaced.welcome.expect("welcome"))
        .expect("rejoin");
    says_nothing(&mut ada, FOURTH_GROUP);

    // Cy repairs the conversation the normal way: the phone out, Bo's live
    // key in. Ada accepted that key long ago: nothing to say.
    let phone_leaf = cy
        .leaf_of_device(FOURTH_GROUP, "device-bo-phone")
        .expect("phone's leaf");
    let tablet = bo_under(&server, 4, "device-bo-tablet", [0xb1; 32]);
    let reseat = cy
        .reseat_person(
            FOURTH_GROUP,
            &[phone_leaf],
            &tablet.generate_key_package().expect("key package"),
        )
        .expect("reseat");
    cy.merge_pending_commit(FOURTH_GROUP).expect("merge");
    ada.process_commit(FOURTH_GROUP, &reseat.commit)
        .expect("ada applies the reseat");
    says_nothing(&mut ada, FOURTH_GROUP);

    // The same leftover in a conversation Ada founded, beside his live key:
    // said once there too.
    ada.create_group(OTHER_GROUP).expect("create");
    forge_add(&mut ada, &bo_phone(&server), OTHER_GROUP);
    let watch = bo_under(&server, 6, "device-bo-watch", [0xb1; 32]);
    forge_add(&mut ada, &watch, OTHER_GROUP);
    says_bo(&mut ada, OTHER_GROUP);

    // And nothing anywhere, however often it is read again; the live key
    // never moved, so a new conversation under it is silent.
    for group in [GROUP, OTHER_GROUP, FOURTH_GROUP] {
        says_nothing(&mut ada, group);
    }
    ada.create_group(THIRD_GROUP).expect("create");
    let mut laptop = bo_under(&server, 8, "device-bo-laptop", [0xb1; 32]);
    add(&mut ada, &mut laptop, THIRD_GROUP);
    says_nothing(&mut ada, THIRD_GROUP);
}

#[test]
fn a_future_dated_key_is_said_but_never_takes_the_pin() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    ada.create_group(GROUP).expect("create");
    let mut live = bo_under(&server, 3, "device-bo-new-phone", [0xb1; 32]);
    add(&mut ada, &mut live, GROUP);
    says_nothing(&mut ada, GROUP);

    // A key Ada never saw, on a credential dated eighty days ahead: said
    // once, and the live key stays.
    let future_key = [0xc5; 32];
    ada.create_group(OTHER_GROUP).expect("create");
    let future = bo_at(&server, 2, "device-bo-future", &future_key, NOW + 80 * DAY);
    forge_add(&mut ada, &future, OTHER_GROUP);
    says_bo(&mut ada, OTHER_GROUP);
    says_nothing(&mut ada, OTHER_GROUP);

    // A real device under the live key says nothing.
    ada.create_group(THIRD_GROUP).expect("create");
    let mut tablet = bo_under(&server, 4, "device-bo-tablet", [0xb1; 32]);
    add(&mut ada, &mut tablet, THIRD_GROUP);
    says_nothing(&mut ada, THIRD_GROUP);

    // A reseat under the live key still goes through: it was never retired.
    // (Done where the future-key leaf is dated two days ahead, not eighty: a
    // leaf eighty days ahead moves that group's tree clock past every other
    // credential there, which refuses any commit in it on its own.)
    let fifth: &[u8] = b"peachy-account-identity-5";
    ada.create_group(fifth).expect("create");
    let soon = bo_at(&server, 10, "device-bo-soon", &future_key, NOW + 2 * DAY);
    forge_add(&mut ada, &soon, fifth);
    says_bo(&mut ada, fifth);
    let soon_leaf = ada.leaf_of_device(fifth, "device-bo-soon").expect("leaf");
    let laptop = bo_under(&server, 8, "device-bo-laptop", [0xb1; 32]);
    ada.reseat_person(
        fifth,
        &[soon_leaf],
        &laptop.generate_key_package().expect("key package"),
    )
    .expect("reseat under the live key");
    ada.merge_pending_commit(fifth).expect("merge");
    says_nothing(&mut ada, fifth);

    // And another device under the future key is still said.
    ada.create_group(FOURTH_GROUP).expect("create");
    let again = bo_at(
        &server,
        9,
        "device-bo-future-2",
        &future_key,
        NOW + 80 * DAY,
    );
    forge_add(&mut ada, &again, FOURTH_GROUP);
    says_bo(&mut ada, FOURTH_GROUP);
}

#[test]
fn a_retired_key_under_a_backdated_or_same_time_credential_says_so() {
    let server = issuer();
    let mut ada = ada_after_bos_move(&server);
    let first = bo_first_key();

    // A new device under the key Bo left, its credential stamped exactly
    // when the move was: no same-day pass. Said once; his live key stays.
    ada.create_group(OTHER_GROUP).expect("create");
    let mut same_time = bo_at(&server, 10, "device-bo-same-time", &first, NOW - 60);
    add(&mut ada, &mut same_time, OTHER_GROUP);
    says_bo(&mut ada, OTHER_GROUP);
    says_nothing(&mut ada, OTHER_GROUP);

    // One backdated to before the move, seated by a commit: said once.
    ada.create_group(THIRD_GROUP).expect("create");
    let mut backdated = bo_at(&server, 11, "device-bo-backdated", &first, NOW - 2 * DAY);
    add(&mut ada, &mut backdated, THIRD_GROUP);
    says_bo(&mut ada, THIRD_GROUP);
    says_nothing(&mut ada, THIRD_GROUP);

    // Even in a tree Ada is seated into, a credential stamped AT the move is
    // not strictly before it: said once.
    let same_time = bo_at(&server, 12, "device-bo-seated", &first, NOW - 60);
    let _cy = seat_ada_in_cys_group(&server, &mut ada, &same_time);
    says_bo(&mut ada, FOURTH_GROUP);
    says_nothing(&mut ada, FOURTH_GROUP);

    // None of it moved his live key: a new device under it says nothing.
    let new_group: &[u8] = b"peachy-account-identity-5";
    ada.create_group(new_group).expect("create");
    let mut watch = bo_under(&server, 6, "device-bo-watch", [0xb1; 32]);
    add(&mut ada, &mut watch, new_group);
    says_nothing(&mut ada, new_group);
}

#[test]
fn a_real_change_back_to_an_old_key_is_said_once_per_conversation() {
    let server = issuer();
    let mut ada = ada_after_bos_move(&server);
    ada.create_group(OTHER_GROUP).expect("create");
    let mut tablet = bo_under(&server, 4, "device-bo-tablet", [0xb1; 32]);
    add(&mut ada, &mut tablet, OTHER_GROUP);
    says_nothing(&mut ada, OTHER_GROUP);
    ada.create_group(THIRD_GROUP).expect("create");
    let mut laptop = bo_under(&server, 8, "device-bo-laptop", [0xb1; 32]);
    add(&mut ada, &mut laptop, THIRD_GROUP);
    says_nothing(&mut ada, THIRD_GROUP);

    // Bo's current key becomes his first one again: a device certified under
    // it after the move.
    let restored = bo_at(&server, 9, "device-bo-restored", &bo_first_key(), NOW - 10);
    for group in [GROUP, OTHER_GROUP] {
        forge_add(&mut ada, &restored, group);
    }
    for group in [GROUP, OTHER_GROUP] {
        says_bo(&mut ada, group);
        says_nothing(&mut ada, group);
    }

    // The devices under the key he left going says nothing more, nor does a
    // new conversation under the key he came back to. A conversation that
    // still shows him only under the key he left, settled while it was
    // current, still encrypts to it: said once there.
    forge_remove(&mut ada, GROUP, "device-bo-new-phone");
    forge_remove(&mut ada, OTHER_GROUP, "device-bo-tablet");
    for group in [GROUP, OTHER_GROUP] {
        says_nothing(&mut ada, group);
    }
    says_bo(&mut ada, THIRD_GROUP);
    says_nothing(&mut ada, THIRD_GROUP);
    ada.create_group(FOURTH_GROUP).expect("create");
    forge_add(&mut ada, &restored, FOURTH_GROUP);
    says_nothing(&mut ada, FOURTH_GROUP);
}

#[test]
fn an_older_key_never_seen_is_said_but_does_not_move_the_live_key() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    // Ada met Bo under his live key only.
    ada.create_group(GROUP).expect("create");
    let mut live = bo_under(&server, 3, "device-bo-new-phone", [0xb1; 32]);
    add(&mut ada, &mut live, GROUP);
    says_nothing(&mut ada, GROUP);

    // An old conversation holds a leaf of his under a key she never saw,
    // issued long before: said, and accepted, but the live key stays.
    ada.create_group(OTHER_GROUP).expect("create");
    let ancient = bo_at(&server, 2, "device-bo-ancient", &[0xa0; 32], NOW - 20 * DAY);
    forge_add(&mut ada, &ancient, OTHER_GROUP);
    says_bo(&mut ada, OTHER_GROUP);
    says_nothing(&mut ada, OTHER_GROUP);

    // His next new device under the live key raises no second notice.
    ada.create_group(THIRD_GROUP).expect("create");
    let mut tablet = bo_under(&server, 4, "device-bo-tablet", [0xb1; 32]);
    add(&mut ada, &mut tablet, THIRD_GROUP);
    says_nothing(&mut ada, THIRD_GROUP);

    // And Ada can still reseat him under it where the old leaf sits.
    let old = ada
        .leaf_of_device(OTHER_GROUP, "device-bo-ancient")
        .expect("old leaf");
    let laptop = bo_under(&server, 8, "device-bo-laptop", [0xb1; 32]);
    ada.reseat_person(
        OTHER_GROUP,
        &[old],
        &laptop.generate_key_package().expect("key package"),
    )
    .expect("reseat under the live key");
    ada.merge_pending_commit(OTHER_GROUP).expect("merge");
    says_nothing(&mut ada, OTHER_GROUP);
}

/// The public account identity key `account` derives.
fn public(account: &[u8]) -> [u8; 32] {
    account_identity_public_key(account).expect("derive")
}

#[test]
fn an_undated_pin_learns_its_time_only_from_its_own_key() {
    let server = issuer();
    let kv = MemoryKv::new();
    let shared = || PeachyStorage::open(Box::new(kv.clone())).expect("open");
    // A store holding Bo pinned under his live key, his first key retired,
    // and no time recorded for the pin.
    {
        let seeded = shared();
        seeded
            .set_account_pins("actor-bo", &[public(&[0xb1; 32])])
            .expect("pin");
        seeded
            .set_account_retired("actor-bo", &[public(&bo_first_key())])
            .expect("retired");
    }
    let mut ada = client_for_account(
        &server,
        1,
        "actor-ada",
        "device-ada-phone",
        Some(&TestIssuer::test_account_key("actor-ada")),
        shared(),
    );

    // The first tree read shows him only under the retired key, on a device
    // newer than anything: no silent re-pin. Said once.
    ada.create_group(GROUP).expect("create");
    let mut old_key_device = bo_at(&server, 2, "device-bo-old-key", &bo_first_key(), NOW - 10);
    add(&mut ada, &mut old_key_device, GROUP);
    says_bo(&mut ada, GROUP);
    says_nothing(&mut ada, GROUP);
}

#[test]
fn a_two_key_conversation_with_no_known_record_draws_no_false_notice() {
    let server = issuer();
    let kv = MemoryKv::new();
    let shared = || PeachyStorage::open(Box::new(kv.clone())).expect("open");
    let ada_on = |storage: PeachyStorage| {
        client_for_account(
            &server,
            1,
            "actor-ada",
            "device-ada-phone",
            Some(&TestIssuer::test_account_key("actor-ada")),
            storage,
        )
    };
    // A conversation with no `known` record: Bo's old phone beside his live
    // key. The store pins the old phone's key and keeps both keys as the
    // group's own, retiring neither.
    let mut ada = ada_on(shared());
    ada.create_group(GROUP).expect("create");
    let mut phone = client(&server, 2, "actor-bo", "device-bo-phone");
    add(&mut ada, &mut phone, GROUP);
    let live = bo_under(&server, 3, "device-bo-new-phone", [0xb1; 32]);
    forge_add(&mut ada, &live, GROUP);
    drop(ada);
    {
        let seeded = shared();
        let old_key = public(&bo_first_key());
        let live_key = public(&[0xb1; 32]);
        seeded
            .set_account_pins("actor-bo", &[old_key])
            .expect("pin");
        seeded
            .set_account_seen(GROUP, "actor-bo", &[old_key, live_key])
            .expect("seen");
    }

    // After the upgrade, the next change to that tree draws nothing (a
    // Welcome into it would be refused, AccountKeyConflict; another device
    // of his is a change).
    let mut ada = ada_on(shared());
    let tablet = bo_under(&server, 4, "device-bo-tablet", [0xb1; 32]);
    forge_add(&mut ada, &tablet, GROUP);
    says_nothing(&mut ada, GROUP);
    says_nothing(&mut ada, GROUP);

    // And a new conversation under his live key draws nothing either.
    ada.create_group(OTHER_GROUP).expect("create");
    let mut watch = bo_under(&server, 6, "device-bo-watch", [0xb1; 32]);
    add(&mut ada, &mut watch, OTHER_GROUP);
    says_nothing(&mut ada, OTHER_GROUP);
}

const DM_GROUP: &[u8] = b"peachy-account-identity-dm";

#[test]
fn a_key_the_server_minted_is_said_and_seated_nowhere_by_the_members_own_devices() {
    // GROUP holds Ada, Bo's real phone under his first key, and Cy. Both of
    // them settle Bo there under that key.
    let server = issuer();
    let cy_kv = MemoryKv::new();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut cy = client_for_account(
        &server,
        7,
        "actor-cy",
        "device-cy-phone",
        Some(&TestIssuer::test_account_key("actor-cy")),
        PeachyStorage::open(Box::new(cy_kv.clone())).expect("open"),
    );
    ada.create_group(GROUP).expect("create");
    add(&mut ada, &mut bo_phone(&server), GROUP);
    add(&mut ada, &mut cy, GROUP);
    says_nothing(&mut ada, GROUP);
    says_nothing(&mut cy, GROUP);

    // The server mints Bo a device under a key of its own; that device founds
    // a DM and welcomes Ada into it. Said there, once.
    let seized_key = [0x5e; 32];
    let mut seized = bo_under(&server, 9, "device-bo-seized", seized_key);
    seized.create_group(DM_GROUP).expect("create");
    add(&mut seized, &mut ada, DM_GROUP);
    says_bo(&mut ada, DM_GROUP);
    says_nothing(&mut ada, DM_GROUP);

    // GROUP still holds Bo's real phone under his first key, which is said
    // there once too (it is no longer the key Ada pins), and nothing Ada's
    // device does seats the minted key there: no commit is staged, and her
    // own commit carries none.
    says_bo(&mut ada, GROUP);
    says_nothing(&mut ada, GROUP);
    assert!(ada.leaf_of_device(GROUP, "device-bo-phone").is_ok());
    assert!(ada.leaf_of_device(GROUP, "device-bo-seized").is_err());
    assert!(!ada.has_pending_commit(GROUP).expect("pending"));
    let update = ada.self_update(GROUP).expect("update");
    ada.merge_pending_commit(GROUP).expect("merge");
    assert!(ada.leaf_of_device(GROUP, "device-bo-phone").is_ok());
    assert!(ada.leaf_of_device(GROUP, "device-bo-seized").is_err());

    // Cy applies Ada's commit: his pin stays on Bo's real key, he is told
    // nothing, and no group of his seats the minted device.
    cy.process_commit(GROUP, &update.commit)
        .expect("cy applies it");
    says_nothing(&mut cy, GROUP);
    cy.flush().expect("flush");
    let cy_pins = PeachyStorage::open(Box::new(cy_kv.clone()))
        .expect("open")
        .account_pins("actor-bo")
        .expect("pins");
    assert_eq!(cy_pins, vec![public(&bo_first_key())]);
    for group in cy.group_ids() {
        assert!(cy.leaf_of_device(&group, "device-bo-seized").is_err());
        assert!(!cy.has_pending_commit(&group).expect("pending"));
    }

    // What remains: `reseat_person`, the door a lost-every-device rejoin
    // takes, accepts a package under the minted key over Bo's real leaf when
    // asked to. Nothing in the core asks; a client calls it only for a seat
    // ask whose person's every leaf the server named revoked
    // (docs/identity.md §Revocation reaches a seated leaf through
    // the roster), and the members then say Bo's security code changed.
    let phone_leaf = ada
        .leaf_of_device(GROUP, "device-bo-phone")
        .expect("phone's leaf");
    let package = bo_under(&server, 10, "device-bo-seized-2", seized_key)
        .generate_key_package()
        .expect("key package");
    assert!(ada.reseat_person(GROUP, &[phone_leaf], &package).is_ok());
    ada.clear_pending_commit(GROUP).expect("clear");
}

#[test]
fn an_upgraded_conversation_left_under_a_retired_key_stays_silent_through_a_later_reseat() {
    let server = issuer();
    let kv = MemoryKv::new();
    let shared = || PeachyStorage::open(Box::new(kv.clone())).expect("open");
    let ada_on = |storage: PeachyStorage| {
        client_for_account(
            &server,
            1,
            "actor-ada",
            "device-ada-phone",
            Some(&TestIssuer::test_account_key("actor-ada")),
            storage,
        )
    };
    // GROUP settled Bo's phone under his first key; then Ada saw him move to
    // a live key elsewhere, and the build she ran said so there.
    let mut ada = ada_on(shared());
    ada.create_group(GROUP).expect("create");
    add(&mut ada, &mut bo_phone(&server), GROUP);
    says_nothing(&mut ada, GROUP);
    ada.create_group(OTHER_GROUP).expect("create");
    let mut new_phone = bo_under(&server, 3, "device-bo-new-phone", [0xb1; 32]);
    add(&mut ada, &mut new_phone, OTHER_GROUP);
    says_bo(&mut ada, OTHER_GROUP);
    ada.flush().expect("flush");
    drop(ada);
    // That build kept settled leaves only: no reported record.
    {
        let seeded = shared();
        let known = seeded
            .account_known_leaves(GROUP)
            .expect("known")
            .expect("a record");
        seeded.forget_account_leaf_records(GROUP).expect("forget");
        seeded
            .set_account_known_leaves(GROUP, &known)
            .expect("known");
    }

    // After the upgrade, the first read is silent, and so is a later reseat
    // of Bo under his live key there: the move was said already.
    let mut ada = ada_on(shared());
    says_nothing(&mut ada, GROUP);
    let phone_leaf = ada
        .leaf_of_device(GROUP, "device-bo-phone")
        .expect("phone's leaf");
    let tablet = bo_under(&server, 4, "device-bo-tablet", [0xb1; 32]);
    ada.reseat_person(
        GROUP,
        &[phone_leaf],
        &tablet.generate_key_package().expect("key package"),
    )
    .expect("reseat under the live key");
    ada.merge_pending_commit(GROUP).expect("merge");
    says_nothing(&mut ada, GROUP);
    says_nothing(&mut ada, GROUP);
}

const SEIZED_GROUP: &[u8] = b"peachy-account-identity-seized";

#[test]
fn a_passive_device_left_under_a_retired_key_is_said_once_and_not_again_after_a_rejoin() {
    // Ada and Bo's phone share Cy's conversation, and Ada settles the phone
    // there while its key is Bo's current one.
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut cy = client(&server, 7, "actor-cy", "device-cy-phone");
    cy.create_group(SEIZED_GROUP).expect("create");
    add(&mut cy, &mut bo_phone(&server), SEIZED_GROUP);
    add(&mut cy, &mut ada, SEIZED_GROUP);
    says_nothing(&mut ada, SEIZED_GROUP);

    // Bo loses the phone and moves to a new key, which Ada sees elsewhere.
    ada.create_group(OTHER_GROUP).expect("create");
    let mut new_phone = bo_under(&server, 3, "device-bo-new-phone", [0xb1; 32]);
    add(&mut ada, &mut new_phone, OTHER_GROUP);
    says_bo(&mut ada, OTHER_GROUP);

    // The phone stays passive in Cy's conversation, which still encrypts to
    // it: said once there, at the next read, and Ada's own commit after it
    // says nothing more.
    says_bo(&mut ada, SEIZED_GROUP);
    says_nothing(&mut ada, SEIZED_GROUP);
    let update = ada.self_update(SEIZED_GROUP).expect("update");
    ada.merge_pending_commit(SEIZED_GROUP).expect("merge");
    cy.process_commit(SEIZED_GROUP, &update.commit)
        .expect("cy applies it");
    says_nothing(&mut ada, SEIZED_GROUP);

    // Ada forgets her copy and Cy seats her back: already said, not again.
    let ada_leaf = cy
        .leaf_of_device(SEIZED_GROUP, "device-ada-phone")
        .expect("ada's leaf");
    let fresh = ada.generate_key_package().expect("key package");
    let replaced = cy
        .replace_member(SEIZED_GROUP, ada_leaf, &fresh)
        .expect("replace");
    cy.merge_pending_commit(SEIZED_GROUP).expect("merge");
    ada.forget_group(SEIZED_GROUP).expect("forget");
    ada.join_from_welcome(&replaced.welcome.expect("welcome"))
        .expect("rejoin");
    says_nothing(&mut ada, SEIZED_GROUP);
    says_nothing(&mut ada, OTHER_GROUP);
}

#[test]
fn a_first_sight_pins_the_live_key_over_a_leaf_dated_months_ahead() {
    // A first sight of Bo under his live key beside a key on a credential
    // dated eighty days ahead: the live key is pinned, both in silence.
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    ada.create_group(GROUP).expect("create");
    let live = bo_under(&server, 3, "device-bo-new-phone", [0xb1; 32]);
    forge_add(&mut ada, &live, GROUP);
    let future = bo_at(&server, 2, "device-bo-future", &[0xc5; 32], NOW + 80 * DAY);
    forge_add(&mut ada, &future, GROUP);
    says_nothing(&mut ada, GROUP);

    // His next real device under the live key says nothing.
    ada.create_group(OTHER_GROUP).expect("create");
    let mut tablet = bo_under(&server, 4, "device-bo-tablet", [0xb1; 32]);
    add(&mut ada, &mut tablet, OTHER_GROUP);
    says_nothing(&mut ada, OTHER_GROUP);
}

#[test]
fn a_group_left_for_good_drops_its_leaf_records_and_a_rejoin_keeps_them() {
    let server = issuer();
    let kv = MemoryKv::new();
    let shared = || PeachyStorage::open(Box::new(kv.clone())).expect("open");
    let mut ada = client_for_account(
        &server,
        1,
        "actor-ada",
        "device-ada-phone",
        Some(&TestIssuer::test_account_key("actor-ada")),
        shared(),
    );
    ada.create_group(GROUP).expect("create");
    add(&mut ada, &mut bo_phone(&server), GROUP);
    says_nothing(&mut ada, GROUP);
    ada.flush().expect("flush");
    let records = || {
        let read = shared();
        (
            read.account_known_leaves(GROUP).expect("known"),
            read.account_reported_leaves(GROUP).expect("reported"),
        )
    };
    let (known, reported) = records();
    assert_eq!(known.map(|k| k.len()), Some(1));
    assert_eq!(reported, Some(Vec::new()));

    // Forgetting the copy, as a rejoin does, keeps them.
    ada.forget_group(GROUP).expect("forget");
    ada.flush().expect("flush");
    let (known, reported) = records();
    assert!(known.is_some() && reported.is_some());

    // Leaving for good drops them.
    ada.forget_remembered_roster(GROUP).expect("forget roster");
    ada.flush().expect("flush");
    assert_eq!(records(), (None, None));
}

#[test]
fn a_group_left_by_leaving_drops_its_leaf_records() {
    let server = issuer();
    let kv = MemoryKv::new();
    let shared = || PeachyStorage::open(Box::new(kv.clone())).expect("open");
    let mut ada = client_for_account(
        &server,
        1,
        "actor-ada",
        "device-ada-phone",
        Some(&TestIssuer::test_account_key("actor-ada")),
        shared(),
    );
    ada.create_group(GROUP).expect("create");
    add(&mut ada, &mut bo_phone(&server), GROUP);
    says_nothing(&mut ada, GROUP);
    // Bo goes; Ada, alone in it now, leaves, which finishes at once.
    forge_remove(&mut ada, GROUP, "device-bo-phone");
    ada.flush().expect("flush");
    assert!(shared()
        .account_known_leaves(GROUP)
        .expect("known")
        .is_some());
    assert!(ada.begin_leave(GROUP).expect("leave").is_empty());
    ada.flush().expect("flush");
    let read = shared();
    assert_eq!(read.account_known_leaves(GROUP).expect("known"), None);
    assert_eq!(read.account_reported_leaves(GROUP).expect("reported"), None);
}

/// A store with an undated pin, the conversations read in `order`, then Bo's
/// live-key watch in a new conversation and every conversation read twice
/// more: every notice any read gave.
fn upgraded_reads_in_order(order: &[&[u8]]) -> Vec<(String, Vec<String>)> {
    let server = issuer();
    let kv = MemoryKv::new();
    let shared = || PeachyStorage::open(Box::new(kv.clone())).expect("open");
    let ada_on = |storage: PeachyStorage| {
        client_for_account(
            &server,
            1,
            "actor-ada",
            "device-ada-phone",
            Some(&TestIssuer::test_account_key("actor-ada")),
            storage,
        )
    };
    // As in a_two_key_conversation_with_no_known_record_draws_no_false_notice: GROUP
    // holds Bo's old phone beside his live key; OTHER only the old phone;
    // THIRD only his live key, on his tablet. Bo moved to the live key long
    // ago and has changed nothing since.
    let mut ada = ada_on(shared());
    let mut phone = client(&server, 2, "actor-bo", "device-bo-phone");
    ada.create_group(GROUP).expect("create");
    add(&mut ada, &mut phone, GROUP);
    let live = bo_under(&server, 3, "device-bo-new-phone", [0xb1; 32]);
    forge_add(&mut ada, &live, GROUP);
    ada.create_group(OTHER_GROUP).expect("create");
    add(&mut ada, &mut phone, OTHER_GROUP);
    ada.create_group(THIRD_GROUP).expect("create");
    let mut tablet = bo_under(&server, 4, "device-bo-tablet", [0xb1; 32]);
    add(&mut ada, &mut tablet, THIRD_GROUP);
    ada.flush().expect("flush");
    drop(ada);
    // That build pinned the old phone's key with no time, kept both keys as
    // GROUP's own, and retired neither.
    {
        let seeded = shared();
        let old_key = public(&bo_first_key());
        let live_key = public(&[0xb1; 32]);
        seeded
            .set_account_pins("actor-bo", &[old_key])
            .expect("pin");
        seeded
            .set_account_seen(GROUP, "actor-bo", &[old_key, live_key])
            .expect("seen");
        seeded
            .set_account_seen(OTHER_GROUP, "actor-bo", &[old_key])
            .expect("seen");
        seeded
            .set_account_seen(THIRD_GROUP, "actor-bo", &[live_key])
            .expect("seen");
    }

    let mut ada = ada_on(shared());
    let mut said = Vec::new();
    let mut read = |ada: &mut Client, group: &[u8]| {
        let changed = ada.observe_account_keys(group).expect("observe");
        if !changed.is_empty() {
            said.push((String::from_utf8_lossy(group).into_owned(), changed));
        }
    };
    for group in order {
        read(&mut ada, group);
    }
    for group in order {
        read(&mut ada, group);
    }
    ada.create_group(FOURTH_GROUP).expect("create");
    let mut watch = bo_under(&server, 6, "device-bo-watch", [0xb1; 32]);
    add(&mut ada, &mut watch, FOURTH_GROUP);
    for _ in 0..2 {
        for group in [FOURTH_GROUP, GROUP, OTHER_GROUP, THIRD_GROUP] {
            read(&mut ada, group);
        }
    }
    said
}

#[test]
fn an_upgrade_draws_no_notice_whichever_conversation_is_read_first() {
    for order in [
        [GROUP, OTHER_GROUP, THIRD_GROUP],
        [OTHER_GROUP, GROUP, THIRD_GROUP],
        [OTHER_GROUP, THIRD_GROUP, GROUP],
        [THIRD_GROUP, OTHER_GROUP, GROUP],
    ] {
        let said = upgraded_reads_in_order(&order);
        assert!(
            said.is_empty(),
            "read first: {}; said: {said:?}",
            String::from_utf8_lossy(order[0])
        );
    }
}

/// A copy of everything `kv` holds.
fn snapshot(kv: &MemoryKv) -> MemoryKv {
    let copy = MemoryKv::new();
    for (key, value) in KvStore::scan(kv, &[]).expect("scan") {
        KvStore::put(&copy, &key, &value).expect("put");
    }
    KvStore::flush(&copy).expect("flush");
    copy
}

/// Ada over `kv`, which outlives her.
fn ada_over(server: &TestIssuer, kv: &MemoryKv) -> Client {
    client_for_account(
        server,
        1,
        "actor-ada",
        "device-ada-phone",
        Some(&TestIssuer::test_account_key("actor-ada")),
        PeachyStorage::open(Box::new(kv.clone())).expect("open"),
    )
}

/// A store dated in the wrong read order: GROUP holds Bo's old phone (ten
/// days old) beside his live key (five days old), both accepted there;
/// OTHER holds only the old phone, THIRD only his live-key tablet. Each
/// conversation keeps its settled leaves and no reported ones. `pinned_old` is the wrong read order (OTHER
/// first: the old key pinned, dated by the phone, and the live key retired
/// as merely accepted); otherwise the honest one (the live key pinned,
/// dated by its leaf, the old key retired).
fn store_dated_in_read_order(server: &TestIssuer, pinned_old: bool) -> MemoryKv {
    let kv = MemoryKv::new();
    let mut ada = ada_over(server, &kv);
    let mut phone = bo_phone(server);
    ada.create_group(GROUP).expect("create");
    add(&mut ada, &mut phone, GROUP);
    let live = bo_at(server, 3, "device-bo-new-phone", &[0xb1; 32], NOW - 5 * DAY);
    forge_add(&mut ada, &live, GROUP);
    ada.create_group(OTHER_GROUP).expect("create");
    add(&mut ada, &mut phone, OTHER_GROUP);
    ada.create_group(THIRD_GROUP).expect("create");
    let mut tablet = bo_at(server, 4, "device-bo-tablet", &[0xb1; 32], NOW - 5 * DAY);
    add(&mut ada, &mut tablet, THIRD_GROUP);
    ada.flush().expect("flush");
    drop(ada);

    // Each tree's leaves of Bo's, as leaf records name them, read off a copy.
    let copy = snapshot(&kv);
    let mut reader = ada_over(server, &copy);
    let mut leaves = Vec::new();
    for group in [GROUP, OTHER_GROUP, THIRD_GROUP] {
        reader.observe_account_keys(group).expect("observe");
    }
    reader.flush().expect("flush");
    let read = PeachyStorage::open(Box::new(copy.clone())).expect("open");
    for group in [GROUP, OTHER_GROUP, THIRD_GROUP] {
        let mut all = read
            .account_known_leaves(group)
            .expect("known")
            .unwrap_or_default();
        all.extend(
            read.account_reported_leaves(group)
                .expect("reported")
                .unwrap_or_default(),
        );
        leaves.push(all);
    }

    let seeded = PeachyStorage::open(Box::new(kv.clone())).expect("open");
    let old_key = public(&bo_first_key());
    let live_key = public(&[0xb1; 32]);
    let (pin, retired, since) = if pinned_old {
        (old_key, live_key, NOW - 10 * DAY)
    } else {
        (live_key, old_key, NOW - 5 * DAY)
    };
    seeded.set_account_pins("actor-bo", &[pin]).expect("pin");
    seeded
        .set_account_retired("actor-bo", &[retired])
        .expect("retired");
    seeded
        .set_account_pin_since("actor-bo", since)
        .expect("since");
    seeded
        .set_account_seen(GROUP, "actor-bo", &[old_key, live_key])
        .expect("seen");
    seeded
        .set_account_seen(OTHER_GROUP, "actor-bo", &[old_key])
        .expect("seen");
    seeded
        .set_account_seen(THIRD_GROUP, "actor-bo", &[live_key])
        .expect("seen");
    for (group, settled) in [GROUP, OTHER_GROUP, THIRD_GROUP].into_iter().zip(&leaves) {
        seeded
            .set_account_known_leaves(group, settled)
            .expect("known");
    }
    kv
}

#[test]
fn a_pin_dated_in_the_wrong_read_order_is_repaired_in_silence() {
    for order in [
        [GROUP, OTHER_GROUP, THIRD_GROUP],
        [OTHER_GROUP, THIRD_GROUP, GROUP],
        [THIRD_GROUP, GROUP, OTHER_GROUP],
    ] {
        let server = issuer();
        let kv = store_dated_in_read_order(&server, true);
        let mut ada = ada_over(&server, &kv);
        let mut said = Vec::new();
        let mut read = |ada: &mut Client, group: &[u8]| {
            let changed = ada.observe_account_keys(group).expect("observe");
            if !changed.is_empty() {
                said.push((String::from_utf8_lossy(group).into_owned(), changed));
            }
        };
        for group in order.iter().chain(order.iter()) {
            read(&mut ada, group);
        }
        // His next device under the live key, in a new conversation.
        ada.create_group(FOURTH_GROUP).expect("create");
        let mut watch = bo_under(&server, 6, "device-bo-watch", [0xb1; 32]);
        add(&mut ada, &mut watch, FOURTH_GROUP);
        for _ in 0..2 {
            for group in [FOURTH_GROUP, GROUP, OTHER_GROUP, THIRD_GROUP] {
                read(&mut ada, group);
            }
        }
        assert!(
            said.is_empty(),
            "read first: {}; said: {said:?}",
            String::from_utf8_lossy(order[0])
        );
        ada.flush().expect("flush");
        let pins = PeachyStorage::open(Box::new(kv.clone()))
            .expect("open")
            .account_pins("actor-bo")
            .expect("pins");
        assert_eq!(pins, vec![public(&[0xb1; 32])]);
    }
}

#[test]
fn a_real_change_back_after_an_honest_dating_is_still_said() {
    // The honest dating: the live key pinned, the old key retired. The
    // repair moves nothing, and every conversation is silent.
    let server = issuer();
    let kv = store_dated_in_read_order(&server, false);
    let mut ada = ada_over(&server, &kv);
    for group in [OTHER_GROUP, GROUP, THIRD_GROUP] {
        says_nothing(&mut ada, group);
    }
    ada.flush().expect("flush");
    let read = || {
        PeachyStorage::open(Box::new(kv.clone()))
            .expect("open")
            .account_pins("actor-bo")
            .expect("pins")
    };
    assert_eq!(read(), vec![public(&[0xb1; 32])]);

    // Then Bo really goes back to his old key, on a device issued after his
    // live key's: said where it shows, never taken in silence.
    let back = bo_at(&server, 8, "device-bo-back", &bo_first_key(), NOW - 60);
    forge_add(&mut ada, &back, GROUP);
    says_bo(&mut ada, GROUP);
    says_nothing(&mut ada, GROUP);
    ada.flush().expect("flush");
    assert_eq!(read(), vec![public(&bo_first_key())]);
}

#[test]
fn the_repair_keeps_a_pin_another_tree_shows_a_newer_leaf_under() {
    // The wrong-order store, and a conversation besides holding a device
    // under the pinned (old) key issued after the live key's leaves: the
    // once-per-store rule picks the old key there, so the repair moves
    // nothing.
    let server = issuer();
    let kv = store_dated_in_read_order(&server, true);
    let mut ada = ada_over(&server, &kv);
    ada.create_group(b"peachy-account-identity-5")
        .expect("create");
    let mut laptop = bo_at(
        &server,
        5,
        "device-bo-old-laptop",
        &bo_first_key(),
        NOW - 2 * DAY,
    );
    add(&mut ada, &mut laptop, b"peachy-account-identity-5");
    ada.observe_account_keys(GROUP).expect("observe");
    ada.flush().expect("flush");
    let read = PeachyStorage::open(Box::new(kv.clone())).expect("open");
    assert_eq!(
        read.account_pins("actor-bo").expect("pins"),
        vec![public(&bo_first_key())]
    );
    assert_eq!(
        read.account_retired("actor-bo").expect("retired"),
        vec![public(&[0xb1; 32])]
    );
}
