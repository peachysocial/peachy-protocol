// SPDX-License-Identifier: MIT
//! A leaf the delivery service names stale leaves a group only on evidence
//! the server cannot make up (`Client::stale_leaf_removable`,
//! docs/identity.md §Revocation reaches a seated leaf through the
//! roster):
//!
//! - **a revocation its own account signed** over its own device key, or
//! - **a credential past `exp`** while the person keeps an unlapsed leaf
//!   there (a last leaf only past its grace), judged on the device's own
//!   clock, or
//! - while `SIGNED_REVOCATIONS_ENFORCED` is false, **another unlapsed leaf
//!   of the same person** in the group, so the person stays a member.
//!
//! A person's last leaf leaves otherwise only in the commit that seats the
//! same person's new device (`Client::reseat_person`), and a device signs a
//! revocation only of a key it vouches for
//! (`Client::sign_install_revocations`).

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;

use peachy_mls_core::issuer::{device_key_pair, TestIssuer};
use peachy_mls_core::{
    account_identity_public_key, set_server_clock_offset_ms, sign_account_device,
    sign_device_revocation, verify_device_revocation, Client, ClientConfig, MemoryKv,
    PeachyStorage, SIGNED_REVOCATIONS_ENFORCED,
};
use support::{advance_ms, client, device_seed, issuer, TestClock, DAY, HOUR, NOW};

const G: &[u8] = b"88888888-8888-4888-8888-888888888888";

fn add(adder: &mut Client, joiner: &mut Client, group: &[u8]) -> Vec<u8> {
    let key_package = joiner.generate_key_package().expect("key package");
    let bundle = adder.add_member(group, &key_package).expect("add");
    adder.merge_pending_commit(group).expect("merge");
    support::join_at_head(
        joiner,
        &bundle.welcome.expect("welcome"),
        support::head_of(adder, group),
    )
    .expect("join");
    bundle.commit
}

fn public(tag: u8) -> [u8; 32] {
    device_key_pair(&device_seed(tag)).1
}

/// Bo's group G seats Ada's laptop and phone, and Cy's one device.
fn group() -> (Client, u32, u32) {
    let server = issuer();
    let mut bo = client(&server, 3, "actor-bo", "device-bo");
    let mut laptop = client(&server, 1, "actor-ada", "device-ada-laptop");
    let mut phone = client(&server, 2, "actor-ada", "device-ada-phone");
    let mut cy = client(&server, 4, "actor-cy", "device-cy");
    bo.create_group(G).unwrap();
    add(&mut bo, &mut laptop, G);
    add(&mut bo, &mut phone, G);
    add(&mut bo, &mut cy, G);
    let phone_leaf = bo.leaf_of_device(G, "device-ada-phone").unwrap();
    let cy_leaf = bo.leaf_of_device(G, "device-cy").unwrap();
    (bo, phone_leaf, cy_leaf)
}

fn leaf_key(client: &Client, leaf: u32) -> Vec<u8> {
    client
        .roster(G)
        .unwrap()
        .into_iter()
        .find(|e| e.leaf_index == leaf)
        .expect("seated")
        .leaf_key
}

/// `remove_stale_leaf` is the judge and the removal in one door: a leaf the
/// judge keeps is never staged, so a client acting on the server's list
/// cannot remove a person's last device by skipping the question.
#[test]
fn the_stale_removal_door_stages_nothing_the_judge_keeps() {
    let (mut bo, phone_leaf, cy_leaf) = group();
    let epoch = bo.epoch(G).unwrap();
    // Cy's only leaf, on the server's word alone: kept, nothing staged.
    let key = leaf_key(&bo, cy_leaf);
    assert!(bo
        .remove_stale_leaf(G, cy_leaf, &key, &[], 0)
        .unwrap()
        .is_none());
    // This device's own leaf never goes on the server's word.
    let own = bo.leaf_of_device(G, "device-bo").unwrap();
    let own_key = leaf_key(&bo, own);
    assert!(bo
        .remove_stale_leaf(G, own, &own_key, &[], 0)
        .unwrap()
        .is_none());
    // Nothing was staged: the group can still stage a commit of its own.
    assert_eq!(bo.epoch(G).unwrap(), epoch);
    // One of Ada's two leaves goes while the sibling rule stands.
    let key = leaf_key(&bo, phone_leaf);
    let staged = bo.remove_stale_leaf(G, phone_leaf, &key, &[], 0).unwrap();
    assert_eq!(staged.is_some(), !SIGNED_REVOCATIONS_ENFORCED);
    if staged.is_some() {
        bo.clear_pending_commit(G).unwrap();
    }
    // Cy's own account's signed revocation lets the last leaf go.
    let revocation =
        sign_device_revocation(&TestIssuer::test_account_key("actor-cy"), &public(4)).unwrap();
    let key = leaf_key(&bo, cy_leaf);
    assert!(bo
        .remove_stale_leaf(G, cy_leaf, &key, &revocation, 0)
        .unwrap()
        .is_some());
}

#[test]
fn a_persons_last_leaf_is_not_removed_on_the_servers_word_alone() {
    let (mut bo, _, cy_leaf) = group();
    assert!(!bo.stale_leaf_removable(G, cy_leaf, &[], 0).unwrap());
    // Bytes of the right length that verify under nothing.
    assert!(!bo.stale_leaf_removable(G, cy_leaf, &[0u8; 64], 0).unwrap());
}

#[test]
fn a_revocation_the_persons_own_account_signed_removes_the_last_leaf() {
    let (mut bo, _, cy_leaf) = group();
    let revocation =
        sign_device_revocation(&TestIssuer::test_account_key("actor-cy"), &public(4)).unwrap();
    assert!(bo.stale_leaf_removable(G, cy_leaf, &revocation, 0).unwrap());
}

#[test]
fn a_revocation_by_another_account_or_of_another_key_removes_nothing() {
    let (mut bo, _, cy_leaf) = group();
    // The server's own key, or anyone else's account, cannot revoke Cy.
    let by_ada =
        sign_device_revocation(&TestIssuer::test_account_key("actor-ada"), &public(4)).unwrap();
    assert!(!bo.stale_leaf_removable(G, cy_leaf, &by_ada, 0).unwrap());
    // Cy's account revoking some other key is not a revocation of this leaf.
    let other_key =
        sign_device_revocation(&TestIssuer::test_account_key("actor-cy"), &public(9)).unwrap();
    assert!(!bo.stale_leaf_removable(G, cy_leaf, &other_key, 0).unwrap());
}

#[test]
fn one_of_several_devices_goes_on_the_servers_word_until_enforcement() {
    let (mut bo, phone_leaf, _) = group();
    assert_eq!(
        bo.stale_leaf_removable(G, phone_leaf, &[], 0).unwrap(),
        !SIGNED_REVOCATIONS_ENFORCED,
    );
    let revocation =
        sign_device_revocation(&TestIssuer::test_account_key("actor-ada"), &public(2)).unwrap();
    assert!(bo
        .stale_leaf_removable(G, phone_leaf, &revocation, 0)
        .unwrap());
}

#[test]
fn a_last_leaf_past_its_credential_stays_until_its_grace() {
    let (mut bo, _, cy_leaf) = group();
    // Credentials run 30 days, and the server is the issuer: a lapse is its
    // word too. One day past `exp`, Cy's only leaf stays.
    advance_ms(u64::try_from(31 * DAY * 1000).unwrap());
    assert!(!bo.stale_leaf_removable(G, cy_leaf, &[], 0).unwrap());
}

#[test]
fn a_stale_leaf_is_judged_on_the_tree_clock_and_its_seat() {
    // What a lapse is read against beyond this device's clock: the newest
    // `iat` in the tree, which a clock running fast does not move, and when
    // the leaf's own device minted the package it is seated from.
    let server = issuer();
    let mut bo = client(&server, 3, "actor-bo", "device-bo");
    let laptop = client(&server, 1, "actor-ada", "device-ada-laptop");
    bo.create_group(G).unwrap();
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let not_before = wall - 7 * 86_400;
    let package = laptop
        .forge_key_package_with_lifetime(not_before, wall + 60 * 86_400)
        .unwrap();
    bo.add_member(G, &package).unwrap();
    bo.merge_pending_commit(G).unwrap();
    let laptop_leaf = bo.leaf_of_device(G, "device-ada-laptop").unwrap();
    advance_ms(u64::try_from(40 * DAY * 1000).unwrap());
    let (tree, minted_at) = bo.stale_leaf_clock_for_test(G, laptop_leaf).unwrap();
    assert_eq!(tree, NOW - HOUR);
    assert_eq!(minted_at, Some(i64::try_from(not_before).unwrap() + HOUR));
}

#[test]
fn a_lapsed_sibling_does_not_let_a_device_go() {
    // Every leaf lapsed together: Ada's laptop no longer counts as the leaf
    // that keeps her a member, so her phone does not go on the list alone.
    let (mut bo, phone_leaf, _) = group();
    advance_ms(u64::try_from(31 * DAY * 1000).unwrap());
    assert!(!bo.stale_leaf_removable(G, phone_leaf, &[], 0).unwrap());
}

#[test]
fn the_servers_clock_offset_ages_no_leaf() {
    let (mut bo, phone_leaf, _) = group();
    // Twelve hours before `exp` on this device, a day past it on the
    // server-corrected clock. Ada's two leaves are both unlapsed here, so the
    // sibling rule is the only one that could answer; the lapse is not one.
    advance_ms(u64::try_from((30 * DAY - 12 * HOUR) * 1000).unwrap());
    set_server_clock_offset_ms(86_400_000);
    let removable = bo.stale_leaf_removable(G, phone_leaf, &[], 0).unwrap();
    set_server_clock_offset_ms(0);
    assert_eq!(removable, !SIGNED_REVOCATIONS_ENFORCED);
}

#[test]
fn a_leaf_that_is_not_there_is_never_removable() {
    let (mut bo, _, _) = group();
    assert!(!bo.stale_leaf_removable(G, 99, &[], 0).unwrap());
    assert!(bo
        .stale_leaf_removable(b"no-such-group", 0, &[], 0)
        .is_err());
}

/// A device of `actor` under an account key of its own: a person who lost
/// every device and started over (`ClaimSoleDevice`), or a server's mint.
fn started_over(
    server: &TestIssuer,
    tag: u8,
    actor: &str,
    device: &str,
    account: Option<&[u8]>,
) -> Client {
    let seed = device_seed(tag);
    let (_, public) = device_key_pair(&seed);
    let token = server
        .issue_for_account(actor, device, &public, account, NOW - HOUR, NOW + 30 * DAY)
        .expect("mint");
    let mut config = ClientConfig::new(token, seed, server.trusted_keys().expect("keys"))
        .with_storage(PeachyStorage::in_memory())
        .with_own_account_identity(
            account.map(|a| account_identity_public_key(a).expect("derive")),
        );
    config.clock = Some(Box::new(TestClock));
    Client::new(config).expect("client")
}

const NEW_ACCOUNT_KEY: [u8; 32] = [0x42; 32];

#[test]
fn a_person_who_started_over_is_reseated_in_one_commit() {
    let server = issuer();
    let (mut bo, _, cy_leaf) = group();
    // Bo has pinned Cy's account key.
    assert!(bo.observe_account_keys(G).unwrap().is_empty());
    let mut fresh = started_over(
        &server,
        5,
        "actor-cy",
        "device-cy-new",
        Some(&NEW_ACCOUNT_KEY),
    );
    let key_package = fresh.generate_key_package().unwrap();
    // One person, one account key: the plain add is refused while the old
    // leaf stays, and the old leaf is Cy's last, so it does not go alone.
    assert!(bo.add_member(G, &key_package).is_err());
    assert!(!bo.stale_leaf_removable(G, cy_leaf, &[], 0).unwrap());

    let bundle = bo.reseat_person(G, &[cy_leaf], &key_package).unwrap();
    bo.merge_pending_commit(G).unwrap();
    support::join_at_head(
        &mut fresh,
        &bundle.welcome.expect("welcome"),
        support::head_of(&bo, G),
    )
    .unwrap();
    let devices: Vec<String> = bo
        .roster(G)
        .unwrap()
        .into_iter()
        .filter_map(|e| e.identity.ok())
        .filter(|id| id.actor_id == "actor-cy")
        .map(|id| id.device_id)
        .collect();
    assert_eq!(devices, ["device-cy-new"]);
    // And every member is told: Cy's security code changed.
    assert_eq!(
        bo.observe_account_keys(G).unwrap(),
        ["actor-cy".to_string()]
    );
}

#[test]
fn every_other_member_takes_the_reseat_and_sees_the_new_account_key() {
    // The commit is judged by every receiver, not only built by the adder:
    // another member merges it, and Cy's security code changes for them too.
    let server = issuer();
    let mut bo = client(&server, 3, "actor-bo", "device-bo");
    let mut dee = client(&server, 6, "actor-dee", "device-dee");
    let mut cy = client(&server, 4, "actor-cy", "device-cy");
    bo.create_group(G).unwrap();
    add(&mut bo, &mut dee, G);
    let commit = add(&mut bo, &mut cy, G);
    dee.process_commit(G, &commit).unwrap();
    assert!(dee.observe_account_keys(G).unwrap().is_empty());
    let cy_leaf = bo.leaf_of_device(G, "device-cy").unwrap();

    let fresh = started_over(
        &server,
        5,
        "actor-cy",
        "device-cy-new",
        Some(&NEW_ACCOUNT_KEY),
    );
    let key_package = fresh.generate_key_package().unwrap();
    let bundle = bo.reseat_person(G, &[cy_leaf], &key_package).unwrap();
    bo.merge_pending_commit(G).unwrap();
    dee.process_commit(G, &bundle.commit).unwrap();
    assert_eq!(
        dee.observe_account_keys(G).unwrap(),
        ["actor-cy".to_string()]
    );
    assert!(dee.leaf_of_device(G, "device-cy").is_err());
    assert!(dee.leaf_of_device(G, "device-cy-new").is_ok());
}

#[test]
fn a_reseat_needs_an_account_signature_and_all_of_the_persons_leaves() {
    let server = issuer();
    let (mut bo, phone_leaf, cy_leaf) = group();
    // No account certificate: such a device mints no key package, and one
    // forged for it (the server's own device) is refused.
    let unsigned = started_over(&server, 5, "actor-cy", "device-cy-new", None);
    assert!(unsigned.generate_key_package().is_err());
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let package = unsigned
        .forge_key_package_with_lifetime(wall - 3_600, wall + 60 * 86_400)
        .unwrap();
    assert!(bo.reseat_person(G, &[cy_leaf], &package).is_err());

    // Ada keeps two leaves; naming only one of them is refused.
    let ada_new = started_over(
        &server,
        6,
        "actor-ada",
        "device-ada-new",
        Some(&NEW_ACCOUNT_KEY),
    );
    let package = ada_new.generate_key_package().unwrap();
    assert!(bo.reseat_person(G, &[phone_leaf], &package).is_err());
    // A leaf of somebody else is not the person's.
    assert!(bo.reseat_person(G, &[cy_leaf], &package).is_err());
    let laptop_leaf = bo.leaf_of_device(G, "device-ada-laptop").unwrap();
    assert!(bo
        .reseat_person(G, &[phone_leaf, laptop_leaf], &package)
        .is_ok());
}

#[test]
fn a_device_under_the_same_account_key_is_added_and_removes_nobody() {
    // Whoever holds Cy's account key signs her old devices' revocations; a
    // reseat under it would change no security code, so nobody would see a
    // removal the server asked for. The new device is added beside the old
    // leaf, which goes on its own evidence.
    let server = issuer();
    let (mut bo, _, cy_leaf) = group();
    assert!(bo.observe_account_keys(G).unwrap().is_empty());
    let same_key = TestIssuer::test_account_key("actor-cy");
    let fresh = started_over(&server, 5, "actor-cy", "device-cy-new", Some(&same_key));
    let package = fresh.generate_key_package().unwrap();
    bo.reseat_person(G, &[cy_leaf], &package).unwrap();
    bo.merge_pending_commit(G).unwrap();
    assert_eq!(bo.leaf_of_device(G, "device-cy").unwrap(), cy_leaf);
    assert!(bo.leaf_of_device(G, "device-cy-new").is_ok());
    assert!(bo.observe_account_keys(G).unwrap().is_empty());
}

#[test]
fn a_reseat_never_brings_back_a_key_the_person_moved_away_from() {
    let server = issuer();
    let (mut bo, _, cy_leaf) = group();
    assert!(bo.observe_account_keys(G).unwrap().is_empty());
    let fresh = started_over(
        &server,
        5,
        "actor-cy",
        "device-cy-new",
        Some(&NEW_ACCOUNT_KEY),
    );
    let bundle = bo
        .reseat_person(G, &[cy_leaf], &fresh.generate_key_package().unwrap())
        .unwrap();
    drop(bundle);
    bo.merge_pending_commit(G).unwrap();
    assert_eq!(
        bo.observe_account_keys(G).unwrap(),
        ["actor-cy".to_string()]
    );
    // A device under Cy's old key, which still signs for her, cannot reseat
    // her new one away: the key she left is retired on this device.
    let old_key = TestIssuer::test_account_key("actor-cy");
    let back = started_over(&server, 6, "actor-cy", "device-cy-back", Some(&old_key));
    let new_leaf = bo.leaf_of_device(G, "device-cy-new").unwrap();
    assert!(bo
        .reseat_person(G, &[new_leaf], &back.generate_key_package().unwrap())
        .is_err());
    // A third key is still a reseat, and every member sees it.
    let third = started_over(&server, 7, "actor-cy", "device-cy-third", Some(&[0x43; 32]));
    assert!(bo
        .reseat_person(G, &[new_leaf], &third.generate_key_package().unwrap())
        .is_ok());
}

#[test]
fn a_key_retired_in_one_group_still_adds_where_the_persons_leaves_carry_it() {
    // Cy started over in G2 (or the server took her seat there): Bo retires
    // her old key for every group. In G her leaf still carries that key, and
    // a new device of hers under it is an ordinary add beside it, not a
    // refused reseat.
    const G2: &[u8] = b"99999999-9999-4999-8999-999999999999";
    let server = issuer();
    let mut bo = client(&server, 3, "actor-bo", "device-bo");
    let mut cy = client(&server, 4, "actor-cy", "device-cy");
    bo.create_group(G).unwrap();
    bo.create_group(G2).unwrap();
    add(&mut bo, &mut cy, G);
    add(&mut bo, &mut cy, G2);
    assert!(bo.observe_account_keys(G).unwrap().is_empty());
    assert!(bo.observe_account_keys(G2).unwrap().is_empty());
    let fresh = started_over(
        &server,
        5,
        "actor-cy",
        "device-cy-new",
        Some(&NEW_ACCOUNT_KEY),
    );
    let cy_in_g2 = bo.leaf_of_device(G2, "device-cy").unwrap();
    bo.reseat_person(G2, &[cy_in_g2], &fresh.generate_key_package().unwrap())
        .unwrap();
    bo.merge_pending_commit(G2).unwrap();
    assert_eq!(
        bo.observe_account_keys(G2).unwrap(),
        ["actor-cy".to_string()]
    );
    let old_key = TestIssuer::test_account_key("actor-cy");
    let back = started_over(&server, 6, "actor-cy", "device-cy-back", Some(&old_key));
    let cy_in_g = bo.leaf_of_device(G, "device-cy").unwrap();
    bo.reseat_person(G, &[cy_in_g], &back.generate_key_package().unwrap())
        .unwrap();
    bo.merge_pending_commit(G).unwrap();
    assert_eq!(bo.leaf_of_device(G, "device-cy").unwrap(), cy_in_g);
    assert!(bo.leaf_of_device(G, "device-cy-back").is_ok());
}

#[test]
fn a_reseat_never_reseats_the_committers_own_person() {
    let server = issuer();
    let (mut bo, _, _) = group();
    let bo_new = started_over(
        &server,
        7,
        "actor-bo",
        "device-bo-new",
        Some(&NEW_ACCOUNT_KEY),
    );
    let package = bo_new.generate_key_package().unwrap();
    let bo_leaf = bo.leaf_of_device(G, "device-bo").unwrap();
    assert!(bo.reseat_person(G, &[bo_leaf], &package).is_err());
}

/// Ada's phone, which let her laptop in: the laptop is on its chain.
fn ada_phone_with_laptop_on_its_chain() -> Client {
    let server = issuer();
    let mut phone = client(&server, 2, "actor-ada", "device-ada-phone");
    phone
        .remember_own_approver("device-ada-laptop", &public(1))
        .unwrap();
    phone
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn list(rows: &[(&str, &str, Option<[u8; 32]>)]) -> String {
    let rows: Vec<serde_json::Value> = rows
        .iter()
        .map(|(id, twin, key)| {
            serde_json::json!({
                "id": id,
                "twinOf": twin,
                "signingKey": key.map(|k| hex(&k)).unwrap_or_default(),
            })
        })
        .collect();
    serde_json::Value::Array(rows).to_string()
}

fn signed(
    phone: &mut Client,
    named: &str,
    denying: bool,
    rows: &[(&str, &str, Option<[u8; 32]>)],
) -> Vec<String> {
    // The confirmation names every row the list links to the named one.
    let named_with: Vec<&str> = rows
        .iter()
        .filter(|(_, twin, _)| *twin == named)
        .map(|(id, _, _)| *id)
        .collect();
    let rows: serde_json::Value = serde_json::from_str(&list(rows)).unwrap();
    let request = serde_json::json!({
        "named": named,
        "denying": denying,
        "namedWith": named_with,
        "ownDeviceIds": ["phone-plain", "device-ada-phone"],
        "rows": rows,
    });
    let out = phone
        .sign_install_revocations(
            &TestIssuer::test_account_key("actor-ada"),
            &request.to_string(),
        )
        .unwrap();
    let out: Vec<serde_json::Value> = serde_json::from_str(&out).unwrap();
    out.iter()
        .map(|entry| {
            let id = entry["deviceId"].as_str().unwrap().to_string();
            let signature: Vec<u8> = (0..64)
                .map(|i| {
                    u8::from_str_radix(&entry["signature"].as_str().unwrap()[i * 2..i * 2 + 2], 16)
                        .unwrap()
                })
                .collect();
            let account =
                account_identity_public_key(&TestIssuer::test_account_key("actor-ada")).unwrap();
            let key = if id == "device-ada-laptop" {
                public(1)
            } else {
                public(2)
            };
            assert!(verify_device_revocation(&account, &key, &signature));
            id
        })
        .collect()
}

#[test]
fn a_device_signs_only_the_install_it_vouches_for_on_a_link_it_pinned() {
    let mut phone = ada_phone_with_laptop_on_its_chain();
    let honest = [
        ("laptop-plain", "", None),
        ("device-ada-laptop", "laptop-plain", Some(public(1))),
        ("phone-plain", "", None),
        ("device-ada-phone", "phone-plain", Some(public(2))),
    ];
    // Before this device has seen the link, the laptop's MLS row is not
    // reached through it.
    assert!(signed(&mut phone, "laptop-plain", false, &honest).is_empty());
    assert_eq!(phone.note_own_install_links(&list(&honest)).unwrap(), 2);
    assert_eq!(
        signed(&mut phone, "laptop-plain", false, &honest),
        ["device-ada-laptop"]
    );
    // A second sight pins nothing new.
    assert_eq!(phone.note_own_install_links(&list(&honest)).unwrap(), 0);
}

#[test]
fn a_device_list_cannot_steer_a_removal_onto_a_live_device() {
    let mut phone = ada_phone_with_laptop_on_its_chain();
    let honest = [
        ("laptop-plain", "", None),
        ("device-ada-laptop", "laptop-plain", Some(public(1))),
    ];
    phone.note_own_install_links(&list(&honest)).unwrap();
    // The server invents a device and names the laptop's MLS row its twin.
    let steered = [
        ("fake", "", Some([0x77; 32])),
        ("laptop-plain", "", None),
        ("device-ada-laptop", "fake", Some(public(1))),
    ];
    phone.note_own_install_links(&list(&steered)).unwrap();
    assert!(signed(&mut phone, "fake", false, &steered).is_empty());
    // Or denies it, which signs nothing whatever it is linked to.
    assert!(signed(&mut phone, "device-ada-laptop", true, &honest).is_empty());
    // Or points the removal at this install.
    let mine = [
        ("fake", "phone-plain", Some([0x77; 32])),
        ("phone-plain", "", None),
        ("device-ada-phone", "phone-plain", Some(public(2))),
    ];
    assert!(signed(&mut phone, "fake", false, &mine).is_empty());
    // Or lists this device's own key under a new id.
    let own_key = [("fake", "", Some(public(2)))];
    assert!(signed(&mut phone, "fake", false, &own_key).is_empty());
}

#[test]
fn an_id_the_list_names_twice_is_never_signed() {
    // The laptop's row as the phone vouches for it, then the same id again
    // under the key of Ada's live tablet: the first row qualifies, and the
    // key the list gives the id is the second. Nothing is signed, in either
    // order, and the tablet's key stays approvable.
    let mut phone = ada_phone_with_laptop_on_its_chain();
    let account = TestIssuer::test_account_key("actor-ada");
    for rows in [
        [
            ("device-ada-laptop", "", Some(public(1))),
            ("device-ada-laptop", "", Some(public(5))),
        ],
        [
            ("device-ada-laptop", "", Some(public(5))),
            ("device-ada-laptop", "", Some(public(1))),
        ],
    ] {
        let request = serde_json::json!({
            "named": "device-ada-laptop",
            "namedWith": [],
            "ownDeviceIds": ["phone-plain", "device-ada-phone"],
            "rows": serde_json::from_str::<serde_json::Value>(&list(&rows)).unwrap(),
        });
        let out = phone
            .sign_install_revocations(&account, &request.to_string())
            .unwrap();
        assert_eq!(out, "[]");
    }
    assert!(phone
        .sign_own_device_approval("device-ada-tablet", &public(5), 0)
        .is_ok());
    // The laptop listed once is signed as before.
    let once = [("device-ada-laptop", "", Some(public(1)))];
    assert_eq!(
        signed(&mut phone, "device-ada-laptop", false, &once),
        ["device-ada-laptop"]
    );
}

/// The registration that restored Ada's phone answered `keys` as signed out
/// (`Client::note_restore_signed_out`), each with her account's certificate.
fn answered(phone: &mut Client, since: i64, keys: &[[u8; 32]]) -> u32 {
    let account = TestIssuer::test_account_key("actor-ada");
    let certified: Vec<([u8; 32], [u8; 64])> = keys
        .iter()
        .map(|key| (*key, sign_account_device(&account, key).unwrap()))
        .collect();
    answered_with(phone, since, &certified)
}

/// [`answered`], with the certificate the answer carried for each key.
fn answered_with(phone: &mut Client, since: i64, keys: &[([u8; 32], [u8; 64])]) -> u32 {
    let account = TestIssuer::test_account_key("actor-ada");
    let identity = account_identity_public_key(&account).unwrap();
    let certificates: Vec<String> = keys.iter().map(|(_, c)| hex(c)).collect();
    let keys: Vec<String> = keys.iter().map(|(key, _)| hex(key)).collect();
    phone
        .note_restore_signed_out(
            &serde_json::json!({
                "restoredSince": since,
                "keys": keys,
                "certificates": certificates,
                "accountIdentityKey": hex(&identity),
            })
            .to_string(),
        )
        .unwrap()
}

/// The core keeps only the keys whose certificate verifies under the account
/// identity key the device holds: one the account never certified (a server
/// could have made it up), one certified by another account, and one with
/// no certificate are dropped, so a server cannot have the device refuse a
/// device it never linked.
#[test]
fn a_restore_keeps_only_the_keys_the_account_certified() {
    let server = issuer();
    let mut phone = client(&server, 2, "actor-ada", "device-ada-phone");
    let ada = TestIssuer::test_account_key("actor-ada");
    let other = TestIssuer::test_account_key("actor-bo");
    let keys = [
        (public(1), sign_account_device(&ada, &public(1)).unwrap()),
        (public(5), sign_account_device(&other, &public(5)).unwrap()),
        (public(6), sign_account_device(&ada, &public(7)).unwrap()),
        (public(7), [0u8; 64]),
    ];
    assert_eq!(answered_with(&mut phone, NOW, &keys), 1);
    let mut approve = |tag: u8| {
        phone
            .sign_own_device_approval(&format!("device-{tag}"), &public(tag), 0)
            .is_ok()
    };
    assert!(!approve(1), "the certified key is signed out");
    for tag in [5, 6, 7] {
        assert!(approve(tag), "key {tag} was never kept");
    }
}

/// A restore's answer is verified under the account identity key the device
/// holds, never one the request names: an answer naming another key, with
/// certificates that verify under it, is refused and keeps nothing.
#[test]
fn a_restore_answer_naming_another_identity_key_is_refused() {
    let server = issuer();
    let mut phone = client(&server, 2, "actor-ada", "device-ada-phone");
    let made_up = TestIssuer::test_account_key("actor-bo");
    let request = serde_json::json!({
        "restoredSince": NOW,
        "keys": [hex(&public(1))],
        "certificates": [hex(&sign_account_device(&made_up, &public(1)).unwrap())],
        "accountIdentityKey": hex(&account_identity_public_key(&made_up).unwrap()),
    });
    assert!(phone.note_restore_signed_out(&request.to_string()).is_err());
    assert!(phone
        .sign_own_device_approval("device-1", &public(1), 0)
        .is_ok());
    // The same restore, answered under the key the phone holds, still keeps.
    assert_eq!(answered(&mut phone, NOW, &[public(1)]), 1);
}

#[test]
fn a_pin_restore_signs_the_installs_it_signed_out_and_no_other() {
    // Ada's phone took the account key back from her PIN; the server signed
    // her laptop out in the same registration, and its answer said so. The
    // laptop is on no chain the phone holds (it restored, nobody let it in),
    // and it signs it anyway: "every other device" is what the restore meant.
    let server = issuer();
    let mut phone = client(&server, 2, "actor-ada", "device-ada-phone");
    assert_eq!(answered(&mut phone, NOW, &[public(1), public(7)]), 2);
    let rows = serde_json::json!([
        {"id": "laptop-plain", "revoked": true, "revokedAt": NOW + 10},
        {"id": "device-ada-laptop", "twinOf": "laptop-plain", "signingKey": hex(&public(1)),
         "revoked": true, "revokedAt": NOW + 10},
        {"id": "device-old", "signingKey": hex(&public(7)), "revoked": true, "revokedAt": NOW - DAY},
        {"id": "device-ada-phone", "signingKey": hex(&public(2))},
    ]);
    let request = |since: i64| {
        serde_json::json!({
            "ownDeviceIds": ["phone-plain"],
            "restoredSince": since,
            "rows": rows,
        })
        .to_string()
    };
    let account = TestIssuer::test_account_key("actor-ada");
    let out: Vec<serde_json::Value> = serde_json::from_str(
        &phone
            .sign_install_revocations(&account, &request(NOW))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0]["deviceId"], "device-ada-laptop");
    let signature: Vec<u8> = (0..64)
        .map(|i| {
            u8::from_str_radix(&out[0]["signature"].as_str().unwrap()[i * 2..i * 2 + 2], 16)
                .unwrap()
        })
        .collect();
    let identity = account_identity_public_key(&account).unwrap();
    assert!(verify_device_revocation(&identity, &public(1), &signature));
    // Without a restore, a revoked row on no chain is never signed.
    let out = phone
        .sign_install_revocations(&account, &request(0))
        .unwrap();
    assert_eq!(out, "[]");
}

/// What a PIN restore signs on one read of the list: the ids, each signature
/// checked under the account's identity key against the key the row lists.
fn restore_signed(phone: &mut Client, since: i64, rows: serde_json::Value) -> Vec<String> {
    let account = TestIssuer::test_account_key("actor-ada");
    let identity = account_identity_public_key(&account).unwrap();
    let keys: std::collections::BTreeMap<String, String> = rows
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                row["id"].as_str().unwrap().to_string(),
                row["signingKey"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    let request = serde_json::json!({
        "ownDeviceIds": ["phone-plain"],
        "restoredSince": since,
        "rows": rows,
    });
    let out = phone
        .sign_install_revocations(&account, &request.to_string())
        .unwrap();
    let out: Vec<serde_json::Value> = serde_json::from_str(&out).unwrap();
    out.iter()
        .map(|entry| {
            let id = entry["deviceId"].as_str().unwrap().to_string();
            let unhex = |text: &str| -> Vec<u8> {
                (0..text.len() / 2)
                    .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
                    .collect()
            };
            let signature = unhex(entry["signature"].as_str().unwrap());
            assert!(verify_device_revocation(
                &identity,
                &unhex(&keys[&id]),
                &signature
            ));
            id
        })
        .collect()
}

#[test]
fn a_pin_restore_signs_only_what_its_registration_answered() {
    // The registration that restored Ada's phone answered the laptop signed
    // out.
    let server = issuer();
    let mut phone = client(&server, 2, "actor-ada", "device-ada-phone");
    answered(&mut phone, NOW, &[public(1)]);
    let laptop = serde_json::json!({"id": "device-ada-laptop", "signingKey": hex(&public(1)),
        "revoked": true, "revokedAt": NOW + 10});
    let me = serde_json::json!({"id": "device-ada-phone", "signingKey": hex(&public(2))});
    // She then links her tablet. The server lists the tablet's key revoked
    // ten minutes after the restore, inside the band, and leaves its live row
    // out: the key was not in the restore's answer, so it is never signed.
    let tablet = serde_json::json!({"id": "device-ada-tablet", "signingKey": hex(&public(5)),
        "revoked": true, "revokedAt": NOW + 600});
    assert_eq!(
        restore_signed(&mut phone, NOW, serde_json::json!([laptop, tablet, me])),
        ["device-ada-laptop"]
    );
    // Nor under the laptop's id.
    let swapped = serde_json::json!({"id": "device-ada-laptop", "signingKey": hex(&public(5)),
        "revoked": true, "revokedAt": NOW + 10});
    assert!(restore_signed(&mut phone, NOW, serde_json::json!([swapped, me])).is_empty());
    // Nor the laptop's row with a second row under its id after it, whose
    // key the list would give the id.
    assert!(restore_signed(&mut phone, NOW, serde_json::json!([laptop, swapped, me])).is_empty());
    // A second answer for the same restore changes nothing.
    assert_eq!(answered(&mut phone, NOW, &[public(5)]), 0);
    assert_eq!(
        restore_signed(&mut phone, NOW, serde_json::json!([laptop, tablet, me])),
        ["device-ada-laptop"]
    );
}

#[test]
fn a_restore_answered_not_restored_never_signs_a_key_a_later_answer_names() {
    // The registration that restored Ada's phone answered "not restored", and
    // the client noted that as an empty answer (docs/identity.md
    // §RevokeDevice): the restore is answered, with nothing to sign.
    let server = issuer();
    let mut phone = client(&server, 2, "actor-ada", "device-ada-phone");
    assert_eq!(answered(&mut phone, NOW, &[]), 0);
    // A renewal later answers "restored" and names the laptop Ada linked
    // since; the server lists that key revoked inside the band.
    assert_eq!(answered(&mut phone, NOW, &[public(1)]), 0);
    let laptop = serde_json::json!({"id": "device-ada-laptop", "signingKey": hex(&public(1)),
        "revoked": true, "revokedAt": NOW + 600});
    let me = serde_json::json!({"id": "device-ada-phone", "signingKey": hex(&public(2))});
    assert!(restore_signed(&mut phone, NOW, serde_json::json!([laptop, me])).is_empty());
    // And the phone still approves it: the empty answer signed nothing out.
    assert_eq!(
        phone
            .sign_own_device_approval("device-ada-laptop", &public(1), NOW)
            .unwrap()
            .len(),
        64
    );
}

#[test]
fn a_stalled_list_read_signs_no_device_linked_after_the_restore() {
    // Ada's phone restored, but kept no answer from that registration (the
    // answer was lost). The server fails every list read
    // until Ada links her laptop, the next step after a restore.
    let server = issuer();
    let mut phone = client(&server, 2, "actor-ada", "device-ada-phone");
    let laptop = client(&server, 1, "actor-ada", "device-ada-laptop");
    let me = serde_json::json!({"id": "device-ada-phone", "signingKey": hex(&public(2))});
    let laptop_signed_out = serde_json::json!({"id": "device-ada-laptop",
        "signingKey": hex(&public(1)), "revoked": true, "revokedAt": NOW + 600});
    // With no answer kept, the first read the server allows signs nothing,
    // whatever it lists.
    assert!(restore_signed(&mut phone, NOW, serde_json::json!([laptop_signed_out, me])).is_empty());
    // The phone approves the laptop, and the approval closes the restore.
    let approval = phone
        .sign_own_device_approval("device-ada-laptop", &public(1), NOW)
        .unwrap();
    assert_eq!(approval.len(), 64);
    // An answer that turns up after it is not taken.
    assert_eq!(answered(&mut phone, NOW, &[public(1)]), 0);
    // Approved but not yet seated: the next read lists the laptop's key
    // revoked inside the band, and the phone still signs nothing.
    assert!(restore_signed(&mut phone, NOW, serde_json::json!([laptop_signed_out, me])).is_empty());
    drop(laptop);
}

#[test]
fn a_device_waiting_at_the_restore_is_never_approved_once_signed_out() {
    // Ada's laptop was waiting for an approval when she restored her phone
    // from her PIN. The server kept the laptop waiting, and named its key in
    // the restoring registration's answer as signed out.
    let server = issuer();
    let mut phone = client(&server, 2, "actor-ada", "device-ada-phone");
    answered(&mut phone, NOW, &[public(1)]);
    // Before the phone signs anything, the key it took as signed out is not
    // approved.
    assert!(phone
        .sign_own_device_approval("device-ada-laptop", &public(1), NOW)
        .is_err());
    let laptop = serde_json::json!({"id": "device-ada-laptop", "signingKey": hex(&public(1)),
        "revoked": true, "revokedAt": NOW + 10});
    assert_eq!(
        restore_signed(&mut phone, NOW, serde_json::json!([laptop])),
        ["device-ada-laptop"]
    );
    // Nor once it has signed its revocation, under any id: the laptop starts
    // over under a new key, and the signature names nobody in use.
    assert!(phone
        .sign_own_device_approval("device-ada-laptop", &public(1), NOW)
        .is_err());
    assert!(phone
        .sign_own_device_approval("device-ada-laptop-2", &public(1), 0)
        .is_err());
    assert!(phone
        .sign_own_device_approval("device-ada-laptop", &public(6), NOW)
        .is_ok());
}

#[test]
fn a_device_never_approves_a_key_it_signed_or_forgot() {
    let mut phone = ada_phone_with_laptop_on_its_chain();
    let honest = [
        ("laptop-plain", "", None),
        ("device-ada-laptop", "laptop-plain", Some(public(1))),
    ];
    phone.note_own_install_links(&list(&honest)).unwrap();
    assert_eq!(
        signed(&mut phone, "laptop-plain", false, &honest),
        ["device-ada-laptop"]
    );
    assert!(phone
        .sign_own_device_approval("device-ada-laptop", &public(1), 0)
        .is_err());
    // A device it forgot, whose revocation it never signed.
    let server = issuer();
    let mut other = client(&server, 2, "actor-ada", "device-ada-phone");
    other
        .forget_own_device_with_key("device-ada-tablet", &public(5))
        .unwrap();
    assert!(other
        .sign_own_device_approval("device-ada-tablet", &public(5), 0)
        .is_err());
    assert!(other
        .sign_own_device_approval("device-ada-new", &public(6), 0)
        .is_ok());
}

#[test]
fn an_approval_is_the_one_the_devices_seed_makes() {
    let server = issuer();
    let mut phone = client(&server, 2, "actor-ada", "device-ada-phone");
    let approval = phone
        .sign_own_device_approval("device-ada-laptop", &public(1), 0)
        .unwrap();
    assert_eq!(
        approval,
        peachy_mls_core::sign_device_approval(&device_seed(2), "device-ada-laptop", &public(1))
            .unwrap()
            .to_vec()
    );
}

#[test]
fn a_pin_restore_never_signs_a_key_on_this_devices_chain() {
    // After the restore (its answer named the tablet), the phone approves the
    // laptop and seats it from that approval, the way every client does: the
    // laptop's key is on its chain now. A list that names it revoked in the
    // band, under its own id or another, gets no signature of it.
    let server = issuer();
    let mut phone = client(&server, 2, "actor-ada", "device-ada-phone");
    let laptop = client(&server, 1, "actor-ada", "device-ada-laptop");
    answered(&mut phone, NOW, &[public(5)]);
    let approval = phone
        .sign_own_device_approval("device-ada-laptop", &public(1), NOW)
        .unwrap();
    let key_package = laptop.generate_key_package().unwrap();
    assert_eq!(
        phone.check_own_device_approval(&key_package, "device-ada-phone", &approval),
        peachy_mls_core::OwnDeviceVerdict::Approved
    );
    assert_eq!(
        phone.check_own_device_key("device-ada-laptop", &public(1), "", &[]),
        peachy_mls_core::OwnDeviceVerdict::Known
    );
    let rows = serde_json::json!([
        {"id": "device-ada-laptop", "signingKey": hex(&public(1)), "revoked": true, "revokedAt": NOW + 10},
        {"id": "device-other", "signingKey": hex(&public(1)), "revoked": true, "revokedAt": NOW + 10},
        {"id": "device-ada-tablet", "signingKey": hex(&public(5)), "revoked": true, "revokedAt": NOW + 10},
    ]);
    assert_eq!(restore_signed(&mut phone, NOW, rows), ["device-ada-tablet"]);
}

#[test]
fn a_restore_snapshot_survives_the_client_and_belongs_to_its_restore() {
    // The snapshot is kept in the store: a client opened again on it signs
    // only what the restore's answer named, and a later restore keeps its own.
    let kv = MemoryKv::new();
    let on = |kv: &MemoryKv| {
        support::client_on(
            &issuer(),
            2,
            "actor-ada",
            "device-ada-phone",
            PeachyStorage::open(Box::new(kv.clone())).unwrap(),
        )
    };
    let mut phone = on(&kv);
    answered(&mut phone, NOW, &[public(1)]);
    let laptop = serde_json::json!({"id": "device-ada-laptop", "signingKey": hex(&public(1)),
        "revoked": true, "revokedAt": NOW + 10});
    let tablet = serde_json::json!({"id": "device-ada-tablet", "signingKey": hex(&public(5)),
        "revoked": true, "revokedAt": NOW + 600});
    drop(phone);
    let mut reopened = on(&kv);
    assert_eq!(
        restore_signed(&mut reopened, NOW, serde_json::json!([laptop, tablet])),
        ["device-ada-laptop"]
    );
    // A second restore a day later keeps its own answer and reads its own
    // band.
    answered(&mut reopened, NOW + DAY, &[public(5)]);
    let tablet_later = serde_json::json!({"id": "device-ada-tablet", "signingKey": hex(&public(5)),
        "revoked": true, "revokedAt": NOW + DAY + 10});
    assert_eq!(
        restore_signed(
            &mut reopened,
            NOW + DAY,
            serde_json::json!([laptop, tablet_later])
        ),
        ["device-ada-tablet"]
    );
}

#[test]
fn every_own_device_door_reads_only_objects_a_json_value_holds() {
    // What a struct reader would take and no other reader reads alike: a
    // request, a row or an answer written as an array, field by field, and
    // a number no JSON value holds in a field the core does not read.
    let mut phone = ada_phone_with_laptop_on_its_chain();
    let account = TestIssuer::test_account_key("actor-ada");
    let laptop = hex(&public(1));
    let row = format!("[\"device-ada-laptop\",\"laptop-plain\",\"{laptop}\"]");
    for rows in [
        format!("[{row}]"),
        "[{\"id\":\"device-ada-laptop\",\"twinOf\":\"laptop-plain\",\"x\":1e400}]".to_string(),
    ] {
        assert!(phone.note_own_install_links(&rows).is_err(), "{rows}");
    }
    let object_row = format!("{{\"id\":\"device-ada-laptop\",\"signingKey\":\"{laptop}\"}}");
    for request in [
        format!("[\"device-ada-laptop\",false,[],[],[{object_row}],0]"),
        format!("{{\"named\":\"device-ada-laptop\",\"rows\":[{row}]}}"),
        format!("{{\"named\":\"device-ada-laptop\",\"rows\":[{object_row}],\"x\":1e400}}"),
    ] {
        assert!(
            phone.sign_install_revocations(&account, &request).is_err(),
            "{request}"
        );
    }
    for answer in [
        format!("[{NOW},[\"{laptop}\"]]"),
        format!("{{\"restoredSince\":{NOW},\"keys\":[\"{laptop}\"],\"x\":1e400}}"),
    ] {
        assert!(phone.note_restore_signed_out(&answer).is_err(), "{answer}");
    }
    // Nothing was signed out, and the same request as objects signs.
    let request = format!("{{\"named\":\"device-ada-laptop\",\"rows\":[{object_row}]}}");
    let out = phone.sign_install_revocations(&account, &request).unwrap();
    assert!(out.contains("device-ada-laptop"), "{out}");
}

/// The refusal the delivery service switched on (`signed_revocations`,
/// `Client::adopt_client_refusals`) holds the sibling rule back at once, and
/// a later list that leaves it out does not let it go again.
#[test]
fn a_switched_on_signed_revocations_refusal_keeps_the_sibling_and_stays_on() {
    let (mut bo, phone_leaf, _) = group();
    assert_eq!(
        bo.stale_leaf_removable(G, phone_leaf, &[], 0).unwrap(),
        !SIGNED_REVOCATIONS_ENFORCED
    );
    assert!(bo.adopt_client_refusals(&["no_such_refusal"]).is_empty());
    assert_eq!(
        bo.adopt_client_refusals(&["signed_revocations"]),
        vec!["signed_revocations".to_string()]
    );
    assert!(bo.client_refusal_on("signed_revocations"));
    assert!(!bo.stale_leaf_removable(G, phone_leaf, &[], 0).unwrap());
    let key = leaf_key(&bo, phone_leaf);
    assert!(bo
        .remove_stale_leaf(G, phone_leaf, &key, &[], 0)
        .unwrap()
        .is_none());
    // The server leaves it out: still on.
    bo.adopt_client_refusals(&[] as &[&str]);
    assert!(!bo.stale_leaf_removable(G, phone_leaf, &[], 0).unwrap());
    // Ada's own account's signed revocation still lets the phone go.
    let revocation =
        sign_device_revocation(&TestIssuer::test_account_key("actor-ada"), &public(2)).unwrap();
    assert!(bo
        .stale_leaf_removable(G, phone_leaf, &revocation, 0)
        .unwrap());
}
