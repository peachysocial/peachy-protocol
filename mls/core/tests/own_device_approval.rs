// SPDX-License-Identifier: MIT
//! Seating a sibling needs an approval from a device the adder already trusts
//! (docs/identity.md §What the adder checks).
//!
//! The account key never rotates when a device is removed, and the account's
//! certificate on a device key is something any holder of the account key can
//! make. A removed laptop keeps the key. Before this check, it could certify a
//! fresh device key, register it from a new sign-in, and the person's own
//! phone would seat it in every group with nothing any peer could see: the
//! identity key is the person's own. These tests hold the opposite.

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use peachy_mls_core::issuer::{device_key_pair, TestIssuer};
use peachy_mls_core::{
    account_identity_public_key, generate_account_key, sign_account_device, sign_device_approval,
    verify_account_device, Client, ClientConfig, FixedClock, OwnDeviceVerdict, PeachyStorage,
};
use support::{device_seed, issuer, DAY, HOUR, NOW};

const GROUP: &[u8] = b"peachy-own-device-approval";

/// A client whose credential carries the account's certificate, which is what
/// the server issues after `RegisterDevice` with a valid account signature.
fn certified(
    server: &TestIssuer,
    seed: [u8; 32],
    actor: &str,
    device: &str,
    account_key: &[u8; 32],
) -> Client {
    let (_, public) = device_key_pair(&seed);
    let token = server
        .issue_for_account(
            actor,
            device,
            &public,
            Some(account_key.as_slice()),
            NOW - HOUR,
            NOW + 30 * DAY,
        )
        .expect("certified");
    let mut config = ClientConfig::new(token, seed, server.trusted_keys().expect("keys"))
        .with_storage(PeachyStorage::in_memory())
        .with_own_account_identity(Some(
            account_identity_public_key(account_key).expect("derive"),
        ));
    config.clock = Some(Box::new(FixedClock(NOW)));
    Client::new(config).expect("client")
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

fn public(seed: &[u8; 32]) -> [u8; 32] {
    device_key_pair(seed).1
}

/// A removed device's retained key vouches for nobody: the laptop is let in
/// by the phone, is removed, and its retained account key certifies a new
/// device. The phone refuses to seat that device, with or without an approval signed by the
/// removed laptop's own key.
#[test]
fn a_removed_device_s_retained_key_cannot_get_a_new_device_seated() {
    let server = issuer();
    let account_key = generate_account_key().expect("account key");

    let phone_seed = device_seed(1);
    let mut phone = certified(
        &server,
        phone_seed,
        "actor-ada",
        "device-ada-phone",
        &account_key,
    );

    // The phone lets the laptop in: an approval over the laptop's id and key.
    let laptop_seed = device_seed(2);
    let laptop_approval =
        sign_device_approval(&phone_seed, "device-ada-laptop", &public(&laptop_seed))
            .expect("approve");
    let mut laptop = certified(
        &server,
        laptop_seed,
        "actor-ada",
        "device-ada-laptop",
        &account_key,
    );

    let mut bo = certified(
        &server,
        device_seed(3),
        "actor-bo",
        "device-bo-phone",
        &[0xb0; 32],
    );
    phone.create_group(GROUP).expect("create");
    add(&mut phone, &mut bo, GROUP);

    // An honest sibling: the phone approved it, so the phone seats it.
    let laptop_kp = laptop.generate_key_package().expect("kp");
    assert_eq!(
        phone.check_own_device_approval(&laptop_kp, "device-ada-phone", &laptop_approval),
        OwnDeviceVerdict::Approved
    );
    let seat_laptop = add(&mut phone, &mut laptop, GROUP);
    bo.process_commit(GROUP, &seat_laptop).expect("bo applies");

    // The laptop is stolen and removed: the phone forgets it, and its leaf
    // leaves the group.
    assert!(phone
        .forget_own_device_with_key("device-ada-laptop", &public(&laptop_seed))
        .expect("forget"));
    let leaf = phone
        .leaf_of_device(GROUP, "device-ada-laptop")
        .expect("leaf");
    let removal = phone.remove_leaf(GROUP, leaf).expect("remove");
    phone.merge_pending_commit(GROUP).expect("merge");
    bo.process_commit(GROUP, &removal.commit)
        .expect("bo applies removal");

    // The thief: a fresh device key, certified under the retained account key.
    let thief_seed = device_seed(9);
    let signature = sign_account_device(&account_key, &public(&thief_seed)).expect("sign");
    let identity = account_identity_public_key(&account_key).expect("identity");
    assert!(verify_account_device(
        &identity,
        &public(&thief_seed),
        &signature
    ));
    let mut thief = certified(
        &server,
        thief_seed,
        "actor-ada",
        "device-ada-thief",
        &account_key,
    );
    let thief_kp = thief.generate_key_package().expect("kp");
    assert!(
        phone
            .key_package_identity(&thief_kp)
            .expect("parses")
            .is_ok(),
        "the certificate alone verifies: that is the hole this check closes"
    );

    // No approval at all.
    assert_eq!(
        phone.check_own_device_approval(&thief_kp, "", &[]),
        OwnDeviceVerdict::Unanchored
    );
    // An approval the stolen laptop signs with its own device key: the
    // phone forgot the laptop, so it vouches for nobody.
    let by_laptop =
        sign_device_approval(&laptop_seed, "device-ada-thief", &public(&thief_seed)).expect("sign");
    assert_eq!(
        phone.check_own_device_approval(&thief_kp, "device-ada-laptop", &by_laptop),
        OwnDeviceVerdict::Unanchored
    );
    // An approval that claims the phone, signed by somebody else.
    assert_eq!(
        phone.check_own_device_approval(&thief_kp, "device-ada-phone", &by_laptop),
        OwnDeviceVerdict::BadApproval
    );
    // The phone's real approval of the LAPTOP, moved onto the thief's package.
    assert_eq!(
        phone.check_own_device_approval(&thief_kp, "device-ada-phone", &laptop_approval),
        OwnDeviceVerdict::BadApproval
    );
    let _ = &mut thief;
}

/// Approvals chain through leaves the adder can see: the laptop let in the
/// tablet, and the phone, sharing a group with the laptop, seats the tablet.
#[test]
fn an_approval_by_a_sibling_seated_in_any_held_group_is_trusted() {
    let server = issuer();
    let account_key = generate_account_key().expect("account key");
    let phone_seed = device_seed(1);
    let laptop_seed = device_seed(2);
    let tablet_seed = device_seed(4);
    let mut phone = certified(
        &server,
        phone_seed,
        "actor-ada",
        "device-ada-phone",
        &account_key,
    );
    let mut laptop = certified(
        &server,
        laptop_seed,
        "actor-ada",
        "device-ada-laptop",
        &account_key,
    );
    let tablet = certified(
        &server,
        tablet_seed,
        "actor-ada",
        "device-ada-tablet",
        &account_key,
    );

    // The phone approved the laptop and checks that approval before it
    // seats it: an own add on no seating verdict anchors nothing.
    let by_phone = sign_device_approval(&phone_seed, "device-ada-laptop", &public(&laptop_seed))
        .expect("sign");
    let laptop_first_kp = laptop.generate_key_package().expect("kp");
    assert_eq!(
        phone.check_own_device_approval(&laptop_first_kp, "device-ada-phone", &by_phone),
        OwnDeviceVerdict::Approved
    );
    phone.create_group(b"with-laptop").expect("create");
    add(&mut phone, &mut laptop, b"with-laptop");
    phone.create_group(b"phone-only").expect("create");

    let by_laptop = sign_device_approval(&laptop_seed, "device-ada-tablet", &public(&tablet_seed))
        .expect("sign");
    let tablet_kp = tablet.generate_key_package().expect("kp");
    // The laptop is a leaf of another group the phone holds: anchored.
    assert_eq!(
        phone.check_own_device_approval(&tablet_kp, "device-ada-laptop", &by_laptop),
        OwnDeviceVerdict::Approved
    );
    // What the phone has seen of its own account: the laptop, once.
    assert_eq!(
        phone.own_sibling_leaves().expect("leaves"),
        vec!["device-ada-laptop".to_string()]
    );
    // A device that is already a leaf, same key, needs no approval.
    let laptop_kp = laptop.generate_key_package().expect("kp");
    assert_eq!(
        phone.check_own_device_approval(&laptop_kp, "", &[]),
        OwnDeviceVerdict::Known
    );
    // Another person's device, and this device itself, are not this check's.
    let bo = certified(
        &server,
        device_seed(3),
        "actor-bo",
        "device-bo-phone",
        &[0xb0; 32],
    );
    assert_eq!(
        phone.check_own_device_approval(&bo.generate_key_package().expect("kp"), "", &[]),
        OwnDeviceVerdict::NotOwnDevice
    );
    assert_eq!(
        phone.check_own_device_approval(&phone.generate_key_package().expect("kp"), "", &[]),
        OwnDeviceVerdict::NotOwnDevice
    );
}

/// The account's first device has no approval. A new device knows it as the
/// device that let it in, before the two share any group, so its first
/// conversation still reaches the phone.
#[test]
fn the_device_that_let_this_one_in_is_trusted_before_any_group_is_shared() {
    let server = issuer();
    let account_key = generate_account_key().expect("account key");
    let phone_seed = device_seed(1);
    let laptop_seed = device_seed(2);
    let phone = certified(
        &server,
        phone_seed,
        "actor-ada",
        "device-ada-phone",
        &account_key,
    );
    let mut laptop = certified(
        &server,
        laptop_seed,
        "actor-ada",
        "device-ada-laptop",
        &account_key,
    );
    let phone_kp = phone.generate_key_package().expect("kp");

    assert_eq!(
        laptop.check_own_device_approval(&phone_kp, "", &[]),
        OwnDeviceVerdict::Unanchored,
        "a root device nobody vouched for is not seated by a stranger to it"
    );
    laptop
        .remember_own_approver("device-ada-phone", &public(&phone_seed))
        .expect("remember");
    assert_eq!(
        laptop.check_own_device_approval(&phone_kp, "", &[]),
        OwnDeviceVerdict::Known
    );
    // The remembered approver vouches only under its own key.
    let impostor = certified(
        &server,
        device_seed(7),
        "actor-ada",
        "device-ada-phone",
        &account_key,
    );
    assert_eq!(
        laptop.check_own_device_approval(&impostor.generate_key_package().expect("kp"), "", &[]),
        OwnDeviceVerdict::Unanchored
    );
    assert!(laptop
        .remember_own_approver("", &public(&phone_seed))
        .is_err());
    assert!(laptop
        .remember_own_approver("device-ada-phone", &[1, 2, 3])
        .is_err());
}

#[test]
fn verdict_codes_are_stable() {
    let codes: Vec<(u32, &str, bool)> = OwnDeviceVerdict::ALL
        .iter()
        .map(|v| (v.code(), v.name(), v.seats()))
        .collect();
    assert_eq!(
        codes,
        vec![
            (0, "known", true),
            (1, "approved", true),
            (2, "unanchored", false),
            (3, "bad_approval", false),
            (4, "not_own_device", false),
            (5, "credential_rejected", false),
        ]
    );
}
