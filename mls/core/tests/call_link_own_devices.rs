// SPDX-License-Identifier: MIT
//! A call link's group lives in a second core on the device: in memory, with
//! the device's own credential and key, holding none of the main core's
//! records (docs/calls.md §Call links on participant keys). The main
//! core hands it what it holds (`Client::own_device_trust`), the link's core
//! adopts it (`Client::adopt_own_device_trust`), and from then on the
//! own-device checks run there too:
//!
//! - **Its adds seat no forgotten device** of the account, by id or key.
//! - **A forgotten device's Welcome seats this device in nothing.**
//! - **A forgotten device's approval vouches for nobody**; an approval by a
//!   device on the main core's chain does.
//! - **An own leaf on no chain is not the person's**
//!   (`Client::own_device_standing`): only this device and devices on the
//!   chain count as the person in the call.
//! - **A core adopts only its own device's trust**, whole or not at all;
//!   forgotten ids and keys accumulate across adoptions.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;

use peachy_mls_core::issuer::device_key_pair;
use peachy_mls_core::{sign_device_approval, Client, Error, OwnDeviceStanding, OwnDeviceVerdict};
use support::{client, device_seed, issuer, past_the_mark};

/// The call link's group.
const L: &[u8] = b"88888888-8888-4888-8888-888888888888";

fn public(tag: u8) -> [u8; 32] {
    device_key_pair(&device_seed(tag)).1
}

fn approval(approver_tag: u8, device_id: &str, device_tag: u8) -> Vec<u8> {
    sign_device_approval(&device_seed(approver_tag), device_id, &public(device_tag))
        .unwrap()
        .to_vec()
}

/// Ada's laptop (tag 1) was let in by her desktop (tag 6) and verified the
/// phone's (tag 2) approval by the desktop. Then the phone is stolen and
/// removed: the laptop's main core forgets it under the key it saw.
fn laptop_main_core() -> Client {
    let server = issuer();
    let mut laptop = client(&server, 1, "actor-ada", "device-ada-laptop");
    laptop
        .remember_own_approver("device-ada-desktop", &public(6))
        .unwrap();
    let phone = client(&server, 2, "actor-ada", "device-ada-phone");
    assert_eq!(
        laptop.check_own_device_approval(
            &phone.generate_key_package().unwrap(),
            "device-ada-desktop",
            &approval(6, "device-ada-phone", 2),
        ),
        OwnDeviceVerdict::Approved
    );
    assert!(laptop
        .forget_own_device_with_key("device-ada-phone", &public(2))
        .unwrap());
    laptop
}

/// The laptop's call link core: the same credential and key, a fresh store.
fn link_core() -> Client {
    client(&issuer(), 1, "actor-ada", "device-ada-laptop")
}

fn adopted_link_core(main: &Client) -> Client {
    let mut link = link_core();
    link.adopt_own_device_trust(&main.own_device_trust().unwrap())
        .unwrap();
    link
}

#[test]
fn a_link_core_that_adopted_nothing_would_seat_the_removed_phone() {
    // The gap this closes: on its own records the link's core knows nothing
    // of the removal.
    let server = issuer();
    let mut link = link_core();
    let phone = client(&server, 2, "actor-ada", "device-ada-phone");
    link.create_group(L).unwrap();
    assert!(link
        .add_member(L, &phone.generate_key_package().unwrap())
        .is_ok());
}

#[test]
fn the_link_cores_add_refuses_a_forgotten_own_device() {
    let main = laptop_main_core();
    let server = issuer();
    let mut link = adopted_link_core(&main);
    link.create_group(L).unwrap();
    let phone = client(&server, 2, "actor-ada", "device-ada-phone");
    assert!(link
        .add_member(L, &phone.generate_key_package().unwrap())
        .is_err());
    // Its key under an id the server chose is the same removed device.
    let ghost = client(&server, 2, "actor-ada", "device-ada-ghost");
    assert!(link
        .add_member(L, &ghost.generate_key_package().unwrap())
        .is_err());
    // Nothing was seated: the group is still the laptop alone.
    assert_eq!(link.roster(L).unwrap().len(), 1);
    // A device on the chain is seated as before.
    let desktop = client(&server, 6, "actor-ada", "device-ada-desktop");
    assert!(link
        .add_member(L, &desktop.generate_key_package().unwrap())
        .is_ok());
}

#[test]
fn a_forgotten_devices_welcome_seats_the_link_core_in_nothing() {
    let main = laptop_main_core();
    let server = issuer();
    let mut phone = client(&server, 2, "actor-ada", "device-ada-phone");
    phone.create_group(L).unwrap();
    past_the_mark(&mut phone, L);

    // Without the main core's records the link core would take it.
    let mut bare = link_core();
    let by_phone = phone
        .add_member(L, &bare.generate_key_package().unwrap())
        .unwrap();
    phone.merge_pending_commit(L).unwrap();
    assert!(bare.join_from_welcome(&by_phone.welcome.unwrap()).is_ok());

    // Having adopted them it refuses, as the main core does.
    let mut phone = client(&server, 2, "actor-ada", "device-ada-phone");
    phone.create_group(L).unwrap();
    past_the_mark(&mut phone, L);
    let mut link = adopted_link_core(&main);
    let by_phone = phone
        .add_member(L, &link.generate_key_package().unwrap())
        .unwrap();
    phone.merge_pending_commit(L).unwrap();
    assert!(matches!(
        link.join_from_welcome(&by_phone.welcome.unwrap()),
        Err(Error::WelcomeFromOutsider)
    ));
    assert!(!link.is_active(L).unwrap_or(false));
}

#[test]
fn a_forgotten_devices_approval_counts_for_nothing_in_the_link_core() {
    let main = laptop_main_core();
    let server = issuer();
    let mut link = adopted_link_core(&main);
    let next = client(&server, 9, "actor-ada", "device-ada-next");
    let kp = next.generate_key_package().unwrap();
    assert_eq!(
        link.check_own_device_approval(&kp, "device-ada-phone", &approval(2, "device-ada-next", 9)),
        OwnDeviceVerdict::Unanchored
    );
    // The desktop is on the chain the link core adopted: its approval vouches.
    let mut link = adopted_link_core(&main);
    let kp = next.generate_key_package().unwrap();
    assert_eq!(
        link.check_own_device_approval(
            &kp,
            "device-ada-desktop",
            &approval(6, "device-ada-next", 9)
        ),
        OwnDeviceVerdict::Approved
    );
}

#[test]
fn an_own_leaf_on_no_chain_is_not_counted_as_the_person() {
    let main = laptop_main_core();
    let server = issuer();
    let mut link = adopted_link_core(&main);
    let mut bo = client(&server, 3, "actor-bo", "device-bo");
    let mut tablet = client(&server, 5, "actor-ada", "device-ada-tablet");

    // Bo founds the call and seats the laptop, then a tablet of Ada's that no
    // device on her chain ever approved.
    bo.create_group(L).unwrap();
    let kp = link.generate_key_package().unwrap();
    let to_link = bo.add_member(L, &kp).unwrap();
    bo.merge_pending_commit(L).unwrap();
    link.join_from_welcome(&to_link.welcome.unwrap()).unwrap();
    let kp = tablet.generate_key_package().unwrap();
    let to_tablet = bo.add_member(L, &kp).unwrap();
    bo.merge_pending_commit(L).unwrap();
    link.process_commit(L, &to_tablet.commit).unwrap();
    tablet
        .join_from_welcome(&to_tablet.welcome.unwrap())
        .unwrap();

    let standing = |link: &Client, actor: &str, device: &str, tag: u8| {
        link.own_device_standing(actor, device, &public(tag))
    };
    // Every leaf of the call, as the screen asks of it.
    let mut seen = Vec::new();
    for entry in link.roster(L).unwrap() {
        let identity = entry.identity.unwrap();
        seen.push((
            identity.device_id.clone(),
            link.own_device_standing(
                &identity.actor_id,
                &identity.device_id,
                &identity.device_key,
            ),
        ));
    }
    assert!(seen.contains(&("device-bo".into(), OwnDeviceStanding::NotOwn)));
    assert!(seen.contains(&("device-ada-laptop".into(), OwnDeviceStanding::ThisDevice)));
    assert!(seen.contains(&("device-ada-tablet".into(), OwnDeviceStanding::OffChain)));
    assert!(!OwnDeviceStanding::OffChain.counts_as_own());

    assert_eq!(
        standing(&link, "actor-ada", "device-ada-desktop", 6),
        OwnDeviceStanding::OnChain
    );
    assert!(OwnDeviceStanding::OnChain.counts_as_own());
    assert_eq!(
        standing(&link, "actor-ada", "device-ada-phone", 2),
        OwnDeviceStanding::Forgotten
    );
    assert_eq!(
        standing(&link, "actor-ada", "device-ada-ghost", 2),
        OwnDeviceStanding::Forgotten
    );
    // This device's id under another key, or its key under another id, is
    // never this device.
    assert_eq!(
        standing(&link, "actor-ada", "device-ada-laptop", 7),
        OwnDeviceStanding::OffChain
    );
    assert_eq!(
        standing(&link, "actor-ada", "device-ada-twin", 1),
        OwnDeviceStanding::OffChain
    );
    // Before adopting, only this device is the person's.
    let bare = link_core();
    assert_eq!(
        standing(&bare, "actor-ada", "device-ada-desktop", 6),
        OwnDeviceStanding::OffChain
    );
    assert_eq!(
        standing(&bare, "actor-ada", "device-ada-laptop", 1),
        OwnDeviceStanding::ThisDevice
    );
}

#[test]
fn a_commit_seating_a_forgotten_device_puts_it_nowhere_near_the_chain() {
    let main = laptop_main_core();
    let server = issuer();
    let mut link = adopted_link_core(&main);
    let mut bo = client(&server, 3, "actor-bo", "device-bo");
    let phone = client(&server, 2, "actor-ada", "device-ada-phone");
    bo.create_group(L).unwrap();
    let to_link = bo
        .add_member(L, &link.generate_key_package().unwrap())
        .unwrap();
    bo.merge_pending_commit(L).unwrap();
    link.join_from_welcome(&to_link.welcome.unwrap()).unwrap();
    // Bo seats the stolen phone on its certificate, as any contact can.
    let to_phone = bo
        .add_member(L, &phone.generate_key_package().unwrap())
        .unwrap();
    bo.merge_pending_commit(L).unwrap();
    link.process_commit(L, &to_phone.commit).unwrap();
    assert_eq!(
        link.own_device_standing("actor-ada", "device-ada-phone", &public(2)),
        OwnDeviceStanding::Forgotten
    );
    assert!(!link
        .own_device_anchors()
        .unwrap()
        .iter()
        .any(|(id, key)| id == "device-ada-phone" || key.as_slice() == public(2)));
}

#[test]
fn a_core_adopts_only_its_own_devices_trust_and_only_whole() {
    let server = issuer();
    let mut main = laptop_main_core();
    let mut link = link_core();
    let form = main.own_device_trust().unwrap();

    // Another device's form, even of the same account, is refused.
    let tablet = client(&server, 5, "actor-ada", "device-ada-tablet");
    assert!(link
        .adopt_own_device_trust(&tablet.own_device_trust().unwrap())
        .is_err());
    // As is the same id under another key.
    let impostor = client(&server, 7, "actor-ada", "device-ada-laptop");
    assert!(link
        .adopt_own_device_trust(&impostor.own_device_trust().unwrap())
        .is_err());
    // A version this build does not read, or a malformed entry, adopts
    // nothing at all.
    let mut v2: serde_json::Value = serde_json::from_str(&form).unwrap();
    v2["v"] = 2.into();
    assert!(link.adopt_own_device_trust(&v2.to_string()).is_err());
    let mut bad: serde_json::Value = serde_json::from_str(&form).unwrap();
    bad["forgottenKeys"]
        .as_array_mut()
        .unwrap()
        .push("not-hex".into());
    assert!(link.adopt_own_device_trust(&bad.to_string()).is_err());
    assert!(link.adopt_own_device_trust("not json").is_err());
    assert_eq!(
        link.own_device_standing("actor-ada", "device-ada-phone", &public(2)),
        OwnDeviceStanding::OffChain
    );

    // The form names no anchor that is this device, and the phone's key.
    let parsed: serde_json::Value = serde_json::from_str(&form).unwrap();
    assert!(parsed["anchors"]
        .as_array()
        .unwrap()
        .iter()
        .all(|a| a["deviceId"] != "device-ada-laptop"));
    assert!(parsed["forgottenDevices"]
        .as_array()
        .unwrap()
        .contains(&"device-ada-phone".into()));

    link.adopt_own_device_trust(&form).unwrap();
    assert_eq!(
        link.own_device_standing("actor-ada", "device-ada-phone", &public(2)),
        OwnDeviceStanding::Forgotten
    );

    // The main core forgets the desktop next. Adopting again takes it off the
    // link core's chain, and keeps the phone forgotten.
    assert!(main
        .forget_own_device_with_key("device-ada-desktop", &public(6))
        .unwrap());
    link.adopt_own_device_trust(&main.own_device_trust().unwrap())
        .unwrap();
    assert_eq!(
        link.own_device_standing("actor-ada", "device-ada-desktop", &public(6)),
        OwnDeviceStanding::Forgotten
    );
    assert_eq!(
        link.own_device_standing("actor-ada", "device-ada-phone", &public(2)),
        OwnDeviceStanding::Forgotten
    );
    // Forgotten entries accumulate: an older form forgets nothing back.
    link.adopt_own_device_trust(&form).unwrap();
    assert_eq!(
        link.own_device_standing("actor-ada", "device-ada-desktop", &public(6)),
        OwnDeviceStanding::Forgotten
    );
}
