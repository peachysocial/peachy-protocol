// SPDX-License-Identifier: MIT
//! A device hands its account's history only to a sibling its own devices
//! vouch for (docs/sealed-messages.md §Handing history to your own
//! new device).
//!
//! A row the device list shows live, approved and certified need not be one a
//! device of the account let in, and those flags are all a self-note sender
//! needs, so an ask for history from such a row opens and names its own
//! sender. These tests hold that the answer now turns on
//! `check_own_device_key`, the seat check's evidence, and that every verdict
//! but `known` and `approved` gets the nothing-to-send note
//! (`mls/fixtures/formats/self-note-trust.json`, `answers`).

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;

use peachy_mls_core::issuer::{device_key_pair, TestIssuer};
use peachy_mls_core::{
    account_identity_public_key, generate_account_key, note_open_signed, note_seal_signed,
    note_sender, sign_account_device, sign_device_approval, verify_account_device, Client,
    ClientConfig, FixedClock, OwnDeviceVerdict, PeachyStorage,
};
use support::{device_seed, issuer, DAY, HOUR, NOW};

const NOW_MS: i64 = NOW * 1000;

fn device_on_account(server: &TestIssuer, tag: u8, device: &str, account: &[u8]) -> Client {
    let seed = device_seed(tag);
    let (_, public) = device_key_pair(&seed);
    let token = server
        .issue_for_account(
            "actor-ada",
            device,
            &public,
            Some(account),
            NOW - HOUR,
            NOW + 30 * DAY,
        )
        .expect("mint");
    let mut config = ClientConfig::new(token, seed, server.trusted_keys().expect("keys"))
        .with_storage(PeachyStorage::in_memory())
        .with_own_account_identity(Some(
            peachy_mls_core::account_identity_public_key(account).expect("derive"),
        ));
    config.clock = Some(Box::new(FixedClock(NOW)));
    Client::new(config).expect("client")
}

fn public(tag: u8) -> [u8; 32] {
    device_key_pair(&device_seed(tag)).1
}

fn table() -> serde_json::Value {
    serde_json::from_str(include_str!("../../fixtures/formats/self-note-trust.json"))
        .expect("fixture")
}

/// What the published table says a device sends a sibling whose own-device
/// verdict is `name`: `"history"` or `"none"`.
fn answer_for(name: &str) -> String {
    let table = table();
    let answers = table["answers"].as_array().expect("answers");
    let case = answers
        .iter()
        .find(|case| case["verdict"] == name)
        .unwrap_or_else(|| panic!("no answer for verdict {name}"));
    case["expect"].as_str().expect("expect").to_owned()
}

/// A row on no chain asks for history with a signed note naming itself. The
/// note opens; the answer is `none`, never the document's pointer.
#[test]
fn a_row_on_no_chain_is_answered_with_nothing() {
    let server = issuer();
    let account_key = generate_account_key().expect("key");

    let mut laptop = device_on_account(&server, 1, "device-ada-laptop", &account_key);
    let phone_key = public(2);
    laptop
        .remember_own_approver("device-ada-phone", &phone_key)
        .expect("remember");
    assert_eq!(
        laptop.check_own_device_key("device-ada-phone", &phone_key, "", &[]),
        OwnDeviceVerdict::Known,
        "before its removal the phone is the device that let the laptop in"
    );

    // Ada removes the phone; the laptop forgets it, by id and key.
    assert!(laptop
        .forget_own_device_with_key("device-ada-phone", &phone_key)
        .expect("forget"));

    // A row certified under the account key, on no chain.
    let new_seed = device_seed(9);
    let new_key = public(9);
    let new_id = "device-ada-new";
    let cert = sign_account_device(&account_key, &new_key).expect("cert");
    assert!(verify_account_device(
        &account_identity_public_key(&account_key).unwrap(),
        &new_key,
        &cert
    ));
    let approval = sign_device_approval(&device_seed(2), new_id, &new_key).expect("approval");

    // Its signed ask opens under the key the list gives, and names its sender.
    let ask_id = [0x51u8; 16];
    let ask = format!(r#"{{"peachy":"history","v":1,"d":"{new_id}","f":0}}"#);
    let note = note_seal_signed(
        &account_key,
        &ask_id,
        ask.as_bytes(),
        new_id,
        NOW_MS,
        &new_seed,
    )
    .expect("seal ask");
    let sender = note_sender(&account_key, &ask_id, &note).expect("sender");
    let opened =
        note_open_signed(&account_key, &ask_id, &note, &sender, &new_key, NOW_MS).expect("open");
    let body: serde_json::Value = serde_json::from_slice(&opened).unwrap();
    assert_eq!(body["d"], sender);

    // The answer: the row's id, key and approval, as the list carries them.
    let verdict = laptop.check_own_device_key(new_id, &new_key, "device-ada-phone", &approval);
    assert_eq!(verdict, OwnDeviceVerdict::Unanchored);
    assert_eq!(
        answer_for(verdict.name()),
        "none",
        "no hand-off to {new_id}"
    );

    // Without an approval, or with one naming the laptop that does not verify.
    assert_eq!(
        laptop.check_own_device_key(new_id, &new_key, "", &[]),
        OwnDeviceVerdict::Unanchored
    );
    let forged = sign_device_approval(&new_seed, new_id, &new_key).expect("self-signed");
    assert_eq!(
        laptop.check_own_device_key(new_id, &new_key, "device-ada-laptop", &forged),
        OwnDeviceVerdict::BadApproval
    );
    assert_eq!(answer_for("bad_approval"), "none");

    // The phone's own id and key are forgotten for good.
    assert_eq!(
        laptop.check_own_device_key("device-ada-phone", &phone_key, "", &[]),
        OwnDeviceVerdict::Unanchored
    );
    // And so is its key under any id the server files it under.
    assert_eq!(
        laptop.check_own_device_key("device-ada-renamed", &phone_key, "", &[]),
        OwnDeviceVerdict::Unanchored
    );

    // The key-package door agrees with the row door on the same device.
    let new_row = device_on_account(&server, 9, new_id, &account_key);
    let package = new_row.generate_key_package().expect("kp");
    assert_eq!(
        laptop.check_own_device_approval(&package, "device-ada-phone", &approval),
        verdict
    );
}

/// A device the person let in from a device on this one's approval chain
/// still gets the hand-off; one it only shares a tree with does not.
#[test]
fn a_sibling_the_person_let_in_gets_the_history() {
    let server = issuer();
    let account_key = generate_account_key().expect("key");
    let mut laptop = device_on_account(&server, 1, "device-ada-laptop", &account_key);

    // Approved by the laptop itself.
    let tablet_key = public(3);
    let by_laptop =
        sign_device_approval(&device_seed(1), "device-ada-tablet", &tablet_key).expect("approve");
    let verdict = laptop.check_own_device_key(
        "device-ada-tablet",
        &tablet_key,
        "device-ada-laptop",
        &by_laptop,
    );
    assert_eq!(verdict, OwnDeviceVerdict::Approved);
    assert_eq!(answer_for(verdict.name()), "history");

    // The same approval over another key is not an approval of that key.
    assert_eq!(
        laptop.check_own_device_key(
            "device-ada-tablet",
            &public(4),
            "device-ada-laptop",
            &by_laptop
        ),
        OwnDeviceVerdict::BadApproval
    );

    // Approved by the device that let the laptop in.
    let phone_key = public(2);
    laptop
        .remember_own_approver("device-ada-phone", &phone_key)
        .expect("remember");
    let watch_key = public(5);
    let by_phone =
        sign_device_approval(&device_seed(2), "device-ada-watch", &watch_key).expect("approve");
    assert_eq!(
        laptop.check_own_device_key(
            "device-ada-watch",
            &watch_key,
            "device-ada-phone",
            &by_phone
        ),
        OwnDeviceVerdict::Approved
    );

    // A leaf of the account in a group the laptop holds, with no approval:
    // the desktop seated the laptop, so the laptop found it in the tree. A
    // tree tells the laptop nothing about who let the desktop in.
    let mut desktop = device_on_account(&server, 6, "device-ada-desktop", &account_key);
    desktop.create_group(b"history-gate").expect("create");
    let package = laptop.generate_key_package().expect("kp");
    let bundle = desktop.add_member(b"history-gate", &package).expect("add");
    desktop
        .merge_pending_commit(b"history-gate")
        .expect("merge");
    laptop
        .join_from_welcome(&bundle.welcome.expect("welcome"))
        .expect("join");
    let verdict = laptop.check_own_device_key("device-ada-desktop", &public(6), "", &[]);
    assert_eq!(verdict, OwnDeviceVerdict::Unanchored);
    assert_eq!(answer_for(verdict.name()), "none");
    // Its approval under a device on the chain still vouches for it.
    let by_phone =
        sign_device_approval(&device_seed(2), "device-ada-desktop", &public(6)).expect("approve");
    assert_eq!(
        laptop.check_own_device_key(
            "device-ada-desktop",
            &public(6),
            "device-ada-phone",
            &by_phone
        ),
        OwnDeviceVerdict::Approved
    );
}

/// Malformed rows, this device itself, and every verdict in the table.
#[test]
fn every_other_verdict_is_answered_with_nothing() {
    let server = issuer();
    let account_key = generate_account_key().expect("key");
    let laptop = device_on_account(&server, 1, "device-ada-laptop", &account_key);

    assert_eq!(
        laptop.check_own_device_key("device-ada-laptop", &public(1), "", &[]),
        OwnDeviceVerdict::NotOwnDevice
    );
    assert_eq!(
        laptop.check_own_device_key("device-ada-twin", &public(1), "", &[]),
        OwnDeviceVerdict::Unanchored,
        "this device's key under another id is not this device"
    );
    assert_eq!(
        laptop.check_own_device_key("device-ada-tablet", &[7u8; 31], "", &[]),
        OwnDeviceVerdict::CredentialRejected
    );
    assert_eq!(
        laptop.check_own_device_key("", &public(3), "", &[]),
        OwnDeviceVerdict::CredentialRejected
    );

    for verdict in OwnDeviceVerdict::ALL {
        let want = if verdict.seats() { "history" } else { "none" };
        assert_eq!(answer_for(verdict.name()), want, "{}", verdict.name());
    }
    // A verdict a build does not know is answered with nothing too.
    let table = table();
    let unknown = table["answers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| {
            OwnDeviceVerdict::ALL
                .iter()
                .all(|v| case["verdict"] != v.name())
        })
        .expect("a case for an unknown verdict");
    assert_eq!(unknown["expect"], "none");
}
