// SPDX-License-Identifier: MIT
//! A new device takes its account key only from a device the person vouched
//! for (mls/core/src/account_store.rs, "The account-key box").
//!
//! The attack these tests hold shut: the server runs a device of its own,
//! lists it as one of the person's approved devices, and seals an account key
//! it chose to the new device. The box is well formed and opens under the key
//! the server listed, and a store sealed under the server's key opens with it,
//! so nothing cryptographic tells the new device it was handed the wrong key.
//! What does is the person: the approver's number they picked on the new
//! device.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use peachy_mls_core::account_store::{
    account_key_accept_hybrid, account_key_open, account_key_seal, account_key_seal_hybrid,
    account_key_seal_linked, store_open, store_seal,
};
use peachy_mls_core::device_link::{
    device_link_approver_number, device_link_commitment, device_link_kem_public_key,
    device_link_number,
};
use peachy_mls_core::issuer::device_key_pair;

const DEVICE_ID: &str = "00000000-0000-4000-8000-000000000004";
const NEW_SEED: [u8; 32] = [0x04; 32];
const NEW_LINK_SEED: [u8; 32] = [0x14; 32];
const ADA_PHONE_SEED: [u8; 32] = [0x11; 32];
const SERVER_DEVICE_SEED: [u8; 32] = [0x55; 32];
const ADAS_KEY: [u8; 32] = [0xa1; 32];
const SERVERS_KEY: [u8; 32] = [0x42; 32];

fn public(seed: &[u8; 32]) -> [u8; 32] {
    device_key_pair(seed).1
}

/// The post-quantum box `approver_seed` seals `key` in for the new device.
fn hybrid_box(approver_seed: &[u8; 32], key: &[u8; 32]) -> Vec<u8> {
    let link_key = device_link_kem_public_key(&NEW_LINK_SEED).unwrap();
    account_key_seal_hybrid(approver_seed, &public(&NEW_SEED), &link_key, DEVICE_ID, key).unwrap()
}

/// The server's box opens under the key it listed: the primitive is not the
/// defence, and this test says so.
#[test]
fn the_servers_box_opens_under_the_key_it_listed() {
    let sealed = account_key_seal(
        &SERVER_DEVICE_SEED,
        &public(&NEW_SEED),
        DEVICE_ID,
        &SERVERS_KEY,
    )
    .expect("anyone holding a listed key can seal");
    let opened = account_key_open(&NEW_SEED, &public(&SERVER_DEVICE_SEED), DEVICE_ID, &sealed)
        .expect("it opens");
    assert_eq!(opened, SERVERS_KEY);
    // And a manifest the server sealed under its key opens with it too.
    let manifest = br#"{"version":1,"ids":[]}"#;
    let value = store_seal(&SERVERS_KEY, &[0u8; 16], manifest).unwrap();
    assert_eq!(store_open(&opened, &[0u8; 16], &value).unwrap(), manifest);
}

/// The regression: the new device's door refuses the server's box, whatever
/// the device confirmed, unless the device itself allows server approvals.
#[test]
fn the_new_device_refuses_a_box_from_an_approver_the_person_never_vouched_for() {
    let server = public(&SERVER_DEVICE_SEED);
    let sealed = hybrid_box(&SERVER_DEVICE_SEED, &SERVERS_KEY);
    // Confirmed nobody.
    let err = account_key_accept_hybrid(
        &NEW_SEED,
        &server,
        DEVICE_ID,
        &sealed,
        &NEW_LINK_SEED,
        &[],
        false,
    )
    .expect_err("refused");
    assert!(err.to_string().contains("did not confirm"), "{err}");
    // The person picked Ada's phone's number: a box from the server's device
    // is still refused.
    let err = account_key_accept_hybrid(
        &NEW_SEED,
        &server,
        DEVICE_ID,
        &sealed,
        &NEW_LINK_SEED,
        &public(&ADA_PHONE_SEED),
        false,
    )
    .expect_err("refused");
    assert!(err.to_string().contains("did not confirm"), "{err}");
    // A classical box from the server is refused even as if confirmed.
    let plain = account_key_seal(
        &SERVER_DEVICE_SEED,
        &public(&NEW_SEED),
        DEVICE_ID,
        &SERVERS_KEY,
    )
    .unwrap();
    assert!(
        account_key_accept_hybrid(&NEW_SEED, &server, DEVICE_ID, &plain, &[], &server, false)
            .is_err()
    );
}

/// A box keyed with a QR code's link secret never opens at the door: no
/// client shows a QR code, so no secret could have been read off one.
#[test]
fn a_box_keyed_with_a_qr_codes_secret_never_opens() {
    let ada = public(&ADA_PHONE_SEED);
    let linked = account_key_seal_linked(
        &ADA_PHONE_SEED,
        &public(&NEW_SEED),
        DEVICE_ID,
        &ADAS_KEY,
        &[0x5e; 32],
    )
    .unwrap();
    for allowed in [false, true] {
        let err =
            account_key_accept_hybrid(&NEW_SEED, &ada, DEVICE_ID, &linked, &[], &ada, allowed)
                .expect_err("refused");
        assert!(err.to_string().contains("showed no QR code"), "{err}");
    }
}

/// The number path end to end, both directions: the person picks the new
/// device's number on Ada's phone and Ada's phone's number on the new device,
/// and the new device then accepts a box from the key its pairing bound.
#[test]
fn the_two_numbers_confirm_the_approver_to_the_new_device() {
    let new_public = public(&NEW_SEED);
    let ada = public(&ADA_PHONE_SEED);
    let approver_nonce = [0x66; 32];
    let device_nonce = [0x55; 32];
    let commitment = device_link_commitment(&approver_nonce).unwrap();

    // What each screen shows.
    let on_new_device = device_link_number(
        &new_public,
        &ada,
        &commitment,
        &device_nonce,
        &approver_nonce,
    )
    .unwrap();
    let on_ada_phone = device_link_approver_number(
        &new_public,
        &ada,
        &commitment,
        &device_nonce,
        &approver_nonce,
    )
    .unwrap();
    // Both devices derive both numbers; each shows one and offers the other.
    assert_eq!(on_new_device.len(), 2);
    assert_eq!(on_ada_phone.len(), 2);

    // The person picked Ada's phone's number on the new device: that confirms
    // the key the pairing bound, and Ada's box is accepted.
    let sealed = hybrid_box(&ADA_PHONE_SEED, &ADAS_KEY);
    let accepted = account_key_accept_hybrid(
        &NEW_SEED,
        &ada,
        DEVICE_ID,
        &sealed,
        &NEW_LINK_SEED,
        &ada,
        false,
    )
    .expect("accepted");
    assert_eq!(accepted, ADAS_KEY);

    // A server that ran the exchange as an approver of its own gets a number
    // on the new device over ITS key, and the new device confirms that key
    // only if the person picks a number Ada's phone never showed.
    let server = public(&SERVER_DEVICE_SEED);
    let server_number = device_link_approver_number(
        &new_public,
        &server,
        &commitment,
        &device_nonce,
        &approver_nonce,
    )
    .unwrap();
    assert_eq!(server_number.len(), 2);
}
