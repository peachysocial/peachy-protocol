// SPDX-License-Identifier: MIT
//! The account-key box a new device receives when it is approved: arbitrary
//! bytes into `account_key_open`, and boxes the fuzzer's inputs seal, then
//! attacked. docs/mls-core.md §Fuzzing.
//!
//! The first input byte picks the mode:
//! - even: `recipient seed (32) ‖ approver key (32) ‖ device id length (1) ‖
//!   device id ‖ box`, the box opened as it would arrive;
//! - odd: `approver seed (32) ‖ recipient seed (32) ‖ ephemeral (32) ‖
//!   nonce (12) ‖ account key (32) ‖ flip position (2) ‖ device id`, sealed
//!   from the approver to the recipient, then opened.
//!
//! - No input panics.
//! - A sealed box is exactly `ACCOUNT_KEY_BOX_BYTES` long and opens, for its
//!   recipient and device id, to exactly the account key sealed in it.
//! - It does not open for another device id, from another approver, or with
//!   any one bit flipped.
//! - At the new device's door (`account_key_accept_hybrid`) this classical
//!   box opens only under the test switch, confirmed approver or not; the
//!   same key sealed with a link secret never opens there, nor at the plain
//!   door.

#![no_main]

use libfuzzer_sys::fuzz_target;
use peachy_mls_core::account_store::{account_key_seal_linked_with, account_key_seal_with};
use peachy_mls_core::{
    account_key_accept_hybrid, account_key_open, signing_key_public_key, ACCOUNT_KEY_BOX_BYTES,
};

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };

    if mode & 1 == 0 {
        let Some((recipient_seed, rest)) = rest.split_first_chunk::<32>() else {
            return;
        };
        let Some((approver_key, rest)) = rest.split_first_chunk::<32>() else {
            return;
        };
        let Some((&id_len, rest)) = rest.split_first() else {
            return;
        };
        let Some((id, sealed_box)) = rest.split_at_checked(usize::from(id_len) % 48) else {
            return;
        };
        let Ok(device_id) = std::str::from_utf8(id) else {
            return;
        };
        // Forging the box is not something a fuzzer does; only no panic.
        let _ = account_key_open(recipient_seed, approver_key, device_id, sealed_box);
        return;
    }

    let Some((approver_seed, rest)) = rest.split_first_chunk::<32>() else {
        return;
    };
    let Some((recipient_seed, rest)) = rest.split_first_chunk::<32>() else {
        return;
    };
    let Some((ephemeral, rest)) = rest.split_first_chunk::<32>() else {
        return;
    };
    let Some((nonce, rest)) = rest.split_first_chunk::<12>() else {
        return;
    };
    let Some((account_key, rest)) = rest.split_first_chunk::<32>() else {
        return;
    };
    let Some((flip, id)) = rest.split_first_chunk::<2>() else {
        return;
    };
    let Ok(device_id) = std::str::from_utf8(id) else {
        return;
    };
    let approver_key = signing_key_public_key(approver_seed).expect("a 32-byte seed has a key");
    let recipient_key = signing_key_public_key(recipient_seed).expect("a 32-byte seed has a key");

    let Ok(sealed) = account_key_seal_with(
        approver_seed,
        &recipient_key,
        device_id,
        account_key,
        ephemeral,
        nonce,
    ) else {
        return; // an empty device id, for one, is refused at seal time
    };
    assert_eq!(sealed.len(), ACCOUNT_KEY_BOX_BYTES);
    let opened = account_key_open(recipient_seed, &approver_key, device_id, &sealed)
        .expect("a sealed box opens for its recipient");
    assert_eq!(&opened, account_key);

    let other_device = format!("{device_id}x");
    assert!(
        account_key_open(recipient_seed, &approver_key, &other_device, &sealed).is_err(),
        "opened for another device id"
    );
    let mut other_seed = *approver_seed;
    other_seed[0] ^= 1;
    let other_approver = signing_key_public_key(&other_seed).expect("a 32-byte seed has a key");
    assert!(
        account_key_open(recipient_seed, &other_approver, device_id, &sealed).is_err(),
        "opened as if from another approver"
    );

    let bit = usize::from(u16::from_be_bytes(*flip)) % (sealed.len() * 8);
    let mut tampered = sealed.clone();
    tampered[bit / 8] ^= 1 << (bit % 8);
    assert!(
        account_key_open(recipient_seed, &approver_key, device_id, &tampered).is_err(),
        "a flipped bit still opened"
    );

    // THE NEW DEVICE'S DOOR.
    let accept = |sealed: &[u8], confirmed: &[u8], allowed: bool| {
        account_key_accept_hybrid(
            recipient_seed,
            &approver_key,
            device_id,
            sealed,
            &[],
            confirmed,
            allowed,
        )
    };
    assert!(
        accept(&sealed, &[], false).is_err(),
        "opened from an approver nobody confirmed"
    );
    assert!(
        accept(&sealed, &other_approver, false).is_err(),
        "opened on another's confirmation"
    );
    assert!(
        accept(&sealed, &approver_key, false).is_err(),
        "a classical box opened without the test switch"
    );
    assert_eq!(
        &accept(&sealed, &[], true).expect("the test switch"),
        account_key
    );

    let secret = *ephemeral;
    let Ok(linked) = account_key_seal_linked_with(
        approver_seed,
        &recipient_key,
        device_id,
        account_key,
        &secret,
        ephemeral,
        nonce,
    ) else {
        panic!("a key that sealed plainly did not seal with a secret");
    };
    for allowed in [false, true] {
        assert!(
            accept(&linked, &approver_key, allowed).is_err(),
            "a linked box opened at the new device's door"
        );
    }
    assert!(
        account_key_open(recipient_seed, &approver_key, device_id, &linked).is_err(),
        "a linked box opened at the plain door"
    );
});
