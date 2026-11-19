// SPDX-License-Identifier: MIT
//! The two signatures an account's identity key makes over one of its device
//! keys, as a peer checks them from bytes the server relays:
//! `verify_account_device` (the account vouching for a device) and
//! `verify_device_revocation` (the account revoking one).
//! docs/mls-core.md §Fuzzing.
//!
//! The first input byte's bit 0 picks the layout, since no fuzzer forges an
//! Ed25519 signature:
//! - clear: `account public key (32) ‖ device key (32) ‖ signature`, all
//!   arbitrary;
//! - set: `account key (32) ‖ device key (32) ‖ spec`: the target signs both
//!   statements with the identity key the account key derives, then
//!   `common::mutate`s `signature ‖ device key` by `spec`.
//!
//! Asserted:
//! - No input panics.
//! - The two statements are separated: no signature checks as both.
//! - What the account signed checks, as what it was signed as and not as the
//!   other; changed in any byte, it does not check.

#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use peachy_mls_core::{
    account_identity_public_key, sign_account_device, sign_device_revocation,
    verify_account_device, verify_device_revocation,
};

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let Some((key, rest)) = rest.split_at_checked(32) else {
        return;
    };
    let Some((device_key, rest)) = rest.split_at_checked(32) else {
        return;
    };
    if mode & 1 == 0 {
        let vouches = verify_account_device(key, device_key, rest);
        let revokes = verify_device_revocation(key, device_key, rest);
        assert!(
            !(vouches && revokes),
            "one signature checked as both statements"
        );
        return;
    }

    let account_public = account_identity_public_key(key).expect("a 32-byte account key");
    let vouch = sign_account_device(key, device_key).expect("a 32-byte device key");
    let revoke = sign_device_revocation(key, device_key).expect("a 32-byte device key");
    assert!(verify_account_device(&account_public, device_key, &vouch));
    assert!(verify_device_revocation(
        &account_public,
        device_key,
        &revoke
    ));
    assert!(!verify_account_device(&account_public, device_key, &revoke));
    assert!(!verify_device_revocation(
        &account_public,
        device_key,
        &vouch
    ));

    for (signature, check) in [
        (
            &vouch[..],
            verify_account_device as fn(&[u8], &[u8], &[u8]) -> bool,
        ),
        (&revoke[..], verify_device_revocation),
    ] {
        let signed = [signature, device_key].concat();
        let changed = common::mutate(&signed, rest);
        if changed != signed {
            let (signature, device_key) = changed.split_at(signature.len());
            assert!(
                !check(&account_public, device_key, signature),
                "a changed signature or device key checked"
            );
        }
    }
});
