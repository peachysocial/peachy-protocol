// SPDX-License-Identifier: MIT
//! Device seals through `device_seal_open`, the box beside a version 3
//! envelope that tells one device its group, sender and epoch secret: any
//! sender, and the server, chooses its bytes. docs/mls-core.md
//! §Fuzzing.
//!
//! The first input byte's bit 0 picks the layout, since no fuzzer forges an
//! AEAD tag:
//! - clear: `recipient seed (32) ‖ seal (226) ‖ envelope`, all arbitrary
//!   (`mls/fixtures/device-seal.json`'s `open` cases are laid out this way);
//! - set: `sender (1) ‖ recipient (1) ‖ group_len (1) ‖ field (1) ‖
//!   spec_len (1) ‖ spec ‖ group id (group_len) ‖ epoch secret (32) ‖
//!   ephemeral (32) ‖ envelope`. The devices' seeds are 32 copies of their
//!   byte. The target seals with `device_seal_with_ephemeral`, then `field`
//!   changes one thing: 0 nothing, 1 the seal and 2 the envelope (each
//!   `common::mutate`d by `spec`), 3 the recipient (the next seed).
//!
//! Asserted:
//! - No input panics.
//! - What opens names a group of 1 to `DEVICE_SEAL_MAX_GROUP_ID_BYTES` bytes,
//!   and is bound to its envelope: it does not open for that envelope with a
//!   byte more.
//! - A seal of a group id that fits, between two real device keys, is made;
//!   unchanged, it opens to exactly its sender's key, group and secret; with
//!   any change, it does not open.

#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use peachy_mls_core::issuer::device_key_pair;
use peachy_mls_core::{
    device_seal_open, device_seal_with_ephemeral, DEVICE_SEAL_BYTES, DEVICE_SEAL_MAX_GROUP_ID_BYTES,
};

fn assert_bound(seed: &[u8], seal: &[u8], envelope: &[u8]) {
    let mut longer = envelope.to_vec();
    longer.push(0);
    assert!(
        device_seal_open(seed, seal, &longer).is_err(),
        "a device seal opened for another envelope"
    );
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    if mode & 1 == 0 {
        if rest.len() < 32 + DEVICE_SEAL_BYTES {
            let _ = device_seal_open(&rest[..rest.len().min(32)], rest, &[]);
            return;
        }
        let (seed, rest) = rest.split_at(32);
        let (seal, envelope) = rest.split_at(DEVICE_SEAL_BYTES);
        if let Ok(opened) = device_seal_open(seed, seal, envelope) {
            assert!(
                (1..=DEVICE_SEAL_MAX_GROUP_ID_BYTES).contains(&opened.group_id.len()),
                "a device seal opened to a group id of {} bytes",
                opened.group_id.len()
            );
            assert_bound(seed, seal, envelope);
        }
        return;
    }

    let [sender, recipient, group_len, field, spec_len, rest @ ..] = rest else {
        return;
    };
    let Some((spec, rest)) = rest.split_at_checked(usize::from(*spec_len)) else {
        return;
    };
    let Some((group_id, rest)) = rest.split_at_checked(usize::from(*group_len)) else {
        return;
    };
    let Some((epoch_secret, rest)) = rest.split_at_checked(32) else {
        return;
    };
    let Some((ephemeral, envelope)) = rest.split_at_checked(32) else {
        return;
    };
    let sender_seed = [*sender; 32];
    let recipient_seed = [*recipient; 32];
    let (_, sender_key) = device_key_pair(&sender_seed);
    let (_, recipient_key) = device_key_pair(&recipient_seed);

    let sealed = device_seal_with_ephemeral(
        &sender_seed,
        &recipient_key,
        group_id,
        epoch_secret,
        envelope,
        ephemeral,
    );
    let fits = (1..=DEVICE_SEAL_MAX_GROUP_ID_BYTES).contains(&group_id.len());
    assert_eq!(
        sealed.is_ok(),
        fits,
        "a device seal was made for a {}-byte group id, or refused for one that fits",
        group_id.len()
    );
    let Ok(seal) = sealed else {
        return;
    };
    assert_eq!(seal.len(), DEVICE_SEAL_BYTES);

    let (mut seal2, mut envelope2, mut seed2) = (seal.clone(), envelope.to_vec(), recipient_seed);
    match field % 4 {
        1 => seal2 = common::mutate(&seal, spec),
        2 => envelope2 = common::mutate(envelope, spec),
        3 => seed2 = [recipient.wrapping_add(1); 32],
        _ => {}
    }
    let changed = seal2 != seal || envelope2 != envelope || seed2 != recipient_seed;
    let opened = device_seal_open(&seed2, &seal2, &envelope2);
    if changed {
        assert!(
            opened.is_err(),
            "a device seal changed by field {field} opened"
        );
        return;
    }
    let opened = opened.expect("a device seal opens for its recipient");
    assert_eq!(opened.sender_key, sender_key);
    assert_eq!(opened.group_id, group_id);
    assert_eq!(opened.epoch_secret.as_slice(), epoch_secret);
    assert_bound(&recipient_seed, &seal, envelope);
});
