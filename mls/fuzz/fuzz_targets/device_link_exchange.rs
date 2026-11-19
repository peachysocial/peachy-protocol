// SPDX-License-Identifier: MIT
//! The device-link exchange's doors that `device_link` leaves: the
//! approver's commitment signature (`verify_device_link_commitment`), the
//! waiting device's signature over its post-quantum link key
//! (`verify_device_link_kem`), and the approver's rule over what the device
//! list shows (`device_link_approver_step`). The server relays every byte.
//! docs/mls-core.md §Fuzzing.
//!
//! The first input byte picks the door (`mode % 3`):
//! - 0, the commitment: `seed (32) ‖ approver key (32) ‖ pending key (32) ‖
//!   commitment (32) ‖ signature (64) ‖ device id`;
//! - 1, the link key: `seed (32) ‖ pending key (32) ‖ commitment (32) ‖
//!   device nonce (32) ‖ signature (64) ‖ device id`, over the link key
//!   `mls/fixtures/device-link.json`'s seed derives;
//! - 2, the approver's step: seven length-prefixed fields (`len (1) ‖
//!   bytes`): pending key, commitment, bound device nonce, listed key, listed
//!   commitment, listed device nonce, listed approver nonce.
//!
//! In 0 and 1, `signature` is checked as it arrives under the key that
//! follows the seed (the fixture's `verify…` cases are laid out this way),
//! and the seed's own key signs the honest one.
//!
//! Asserted:
//! - No input panics, whatever signature, key or field arrives.
//! - An honest signature checks, and not for another device id, nor with a
//!   bit flipped.
//! - The approver's step is the rule as `device_link_approver_step`'s docs
//!   state it, refusing exactly the malformed state of the caller's own.

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use peachy_mls_core::{
    device_link_approver_step, device_link_commitment, device_link_kem_public_key,
    sign_device_link_commitment, sign_device_link_kem, signing_key_public_key,
    verify_device_link_commitment, verify_device_link_kem, DeviceLinkApproverStep,
};

/// `linkKey/from-its-seed`'s seed.
const LINK_SEED: [u8; 32] = [0x5a; 32];

fn link_key() -> &'static [u8] {
    static KEY: OnceLock<Vec<u8>> = OnceLock::new();
    KEY.get_or_init(|| device_link_kem_public_key(&LINK_SEED).expect("a link key"))
}

fn flip(signature: &[u8; 64], at: &[u8; 32]) -> [u8; 64] {
    let mut flipped = *signature;
    flipped[usize::from(at[0]) % 64] ^= 1 << (at[1] % 8);
    flipped
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    match mode % 3 {
        0 => commitment(rest),
        1 => kem(rest),
        _ => approver_step(rest),
    }
});

fn commitment(data: &[u8]) {
    let Some((seed, rest)) = data.split_first_chunk::<32>() else {
        return;
    };
    let Some((approver_key, rest)) = rest.split_first_chunk::<32>() else {
        return;
    };
    let Some((pending_key, rest)) = rest.split_first_chunk::<32>() else {
        return;
    };
    let Some((commitment, rest)) = rest.split_first_chunk::<32>() else {
        return;
    };
    let Some((signature, id)) = rest.split_first_chunk::<64>() else {
        return;
    };
    let device_id = String::from_utf8_lossy(id);
    let _ =
        verify_device_link_commitment(approver_key, &device_id, pending_key, commitment, signature);
    // A commitment of a length no approver signs.
    let _ = verify_device_link_commitment(approver_key, &device_id, pending_key, id, signature);
    let approver = signing_key_public_key(seed).expect("a 32-byte seed has a key");

    let Ok(honest) = sign_device_link_commitment(seed, &device_id, pending_key, commitment) else {
        assert!(
            device_id.is_empty(),
            "a commitment for a real device would not sign"
        );
        return;
    };
    let check = |id: &str, signature: &[u8]| {
        verify_device_link_commitment(&approver, id, pending_key, commitment, signature)
    };
    assert!(check(&device_id, &honest));
    assert!(!check(&format!("{device_id}x"), &honest));
    assert!(!check(&device_id, &flip(&honest, commitment)));
}

fn kem(data: &[u8]) {
    let Some((seed, rest)) = data.split_first_chunk::<32>() else {
        return;
    };
    let Some((pending_key, rest)) = rest.split_first_chunk::<32>() else {
        return;
    };
    let Some((commitment, rest)) = rest.split_first_chunk::<32>() else {
        return;
    };
    let Some((nonce, rest)) = rest.split_first_chunk::<32>() else {
        return;
    };
    let Some((signature, id)) = rest.split_first_chunk::<64>() else {
        return;
    };
    let device_id = String::from_utf8_lossy(id);
    let _ = verify_device_link_kem(
        pending_key,
        &device_id,
        commitment,
        nonce,
        link_key(),
        signature,
    );
    // A link key of a length no KEM posts.
    let _ = verify_device_link_kem(pending_key, &device_id, commitment, nonce, id, signature);
    let pending = signing_key_public_key(seed).expect("a 32-byte seed has a key");

    let Ok(honest) = sign_device_link_kem(seed, &device_id, commitment, nonce, link_key()) else {
        assert!(
            device_id.is_empty(),
            "a link key for a real device would not sign"
        );
        return;
    };
    let check = |id: &str, nonce: &[u8], signature: &[u8]| {
        verify_device_link_kem(&pending, id, commitment, nonce, link_key(), signature)
    };
    assert!(check(&device_id, nonce, &honest));
    assert!(!check(&format!("{device_id}x"), nonce, &honest));
    assert!(!check(&device_id, nonce, &flip(&honest, nonce)));
    let mut other_nonce = *nonce;
    other_nonce[0] ^= 1;
    assert!(!check(&device_id, &other_nonce, &honest));
}

fn approver_step(data: &[u8]) {
    let mut fields = Vec::with_capacity(7);
    let mut rest = data;
    for _ in 0..7 {
        let Some((&len, tail)) = rest.split_first() else {
            return;
        };
        let Some((field, tail)) = tail.split_at_checked(usize::from(len) % 40) else {
            return;
        };
        fields.push(field);
        rest = tail;
    }
    let [pending_key, commitment, bound, listed_key, listed_commitment, listed_nonce, listed_reveal] =
        fields[..]
    else {
        return;
    };
    let got = device_link_approver_step(
        pending_key,
        commitment,
        bound,
        listed_key,
        listed_commitment,
        listed_nonce,
        listed_reveal,
    );
    if pending_key.len() != 32 || commitment.len() != 32 || !matches!(bound.len(), 0 | 32) {
        assert!(got.is_err(), "malformed approver state was taken");
        return;
    }
    let got = got.expect("well-formed approver state is answered");
    use DeviceLinkApproverStep::*;
    let revealed = !listed_reveal.is_empty();
    let ours = listed_reveal.len() == 32
        && device_link_commitment(listed_reveal).expect("a 32-byte nonce commits") == commitment;
    let expected = if listed_key != pending_key {
        Interrupted
    } else if listed_commitment != commitment {
        if bound.is_empty() {
            Commit
        } else {
            Interrupted
        }
    } else if revealed && !ours {
        Interrupted
    } else if bound.is_empty() {
        if revealed {
            Interrupted
        } else if listed_nonce.len() == 32 {
            Reveal
        } else {
            Wait
        }
    } else if listed_nonce != bound {
        Interrupted
    } else if revealed {
        Show
    } else {
        Reveal
    };
    assert_eq!(got, expected);
}
