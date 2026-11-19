// SPDX-License-Identifier: MIT
//! Linking a new device: the QR code, the commitment and the number, the
//! waiting device's one-exchange rule, and the approval signature.
//! docs/mls-core.md §Fuzzing.
//!
//! The first input byte picks the door (modulo 4):
//! - 0, the QR code: `key (32) ‖ link secret (32) ‖ device id length (1) ‖
//!   device id ‖ scanned`. A device id is refused exactly when it is empty,
//!   holds `/` or anything but printable ASCII; an accepted one gives a code
//!   that matches itself, with surrounding whitespace, and gives back its
//!   secret, and not another key. A scanned code that matches is exactly the
//!   code of the secret it gives back.
//! - 1, the number: `new device key ‖ approver key ‖ commitment ‖ device
//!   nonce ‖ approver nonce`, 32 bytes each. A number comes back exactly when
//!   the keys differ and the nonce opens the commitment, and it is two digits.
//! - 2, the waiting device's step: six length-prefixed fields (bound approver
//!   id, key, commitment; offered approver id, key, commitment), checked
//!   against the rule as the docs state it.
//! - 3, the approval: `seed (32) ‖ signing key (32) ‖ signature (64) ‖ device
//!   id`. Arbitrary signatures never panic; an honest one verifies, and not for
//!   another device id or with a flipped bit.

#![no_main]

use libfuzzer_sys::fuzz_target;
use peachy_mls_core::{
    device_link_approver_number, device_link_commitment, device_link_number, device_link_qr,
    device_link_qr_matches, device_link_qr_secret, device_link_waiter_step, sign_device_approval,
    signing_key_public_key, verify_device_approval, DeviceLinkWaiterStep, DEVICE_LINK_QR_PREFIX,
};

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    match mode % 4 {
        0 => qr(rest),
        1 => number(rest),
        2 => waiter_step(rest),
        _ => approval(rest),
    }
});

fn qr(data: &[u8]) {
    let Some((key, rest)) = data.split_first_chunk::<32>() else {
        return;
    };
    let Some((secret, rest)) = rest.split_first_chunk::<32>() else {
        return;
    };
    let Some((&id_len, rest)) = rest.split_first() else {
        return;
    };
    let Some((id, scanned)) = rest.split_at_checked(usize::from(id_len) % 48) else {
        return;
    };
    let (Ok(device_id), Ok(scanned)) = (std::str::from_utf8(id), std::str::from_utf8(scanned))
    else {
        return;
    };
    let valid_id = !device_id.is_empty()
        && !device_id.contains('/')
        && device_id.bytes().all(|b| b.is_ascii_graphic());
    match device_link_qr(device_id, key, secret) {
        Ok(code) => {
            assert!(valid_id, "a QR code for a device id the rule refuses");
            assert!(code.starts_with(DEVICE_LINK_QR_PREFIX));
            assert!(device_link_qr_matches(&code, device_id, key));
            assert!(device_link_qr_matches(
                &format!(" {code}\n"),
                device_id,
                key
            ));
            assert_eq!(device_link_qr_secret(&code, device_id, key), Some(*secret));
            let found = device_link_qr_secret(scanned, device_id, key);
            assert_eq!(
                device_link_qr_matches(scanned, device_id, key),
                found.is_some()
            );
            if let Some(found) = found {
                let rebuilt =
                    device_link_qr(device_id, key, &found).expect("a matched id is valid");
                assert_eq!(
                    scanned.trim(),
                    rebuilt,
                    "a code matched that is not its own"
                );
            }
            let mut other = *key;
            other[0] ^= 1;
            assert!(!device_link_qr_matches(&code, device_id, &other));
        }
        Err(_) => {
            assert!(!valid_id, "a valid device id was refused");
            assert!(!device_link_qr_matches(scanned, device_id, key));
        }
    }
}

fn number(data: &[u8]) {
    let Some((new_key, rest)) = data.split_first_chunk::<32>() else {
        return;
    };
    let Some((approver_key, rest)) = rest.split_first_chunk::<32>() else {
        return;
    };
    let Some((commitment, rest)) = rest.split_first_chunk::<32>() else {
        return;
    };
    let Some((device_nonce, rest)) = rest.split_first_chunk::<32>() else {
        return;
    };
    let Some((approver_nonce, _)) = rest.split_first_chunk::<32>() else {
        return;
    };
    let honest = device_link_commitment(approver_nonce).expect("a 32-byte nonce commits");
    let result = device_link_number(
        new_key,
        approver_key,
        commitment,
        device_nonce,
        approver_nonce,
    );
    assert_eq!(
        result.is_ok(),
        new_key != approver_key && *commitment == honest,
        "a number exactly when the keys differ and the nonce opens the commitment"
    );
    let approver_number =
        device_link_approver_number(new_key, approver_key, &honest, device_nonce, approver_nonce);
    assert_eq!(
        approver_number.is_ok(),
        device_link_number(new_key, approver_key, &honest, device_nonce, approver_nonce).is_ok(),
        "the two numbers refuse different exchanges"
    );
    if let Ok(n) = &approver_number {
        assert!(n.len() == 2 && n.bytes().all(|b| b.is_ascii_digit()));
    }
    if let Ok(number) =
        device_link_number(new_key, approver_key, &honest, device_nonce, approver_nonce)
    {
        assert_eq!(number.len(), 2);
        assert!(number.bytes().all(|b| b.is_ascii_digit()));
    } else {
        assert_eq!(new_key, approver_key, "an honest exchange was refused");
    }
    assert!(device_link_number(
        &new_key[1..],
        approver_key,
        &honest,
        device_nonce,
        approver_nonce
    )
    .is_err());
}

/// One length-prefixed field, at most 40 bytes.
fn field(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let (&len, rest) = data.split_first()?;
    rest.split_at_checked(usize::from(len) % 41)
}

fn waiter_step(data: &[u8]) {
    let Some((bound_id, rest)) = field(data) else {
        return;
    };
    let Some((bound_key, rest)) = field(rest) else {
        return;
    };
    let Some((bound_commitment, rest)) = field(rest) else {
        return;
    };
    let Some((id, rest)) = field(rest) else {
        return;
    };
    let Some((key, rest)) = field(rest) else {
        return;
    };
    let Some((commitment, _)) = field(rest) else {
        return;
    };
    let (Ok(bound_id), Ok(id)) = (std::str::from_utf8(bound_id), std::str::from_utf8(id)) else {
        return;
    };

    // The rule, as docs/mls-core.md and the function's own docs state it.
    let expected = if id.is_empty() || key.len() != 32 || commitment.len() != 32 {
        None
    } else if bound_id.is_empty() && bound_key.is_empty() && bound_commitment.is_empty() {
        Some(DeviceLinkWaiterStep::Answer)
    } else if bound_id.is_empty() || bound_key.len() != 32 || bound_commitment.len() != 32 {
        None
    } else if id != bound_id {
        Some(DeviceLinkWaiterStep::Ignore)
    } else if key == bound_key && commitment == bound_commitment {
        Some(DeviceLinkWaiterStep::Continue)
    } else {
        Some(DeviceLinkWaiterStep::Interrupted)
    };
    let got =
        device_link_waiter_step(bound_id, bound_key, bound_commitment, id, key, commitment).ok();
    assert_eq!(got, expected);
}

fn approval(data: &[u8]) {
    let Some((seed, rest)) = data.split_first_chunk::<32>() else {
        return;
    };
    let Some((signing_key, rest)) = rest.split_first_chunk::<32>() else {
        return;
    };
    let Some((signature, id)) = rest.split_first_chunk::<64>() else {
        return;
    };
    let Ok(device_id) = std::str::from_utf8(id) else {
        return;
    };
    let approver = signing_key_public_key(seed).expect("a 32-byte seed has a key");
    // Arbitrary signatures, under the approver's real key and under the
    // fuzzer's bytes as a key: no panic, whatever the answer.
    let _ = verify_device_approval(&approver, device_id, signing_key, signature);
    let _ = verify_device_approval(signing_key, device_id, signing_key, signature);

    let Ok(honest) = sign_device_approval(seed, device_id, signing_key) else {
        assert!(
            device_id.is_empty(),
            "an approval of a real device would not sign"
        );
        return;
    };
    assert!(verify_device_approval(
        &approver,
        device_id,
        signing_key,
        &honest
    ));
    assert!(!verify_device_approval(
        &approver,
        &format!("{device_id}x"),
        signing_key,
        &honest
    ));
    let mut flipped = honest;
    flipped[usize::from(signature[0]) % 64] ^= 1 << (signature[1] % 8);
    assert!(!verify_device_approval(
        &approver,
        device_id,
        signing_key,
        &flipped
    ));
}
