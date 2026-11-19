// SPDX-License-Identifier: MIT
//! The account store's doors that `account_store_open` and
//! `account_key_box_open` leave: signed self-notes (`note_sender`,
//! `note_open_signed`), the transfer-key box a history hand-off carries
//! (`transfer_key_open`) and the post-quantum account-key box
//! (`account_key_accept_hybrid`). Another device of the account, or the
//! server, chooses these bytes. docs/mls-core.md §Fuzzing.
//!
//! The first input byte picks the door (`mode % 3`), and its bit 7 whether
//! the fuzzer's bytes arrive as they are or the target seals them first,
//! since no fuzzer forges an AEAD tag or a signature:
//! - 0, signed notes. As they are: `account key (32) ‖ id (16) ‖ sender key
//!   (32) ‖ now (8, BE ms) ‖ sender_len (1) ‖ sender ‖ value`. Sealed:
//!   `account key (32) ‖ id (16) ‖ issued at (6, BE ms) ‖ sender_len (1) ‖
//!   sender ‖ spec_len (1) ‖ spec ‖ plaintext`, sealed with
//!   `note_seal_signed_with` by the device seeded `[1; 32]`, then
//!   `common::mutate`d by `spec`.
//! - 1, transfer boxes. As they are: `recipient seed (32) ‖ id_len (1) ‖
//!   device id ‖ box`. Sealed: `recipient seed (32) ‖ ephemeral (32) ‖ nonce
//!   (12) ‖ key (32) ‖ spec_len (1) ‖ spec ‖ device id`, sealed with
//!   `transfer_key_seal_with`, then mutated.
//! - 2, hybrid boxes, opened with `mls/fixtures/account-store.json`'s
//!   link-key seed. As they are: `recipient seed (32) ‖ approver key (32) ‖
//!   id_len (1) ‖ device id ‖ box`, the approver confirmed. Sealed: `approver
//!   seed (32) ‖ recipient seed (32) ‖ account key (32) ‖ spec_len (1) ‖ spec
//!   ‖ device id`, sealed with `account_key_seal_hybrid` to that link key,
//!   then mutated.
//!
//! Asserted:
//! - No input panics.
//! - A signed note opens only from the device it names and only at a time
//!   inside its window; unchanged, it opens to its plaintext and names its
//!   sender; with any byte changed, it does not open.
//! - A transfer box opens for its recipient and device id to its key, and not
//!   for another id, nor with any byte changed.
//! - A hybrid box opens for its recipient to its account key from the
//!   confirmed approver, not from an approver the person did not confirm, and
//!   not with any byte changed.

#![no_main]

mod common;

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use peachy_mls_core::account_store::{note_seal_signed_with, transfer_key_seal_with};
use peachy_mls_core::{
    account_key_accept_hybrid, account_key_seal_hybrid, device_link_kem_public_key,
    note_open_signed, note_sender, signing_key_public_key, transfer_key_open, NOTE_MAX_AGE_MS,
};

const SENDER_SEED: [u8; 32] = [1; 32];
/// `boxAcceptHybrid`'s link-key seed in `mls/fixtures/account-store.json`.
const LINK_SEED: [u8; 32] = [0x5a; 32];
const NONCE: [u8; 12] = [3; 12];

fn link_key() -> &'static [u8] {
    static KEY: OnceLock<Vec<u8>> = OnceLock::new();
    KEY.get_or_init(|| device_link_kem_public_key(&LINK_SEED).expect("a link key"))
}

/// `len (1) ‖ bytes`, as text, and what follows.
fn text(data: &[u8]) -> Option<(String, &[u8])> {
    let (&len, rest) = data.split_first()?;
    let (bytes, rest) = rest.split_at_checked(usize::from(len))?;
    Some((String::from_utf8_lossy(bytes).into_owned(), rest))
}

fn spec_and_rest(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let (&len, rest) = data.split_first()?;
    rest.split_at_checked(usize::from(len))
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let sealed = mode & 0x80 != 0;
    match mode % 3 {
        0 => note(rest, sealed),
        1 => transfer(rest, sealed),
        _ => hybrid(rest, sealed),
    }
});

fn note(data: &[u8], sealed: bool) {
    let Some((account_key, rest)) = data.split_at_checked(32) else {
        return;
    };
    let Some((id, rest)) = rest.split_at_checked(16) else {
        return;
    };
    if !sealed {
        let Some((sender_key, rest)) = rest.split_at_checked(32) else {
            return;
        };
        let Some((now, rest)) = rest.split_first_chunk::<8>() else {
            return;
        };
        let Some((sender, value)) = text(rest) else {
            return;
        };
        let _ = note_sender(account_key, id, value);
        let now = i64::from_be_bytes(*now);
        let _ = note_open_signed(account_key, id, value, &sender, sender_key, now);
        return;
    }
    let sender_key = signing_key_public_key(&SENDER_SEED).expect("a key");
    let Some((at, rest)) = rest.split_first_chunk::<6>() else {
        return;
    };
    let mut wide = [0u8; 8];
    wide[2..].copy_from_slice(at);
    let issued_at = i64::from_be_bytes(wide);
    let Some((sender, rest)) = text(rest) else {
        return;
    };
    let Some((spec, plaintext)) = spec_and_rest(rest) else {
        return;
    };
    let Ok(value) = note_seal_signed_with(
        account_key,
        id,
        plaintext,
        &sender,
        issued_at,
        &SENDER_SEED,
        &NONCE,
    ) else {
        return;
    };
    assert_eq!(
        note_sender(account_key, id, &value).ok().as_deref(),
        Some(sender.as_str())
    );
    let open = |value: &[u8], from: &str, now: i64| {
        note_open_signed(account_key, id, value, from, &sender_key, now)
    };
    assert_eq!(
        open(&value, &sender, issued_at).expect("a signed note opens at its own time"),
        plaintext
    );
    assert!(open(&value, &format!("{sender}x"), issued_at).is_err());
    assert!(open(&value, &sender, issued_at + NOTE_MAX_AGE_MS + 1).is_err());
    let changed = common::mutate(&value, spec);
    if changed != value {
        assert!(
            open(&changed, &sender, issued_at).is_err(),
            "a changed note opened"
        );
    }
}

fn transfer(data: &[u8], sealed: bool) {
    let Some((recipient_seed, rest)) = data.split_at_checked(32) else {
        return;
    };
    if !sealed {
        let Some((device_id, sealed_box)) = text(rest) else {
            return;
        };
        let _ = transfer_key_open(recipient_seed, &device_id, sealed_box);
        return;
    }
    let Some((ephemeral, rest)) = rest.split_first_chunk::<32>() else {
        return;
    };
    let Some((nonce, rest)) = rest.split_first_chunk::<12>() else {
        return;
    };
    let Some((key, rest)) = rest.split_first_chunk::<32>() else {
        return;
    };
    let Some((spec, device_id)) = spec_and_rest(rest) else {
        return;
    };
    let device_id = String::from_utf8_lossy(device_id);
    let recipient_key = signing_key_public_key(recipient_seed).expect("a key");
    let Ok(sealed_box) = transfer_key_seal_with(&recipient_key, &device_id, key, ephemeral, nonce)
    else {
        assert!(
            device_id.is_empty(),
            "a transfer key to a real device would not seal"
        );
        return;
    };
    assert_eq!(
        transfer_key_open(recipient_seed, &device_id, &sealed_box).expect("it opens"),
        *key
    );
    assert!(transfer_key_open(recipient_seed, &format!("{device_id}x"), &sealed_box).is_err());
    let changed = common::mutate(&sealed_box, spec);
    if changed != sealed_box {
        assert!(
            transfer_key_open(recipient_seed, &device_id, &changed).is_err(),
            "a changed transfer box opened"
        );
    }
}

fn hybrid(data: &[u8], sealed: bool) {
    if !sealed {
        let Some((recipient_seed, rest)) = data.split_at_checked(32) else {
            return;
        };
        let Some((approver_key, rest)) = rest.split_at_checked(32) else {
            return;
        };
        let Some((device_id, sealed_box)) = text(rest) else {
            return;
        };
        for server_approval_allowed in [false, true] {
            let _ = account_key_accept_hybrid(
                recipient_seed,
                approver_key,
                &device_id,
                sealed_box,
                &LINK_SEED,
                approver_key,
                server_approval_allowed,
            );
        }
        return;
    }
    let Some((approver_seed, rest)) = data.split_at_checked(32) else {
        return;
    };
    let Some((recipient_seed, rest)) = rest.split_at_checked(32) else {
        return;
    };
    let Some((account_key, rest)) = rest.split_at_checked(32) else {
        return;
    };
    let Some((spec, device_id)) = spec_and_rest(rest) else {
        return;
    };
    let device_id = String::from_utf8_lossy(device_id);
    let approver_key = signing_key_public_key(approver_seed).expect("a key");
    let recipient_key = signing_key_public_key(recipient_seed).expect("a key");
    let Ok(sealed_box) = account_key_seal_hybrid(
        approver_seed,
        &recipient_key,
        link_key(),
        &device_id,
        account_key,
    ) else {
        assert!(
            device_id.is_empty(),
            "a hybrid box to a real device would not seal"
        );
        return;
    };
    let accept = |sealed_box: &[u8], confirmed: &[u8]| {
        account_key_accept_hybrid(
            recipient_seed,
            &approver_key,
            &device_id,
            sealed_box,
            &LINK_SEED,
            confirmed,
            false,
        )
    };
    assert_eq!(
        accept(&sealed_box, &approver_key).expect("a hybrid box opens from its approver"),
        account_key
    );
    assert!(accept(&sealed_box, &recipient_key).is_err() || recipient_key == approver_key);
    let changed = common::mutate(&sealed_box, spec);
    if changed != sealed_box {
        assert!(
            accept(&changed, &approver_key).is_err(),
            "a changed hybrid box opened"
        );
    }
}
