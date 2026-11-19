// SPDX-License-Identifier: MIT
//! The account store's record opener: arbitrary bytes into `store_open`, and
//! the fuzzer's plaintexts sealed and then attacked.
//! docs/mls-core.md §Fuzzing.
//!
//! The first input byte picks the mode (bit 1):
//! - modes 0 and 1: `key length (1) ‖ id length (1) ‖ key ‖ id ‖ value`, the
//!   value opened as it would arrive from the server;
//! - modes 2 and 3: `key (32) ‖ id (16) ‖ nonce (12) ‖ flip position (2) ‖
//!   plaintext`, sealed with that nonce and then opened.
//!
//! - No input panics, and no record opens as a self-note.
//! - A sealed value opens to exactly what was sealed, and sealing what it opens
//!   to again, with the same nonce, gives back the same bytes.
//! - It does not open under another id, in the other domain, or with any one
//!   bit flipped.
//! - A plaintext over the limit is refused at seal time.

#![no_main]

use libfuzzer_sys::fuzz_target;
use peachy_mls_core::account_store::store_seal_with as seal;
use peachy_mls_core::{note_sender, store_open as open, MAX_STORE_PLAINTEXT_BYTES};

/// A record never opens in the self-note domain.
fn other_open(key: &[u8], id: &[u8], value: &[u8]) -> peachy_mls_core::Result<String> {
    note_sender(key, id, value)
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };

    if mode & 2 == 0 {
        let Some((&[key_len, id_len], rest)) = rest.split_first_chunk::<2>() else {
            return;
        };
        let Some((key, rest)) = rest.split_at_checked(usize::from(key_len) % 48) else {
            return;
        };
        let Some((id, value)) = rest.split_at_checked(usize::from(id_len) % 24) else {
            return;
        };
        if let Ok(plaintext) = open(key, id, value) {
            // Forging an AES-GCM tag is not something a fuzzer does; if one
            // opens, it still keeps to the limit and to its own domain.
            assert!(plaintext.len() <= MAX_STORE_PLAINTEXT_BYTES);
            assert!(other_open(key, id, value).is_err());
        }
        return;
    }

    let Some((key, rest)) = rest.split_first_chunk::<32>() else {
        return;
    };
    let Some((id, rest)) = rest.split_first_chunk::<16>() else {
        return;
    };
    let Some((nonce, rest)) = rest.split_first_chunk::<12>() else {
        return;
    };
    let Some((flip, plaintext)) = rest.split_first_chunk::<2>() else {
        return;
    };
    let Ok(sealed) = seal(key, id, plaintext, nonce) else {
        assert!(
            plaintext.len() > MAX_STORE_PLAINTEXT_BYTES,
            "a plaintext within the limit was refused"
        );
        return;
    };
    assert!(
        plaintext.len() <= MAX_STORE_PLAINTEXT_BYTES,
        "a plaintext over the limit sealed"
    );

    let opened = open(key, id, &sealed).expect("a sealed value opens");
    assert_eq!(opened, plaintext);
    assert_eq!(seal(key, id, &opened, nonce).expect("re-seals"), sealed);
    assert!(
        other_open(key, id, &sealed).is_err(),
        "opened in the other domain"
    );

    let mut other_id = *id;
    other_id[0] ^= 1;
    assert!(
        open(key, &other_id, &sealed).is_err(),
        "opened under another id"
    );
    let mut other_key = *key;
    other_key[31] ^= 1;
    assert!(
        open(&other_key, id, &sealed).is_err(),
        "opened under another key"
    );

    let bit = usize::from(u16::from_be_bytes(*flip)) % (sealed.len() * 8);
    let mut tampered = sealed.clone();
    tampered[bit / 8] ^= 1 << (bit % 8);
    assert!(
        open(key, id, &tampered).is_err(),
        "a flipped bit still opened"
    );
});
