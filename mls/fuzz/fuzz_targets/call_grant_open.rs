// SPDX-License-Identifier: MIT
//! Arbitrary sealed bytes into `open_call_media_grant`, the door every media
//! grant a peer seals to this device goes through: the suite chosen by the
//! length of `enc`, the HPKE open under the grant's bound `info`, then the
//! plaintext codec. docs/mls-core.md §Fuzzing.
//!
//! Input: `suite (1) ‖ call_id (16) ‖ sender_leaf (4, BE) ‖ to_leaf (4, BE) ‖
//! rest`. The suite byte's bit 0 picks the X-Wing recipient key (else the
//! X25519 one), bit 1 the other participant's key of that suite. With bit 7
//! clear, `enc` is the first 32 bytes of `rest` (X25519) or the first
//! [`CALL_MEDIA_PQ_ENC_BYTES`] (X-Wing); with it set, `rest`'s first byte
//! gives `enc`'s length, so lengths no suite takes are tried too. The
//! ciphertext is what follows.
//!
//! - No input panics.
//! - What opens decodes within the encoder's bounds, so it re-encodes.
//! - What opens is bound to its recipient, call and both leaves: the same
//!   bytes for the next `to_leaf`, the next `sender_leaf`, another call id or
//!   the other participant's key do not open. (Only the golden fixture's
//!   grants open here; no fuzzer forges an HPKE ciphertext.)

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use peachy_mls_core::call::{
    call_media_key_pair, call_media_pq_key_pair, encode_media_grant_payload, open_call_media_grant,
    CALL_ID_BYTES, CALL_MEDIA_PQ_ENC_BYTES, CALL_MEDIA_PUBLIC_KEY_BYTES,
};

/// `mls/fixtures/calls.json`'s `media-key-pair-recipient` and
/// `media-key-pair-other`, so its `openMediaGrant` cases open here.
const RECIPIENT_IKM: [u8; 32] = [
    0x2b, 0x29, 0x2e, 0x8e, 0x72, 0x66, 0xd2, 0x7b, 0x3b, 0xa2, 0x10, 0x34, 0x3c, 0x0f, 0xf9, 0xea,
    0xa4, 0x73, 0x03, 0x28, 0x5f, 0xf2, 0x2f, 0xb7, 0xe2, 0x83, 0xc0, 0x60, 0xe7, 0x01, 0x82, 0x01,
];
const OTHER_IKM: [u8; 32] = [
    0x86, 0x29, 0x7b, 0x0e, 0x2f, 0xd0, 0x49, 0x91, 0xe6, 0xe7, 0xb4, 0x2f, 0x47, 0x62, 0x9b, 0xf1,
    0x36, 0x8e, 0x2a, 0x53, 0xd7, 0xa8, 0x02, 0x8e, 0x00, 0x0d, 0x68, 0xe3, 0x12, 0xac, 0x05, 0x5f,
];

/// The private keys: `[suite][participant]`, suite 0 X25519 and 1 X-Wing.
fn keys() -> &'static [[Vec<u8>; 2]; 2] {
    static KEYS: OnceLock<[[Vec<u8>; 2]; 2]> = OnceLock::new();
    KEYS.get_or_init(|| {
        let classical = |ikm: &[u8]| call_media_key_pair(ikm).expect("an X25519 call key").0;
        let pq = |ikm: &[u8]| call_media_pq_key_pair(ikm).expect("an X-Wing call key").0;
        [
            [classical(&RECIPIENT_IKM), classical(&OTHER_IKM)],
            [pq(&RECIPIENT_IKM), pq(&OTHER_IKM)],
        ]
    })
}

const HEADER: usize = 1 + CALL_ID_BYTES + 4 + 4;

fuzz_target!(|data: &[u8]| {
    if data.len() < HEADER {
        return;
    }
    let suite_byte = data[0];
    let call_id = &data[1..1 + CALL_ID_BYTES];
    let at = 1 + CALL_ID_BYTES;
    let sender_leaf = u32::from_be_bytes(data[at..at + 4].try_into().expect("4 bytes"));
    let to_leaf = u32::from_be_bytes(data[at + 4..at + 8].try_into().expect("4 bytes"));
    let mut rest = &data[HEADER..];
    let suite = usize::from(suite_byte & 1);
    let participant = usize::from((suite_byte >> 1) & 1);
    let enc_len = if suite_byte & 0x80 != 0 {
        let Some((&len, tail)) = rest.split_first() else {
            return;
        };
        rest = tail;
        usize::from(len)
    } else if suite == 0 {
        CALL_MEDIA_PUBLIC_KEY_BYTES
    } else {
        CALL_MEDIA_PQ_ENC_BYTES
    };
    let (enc, ciphertext) = rest.split_at(enc_len.min(rest.len()));
    let key = &keys()[suite][participant];

    let Ok(payload) = open_call_media_grant(key, call_id, sender_leaf, to_leaf, enc, ciphertext)
    else {
        return;
    };
    encode_media_grant_payload(&payload).expect("an opened grant re-encodes");

    let open = |key: &[u8], call_id: &[u8], sender: u32, to: u32| {
        open_call_media_grant(key, call_id, sender, to, enc, ciphertext).is_ok()
    };
    assert!(
        !open(key, call_id, sender_leaf, to_leaf.wrapping_add(1)),
        "a grant opened for another recipient leaf"
    );
    assert!(
        !open(key, call_id, sender_leaf.wrapping_add(1), to_leaf),
        "a grant opened as another sender's"
    );
    let mut other_call = call_id.to_vec();
    other_call[0] ^= 1;
    assert!(
        !open(key, &other_call, sender_leaf, to_leaf),
        "a grant opened in another call"
    );
    assert!(
        !open(
            &keys()[suite][1 - participant],
            call_id,
            sender_leaf,
            to_leaf
        ),
        "a grant opened under another participant's key"
    );
});
