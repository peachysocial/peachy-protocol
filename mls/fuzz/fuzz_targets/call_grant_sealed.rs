// SPDX-License-Identifier: MIT
//! Near-valid media grants through `open_call_media_grant`: the target seals
//! a real grant to a real call key, under either suite, then changes one
//! field, so the fuzzer's bytes reach past the HPKE open that
//! `call_grant_open`'s arbitrary bytes never get through.
//! docs/mls-core.md §Fuzzing.
//!
//! Input: `mode (1) ‖ call_id (16) ‖ sender_leaf (4, BE) ‖ to_leaf (4, BE) ‖
//! spec_len (1) ‖ spec (spec_len) ‖ body`.
//!
//! - `mode` bit 0: the X-Wing suite, else X25519.
//! - `mode` bit 1: `body` is the plaintext itself, sealed with HPKE exactly
//!   as `seal_call_media_grant` seals (same suite, same `info`, empty aad),
//!   so the codec sees bytes no encoder writes after a real open. Clear:
//!   `body` is a payload, `generation (4, BE) ‖ secret (32) ‖ session id ‖
//!   0x00 ‖ track ‖ 0x00 ‖ track …` (text read lossily as UTF-8), sealed with
//!   `seal_call_media_grant` under X-Wing. That door seals to no X25519 key,
//!   so under X25519 the target seals the encoded payload itself.
//! - `mode` bits 2-4, the field `spec` changes once sealed: 0 none, 1 `enc`,
//!   2 the ciphertext, 3 the call id (each `common::mutate`d by `spec`), 4 the
//!   sender leaf, 5 the recipient leaf (each XORed with `spec`'s first four
//!   bytes), 6 the recipient key (the other participant's), 7 the ciphertext
//!   cut short by `spec[0] + 1` bytes.
//!
//! Asserted:
//! - No input panics.
//! - A payload seals to an X-Wing key exactly when it encodes, and never to
//!   an X25519 key; an unchanged grant opens to exactly the payload sealed; an unchanged raw grant opens exactly when
//!   `decode_media_grant_payload` reads its plaintext, to what it reads.
//! - A grant changed in any field does not open.

#![no_main]

mod common;

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::crypto::OpenMlsCrypto as _;
use peachy_mls_core::call::{
    call_media_grant_info, call_media_key_pair, call_media_pq_key_pair, decode_media_grant_payload,
    encode_media_grant_payload, open_call_media_grant, seal_call_media_grant, MediaGrantPayload,
    CALL_ID_BYTES, CALL_MEDIA_HPKE, CALL_MEDIA_HPKE_PQ,
};

/// One participant's call keys, `(private, public)`.
type Pair = (Vec<u8>, Vec<u8>);

/// `[suite][participant]`, suite 0 X25519 and 1 X-Wing.
fn keys() -> &'static [[Pair; 2]; 2] {
    static KEYS: OnceLock<[[Pair; 2]; 2]> = OnceLock::new();
    KEYS.get_or_init(|| {
        let classical = |n: u8| {
            let (private, public) = call_media_key_pair(&[n; 32]).expect("an X25519 call key");
            (private, public.to_vec())
        };
        let pq = |n: u8| call_media_pq_key_pair(&[n; 32]).expect("an X-Wing call key");
        [[classical(1), classical(2)], [pq(1), pq(2)]]
    })
}

const HEADER: usize = 1 + CALL_ID_BYTES + 4 + 4 + 1;

/// A payload from the fuzzer's bytes, or `None` when they are too short.
fn payload(body: &[u8]) -> Option<MediaGrantPayload> {
    let generation = u32::from_be_bytes(body.get(..4)?.try_into().ok()?);
    let secret: [u8; 32] = body.get(4..36)?.try_into().ok()?;
    let mut texts = body[36..]
        .split(|&b| b == 0)
        .map(|part| String::from_utf8_lossy(part).into_owned());
    let session_id = texts.next().unwrap_or_default();
    Some(MediaGrantPayload {
        generation,
        secret: secret.into(),
        session_id,
        track_names: texts.collect(),
    })
}

/// `plaintext` sealed as `seal_call_media_grant` seals, under `config`.
fn hpke_seal(
    config: openmls_traits::types::HpkeConfig,
    public_key: &[u8],
    call_id: &[u8],
    sender_leaf: u32,
    to_leaf: u32,
    plaintext: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let sealed = RustCrypto::default()
        .hpke_seal(
            config,
            public_key,
            &call_media_grant_info(call_id, sender_leaf, to_leaf),
            &[],
            plaintext,
        )
        .expect("HPKE seals to a real key");
    (
        sealed.kem_output.as_slice().to_vec(),
        sealed.ciphertext.as_slice().to_vec(),
    )
}

fn xor4(value: u32, spec: &[u8]) -> u32 {
    let mut mask = [0u8; 4];
    for (m, s) in mask.iter_mut().zip(spec) {
        *m = *s;
    }
    value ^ u32::from_be_bytes(mask)
}

fuzz_target!(|data: &[u8]| {
    if data.len() < HEADER {
        return;
    }
    let mode = data[0];
    let call_id = &data[1..1 + CALL_ID_BYTES];
    let at = 1 + CALL_ID_BYTES;
    let sender_leaf = u32::from_be_bytes(data[at..at + 4].try_into().expect("4 bytes"));
    let to_leaf = u32::from_be_bytes(data[at + 4..at + 8].try_into().expect("4 bytes"));
    let spec_len = usize::from(data[at + 8]);
    let Some(spec) = data.get(HEADER..HEADER + spec_len) else {
        return;
    };
    let body = &data[HEADER + spec_len..];
    let suite = usize::from(mode & 1);
    let raw = mode & 2 != 0;
    let field = (mode >> 2) & 7;
    let (private_key, public_key) = &keys()[suite][0];

    // Seal, and what an unchanged grant must open to.
    let config = if suite == 0 {
        CALL_MEDIA_HPKE
    } else {
        CALL_MEDIA_HPKE_PQ
    };
    let (enc, ciphertext, expected) = if raw {
        let (enc, ciphertext) = hpke_seal(config, public_key, call_id, sender_leaf, to_leaf, body);
        (enc, ciphertext, decode_media_grant_payload(body).ok())
    } else {
        let Some(payload) = payload(body) else {
            return;
        };
        let sealed = seal_call_media_grant(public_key, call_id, sender_leaf, to_leaf, &payload);
        let encoded = encode_media_grant_payload(&payload);
        if suite == 0 {
            assert!(sealed.is_err(), "a grant sealed to an X25519 key");
        } else {
            assert_eq!(
                sealed.is_ok(),
                encoded.is_ok(),
                "a payload sealed and did not encode, or the other way round"
            );
        }
        let Ok(plaintext) = encoded else {
            return;
        };
        let (enc, ciphertext) = match sealed {
            Ok(sealed) => sealed,
            Err(_) => hpke_seal(
                config,
                public_key,
                call_id,
                sender_leaf,
                to_leaf,
                &plaintext,
            ),
        };
        (enc, ciphertext, Some(payload))
    };

    let (mut enc2, mut ciphertext2, mut call_id2) =
        (enc.clone(), ciphertext.clone(), call_id.to_vec());
    let (mut sender2, mut to2, mut key2) = (sender_leaf, to_leaf, private_key);
    match field {
        1 => enc2 = common::mutate(&enc, spec),
        2 => ciphertext2 = common::mutate(&ciphertext, spec),
        3 => call_id2 = common::mutate(call_id, spec),
        4 => sender2 = xor4(sender_leaf, spec),
        5 => to2 = xor4(to_leaf, spec),
        6 => key2 = &keys()[suite][1].0,
        7 => {
            let cut = usize::from(spec.first().copied().unwrap_or(0)) + 1;
            ciphertext2.truncate(ciphertext.len().saturating_sub(cut));
        }
        _ => {}
    }
    let changed = enc2 != enc
        || ciphertext2 != ciphertext
        || call_id2 != call_id
        || sender2 != sender_leaf
        || to2 != to_leaf
        || field == 6;

    let opened = open_call_media_grant(key2, &call_id2, sender2, to2, &enc2, &ciphertext2);
    if changed {
        assert!(opened.is_err(), "a grant changed in field {field} opened");
    } else {
        assert_eq!(
            opened.ok(),
            expected,
            "an unchanged grant opened to something else"
        );
    }
});
