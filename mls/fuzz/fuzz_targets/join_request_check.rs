// SPDX-License-Identifier: MIT
//! A signed seat ask: arbitrary proofs into `check_join_request`, and honest
//! ones signed at a time the fuzzer picks. docs/mls-core.md §Fuzzing.
//!
//! The first input byte picks what the rest is:
//! - even: a proof, as it would arrive in a join inbox;
//! - odd: `issued_at (8, big-endian) ‖ nonce (16) ‖ flip position (2,
//!   optional)`, signed by the device's real key and, if a flip position is
//!   there, with that one bit flipped.
//!
//! - No input panics, and a verdict's code names it.
//! - `Malformed` exactly when the proof does not parse.
//! - An honest proof is `Accepted`, `Stale` or `FromTheFuture` exactly as its
//!   time says; a proof with any one bit flipped is never `Accepted`.
//! - What is accepted for this group, actor and device is refused for another
//!   group, another actor and another device key.

#![no_main]

use libfuzzer_sys::fuzz_target;
use peachy_mls_core::issuer::device_key_pair;
use peachy_mls_core::{
    check_join_request, join_request_nonce, sign_join_request, JoinRequestVerdict, PeachyIdentity,
    JOIN_REQUEST_FUTURE_SKEW_SECONDS, JOIN_REQUEST_MAX_AGE_SECONDS, JOIN_REQUEST_NONCE_BYTES,
    JOIN_REQUEST_PROOF_BYTES,
};

/// 2026-09-16T00:00:00Z, the integration tests' clock.
const NOW: i64 = 1_789_516_800;
const GROUP: &[u8] = b"3f1c2b8e-7a41-4d2c-9b1e-000000000001";
const OTHER_GROUP: &[u8] = b"3f1c2b8e-7a41-4d2c-9b1e-000000000002";
const ACTOR: &str = "actor-ada";
const DEVICE: &str = "device-ada-phone";
const SEED: [u8; 32] = [0x11; 32];

fn identity(device_key: [u8; 32]) -> PeachyIdentity {
    PeachyIdentity {
        actor_id: ACTOR.to_owned(),
        device_id: DEVICE.to_owned(),
        device_key,
        kid: "fe812c12".to_owned(),
        expires_at: NOW + 86_400,
        issued_at: NOW - 3_600,
        account_key: None,
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let signer = identity(device_key_pair(&SEED).1);

    let proof = if mode & 1 == 0 {
        rest.to_vec()
    } else {
        let Some((issued_at, rest)) = rest.split_first_chunk::<8>() else {
            return;
        };
        let Some((nonce, rest)) = rest.split_first_chunk::<JOIN_REQUEST_NONCE_BYTES>() else {
            return;
        };
        let issued_at = i64::from_be_bytes(*issued_at);
        let mut proof = sign_join_request(&SEED, GROUP, ACTOR, DEVICE, issued_at, nonce)
            .expect("an honest ask signs");
        assert_eq!(proof.len(), JOIN_REQUEST_PROOF_BYTES);
        assert_eq!(join_request_nonce(&proof), Some(*nonce));

        let expected = if issued_at < NOW.saturating_sub(JOIN_REQUEST_MAX_AGE_SECONDS) {
            JoinRequestVerdict::Stale
        } else if issued_at > NOW.saturating_add(JOIN_REQUEST_FUTURE_SKEW_SECONDS) {
            JoinRequestVerdict::FromTheFuture
        } else {
            JoinRequestVerdict::Accepted
        };
        assert_eq!(
            check_join_request(&signer, GROUP, ACTOR, DEVICE, &proof, NOW),
            expected
        );

        if let Some((flip, _)) = rest.split_first_chunk::<2>() {
            let bit = usize::from(u16::from_be_bytes(*flip)) % (proof.len() * 8);
            proof[bit / 8] ^= 1 << (bit % 8);
            assert_ne!(
                check_join_request(&signer, GROUP, ACTOR, DEVICE, &proof, NOW),
                JoinRequestVerdict::Accepted,
                "a proof with a flipped bit was accepted"
            );
        }
        proof
    };

    let verdict = check_join_request(&signer, GROUP, ACTOR, DEVICE, &proof, NOW);
    assert_eq!(JoinRequestVerdict::from_code(verdict.code()), Some(verdict));
    assert_eq!(
        verdict == JoinRequestVerdict::Malformed,
        join_request_nonce(&proof).is_none(),
        "Malformed exactly when the proof does not parse"
    );
    if verdict.is_accepted() {
        assert_eq!(
            check_join_request(&signer, OTHER_GROUP, ACTOR, DEVICE, &proof, NOW),
            JoinRequestVerdict::BadSignature
        );
        assert_eq!(
            check_join_request(&signer, GROUP, "actor-bo", DEVICE, &proof, NOW),
            JoinRequestVerdict::IdentityMismatch
        );
        let stranger = identity(device_key_pair(&[0x22; 32]).1);
        assert_eq!(
            check_join_request(&stranger, GROUP, ACTOR, DEVICE, &proof, NOW),
            JoinRequestVerdict::BadSignature
        );
    }
});
