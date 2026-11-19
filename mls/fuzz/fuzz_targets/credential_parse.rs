// SPDX-License-Identifier: MIT
//! The device credential: arbitrary bytes into `DeviceCredential::parse` and
//! `PeachyIdentityProvider::validate_token`, the door every leaf, key package
//! and Welcome credential goes through. docs/mls-core.md §Fuzzing.
//!
//! The first input byte picks what the rest is, since no fuzzer forges an
//! Ed25519 signature:
//! - even: a whole token, as it would arrive in a leaf;
//! - odd: a payload, signed by the trusted test issuer under the `pdc1`
//!   prefix, so the payload's own parsing and every check after the
//!   signature is reached.
//!
//! - No input panics, and a token that does not parse never validates.
//! - What parses keeps its bytes, and parses again to the same payload and key.
//! - The account certificate is present exactly when the payload names an
//!   account key.
//! - What validates says what the payload says, under another leaf key it is
//!   refused, and under another issuer it is refused.

#![no_main]

use libfuzzer_sys::fuzz_target;
use peachy_mls_core::issuer::TestIssuer;
use peachy_mls_core::{DeviceCredential, FixedClock, PeachyIdentityProvider};

/// 2026-09-16T00:00:00Z, the integration tests' clock.
const NOW: i64 = 1_789_516_800;

fn provider(issuer: &TestIssuer) -> PeachyIdentityProvider {
    PeachyIdentityProvider::with_clock(
        issuer.trusted_keys().expect("the test issuer's keys load"),
        Box::new(FixedClock(NOW)),
    )
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let issuer = TestIssuer::from_seed(&[7; 32]);
    let token = if mode & 1 == 0 {
        rest.to_vec()
    } else {
        issuer.issue_raw("pdc1", rest)
    };

    let parsed = DeviceCredential::parse(&token);
    if let Ok(credential) = &parsed {
        assert_eq!(credential.token(), &token[..]);
        let again =
            DeviceCredential::parse(credential.token()).expect("a parsed token parses again");
        assert_eq!(again.payload(), credential.payload());
        assert_eq!(again.device_key(), credential.device_key());
        assert_eq!(
            credential.account().is_some(),
            !credential.payload().account_key.is_empty(),
            "the account certificate is there exactly when the payload names an account key"
        );
    }

    // The leaf key the token itself names, so that a validation can succeed.
    let leaf = parsed.as_ref().map(|c| *c.device_key()).unwrap_or([0; 32]);
    let validated = provider(&issuer).validate_token(&token, &leaf);
    let Ok(identity) = validated else {
        return;
    };
    let credential = parsed.expect("a token that validates parses");
    let payload = credential.payload();
    assert_eq!(identity.actor_id, payload.actor_id);
    assert_eq!(identity.device_id, payload.device_id);
    assert_eq!(identity.kid, payload.kid);
    assert_eq!(identity.issued_at, payload.iat);
    assert_eq!(identity.expires_at, payload.exp);
    assert_eq!(identity.device_key, leaf);
    assert_eq!(
        identity.account_key,
        credential.account().map(|(key, _)| *key)
    );

    let mut other_leaf = leaf;
    other_leaf[0] ^= 1;
    assert!(
        provider(&issuer)
            .validate_token(&token, &other_leaf)
            .is_err(),
        "a credential validated for a leaf key it does not bind"
    );
    assert!(
        provider(&TestIssuer::from_seed(&[8; 32]))
            .validate_token(&token, &leaf)
            .is_err(),
        "a credential validated under an issuer that did not sign it"
    );
});
