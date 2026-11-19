// SPDX-License-Identifier: MIT
//! What the targets that drive a real group share: devices certified by the
//! test issuer on a fixed clock, and the one mutation a target applies to a
//! real object. Not a target itself (no `[[bin]]` names it).

#![allow(dead_code)]

use peachy_mls_core::issuer::{device_key_pair, TestIssuer};
use peachy_mls_core::{
    account_identity_public_key, Client, ClientConfig, FixedClock, PeachyStorage,
};

/// 2026-09-16T00:00:00Z, the integration tests' clock.
pub const NOW: i64 = 1_789_516_800;

pub const GROUP: &[u8] = b"11111111-1111-4111-8111-111111111111";

pub fn issuer() -> TestIssuer {
    TestIssuer::from_seed(&[7u8; 32])
}

/// A device of `actor`, certified under the actor's test account key and
/// holding that key, as an approved device does, so it can mint key packages.
pub fn device(issuer: &TestIssuer, n: u8, actor: &str, device: &str) -> Client {
    let mut seed = [0u8; 32];
    seed[0] = n;
    let (_, public) = device_key_pair(&seed);
    let token = issuer
        .issue(actor, device, &public, NOW - 3_600, NOW + 30 * 86_400)
        .expect("the test issuer mints");
    let held = account_identity_public_key(&TestIssuer::test_account_key(actor))
        .expect("a test account key derives an identity key");
    let mut config = ClientConfig::new(token, seed, issuer.trusted_keys().expect("trusted keys"))
        .with_storage(PeachyStorage::in_memory())
        .with_own_account_identity(Some(held));
    config.clock = Some(Box::new(FixedClock(NOW)));
    Client::new(config).expect("a client")
}

/// `real` with the fuzzer's bytes XORed in: `spec` is `offset (2,
/// big-endian) ‖ mask`, the offset taken modulo the length and the mask
/// applied from there, wrapping. Changes nothing when the mask is all zero.
pub fn mutate(real: &[u8], spec: &[u8]) -> Vec<u8> {
    let mut out = real.to_vec();
    if out.is_empty() || spec.len() < 2 {
        return out;
    }
    let start = usize::from(u16::from_be_bytes([spec[0], spec[1]])) % out.len();
    for (i, mask) in spec[2..].iter().enumerate() {
        let at = (start + i) % out.len();
        out[at] ^= mask;
    }
    out
}
