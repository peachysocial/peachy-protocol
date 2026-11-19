// SPDX-License-Identifier: MIT
//! Seal whatever the fuzzer chooses, then check three things. It opens to
//! exactly what was sealed. It does not open for another group. And flipping
//! any one bit of it makes it refuse to open: the envelope's integrity covers
//! the version, the nonce, the route tag and the kind.
//!
//! Input layout: `kind (1) ‖ flip position (2, big-endian) ‖ inner (rest)`.
//! docs/mls-core.md §Fuzzing.

#![no_main]

use libfuzzer_sys::fuzz_target;
use peachy_mls_core::envelope::{open_envelope_for, seal_envelope_with_nonce};

const GROUP_A: &[u8] = b"11111111-1111-4111-8111-111111111111";
const GROUP_B: &[u8] = b"22222222-2222-4222-8222-222222222222";
const NONCE: [u8; 12] = [7; 12];

fuzz_target!(|data: &[u8]| {
    let Some((&kind, rest)) = data.split_first() else {
        return;
    };
    let Some((flip, inner)) = rest.split_first_chunk::<2>() else {
        return;
    };
    let Ok(sealed) = seal_envelope_with_nonce(GROUP_A, kind, inner, &NONCE) else {
        return; // an unknown kind is refused at seal time, which is correct
    };

    let opened = open_envelope_for(GROUP_A, &sealed).expect("a sealed envelope opens");
    assert_eq!(opened.kind, kind);
    assert_eq!(opened.inner, inner);
    assert!(open_envelope_for(GROUP_B, &sealed).is_err());

    let bit = usize::from(u16::from_be_bytes(*flip)) % (sealed.len() * 8);
    let mut tampered = sealed.clone();
    tampered[bit / 8] ^= 1 << (bit % 8);
    assert!(
        open_envelope_for(GROUP_A, &tampered).is_err(),
        "a flipped bit still opened"
    );
});
