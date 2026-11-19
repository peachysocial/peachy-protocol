// SPDX-License-Identifier: MIT
//! Arbitrary bytes into `decode_media_grant_payload`, the codec a call media
//! grant's plaintext goes through once `open_call_media_grant` has opened it.
//! `call_grant_open` and `call_grant_sealed` drive the open itself.
//! docs/mls-core.md §Fuzzing.
//!
//! - No input panics.
//! - Decoding is canonical: when `x` decodes to `p`, `encode(p)` decodes to
//!   `p` again, and re-encoding gives the same bytes.
//! - What decodes keeps the encoder's bounds, so it always re-encodes.

#![no_main]

use libfuzzer_sys::fuzz_target;
use peachy_mls_core::call::{decode_media_grant_payload, encode_media_grant_payload};

fuzz_target!(|data: &[u8]| {
    let Ok(payload) = decode_media_grant_payload(data) else {
        return;
    };
    let bytes = encode_media_grant_payload(&payload).expect("a decoded grant re-encodes");
    let again = decode_media_grant_payload(&bytes).expect("a canonical encoding decodes");
    assert_eq!(again, payload);
    assert_eq!(
        encode_media_grant_payload(&again).expect("re-encodes"),
        bytes
    );
});
