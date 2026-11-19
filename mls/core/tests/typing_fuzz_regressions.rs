// SPDX-License-Identifier: MIT
//! Inputs the `typing_open` fuzz target (`mls/fuzz/fuzz_targets/typing_open.rs`)
//! turned up, kept so the typing sealer keeps refusing them.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use peachy_mls_core::typing::{
    open_typing_wire, parse_typing, seal_typing_wire, TYPING_KEY_BYTES, TYPING_NONCE_BYTES,
};

const KEY: [u8; TYPING_KEY_BYTES] = [7; TYPING_KEY_BYTES];
const NONCE: [u8; TYPING_NONCE_BYTES] = [3; TYPING_NONCE_BYTES];

/// Found by the typing_open fuzz target (its mode byte 1, a text the group
/// seals): a frame's JSON with NULs after it. The sealer took it, and the
/// opener, which strips trailing NULs as padding, opened it to the JSON
/// alone: a frame that opened as other bytes than were sealed.
const TRAILING_NULS: &str =
    "{\"peachy\":\"typing\",\"t\":true,\"u\":\"111111111\",\"v\":1}\0\0\0\0\0\0\0\0";

#[test]
fn a_text_ending_in_nul_is_not_sealed() {
    assert!(seal_typing_wire(&KEY, &NONCE, TRAILING_NULS).is_err());
    assert!(seal_typing_wire(&KEY, &NONCE, "\0").is_err());
}

#[test]
fn what_seals_opens_to_exactly_its_text() {
    let json = TRAILING_NULS.trim_end_matches('\0');
    assert!(parse_typing(json).is_some());
    for text in [json, "", "a\0b"] {
        let frame = seal_typing_wire(&KEY, &NONCE, text).unwrap();
        assert_eq!(open_typing_wire(&KEY, &frame).as_deref(), Some(text));
    }
}
