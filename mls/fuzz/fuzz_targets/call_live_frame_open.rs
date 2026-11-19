// SPDX-License-Identifier: MIT
//! The live lane's frame: arbitrary bytes into `open_live_frame` under a
//! fixed key, then the fuzzer's bytes sealed as a frame and attacked.
//! docs/mls-core.md §Fuzzing.
//!
//! - No input panics, and a forged frame never opens.
//! - A sealed frame opens to exactly what was sealed, stamp included.
//! - Its length is hidden: every frame is a whole number of padding blocks.
//! - The MLS lane byte in the lane position refuses, so an unauthenticated
//!   live frame can never be read as a ring-lane `Hangup` or `Remove`.
//! - Any one flipped bit refuses, and so does another key.

#![no_main]

use libfuzzer_sys::fuzz_target;
use peachy_mls_core::call::{
    open_live_frame, seal_live_frame_with_nonce, LiveStamp, CALL_LANE_MLS, CALL_LIVE_PADDING_BLOCK,
};

const KEY: [u8; 32] = [9; 32];
const OTHER_KEY: [u8; 32] = [8; 32];
const NONCE: [u8; 12] = [3; 12];
/// Lane byte, nonce, GCM tag.
const OVERHEAD: usize = 1 + 12 + 16;

fuzz_target!(|data: &[u8]| {
    // Forging a GCM tag is not something a fuzzer does.
    assert!(
        open_live_frame(&KEY, data).is_err(),
        "a forged live frame opened"
    );

    // The stamp, from the input too, so every value of it is exercised.
    let mut head = [0u8; 12];
    for (slot, byte) in head.iter_mut().zip(data) {
        *slot = *byte;
    }
    let stamp = LiveStamp {
        sender_leaf: u32::from_be_bytes([head[0], head[1], head[2], head[3]]),
        sent_at_ms: u64::from_be_bytes([
            head[4], head[5], head[6], head[7], head[8], head[9], head[10], head[11],
        ]),
    };
    let Ok(sealed) = seal_live_frame_with_nonce(&KEY, stamp, data, &NONCE) else {
        assert!(
            data.len() > usize::from(u16::MAX),
            "a sealable signal was refused"
        );
        return;
    };
    assert_eq!(
        (sealed.len() - OVERHEAD) % CALL_LIVE_PADDING_BLOCK,
        0,
        "length not padded"
    );
    assert_eq!(
        open_live_frame(&KEY, &sealed).expect("opens"),
        (stamp, data.to_vec())
    );
    assert!(
        open_live_frame(&OTHER_KEY, &sealed).is_err(),
        "opened under another key"
    );

    let mut lane = sealed.clone();
    lane[0] = CALL_LANE_MLS;
    assert!(
        open_live_frame(&KEY, &lane).is_err(),
        "an MLS-lane byte opened as live"
    );

    // One flipped bit, at a position the input picks.
    let at = data.iter().fold(0usize, |acc, b| {
        acc.wrapping_mul(31).wrapping_add(usize::from(*b))
    }) % (sealed.len() * 8);
    let mut flipped = sealed.clone();
    flipped[at / 8] ^= 1 << (at % 8);
    assert!(
        open_live_frame(&KEY, &flipped).is_err(),
        "a flipped bit at {at} opened"
    );

    // A truncated frame never opens either.
    assert!(open_live_frame(&KEY, &sealed[..sealed.len() - 1]).is_err());
});
