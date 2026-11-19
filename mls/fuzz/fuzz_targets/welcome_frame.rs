// SPDX-License-Identifier: MIT
//! The padded Welcome frame: what every join reads before OpenMLS sees a
//! byte (`crate::welcome_frame`). docs/mls-core.md §Fuzzing.
//!
//! Input layout: `mode (1) ‖ rest`.
//!
//! - Mode 0: `rest` is read by `unframe_welcome` and
//!   `unframe_welcome_parts`, as a join and a reseat read it.
//! - Any other mode: `rest` is a Welcome the fuzzer chooses, framed to a
//!   length taken from the mode byte, then read back.
//!
//! - No input panics.
//! - Bytes that start with neither magic (version 1, or version 2 with a gap
//!   block) are refused: a Welcome arrives in a frame.
//! - A frame is read exactly when its length is non-zero, fits, a version 2
//!   frame's gap block fits after the Welcome, and every byte after them is
//!   zero; what it reads is the slice the length names, and the block's
//!   bytes for version 2.
//! - A Welcome framed and read back is the same Welcome; the frame is at
//!   least the padded length asked for and no longer than it needs to be,
//!   and any one bit flipped in its fill is refused.

#![no_main]

use libfuzzer_sys::fuzz_target;
use peachy_mls_core::welcome_frame::{
    frame_welcome, unframe_welcome, unframe_welcome_parts, UnframedWelcome, WELCOME_FRAME_BLOCK,
    WELCOME_FRAME_GAP_MAGIC, WELCOME_FRAME_HEADER_BYTES, WELCOME_FRAME_MAGIC,
    WELCOME_GAP_BLOCK_BYTES,
};

/// What `unframe_welcome_parts` should read from `bytes`, written from the
/// layout in the module docs rather than from the reader.
fn expected(bytes: &[u8]) -> Option<UnframedWelcome<'_>> {
    let (rest, block_len) = if let Some(rest) = bytes.strip_prefix(&WELCOME_FRAME_MAGIC[..]) {
        (rest, None)
    } else if let Some(rest) = bytes.strip_prefix(&WELCOME_FRAME_GAP_MAGIC[..]) {
        (rest, Some(WELCOME_GAP_BLOCK_BYTES))
    } else {
        return None;
    };
    if rest.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
    let body = &rest[4..];
    if len == 0 || len > body.len() {
        return None;
    }
    let after = &body[len..];
    let (gap_block, fill) = match block_len {
        None => (None, after),
        Some(n) if n <= after.len() => (Some(&after[..n]), &after[n..]),
        Some(_) => return None,
    };
    if fill.iter().any(|&b| b != 0) {
        return None;
    }
    Some(UnframedWelcome {
        welcome: &body[..len],
        gap_block,
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    if mode == 0 {
        let want = expected(rest);
        assert_eq!(unframe_welcome_parts(rest).ok(), want);
        assert_eq!(unframe_welcome(rest).ok(), want.map(|parts| parts.welcome));
        return;
    }
    let padded_len = usize::from(mode) * WELCOME_FRAME_BLOCK / 16;
    let Ok(framed) = frame_welcome(rest, padded_len) else {
        assert!(rest.is_empty(), "a non-empty Welcome was refused a frame");
        return;
    };
    assert!(framed.len() >= padded_len);
    assert_eq!(
        framed.len(),
        padded_len.max(WELCOME_FRAME_HEADER_BYTES + rest.len())
    );
    assert_eq!(unframe_welcome(&framed).ok(), Some(rest));
    let fill_start = WELCOME_FRAME_HEADER_BYTES + rest.len();
    if fill_start < framed.len() {
        let mut flipped = framed.clone();
        let at = fill_start + usize::from(mode) % (framed.len() - fill_start);
        flipped[at] ^= 1 << (mode % 8);
        assert!(unframe_welcome(&flipped).is_err(), "a dirty fill was read");
    }
});
