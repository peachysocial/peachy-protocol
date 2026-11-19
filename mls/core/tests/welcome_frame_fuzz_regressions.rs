// SPDX-License-Identifier: MIT
//! Inputs the `welcome_frame` fuzz target (`mls/fuzz/fuzz_targets/welcome_frame.rs`)
//! turned up, kept so the reader and the join doors keep refusing them.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use peachy_mls_core::welcome_frame::{
    unframe_welcome, unframe_welcome_parts, WELCOME_FRAME_GAP_MAGIC, WELCOME_GAP_BLOCK_BYTES,
};
use support::{client, issuer};

/// Found by the welcome_frame fuzz target (base64 `AP9QVwIAgAA9`, the target's mode byte 0 then
/// this): a version 2 magic whose length stops after three of its four
/// bytes. The reader refused it, as it should; the target's model knew only
/// the version 1 magic and expected the bytes back unchanged.
const TRUNCATED_GAP_FRAME: [u8; 8] = [0xff, 0x50, 0x57, 0x02, 0x00, 0x80, 0x00, 0x3d];

#[test]
fn a_version_two_frame_cut_inside_its_length_is_refused() {
    assert!(TRUNCATED_GAP_FRAME.starts_with(&WELCOME_FRAME_GAP_MAGIC));
    assert!(unframe_welcome(&TRUNCATED_GAP_FRAME).is_err());
    assert!(unframe_welcome_parts(&TRUNCATED_GAP_FRAME).is_err());
}

#[test]
fn a_version_two_frame_without_room_for_its_gap_block_is_refused() {
    // A whole length and Welcome, then one byte short of the block.
    let mut frame = WELCOME_FRAME_GAP_MAGIC.to_vec();
    frame.extend_from_slice(&1u32.to_be_bytes());
    frame.push(0x00);
    frame.resize(frame.len() + WELCOME_GAP_BLOCK_BYTES - 1, 0);
    assert!(unframe_welcome_parts(&frame).is_err());
    frame.push(0);
    let parts = unframe_welcome_parts(&frame).unwrap();
    assert_eq!(parts.welcome, &[0x00]);
    assert_eq!(
        parts.gap_block.map(<[u8]>::len),
        Some(WELCOME_GAP_BLOCK_BYTES)
    );
}

#[test]
fn the_join_doors_refuse_the_truncated_frame_without_panicking() {
    let s = issuer();
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    assert!(bo.welcome_group(&TRUNCATED_GAP_FRAME).is_err());
    assert!(bo.join_from_welcome(&TRUNCATED_GAP_FRAME).is_err());
}
