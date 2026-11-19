// SPDX-License-Identifier: MIT
//! The live lane's replay window past its per-leaf cap (`MAX_SEEN`), found by
//! the `call_envelope_open` fuzz target: a stamp below every one a full
//! record held was forgotten as it was accepted, so the same frame opened
//! again on every replay. docs/calls.md §The live lane's replay
//! window.

use peachy_mls_core::call::replay::MAX_SEEN;
use peachy_mls_core::call::{LiveReplayVerdict, LiveReplayWindow};

const NOW: u64 = 1_789_516_800_000;
const CALL: [u8; 16] = [1; 16];

fn check(window: &mut LiveReplayWindow, stamp: u64, mono: u64) -> LiveReplayVerdict {
    window.check(b"g", CALL, 1, 0, stamp, NOW, mono)
}

#[test]
fn a_stamp_below_a_full_record_is_a_duplicate_when_replayed() {
    let mut window = LiveReplayWindow::new();
    for i in 0..MAX_SEEN as u64 {
        assert_eq!(
            check(&mut window, NOW + 1_000 + i, i),
            LiveReplayVerdict::Accepted
        );
    }
    let mono = MAX_SEEN as u64;
    assert_eq!(check(&mut window, NOW, mono), LiveReplayVerdict::Accepted);
    assert_eq!(
        check(&mut window, NOW, mono + 1),
        LiveReplayVerdict::Duplicate
    );
    assert_eq!(window.stamps(), MAX_SEEN);
}

#[test]
fn stamps_forged_ahead_of_a_leaf_leave_its_own_frames_unreplayable() {
    let mut window = LiveReplayWindow::new();
    // A member claims the leaf and fills its record with stamps ahead of the
    // leaf's clock.
    for i in 0..MAX_SEEN as u64 {
        assert_eq!(
            check(&mut window, NOW + 100_000 + i, i),
            LiveReplayVerdict::Accepted
        );
    }
    // The leaf's own heartbeats, every 10 s, each replayed by the server.
    let mut mono = MAX_SEEN as u64;
    for beat in 0..12u64 {
        let stamp = NOW - 60_000 + beat * 10_000;
        assert_eq!(check(&mut window, stamp, mono), LiveReplayVerdict::Accepted);
        mono += 1;
        assert_eq!(
            check(&mut window, stamp, mono),
            LiveReplayVerdict::Duplicate,
            "heartbeat {beat} opened twice"
        );
        mono += 1;
    }
}
