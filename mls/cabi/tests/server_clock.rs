// SPDX-License-Identifier: MIT
//! The server clock offset, through the C door.
//!
//! Its own test binary, because the offset is process-wide: setting it beside
//! `abi.rs`'s live-lane journeys, which run on parallel threads of one
//! process, would move their clocks mid-test.

use peachy_mls_cabi::*;

#[test]
fn the_server_clock_offset_crosses_the_c_door_clamped() {
    assert_eq!(peachy_mls_server_clock_offset_ms(), 0, "0 until set");

    peachy_mls_set_server_clock_offset_ms(-150_000);
    assert_eq!(peachy_mls_server_clock_offset_ms(), -150_000);
    assert_eq!(
        peachy_mls_core::server_clock_offset_ms(),
        -150_000,
        "the core holds what the door set"
    );

    // A server cannot move this device's agreed clock by more than a day.
    peachy_mls_set_server_clock_offset_ms(i64::MAX);
    assert_eq!(
        peachy_mls_server_clock_offset_ms(),
        peachy_mls_core::SERVER_CLOCK_OFFSET_MAX_MS
    );
    peachy_mls_set_server_clock_offset_ms(i64::MIN);
    assert_eq!(
        peachy_mls_server_clock_offset_ms(),
        -peachy_mls_core::SERVER_CLOCK_OFFSET_MAX_MS
    );

    peachy_mls_set_server_clock_offset_ms(0);
    assert_eq!(peachy_mls_server_clock_offset_ms(), 0);
}
