// SPDX-License-Identifier: MIT
//! Arbitrary bytes from the mailbox, opened as an envelope: no input may
//! panic, and nothing may open for a group it was not sealed for.
//!
//! Every sealed byte a device receives (message, commit, seat ask, typing
//! frame, and a call signal, kind 6) goes through this door
//! before anything else reads it, and the server or any sender chooses those
//! bytes. docs/mls-core.md §Fuzzing.

#![no_main]

use libfuzzer_sys::fuzz_target;
use peachy_mls_core::envelope::{envelope_is_for, open_envelope_among, open_envelope_for};

const GROUP_A: &[u8] = b"11111111-1111-4111-8111-111111111111";
const GROUP_B: &[u8] = b"22222222-2222-4222-8222-222222222222";

fuzz_target!(|data: &[u8]| {
    let _ = envelope_is_for(GROUP_A, data);
    let _ = open_envelope_for(GROUP_A, data);
    if let Ok(Some(opened)) = open_envelope_among([GROUP_A, GROUP_B], data) {
        // Forging an AEAD tag is not something a fuzzer does. If one opens,
        // it must at least be for one of the groups we offered.
        assert!(opened.group_id == GROUP_A || opened.group_id == GROUP_B);
    }
});
