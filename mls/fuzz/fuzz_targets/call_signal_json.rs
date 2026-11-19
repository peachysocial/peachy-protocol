// SPDX-License-Identifier: MIT
//! The JSON door the bindings and the fixture use: arbitrary text into
//! `signal_from_json`. docs/mls-core.md §Fuzzing.
//!
//! - No input panics.
//! - Whatever parses prints, and the printed form parses to the same value.
//! - When it is also encodable (the binary codec refuses an `Unknown` body,
//!   version 0 and anything past the size bounds), the binary form decodes to
//!   the same value too: the JSON and binary doors never disagree.

#![no_main]

use libfuzzer_sys::fuzz_target;
use peachy_mls_core::call::{
    decode_call_signal, encode_call_signal, signal_from_json, signal_to_json,
};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(signal) = signal_from_json(text) else {
        return;
    };
    let json = signal_to_json(&signal).expect("a parsed signal prints");
    assert_eq!(signal_from_json(&json).expect("re-parses"), signal);
    assert_eq!(
        signal_to_json(&signal_from_json(&json).expect("re-parses")).expect("prints"),
        json
    );
    if let Ok(bytes) = encode_call_signal(&signal) {
        assert_eq!(decode_call_signal(&bytes).expect("decodes"), signal);
    }
});
