// SPDX-License-Identifier: MIT
//! Arbitrary bytes into `decode_call_signal`, the codec every call signal's
//! plaintext goes through on both lanes. docs/mls-core.md §Fuzzing.
//!
//! - No input panics.
//! - Nothing past `MAX_CALL_SIGNAL_BYTES` decodes.
//! - Decoding is canonical: when `x` decodes to `s` (and `s` is a type this
//!   build knows), `encode(s)` decodes to `s` again, and re-encoding gives the
//!   same bytes. An `Unknown` body is the one thing that does not re-encode,
//!   by design: there is nothing to say.
//! - The lane rule is a property of the body alone, so it survives the trip.

#![no_main]

use libfuzzer_sys::fuzz_target;
use peachy_mls_core::call::{
    decode_call_signal, encode_call_signal, CallSignalBody, MAX_CALL_SIGNAL_BYTES,
};

fuzz_target!(|data: &[u8]| {
    let Ok(signal) = decode_call_signal(data) else {
        return;
    };
    assert!(
        data.len() <= MAX_CALL_SIGNAL_BYTES,
        "an oversize signal decoded"
    );
    assert!(signal.version >= 1, "version 0 decoded");
    if signal.body == CallSignalBody::Unknown {
        assert!(
            encode_call_signal(&signal).is_err(),
            "an unknown body encoded"
        );
        return;
    }
    let bytes = encode_call_signal(&signal).expect("a decoded signal re-encodes");
    assert!(bytes.len() <= MAX_CALL_SIGNAL_BYTES);
    let again = decode_call_signal(&bytes).expect("a canonical encoding decodes");
    assert_eq!(again, signal);
    assert_eq!(again.body.is_mls_lane(), signal.body.is_mls_lane());
    assert_eq!(encode_call_signal(&again).expect("re-encodes"), bytes);
});
