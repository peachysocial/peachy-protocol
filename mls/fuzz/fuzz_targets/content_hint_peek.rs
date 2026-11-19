// SPDX-License-Identifier: MIT
//! The content hint and the keyless peek: what a receiver reads off a group
//! message before, or instead of, opening it (`crate::hint`).
//! docs/mls-core.md §Fuzzing.
//!
//! Input layout: `mode (1) ‖ rest`.
//!
//! - Mode 0: `rest` is a message's authenticated data, read by
//!   `hint_from_aad` and `commitment_from_aad`.
//! - Mode 2: `hint (1) ‖ plaintext`, read by `resend_secret_of`.
//! - Any other mode: `rest` is a whole group message, read by
//!   `peek_message`.
//!
//! - No input panics.
//! - `hint_from_aad` answers a hint exactly when the bytes start with the
//!   tag, the version and one of the four known hints, and that hint's own
//!   AAD reads back as the same hint.
//! - `commitment_from_aad` answers the 16 bytes after a known hint exactly
//!   when they are there and not all zero, and a commitment written into an
//!   AAD reads back.
//! - `resend_secret_of` answers a secret only for the two resendable hints: a
//!   transcript frame's UUID, lowercased, or a salted lane frame whole.
//! - A peek's hint obeys the same rule, and `hint_is_urgent` is true exactly
//!   for the two resendable hints.

#![no_main]

use libfuzzer_sys::fuzz_target;
use peachy_mls_core::hint::{
    commitment_from_aad, hint_aad, hint_aad_with_commitment, hint_from_aad, hint_is_urgent,
    peek_message, resend_secret_of, CONTENT_HINT_DEFAULT, CONTENT_HINT_IMPLICIT,
    CONTENT_HINT_RESENDABLE, CONTENT_HINT_RESENDABLE_LANE, RESEND_COMMITMENT_BYTES,
};

const KNOWN: [u8; 4] = [
    CONTENT_HINT_DEFAULT,
    CONTENT_HINT_RESENDABLE,
    CONTENT_HINT_IMPLICIT,
    CONTENT_HINT_RESENDABLE_LANE,
];

fn check_hint(hint: u8) {
    assert!(KNOWN.contains(&hint), "an unknown hint was answered");
    assert_eq!(hint_from_aad(&hint_aad(hint)), Some(hint));
    assert_eq!(
        hint_is_urgent(hint),
        matches!(hint, CONTENT_HINT_RESENDABLE | CONTENT_HINT_RESENDABLE_LANE)
    );
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    if mode == 0 {
        let read = hint_from_aad(rest);
        let expected = match rest {
            [0x70, 0x01, hint, ..] if KNOWN.contains(hint) => Some(*hint),
            _ => None,
        };
        assert_eq!(read, expected);
        if let Some(hint) = read {
            check_hint(hint);
        }
        let commitment = commitment_from_aad(rest);
        let tail = rest.get(3..3 + RESEND_COMMITMENT_BYTES);
        let expected: Option<[u8; RESEND_COMMITMENT_BYTES]> = match (read, tail) {
            (Some(_), Some(tail)) if tail.iter().any(|b| *b != 0) => tail.try_into().ok(),
            _ => None,
        };
        assert_eq!(commitment, expected);
        if let (Some(hint), Some(commitment)) = (read, commitment) {
            let written = hint_aad_with_commitment(hint, Some(commitment));
            assert_eq!(commitment_from_aad(&written), Some(commitment));
            assert_eq!(hint_from_aad(&written), Some(hint));
        }
    } else if mode == 2 {
        let Some((&hint, plaintext)) = rest.split_first() else {
            return;
        };
        let Some(secret) = resend_secret_of(hint, plaintext) else {
            return;
        };
        match hint {
            CONTENT_HINT_RESENDABLE => {
                assert_eq!(plaintext.first(), Some(&0xFF));
                assert_eq!(secret.len(), 36);
                assert!(secret.iter().enumerate().all(|(at, b)| match at {
                    8 | 13 | 18 | 23 => *b == b'-',
                    _ => b.is_ascii_digit() || (b'a'..=b'f').contains(b),
                }));
            }
            CONTENT_HINT_RESENDABLE_LANE => assert_eq!(secret, plaintext),
            _ => panic!("a secret for hint {hint}, which no answer carries"),
        }
    } else if let Some(peek) = peek_message(rest) {
        if let Some(hint) = peek.hint {
            check_hint(hint);
        }
    }
});
