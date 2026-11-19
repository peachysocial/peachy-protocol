// SPDX-License-Identifier: MIT
//! Version 3 envelopes, the ones keyed by an epoch's envelope secret rather
//! than the group id: `epoch_envelope_is_for` (the route tag) and
//! `open_epoch_envelope` (the AEAD, the kind and the padded length).
//! `envelope_open` covers the group-id-keyed versions. docs/mls-core.md
//! §Fuzzing.
//!
//! The first input byte's bit 0 picks the layout, since no fuzzer forges an
//! AEAD tag:
//! - clear: `epoch secret (32) ‖ envelope`, the envelope tried under that
//!   secret and under it with one bit flipped, and as two groups'
//!   group-id-keyed envelope (`mls/fixtures/rosters.json`'s version 3 cases
//!   are laid out this way);
//! - set: `kind (1) ‖ spec_len (1) ‖ spec ‖ inner`. The target seals `inner`
//!   as a version 3 envelope of `kind` under the first secret, then
//!   `common::mutate`s it by `spec`.
//!
//! Asserted:
//! - No input panics.
//! - What opens was routed: `epoch_envelope_is_for` holds for its secret.
//! - A version 3 envelope never opens by a group id.
//! - An envelope of a known kind seals; unchanged, it opens under its secret
//!   to its kind and inner bytes, and under no other secret or group; with
//!   any byte changed, it does not open.

#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use peachy_mls_core::envelope::{
    epoch_envelope_is_for, open_envelope_among, open_envelope_for, open_epoch_envelope,
    seal_epoch_envelope_with_nonce, ENVELOPE_VERSION_EPOCH,
};

const SECRET_A: [u8; 32] = [0xa1; 32];
const SECRET_B: [u8; 32] = [0xb2; 32];
const GROUP_A: &[u8] = b"11111111-1111-4111-8111-111111111111";
const GROUP_B: &[u8] = b"22222222-2222-4222-8222-222222222222";
const NONCE: [u8; 12] = [5; 12];

fn never_by_group(envelope: &[u8]) {
    if envelope.first() == Some(&ENVELOPE_VERSION_EPOCH) {
        assert!(open_envelope_for(GROUP_A, envelope).is_err());
        assert!(matches!(
            open_envelope_among([GROUP_A, GROUP_B], envelope),
            Ok(None)
        ));
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    if mode & 1 == 0 {
        let Some((secret, envelope)) = rest.split_first_chunk::<32>() else {
            return;
        };
        let mut other = *secret;
        other[0] ^= 1;
        let opened = open_epoch_envelope(secret, envelope).is_ok();
        if opened {
            assert!(
                epoch_envelope_is_for(secret, envelope),
                "an epoch envelope opened that its tag did not route"
            );
        }
        assert!(
            !(opened && open_epoch_envelope(&other, envelope).is_ok()),
            "an epoch envelope opened under two secrets"
        );
        never_by_group(envelope);
        return;
    }

    let [kind, spec_len, rest @ ..] = rest else {
        return;
    };
    let Some((spec, inner)) = rest.split_at_checked(usize::from(*spec_len)) else {
        return;
    };
    let Ok(sealed) = seal_epoch_envelope_with_nonce(&SECRET_A, *kind, inner, &NONCE) else {
        return;
    };
    assert_eq!(sealed[0], ENVELOPE_VERSION_EPOCH);
    never_by_group(&sealed);
    assert!(
        open_epoch_envelope(&SECRET_B, &sealed).is_err(),
        "an epoch envelope opened under another epoch's secret"
    );
    let changed = common::mutate(&sealed, spec);
    let opened = open_epoch_envelope(&SECRET_A, &changed);
    if changed == sealed {
        let (opened_kind, opened_inner) = opened.expect("an epoch envelope opens under its secret");
        assert_eq!(
            (opened_kind, opened_inner.to_vec()),
            (*kind, inner.to_vec())
        );
    } else {
        assert!(opened.is_err(), "a changed epoch envelope opened");
    }
});
