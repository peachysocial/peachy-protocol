// SPDX-License-Identifier: MIT
//! An envelope's length says how big it is, never what kind it is
//! (docs/delivery.md §The wrapped envelope).
//!
//! Every kind is padded by the same rule, so a seat ask, a typing frame, a
//! call frame and every MLS message of a short length are one size on the
//! wire, and a longer one lands in a bucket that depends on its length alone.
//!
//! That is version 2, whose layout version 3 shares (mls/core/src/envelope.rs
//! §Versions); version 3 needs a group's epoch, so these seal version 2,
//! keyed by the group id.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use peachy_mls_core::envelope::{
    open_envelope_for, padded_envelope_len, seal_group_id_envelope, ENVELOPE_KIND_CALL,
    ENVELOPE_KIND_COMMIT, ENVELOPE_KIND_LINK_PREVIEW, ENVELOPE_KIND_MESSAGE,
    ENVELOPE_KIND_SEAT_ASK, ENVELOPE_KIND_TYPING,
};

use peachy_mls_core::hint::{
    CONTENT_HINT_IMPLICIT, CONTENT_HINT_RESENDABLE, CONTENT_HINT_RESENDABLE_LANE,
};
use peachy_mls_core::Client;
use support::{client, issuer};

const G: &[u8] = b"0f8e2a1c-5b7d-4e9a-8c3f-2d1b6a9e7c40";
const ADA: &str = "5b0f5a52-8a55-4a5b-9d59-1b9a7a3f0c11";
const BO: &str = "0f3c6d2e-1111-4222-8333-944455556666";
const ADA_D: &str = "11111111-aaaa-4aaa-8aaa-111111111111";
const BO_D: &str = "22222222-bbbb-4bbb-8bbb-222222222222";

fn pair() -> (Client, Client) {
    let s = issuer();
    let mut ada = client(&s, 1, ADA, ADA_D);
    let mut bo = client(&s, 2, BO, BO_D);
    ada.create_group(G).unwrap();
    let kp = bo.generate_key_package().unwrap();
    let added = ada.add_member(G, &kp).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.join_from_welcome(&added.welcome.unwrap()).unwrap();
    (ada, bo)
}

#[test]
fn every_short_envelope_is_one_size_whatever_its_kind() {
    let (mut ada, _bo) = pair();
    // A transcript frame, a receipt, a reaction: three MLS messages of three
    // kinds, each with the hint its kind carries.
    let mut transcript = vec![0xFF, 0x05];
    transcript.extend_from_slice(
        br#"{"i":"6f1c2d3e-4a5b-4c6d-8e7f-901a2b3c4d5e","t":"ok","a":[],"ak":"AAAAAAAAAAAAAAAAAAAAAA=="}"#,
    );
    let receipt =
        br#"{"peachy":"receipt","v":1,"k":"delivered","m":"6f1c2d3e-4a5b-4c6d-8e7f-901a2b3c4d5e"}"#;
    let reaction =
        br#"{"peachy":"react","v":1,"m":"6f1c2d3e-4a5b-4c6d-8e7f-901a2b3c4d5e","e":"x"}"#;
    let mut lengths = Vec::new();
    for (pt, hint) in [
        (&transcript[..], CONTENT_HINT_RESENDABLE),
        (&receipt[..], CONTENT_HINT_IMPLICIT),
        (&reaction[..], CONTENT_HINT_RESENDABLE_LANE),
    ] {
        let mls = ada.encrypt_with_hint(G, pt, hint).unwrap();
        lengths.push(
            seal_group_id_envelope(G, ENVELOPE_KIND_MESSAGE, &mls)
                .unwrap()
                .len(),
        );
    }
    // A seat ask as a client writes it: two uuids and a base64 proof.
    let proof = ada.sign_join_request(G).unwrap();
    assert_eq!(proof.len(), 89);
    let ask = format!(r#"{{"d":"{ADA_D}","a":"{ADA}","p":"{}"}}"#, "A".repeat(120));
    lengths.push(
        seal_group_id_envelope(G, ENVELOPE_KIND_SEAT_ASK, ask.as_bytes())
            .unwrap()
            .len(),
    );
    // A typing frame (156 bytes), a call frame, a link preview and a small
    // commit-sized blob.
    lengths.push(
        seal_group_id_envelope(G, ENVELOPE_KIND_TYPING, &[0u8; 156])
            .unwrap()
            .len(),
    );
    lengths.push(
        seal_group_id_envelope(G, ENVELOPE_KIND_CALL, &[7u8; 90])
            .unwrap()
            .len(),
    );
    lengths.push(
        seal_group_id_envelope(G, ENVELOPE_KIND_LINK_PREVIEW, &[1u8; 40])
            .unwrap()
            .len(),
    );
    lengths.push(
        seal_group_id_envelope(G, ENVELOPE_KIND_COMMIT, &[2u8; 300])
            .unwrap()
            .len(),
    );
    assert!(
        lengths.iter().all(|&l| l == lengths[0]),
        "every short envelope must be one length, whatever its kind: {lengths:?}"
    );
}

#[test]
fn a_longer_envelope_is_sized_by_its_length_alone() {
    for len in [
        0usize,
        1,
        500,
        1009,
        1010,
        1500,
        4000,
        40_000,
        131_072,
        1 << 20,
    ] {
        let inner = vec![9u8; len];
        let lengths: Vec<usize> = [
            ENVELOPE_KIND_MESSAGE,
            ENVELOPE_KIND_COMMIT,
            ENVELOPE_KIND_SEAT_ASK,
            ENVELOPE_KIND_CALL,
        ]
        .iter()
        .map(|&kind| seal_group_id_envelope(G, kind, &inner).unwrap().len())
        .collect();
        assert!(
            lengths.iter().all(|&l| l == lengths[0]),
            "{len}: {lengths:?}"
        );
        assert_eq!(lengths[0], padded_envelope_len(len), "{len}");
        // The padding opens back to exactly the inner bytes.
        let sealed = seal_group_id_envelope(G, ENVELOPE_KIND_SEAT_ASK, &inner).unwrap();
        let opened = open_envelope_for(G, &sealed).unwrap();
        assert_eq!(opened.kind, ENVELOPE_KIND_SEAT_ASK);
        assert_eq!(opened.inner, inner);
    }
}

#[test]
fn padding_costs_at_most_an_eighth_above_the_floor() {
    let mut last = 0;
    for len in (0..300_000).step_by(37) {
        let padded = padded_envelope_len(len);
        assert!(padded >= last, "monotone");
        last = padded;
        assert!(padded > len);
        if len > 1024 {
            assert!(
                (padded as f64) <= (len as f64) * 1.125 + 64.0,
                "{len} -> {padded}"
            );
        }
    }
}
