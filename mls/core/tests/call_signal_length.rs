// SPDX-License-Identifier: MIT
//! A call signal's length does not say it is a call
//! (docs/calls.md §The two lanes;
//! docs/delivery.md §The wrapped envelope).
//!
//! A call signal on the MLS lane is an MLS application message with one lane
//! byte ahead of it, and a message, reaction or receipt is an MLS application
//! message carrying a three-byte content hint in its authenticated data. Both
//! the lane byte and the authenticated data sit outside MLS's 256-byte
//! padding, and the version-1 envelope a group with an older leaf is sent
//! adds a flat 46 bytes, so any difference between them is on the wire
//! there. A call signal carries `CALL_LANE_AAD`, eighteen bytes, so lane
//! byte plus AAD is nineteen, the same as a hint and its author's
//! commitment.
//!
//! 1. The server cannot tell a hang-up from a message, or a raised hand from
//!    a receipt, by length: all are one length on the envelope a build sends
//!    (keyed by the epoch here).
//! 2. Exactly: a call signal is as long as a message whose plaintext is the
//!    signal's own bytes, for every MLS-lane body, short or long, on every
//!    envelope version.
//! 3. Read both: a receiver opens a call signal with the call AAD and one
//!    with none (what builds before it sent), and reads no content hint from
//!    either.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use peachy_mls_core::call::{
    encode_call_signal, CallMedia, CallSignal, CallSignalBody, HangupReason, CALL_LANE_AAD,
    CALL_LANE_MLS,
};
use peachy_mls_core::envelope::{
    seal_group_id_envelope, ENVELOPE_KIND_CALL, ENVELOPE_KIND_MESSAGE, ENVELOPE_VERSION_EPOCH,
    ENVELOPE_VERSION_PADDED,
};
use peachy_mls_core::hint::{
    hint_aad_with_commitment, hint_from_aad, peek_message, CONTENT_HINT_IMPLICIT,
    CONTENT_HINT_RESENDABLE, CONTENT_HINT_RESENDABLE_LANE, RESEND_COMMITMENT_BYTES,
};
use peachy_mls_core::Client;
use support::{client, issuer};

const G: &[u8] = b"0f8e2a1c-5b7d-4e9a-8c3f-2d1b6a9e7c40";
const ADA: &str = "5b0f5a52-8a55-4a5b-9d59-1b9a7a3f0c11";
const BO: &str = "0f3c6d2e-1111-4222-8333-944455556666";
const ADA_D: &str = "11111111-aaaa-4aaa-8aaa-111111111111";
const BO_D: &str = "22222222-bbbb-4bbb-8bbb-222222222222";
const CALL_ID: [u8; 16] = *b"0123456789abcdef";

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

/// A message's envelope as a client sends it today.
fn message_envelope(c: &mut Client, pt: &[u8], hint: u8) -> Vec<u8> {
    let mls = c.encrypt_with_hint(G, pt, hint).unwrap();
    c.seal_envelope(G, ENVELOPE_KIND_MESSAGE, &mls).unwrap()
}

/// What `envelope` carries, opened by a member's copy.
fn inner_of(by: &mut Client, envelope: &[u8]) -> Vec<u8> {
    by.open_envelope(envelope)
        .unwrap()
        .expect("a member opens it")
        .inner
}

fn hangup() -> CallSignal {
    CallSignal::new(
        CALL_ID,
        CallSignalBody::Hangup {
            reason: HangupReason::Declined,
        },
    )
}

#[test]
fn the_call_aad_is_no_content_hint() {
    assert_eq!(hint_from_aad(&CALL_LANE_AAD), None);
    // Lane byte plus call AAD is a hinted message's AAD: the hint's three
    // bytes and the author's commitment's sixteen.
    assert_eq!(
        1 + CALL_LANE_AAD.len(),
        hint_aad_with_commitment(CONTENT_HINT_IMPLICIT, None).len()
    );
    assert_eq!(1 + CALL_LANE_AAD.len(), 3 + RESEND_COMMITMENT_BYTES);
}

#[test]
fn a_call_signal_is_as_long_as_a_message_or_receipt_of_its_block() {
    let (mut ada, _bo) = pair();

    let receipt =
        br#"{"peachy":"receipt","v":1,"k":"delivered","m":"6f1c2d3e-4a5b-4c6d-8e7f-901a2b3c4d5e"}"#;
    let reaction =
        br#"{"peachy":"react","v":1,"m":"6f1c2d3e-4a5b-4c6d-8e7f-901a2b3c4d5e","e":"x"}"#;
    let mut transcript = vec![0xFF, 0x05];
    transcript.extend_from_slice(
        br#"{"i":"6f1c2d3e-4a5b-4c6d-8e7f-901a2b3c4d5e","t":"ok","a":[],"ak":"AAAAAAAAAAAAAAAAAAAAAA=="}"#,
    );
    let first = message_envelope(&mut ada, receipt, CONTENT_HINT_IMPLICIT);
    assert_eq!(
        first[0], ENVELOPE_VERSION_EPOCH,
        "both leaves read version 3"
    );
    let l_receipt = first.len();
    let l_reaction = message_envelope(&mut ada, reaction, CONTENT_HINT_RESENDABLE_LANE).len();
    let l_message = message_envelope(&mut ada, &transcript, CONTENT_HINT_RESENDABLE).len();

    // Urgent: a hang-up goes out as a message would.
    let l_hangup = ada.seal_call_signal(G, &hangup()).unwrap().len();
    // Not urgent: a raised hand goes out as a receipt would.
    let hand = CallSignal::new(CALL_ID, CallSignalBody::RaiseHand { up: true });
    let l_hand = ada.seal_call_signal(G, &hand).unwrap().len();
    // A signed one, through the other door.
    let l_signed = ada
        .seal_call_signal_on_mls_lane(G, &hangup())
        .unwrap()
        .len();

    assert_eq!(l_receipt, l_message);
    assert_eq!(l_reaction, l_message);
    assert_eq!(
        l_hangup, l_message,
        "a hang-up must not be told from a message"
    );
    assert_eq!(
        l_hand, l_receipt,
        "a call control must not be told from a receipt"
    );
    assert_eq!(l_signed, l_message);
}

#[test]
fn every_mls_lane_body_is_exactly_as_long_as_a_message_of_its_bytes() {
    let (mut ada, _bo) = pair();
    let bodies = [
        CallSignalBody::Offer {
            media: CallMedia::Video,
            ring: true,
            created_at_ms: 1_767_000_000_000,
        },
        CallSignalBody::Answer,
        CallSignalBody::Hangup {
            reason: HangupReason::Declined,
        },
        CallSignalBody::RaiseHand { up: true },
        CallSignalBody::React {
            emoji: "x".to_owned(),
        },
        CallSignalBody::RemoteMute {
            target: "p-2".to_owned(),
        },
        CallSignalBody::Remove {
            target: "p-2".to_owned(),
        },
        CallSignalBody::Media {
            audio_on: true,
            video_on: false,
            presenting: false,
        },
        // Long enough to span several padding blocks.
        CallSignalBody::Direct {
            to_leaf: 1,
            sdp: "v=0\r\n".repeat(200),
            offer: true,
        },
    ];
    for body in bodies {
        assert!(body.is_mls_lane());
        let signal = CallSignal::new(CALL_ID, body.clone());
        let plaintext = encode_call_signal(&signal).unwrap();
        let call = ada.seal_call_signal(G, &signal).unwrap();
        let message = message_envelope(&mut ada, &plaintext, CONTENT_HINT_IMPLICIT);
        assert_eq!(call.len(), message.len(), "{body:?} on the wire");

        // The inner bytes match too, so an envelope of another version cannot
        // split them either.
        let call_inner = inner_of(&mut ada, &call);
        let message_inner = inner_of(&mut ada, &message);
        assert_eq!(call_inner.len(), message_inner.len(), "{body:?} inner");
        assert_eq!(
            seal_group_id_envelope(G, ENVELOPE_KIND_CALL, &call_inner)
                .unwrap()
                .len(),
            seal_group_id_envelope(G, ENVELOPE_KIND_MESSAGE, &message_inner)
                .unwrap()
                .len(),
            "{body:?} as version 2"
        );
    }
}

#[test]
fn a_receiver_opens_a_call_signal_with_the_call_aad_or_without_it() {
    let (mut ada, mut bo) = pair();
    let signal = hangup();

    // As this build sends it: the call AAD.
    let with_aad = ada.seal_call_signal(G, &signal).unwrap();
    // As builds before it sent it: no AAD at all.
    let mut legacy_inner = vec![CALL_LANE_MLS];
    legacy_inner.extend_from_slice(
        &ada.encrypt_without_hint(G, &encode_call_signal(&signal).unwrap())
            .unwrap(),
    );
    let with_inner = inner_of(&mut bo, &with_aad);
    assert_eq!(with_inner.len(), legacy_inner.len() + CALL_LANE_AAD.len());
    // Keyed by the group id, as a device holding no epoch secret wraps it.
    let without_aad = seal_group_id_envelope(G, ENVELOPE_KIND_CALL, &legacy_inner).unwrap();
    assert_eq!(without_aad[0], ENVELOPE_VERSION_PADDED);

    for envelope in [with_aad, without_aad] {
        let opened = bo.open_envelope(&envelope).unwrap().expect("Bo opens it");
        assert_eq!(opened.kind, ENVELOPE_KIND_CALL);
        assert_eq!(opened.inner[0], CALL_LANE_MLS);
        // Neither form carries a content hint a receiver could act on.
        let peek = peek_message(&opened.inner[1..]).unwrap();
        assert_eq!(peek.hint, None);
        let got = bo.open_call_signal(G, &opened.inner).unwrap();
        assert_eq!(got.signal.body, signal.body);
    }
}
