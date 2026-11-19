// SPDX-License-Identifier: MIT
//! THE LIVE LANE JUDGES BY THE SERVER-CORRECTED CLOCK (docs/calls.md
//! §The live lane's replay window).
//!
//! A device whose clock is more than 120 s off had every live frame it sent
//! dropped, and dropped every live frame it got. The client hands the core
//! the offset between the server's clock and its own
//! ([`peachy_mls_core::set_server_clock_offset_ms`], learned from the server
//! time a mailbox fetch answers with), and the core stamps and checks live
//! frames on its clock plus that offset.
//!
//! The offset is process-wide, so this file is its own test binary and runs
//! its steps in one test.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use peachy_mls_core::call::{
    append_live_signature, encode_call_signal, live_signature_statement, open_live_frame,
    seal_live_frame, CallSignal, CallSignalBody, LiveStamp, CALL_LIVE_EXPORTER_LABEL,
};
use peachy_mls_core::{
    server_clock_offset_ms, set_server_clock_offset_ms, Client, SERVER_CLOCK_OFFSET_MAX_MS,
};
use support::{client, issuer, step_wall_ms, NOW};

const NOW_MS: u64 = NOW as u64 * 1000;
const GROUP: &[u8] = b"peachy-call-clock-offset";
const CALL_ID: [u8; 16] = *b"clock-offset-cal";
const FIVE_MINUTES_MS: i64 = 5 * 60 * 1000;

fn leaf(member: &Client) -> u32 {
    let device = member.identity().device_id.clone();
    member.leaf_of_device(GROUP, &device).unwrap()
}

fn joined(leaf_index: u32) -> CallSignal {
    CallSignal::new(
        CALL_ID,
        CallSignalBody::Joined {
            participant_id: "p-ada".into(),
            session_id: String::new(),
            track_names: Vec::new(),
            leaf_index,
            media_key: Vec::new(),
            started_at_ms: 0,
            media_key_pq: Vec::new(),
            participation: None,
        },
    )
}

#[test]
fn live_frames_are_stamped_and_judged_on_the_server_corrected_clock() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(&server, 2, "actor-bo", "device-bo-phone");
    ada.create_group(GROUP).unwrap();
    let kp = bo.generate_key_package().unwrap();
    let added = ada.add_member(GROUP, &kp).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    bo.join_from_welcome(&added.welcome.clone().unwrap())
        .unwrap();
    ada.call_media_start(GROUP, &CALL_ID, "p-ada", "sess", &["sess-audio".into()])
        .unwrap();
    let ada_leaf = leaf(&ada);
    let first = ada
        .seal_call_signal_on_mls_lane(GROUP, &joined(ada_leaf))
        .unwrap();
    let inner = bo.open_envelope(&first).unwrap().unwrap().inner;
    bo.open_call_signal(GROUP, &inner).unwrap();
    let key = bo
        .export_secret(GROUP, CALL_LIVE_EXPORTER_LABEL, &[], 32)
        .unwrap();

    // The device clocks run five minutes slow. A frame stamped on true time
    // (a peer whose clock is right) is outside the window. Signed by Ada's
    // leaf key, as the sealing core signs a live frame.
    step_wall_ms(-FIVE_MINUTES_MS);
    let epoch = ada.epoch(GROUP).unwrap();
    let on_time = |at_ms: u64| {
        use ed25519_dalek::Signer as _;
        let stamp = LiveStamp {
            sender_leaf: ada_leaf,
            sent_at_ms: at_ms,
        };
        let mut signal = encode_call_signal(&joined(ada_leaf)).unwrap();
        let (signing, _) = peachy_mls_core::issuer::device_key_pair(&support::device_seed(1));
        let signature = signing
            .sign(&live_signature_statement(GROUP, epoch, stamp, &signal))
            .to_bytes();
        append_live_signature(&mut signal, &signature);
        seal_live_frame(&key, stamp, &signal).unwrap()
    };
    let err = bo.open_call_signal(GROUP, &on_time(NOW_MS)).unwrap_err();
    assert!(err.to_string().contains("as a replay"), "{err}");

    // Told the server's clock is five minutes ahead of its own, the device
    // takes it, and seals on true time.
    set_server_clock_offset_ms(FIVE_MINUTES_MS);
    bo.open_call_signal(GROUP, &on_time(NOW_MS + 1))
        .expect("a frame on true time opens on the corrected clock");
    let envelope = ada.seal_call_signal(GROUP, &joined(ada_leaf)).unwrap();
    let inner = ada.open_envelope(&envelope).unwrap().unwrap().inner;
    let (stamp, _) = open_live_frame(&key, &inner).unwrap();
    assert!(
        stamp.sent_at_ms.abs_diff(NOW_MS) < 1_000,
        "stamped {} on a clock five minutes slow",
        stamp.sent_at_ms
    );

    // The offset is bounded: a server can move the agreed clock a day at most.
    set_server_clock_offset_ms(2 * SERVER_CLOCK_OFFSET_MAX_MS);
    assert_eq!(server_clock_offset_ms(), SERVER_CLOCK_OFFSET_MAX_MS);
    set_server_clock_offset_ms(-2 * SERVER_CLOCK_OFFSET_MAX_MS);
    assert_eq!(server_clock_offset_ms(), -SERVER_CLOCK_OFFSET_MAX_MS);
    set_server_clock_offset_ms(0);
}
