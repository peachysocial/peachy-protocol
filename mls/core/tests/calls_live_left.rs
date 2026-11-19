// SPDX-License-Identifier: MIT
//! A LIVE `Left` NEVER OPENS (docs/calls.md §The two lanes).
//!
//! Every `Left` goes signed, on the MLS lane: sealing a participant's own
//! ends its media keys, and every participant that bound it rotates past it.
//! A live frame is signed by the leaf it claims, but it binds nothing and
//! unbinds nothing, so a live `Left`, forged or signed by its own leaf, is
//! refused. A live `Joined` is a heartbeat, and opens only for the leaf its
//! frame claims, never naming this device or a participant bound at another
//! leaf.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use peachy_mls_core::call::{
    append_live_signature, encode_call_signal, live_signature_statement, seal_live_frame,
    CallSignal, CallSignalBody, LiveStamp, OpenedCallSignal, CALL_LIVE_EXPORTER_LABEL,
};
use peachy_mls_core::Client;
use support::{client, issuer, NOW};

const NOW_MS: u64 = NOW as u64 * 1000;
const GROUP: &[u8] = b"peachy-call-live-left";
const CALL_ID: [u8; 16] = *b"live-left-call-1";

/// Ada, Bo and Cy in one group.
fn three() -> (Client, Client, Client) {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(&server, 2, "actor-bo", "device-bo-phone");
    let mut cy = client(&server, 3, "actor-cy", "device-cy-phone");
    ada.create_group(GROUP).unwrap();
    let kp = bo.generate_key_package().unwrap();
    let added = ada.add_member(GROUP, &kp).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    bo.join_from_welcome(&added.welcome.clone().unwrap())
        .unwrap();
    let kp = cy.generate_key_package().unwrap();
    let added = ada.add_member(GROUP, &kp).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    bo.process_commit(GROUP, &added.commit).unwrap();
    cy.join_from_welcome(&added.welcome.clone().unwrap())
        .unwrap();
    (ada, bo, cy)
}

fn leaf(member: &Client) -> u32 {
    let device = member.identity().device_id.clone();
    member.leaf_of_device(GROUP, &device).unwrap()
}

fn left(participant: &str) -> CallSignal {
    CallSignal::new(
        CALL_ID,
        CallSignalBody::Left {
            participant_id: participant.into(),
        },
    )
}

/// A live `Left` written by hand under the epoch's live key, as any member
/// with its own code can, claiming `claimed_leaf`, unsigned.
fn forged_live_left(member: &Client, claimed_leaf: u32, participant: &str, at_ms: u64) -> Vec<u8> {
    let key = member
        .export_secret(GROUP, CALL_LIVE_EXPORTER_LABEL, &[], 32)
        .unwrap();
    seal_live_frame(
        &key,
        LiveStamp {
            sender_leaf: claimed_leaf,
            sent_at_ms: at_ms,
        },
        &encode_call_signal(&left(participant)).unwrap(),
    )
    .unwrap()
}

/// A live frame claiming the SIGNER'S OWN leaf, signed with its own leaf key
/// exactly as the sealing core signs one, carrying any signal it likes.
fn own_signed_live(member: &Client, tag: u8, at_ms: u64, signal: &CallSignal) -> Vec<u8> {
    use ed25519_dalek::Signer as _;
    let stamp = LiveStamp {
        sender_leaf: leaf(member),
        sent_at_ms: at_ms,
    };
    let epoch = member.epoch(GROUP).unwrap();
    let encoded = encode_call_signal(signal).unwrap();
    let (signing, _) = peachy_mls_core::issuer::device_key_pair(&support::device_seed(tag));
    let signature = signing
        .sign(&live_signature_statement(GROUP, epoch, stamp, &encoded))
        .to_bytes();
    let mut signed = encoded;
    append_live_signature(&mut signed, &signature);
    let key = member
        .export_secret(GROUP, CALL_LIVE_EXPORTER_LABEL, &[], 32)
        .unwrap();
    seal_live_frame(&key, stamp, &signed).unwrap()
}

fn start(member: &mut Client, participant: &str, session: &str) {
    member
        .call_media_start(
            GROUP,
            &CALL_ID,
            participant,
            session,
            &[format!("{session}-audio")],
        )
        .unwrap();
}

fn signed_joined(member: &mut Client, participant: &str) -> Vec<u8> {
    let own_leaf = leaf(member);
    member
        .seal_call_signal_on_mls_lane(
            GROUP,
            &CallSignal::new(
                CALL_ID,
                CallSignalBody::Joined {
                    participant_id: participant.into(),
                    session_id: String::new(),
                    track_names: Vec::new(),
                    leaf_index: own_leaf,
                    media_key: Vec::new(),
                    started_at_ms: 0,
                    media_key_pq: Vec::new(),
                    participation: None,
                },
            ),
        )
        .unwrap()
}

/// A heartbeat as it goes live: no call key.
fn live_joined(leaf_index: u32, participant: &str) -> CallSignal {
    CallSignal::new(
        CALL_ID,
        CallSignalBody::Joined {
            participant_id: participant.into(),
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

fn open_live(member: &mut Client, frame: &[u8]) -> peachy_mls_core::Result<OpenedCallSignal> {
    member.open_call_signal(GROUP, frame)
}

fn open_sealed(member: &mut Client, envelope: &[u8]) -> peachy_mls_core::Result<OpenedCallSignal> {
    let inner = member.open_envelope(envelope).unwrap().unwrap().inner;
    member.open_call_signal(GROUP, &inner)
}

/// Ada and Cy are in the call and Cy has bound Ada. A member's forged live
/// `Left` naming Ada carries no signature and is refused; Ada's own live
/// `Left`, signed by her own leaf, is refused too, since a `Left` comes
/// signed on the MLS lane. Cy still lists Ada.
#[test]
fn a_live_left_is_refused_whoever_signs_it() {
    let (mut ada, bo, mut cy) = three();
    let ada_leaf = leaf(&ada);
    start(&mut ada, "p-ada", "sess-ada");
    let ada_joined = signed_joined(&mut ada, "p-ada");
    start(&mut cy, "p-cy", "sess-cy");
    let _cy_joined = signed_joined(&mut cy, "p-cy");
    let bound = open_sealed(&mut cy, &ada_joined).unwrap();
    assert!(!bound.send.is_empty(), "Cy grants Ada her secret");

    let forged = forged_live_left(&bo, ada_leaf, "p-ada", NOW_MS + 1);
    let err = open_live(&mut cy, &forged).unwrap_err().to_string();
    assert!(err.contains("carries no signature"), "{err}");

    let own = own_signed_live(&ada, 1, NOW_MS + 2, &left("p-ada"));
    let err = open_live(&mut cy, &own).unwrap_err().to_string();
    assert!(
        err.contains("a Left comes signed, on the MLS lane"),
        "{err}"
    );

    let keys = cy.call_media_keys(GROUP, &CALL_ID, false).unwrap();
    assert!(keys
        .participants
        .iter()
        .any(|p| p.participant_id == "p-ada"));
}

/// Ada holds `p-ada`. Bo's signed `Joined` under that id is refused at Ada,
/// and so is Cy's signed `Left` naming it.
#[test]
fn a_device_keeps_its_own_participant_id() {
    let (mut ada, mut bo, mut cy) = three();
    start(&mut ada, "p-ada", "sess-ada");
    let _ = signed_joined(&mut ada, "p-ada");

    start(&mut bo, "p-ada", "sess-bo");
    let squat = signed_joined(&mut bo, "p-ada");
    let err = open_sealed(&mut ada, &squat).unwrap_err();
    assert!(
        err.to_string()
            .contains("another participant in this call holds"),
        "Ada bound another leaf under her own id: {err}"
    );

    let signed_left = cy
        .seal_call_signal_on_mls_lane(GROUP, &left("p-ada"))
        .unwrap();
    let err = open_sealed(&mut ada, &signed_left).unwrap_err();
    assert!(
        err.to_string().contains("this device's own participant"),
        "a signed Left naming Ada's own id opened at Ada: {err}"
    );
}

/// Ada and Cy are in the call, and Cy has bound Ada. Bo, a member not in the
/// call, writes a live `Joined` from his OWN leaf, signed with his own leaf
/// key, naming Ada's id and then Cy's own: both are refused. Ada's own
/// heartbeat, from her leaf, still opens.
#[test]
fn a_live_joined_naming_a_keyed_participant_or_this_device_opens_only_from_its_leaf() {
    let (mut ada, bo, mut cy) = three();
    start(&mut ada, "p-ada", "sess-ada");
    let ada_joined = signed_joined(&mut ada, "p-ada");
    start(&mut cy, "p-cy", "sess-cy");
    open_sealed(&mut cy, &ada_joined).unwrap();
    let keys = cy.call_media_keys(GROUP, &CALL_ID, false).unwrap();
    assert!(keys
        .participants
        .iter()
        .any(|p| p.participant_id == "p-ada"));

    let bo_leaf = leaf(&bo);
    let naming_ada = own_signed_live(&bo, 2, NOW_MS + 5, &live_joined(bo_leaf, "p-ada"));
    let err = open_live(&mut cy, &naming_ada).unwrap_err().to_string();
    assert!(err.contains("bound at another leaf"), "{err}");
    let naming_cy = own_signed_live(&bo, 2, NOW_MS + 6, &live_joined(bo_leaf, "p-cy"));
    let err = open_live(&mut cy, &naming_cy).unwrap_err().to_string();
    assert!(err.contains("this device"), "{err}");

    let ada_leaf = leaf(&ada);
    let own = own_signed_live(&ada, 1, NOW_MS + 7, &live_joined(ada_leaf, "p-ada"));
    open_live(&mut cy, &own).expect("Ada's own live Joined, from her leaf, opens");
}
