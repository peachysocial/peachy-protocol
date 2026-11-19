// SPDX-License-Identifier: MIT
//! `mls/fixtures/calls.json`, replayed through the fixture door, and a call
//! carried end to end between real group members (docs/calls.md §Keys,
//! §Signaling, §Ringing).
//!
//! The fixture was written by an independent implementation
//! (a separate Python generator, not in this repository), so a pass here is two implementations
//! agreeing. The JavaScript, Swift and Kotlin replays make the same call
//! through the same door.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use std::collections::BTreeSet;

use peachy_mls_core::call::{
    call_frame_key, call_sender_key, CallLane, CallMedia, CallSignal, CallSignalBody, HangupReason,
    CALL_EXPORTER_LABEL,
};
use peachy_mls_core::envelope::ENVELOPE_KIND_CALL;
use peachy_mls_core::fixture::evaluate_case_json;
use peachy_mls_core::{Client, Incoming};
use serde_json::Value;
use support::{client, issuer};

const FIXTURE: &str = include_str!("../../fixtures/calls.json");

#[test]
fn every_call_case_gets_the_verdict_it_expects() {
    let root: Value = serde_json::from_str(FIXTURE).expect("calls.json is valid JSON");
    let cases = root["cases"].as_array().expect("`cases` is an array");
    assert!(cases.len() >= 100, "only {} cases", cases.len());
    let mut ids = BTreeSet::new();
    let mut calls = BTreeSet::new();
    let mut failures = Vec::new();
    for case in cases {
        let id = case["id"]
            .as_str()
            .expect("every case has an id")
            .to_string();
        assert!(ids.insert(id.clone()), "two cases share the id {id:?}");
        assert_eq!(case["kind"], "call", "case {id}");
        calls.insert(case["call"].as_str().unwrap().to_string());
        let has_expect = case.get("expect").is_some();
        let expect_error = case.get("expectError").and_then(Value::as_str);
        assert!(
            has_expect != expect_error.is_some(),
            "case {id}: exactly one of expect / expectError"
        );
        match (evaluate_case_json(&case.to_string()), expect_error) {
            (Ok(actual), None) => {
                let actual: Value = serde_json::from_str(&actual).unwrap();
                if actual != case["expect"] {
                    failures.push(format!(
                        "  {id}\n    expected {}\n    actual   {actual}",
                        case["expect"]
                    ));
                }
            }
            (Ok(actual), Some(want)) => {
                failures.push(format!(
                    "  {id}\n    expected an error with {want:?}\n    actual   {actual}"
                ));
            }
            (Err(err), Some(want)) => {
                if !err.to_string().contains(want) {
                    failures.push(format!(
                        "  {id}\n    expected an error with {want:?}\n    actual error {err}"
                    ));
                }
            }
            (Err(err), None) => failures.push(format!("  {id}\n    refused: {err}")),
        }
    }
    assert!(
        failures.is_empty(),
        "{} cases disagree:\n{}",
        failures.len(),
        failures.join("\n")
    );
    for call in [
        "constants",
        "senderKey",
        "encode",
        "decode",
        "sealLive",
        "openLive",
        "liveReplay",
        "envelope",
        "ring",
        "selfUpdateOffset",
        "senderKeyV2",
        "mediaAdvance",
        "mediaKeyPair",
        "openMediaGrant",
    ] {
        assert!(calls.contains(call), "no `{call}` case");
    }
}

const GROUP: &[u8] = b"peachy-call-group";
const CALL_ID: [u8; 16] = *b"0123456789abcdef";

fn two_members() -> (Client, Client) {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(&server, 2, "actor-bo", "device-bo-phone");
    ada.create_group(GROUP).expect("create");
    let bo_kp = bo.generate_key_package().expect("bo key package");
    let added = ada.add_member(GROUP, &bo_kp).expect("add bo");
    ada.merge_pending_commit(GROUP).expect("merge the add");
    bo.join_from_welcome(&added.welcome.clone().expect("welcome"))
        .expect("bo joins");
    (ada, bo)
}

fn open_call(receiver: &mut Client, envelope: &[u8]) -> peachy_mls_core::call::OpenedCallSignal {
    let opened = receiver
        .open_envelope(envelope)
        .expect("the envelope opens")
        .expect("it is for a group this device holds");
    assert_eq!(opened.group_id, GROUP);
    assert_eq!(opened.kind, ENVELOPE_KIND_CALL);
    receiver
        .open_call_signal(GROUP, &opened.inner)
        .expect("the call signal opens")
}

#[test]
fn members_derive_the_same_keys_and_a_call_round_trips() {
    let (mut ada, mut bo) = two_members();

    // The same key ring on both sides, from the exporter.
    let a = ada.call_keys(GROUP, &CALL_ID).expect("ada's keys");
    let b = bo.call_keys(GROUP, &CALL_ID).expect("bo's keys");
    assert_eq!(a, b);
    assert_eq!(a.senders.len(), 2);
    assert_eq!(a.key_index, (a.epoch % 256) as u8);
    let root = ada
        .export_secret(GROUP, CALL_EXPORTER_LABEL, &CALL_ID, 32)
        .expect("export");
    assert_eq!(a.call_root.as_slice(), root.as_slice());
    for sender in &a.senders {
        assert_eq!(
            *sender.key,
            call_sender_key(&root, sender.leaf_index).unwrap()
        );
    }
    assert_ne!(a.senders[0].key, a.senders[1].key, "one key per sender");
    assert_ne!(
        call_frame_key(&*a.senders[0].key).unwrap(),
        *a.senders[0].key,
        "the frame key is derived, not the sender key itself"
    );
    // Another call in the same epoch has other keys.
    let other = ada
        .call_keys(GROUP, b"fedcba9876543210")
        .expect("other call");
    assert_ne!(other.call_root, a.call_root);
    assert!(ada.call_keys(GROUP, b"short").is_err());

    // An Offer on the MLS lane, attributed to its sender.
    let offer = CallSignal::new(
        CALL_ID,
        CallSignalBody::Offer {
            media: CallMedia::Video,
            ring: true,
            created_at_ms: 1_789_516_800_000,
        },
    );
    let sealed = ada.seal_call_signal(GROUP, &offer).expect("seal the offer");
    let opened = open_call(&mut bo, &sealed);
    assert_eq!(opened.lane, CallLane::Mls);
    assert_eq!(opened.signal, offer);
    let sender = opened.sender.expect("the MLS lane names its sender");
    assert_eq!(sender.actor_id, "actor-ada");
    assert_eq!(sender.device_id, "device-ada-phone");

    // A Hangup back.
    let hangup = CallSignal::new(
        CALL_ID,
        CallSignalBody::Hangup {
            reason: HangupReason::Declined,
        },
    );
    let sealed = bo
        .seal_call_signal(GROUP, &hangup)
        .expect("seal the hangup");
    let opened = open_call(&mut ada, &sealed);
    assert_eq!(opened.signal, hangup);
    assert_eq!(opened.sender.unwrap().actor_id, "actor-bo");

    // An in-call control names its sender: the default door signs it.
    let media = CallSignal::new(
        CALL_ID,
        CallSignalBody::Media {
            audio_on: true,
            video_on: false,
            presenting: false,
        },
    );
    let sealed = ada
        .seal_call_signal(GROUP, &media)
        .expect("seal the media state");
    let opened = open_call(&mut bo, &sealed);
    assert_eq!(opened.lane, CallLane::Mls);
    assert_eq!(opened.sender.unwrap().actor_id, "actor-ada");
    assert_eq!(opened.signal, media);

    // A device's own Left goes signed, whatever this core remembers of the
    // call, so every participant that bound it rotates past it. (A Left
    // sealed live is refused.)
    let left = CallSignal::new(
        CALL_ID,
        CallSignalBody::Left {
            participant_id: "p-ada".into(),
        },
    );
    let sealed = ada.seal_call_signal(GROUP, &left).expect("seal the left");
    let opened = open_call(&mut bo, &sealed);
    assert_eq!(opened.lane, CallLane::Mls);
    assert_eq!(opened.sender.unwrap().actor_id, "actor-ada");
    assert_eq!(opened.signal, left);

    // A commit is never a call: a handshake wrapped in a call envelope is
    // refused before it can move the group.
    let epoch = bo.epoch(GROUP).unwrap();
    let update = ada.self_update(GROUP).expect("ada updates");
    let mut wrapped = vec![1u8];
    wrapped.extend_from_slice(&update.commit);
    assert!(bo.open_call_signal(GROUP, &wrapped).is_err());
    assert_eq!(bo.epoch(GROUP).unwrap(), epoch);
}

/// Threat model D10: a participant's first `Joined` goes signed, and binds its
/// tracks to its OWN leaf. A signed `Joined` naming someone else's leaf is
/// refused; a live `Joined` names no sender and the client binds nothing from
/// it.
#[test]
fn a_signed_joined_must_name_its_senders_own_leaf() {
    let (mut ada, mut bo) = two_members();
    let ada_leaf = ada.leaf_of_device(GROUP, "device-ada-phone").unwrap();
    let bo_leaf = bo.leaf_of_device(GROUP, "device-bo-phone").unwrap();
    let joined = |leaf_index| {
        CallSignal::new(
            CALL_ID,
            CallSignalBody::Joined {
                participant_id: "p-ada".into(),
                session_id: "cf-1".into(),
                track_names: vec!["audio-0".into()],
                leaf_index,
                media_key: Vec::new(),
                started_at_ms: 0,
                media_key_pq: Vec::new(),
                participation: None,
            },
        )
    };

    // A Joined goes out only from a participant.
    ada.call_media_start(GROUP, &CALL_ID, "p-ada", "cf-1", &["audio-0".into()])
        .unwrap();
    let honest = ada
        .seal_call_signal_on_mls_lane(GROUP, &joined(ada_leaf))
        .unwrap();
    let opened = open_call(&mut bo, &honest);
    assert_eq!(opened.lane, CallLane::Mls);
    assert_eq!(opened.sender_leaf, Some(ada_leaf));
    // The core writes the call keys and the participation mark itself, and
    // leaves the session and tracks to the grants.
    match &opened.signal.body {
        CallSignalBody::Joined {
            participant_id,
            session_id,
            track_names,
            leaf_index,
            media_key,
            media_key_pq,
            participation,
            ..
        } => {
            assert_eq!(participant_id, "p-ada");
            assert_eq!(*leaf_index, ada_leaf);
            assert!(session_id.is_empty() && track_names.is_empty());
            assert!(!media_key.is_empty() && !media_key_pq.is_empty());
            assert_eq!(participation.map(|p| p.seq), Some(1));
        }
        other => panic!("not a Joined: {other:?}"),
    }
    assert!(opened
        .to_json()
        .unwrap()
        .contains(&format!("\"senderLeaf\":{ada_leaf}")));

    let forged = ada
        .seal_call_signal_on_mls_lane(GROUP, &joined(bo_leaf))
        .unwrap();
    let inner = bo.open_envelope(&forged).unwrap().unwrap().inner;
    let err = bo.open_call_signal(GROUP, &inner).unwrap_err();
    assert!(err.to_string().contains("names leaf"), "{err}");

    // The heartbeat rides the live lane, naming no sender.
    let live = open_call(
        &mut bo,
        &ada.seal_call_signal(GROUP, &joined(ada_leaf)).unwrap(),
    );
    assert_eq!(live.lane, CallLane::Live);
    assert_eq!(live.sender_leaf, None);
}

#[test]
fn every_epoch_change_rekeys_and_a_removed_member_falls_out() {
    let server = issuer();
    let (mut ada, mut bo) = two_members();
    let mut cy = client(&server, 3, "actor-cy", "device-cy-phone");
    let cy_kp = cy.generate_key_package().unwrap();

    let before = ada.call_keys(GROUP, &CALL_ID).unwrap();

    // The committer can load e+1 before merging, and it is what everyone
    // lands on.
    let added = ada.add_member(GROUP, &cy_kp).expect("add cy");
    let pending = ada
        .pending_call_keys(GROUP, &CALL_ID)
        .expect("pending keys");
    assert_eq!(pending.epoch, before.epoch + 1);
    ada.merge_pending_commit(GROUP).unwrap();
    match bo.process_commit(GROUP, &added.commit).unwrap() {
        Incoming::Commit(_) => {}
        other => panic!("expected a commit, got {other:?}"),
    }
    cy.join_from_welcome(&added.welcome.clone().unwrap())
        .unwrap();

    let after = ada.call_keys(GROUP, &CALL_ID).unwrap();
    assert_eq!(after.epoch, before.epoch + 1);
    assert_eq!(after.call_root, pending.call_root);
    assert_ne!(
        after.call_root, before.call_root,
        "a new epoch is a new key"
    );
    assert_eq!(after.key_index, before.key_index.wrapping_add(1));
    assert_eq!(after.senders.len(), 3);
    assert_eq!(bo.call_keys(GROUP, &CALL_ID).unwrap(), after);
    assert_eq!(cy.call_keys(GROUP, &CALL_ID).unwrap(), after);

    // Cy is removed. Cy's last ring is the one it had; the group's next is
    // one Cy cannot derive, and Cy cannot open a live frame under it.
    let cy_leaf = ada.leaf_of_device(GROUP, "device-cy-phone").unwrap();
    let removal = ada.remove_leaf(GROUP, cy_leaf).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    bo.process_commit(GROUP, &removal.commit).unwrap();
    let without_cy = ada.call_keys(GROUP, &CALL_ID).unwrap();
    assert_eq!(bo.call_keys(GROUP, &CALL_ID).unwrap(), without_cy);
    assert_ne!(
        cy.call_keys(GROUP, &CALL_ID).unwrap().call_root,
        without_cy.call_root
    );

    let joined = CallSignal::new(
        CALL_ID,
        CallSignalBody::Media {
            audio_on: true,
            video_on: true,
            presenting: false,
        },
    );
    let sealed = ada.seal_call_signal(GROUP, &joined).unwrap();
    // The envelope is keyed by the epoch Cy is not in: it does not open.
    assert!(cy.open_envelope(&sealed).unwrap().is_none());
    // Nor does the frame inside it, handed over by a member.
    let inner = bo
        .open_envelope(&sealed)
        .unwrap()
        .expect("a member opens it")
        .inner;
    assert!(
        cy.open_call_signal(GROUP, &inner).is_err(),
        "a removed member opens no live frame from the next epoch"
    );
    assert_eq!(open_call(&mut bo, &sealed).signal, joined);
}
