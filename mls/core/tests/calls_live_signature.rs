// SPDX-License-Identifier: MIT
//! A LIVE FRAME IS SIGNED BY THE LEAF IT CLAIMS (docs/calls.md
//! §The live lane's signature).
//!
//! Every member holds the live key, so a frame sealed under it alone says
//! nothing about who wrote it: a member could write a live `Joined` or `Left`
//! claiming another's leaf. This build signs every live frame it seals with
//! its leaf's signature key, over the group, the epoch, the stamp and the
//! signal. A receiver verifies a signed frame under the key of the leaf it
//! claims, and refuses an unsigned one.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use peachy_mls_core::call::{
    decode_call_signal, encode_call_signal, live_signature_holds, live_signature_statement,
    open_live_frame, seal_live_frame, split_live_signature, CallSignal, CallSignalBody, LiveStamp,
    CALL_LIVE_EXPORTER_LABEL,
};
use peachy_mls_core::Client;
use support::{client, issuer, NOW};

const NOW_MS: u64 = NOW as u64 * 1000;
const GROUP: &[u8] = b"peachy-call-live-signature";
const CALL_ID: [u8; 16] = *b"live-signed-call";

/// Ada, Bo and Cy in one group; Ada is in the call, bound at Bo by her
/// signed `Joined`, so her live heartbeat opens there.
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

    ada.call_media_start(GROUP, &CALL_ID, "p-ada", "sess", &["sess-audio".into()])
        .unwrap();
    let ada_leaf = leaf(&ada);
    let first = ada
        .seal_call_signal_on_mls_lane(GROUP, &joined(ada_leaf, "p-ada"))
        .unwrap();
    let inner = bo.open_envelope(&first).unwrap().unwrap().inner;
    bo.open_call_signal(GROUP, &inner).unwrap();
    (ada, bo, cy)
}

fn leaf(member: &Client) -> u32 {
    let device = member.identity().device_id.clone();
    member.leaf_of_device(GROUP, &device).unwrap()
}

fn joined(leaf_index: u32, participant: &str) -> CallSignal {
    CallSignal::new(
        CALL_ID,
        CallSignalBody::Joined {
            participant_id: participant.into(),
            session_id: "sess".into(),
            track_names: vec!["sess-audio".into()],
            leaf_index,
            media_key: Vec::new(),
            started_at_ms: 0,
            media_key_pq: Vec::new(),
            participation: None,
        },
    )
}

fn live_key(member: &Client) -> Vec<u8> {
    member
        .export_secret(GROUP, CALL_LIVE_EXPORTER_LABEL, &[], 32)
        .unwrap()
}

/// An unsigned live frame written by hand under the live key, as a member
/// forges one, claiming `claimed_leaf`.
fn unsigned_live(member: &Client, claimed_leaf: u32, at_ms: u64, signal: &CallSignal) -> Vec<u8> {
    seal_live_frame(
        &live_key(member),
        LiveStamp {
            sender_leaf: claimed_leaf,
            sent_at_ms: at_ms,
        },
        &encode_call_signal(signal).unwrap(),
    )
    .unwrap()
}

/// Ada's own live `Joined` (a heartbeat), as her core seals it: the
/// envelope's inner bytes.
fn ada_heartbeat(ada: &mut Client) -> Vec<u8> {
    let ada_leaf = leaf(ada);
    let envelope = ada
        .seal_call_signal(GROUP, &joined(ada_leaf, "p-ada"))
        .unwrap();
    ada.open_envelope(&envelope).unwrap().unwrap().inner
}

fn left(participant: &str) -> CallSignal {
    CallSignal::new(
        CALL_ID,
        CallSignalBody::Left {
            participant_id: participant.into(),
        },
    )
}

#[test]
fn a_device_signs_its_live_frames_and_they_open() {
    let (mut ada, mut bo, _cy) = three();
    let frame = ada_heartbeat(&mut ada);
    let (_, plaintext) = open_live_frame(&live_key(&bo), &frame).unwrap();
    let (unsigned, signature) = split_live_signature(&plaintext).unwrap();
    assert!(
        signature.is_some(),
        "the core sealed an unsigned live frame"
    );
    // A decoder that does not check signatures skips it as an unknown field
    // and reads the same signal.
    assert_eq!(
        decode_call_signal(&plaintext).unwrap(),
        decode_call_signal(unsigned).unwrap()
    );
    let opened = bo.open_call_signal(GROUP, &frame).unwrap();
    // The core writes the participation's start and mark itself.
    match opened.signal.body {
        CallSignalBody::Joined {
            participant_id,
            leaf_index,
            participation,
            ..
        } => {
            assert_eq!(participant_id, "p-ada");
            assert_eq!(leaf_index, leaf(&ada));
            assert!(participation.is_some());
        }
        other => panic!("not a Joined: {other:?}"),
    }
}

/// An unsigned live frame is refused, whatever leaf it claims.
#[test]
fn an_unsigned_frame_is_refused() {
    let (mut ada, mut bo, cy) = three();
    let ada_leaf = leaf(&ada);
    let cy_leaf = leaf(&cy);

    let unsigned_joined = unsigned_live(&cy, ada_leaf, NOW_MS + 1, &joined(ada_leaf, "p-ada"));
    let err = bo.open_call_signal(GROUP, &unsigned_joined).unwrap_err();
    assert!(err.to_string().contains("carries no signature"), "{err}");
    let unsigned_left = unsigned_live(&cy, ada_leaf, NOW_MS + 2, &left("p-ada"));
    let err = bo.open_call_signal(GROUP, &unsigned_left).unwrap_err();
    assert!(err.to_string().contains("carries no signature"), "{err}");
    let own = unsigned_live(&cy, cy_leaf, NOW_MS + 3, &joined(cy_leaf, "p-cy"));
    let err = bo.open_call_signal(GROUP, &own).unwrap_err();
    assert!(err.to_string().contains("carries no signature"), "{err}");

    let signed = ada_heartbeat(&mut ada);
    bo.open_call_signal(GROUP, &signed).unwrap();
}

/// A signed frame re-sealed with another stamp, another claimed leaf or
/// another signal does not verify.
#[test]
fn a_signed_frame_moved_to_another_stamp_leaf_or_signal_is_refused() {
    let (mut ada, mut bo, cy) = three();
    let ada_leaf = leaf(&ada);
    let cy_leaf = leaf(&cy);
    let key = live_key(&bo);
    let frame = ada_heartbeat(&mut ada);
    let (stamp, plaintext) = open_live_frame(&key, &frame).unwrap();

    let restamped = seal_live_frame(
        &key,
        LiveStamp {
            sender_leaf: ada_leaf,
            sent_at_ms: stamp.sent_at_ms + 7,
        },
        &plaintext,
    )
    .unwrap();
    let err = bo.open_call_signal(GROUP, &restamped).unwrap_err();
    assert!(err.to_string().contains("does not hold"), "{err}");

    // Claiming Cy's leaf, with a Joined naming it, under Ada's signature.
    let (_, signature) = split_live_signature(&plaintext).unwrap();
    let mut moved = encode_call_signal(&joined(cy_leaf, "p-cy")).unwrap();
    peachy_mls_core::call::append_live_signature(&mut moved, &signature.unwrap());
    let other_leaf = seal_live_frame(
        &key,
        LiveStamp {
            sender_leaf: cy_leaf,
            sent_at_ms: stamp.sent_at_ms + 8,
        },
        &moved,
    )
    .unwrap();
    let err = bo.open_call_signal(GROUP, &other_leaf).unwrap_err();
    assert!(err.to_string().contains("does not hold"), "{err}");

    // Ada's leaf and stamp, another signal.
    let mut swapped = encode_call_signal(&left("p-ada")).unwrap();
    peachy_mls_core::call::append_live_signature(&mut swapped, &signature.unwrap());
    let other_signal = seal_live_frame(&key, stamp, &swapped).unwrap();
    let err = bo.open_call_signal(GROUP, &other_signal).unwrap_err();
    assert!(err.to_string().contains("does not hold"), "{err}");

    // The genuine frame still opens: none of the refusals took its stamp.
    bo.open_call_signal(GROUP, &frame).unwrap();
}

/// `unsigned` sealed as a live frame claiming `sender_leaf`, signed by
/// hand with the key of the client built with `tag`: a frame that member's
/// device could seal, whatever its core would.
fn signed_live(
    receiver: &Client,
    tag: u8,
    sender_leaf: u32,
    at_ms: u64,
    unsigned: &[u8],
) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let stamp = LiveStamp {
        sender_leaf,
        sent_at_ms: at_ms,
    };
    let epoch = receiver.epoch(GROUP).unwrap();
    let (signing, public) = peachy_mls_core::issuer::device_key_pair(&support::device_seed(tag));
    let signature = signing
        .sign(&live_signature_statement(GROUP, epoch, stamp, unsigned))
        .to_bytes();
    assert!(live_signature_holds(
        &public, GROUP, epoch, stamp, unsigned, &signature
    ));
    let mut signed = unsigned.to_vec();
    peachy_mls_core::call::append_live_signature(&mut signed, &signature);
    seal_live_frame(&live_key(receiver), stamp, &signed).unwrap()
}

/// A body this build does not know is refused on the live lane, even
/// signed by the leaf its frame claims: only the MLS lane opens one, as
/// `Unknown`, so no newer type can ride the lane a frame's sender cannot
/// be held to.
#[test]
fn a_signed_live_frame_of_a_type_this_build_does_not_know_is_refused() {
    let (ada, mut bo, _cy) = three();
    let ada_leaf = leaf(&ada);
    // Version 2, the call id, and field 40: a body this build does not know.
    let mut unknown = vec![0x08, 0x02, 0x12, 16];
    unknown.extend_from_slice(&CALL_ID);
    unknown.extend_from_slice(&[0xC2, 0x02, 0x02, 0x08, 0x01]);
    assert_eq!(
        decode_call_signal(&unknown).unwrap().body,
        CallSignalBody::Unknown
    );
    let frame = signed_live(&bo, 1, ada_leaf, NOW_MS + 1, &unknown);
    let err = bo.open_call_signal(GROUP, &frame).unwrap_err();
    assert!(
        err.to_string().contains("must come on the MLS lane"),
        "{err}"
    );

    // The same hand, a type the live lane carries: it opens, so the refusal
    // above is the type's.
    let heartbeat = encode_call_signal(&joined(ada_leaf, "p-ada")).unwrap();
    let frame = signed_live(&bo, 1, ada_leaf, NOW_MS + 2, &heartbeat);
    bo.open_call_signal(GROUP, &frame).unwrap();
}

/// A live `Joined` is judged against the bindings the tree still holds: a
/// participant bound at a leaf a commit has since removed is bound nowhere,
/// though no door has read the tree since the commit. So another member's
/// heartbeat may then name that id: no guarantee that a heartbeat speaks
/// only for its own participant, and the tile it keeps holds no key.
#[test]
fn a_live_joined_is_judged_after_the_bindings_a_commit_ended_are_dropped() {
    let (mut ada, mut bo, mut cy) = three();
    let ada_leaf = leaf(&ada);
    let cy_leaf = leaf(&cy);
    cy.call_media_start(
        GROUP,
        &CALL_ID,
        "p-cy",
        "sess-cy",
        &["sess-cy-audio".into()],
    )
    .unwrap();
    let envelope = cy
        .seal_call_signal_on_mls_lane(GROUP, &joined(cy_leaf, "p-cy"))
        .unwrap();
    let inner = bo.open_envelope(&envelope).unwrap().unwrap().inner;
    bo.open_call_signal(GROUP, &inner).unwrap();

    // While Cy's leaf holds Cy, a heartbeat from another leaf naming p-cy
    // speaks for Cy's tile, and is refused.
    let naming_cy = encode_call_signal(&joined(ada_leaf, "p-cy")).unwrap();
    let frame = signed_live(&bo, 1, ada_leaf, NOW_MS + 1, &naming_cy);
    let err = bo.open_call_signal(GROUP, &frame).unwrap_err();
    assert!(err.to_string().contains("names p-cy"), "{err}");

    // Ada removes Cy. Bo merges the commit and opens nothing else.
    let cy_key = bo
        .roster(GROUP)
        .unwrap()
        .into_iter()
        .find(|entry| entry.leaf_index == cy_leaf)
        .unwrap()
        .leaf_key;
    let removal = ada.remove_member(GROUP, cy_leaf, &cy_key).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    bo.process_commit(GROUP, &removal.commit).unwrap();

    let frame = signed_live(&bo, 1, ada_leaf, NOW_MS + 2, &naming_cy);
    bo.open_call_signal(GROUP, &frame).unwrap();
}
