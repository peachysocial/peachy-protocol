// SPDX-License-Identifier: MIT
//! WHAT A MEMBER CAN DO IN A CALL: the call doors against a member of the
//! group who holds every key the epoch gives and writes frames by hand
//! (docs/calls.md §The two lanes, §The live lane's replay window,
//! §In-call controls, §Ringing).
//!
//! Every member holds the live key, and a live frame is signed by the leaf it
//! claims (calls_live_signature.rs). What the core refuses besides:
//!
//! 1. A live `Joined` that names a leaf other than the one its own frame
//!    claims. A member's own core always claims its own leaf, so a
//!    heartbeat for someone else's tile needs a frame written by hand.
//! 2. An in-call control on the live lane. `seal_call_signal` signs every
//!    control, and the core refuses one that arrives live.
//! 3. A live frame claiming a leaf the tree does not hold.
//! 4. A frame claiming another's leaf: it does not carry that leaf's
//!    signature. On the window itself, a stamp ahead of a leaf's clock takes
//!    only that one stamp, never the leaf's later frames, and the window
//!    holds a bounded number of senders and stamps, whatever call ids and
//!    leaves members put in their frames.
//! 5. An offer whose caller's stamp is far ahead of, or far behind, this
//!    device's clock, whatever age the server's clock gives it.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use peachy_mls_core::call::{
    append_live_signature, encode_call_signal, live_signature_statement, ring_step,
    seal_live_frame, CallLane, CallMedia, CallSignal, CallSignalBody, LiveReplayVerdict,
    LiveReplayWindow, LiveStamp, RingEffect, RingEvent, RingGate, RingOutcome, RingState,
    CALL_LIVE_EXPORTER_LABEL, CALL_LIVE_MAX_SENDERS, CALL_LIVE_MAX_SKEW_MS, CALL_OFFER_MAX_AGE_MS,
    CALL_OFFER_MAX_SKEW_MS,
};
use peachy_mls_core::Client;
use support::{client, issuer, NOW};

const NOW_MS: u64 = NOW as u64 * 1000;
const GROUP: &[u8] = b"peachy-call-member-group";
const CALL_ID: [u8; 16] = *b"0123456789abcdef";

fn three_members() -> (Client, Client, Client) {
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

/// A live frame written by hand under the epoch's live key, as a member with
/// a modified client could write one.
fn forge_live(member: &Client, leaf: u32, at_ms: u64, body: CallSignalBody) -> Vec<u8> {
    let key = member
        .export_secret(GROUP, CALL_LIVE_EXPORTER_LABEL, &[], 32)
        .unwrap();
    seal_live_frame(
        &key,
        LiveStamp {
            sender_leaf: leaf,
            sent_at_ms: at_ms,
        },
        &encode_call_signal(&CallSignal::new(CALL_ID, body)).unwrap(),
    )
    .unwrap()
}

/// A live frame written by hand from the member's OWN leaf, signed with its
/// own leaf key exactly as the sealing core signs one, carrying any body.
fn signed_live(member: &Client, tag: u8, at_ms: u64, body: CallSignalBody) -> Vec<u8> {
    use ed25519_dalek::Signer as _;
    let device = member.identity().device_id.clone();
    let stamp = LiveStamp {
        sender_leaf: member.leaf_of_device(GROUP, &device).unwrap(),
        sent_at_ms: at_ms,
    };
    let epoch = member.epoch(GROUP).unwrap();
    let mut signal = encode_call_signal(&CallSignal::new(CALL_ID, body)).unwrap();
    let (signing, _) = peachy_mls_core::issuer::device_key_pair(&support::device_seed(tag));
    let signature = signing
        .sign(&live_signature_statement(GROUP, epoch, stamp, &signal))
        .to_bytes();
    append_live_signature(&mut signal, &signature);
    let key = member
        .export_secret(GROUP, CALL_LIVE_EXPORTER_LABEL, &[], 32)
        .unwrap();
    seal_live_frame(&key, stamp, &signal).unwrap()
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

fn joined(participant: &str, session: &str, leaf: u32) -> CallSignalBody {
    CallSignalBody::Joined {
        participant_id: participant.into(),
        session_id: session.into(),
        track_names: vec![format!("{session}-audio")],
        leaf_index: leaf,
        media_key: Vec::new(),
        started_at_ms: 0,
        media_key_pq: Vec::new(),
        participation: None,
    }
}

/// Seal through the member's own core and open as `opener` would. A
/// `Joined` goes out only from a participant (`start`).
fn sealed(sender: &mut Client, opener: &Client, signal: &CallSignal) -> Vec<u8> {
    let envelope = sender.seal_call_signal(GROUP, signal).unwrap();
    opener.open_envelope(&envelope).unwrap().unwrap().inner
}

#[test]
fn a_live_joined_must_name_the_leaf_its_frame_claims() {
    let (ada, mut bo, mut cy) = three_members();
    let ada_leaf = ada.leaf_of_device(GROUP, "device-ada-phone").unwrap();
    let bo_leaf = bo.leaf_of_device(GROUP, "device-bo-phone").unwrap();

    // The instrument: Bo's own heartbeat, naming his own leaf, opens.
    start(&mut bo, "p-bo", "bo-session");
    let own = sealed(
        &mut bo,
        &cy,
        &CallSignal::new(CALL_ID, joined("p-bo", "bo-session", bo_leaf)),
    );
    let opened = cy.open_call_signal(GROUP, &own).unwrap();
    assert_eq!(opened.lane, CallLane::Live);

    // Bo writes a heartbeat naming Ada's leaf, signed by his own: its frame
    // claims Bo's leaf, so the Joined is refused.
    let forged = signed_live(
        &bo,
        2,
        NOW_MS + 3,
        joined("p-ada", "bo-attacker-session", ada_leaf),
    );
    let err = cy.open_call_signal(GROUP, &forged).unwrap_err();
    assert!(err.to_string().contains("names leaf"), "{err}");
}

#[test]
fn in_call_controls_are_sealed_signed_and_refused_on_the_live_lane() {
    let (ada, mut bo, mut cy) = three_members();
    let bo_leaf = bo.leaf_of_device(GROUP, "device-bo-phone").unwrap();
    let controls = [
        CallSignalBody::RemoteMute {
            target: "p-cy".into(),
        },
        CallSignalBody::Media {
            audio_on: false,
            video_on: false,
            presenting: true,
        },
        CallSignalBody::RaiseHand { up: true },
        CallSignalBody::React { emoji: "x".into() },
    ];
    for (i, body) in controls.iter().enumerate() {
        // The default door signs it: it opens on the MLS lane, naming Bo.
        let inner = sealed(&mut bo, &cy, &CallSignal::new(CALL_ID, body.clone()));
        let opened = cy.open_call_signal(GROUP, &inner).unwrap();
        assert_eq!(opened.lane, CallLane::Mls, "{body:?}");
        assert_eq!(
            opened.sender.as_ref().map(|s| s.device_id.as_str()),
            Some("device-bo-phone")
        );
        assert_eq!(opened.sender_leaf, Some(bo_leaf));

        // Written by hand on the live lane, it is refused.
        let live = forge_live(&ada, bo_leaf, NOW_MS + 100 + i as u64, body.clone());
        let err = cy.open_call_signal(GROUP, &live).unwrap_err();
        assert!(
            err.to_string().contains("must come on the MLS lane"),
            "{body:?}: {err}"
        );
    }
}

#[test]
fn a_live_frame_claiming_a_leaf_outside_the_tree_is_refused() {
    let (ada, _bo, mut cy) = three_members();
    let frame = forge_live(
        &ada,
        99,
        NOW_MS,
        CallSignalBody::Left {
            participant_id: "p-ada".into(),
        },
    );
    let err = cy.open_call_signal(GROUP, &frame).unwrap_err();
    assert!(err.to_string().contains("not in the tree"), "{err}");
}

/// A member claims Ada's leaf with a stamp at the edge of Cy's clock bound:
/// it carries no signature of hers and is refused. On the window itself,
/// even one that got in every 110 s takes only its own stamp, and Ada's own
/// heartbeats, every 10 s, still open.
#[test]
fn a_claimed_leaf_cannot_silence_its_owner() {
    let (mut ada, bo, mut cy) = three_members();
    let ada_leaf = ada.leaf_of_device(GROUP, "device-ada-phone").unwrap();

    // On the real door: Bo's frame stamped 119 s ahead, then Ada's heartbeat.
    let poison = forge_live(
        &bo,
        ada_leaf,
        NOW_MS + CALL_LIVE_MAX_SKEW_MS - 1_000,
        joined("p-ada", "ada-session", ada_leaf),
    );
    let err = cy.open_call_signal(GROUP, &poison).unwrap_err();
    assert!(err.to_string().contains("carries no signature"), "{err}");
    start(&mut ada, "p-ada", "ada-session");
    let honest = sealed(
        &mut ada,
        &cy,
        &CallSignal::new(CALL_ID, joined("p-ada", "ada-session", ada_leaf)),
    );
    cy.open_call_signal(GROUP, &honest).unwrap();

    // Over half an hour, on the window itself. A forged frame takes exactly
    // the stamp it names; the owner's are its clock's milliseconds, which the
    // forger does not see ahead of time, so the forged ones fall between.
    let mut w = LiveReplayWindow::new();
    let t0 = NOW_MS;
    let (mut refused, mut total) = (0, 0);
    let mut t = t0;
    while t < t0 + 30 * 60_000 {
        if (t - t0).is_multiple_of(110_000) {
            assert_eq!(
                w.check(GROUP, CALL_ID, 7, 2, t + CALL_LIVE_MAX_SKEW_MS - 7, t, t),
                LiveReplayVerdict::Accepted
            );
        }
        total += 1;
        if w.check(GROUP, CALL_ID, 7, 2, t, t, t) != LiveReplayVerdict::Accepted {
            refused += 1;
        }
        t += 10_000;
    }
    assert_eq!(refused, 0, "{refused} of {total} heartbeats refused");
}

/// Call ids and leaves are the frame's to say, so the window holds a bounded
/// number of senders however many a member invents, and forgets stamps once
/// the clock bound refuses them anyway.
#[test]
fn the_replay_window_is_bounded() {
    let mut w = LiveReplayWindow::new();
    for i in 0..(4 * CALL_LIVE_MAX_SENDERS as u32) {
        let mut call = [0u8; 16];
        call[..4].copy_from_slice(&i.to_be_bytes());
        assert_eq!(
            w.check(GROUP, call, 1, i, NOW_MS, NOW_MS, NOW_MS),
            LiveReplayVerdict::Accepted
        );
        assert!(w.senders() <= CALL_LIVE_MAX_SENDERS);
    }
    // One sender, a frame a second for an hour: only the last 240 s stay.
    let mut w = LiveReplayWindow::new();
    for s in 0..3_600u64 {
        let at = NOW_MS + s * 1_000;
        assert_eq!(
            w.check(GROUP, CALL_ID, 1, 0, at, at, at),
            LiveReplayVerdict::Accepted
        );
    }
    assert!(w.stamps() <= 2 * (CALL_LIVE_MAX_SKEW_MS / 1_000) as usize + 1);
    // What the window forgot is refused by the clock bound instead.
    assert_eq!(
        w.check(
            GROUP,
            CALL_ID,
            1,
            0,
            NOW_MS,
            NOW_MS + 3_599_000,
            NOW_MS + 3_599_000
        ),
        LiveReplayVerdict::Stale
    );
}

fn offer(age_ms: i64, created_at_ms: i64, now_ms: i64) -> RingEvent {
    RingEvent::Offer {
        call_id: "30313233343536373839616263646566".into(),
        conversation: "dm".into(),
        sender: "mallory".into(),
        from_self: false,
        media: CallMedia::Audio,
        ring: true,
        age_ms,
        created_at_ms,
        now_ms,
        member_count: 2,
        one_to_one: true,
        gate: RingGate::Allowed,
        already_ended: false,
        early_hangup: None,
    }
}

fn rings(event: &RingEvent) -> bool {
    ring_step(&RingState::Idle, event)
        .effects
        .iter()
        .any(|e| matches!(e, RingEffect::Ring { .. }))
}

fn missed(event: &RingEvent) -> bool {
    ring_step(&RingState::Idle, event).effects.iter().any(|e| {
        matches!(
            e,
            RingEffect::Ended {
                outcome: RingOutcome::Missed,
                ..
            }
        )
    })
}

#[test]
fn an_offer_rings_only_while_the_callers_stamp_is_fresh_too() {
    let now = NOW * 1000;
    let max_age = CALL_OFFER_MAX_AGE_MS as i64;
    let skew = CALL_OFFER_MAX_SKEW_MS as i64;

    // The instrument: a fresh offer by both clocks rings.
    assert!(rings(&offer(1_500, now - 1_500, now)));
    // Clocks a little apart either way still ring.
    assert!(rings(&offer(0, now + skew, now)));
    assert!(rings(&offer(1_500, now - max_age - skew, now)));

    // Dated as far ahead as the codec allows: never rings, on either path.
    let far = (1i64 << 53) - 1;
    for age in [0, 1_500] {
        let e = offer(age, far, now);
        assert!(!rings(&e) && missed(&e));
    }
    let e = offer(0, now + skew + 1, now);
    assert!(!rings(&e) && missed(&e));

    // The server says it took the offer a second ago; the caller made it ten
    // minutes ago. It is a missed call.
    let e = offer(1_000, now - 600_000, now);
    assert!(!rings(&e) && missed(&e));
    let e = offer(1_000, now - max_age - skew - 1, now);
    assert!(!rings(&e) && missed(&e));

    // An age from the future by the server's clock is not fresh either.
    let e = offer(-skew - 1, now, now);
    assert!(!rings(&e) && missed(&e));
}
