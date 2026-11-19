// SPDX-License-Identifier: MIT
//! A CORE THAT LOST A CALL'S STATE NEVER DOWNGRADES IT (docs/calls.md
//! §Participant media keys, §Lost state).
//!
//! A call's participant media state lives in the [`Client`], in memory. A
//! client rebuilt mid-call (recovery after a panic, or iOS reopening its
//! client after the notification extension moved the ratchet) has none of
//! it. These hold, with no attacker involved:
//!
//! 1. The rebuilt core refuses to seal the client's next `Joined`, which
//!    would go out with no call key, and says why ("call state lost").
//! 2. The client rejoins (`start` under the same participant id, a signed
//!    `Joined`, `share`): the others take it as a returning device, and each
//!    sends its own signed `Joined` again so the rebuilt core can bind it.
//!    The call stays on participant keys, and a later leaver is rotated past
//!    on the rebuilt device too.
//! 3. `start` names the participant id it starts, so only a `Left` naming
//!    exactly that id ends the keys, however many ids came before and
//!    whatever the core remembers of them.
//! 4. Every own `Left` goes signed, whichever door sealed it.
//! 5. A keyless `Joined` never goes out: not after a failed `start`, and
//!    not after `end`.
//! 6. The live lane's replay window does not forget a stamp because the wall
//!    clock was stepped.
//! 7. A device's participations are ordered: a signed `Joined` the server
//!    held back past a rejoin is refused, so it cannot re-bind the rejoined
//!    device to the call key its lost state took with it, nor its leaf to an
//!    id it left; and a grant from an earlier participation never stands in
//!    for the current one's.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use peachy_mls_core::call::{
    call_frame_key, CallLane, CallMediaKeys, CallSignal, CallSignalBody, OpenedCallSignal,
};
use peachy_mls_core::{Client, MemoryKv, PeachyStorage};
use support::{advance_ms, client, client_on, issuer};

const GROUP: &[u8] = b"peachy-call-lost-state";
const CALL_ID: [u8; 16] = *b"call-lost-state!";
const NAMES: [&str; 4] = ["ada", "bo", "cy", "di"];
const LOST: &str = "call state lost";

/// Four members in one group; Bo's store is `bo_kv`, so Bo's client can be
/// rebuilt on it.
fn members_with_bo_on(bo_kv: &MemoryKv) -> Vec<Client> {
    let server = issuer();
    let mut out: Vec<Client> = (0..4u8)
        .map(|i| {
            let name = NAMES[usize::from(i)];
            let actor = format!("actor-{name}");
            let device = format!("device-{name}-phone");
            if i == 1 {
                client_on(
                    &server,
                    i + 1,
                    &actor,
                    &device,
                    PeachyStorage::open(Box::new(bo_kv.clone())).unwrap(),
                )
            } else {
                client(&server, i + 1, &actor, &device)
            }
        })
        .collect();
    out[0].create_group(GROUP).unwrap();
    for i in 1..out.len() {
        let kp = out[i].generate_key_package().unwrap();
        let added = out[0].add_member(GROUP, &kp).unwrap();
        out[0].merge_pending_commit(GROUP).unwrap();
        for member in out.iter_mut().take(i).skip(1) {
            member.process_commit(GROUP, &added.commit).unwrap();
        }
        out[i]
            .join_from_welcome(&added.welcome.clone().unwrap())
            .unwrap();
    }
    out
}

/// Bo's client is rebuilt on the same store, mid-call.
fn rebuild_bo(bo_kv: &MemoryKv) -> Client {
    client_on(
        &issuer(),
        2,
        "actor-bo",
        "device-bo-phone",
        PeachyStorage::open(Box::new(bo_kv.clone())).unwrap(),
    )
}

fn leaf(member: &Client) -> u32 {
    let device = member.identity().device_id.clone();
    member.leaf_of_device(GROUP, &device).unwrap()
}

fn try_open(member: &mut Client, envelope: &[u8]) -> Option<OpenedCallSignal> {
    let inner = member.open_envelope(envelope).unwrap().unwrap().inner;
    member.open_call_signal(GROUP, &inner).ok()
}

fn settle(all: &mut [Client], from: usize, envelopes: Vec<Vec<u8>>) {
    let mut queue = vec![(from, envelopes)];
    while let Some((from, envelopes)) = queue.pop() {
        for envelope in &envelopes {
            for (i, member) in all.iter_mut().enumerate() {
                if i == from {
                    continue;
                }
                if let Some(opened) = try_open(member, envelope) {
                    if !opened.send.is_empty() {
                        queue.push((i, opened.send));
                    }
                }
            }
        }
    }
}

/// `start` for `participant`, as every client asks it: the id, session and
/// tracks from the JoinCall answer.
fn start(
    member: &mut Client,
    participant: &str,
    session: &str,
) -> peachy_mls_core::Result<[u8; 32]> {
    member.call_media_start(
        GROUP,
        &CALL_ID,
        participant,
        session,
        &[format!("{session}-audio")],
    )
}

/// A `Joined` as every client builds it: participant, session and tracks
/// from the JoinCall answer, no media key (the core fills it in for a v2
/// participant and strips the session).
fn client_joined(member: &Client, participant: &str, session: &str) -> CallSignal {
    CallSignal::new(
        CALL_ID,
        CallSignalBody::Joined {
            participant_id: participant.into(),
            session_id: session.into(),
            track_names: vec![format!("{session}-audio")],
            leaf_index: leaf(member),
            media_key: Vec::new(),
            started_at_ms: 0,
            media_key_pq: Vec::new(),
            participation: None,
        },
    )
}

fn left(participant: &str) -> CallSignal {
    CallSignal::new(
        CALL_ID,
        CallSignalBody::Left {
            participant_id: participant.into(),
        },
    )
}

/// The documented v2 join: `start`, the signed `Joined`, `share`.
fn join(all: &mut [Client], i: usize, participant: &str, session: &str) {
    start(&mut all[i], participant, session).unwrap();
    let signal = client_joined(&all[i], participant, session);
    let envelope = all[i].seal_call_signal_on_mls_lane(GROUP, &signal).unwrap();
    settle(all, i, vec![envelope]);
    let grants = all[i].call_media_share(GROUP, &CALL_ID).unwrap();
    settle(all, i, grants);
}

fn keys(member: &mut Client) -> CallMediaKeys {
    member.call_media_keys(GROUP, &CALL_ID, false).unwrap()
}

fn keyed(member: &mut Client, leaf_index: u32, participant: &str) -> bool {
    keys(member)
        .participants
        .iter()
        .any(|p| p.leaf_index == leaf_index && p.participant_id == participant && p.keyed)
}

fn frame(sender: &mut Client, payload: &[u8], iv: u8) -> Vec<u8> {
    let keys = keys(sender);
    let own = keys
        .senders
        .iter()
        .find(|key| key.leaf_index == keys.own_leaf && key.key_index == keys.send_key_index)
        .unwrap();
    let frame_key = call_frame_key(&*own.key).unwrap();
    let (header, rest) = payload.split_at(1);
    let iv = [iv; 12];
    let ciphertext = Aes128Gcm::new_from_slice(&frame_key)
        .unwrap()
        .encrypt(
            Nonce::from_slice(&iv),
            Payload {
                msg: rest,
                aad: header,
            },
        )
        .unwrap();
    let mut out = header.to_vec();
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&iv);
    out.push(12);
    out.push(keys.send_key_index);
    out
}

fn decrypts(sender_key: &[u8; 16], wire: &[u8]) -> bool {
    let frame_key = call_frame_key(sender_key).unwrap();
    let body = &wire[..wire.len() - 2];
    let (front, iv) = body.split_at(body.len() - 12);
    let (header, ciphertext) = front.split_at(1);
    Aes128Gcm::new_from_slice(&frame_key)
        .unwrap()
        .decrypt(
            Nonce::from_slice(iv),
            Payload {
                msg: ciphertext,
                aad: header,
            },
        )
        .is_ok()
}

fn opens_at(receiver: &mut Client, sender_leaf: u32, wire: &[u8]) -> bool {
    keys(receiver)
        .senders
        .iter()
        .any(|k| k.leaf_index == sender_leaf && decrypts(&k.key, wire))
}

/// Every v1 key Di, a member who never joins, derives.
fn di_reads(di: &Client, sender_leaf: u32, wire: &[u8]) -> bool {
    di.call_keys(GROUP, &CALL_ID)
        .unwrap()
        .senders
        .iter()
        .any(|k| k.leaf_index == sender_leaf && decrypts(&k.key, wire))
}

fn opus(seed: u8) -> Vec<u8> {
    let mut out = vec![0x78u8];
    out.extend((0..80u8).map(|i| i.wrapping_mul(31) ^ seed));
    out
}

fn refused_as_lost(result: peachy_mls_core::Result<Vec<u8>>) -> bool {
    matches!(result, Err(err) if err.to_string().contains(LOST))
}

/// Bo's client is rebuilt mid-call. Its next `Joined`, signed
/// (the first of an epoch) or a heartbeat, is refused, so nobody falls back
/// to the shared key, and Di, who never joined, still reads nothing.
#[test]
fn a_core_rebuilt_mid_call_refuses_the_joined_that_would_downgrade_the_call() {
    let kv = MemoryKv::new();
    let mut all = members_with_bo_on(&kv);
    let (ada, bo, cy, di) = (0usize, 1usize, 2usize, 3usize);
    let ada_leaf = leaf(&all[ada]);
    join(&mut all, ada, "p-ada", "sess-ada");
    join(&mut all, bo, "p-bo", "sess-bo");
    join(&mut all, cy, "p-cy", "sess-cy");

    all[bo] = rebuild_bo(&kv);
    let signal = client_joined(&all[bo], "p-bo", "sess-bo");
    assert!(
        refused_as_lost(all[bo].seal_call_signal_on_mls_lane(GROUP, &signal)),
        "the signed Joined is refused"
    );
    assert!(
        refused_as_lost(all[bo].seal_call_signal(GROUP, &signal)),
        "and so is the heartbeat"
    );
    let err = all[bo]
        .call_media_keys(GROUP, &CALL_ID, false)
        .expect_err("Bo's core forgot the call");
    assert!(err.to_string().contains(LOST), "keys says so too: {err}");

    let ada_frame = frame(&mut all[ada], &opus(9), 9);
    assert!(opens_at(&mut all[cy], ada_leaf, &ada_frame));
    assert!(
        !di_reads(&all[di], ada_leaf, &ada_frame),
        "Di reads nothing"
    );
}

/// The way back: the rebuilt client rejoins under the same
/// participant id. Everyone binds its fresh key, and it binds everyone again
/// from the signed `Joined` each sends back, so the call stays on
/// participant keys; and a leaver after that is rotated past on the rebuilt
/// device too.
#[test]
fn a_rebuilt_core_rejoins_and_rotates_past_the_next_leaver() {
    let kv = MemoryKv::new();
    let mut all = members_with_bo_on(&kv);
    let (ada, bo, cy, di) = (0usize, 1usize, 2usize, 3usize);
    let (ada_leaf, bo_leaf, cy_leaf) = (leaf(&all[ada]), leaf(&all[bo]), leaf(&all[cy]));
    join(&mut all, ada, "p-ada", "sess-ada");
    join(&mut all, bo, "p-bo", "sess-bo");
    join(&mut all, cy, "p-cy", "sess-cy");

    all[bo] = rebuild_bo(&kv);
    // Its heartbeat is refused; the client answers by joining again.
    let beat = client_joined(&all[bo], "p-bo", "sess-bo");
    assert!(refused_as_lost(all[bo].seal_call_signal(GROUP, &beat)));
    join(&mut all, bo, "p-bo", "sess-bo");

    assert!(
        keyed(&mut all[ada], bo_leaf, "p-bo"),
        "Ada holds Bo's fresh key"
    );
    assert!(
        keyed(&mut all[bo], ada_leaf, "p-ada"),
        "Bo holds Ada's again"
    );
    assert!(keyed(&mut all[bo], cy_leaf, "p-cy"), "and Cy's");
    let bo_frame = frame(&mut all[bo], &opus(3), 3);
    assert!(opens_at(&mut all[ada], bo_leaf, &bo_frame));
    assert!(!di_reads(&all[di], bo_leaf, &bo_frame));
    let ada_frame = frame(&mut all[ada], &opus(4), 4);
    assert!(opens_at(&mut all[bo], ada_leaf, &ada_frame));

    // Cy leaves: Bo, rebuilt, owes a rotation past Cy like everyone else.
    let envelope = all[cy]
        .seal_call_signal_on_mls_lane(GROUP, &left("p-cy"))
        .unwrap();
    let at_bo = try_open(&mut all[bo], &envelope).unwrap();
    assert!(!at_bo.send.is_empty(), "Bo draws a fresh secret past Cy");
    assert_eq!(at_bo.unbound_leaf, Some(cy_leaf));
}

/// After a rebuild, the rejoin's documented order
/// `start`, then the old participant's `Left`, then the new `Joined` keeps
/// the new participation's keys: `start` named the new id.
#[test]
fn after_a_rebuild_the_old_left_after_start_leaves_the_new_participation() {
    let kv = MemoryKv::new();
    let mut all = members_with_bo_on(&kv);
    let (ada, bo, cy) = (0usize, 1usize, 2usize);
    join(&mut all, ada, "p-ada", "sess-ada");
    join(&mut all, bo, "p-bo", "sess-bo");
    join(&mut all, cy, "p-cy", "sess-cy");

    all[bo] = rebuild_bo(&kv);
    start(&mut all[bo], "p-bo-2", "sess-bo-2").unwrap();
    let old_left = all[bo]
        .seal_call_signal_on_mls_lane(GROUP, &left("p-bo"))
        .unwrap();
    settle(&mut all, bo, vec![old_left]);
    assert!(
        all[bo].call_media_keys(GROUP, &CALL_ID, false).is_ok(),
        "the old participant's Left ended nothing new"
    );
    let new_joined = client_joined(&all[bo], "p-bo-2", "sess-bo-2");
    let envelope = all[bo]
        .seal_call_signal_on_mls_lane(GROUP, &new_joined)
        .unwrap();
    settle(&mut all, bo, vec![envelope]);
    // Every client answers a participant id it has not seen with a signed
    // Joined of its own, once, so the newcomer can bind it.
    for (i, participant, session) in [(ada, "p-ada", "sess-ada"), (cy, "p-cy", "sess-cy")] {
        let answer = client_joined(&all[i], participant, session);
        let envelope = all[i].seal_call_signal_on_mls_lane(GROUP, &answer).unwrap();
        settle(&mut all, i, vec![envelope]);
    }
    let grants = all[bo].call_media_share(GROUP, &CALL_ID).unwrap();
    settle(&mut all, bo, grants);
    let bo_leaf = leaf(&all[bo]);
    assert!(keyed(&mut all[ada], bo_leaf, "p-bo-2"));
}

/// After a rebuild, the old participant's `Left`
/// sealed through the ordinary door goes signed, so every participant
/// unbinds the old participation and rotates past it.
#[test]
fn after_a_rebuild_an_own_left_through_the_plain_door_goes_signed() {
    let kv = MemoryKv::new();
    let mut all = members_with_bo_on(&kv);
    let (ada, bo, cy) = (0usize, 1usize, 2usize);
    join(&mut all, ada, "p-ada", "sess-ada");
    join(&mut all, bo, "p-bo", "sess-bo");
    join(&mut all, cy, "p-cy", "sess-cy");
    let bo_leaf = leaf(&all[bo]);

    all[bo] = rebuild_bo(&kv);
    let old_left = all[bo].seal_call_signal(GROUP, &left("p-bo")).unwrap();
    let inner = all[ada].open_envelope(&old_left).unwrap().unwrap().inner;
    assert_eq!(CallLane::split(&inner).unwrap().0, CallLane::Mls, "signed");
    let opened = all[ada].open_call_signal(GROUP, &inner).unwrap();
    assert_eq!(opened.unbound_leaf, Some(bo_leaf));
    assert!(
        !opened.send.is_empty(),
        "Ada rotates past the old participation"
    );
    assert!(!keyed(&mut all[ada], bo_leaf, "p-bo"));
}

/// A `start` that fails licenses nothing. The
/// client's keyless `Joined` after it is refused, so no participant falls
/// back and Di reads nothing.
#[test]
fn a_failed_start_licenses_no_keyless_joined() {
    let kv = MemoryKv::new();
    let mut all = members_with_bo_on(&kv);
    let (ada, bo, cy, di) = (0usize, 1usize, 2usize, 3usize);
    let ada_leaf = leaf(&all[ada]);
    join(&mut all, ada, "p-ada", "sess-ada");
    join(&mut all, bo, "p-bo", "sess-bo");

    let server_session = "s".repeat(300);
    assert!(start(&mut all[cy], "p-cy", &server_session).is_err());
    let fallback = client_joined(&all[cy], "p-cy", "sess-cy");
    assert!(refused_as_lost(
        all[cy].seal_call_signal_on_mls_lane(GROUP, &fallback)
    ));
    assert!(refused_as_lost(all[cy].seal_call_signal(GROUP, &fallback)));

    let ada_frame = frame(&mut all[ada], &opus(7), 7);
    assert!(!di_reads(&all[di], ada_leaf, &ada_frame));
}

/// With `start` naming its id there is no list of former ids to
/// overflow. Seventeen rejoins later, a `Left` for the first id ends nothing.
#[test]
fn any_number_of_former_ids_leave_the_current_participation_alone() {
    let kv = MemoryKv::new();
    let mut all = members_with_bo_on(&kv);
    let bo = 1usize;
    for n in 0..17 {
        let id = format!("p-bo-{n}");
        start(&mut all[bo], &id, "sess-bo").unwrap();
        let signal = client_joined(&all[bo], &id, "sess-bo");
        all[bo]
            .seal_call_signal_on_mls_lane(GROUP, &signal)
            .unwrap();
    }
    start(&mut all[bo], "p-bo-17", "sess-bo").unwrap();
    for n in 0..17 {
        all[bo]
            .seal_call_signal_on_mls_lane(GROUP, &left(&format!("p-bo-{n}")))
            .unwrap();
        assert!(
            all[bo].call_media_keys(GROUP, &CALL_ID, false).is_ok(),
            "the Left for p-bo-{n} ended the new participation"
        );
    }
    all[bo]
        .seal_call_signal_on_mls_lane(GROUP, &left("p-bo-17"))
        .unwrap();
    assert!(
        all[bo].call_media_keys(GROUP, &CALL_ID, false).is_err(),
        "the current participation's own Left ends it"
    );
}

/// `end` after the device's own `Left` licenses no keyless
/// `Joined` either.
#[test]
fn end_licenses_no_keyless_joined() {
    let kv = MemoryKv::new();
    let mut all = members_with_bo_on(&kv);
    let (ada, bo) = (0usize, 1usize);
    join(&mut all, ada, "p-ada", "sess-ada");
    join(&mut all, bo, "p-bo", "sess-bo");

    let envelope = all[bo]
        .seal_call_signal_on_mls_lane(GROUP, &left("p-bo"))
        .unwrap();
    settle(&mut all, bo, vec![envelope]);
    all[bo].call_media_end(GROUP, &CALL_ID).unwrap();
    let late = client_joined(&all[bo], "p-bo", "sess-bo");
    assert!(refused_as_lost(all[bo].seal_call_signal(GROUP, &late)));
    assert!(refused_as_lost(
        all[bo].seal_call_signal_on_mls_lane(GROUP, &late)
    ));
}

/// A live frame's stamp is remembered by the monotonic clock,
/// so stepping the wall clock forward and back does not let a recording of
/// it in again.
#[test]
fn a_wall_clock_step_does_not_forget_a_live_stamp() {
    let kv = MemoryKv::new();
    let mut all = members_with_bo_on(&kv);
    let (ada, bo) = (0usize, 1usize);
    let ada_leaf = leaf(&all[ada]);
    let beat = |member: &mut Client| {
        let signal = CallSignal::new(
            CALL_ID,
            CallSignalBody::Joined {
                participant_id: "p-ada".into(),
                session_id: "sess-ada".into(),
                track_names: Vec::new(),
                leaf_index: ada_leaf,
                media_key: Vec::new(),
                started_at_ms: 0,
                media_key_pq: Vec::new(),
                participation: None,
            },
        );
        member.seal_call_signal(GROUP, &signal).unwrap()
    };
    // Ada is in the call, so her heartbeat seals.
    all[ada]
        .call_media_start(GROUP, &CALL_ID, "p-ada", "sess-ada", &[])
        .unwrap();
    let recorded = beat(&mut all[ada]);
    assert!(try_open(&mut all[bo], &recorded).is_some());
    // The wall clock jumps three minutes ahead; a fresh heartbeat is opened.
    support::step_wall_ms(180_000);
    let later = beat(&mut all[ada]);
    assert!(try_open(&mut all[bo], &later).is_some());
    // And steps back: the recording is still within the clock bound.
    support::step_wall_ms(-180_000);
    assert!(
        try_open(&mut all[bo], &recorded).is_none(),
        "the recording is refused as a duplicate"
    );
}

/// Open one envelope at one member, its refusal included.
fn open_at(member: &mut Client, envelope: &[u8]) -> peachy_mls_core::Result<OpenedCallSignal> {
    let inner = member.open_envelope(envelope).unwrap().unwrap().inner;
    member.open_call_signal(GROUP, &inner)
}

fn refused_as_earlier(result: peachy_mls_core::Result<OpenedCallSignal>) -> bool {
    matches!(result, Err(err) if err.to_string().contains("earlier participation"))
}

/// A client answering a participant id it has not seen with its own signed
/// `Joined` (docs/calls.md; the client half the core relies on).
fn answer(all: &mut [Client], i: usize, participant: &str, session: &str) {
    let signal = client_joined(&all[i], participant, session);
    let envelope = all[i].seal_call_signal_on_mls_lane(GROUP, &signal).unwrap();
    settle(all, i, vec![envelope]);
}

/// The server holds Bo's first signed `Joined` (call key K1) from Ada and
/// hands it over only after Bo's core lost the call's state and Bo rejoined
/// under the same participant id (K2). Ada refuses it as an earlier
/// participation's, so she never re-binds Bo to K1, whose private half died
/// with the old core: after the next leaver both still hear each other.
#[test]
fn a_late_first_joined_cannot_rebind_a_rejoined_device_to_its_dead_call_key() {
    let kv = MemoryKv::new();
    let mut all = members_with_bo_on(&kv);
    let (ada, bo, cy, di) = (0usize, 1usize, 2usize, 3usize);
    let (ada_leaf, bo_leaf) = (leaf(&all[ada]), leaf(&all[bo]));
    join(&mut all, ada, "p-ada", "sess-ada");
    join(&mut all, cy, "p-cy", "sess-cy");

    // Bo joins; the server gives its signed Joined to Cy and Di only.
    start(&mut all[bo], "p-bo", "sess-bo").unwrap();
    let first = client_joined(&all[bo], "p-bo", "sess-bo");
    let held_from_ada = all[bo].seal_call_signal_on_mls_lane(GROUP, &first).unwrap();
    for i in [cy, di] {
        let send = open_at(&mut all[i], &held_from_ada).unwrap().send;
        settle(&mut all, i, send);
    }

    // Bo's core is rebuilt mid-call, which takes a moment, and Bo rejoins
    // under the same id with a fresh call key.
    advance_ms(1_500);
    all[bo] = rebuild_bo(&kv);
    join(&mut all, bo, "p-bo", "sess-bo");
    answer(&mut all, ada, "p-ada", "sess-ada");
    let before = frame(&mut all[ada], &opus(1), 1);
    assert!(opens_at(&mut all[bo], ada_leaf, &before), "Bo hears Ada");
    let bo_frame = frame(&mut all[bo], &opus(2), 2);
    assert!(opens_at(&mut all[ada], bo_leaf, &bo_frame), "Ada hears Bo");

    // The server releases the held Joined to Ada: refused.
    assert!(
        refused_as_earlier(open_at(&mut all[ada], &held_from_ada)),
        "the earlier participation's Joined is refused"
    );

    // A later leave: Ada's fresh secret goes to Bo's live key.
    let cy_left = all[cy]
        .seal_call_signal_on_mls_lane(GROUP, &left("p-cy"))
        .unwrap();
    settle(&mut all, cy, vec![cy_left]);
    advance_ms(5_001);
    let send = all[ada].call_media_apply(GROUP, &CALL_ID).unwrap();
    settle(&mut all, ada, send);
    let send = all[bo].call_media_apply(GROUP, &CALL_ID).unwrap();
    settle(&mut all, bo, send);

    let after = frame(&mut all[ada], &opus(3), 3);
    assert!(
        opens_at(&mut all[bo], ada_leaf, &after),
        "Bo still hears Ada after the rotation"
    );
    let bo_frame = frame(&mut all[bo], &opus(4), 4);
    assert!(opens_at(&mut all[ada], bo_leaf, &bo_frame), "and Ada Bo");
}

/// The same reordering across a rejoin under a NEW id, with no state lost:
/// Bo's first Joined (`p-bo`) reaches Ada after the one for `p-bo-2`. Ada
/// refuses it and keeps Bo bound as `p-bo-2`, on its current key.
#[test]
fn a_late_joined_cannot_take_a_leaf_back_to_an_id_it_left() {
    let kv = MemoryKv::new();
    let mut all = members_with_bo_on(&kv);
    let (ada, bo, cy, di) = (0usize, 1usize, 2usize, 3usize);
    let bo_leaf = leaf(&all[bo]);
    join(&mut all, ada, "p-ada", "sess-ada");

    start(&mut all[bo], "p-bo", "sess-bo").unwrap();
    let first = client_joined(&all[bo], "p-bo", "sess-bo");
    let held_from_ada = all[bo].seal_call_signal_on_mls_lane(GROUP, &first).unwrap();
    for i in [cy, di] {
        let send = open_at(&mut all[i], &held_from_ada).unwrap().send;
        settle(&mut all, i, send);
    }
    // Bo leaves and joins again under the id the server gives the new join.
    let old_left = all[bo]
        .seal_call_signal_on_mls_lane(GROUP, &left("p-bo"))
        .unwrap();
    settle(&mut all, bo, vec![old_left]);
    join(&mut all, bo, "p-bo-2", "sess-bo-2");
    assert!(keyed(&mut all[ada], bo_leaf, "p-bo-2"));

    assert!(refused_as_earlier(open_at(&mut all[ada], &held_from_ada)));
    assert!(
        keyed(&mut all[ada], bo_leaf, "p-bo-2"),
        "Ada keeps Bo as p-bo-2, keyed"
    );
    let bo_frame = frame(&mut all[bo], &opus(5), 5);
    assert!(opens_at(&mut all[ada], bo_leaf, &bo_frame));
}

/// A grant Ada held from Bo's earlier participation (Bo's Joined had not
/// reached her) never counts for the rejoined one: when Bo's new Joined
/// binds, the held grant is dropped, and the new participation's grant,
/// at a LOWER generation than the old one rotated to, is the one she takes.
#[test]
fn a_held_grant_from_an_earlier_participation_never_binds() {
    let kv = MemoryKv::new();
    let mut all = members_with_bo_on(&kv);
    let (ada, bo, cy, di) = (0usize, 1usize, 2usize, 3usize);
    let bo_leaf = leaf(&all[bo]);
    join(&mut all, ada, "p-ada", "sess-ada");

    // Bo joins; its Joined never reaches Ada, so its grants to her are held.
    start(&mut all[bo], "p-bo", "sess-bo").unwrap();
    let first = client_joined(&all[bo], "p-bo", "sess-bo");
    let never_to_ada = all[bo].seal_call_signal_on_mls_lane(GROUP, &first).unwrap();
    for i in [cy, di] {
        let send = open_at(&mut all[i], &never_to_ada).unwrap().send;
        settle(&mut all, i, send);
    }
    let grants = all[bo].call_media_share(GROUP, &CALL_ID).unwrap();
    settle(&mut all, bo, grants);
    // Cy comes and goes: Bo rotates, and grants Ada its fresh secret, a
    // later generation, held too.
    join(&mut all, cy, "p-cy", "sess-cy");
    let cy_left = all[cy]
        .seal_call_signal_on_mls_lane(GROUP, &left("p-cy"))
        .unwrap();
    settle(&mut all, cy, vec![cy_left]);
    advance_ms(5_001);
    for i in [ada, bo] {
        let send = all[i].call_media_apply(GROUP, &CALL_ID).unwrap();
        settle(&mut all, i, send);
    }

    // Bo's core is rebuilt and Bo rejoins: generation 0 again, a new secret.
    advance_ms(1_500);
    all[bo] = rebuild_bo(&kv);
    join(&mut all, bo, "p-bo", "sess-bo");
    answer(&mut all, ada, "p-ada", "sess-ada");

    assert!(keyed(&mut all[ada], bo_leaf, "p-bo"));
    let bo_frame = frame(&mut all[bo], &opus(6), 6);
    assert!(
        opens_at(&mut all[ada], bo_leaf, &bo_frame),
        "Ada hears the rejoined Bo, not the secret it held from before"
    );
}
