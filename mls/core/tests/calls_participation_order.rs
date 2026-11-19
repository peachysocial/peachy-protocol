// SPDX-License-Identifier: MIT
//! A DEVICE'S PARTICIPATIONS ARE ORDERED BY A COUNTER IT KEEPS, NOT ITS
//! CLOCK (docs/calls.md §Participant media keys).
//!
//! A signed `Joined` from an earlier participation of the device bound at a
//! leaf is refused, so a `Joined` the server held back cannot re-bind a
//! rejoined device to the call key its lost state took with it. Ordered by
//! the wall clock, a device whose clock was set back between two
//! participations had its new `Joined` refused, and the held-back old one
//! taken. Each participation now carries a random id and the next value of
//! a counter the device keeps in its store, and the counter decides.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use peachy_mls_core::call::{CallSignal, CallSignalBody, Participation};
use peachy_mls_core::{Client, MemoryKv, PeachyStorage};
use support::{client, client_on, issuer, step_wall_ms};

const GROUP: &[u8] = b"peachy-call-participation";
const CALL_ID: [u8; 16] = *b"participate-call";

fn bo_on(kv: &MemoryKv) -> Client {
    client_on(
        &issuer(),
        2,
        "actor-bo",
        "device-bo-phone",
        PeachyStorage::open(Box::new(kv.clone())).unwrap(),
    )
}

/// Ada and Bo in one group, Ada in the call. Bo's store is `kv`, so his core
/// can be rebuilt on it.
fn two(kv: &MemoryKv) -> (Client, Client) {
    let mut ada = client(&issuer(), 1, "actor-ada", "device-ada-phone");
    let mut bo = bo_on(kv);
    ada.create_group(GROUP).unwrap();
    let kp = bo.generate_key_package().unwrap();
    let added = ada.add_member(GROUP, &kp).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    bo.join_from_welcome(&added.welcome.clone().unwrap())
        .unwrap();
    ada.call_media_start(GROUP, &CALL_ID, "p-ada", "sess-ada", &["a".into()])
        .unwrap();
    (ada, bo)
}

fn leaf(member: &Client) -> u32 {
    let device = member.identity().device_id.clone();
    member.leaf_of_device(GROUP, &device).unwrap()
}

/// Bo joins the call as `participant` and seals his signed `Joined`.
fn join(bo: &mut Client, participant: &str) -> Vec<u8> {
    bo.call_media_start(GROUP, &CALL_ID, participant, "sess-bo", &["b".into()])
        .unwrap();
    let own_leaf = leaf(bo);
    bo.seal_call_signal_on_mls_lane(
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

fn open(member: &mut Client, envelope: &[u8]) -> peachy_mls_core::Result<CallSignal> {
    let inner = member.open_envelope(envelope).unwrap().unwrap().inner;
    member
        .open_call_signal(GROUP, &inner)
        .map(|opened| opened.signal)
}

fn mark(signal: &CallSignal) -> (u64, Participation) {
    match &signal.body {
        CallSignalBody::Joined {
            started_at_ms,
            participation,
            ..
        } => (*started_at_ms, participation.expect("a participation mark")),
        other => panic!("not a Joined: {other:?}"),
    }
}

/// Bo joins, his core is rebuilt with his clock set back ten minutes, and he
/// joins again. His second `Joined` starts EARLIER by the clock, yet binds at
/// Ada after the first, and carries the next counter: the counter outlived
/// the core.
#[test]
fn a_rejoin_after_the_clock_was_set_back_binds_after_the_first() {
    let kv = MemoryKv::new();
    let (mut ada, mut bo) = two(&kv);
    let first = join(&mut bo, "p-bo-1");
    let first_signal = open(&mut ada, &first).unwrap();

    drop(bo);
    step_wall_ms(-10 * 60 * 1000);
    let mut bo = bo_on(&kv);
    let second = join(&mut bo, "p-bo-2");
    let second_signal = open(&mut ada, &second)
        .expect("a rejoin whose clock was set back is still the later participation");

    let (first_start, first_mark) = mark(&first_signal);
    let (second_start, second_mark) = mark(&second_signal);
    assert!(second_start < first_start, "the clock did not go back");
    assert_eq!(second_mark.seq, first_mark.seq + 1);
    assert_ne!(second_mark.id, first_mark.id);

    let keys = ada.call_media_keys(GROUP, &CALL_ID, false).unwrap();
    assert!(keys
        .participants
        .iter()
        .any(|p| p.participant_id == "p-bo-2"));
}

/// The held-back case the order exists for: Bo's first `Joined` reaches Ada
/// only after his rejoin's, from a core whose clock was set back. By the
/// clock it looks later; by the counter it is earlier, and it is refused.
#[test]
fn a_held_back_joined_from_an_earlier_participation_is_refused_whatever_the_clock() {
    let kv = MemoryKv::new();
    let (mut ada, mut bo) = two(&kv);
    let held_back = join(&mut bo, "p-bo-1");

    drop(bo);
    step_wall_ms(-10 * 60 * 1000);
    let mut bo = bo_on(&kv);
    let second = join(&mut bo, "p-bo-2");
    open(&mut ada, &second).unwrap();

    let err = open(&mut ada, &held_back).unwrap_err();
    assert!(
        err.to_string().contains("earlier participation"),
        "a held-back Joined re-bound Bo: {err}"
    );
    let keys = ada.call_media_keys(GROUP, &CALL_ID, false).unwrap();
    assert!(keys
        .participants
        .iter()
        .any(|p| p.participant_id == "p-bo-2"));
    assert!(!keys
        .participants
        .iter()
        .any(|p| p.participant_id == "p-bo-1"));
}
