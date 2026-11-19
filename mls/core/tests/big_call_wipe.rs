// SPDX-License-Identifier: MIT
//! A call's keys are wiped from every heap block the core frees in a call
//! big enough to grow what holds them: more senders than a fresh vector's
//! first allocation holds, and a JSON answer longer than serde_json's first
//! buffer. secret_wipe_frames.rs looks at a call of two, where nothing grows.
//!
//! Five members, so a v1 call's keys list five senders (a vector pushed to
//! from empty holds four before it reallocates), and a v2 call's keys, with
//! every member a participant, list more again and spell them in an answer
//! of well over a kilobyte.
//!
//! An allocator stands in front of the system's for this test binary and
//! looks at every block as it is freed; one holding a key under test is
//! counted. The keys the test itself holds are read before it arms and
//! dropped first, so what is counted is the core's own copies. One test in
//! this file, so no other test's frees run beside it.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use peachy_mls_core::call::{CallSignal, CallSignalBody, OpenedCallSignal};
use peachy_mls_core::Client;
use support::{client, issuer};

const GROUP: &[u8] = b"peachy-big-call-wipe";
const CALL_ID: [u8; 16] = *b"0123456789abcdef";
const NAMES: [&str; 5] = ["ada", "bo", "cy", "di", "eve"];

struct Watching;
static ARMED: AtomicBool = AtomicBool::new(false);
static UNWIPED: AtomicUsize = AtomicUsize::new(0);
static NEEDLES: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

unsafe impl GlobalAlloc for Watching {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::SeqCst) {
            // `try_lock`: the needles are never freed while armed, and a
            // dealloc must not wait on a lock.
            if let Ok(needles) = NEEDLES.try_lock() {
                let block = std::slice::from_raw_parts(ptr, layout.size());
                for needle in needles.iter() {
                    if block.windows(needle.len()).any(|w| w == &needle[..]) {
                        UNWIPED.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
        }
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static ALLOCATOR: Watching = Watching;

/// How many blocks freed while `run` ran held a needle.
fn unwiped_during(needles: Vec<Vec<u8>>, run: impl FnOnce()) -> usize {
    *NEEDLES.lock().unwrap() = needles;
    UNWIPED.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    run();
    ARMED.store(false, Ordering::SeqCst);
    UNWIPED.load(Ordering::SeqCst)
}

/// Every member of one group, each having processed every add.
fn members() -> Vec<Client> {
    let server = issuer();
    let mut all: Vec<Client> = NAMES
        .iter()
        .zip(1u8..)
        .map(|(name, tag)| {
            client(
                &server,
                tag,
                &format!("actor-{name}"),
                &format!("device-{name}-phone"),
            )
        })
        .collect();
    all[0].create_group(GROUP).unwrap();
    for i in 1..all.len() {
        let key_package = all[i].generate_key_package().unwrap();
        let added = all[0].add_member(GROUP, &key_package).unwrap();
        all[0].merge_pending_commit(GROUP).unwrap();
        for member in all.iter_mut().take(i).skip(1) {
            member.process_commit(GROUP, &added.commit).unwrap();
        }
        all[i]
            .join_from_welcome(&added.welcome.clone().unwrap())
            .unwrap();
    }
    all
}

fn leaf(member: &Client) -> u32 {
    let device = member.identity().device_id.clone();
    member.leaf_of_device(GROUP, &device).unwrap()
}

fn open(member: &mut Client, envelope: &[u8]) -> OpenedCallSignal {
    let inner = member.open_envelope(envelope).unwrap().unwrap().inner;
    member.open_call_signal(GROUP, &inner).unwrap()
}

/// Deliver `envelopes` from member `from` to every other member, and what
/// each owes in turn, until nobody owes anything.
fn settle(all: &mut [Client], from: usize, envelopes: Vec<Vec<u8>>) {
    let mut queue = vec![(from, envelopes)];
    while let Some((from, envelopes)) = queue.pop() {
        for envelope in &envelopes {
            for (i, member) in all.iter_mut().enumerate() {
                if i == from {
                    continue;
                }
                let opened = open(member, envelope);
                if !opened.send.is_empty() {
                    queue.push((i, opened.send));
                }
            }
        }
    }
}

/// Member `i` joins the v2 call and grants its media secret.
fn join(all: &mut [Client], i: usize) {
    let participant = format!("p-{}", NAMES[i]);
    let session = format!("s-{}", NAMES[i]);
    let tracks = [format!("{session}-audio")];
    all[i]
        .call_media_start(GROUP, &CALL_ID, &participant, &session, &tracks)
        .unwrap();
    let signal = CallSignal::new(
        CALL_ID,
        CallSignalBody::Joined {
            participant_id: participant,
            session_id: session,
            track_names: tracks.to_vec(),
            leaf_index: leaf(&all[i]),
            media_key: Vec::new(),
            started_at_ms: 0,
            media_key_pq: Vec::new(),
            participation: None,
        },
    );
    let envelope = all[i].seal_call_signal_on_mls_lane(GROUP, &signal).unwrap();
    settle(all, i, vec![envelope]);
    let grants = all[i].call_media_share(GROUP, &CALL_ID).unwrap();
    settle(all, i, grants);
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn a_big_calls_keys_are_wiped_from_what_the_core_frees() {
    let mut all = members();

    // v1: the call root and every sender key derived from it.
    let keys = all[0].call_keys(GROUP, &CALL_ID).unwrap();
    let v1_senders = keys.senders.len();
    let mut needles = vec![keys.call_root.to_vec()];
    needles.extend(keys.senders.iter().map(|sender| sender.key.to_vec()));
    drop(keys);
    let v1_unwiped = unwiped_during(needles, || {
        drop(all[0].call_keys(GROUP, &CALL_ID).unwrap());
    });

    // v2: every member a participant; each sender key raw and in the hex
    // the JSON door spells it in.
    for i in 0..all.len() {
        join(&mut all, i);
    }
    let keys = all[0].call_media_keys(GROUP, &CALL_ID, false).unwrap();
    let v2_senders = keys.senders.len();
    let mut needles = Vec::new();
    for sender in &keys.senders {
        needles.push(sender.key.to_vec());
        needles.push(to_hex(&*sender.key).into_bytes());
    }
    drop(keys);
    let request = format!(r#"{{"op":"keys","callId":"{}"}}"#, to_hex(&CALL_ID));
    let mut answer = String::new();
    let v2_unwiped = unwiped_during(needles, || {
        drop(all[0].call_media_keys(GROUP, &CALL_ID, false).unwrap());
        answer = all[0].call_media_json(GROUP, &request).unwrap();
    });

    assert!(
        v1_senders > 4,
        "a v1 call of {v1_senders} senders grows nothing"
    );
    assert!(
        v2_senders > 4,
        "a v2 call of {v2_senders} senders grows nothing"
    );
    assert!(answer.len() > 1024, "the answer is {} bytes", answer.len());
    assert_eq!(
        v1_unwiped, 0,
        "a block the core freed still held a v1 call key"
    );
    assert_eq!(
        v2_unwiped, 0,
        "a block the core freed still held a v2 sender key or its hex"
    );
}
