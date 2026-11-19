// SPDX-License-Identifier: MIT
//! A REMOVING DOOR GRANTS NOTHING TO WHOM IT REMOVES (docs/calls.md
//! §Participant media keys).
//!
//! A door that takes a participant out (`remove` by leaf, `remove` by
//! participant id, a signed `Left`) takes it out before the due switch and any
//! rotation chained behind it, so a fresh secret drawn there goes only to the
//! participants that remain. A `remove` naming this device's own id ends its
//! participation, as `end` does.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use peachy_mls_core::call::{
    call_frame_key, CallMediaKeys, CallSignal, CallSignalBody, OpenedCallSignal, CALL_STATE_LOST,
};
use peachy_mls_core::Client;
use support::{advance_ms, client, issuer};

const GROUP: &[u8] = b"peachy-call-removing-door";
const CALL_ID: [u8; 16] = *b"call-removing-dr";
const NAMES: [&str; 5] = ["ada", "bo", "cy", "di", "ev"];

fn members(n: usize) -> Vec<Client> {
    let server = issuer();
    let mut out: Vec<Client> = (0..n)
        .map(|i| {
            let name = NAMES[i];
            client(
                &server,
                u8::try_from(i + 1).unwrap(),
                &format!("actor-{name}"),
                &format!("device-{name}-phone"),
            )
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

fn leaf(member: &Client) -> u32 {
    let device = member.identity().device_id.clone();
    member.leaf_of_device(GROUP, &device).unwrap()
}

fn open(member: &mut Client, envelope: &[u8]) -> peachy_mls_core::Result<OpenedCallSignal> {
    let inner = member.open_envelope(envelope).unwrap().unwrap().inner;
    member.open_call_signal(GROUP, &inner)
}

fn settle(all: &mut [Client], from: usize, envelopes: Vec<Vec<u8>>) {
    let mut queue = vec![(from, envelopes)];
    while let Some((from, envelopes)) = queue.pop() {
        for envelope in &envelopes {
            for (i, member) in all.iter_mut().enumerate() {
                if i == from {
                    continue;
                }
                if let Ok(opened) = open(member, envelope) {
                    if !opened.send.is_empty() {
                        queue.push((i, opened.send));
                    }
                }
            }
        }
    }
}

fn joined(member: &Client, participant: &str, session: &str) -> CallSignal {
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

fn join(all: &mut [Client], i: usize, participant: &str, session: &str) {
    all[i]
        .call_media_start(
            GROUP,
            &CALL_ID,
            participant,
            session,
            &[format!("{session}-audio")],
        )
        .unwrap();
    let signal = joined(&all[i], participant, session);
    let envelope = all[i].seal_call_signal_on_mls_lane(GROUP, &signal).unwrap();
    settle(all, i, vec![envelope]);
    let grants = all[i].call_media_share(GROUP, &CALL_ID).unwrap();
    settle(all, i, grants);
}

fn keys(member: &mut Client) -> CallMediaKeys {
    member.call_media_keys(GROUP, &CALL_ID, false).unwrap()
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

fn opus(seed: u8) -> Vec<u8> {
    let mut out = vec![0x78u8];
    out.extend((0..80u8).map(|i| i.wrapping_mul(31) ^ seed));
    out
}

/// Ada rotates past Cy, then chains a rotation past Di while that one is
/// pending. Once it is due, an admin's `Remove` of Bo is the first door Ada
/// runs: the chained secret it draws there goes to Ev, who stays, and not to
/// Bo, so Bo cannot read what Ada sends once it switches.
#[test]
fn the_removing_door_grants_its_chained_secret_only_to_who_remains() {
    let mut all = members(5);
    let (ada, bo, cy, di, ev) = (0usize, 1usize, 2usize, 3usize, 4usize);
    let ada_leaf = leaf(&all[ada]);
    join(&mut all, ada, "p-ada", "sess-ada");
    join(&mut all, bo, "p-bo", "sess-bo");
    join(&mut all, cy, "p-cy", "sess-cy");
    join(&mut all, di, "p-di", "sess-di");
    join(&mut all, ev, "p-ev", "sess-ev");

    let cy_left = all[cy]
        .seal_call_signal_on_mls_lane(GROUP, &left("p-cy"))
        .unwrap();
    settle(&mut all, cy, vec![cy_left]);
    let di_left = all[di]
        .seal_call_signal_on_mls_lane(GROUP, &left("p-di"))
        .unwrap();
    settle(&mut all, di, vec![di_left]);
    assert!(all[ada]
        .call_media_apply_after_ms(GROUP, &CALL_ID)
        .is_some());
    advance_ms(6_000);

    let send = all[ada]
        .call_media_remove_participant(GROUP, &CALL_ID, "p-bo")
        .unwrap();
    assert!(!send.is_empty(), "the chained rotation's grants go out");
    let granted = |member: &mut Client| {
        send.iter().any(|envelope| {
            open(member, envelope)
                .ok()
                .and_then(|opened| opened.media)
                .is_some_and(|media| media.sender_leaf == ada_leaf && media.bound)
        })
    };
    assert!(
        granted(&mut all[ev]),
        "Ev, who stays, is granted the fresh secret"
    );
    assert!(
        !granted(&mut all[bo]),
        "Bo, removed by this door, is granted nothing"
    );

    advance_ms(5_001);
    all[ada].call_media_apply(GROUP, &CALL_ID).unwrap();
    let after_removal = frame(&mut all[ada], &opus(9), 9);
    assert!(
        opens_at(&mut all[ev], ada_leaf, &after_removal),
        "Ev reads Ada"
    );
    assert!(
        !opens_at(&mut all[bo], ada_leaf, &after_removal),
        "Bo, removed, reads nothing Ada sends under the secret drawn in the removing door"
    );
}

fn refused_as_lost(result: peachy_mls_core::Result<Vec<u8>>) -> bool {
    matches!(&result, Err(err) if err.to_string().contains(CALL_STATE_LOST))
}

/// A `Remove` this device honors naming its own participant id ends its
/// participation, as `end` does: no own media keys are left, a keyed
/// `Joined` is refused as lost, and `start` under the removed id is refused,
/// while a fresh id joins again.
#[test]
fn a_remove_of_its_own_id_ends_this_devices_participation() {
    let mut all = members(3);
    let (ada, bo) = (0usize, 1usize);
    join(&mut all, ada, "p-ada", "sess-ada");
    join(&mut all, bo, "p-bo", "sess-bo");
    let send = all[bo]
        .call_media_remove_participant(GROUP, &CALL_ID, "p-bo")
        .unwrap();
    assert!(send.is_empty(), "a Remove of its own id grants nothing");
    let keys = all[bo].call_media_keys(GROUP, &CALL_ID, false);
    assert!(
        matches!(&keys, Err(err) if err.to_string().contains(CALL_STATE_LOST)),
        "Bo holds no own media keys after its own Remove: {:?}",
        keys.map(|keys| keys.senders.len())
    );
    let beat = joined(&all[bo], "p-bo", "sess-bo");
    assert!(refused_as_lost(all[bo].seal_call_signal(GROUP, &beat)));
    assert!(
        all[bo]
            .call_media_start(GROUP, &CALL_ID, "p-bo", "sess-bo", &[])
            .is_err(),
        "start under the removed id is refused"
    );
    assert!(all[bo]
        .call_media_start(GROUP, &CALL_ID, "p-bo-2", "sess-bo", &[])
        .is_ok());
}
