// SPDX-License-Identifier: MIT
//! BEING IN THE CALL IS THE KEY BOUNDARY (docs/calls.md
//! §Participant media keys): v2 call keys against members who hold every key
//! the epoch gives.
//!
//! 1. A member who never joins derives no participant's frame key and never
//!    reads a participant's media-server session or tracks.
//! 2. A participant who leaves reads nothing sent after the participants
//!    that remain rotate, though it is still a member in the same epoch and
//!    keeps every key it held. A participant a commit removes is a leaver
//!    too: the others rotate, so its owner's other device, still a member
//!    with the new epoch's call root, reads nothing with what it was granted,
//!    whatever order the client opens the next signals and asks `epoch` in.
//! 3. A newcomer reads nothing sent before it joined.
//! 4. A key counts only from a leaf whose SIGNED `Joined` bound it: a grant
//!    from anyone else is held, and a live `Joined` binds nothing. A live
//!    `Left` is refused: a participant leaves only signed, stale or removed,
//!    and each of those rotates it out. A participant id binds at one leaf, and a keyed
//!    participation keeps its id, so a `Remove` by id leaves nobody keyed
//!    under it. A server that withholds or reorders a signed `Left` keeps a
//!    leaver on a tile until its heartbeat lapses, and reads nothing by it.
//! 5. A `Joined` that names no call key, or no X-Wing key, is refused, and
//!    no call falls back to a key every member derives.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use peachy_mls_core::call::{
    call_frame_key, call_media_advance, call_media_key_pair, call_media_pq_key_pair,
    call_sender_key_v2, encode_call_signal, open_call_media_grant, seal_call_media_grant,
    seal_live_frame, CallLane, CallMediaKeys, CallSignal, CallSignalBody, LiveStamp, MediaGrant,
    MediaGrantPayload, OpenedCallSignal, Participation, CALL_EXPORTER_LABEL_V2, CALL_LANE_MLS,
    CALL_LIVE_EXPORTER_LABEL, CALL_MEDIA_MAX_ADVANCE, CALL_MEDIA_ROTATE_DELAY_MS, CALL_STATE_LOST,
};
use peachy_mls_core::envelope::{seal_group_id_envelope, ENVELOPE_KIND_CALL};
use peachy_mls_core::Client;
use support::{client, issuer};

const GROUP: &[u8] = b"peachy-call-participant-keys";
const CALL_ID: [u8; 16] = *b"0123456789abcdef";

/// The rotation delay passes on every client's clock: a pending rotation is
/// due from here, and the next door that touches the call switches to it.
fn rotation_delay_passes() {
    support::advance_ms(CALL_MEDIA_ROTATE_DELAY_MS);
}

fn members(n: u8) -> Vec<Client> {
    let server = issuer();
    let names = ["ada", "bo", "cy", "di"];
    let mut out: Vec<Client> = (0..n)
        .map(|i| {
            let name = names[usize::from(i)];
            client(
                &server,
                i + 1,
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

fn open(member: &mut Client, envelope: &[u8]) -> OpenedCallSignal {
    let inner = member.open_envelope(envelope).unwrap().unwrap().inner;
    member.open_call_signal(GROUP, &inner).unwrap()
}

/// Deliver `envelopes` from one member to all the others, in order, and
/// return what each one owes in turn (the envelopes its opens asked it to
/// send), so a caller can deliver those as well.
fn deliver(all: &mut [Client], from: usize, envelopes: &[Vec<u8>]) -> Vec<(usize, Vec<Vec<u8>>)> {
    let mut owed = Vec::new();
    for envelope in envelopes {
        for (i, member) in all.iter_mut().enumerate() {
            if i == from {
                continue;
            }
            let opened = open(member, envelope);
            if !opened.send.is_empty() {
                owed.push((i, opened.send));
            }
        }
    }
    owed
}

/// Deliver until nobody owes anything.
fn settle(all: &mut [Client], from: usize, envelopes: Vec<Vec<u8>>) {
    let mut queue = vec![(from, envelopes)];
    while let Some((from, envelopes)) = queue.pop() {
        queue.extend(deliver(all, from, &envelopes));
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

/// A participation mark of a device's own making, later than every one
/// minted before it in this test binary: every signed `Joined` and
/// `MediaKey` carries one, and one without it is refused.
fn own_mark() -> Option<Participation> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1 << 40);
    let seq = NEXT.fetch_add(1, Ordering::Relaxed);
    let mut id = [0x6d; 16];
    id[8..].copy_from_slice(&seq.to_be_bytes());
    Some(Participation { id, seq })
}

/// A device running its own code seals whatever `Joined` it likes, call
/// keys of its own making included: its participation ends first, if any,
/// and the signal goes out through `seal_call_signal_as_written`.
fn own_code(member: &mut Client) {
    member.call_media_end(GROUP, &CALL_ID).unwrap();
}

/// A call key set of a device's own making: the X-Wing private key every
/// grant to it opens with, and the X25519 and X-Wing public keys its signed
/// `Joined` names.
fn own_keys(seed: u8) -> (Vec<u8>, [u8; 32], Vec<u8>) {
    let (_, public) = call_media_key_pair(&[seed; 32]).unwrap();
    let (private, public_pq) = call_media_pq_key_pair(&[seed; 32]).unwrap();
    (private, public, public_pq)
}

fn signed_joined(member: &mut Client, participant: &str, session: &str) -> Vec<u8> {
    let signal = joined(member, participant, session);
    member.seal_call_signal_on_mls_lane(GROUP, &signal).unwrap()
}

fn live_joined(member: &mut Client, participant: &str, session: &str) -> Vec<u8> {
    let signal = joined(member, participant, session);
    member.seal_call_signal(GROUP, &signal).unwrap()
}

/// Member `i` joins the call as a v2 participant: start, a signed `Joined`,
/// then grants to everyone already in it, delivered to all.
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

/// The frame a participant sends now, under its current send key.
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

fn decrypt_with(sender_key: &[u8; 16], wire: &[u8]) -> Option<Vec<u8>> {
    let frame_key = call_frame_key(sender_key).unwrap();
    let body = &wire[..wire.len() - 2];
    let (front, iv) = body.split_at(body.len() - 12);
    let (header, ciphertext) = front.split_at(1);
    let clear = Aes128Gcm::new_from_slice(&frame_key)
        .ok()?
        .decrypt(
            Nonce::from_slice(iv),
            Payload {
                msg: ciphertext,
                aad: header,
            },
        )
        .ok()?;
    let mut out = header.to_vec();
    out.extend_from_slice(&clear);
    Some(out)
}

/// Whether any key `keys` holds for `sender_leaf` opens `wire`, the way a
/// receiver's frame decryptor tries the slot the trailer names.
fn opens(keys: &CallMediaKeys, sender_leaf: u32, wire: &[u8]) -> bool {
    let slot = wire[wire.len() - 1];
    keys.senders
        .iter()
        .filter(|key| key.leaf_index == sender_leaf && key.key_index == slot)
        .any(|key| decrypt_with(&key.key, wire).is_some())
}

/// Whether ANY key in `keys` opens `wire`, whatever slot or leaf: what a
/// member who tries everything it holds gets.
fn opens_with_anything(keys: &[[u8; 16]], wire: &[u8]) -> bool {
    keys.iter().any(|key| decrypt_with(key, wire).is_some())
}

fn every_key(member: &mut Client) -> Vec<[u8; 16]> {
    let mut out: Vec<[u8; 16]> = member
        .call_keys(GROUP, &CALL_ID)
        .unwrap()
        .senders
        .iter()
        .map(|key| *key.key)
        .collect();
    if let Ok(v2) = member.call_media_keys(GROUP, &CALL_ID, false) {
        out.extend(v2.senders.iter().map(|key| *key.key));
    }
    out
}

fn opus(seed: u8) -> Vec<u8> {
    let mut out = vec![0x78u8];
    out.extend((0..80u8).map(|i| i.wrapping_mul(31) ^ seed));
    out
}

#[test]
fn a_member_who_never_joins_hears_nothing_and_sees_no_session() {
    let mut all = members(3);
    let (ada_leaf, bo_leaf) = (leaf(&all[0]), leaf(&all[1]));

    all[0]
        .call_media_start(
            GROUP,
            &CALL_ID,
            "p-ada",
            "sess-ada-SECRET",
            &["ada-audio".into()],
        )
        .unwrap();
    let ada_joined = signed_joined(&mut all[0], "p-ada", "sess-ada-SECRET");
    // Cy reads Ada's signed Joined: a call key, and no session or tracks.
    let seen_by_cy = open(&mut all[2], &ada_joined);
    match &seen_by_cy.signal.body {
        CallSignalBody::Joined {
            session_id,
            track_names,
            media_key,
            ..
        } => {
            assert!(
                session_id.is_empty(),
                "the pull capability left in a Joined"
            );
            assert!(track_names.is_empty());
            assert_eq!(media_key.len(), 32);
        }
        other => panic!("{other:?}"),
    }
    let _ = open(&mut all[1], &ada_joined);
    let share = all[0].call_media_share(GROUP, &CALL_ID).unwrap();
    settle(&mut all, 0, share);
    join(&mut all, 1, "p-bo", "sess-bo-SECRET");

    // A heartbeat on the live lane says no more.
    let beat = live_joined(&mut all[0], "p-ada", "sess-ada-SECRET");
    match open(&mut all[2], &beat).signal.body {
        CallSignalBody::Joined {
            session_id,
            track_names,
            ..
        } => {
            assert!(session_id.is_empty());
            assert!(track_names.is_empty());
        }
        other => panic!("{other:?}"),
    }

    // Bo holds Ada's session from her grant, and her key.
    let bo_keys = keys(&mut all[1]);
    let ada_seen_by_bo = bo_keys
        .participants
        .iter()
        .find(|p| p.leaf_index == ada_leaf)
        .unwrap();
    assert_eq!(ada_seen_by_bo.session_id, "sess-ada-SECRET");
    assert!(ada_seen_by_bo.keyed);

    let ada_frame = frame(&mut all[0], &opus(0x5a), 3);
    let bo_frame = frame(&mut all[1], &opus(0x33), 4);
    assert!(opens(&keys(&mut all[1]), ada_leaf, &ada_frame));
    assert!(opens(&keys(&mut all[0]), bo_leaf, &bo_frame));

    // Cy is a member in the same epoch and was never in the call: no v2 keys,
    // and nothing it can derive opens either frame.
    assert!(all[2].call_media_keys(GROUP, &CALL_ID, false).is_err());
    let cy_keys = every_key(&mut all[2]);
    assert!(!opens_with_anything(&cy_keys, &ada_frame));
    assert!(!opens_with_anything(&cy_keys, &bo_frame));
}

#[test]
fn a_participant_who_left_hears_nothing_after_the_rotation() {
    let mut all = members(3);
    let ada_leaf = leaf(&all[0]);
    join(&mut all, 0, "p-ada", "sess-ada");
    join(&mut all, 1, "p-bo", "sess-bo");
    join(&mut all, 2, "p-cy", "sess-cy");

    // While Bo is in, Ada's frames open for him.
    let before = frame(&mut all[0], &opus(1), 1);
    let bo_kept = keys(&mut all[1]);
    assert!(opens(&bo_kept, ada_leaf, &before));
    assert!(opens(&keys(&mut all[2]), ada_leaf, &before));

    // Bo leaves. His Left goes signed though it is a Left, and his core
    // forgets the call's keys; he keeps a copy of everything he held anyway.
    let bo_every_key = every_key(&mut all[1]);
    let left = all[1]
        .seal_call_signal(
            GROUP,
            &CallSignal::new(
                CALL_ID,
                CallSignalBody::Left {
                    participant_id: "p-bo".into(),
                },
            ),
        )
        .unwrap();
    assert!(all[1].call_media_keys(GROUP, &CALL_ID, false).is_err());
    let owed = deliver(&mut all, 1, &[left]);
    assert_eq!(owed.len(), 2, "Ada and Cy each rotate");
    for (from, envelopes) in owed {
        settle(&mut all, from, envelopes);
    }
    // Ada switches after the delay; Cy holds the new key before then.
    assert_eq!(CALL_MEDIA_ROTATE_DELAY_MS, 5_000);
    rotation_delay_passes();
    all[0].call_media_apply(GROUP, &CALL_ID).unwrap();
    let after = frame(&mut all[0], &opus(2), 2);
    assert!(opens(&keys(&mut all[2]), ada_leaf, &after));

    // Bo, still a member in the same epoch, holding his old keys and every
    // key the epoch gives him, opens none of it.
    assert!(!opens(&bo_kept, ada_leaf, &after));
    assert!(!opens_with_anything(&bo_every_key, &after));
    assert!(!opens_with_anything(&every_key(&mut all[1]), &after));
}

/// Ada (the only admin), Bo, Cy, and one person's two devices, a laptop and
/// a phone, in that order: the phone is last so that, once a commit removes
/// it, `all[..4]` are the members left.
fn four_people_five_devices() -> Vec<Client> {
    let server = issuer();
    let mut out = vec![
        client(&server, 1, "actor-ada", "device-ada-phone"),
        client(&server, 2, "actor-bo", "device-bo-phone"),
        client(&server, 3, "actor-cy", "device-cy-phone"),
        client(&server, 4, "actor-di", "device-di-laptop"),
        client(&server, 5, "actor-di", "device-di-phone"),
    ];
    out[0].create_group(GROUP).unwrap();
    out[0]
        .set_group_meta(GROUP, br#"{"v":1,"n":"Walk","adm":["actor-ada"]}"#)
        .unwrap();
    out[0].merge_pending_commit(GROUP).unwrap();
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

#[test]
fn a_participant_removed_by_commit_hears_nothing_after_the_rotation() {
    let mut all = four_people_five_devices();
    let (ada, bo, cy, laptop, phone) = (0usize, 1usize, 2usize, 3usize, 4usize);
    let (ada_leaf, bo_leaf, phone_leaf) = (leaf(&all[ada]), leaf(&all[bo]), leaf(&all[phone]));
    join(&mut all, ada, "p-ada", "sess-ada");
    join(&mut all, bo, "p-bo", "sess-bo");

    // Di's phone joins with a signed Joined naming a call key whose private
    // half it keeps, and keeps every secret granted to it: what a device
    // whose owner runs her own code holds.
    let (private, public, public_pq) = own_keys(0x4d);
    own_code(&mut all[phone]);
    let phone_joined = all[phone]
        .seal_call_signal_as_written(
            GROUP,
            &CallSignal::new(
                CALL_ID,
                CallSignalBody::Joined {
                    participant_id: "p-di".into(),
                    session_id: String::new(),
                    track_names: Vec::new(),
                    leaf_index: phone_leaf,
                    media_key: public.to_vec(),
                    started_at_ms: 0,
                    media_key_pq: public_pq.clone(),
                    participation: own_mark(),
                },
            ),
        )
        .unwrap();
    let owed = deliver(&mut all, phone, &[phone_joined]);
    assert_eq!(owed.len(), 2, "Ada and Bo each grant the newcomer");
    let mut taken: Vec<(u32, MediaGrantPayload)> = Vec::new();
    for (from, envelopes) in owed {
        for envelope in envelopes {
            for i in (0..all.len()).filter(|i| *i != from) {
                let opened = open(&mut all[i], &envelope);
                if i != phone {
                    continue;
                }
                if let CallSignalBody::MediaKey { grants, .. } = &opened.signal.body {
                    for grant in grants.iter().filter(|g| g.to_leaf == phone_leaf) {
                        let sender = opened.sender_leaf.unwrap();
                        let payload = open_call_media_grant(
                            &private,
                            &CALL_ID,
                            sender,
                            phone_leaf,
                            &grant.enc,
                            &grant.ciphertext,
                        )
                        .unwrap();
                        taken.push((sender, payload));
                    }
                }
            }
        }
    }
    assert_eq!(taken.len(), 2, "the phone holds Ada's and Bo's secrets");
    assert!(keys(&mut all[ada])
        .participants
        .iter()
        .any(|p| p.leaf_index == phone_leaf));

    // Her laptop, never in the call and no admin, removes her own phone
    // from the group. No Left: the commit is all the others see.
    let removal = all[laptop].remove_leaf(GROUP, phone_leaf).unwrap();
    all[laptop].merge_pending_commit(GROUP).unwrap();
    for i in [ada, bo, cy] {
        all[i].process_commit(GROUP, &removal.commit).unwrap();
    }
    all.truncate(4);

    // Both participants reload their keys first, as any signal can make them
    // do: the phone drops out of the call, and the rotation stays owed.
    for i in [ada, bo] {
        assert!(keys(&mut all[i])
            .participants
            .iter()
            .all(|p| p.leaf_index != phone_leaf));
    }
    // Ada pays it on the epoch change; Bo through `remove` (a stale
    // heartbeat), though the commit already took the leaf.
    let ada_rotation = all[ada]
        .call_media_on_epoch(GROUP, &CALL_ID)
        .unwrap()
        .expect("a commit that removes a participant rotates like a leave");
    assert!(!ada_rotation.is_empty());
    let bo_rotation = all[bo]
        .call_media_remove(GROUP, &CALL_ID, phone_leaf)
        .unwrap();
    assert!(!bo_rotation.is_empty());
    for i in [ada, bo] {
        assert!(
            all[i]
                .call_media_on_epoch(GROUP, &CALL_ID)
                .unwrap()
                .is_none(),
            "one rotation per removal"
        );
    }
    settle(&mut all, ada, ada_rotation);
    settle(&mut all, bo, bo_rotation);
    rotation_delay_passes();
    all[ada].call_media_apply(GROUP, &CALL_ID).unwrap();
    all[bo].call_media_apply(GROUP, &CALL_ID).unwrap();

    let ada_frame = frame(&mut all[ada], &opus(0x11), 1);
    let bo_frame = frame(&mut all[bo], &opus(0x22), 2);
    assert!(opens(&keys(&mut all[bo]), ada_leaf, &ada_frame));
    assert!(opens(&keys(&mut all[ada]), bo_leaf, &bo_frame));

    // The laptop, still a member, takes the new epoch's v2 call root and
    // every secret the phone was granted, advanced as far as an advance
    // can go: none of it opens what Ada and Bo send now.
    let can_read = |laptop: &Client, sender_leaf: u32, wire: &[u8]| -> bool {
        let root = laptop
            .export_secret(GROUP, CALL_EXPORTER_LABEL_V2, &CALL_ID, 32)
            .unwrap();
        taken
            .iter()
            .filter(|(sender, _)| *sender == sender_leaf)
            .any(|(_, payload)| {
                let mut secret = *payload.secret;
                (0..=CALL_MEDIA_MAX_ADVANCE).any(|_| {
                    let key = call_sender_key_v2(&root, &secret, sender_leaf).unwrap();
                    secret = call_media_advance(&secret).unwrap();
                    decrypt_with(&key, wire).is_some()
                })
            })
    };
    assert!(!can_read(&all[laptop], ada_leaf, &ada_frame));
    assert!(!can_read(&all[laptop], bo_leaf, &bo_frame));
    assert!(!opens_with_anything(
        &every_key(&mut all[laptop]),
        &ada_frame
    ));

    // Nor does a newcomer's advance afterwards hand it back.
    join(&mut all, cy, "p-cy", "sess-cy");
    let ada_later = frame(&mut all[ada], &opus(0x33), 3);
    assert!(opens(&keys(&mut all[cy]), ada_leaf, &ada_later));
    assert!(!can_read(&all[laptop], ada_leaf, &ada_later));
}

/// When Bo's client asks `epoch` relative to the envelopes it opens.
#[derive(Clone, Copy, Debug, PartialEq)]
enum EpochHook {
    /// Right after each commit, before the next envelope opens.
    Eager,
    /// Once, after the whole mailbox page: both commits and the signed
    /// `Joined` of the device that now sits at the removed leaf.
    Drained,
    /// After the drain, with `keys` reloaded after that signed `Joined` first,
    /// as the apps reload after every signed `Joined`.
    KeysThenDrained,
}

/// Di's phone is a v2 participant that keeps every secret granted to it. Her
/// laptop removes it, and Ada adds Eve, whom RFC 9420 seats at the phone's
/// leaf; Eve joins the call. Bo's client asks `epoch` per `hook`. Returns
/// whether Bo rotated, and whether the removed phone, with the v2 call root
/// from its owner's laptop (still a member), reads Bo's frame afterwards.
fn reseated_leaf(hook: EpochHook) -> (bool, bool) {
    let server = issuer();
    let mut all = four_people_five_devices();
    let (ada, bo, cy, laptop, phone) = (0usize, 1usize, 2usize, 3usize, 4usize);
    let (bo_leaf, phone_leaf) = (leaf(&all[bo]), leaf(&all[phone]));
    join(&mut all, ada, "p-ada", "sess-ada");
    join(&mut all, bo, "p-bo", "sess-bo");

    let (private, public, public_pq) = own_keys(0x4d);
    own_code(&mut all[phone]);
    let phone_joined = all[phone]
        .seal_call_signal_as_written(
            GROUP,
            &CallSignal::new(
                CALL_ID,
                CallSignalBody::Joined {
                    participant_id: "p-di".into(),
                    session_id: String::new(),
                    track_names: Vec::new(),
                    leaf_index: phone_leaf,
                    media_key: public.to_vec(),
                    started_at_ms: 0,
                    media_key_pq: public_pq.clone(),
                    participation: own_mark(),
                },
            ),
        )
        .unwrap();
    let owed = deliver(&mut all, phone, &[phone_joined]);
    let mut taken: Vec<(u32, MediaGrantPayload)> = Vec::new();
    for (from, envelopes) in owed {
        for envelope in envelopes {
            for i in (0..all.len()).filter(|i| *i != from) {
                let opened = open(&mut all[i], &envelope);
                if i != phone {
                    continue;
                }
                if let CallSignalBody::MediaKey { grants, .. } = &opened.signal.body {
                    for grant in grants.iter().filter(|g| g.to_leaf == phone_leaf) {
                        let sender = opened.sender_leaf.unwrap();
                        taken.push((
                            sender,
                            open_call_media_grant(
                                &private,
                                &CALL_ID,
                                sender,
                                phone_leaf,
                                &grant.enc,
                                &grant.ciphertext,
                            )
                            .unwrap(),
                        ));
                    }
                }
            }
        }
    }
    assert!(
        taken.iter().any(|(sender, _)| *sender == bo_leaf),
        "the phone holds Bo's secret"
    );

    let mut bo_rotated = false;
    let mut bo_epoch = |all: &mut Vec<Client>| {
        if let Some(rotation) = all[bo].call_media_on_epoch(GROUP, &CALL_ID).unwrap() {
            assert!(!rotation.is_empty());
            settle(all, bo, rotation);
            rotation_delay_passes();
            all[bo].call_media_apply(GROUP, &CALL_ID).unwrap();
            bo_rotated = true;
        }
    };

    // Commit 1: the laptop removes the phone. Nobody else opens anything at
    // this epoch, so no other door reads the roster on Bo's behalf.
    let removal = all[laptop].remove_leaf(GROUP, phone_leaf).unwrap();
    all[laptop].merge_pending_commit(GROUP).unwrap();
    for i in [ada, bo, cy] {
        all[i].process_commit(GROUP, &removal.commit).unwrap();
    }
    all.truncate(4);
    if hook == EpochHook::Eager {
        bo_epoch(&mut all);
    }
    // Commit 2: Ada adds Eve, seated at the phone's leaf.
    let mut eve = client(&server, 6, "actor-eve", "device-eve-phone");
    let kp = eve.generate_key_package().unwrap();
    let added = all[ada].add_member(GROUP, &kp).unwrap();
    all[ada].merge_pending_commit(GROUP).unwrap();
    for i in [bo, cy, laptop] {
        all[i].process_commit(GROUP, &added.commit).unwrap();
    }
    if hook == EpochHook::Eager {
        bo_epoch(&mut all);
    }
    eve.join_from_welcome(&added.welcome.clone().unwrap())
        .unwrap();
    all.push(eve);
    let eve = 4usize;
    assert_eq!(
        leaf(&all[eve]),
        phone_leaf,
        "Eve sits at the phone's old leaf"
    );

    // Eve joins the call: Bo opens her signed Joined before his epoch hook.
    all[eve]
        .call_media_start(
            GROUP,
            &CALL_ID,
            "p-eve",
            "sess-eve",
            &["sess-eve-audio".into()],
        )
        .unwrap();
    let eve_joined = signed_joined(&mut all[eve], "p-eve", "sess-eve");
    settle(&mut all, eve, vec![eve_joined]);
    if hook == EpochHook::KeysThenDrained {
        let _ = keys(&mut all[bo]);
    }
    let eve_share = all[eve].call_media_share(GROUP, &CALL_ID).unwrap();
    settle(&mut all, eve, eve_share);
    if hook != EpochHook::Eager {
        bo_epoch(&mut all);
    }
    assert!(
        all[bo]
            .call_media_on_epoch(GROUP, &CALL_ID)
            .unwrap()
            .is_none(),
        "one rotation per removal"
    );
    // Bo's first Joined in this epoch goes signed, which binds him for Eve,
    // who was not a member when he joined; his grants held for her count.
    let bo_joined = signed_joined(&mut all[bo], "p-bo", "sess-bo");
    settle(&mut all, bo, vec![bo_joined]);

    let bo_frame = frame(&mut all[bo], &opus(0x22), 2);
    assert!(
        opens(&keys(&mut all[eve]), bo_leaf, &bo_frame),
        "Eve, in the call, reads Bo"
    );
    let root = all[laptop]
        .export_secret(GROUP, CALL_EXPORTER_LABEL_V2, &CALL_ID, 32)
        .unwrap();
    let removed_reads =
        taken
            .iter()
            .filter(|(sender, _)| *sender == bo_leaf)
            .any(|(_, payload)| {
                let mut secret = *payload.secret;
                (0..=CALL_MEDIA_MAX_ADVANCE).any(|_| {
                    let key = call_sender_key_v2(&root, &secret, bo_leaf).unwrap();
                    secret = call_media_advance(&secret).unwrap();
                    decrypt_with(&key, &bo_frame).is_some()
                })
            });
    (bo_rotated, removed_reads)
}

#[test]
fn an_epoch_hook_after_each_commit_rotates_out_a_removed_participant() {
    let (rotated, removed_reads) = reseated_leaf(EpochHook::Eager);
    assert!(rotated, "the removal costs Bo a rotation");
    assert!(!removed_reads, "the removed phone reads Bo after it");
}

/// The signed `Joined` of the device now at the removed participant's leaf
/// opens before Bo's epoch hook runs: that door reads the roster too, so the
/// newcomer's advance does not stand in for the rotation the removal owes.
#[test]
fn a_reseated_leaf_joined_before_the_epoch_hook_still_costs_the_rotation() {
    let (rotated, removed_reads) = reseated_leaf(EpochHook::Drained);
    assert!(rotated, "the removal still costs Bo a rotation");
    assert!(!removed_reads, "the removed phone reads Bo after it");
}

#[test]
fn keys_reloaded_after_a_reseated_leaf_joined_leave_the_rotation_owed() {
    let (rotated, removed_reads) = reseated_leaf(EpochHook::KeysThenDrained);
    assert!(rotated, "the removal still costs Bo a rotation");
    assert!(!removed_reads, "the removed phone reads Bo after it");
}

/// A live `Left` sealed under the epoch's live key by `from`'s own code,
/// claiming `claimed_leaf`: what any member can write, its core bypassed.
fn crafted_live_left(from: &Client, claimed_leaf: u32, participant: &str, at_ms: u64) -> Vec<u8> {
    let live_key = from
        .export_secret(GROUP, CALL_LIVE_EXPORTER_LABEL, &[], 32)
        .unwrap();
    let left = CallSignal::new(
        CALL_ID,
        CallSignalBody::Left {
            participant_id: participant.into(),
        },
    );
    let inner = seal_live_frame(
        &live_key,
        LiveStamp {
            sender_leaf: claimed_leaf,
            sent_at_ms: (support::NOW as u64) * 1000 + at_ms,
        },
        &encode_call_signal(&left).unwrap(),
    )
    .unwrap();
    seal_group_id_envelope(GROUP, ENVELOPE_KIND_CALL, &inner).unwrap()
}

fn try_open(member: &mut Client, envelope: &[u8]) -> Option<OpenedCallSignal> {
    let inner = member.open_envelope(envelope).unwrap().unwrap().inner;
    member.open_call_signal(GROUP, &inner).ok()
}

/// A v2 participant's own `Left` always goes signed, so a live one for a leaf
/// bound as a v2 participant is refused, whoever wrote it: the participant
/// cannot vanish from everyone's tiles while every core still grants it each
/// rotation, and nobody can drop another v2 participant's tile with one. It
/// leaves only through a signed `Left`, a stale heartbeat or a `Remove`, and
/// each of those rotates it out.
#[test]
fn a_live_left_cannot_hide_a_v2_participant() {
    let mut all = members(4);
    let (ada, bo, mallory, di) = (0usize, 1usize, 2usize, 3usize);
    let (ada_leaf, bo_leaf, mallory_leaf, di_leaf) = (
        leaf(&all[ada]),
        leaf(&all[bo]),
        leaf(&all[mallory]),
        leaf(&all[di]),
    );
    join(&mut all, ada, "p-ada", "sess-ada");
    join(&mut all, bo, "p-bo", "sess-bo");
    join(&mut all, mallory, "p-cy", "sess-cy");

    // Her own leaf, and Bo's: refused at every member, Di (not in the call)
    // included.
    let own = crafted_live_left(&all[mallory], mallory_leaf, "p-cy", 7);
    let bo_forged = crafted_live_left(&all[mallory], bo_leaf, "p-bo", 8);
    for i in [ada, bo, di] {
        assert!(
            try_open(&mut all[i], &own).is_none(),
            "member {i} took her live Left"
        );
    }
    for i in [ada, di] {
        assert!(
            try_open(&mut all[i], &bo_forged).is_none(),
            "member {i} took a forged Left for Bo"
        );
    }
    // The refusal is not recorded in the replay window: her heartbeat still
    // opens. A live Left naming an id bound nowhere (Di's, never in the
    // call) is refused too: only a participant bound with no call key leaves
    // live, and an unbound id has no tile to drop.
    let beat = live_joined(&mut all[mallory], "p-cy", "sess-cy");
    assert!(try_open(&mut all[ada], &beat).is_some());
    let di_left = crafted_live_left(&all[di], di_leaf, "p-di", 9);
    assert!(
        try_open(&mut all[ada], &di_left).is_none(),
        "a live Left for an unbound id is refused"
    );

    // No Left naming her opened anywhere, so no client dropped her tile (a
    // client acts on the id an opened Left names), and Ada's core still lists
    // her; when her heartbeat goes stale, `remove` rotates her out.
    assert!(keys(&mut all[ada])
        .participants
        .iter()
        .any(|p| p.leaf_index == mallory_leaf && p.keyed));
    let rotation = all[ada]
        .call_media_remove(GROUP, &CALL_ID, mallory_leaf)
        .unwrap();
    assert!(!rotation.is_empty());
    settle(&mut all, ada, rotation);
    rotation_delay_passes();
    all[ada].call_media_apply(GROUP, &CALL_ID).unwrap();
    let ada_after = frame(&mut all[ada], &opus(0x66), 4);
    assert!(opens(&keys(&mut all[bo]), ada_leaf, &ada_after));
    assert!(!keys(&mut all[ada])
        .participants
        .iter()
        .any(|p| p.leaf_index == mallory_leaf));
    assert!(!opens_with_anything(
        &every_key(&mut all[mallory]),
        &ada_after
    ));

    // Once removed she is bound nowhere at Ada, so a live Left naming her is
    // still refused: Ada has no tile of hers left to drop.
    let after = crafted_live_left(&all[mallory], mallory_leaf, "p-cy", 10);
    assert!(try_open(&mut all[ada], &after).is_none());
}

fn left_names(opened: &OpenedCallSignal) -> Option<&str> {
    match &opened.signal.body {
        CallSignalBody::Left { participant_id } => Some(participant_id),
        _ => None,
    }
}

fn lists_keyed(member: &mut Client, leaf_index: u32, participant: &str) -> bool {
    keys(member)
        .participants
        .iter()
        .any(|p| p.leaf_index == leaf_index && p.participant_id == participant && p.keyed)
}

/// A live `Left` naming a v2 participant's id is refused whatever leaf it
/// claims: a member that is not in the call, the receiver itself, or anyone
/// else. (Every live frame must carry its claimed leaf's signature, and a
/// live `Left` is refused even with one.)
#[test]
fn a_live_left_naming_a_v2_participant_is_refused_whatever_leaf_it_claims() {
    let mut all = members(4);
    let (ada, bo, mallory, di) = (0usize, 1usize, 2usize, 3usize);
    let leaves: Vec<u32> = all.iter().map(leaf).collect();
    join(&mut all, ada, "p-ada", "sess-ada");
    join(&mut all, bo, "p-bo", "sess-bo");
    join(&mut all, mallory, "p-cy", "sess-cy");

    // Her own id, claiming Di's leaf (never in the call), Ada's or Bo's: no
    // member takes it, Di included.
    let mut at = 20;
    for claimed in [leaves[di], leaves[ada], leaves[bo]] {
        at += 1;
        let hide = crafted_live_left(&all[mallory], claimed, "p-cy", at);
        for i in [ada, bo, di] {
            assert!(
                try_open(&mut all[i], &hide).is_none(),
                "member {i} took a live Left for p-cy claiming leaf {claimed}"
            );
        }
    }
    // Bo's id, claiming Di's leaf or the receiver's own: refused too.
    for claimed in [leaves[di], leaves[ada]] {
        at += 1;
        let forged = crafted_live_left(&all[mallory], claimed, "p-bo", at);
        for i in [ada, di] {
            assert!(
                try_open(&mut all[i], &forged).is_none(),
                "member {i} took a live Left for p-bo claiming leaf {claimed}"
            );
        }
    }

    // Nothing was recorded: her heartbeat still opens, every participant's
    // core still lists her keyed, and a live Left naming an id bound nowhere
    // is refused as well: no participant leaves live.
    let beat = live_joined(&mut all[mallory], "p-cy", "sess-cy");
    assert!(try_open(&mut all[ada], &beat).is_some());
    for i in [ada, bo] {
        assert!(lists_keyed(&mut all[i], leaves[mallory], "p-cy"));
    }
    let di_left = crafted_live_left(&all[di], leaves[di], "p-di", at + 1);
    assert!(
        try_open(&mut all[ada], &di_left).is_none(),
        "a Left for an unbound id is refused"
    );
}

/// With every member in the call no leaf is unbound, but each receiver's own
/// leaf is in no peer list of its own. One live `Left` per receiver, each
/// claiming that receiver's leaf and naming a v2 participant (or the
/// receiver itself), is refused by everyone.
#[test]
fn with_everyone_in_the_call_a_live_left_claiming_the_receivers_leaf_is_refused() {
    let mut all = members(4);
    let (ada, bo, mallory, di) = (0usize, 1usize, 2usize, 3usize);
    let leaves: Vec<u32> = all.iter().map(leaf).collect();
    join(&mut all, ada, "p-ada", "sess-ada");
    join(&mut all, bo, "p-bo", "sess-bo");
    join(&mut all, mallory, "p-cy", "sess-cy");
    join(&mut all, di, "p-di", "sess-di");

    let receivers = [(ada, "p-ada"), (bo, "p-bo"), (di, "p-di")];
    let mut at = 30;
    for (target, own_id) in receivers {
        for named in ["p-cy", own_id] {
            at += 1;
            let frame = crafted_live_left(&all[mallory], leaves[target], named, at);
            for (i, _) in receivers {
                assert!(
                    try_open(&mut all[i], &frame).is_none(),
                    "member {i} took a live Left for {named} claiming leaf {}",
                    leaves[target]
                );
            }
        }
    }

    for (i, _) in receivers {
        assert!(lists_keyed(&mut all[i], leaves[mallory], "p-cy"));
    }
    let beat = live_joined(&mut all[mallory], "p-cy", "sess-cy");
    assert!(try_open(&mut all[ada], &beat).is_some());
}

/// Mallory's honest door: her core seals her `Left` signed, the others take
/// it and rotate, whatever the client asked for.
#[test]
fn a_v2_participants_own_left_goes_signed_and_rotates() {
    let mut all = members(3);
    let (ada, bo, cy) = (0usize, 1usize, 2usize);
    join(&mut all, ada, "p-ada", "sess-ada");
    join(&mut all, bo, "p-bo", "sess-bo");
    join(&mut all, cy, "p-cy", "sess-cy");
    let left = all[cy]
        .seal_call_signal(
            GROUP,
            &CallSignal::new(
                CALL_ID,
                CallSignalBody::Left {
                    participant_id: "p-cy".into(),
                },
            ),
        )
        .unwrap();
    let opened = open(&mut all[ada], &left);
    assert_eq!(opened.lane, CallLane::Mls);
    assert!(!opened.send.is_empty(), "a signed Left rotates");
    assert_eq!(
        opened.unbound_leaf,
        Some(leaf(&all[cy])),
        "and reports the leaf it unbound, the one a client drops the tile at"
    );
    let json: serde_json::Value = serde_json::from_str(&opened.to_json().unwrap()).unwrap();
    assert_eq!(json["unboundLeaf"], serde_json::json!(leaf(&all[cy])));
}

/// A signed `Left` naming `participant`, sealed by `from`'s own core (which
/// ends `from`'s own keys if it names `from`'s current participation).
fn signed_left(from: &mut Client, participant: &str) -> Vec<u8> {
    from.seal_call_signal_on_mls_lane(
        GROUP,
        &CallSignal::new(
            CALL_ID,
            CallSignalBody::Left {
                participant_id: participant.into(),
            },
        ),
    )
    .unwrap()
}

/// A signed `Left` speaks only for its sender's own participant. Di has two
/// devices: the phone joins as `p-di`, the laptop never joins. The laptop's
/// signed `Left` naming `p-di` (its leaf unbound, the id another leaf's) is
/// refused at every member, so no client can drop the phone's tile while
/// every core still grants it each rotation; and the phone keeps its tile
/// and its keys honestly, rotated out only by its own `Left`.
#[test]
fn a_signed_left_from_a_second_device_cannot_hide_the_first() {
    let mut all = four_people_five_devices();
    let (ada, bo, cy, laptop, phone) = (0usize, 1usize, 2usize, 3usize, 4usize);
    let leaves: Vec<u32> = all.iter().map(leaf).collect();
    join(&mut all, ada, "p-ada", "sess-ada");
    join(&mut all, bo, "p-bo", "sess-bo");
    join(&mut all, phone, "p-di", "sess-di");

    let forged = signed_left(&mut all[laptop], "p-di");
    for i in [ada, bo, cy] {
        assert!(
            try_open(&mut all[i], &forged).is_none(),
            "member {i} took the laptop's signed Left for the phone"
        );
    }
    for i in [ada, bo] {
        assert!(lists_keyed(&mut all[i], leaves[phone], "p-di"));
    }

    // The phone's own Left unlists and rotates it out in one event.
    let own = signed_left(&mut all[phone], "p-di");
    for i in [ada, bo] {
        let opened = try_open(&mut all[i], &own).expect("the phone's own Left opens");
        assert_eq!(opened.unbound_leaf, Some(leaves[phone]));
        assert!(!opened.send.is_empty(), "member {i} rotated past the phone");
        assert!(!keys(&mut all[i])
            .participants
            .iter()
            .any(|p| p.leaf_index == leaves[phone]));
    }
}

/// A participant in the call that signs a `Left` naming another participant
/// is refused: the core would otherwise rotate out the SIGNER (it unbinds by
/// leaf) while a client dropped the tile of the participant the `Left`
/// names. Nobody rotates, both stay bound and keyed.
#[test]
fn a_participant_cannot_sign_a_left_for_another() {
    let mut all = members(4);
    let (ada, bo, cy, di) = (0usize, 1usize, 2usize, 3usize);
    let leaves: Vec<u32> = all.iter().map(leaf).collect();
    join(&mut all, ada, "p-ada", "sess-ada");
    join(&mut all, bo, "p-bo", "sess-bo");
    join(&mut all, cy, "p-cy", "sess-cy");

    // Cy's core keeps Cy's keys (the Left is not for Cy's own participation);
    // the others refuse it.
    let forged = signed_left(&mut all[cy], "p-ada");
    for i in [bo, di] {
        assert!(
            try_open(&mut all[i], &forged).is_none(),
            "member {i} took Cy's signed Left for Ada"
        );
    }
    // At Ada it names Ada's own participant: refused there too.
    assert!(try_open(&mut all[ada], &forged).is_none());
    for i in [ada, bo] {
        assert!(lists_keyed(&mut all[i], leaves[cy], "p-cy"));
    }
    assert!(lists_keyed(&mut all[bo], leaves[ada], "p-ada"));
}

/// A member that is not in the call, with no accomplice, signs a `Left`
/// naming an honest participant, or the receiver itself: refused at every
/// member, so the participant's tile and keys stay together. A `Left` naming
/// an id nobody holds still opens, and unbinds nothing.
#[test]
fn a_member_outside_the_call_cannot_sign_a_left_for_a_participant() {
    let mut all = members(4);
    let (ada, bo, cy, di) = (0usize, 1usize, 2usize, 3usize);
    let leaves: Vec<u32> = all.iter().map(leaf).collect();
    join(&mut all, ada, "p-ada", "sess-ada");
    join(&mut all, cy, "p-cy", "sess-cy");
    join(&mut all, di, "p-di", "sess-di");

    for named in ["p-di", "p-ada", "p-cy"] {
        let forged = signed_left(&mut all[bo], named);
        for i in [ada, cy, di] {
            assert!(
                try_open(&mut all[i], &forged).is_none(),
                "member {i} took Bo's signed Left for {named}"
            );
        }
    }
    for i in [ada, cy] {
        assert!(lists_keyed(&mut all[i], leaves[di], "p-di"));
    }

    // An id no leaf holds: it opens, and nothing is unbound or rotated.
    let nobody = signed_left(&mut all[bo], "p-nobody");
    let opened = try_open(&mut all[ada], &nobody).expect("a Left for an unheld id opens");
    assert_eq!(left_names(&opened), Some("p-nobody"));
    assert_eq!(opened.unbound_leaf, None);
    assert!(opened.send.is_empty());
}

/// A rejoin sends its old participant's `Left` before its new `Joined`: the
/// old one is unbound and rotated out, and the new one binds. A `Left` for
/// the old id AFTER the new `Joined` (the leaf now bound under the new id) is
/// refused, so it can neither unlist nor un-key the device's new participant.
#[test]
fn a_rejoins_old_left_counts_only_before_its_new_joined() {
    let mut all = members(3);
    let (ada, bo, cy) = (0usize, 1usize, 2usize);
    let cy_leaf = leaf(&all[cy]);
    join(&mut all, ada, "p-ada", "sess-ada");
    join(&mut all, bo, "p-bo", "sess-bo");
    join(&mut all, cy, "p-cy-1", "sess-cy-1");

    // In order: the old Left, then the new session.
    let old = signed_left(&mut all[cy], "p-cy-1");
    for i in [ada, bo] {
        let opened = try_open(&mut all[i], &old).expect("the old Left opens");
        assert_eq!(opened.unbound_leaf, Some(cy_leaf));
        settle(&mut all, i, opened.send);
    }
    join(&mut all, cy, "p-cy-2", "sess-cy-2");
    for i in [ada, bo] {
        assert!(lists_keyed(&mut all[i], cy_leaf, "p-cy-2"));
    }

    // A Left for the old id now, from the same leaf: refused, and the new
    // participant stays bound and keyed. Cy's own core keeps the new
    // session's keys too: the id is a former one of Cy's.
    let late = signed_left(&mut all[cy], "p-cy-1");
    for i in [ada, bo] {
        assert!(
            try_open(&mut all[i], &late).is_none(),
            "member {i} took a late Left for Cy's old participant"
        );
        assert!(lists_keyed(&mut all[i], cy_leaf, "p-cy-2"));
    }
    assert!(all[cy].call_media_keys(GROUP, &CALL_ID, false).is_ok());
}

/// An admin removes Cy's participant; every member that honors the `Remove`
/// tells its core by participant id (Ada through the door, Bo through the
/// JSON door) and rotates past Cy. Cy's device, still a member, ignores the
/// `Remove` and signs a `Joined` under the removed id again: refused at every
/// member, so no core binds or grants it while no client shows its tile, and
/// nothing Ada sends after the rotation opens with anything Cy holds. Coming
/// back is a new join, under the new participant id the server gives every
/// join, and that one binds as usual.
#[test]
fn a_removed_participant_cannot_come_back_under_its_old_id() {
    let mut all = members(3);
    let (ada, bo, cy) = (0usize, 1usize, 2usize);
    let leaves: Vec<u32> = all.iter().map(leaf).collect();
    join(&mut all, ada, "p-ada", "sess-ada");
    join(&mut all, bo, "p-bo", "sess-bo");
    join(&mut all, cy, "p-cy", "sess-cy");
    let cy_kept = every_key(&mut all[cy]);

    let ada_rotated = all[ada]
        .call_media_remove_participant(GROUP, &CALL_ID, "p-cy")
        .unwrap();
    assert!(!ada_rotated.is_empty(), "Ada rotated past Cy");
    settle(&mut all, ada, ada_rotated);
    let call = "30313233343536373839616263646566";
    let bo_rotated = all[bo]
        .call_media_json(
            GROUP,
            &format!(r#"{{"op":"remove","callId":"{call}","participantId":"p-cy"}}"#),
        )
        .unwrap();
    let bo_rotated: serde_json::Value = serde_json::from_str(&bo_rotated).unwrap();
    assert!(!bo_rotated["send"].as_array().unwrap().is_empty());
    assert!(!bo_rotated["applyAfterMs"].is_null());
    for i in [ada, bo] {
        assert!(!keys(&mut all[i])
            .participants
            .iter()
            .any(|p| p.leaf_index == leaves[cy]));
    }

    // Cy's core is still in the call; it signs a Joined under the old id.
    all[cy]
        .call_media_start(
            GROUP,
            &CALL_ID,
            "p-cy",
            "sess-cy-again",
            &["sess-cy-again-audio".into()],
        )
        .unwrap();
    let back = signed_joined(&mut all[cy], "p-cy", "sess-cy-again");
    for i in [ada, bo] {
        assert!(
            try_open(&mut all[i], &back).is_none(),
            "member {i} bound the removed participant again"
        );
        assert!(!keys(&mut all[i])
            .participants
            .iter()
            .any(|p| p.leaf_index == leaves[cy]));
    }
    rotation_delay_passes();
    all[ada].call_media_apply(GROUP, &CALL_ID).unwrap();
    let after = frame(&mut all[ada], &opus(7), 7);
    assert!(opens(&keys(&mut all[bo]), leaves[ada], &after));
    assert!(!opens_with_anything(&cy_kept, &after));
    assert!(!opens_with_anything(&every_key(&mut all[cy]), &after));

    // A new join, under a new id, binds as usual.
    join(&mut all, cy, "p-cy-2", "sess-cy-2");
    for i in [ada, bo] {
        assert!(lists_keyed(&mut all[i], leaves[cy], "p-cy-2"));
    }
}

/// A participant id binds at one leaf in a call, the first to claim it. Di's
/// laptop joins as `p-di`; Di's phone signs a `Joined` copying that id, so a
/// client keying tiles by id would show one tile for both. Every member
/// refuses it, so when Ada, the admin, removes `p-di`, every member that
/// honors the `Remove` unbinds Di entirely: no core lists `p-di`, and the
/// phone reads nothing Ada or Bo sends after the rotation.
#[test]
fn a_second_device_cannot_join_under_a_bound_id_and_outlive_its_removal() {
    let mut all = four_people_five_devices();
    let (ada, bo, cy, laptop, phone) = (0usize, 1usize, 2usize, 3usize, 4usize);
    let leaves: Vec<u32> = all.iter().map(leaf).collect();
    join(&mut all, ada, "p-ada", "sess-ada");
    join(&mut all, bo, "p-bo", "sess-bo");
    join(&mut all, cy, "p-cy", "sess-cy");
    join(&mut all, laptop, "p-di", "sess-di-laptop");

    all[phone]
        .call_media_start(
            GROUP,
            &CALL_ID,
            "p-di",
            "sess-di-phone",
            &["sess-di-phone-audio".into()],
        )
        .unwrap();
    let copied = signed_joined(&mut all[phone], "p-di", "sess-di-phone");
    for i in [ada, bo, cy, laptop] {
        assert!(
            try_open(&mut all[i], &copied).is_none(),
            "member {i} bound the phone under the laptop's id"
        );
    }
    let grants = all[phone].call_media_share(GROUP, &CALL_ID).unwrap();
    for envelope in &grants {
        for i in [ada, bo, cy, laptop] {
            let _ = try_open(&mut all[i], envelope);
        }
    }

    for i in [ada, bo, cy] {
        let rotation = all[i]
            .call_media_remove_participant(GROUP, &CALL_ID, "p-di")
            .unwrap();
        assert!(!rotation.is_empty(), "member {i} rotated past p-di");
        for envelope in &rotation {
            for j in [ada, bo, cy, laptop, phone] {
                if j != i {
                    let _ = try_open(&mut all[j], envelope);
                }
            }
        }
    }
    rotation_delay_passes();
    for i in [ada, bo, cy] {
        all[i].call_media_apply(GROUP, &CALL_ID).unwrap();
        let listed = keys(&mut all[i]).participants;
        assert!(
            !listed.iter().any(|p| p.participant_id == "p-di"
                || p.leaf_index == leaves[laptop]
                || p.leaf_index == leaves[phone]),
            "member {i} still lists one of Di's devices"
        );
    }

    let ada_after = frame(&mut all[ada], &opus(0x41), 1);
    let bo_after = frame(&mut all[bo], &opus(0x42), 2);
    assert!(opens(&keys(&mut all[cy]), leaves[ada], &ada_after));
    assert!(opens(&keys(&mut all[cy]), leaves[bo], &bo_after));
    for device in [laptop, phone] {
        let held = every_key(&mut all[device]);
        assert!(!opens_with_anything(&held, &ada_after));
        assert!(!opens_with_anything(&held, &bo_after));
    }
}

/// A signed `Joined` naming the receiver's own participant id is refused, as
/// is a bound participant renaming itself to an id another leaf holds: a
/// client treats its own id as itself and keys tiles by id, so either would
/// put a keyed participant behind someone else's tile.
#[test]
fn a_joined_cannot_name_the_receivers_id_or_rename_to_a_bound_one() {
    let mut all = members(3);
    let (ada, bo, cy) = (0usize, 1usize, 2usize);
    let leaves: Vec<u32> = all.iter().map(leaf).collect();
    join(&mut all, ada, "p-ada", "sess-ada");
    join(&mut all, bo, "p-bo", "sess-bo");

    // Cy joins under Bo's id: refused at Bo (his own) and at Ada (bound).
    all[cy]
        .call_media_start(
            GROUP,
            &CALL_ID,
            "p-bo",
            "sess-cy",
            &["sess-cy-audio".into()],
        )
        .unwrap();
    let copied = signed_joined(&mut all[cy], "p-bo", "sess-cy");
    for i in [ada, bo] {
        assert!(
            try_open(&mut all[i], &copied).is_none(),
            "member {i} bound Cy under p-bo"
        );
    }

    // Re-sending under his own id refreshes him.
    let same = signed_joined(&mut all[bo], "p-bo", "sess-bo");
    assert!(try_open(&mut all[ada], &same).is_some());
    assert!(lists_keyed(&mut all[ada], leaves[bo], "p-bo"));

    // Bo's own core will not seal a Joined under another id than the one his
    // `start` named.
    let rename = joined(&all[bo], "p-ada", "sess-bo");
    assert!(all[bo]
        .seal_call_signal_on_mls_lane(GROUP, &rename)
        .is_err());
    // Running his own code, bound as p-bo, he sends one under Ada's id with
    // a call key: refused at Ada (her own) and at Cy, who saw both bind.
    let (_, public, public_pq) = own_keys(0x6b);
    own_code(&mut all[bo]);
    let renamed = all[bo]
        .seal_call_signal_as_written(
            GROUP,
            &CallSignal::new(
                CALL_ID,
                CallSignalBody::Joined {
                    participant_id: "p-ada".into(),
                    session_id: String::new(),
                    track_names: Vec::new(),
                    leaf_index: leaves[bo],
                    media_key: public.to_vec(),
                    started_at_ms: 0,
                    media_key_pq: public_pq.clone(),
                    participation: own_mark(),
                },
            ),
        )
        .unwrap();
    for i in [ada, cy] {
        assert!(
            try_open(&mut all[i], &renamed).is_none(),
            "member {i} let Bo rename himself to p-ada"
        );
    }
    assert!(lists_keyed(&mut all[ada], leaves[bo], "p-bo"));
}

/// Deliver `envelopes` from `from` to exactly `to`, in order, then whatever
/// those opens owe, to everyone but its sender, until nothing is owed.
fn deliver_to(all: &mut [Client], from: usize, to: &[usize], envelopes: Vec<Vec<u8>>) {
    let mut queue: Vec<(usize, Vec<usize>, Vec<Vec<u8>>)> = vec![(from, to.to_vec(), envelopes)];
    while let Some((from, to, envelopes)) = queue.pop() {
        for envelope in &envelopes {
            for &i in &to {
                if i == from {
                    continue;
                }
                if let Some(opened) = try_open(&mut all[i], envelope) {
                    if !opened.send.is_empty() {
                        let everyone: Vec<usize> = (0..all.len()).collect();
                        queue.push((i, everyone, opened.send));
                    }
                }
            }
        }
    }
}

/// A signed `Joined` under `participant` that names `media_key` and
/// `media_key_pq` and no session: what a member that never started the call
/// sends with call keys of its own, through its own code.
fn squat_joined(
    squatter: &mut Client,
    participant: &str,
    media_key: &[u8],
    media_key_pq: &[u8],
) -> Vec<u8> {
    let signal = CallSignal::new(
        CALL_ID,
        CallSignalBody::Joined {
            participant_id: participant.into(),
            session_id: String::new(),
            track_names: Vec::new(),
            leaf_index: leaf(squatter),
            media_key: media_key.to_vec(),
            started_at_ms: 0,
            media_key_pq: media_key_pq.to_vec(),
            participation: own_mark(),
        },
    );
    squatter
        .seal_call_signal_as_written(GROUP, &signal)
        .unwrap()
}

/// Every secret in `envelope` (a `MediaKey`) that opens for `thief`'s leaf
/// under `private_key`, a call key pair the thief made itself.
fn grants_to(thief: &mut Client, private_key: &[u8], envelope: &[u8]) -> Vec<[u8; 32]> {
    let Some(opened) = try_open(thief, envelope) else {
        return Vec::new();
    };
    let (Some(sender_leaf), CallSignalBody::MediaKey { grants, .. }) =
        (opened.sender_leaf, &opened.signal.body)
    else {
        return Vec::new();
    };
    let own = leaf(thief);
    grants
        .iter()
        .filter(|grant| grant.to_leaf == own)
        .filter_map(|grant| {
            open_call_media_grant(
                private_key,
                &CALL_ID,
                sender_leaf,
                own,
                &grant.enc,
                &grant.ciphertext,
            )
            .ok()
            .map(|payload| *payload.secret)
        })
        .collect()
}

/// Whether `grants` addresses any grant to `to_leaf`, as `reader` opens it.
fn addresses(reader: &mut Client, envelope: &[u8], to_leaf: u32) -> bool {
    let opened = open(reader, envelope);
    match &opened.signal.body {
        CallSignalBody::MediaKey { grants, .. } => grants.iter().any(|g| g.to_leaf == to_leaf),
        _ => false,
    }
}

/// When the squat opens, relative to Bo's own join.
#[derive(Clone, Copy, Debug)]
enum SquatOpens {
    /// While Bo is a member outside the call.
    BeforeStart,
    /// After Bo's `call_media_start`, before his `Joined`: Bo holds `p-bo`
    /// from `start` on, so the squat is refused outright.
    BeforeJoined,
}

/// No peer is ever bound, listed or granted under this device's own
/// participant id, whatever order the signals open in. The server hands Bo
/// his id and orders his mailbox, so a member (Cy) can get a signed `Joined`
/// under Bo's id opened at Bo, and only at Bo, before Bo takes the id.
/// Taking it (Bo's `start` names it) unbinds Cy there, and a squat opened
/// after is refused: Bo's share grants Cy nothing, Bo's core lists nobody
/// under his own id, Cy's later `Left` under it moves nothing, and no
/// rotation reaches Cy. Cy derives none of Bo's frame keys at any point.
fn a_squat_under_the_receivers_id_never_keys(order: SquatOpens) {
    let mut all = members(4);
    let (ada, bo, cy, di) = (0usize, 1usize, 2usize, 3usize);
    let leaves: Vec<u32> = all.iter().map(leaf).collect();
    join(&mut all, ada, "p-ada", "sess-ada");
    join(&mut all, di, "p-di", "sess-di");

    // Cy never starts the call; it signs a Joined under Bo's coming id with
    // a call key pair of its own, delivered to Bo only.
    let (cy_private, cy_public, cy_public_pq) = own_keys(0x5c);
    let squat = squat_joined(&mut all[cy], "p-bo", &cy_public, &cy_public_pq);
    let mut stolen: Vec<[u8; 32]> = Vec::new();
    let bo_start = |bo: &mut Client| {
        bo.call_media_start(
            GROUP,
            &CALL_ID,
            "p-bo",
            "sess-bo",
            &["sess-bo-audio".into()],
        )
        .unwrap();
    };
    match order {
        SquatOpens::BeforeStart => {
            let opened = try_open(&mut all[bo], &squat).expect("Bo binds Cy before Bo holds p-bo");
            for envelope in &opened.send {
                stolen.extend(grants_to(&mut all[cy], &cy_private, envelope));
            }
            bo_start(&mut all[bo]);
        }
        SquatOpens::BeforeJoined => {
            bo_start(&mut all[bo]);
            assert!(
                try_open(&mut all[bo], &squat).is_none(),
                "Bo bound Cy under the id his start named"
            );
        }
    }

    // Bo joins honestly under the id the server gave him, and shares.
    let bo_joined = signed_joined(&mut all[bo], "p-bo", "sess-bo");
    deliver_to(&mut all, bo, &[ada, di], vec![bo_joined.clone()]);
    let _ = try_open(&mut all[cy], &bo_joined);
    let share = all[bo].call_media_share(GROUP, &CALL_ID).unwrap();
    assert!(!share.is_empty());
    for envelope in &share {
        assert!(
            !addresses(&mut all[ada], envelope, leaves[cy]),
            "{order:?}: Bo's share addressed a grant to Cy's leaf"
        );
        let _ = try_open(&mut all[di], envelope);
        stolen.extend(grants_to(&mut all[cy], &cy_private, envelope));
    }
    let first = frame(&mut all[bo], &opus(0x11), 1);
    assert!(opens(&keys(&mut all[ada]), leaves[bo], &first));

    // Bo's core lists nobody under his own id, and nothing at Cy's leaf.
    let bo_keys = keys(&mut all[bo]);
    assert!(
        bo_keys
            .participants
            .iter()
            .all(|p| p.participant_id != "p-bo"),
        "{order:?}: Bo's core lists a participant under Bo's own id"
    );
    assert!(bo_keys
        .participants
        .iter()
        .all(|p| p.leaf_index != leaves[cy]));
    assert!(bo_keys.senders.iter().all(|k| k.leaf_index != leaves[cy]));
    assert!(lists_keyed(&mut all[bo], leaves[ada], "p-ada"));
    assert!(lists_keyed(&mut all[bo], leaves[di], "p-di"));

    // The squat is refused everywhere else: p-bo is Bo's there.
    for i in [ada, di] {
        assert!(try_open(&mut all[i], &squat).is_none());
        assert!(lists_keyed(&mut all[i], leaves[bo], "p-bo"));
    }

    // Cy's own signed Left under p-bo moves nothing at Bo.
    let listed = |keys: &CallMediaKeys| -> Vec<(u32, String)> {
        keys.participants
            .iter()
            .map(|p| (p.leaf_index, p.participant_id.clone()))
            .collect()
    };
    let before = listed(&keys(&mut all[bo]));
    let cy_left = signed_left(&mut all[cy], "p-bo");
    if let Some(opened) = try_open(&mut all[bo], &cy_left) {
        assert!(opened.send.is_empty(), "{order:?}: Cy's Left rotated Bo");
    }
    assert_eq!(listed(&keys(&mut all[bo])), before);

    // Di leaves; Bo rotates and grants the fresh secret to Ada alone.
    let di_left = signed_left(&mut all[di], "p-di");
    let opened = try_open(&mut all[bo], &di_left).expect("Bo opens Di's Left");
    assert!(!opened.send.is_empty());
    for envelope in &opened.send {
        assert!(!addresses(&mut all[ada], envelope, leaves[cy]));
        stolen.extend(grants_to(&mut all[cy], &cy_private, envelope));
    }
    rotation_delay_passes();
    all[bo].call_media_apply(GROUP, &CALL_ID).unwrap();

    // Ada hears Bo; whatever Cy was granted, from first to last, opens none
    // of Bo's frames from his share on.
    let root: [u8; 32] = all[cy]
        .export_secret(GROUP, CALL_EXPORTER_LABEL_V2, &CALL_ID, 32)
        .unwrap()
        .try_into()
        .unwrap();
    let after = frame(&mut all[bo], &opus(0x22), 2);
    assert!(opens(&keys(&mut all[ada]), leaves[bo], &after));
    for secret in &stolen {
        let mut secret = *secret;
        for _ in 0..4 {
            let key = call_sender_key_v2(&root, &secret, leaves[bo]).unwrap();
            for wire in [&first, &after] {
                assert!(
                    decrypt_with(&key, wire).is_none(),
                    "{order:?}: Cy hears Bo with a secret Bo granted it"
                );
            }
            secret = call_media_advance(&secret).unwrap();
        }
    }
}

#[test]
fn a_squat_opened_before_the_receiver_starts_never_keys_under_its_id() {
    a_squat_under_the_receivers_id_never_keys(SquatOpens::BeforeStart);
}

#[test]
fn a_squat_opened_before_the_receivers_joined_never_keys_under_its_id() {
    a_squat_under_the_receivers_id_never_keys(SquatOpens::BeforeJoined);
}

#[test]
fn a_newcomer_reads_nothing_sent_before_it_joined() {
    let mut all = members(3);
    let ada_leaf = leaf(&all[0]);
    join(&mut all, 0, "p-ada", "sess-ada");
    join(&mut all, 1, "p-bo", "sess-bo");
    let early = frame(&mut all[0], &opus(7), 7);

    join(&mut all, 2, "p-cy", "sess-cy");
    let late = frame(&mut all[0], &opus(8), 8);

    let cy_keys = keys(&mut all[2]);
    assert!(opens(&cy_keys, ada_leaf, &late));
    assert!(!opens_with_anything(&every_key(&mut all[2]), &early));
    // Bo follows Ada's advance without a grant of his own.
    assert!(opens(&keys(&mut all[1]), ada_leaf, &late));
    assert!(opens(&keys(&mut all[1]), ada_leaf, &early));
}

#[test]
fn a_key_counts_only_from_a_signed_joined() {
    let mut all = members(2);
    let (ada_leaf, bo_leaf) = (leaf(&all[0]), leaf(&all[1]));
    all[0]
        .call_media_start(GROUP, &CALL_ID, "p-ada", "sess-ada", &[])
        .unwrap();
    let ada_joined = signed_joined(&mut all[0], "p-ada", "sess-ada");
    // Bo reads Ada's call public key in her signed Joined, as every member can.
    let public = match open(&mut all[1], &ada_joined).signal.body {
        CallSignalBody::Joined { media_key_pq, .. } => media_key_pq,
        other => panic!("{other:?}"),
    };

    // Bo starts and sends a live Joined and then a grant: the live Joined
    // binds nothing, so the grant is held and installs no key.
    all[1]
        .call_media_start(GROUP, &CALL_ID, "p-bo", "sess-bo", &[])
        .unwrap();
    let live = live_joined(&mut all[1], "p-bo", "sess-bo");
    let live = open(&mut all[0], &live);
    assert_eq!(live.sender, None);
    assert!(live.send.is_empty());
    // The participation Bo's `start` began, as his heartbeat names it.
    let CallSignalBody::Joined {
        started_at_ms: bo_started,
        participation: bo_mark,
        ..
    } = live.signal.body
    else {
        panic!("a Joined");
    };
    assert!(bo_mark.is_some(), "the core marks every Joined it seals");
    let payload = MediaGrantPayload {
        generation: 0,
        secret: [9u8; 32].into(),
        session_id: "sess-bo".into(),
        track_names: vec![],
    };
    let (enc, ciphertext) =
        seal_call_media_grant(&public, &CALL_ID, bo_leaf, ada_leaf, &payload).unwrap();
    let grant = all[1]
        .seal_call_signal_on_mls_lane(
            GROUP,
            &CallSignal::new(
                CALL_ID,
                CallSignalBody::MediaKey {
                    generation: 0,
                    rotated: true,
                    grants: vec![MediaGrant {
                        to_leaf: ada_leaf,
                        enc,
                        ciphertext,
                    }],
                    started_at_ms: bo_started,
                    participation: bo_mark,
                },
            ),
        )
        .unwrap();
    let opened = open(&mut all[0], &grant);
    let media = opened.media.unwrap();
    assert!(!media.bound, "a grant from an unbound leaf counted");
    let ada_keys = keys(&mut all[0]);
    assert!(ada_keys.senders.iter().all(|key| key.leaf_index != bo_leaf));
    assert!(ada_keys
        .participants
        .iter()
        .all(|p| p.leaf_index != bo_leaf));

    // Bo's SIGNED Joined binds him, and the held grant counts now; Ada owes
    // him her own key, advanced.
    let signed = signed_joined(&mut all[1], "p-bo", "sess-bo");
    let opened = open(&mut all[0], &signed);
    assert_eq!(opened.send.len(), 1);
    let ada_keys = keys(&mut all[0]);
    let bo = ada_keys
        .participants
        .iter()
        .find(|p| p.leaf_index == bo_leaf)
        .unwrap();
    assert!(bo.keyed);
    assert_eq!(bo.session_id, "sess-bo");
    assert!(ada_keys.senders.iter().any(|key| key.leaf_index == bo_leaf));
}

#[test]
fn a_grant_opens_only_for_its_recipient_call_and_leaves() {
    let (private_a, public_a) = call_media_pq_key_pair(&[1u8; 32]).unwrap();
    let (private_b, _) = call_media_pq_key_pair(&[2u8; 32]).unwrap();
    let (_, classical) = call_media_key_pair(&[1u8; 32]).unwrap();
    let payload = MediaGrantPayload {
        generation: 3,
        secret: [7u8; 32].into(),
        session_id: "s".into(),
        track_names: vec!["t".into()],
    };
    assert!(
        seal_call_media_grant(&classical, &CALL_ID, 1, 2, &payload).is_err(),
        "no grant is sealed to an X25519 key"
    );
    let (enc, ct) = seal_call_media_grant(&public_a, &CALL_ID, 1, 2, &payload).unwrap();
    assert_eq!(
        open_call_media_grant(&private_a, &CALL_ID, 1, 2, &enc, &ct).unwrap(),
        payload
    );
    assert!(open_call_media_grant(&private_b, &CALL_ID, 1, 2, &enc, &ct).is_err());
    assert!(open_call_media_grant(&private_a, b"fedcba9876543210", 1, 2, &enc, &ct).is_err());
    assert!(open_call_media_grant(&private_a, &CALL_ID, 3, 2, &enc, &ct).is_err());
    assert!(open_call_media_grant(&private_a, &CALL_ID, 1, 3, &enc, &ct).is_err());
    let mut flipped = ct.clone();
    flipped[0] ^= 1;
    assert!(open_call_media_grant(&private_a, &CALL_ID, 1, 2, &enc, &flipped).is_err());
}

#[test]
fn the_json_door_starts_shares_removes_and_lists() {
    let mut all = members(2);
    let call = "30313233343536373839616263646566";
    let start = all[0]
        .call_media_json(
            GROUP,
            &format!(
                r#"{{"op":"start","callId":"{call}","participantId":"p-ada","sessionId":"s-ada","trackNames":["a"]}}"#
            ),
        )
        .unwrap();
    let start: serde_json::Value = serde_json::from_str(&start).unwrap();
    assert_eq!(start["mediaKeyHex"].as_str().unwrap().len(), 64);
    let listed = all[0]
        .call_media_json(GROUP, &format!(r#"{{"op":"keys","callId":"{call}"}}"#))
        .unwrap();
    let listed: serde_json::Value = serde_json::from_str(&listed).unwrap();
    assert_eq!(listed["senders"].as_array().unwrap().len(), 1);
    assert_eq!(listed["sendKeyIndex"], listed["senders"][0]["keyIndex"]);
    let removed = all[0]
        .call_media_json(
            GROUP,
            &format!(r#"{{"op":"remove","callId":"{call}","leafIndex":9}}"#),
        )
        .unwrap();
    let removed: serde_json::Value = serde_json::from_str(&removed).unwrap();
    assert_eq!(removed["send"].as_array().unwrap().len(), 0);
    assert!(
        removed["applyAfterMs"].is_null(),
        "nobody was removed, so nothing rotates"
    );
    let epoch = all[0]
        .call_media_json(GROUP, &format!(r#"{{"op":"epoch","callId":"{call}"}}"#))
        .unwrap();
    let epoch: serde_json::Value = serde_json::from_str(&epoch).unwrap();
    assert_eq!(epoch["send"].as_array().unwrap().len(), 0);
    assert!(
        epoch["applyAfterMs"].is_null(),
        "no commit took a participant away, so nothing rotates"
    );
    assert!(all[0]
        .call_media_json(GROUP, &format!(r#"{{"op":"nope","callId":"{call}"}}"#))
        .is_err());
    all[0]
        .call_media_json(GROUP, &format!(r#"{{"op":"end","callId":"{call}"}}"#))
        .unwrap();
    assert!(all[0]
        .call_media_json(GROUP, &format!(r#"{{"op":"keys","callId":"{call}"}}"#))
        .is_err());
    let _ = &mut all[1];
}

// ---- The switch after a rotation is the core's ----------------------------
//
// A remaining participant rotates past a leaver and switches to the fresh
// secret `CALL_MEDIA_ROTATE_DELAY_MS` later. The core keeps that due time and
// switches by itself at the first door call at or after it, so a client that
// never asks to apply (or asks too early) still cuts the leaver off; and a
// rotation asked for while one is pending keeps the pending one's due time,
// so a later leaver cannot postpone the cut-off of an earlier one.

/// `member` joins as a v2 participant under a call key pair it made itself,
/// so it can keep the secrets it is granted: what a device running its own
/// code holds. Returns the private key and the secrets granted by the join.
fn join_keeping(
    all: &mut [Client],
    member: usize,
    participant: &str,
) -> (Vec<u8>, Vec<(u32, [u8; 32])>) {
    let (private, public, public_pq) = own_keys(0x60 + member as u8);
    let member_leaf = leaf(&all[member]);
    own_code(&mut all[member]);
    let joined = all[member]
        .seal_call_signal_as_written(
            GROUP,
            &CallSignal::new(
                CALL_ID,
                CallSignalBody::Joined {
                    participant_id: participant.into(),
                    session_id: String::new(),
                    track_names: Vec::new(),
                    leaf_index: member_leaf,
                    media_key: public.to_vec(),
                    started_at_ms: 0,
                    media_key_pq: public_pq.clone(),
                    participation: own_mark(),
                },
            ),
        )
        .unwrap();
    let mut held = Vec::new();
    let others: Vec<usize> = (0..all.len()).filter(|i| *i != member).collect();
    for &i in &others {
        let Some(opened) = try_open(&mut all[i], &joined) else {
            continue;
        };
        for envelope in opened.send {
            for &j in &others {
                if j != i {
                    let _ = try_open(&mut all[j], &envelope);
                }
            }
            held.extend(kept_grants(&mut all[member], &private, &envelope));
        }
    }
    (private.to_vec(), held)
}

/// Every grant in a `MediaKey` envelope that opens for `keeper` under the
/// call private key it made itself, with its sender's leaf. Opens the
/// envelope at `keeper`.
fn kept_grants(keeper: &mut Client, private_key: &[u8], envelope: &[u8]) -> Vec<(u32, [u8; 32])> {
    let Some(opened) = try_open(keeper, envelope) else {
        return Vec::new();
    };
    let (Some(sender_leaf), CallSignalBody::MediaKey { grants, .. }) =
        (opened.sender_leaf, &opened.signal.body)
    else {
        return Vec::new();
    };
    let own = leaf(keeper);
    grants
        .iter()
        .filter(|grant| grant.to_leaf == own)
        .filter_map(|grant| {
            open_call_media_grant(
                private_key,
                &CALL_ID,
                sender_leaf,
                own,
                &grant.enc,
                &grant.ciphertext,
            )
            .ok()
            .map(|payload| (sender_leaf, *payload.secret))
        })
        .collect()
}

/// Whether a leaver reads `sender_leaf`'s frame with what it holds: the
/// epoch's v2 root (every member derives it) and every secret it was
/// granted, advanced a few steps.
fn kept_secrets_open(
    leaver: &Client,
    secrets: &[(u32, [u8; 32])],
    sender_leaf: u32,
    wire: &[u8],
) -> bool {
    let root: [u8; 32] = leaver
        .export_secret(GROUP, CALL_EXPORTER_LABEL_V2, &CALL_ID, 32)
        .unwrap()
        .try_into()
        .unwrap();
    secrets
        .iter()
        .filter(|(from, _)| *from == sender_leaf)
        .any(|(_, secret)| {
            let mut secret = *secret;
            (0..4).any(|_| {
                let key = call_sender_key_v2(&root, &secret, sender_leaf).unwrap();
                secret = call_media_advance(&secret).unwrap();
                decrypt_with(&key, wire).is_some()
            })
        })
}

/// The open's answer as the C, wasm and Swift doors hand it over.
fn answer_of(opened: &OpenedCallSignal) -> serde_json::Value {
    serde_json::from_str(&opened.to_json().unwrap()).unwrap()
}

fn media_op(member: &mut Client, op: &str) -> serde_json::Value {
    let call: String = CALL_ID.iter().map(|b| format!("{b:02x}")).collect();
    let answer = member
        .call_media_json(GROUP, &format!(r#"{{"op":"{op}","callId":"{call}"}}"#))
        .unwrap();
    serde_json::from_str(&answer).unwrap()
}

/// Deliver `envelopes` from `from` to each of `to`, and whatever grants in
/// them open for `keeper` under its own call key into `held`.
fn deliver_keeping(
    all: &mut [Client],
    from: usize,
    to: &[usize],
    envelopes: &[Vec<u8>],
    keeper: (usize, &[u8]),
    held: &mut Vec<(u32, [u8; 32])>,
) {
    for envelope in envelopes {
        for &j in to {
            if j == from {
                continue;
            }
            if j == keeper.0 {
                held.extend(kept_grants(&mut all[j], keeper.1, envelope));
            } else {
                let _ = try_open(&mut all[j], envelope);
            }
        }
    }
}

/// The rotation a leaver's signed `Left` draws in `open_call_signal` is
/// switched to by the core itself once due: Ada's client never asks to apply,
/// and Cy, who kept every secret it was granted, reads nothing Ada sends
/// after the next door (a heartbeat opened), across an epoch change and a
/// newcomer. Every answer on the way says the rotation is pending.
#[test]
fn a_rotation_a_signed_left_drew_switches_by_itself_once_due() {
    let mut all = members(4);
    let (ada, bo, cy, di) = (0usize, 1usize, 2usize, 3usize);
    let (ada_leaf, cy_leaf) = (leaf(&all[ada]), leaf(&all[cy]));
    join(&mut all, ada, "p-ada", "sess-ada");
    join(&mut all, bo, "p-bo", "sess-bo");
    let (cy_private, mut held) = join_keeping(&mut all, cy, "p-cy");
    assert!(
        held.iter().any(|(from, _)| *from == ada_leaf),
        "Ada granted Cy"
    );
    let sanity = frame(&mut all[ada], &opus(1), 1);
    assert!(
        kept_secrets_open(&all[cy], &held, ada_leaf, &sanity),
        "Cy is in"
    );

    // Cy leaves, signed. Ada's open rotates, and its answer says when the
    // core switches.
    let left = signed_left(&mut all[cy], "p-cy");
    let mut owed = Vec::new();
    for i in [ada, bo, di] {
        let opened = try_open(&mut all[i], &left).expect("Cy's own Left opens");
        if i == ada {
            assert_eq!(opened.unbound_leaf, Some(cy_leaf));
            assert!(!opened.send.is_empty(), "Ada rotated past Cy");
            assert_eq!(opened.apply_after_ms, Some(CALL_MEDIA_ROTATE_DELAY_MS));
            let answer = answer_of(&opened);
            assert_eq!(answer["applyAfterMs"], CALL_MEDIA_ROTATE_DELAY_MS);
            assert_eq!(answer["applied"], false);
        }
        if !opened.send.is_empty() {
            owed.push((i, opened.send));
        }
    }
    for (from, envelopes) in owed {
        deliver_keeping(
            &mut all,
            from,
            &[ada, bo, cy, di],
            &envelopes,
            (cy, &cy_private),
            &mut held,
        );
    }

    // Inside the delay, the stated bound: Cy still reads Ada, and asking to
    // apply early changes nothing.
    assert!(all[ada]
        .call_media_apply(GROUP, &CALL_ID)
        .unwrap()
        .is_empty());
    let inside = frame(&mut all[ada], &opus(2), 2);
    assert!(kept_secrets_open(&all[cy], &held, ada_leaf, &inside));

    // An epoch change (Bo's in-call self-update): `epoch` rotates nothing
    // more, and says the rotation the open drew is still pending.
    let update = all[bo].self_update(GROUP).unwrap();
    all[bo].merge_pending_commit(GROUP).unwrap();
    for i in [ada, cy, di] {
        all[i].process_commit(GROUP, &update.commit).unwrap();
    }
    let epoch = media_op(&mut all[ada], "epoch");
    assert_eq!(epoch["send"].as_array().unwrap().len(), 0);
    assert_eq!(epoch["applyAfterMs"], CALL_MEDIA_ROTATE_DELAY_MS, "{epoch}");

    // The delay passes. Ada's client never asks to apply; Bo's next
    // heartbeat, opened, is the door that switches.
    rotation_delay_passes();
    let beat = live_joined(&mut all[bo], "p-bo", "sess-bo");
    let opened = open(&mut all[ada], &beat);
    assert!(opened.applied, "the heartbeat's open switched Ada's key");
    assert_eq!(opened.apply_after_ms, None);
    assert!(opened.send.is_empty(), "nothing was chained");
    assert_eq!(answer_of(&opened)["applied"], true);
    let after = frame(&mut all[ada], &opus(3), 3);
    assert!(
        !kept_secrets_open(&all[cy], &held, ada_leaf, &after),
        "Cy, gone from every tile, reads Ada after the switch"
    );
    assert!(opens(&keys(&mut all[bo]), ada_leaf, &after), "Bo hears Ada");

    // Nor after a newcomer's advance.
    join(&mut all, di, "p-di", "sess-di");
    let later = frame(&mut all[ada], &opus(4), 4);
    assert!(!kept_secrets_open(&all[cy], &held, ada_leaf, &later));
    assert!(opens(&keys(&mut all[di]), ada_leaf, &later), "Di hears Ada");
}

/// The core switches at the participant's own heartbeat too: with nobody
/// else's heartbeat to open, Ada's own heartbeat seal is the door, and the
/// next answer says it switched, once.
#[test]
fn a_due_rotation_switches_at_the_participants_own_heartbeat() {
    let mut all = members(3);
    let (ada, bo, cy) = (0usize, 1usize, 2usize);
    let ada_leaf = leaf(&all[ada]);
    join(&mut all, ada, "p-ada", "sess-ada");
    let (cy_private, mut held) = join_keeping(&mut all, cy, "p-cy");
    let left = signed_left(&mut all[cy], "p-cy");
    let opened = open(&mut all[ada], &left);
    let _ = try_open(&mut all[bo], &left);
    deliver_keeping(
        &mut all,
        ada,
        &[bo, cy],
        &opened.send,
        (cy, &cy_private),
        &mut held,
    );
    let before = keys(&mut all[ada]).send_key_index;

    rotation_delay_passes();
    let _beat = live_joined(&mut all[ada], "p-ada", "sess-ada");
    assert_ne!(
        keys(&mut all[ada]).send_key_index,
        before,
        "the seal switched the key"
    );
    let after = frame(&mut all[ada], &opus(5), 5);
    assert!(!kept_secrets_open(&all[cy], &held, ada_leaf, &after));
    let answer = media_op(&mut all[ada], "apply");
    assert_eq!(answer["applied"], true, "the next answer says so: {answer}");
    assert!(answer["applyAfterMs"].is_null());
    assert_eq!(media_op(&mut all[ada], "apply")["applied"], false, "once");
}

/// A second leaver inside the window neither postpones the first one's
/// cut-off nor keeps the key: Ada's rotation for Cy keeps its due time when
/// Di leaves 3 s later, and Di (who was granted that rotation) is rotated
/// past by a chained rotation drawn when the first switches.
#[test]
fn a_second_leaver_inside_the_window_keeps_the_due_time_and_chains() {
    let mut all = members(4);
    let (ada, bo, cy, di) = (0usize, 1usize, 2usize, 3usize);
    let (ada_leaf, di_leaf) = (leaf(&all[ada]), leaf(&all[di]));
    join(&mut all, ada, "p-ada", "sess-ada");
    join(&mut all, bo, "p-bo", "sess-bo");
    join(&mut all, cy, "p-cy", "sess-cy");
    let (di_private, mut held) = join_keeping(&mut all, di, "p-di");
    let cy_every_key = every_key(&mut all[cy]);

    // Cy leaves: Ada's rotation is due in 5 s, and Di is granted it.
    let cy_left = signed_left(&mut all[cy], "p-cy");
    let mut owed = Vec::new();
    for i in [ada, bo, di] {
        let opened = try_open(&mut all[i], &cy_left).expect("Cy's own Left opens");
        if i == ada {
            assert_eq!(opened.apply_after_ms, Some(CALL_MEDIA_ROTATE_DELAY_MS));
        }
        if !opened.send.is_empty() {
            owed.push((i, opened.send));
        }
    }
    let held_before = held.iter().filter(|(from, _)| *from == ada_leaf).count();
    for (from, envelopes) in owed {
        deliver_keeping(
            &mut all,
            from,
            &[ada, bo, di],
            &envelopes,
            (di, &di_private),
            &mut held,
        );
    }
    assert!(
        held.iter().filter(|(from, _)| *from == ada_leaf).count() > held_before,
        "Di holds Ada's rotated secret"
    );

    // 3 s later Di leaves too. Ada's answer keeps the first due time (2 s
    // left), and draws nothing yet: Di holds the pending secret.
    support::advance_ms(3_000);
    let di_left = signed_left(&mut all[di], "p-di");
    let opened = open(&mut all[ada], &di_left);
    assert_eq!(opened.unbound_leaf, Some(di_leaf));
    assert!(
        opened.send.is_empty(),
        "chained, not drawn while one is pending"
    );
    assert_eq!(
        opened.apply_after_ms,
        Some(2_000),
        "the first leaver's due time stands"
    );
    let opened_bo = open(&mut all[bo], &di_left);
    deliver_keeping(
        &mut all,
        bo,
        &[ada, di],
        &opened_bo.send,
        (di, &di_private),
        &mut held,
    );
    assert_eq!(media_op(&mut all[ada], "epoch")["applyAfterMs"], 2_000);

    // At the first due time, the next door switches and draws the chained
    // rotation, granted to Bo alone and due 5 s on.
    support::advance_ms(2_000);
    let beat = live_joined(&mut all[bo], "p-bo", "sess-bo");
    let opened = open(&mut all[ada], &beat);
    assert!(opened.applied);
    assert!(!opened.send.is_empty(), "the chained rotation's grants");
    assert_eq!(opened.apply_after_ms, Some(CALL_MEDIA_ROTATE_DELAY_MS));
    let before_chain = held.len();
    deliver_keeping(
        &mut all,
        ada,
        &[bo, di],
        &opened.send,
        (di, &di_private),
        &mut held,
    );
    assert_eq!(held.len(), before_chain, "the chained rotation is not Di's");
    let mid = frame(&mut all[ada], &opus(6), 6);
    assert!(
        !opens_with_anything(&cy_every_key, &mid),
        "Cy is cut off on time"
    );
    assert!(opens(&keys(&mut all[bo]), ada_leaf, &mid), "Bo hears Ada");
    assert!(
        kept_secrets_open(&all[di], &held, ada_leaf, &mid),
        "Di, who left inside the window, reads until the chained switch"
    );

    // 5 s on, the chained rotation switches at the next door (a timer's
    // `apply` here), and Di reads nothing more.
    rotation_delay_passes();
    let answer = media_op(&mut all[ada], "apply");
    assert_eq!(answer["applied"], true, "{answer}");
    assert!(answer["applyAfterMs"].is_null());
    let last = frame(&mut all[ada], &opus(7), 7);
    assert!(!kept_secrets_open(&all[di], &held, ada_leaf, &last));
    assert!(!opens_with_anything(&cy_every_key, &last));
    assert!(opens(&keys(&mut all[bo]), ada_leaf, &last), "Bo hears Ada");
}

/// A sender whose client never asks to apply stays heard: past the delay and
/// every receiver's grace for the old key, the core has switched by itself,
/// and honest receivers, who installed the rotated key when they opened its
/// `MediaKey`, read the new one. A receiver of any build already holds it,
/// so the core switching on its own crosses no build.
#[test]
fn a_sender_whose_client_never_applies_is_still_heard_after_the_grace() {
    let mut all = members(3);
    let (ada, bo, cy) = (0usize, 1usize, 2usize);
    let ada_leaf = leaf(&all[ada]);
    join(&mut all, ada, "p-ada", "sess-ada");
    join(&mut all, bo, "p-bo", "sess-bo");
    join(&mut all, cy, "p-cy", "sess-cy");
    let left = signed_left(&mut all[cy], "p-cy");
    settle(&mut all, cy, vec![left]);
    let before = keys(&mut all[ada]).send_key_index;
    let inside = frame(&mut all[ada], &opus(1), 1);
    assert!(
        opens(&keys(&mut all[bo]), ada_leaf, &inside),
        "inside the window"
    );

    // Past the delay and the receivers' grace (5 s + 10 s), with no `apply`.
    support::advance_ms(CALL_MEDIA_ROTATE_DELAY_MS + 11_000);
    let after = frame(&mut all[ada], &opus(2), 2);
    assert_ne!(
        keys(&mut all[ada]).send_key_index,
        before,
        "the core switched"
    );
    assert!(
        opens(&keys(&mut all[bo]), ada_leaf, &after),
        "Bo still hears Ada"
    );
}

// ---- a rejoin's old Left and this device's own media keys -------------------

/// The keys any member of the epoch derives, in the call or not: v1's.
fn member_keys(member: &Client) -> Vec<[u8; 16]> {
    member
        .call_keys(GROUP, &CALL_ID)
        .unwrap()
        .senders
        .iter()
        .map(|key| *key.key)
        .collect()
}

fn left(participant: &str) -> CallSignal {
    CallSignal::new(
        CALL_ID,
        CallSignalBody::Left {
            participant_id: participant.into(),
        },
    )
}

/// The call key and the session a sealed `Joined` carries, as a receiver
/// opens it.
fn joined_carries(opened: &OpenedCallSignal) -> (usize, String) {
    match &opened.signal.body {
        CallSignalBody::Joined {
            media_key,
            session_id,
            ..
        } => (media_key.len(), session_id.clone()),
        other => panic!("not a Joined: {other:?}"),
    }
}

/// A REJOIN STAYS ON PARTICIPANT KEYS WHATEVER ORDER ITS OLD `Left` GOES IN
/// (docs/calls.md §Participant media keys, Joining). Bo rejoins
/// under a new participant id in an order the spec allows: `start`, then the
/// old participant's signed `Left`, then the new signed `Joined`, then
/// `share`. The old id's `Left` speaks for a participation `start` already
/// replaced, so it leaves the new one's keys alone: Bo's new `Joined` carries
/// its call key and no session, his `share` grants it, nobody falls back to
/// the shared key, and Di, a member who never joins, reads nothing Ada sends.
#[test]
fn a_rejoin_whose_old_left_follows_start_stays_on_participant_keys() {
    let mut all = members(4);
    let (ada, bo, cy, di) = (0usize, 1usize, 2usize, 3usize);
    let bo_leaf = leaf(&all[bo]);
    join(&mut all, ada, "p-ada", "sess-ada");
    join(&mut all, bo, "p-bo", "sess-bo");
    join(&mut all, cy, "p-cy", "sess-cy");

    all[bo]
        .call_media_start(
            GROUP,
            &CALL_ID,
            "p-bo-2",
            "sess-bo-2",
            &["sess-bo-2-audio".into()],
        )
        .unwrap();
    let old_left = all[bo]
        .seal_call_signal_on_mls_lane(GROUP, &left("p-bo"))
        .unwrap();
    for i in [ada, cy, di] {
        let opened = try_open(&mut all[i], &old_left).expect("the old Left opens");
        if i != di {
            assert_eq!(
                opened.unbound_leaf,
                Some(bo_leaf),
                "member {i} unbound p-bo"
            );
        }
        settle(&mut all, i, opened.send);
    }
    assert!(
        all[bo].call_media_keys(GROUP, &CALL_ID, false).is_ok(),
        "the old id's Left left the new participation's keys alone"
    );

    let new_joined = signed_joined(&mut all[bo], "p-bo-2", "sess-bo-2");
    for i in [ada, cy, di] {
        let opened = try_open(&mut all[i], &new_joined).expect("the new Joined opens");
        assert_eq!(
            joined_carries(&opened),
            (32, String::new()),
            "member {i} got Bo's call key and no session"
        );
        settle(&mut all, i, opened.send);
    }
    let grants = all[bo]
        .call_media_share(GROUP, &CALL_ID)
        .expect("Bo's share finds his media state");
    assert!(!grants.is_empty());
    settle(&mut all, bo, grants);

    for i in [ada, cy] {
        assert!(lists_keyed(&mut all[i], bo_leaf, "p-bo-2"));
    }
    let ada_frame = frame(&mut all[ada], &opus(2), 2);
    assert!(
        !opens_with_anything(&member_keys(&all[di]), &ada_frame),
        "Di, who never joined, reads Ada"
    );
    assert!(
        opens(&keys(&mut all[bo]), leaf(&all[ada]), &ada_frame),
        "Bo hears Ada"
    );
    let bo_frame = frame(&mut all[bo], &opus(3), 3);
    assert!(
        opens(&keys(&mut all[cy]), bo_leaf, &bo_frame),
        "Cy hears Bo"
    );
    assert!(!opens_with_anything(&member_keys(&all[di]), &bo_frame));
}

/// The old `Left` sent BEFORE `start`, and again after it (a client that
/// lost track of having sent it): the first ends the old keys as before; the
/// second names an id this device no longer holds, so it ends nothing.
#[test]
fn an_old_left_sent_again_after_start_leaves_the_new_keys() {
    let mut all = members(3);
    let (ada, bo, cy) = (0usize, 1usize, 2usize);
    join(&mut all, ada, "p-ada", "sess-ada");
    join(&mut all, bo, "p-bo", "sess-bo");
    join(&mut all, cy, "p-cy", "sess-cy");
    let first = all[bo]
        .seal_call_signal_on_mls_lane(GROUP, &left("p-bo"))
        .unwrap();
    assert!(all[bo].call_media_keys(GROUP, &CALL_ID, false).is_err());
    settle(&mut all, bo, vec![first]);
    all[bo]
        .call_media_start(GROUP, &CALL_ID, "p-bo-2", "sess-bo-2", &[])
        .unwrap();
    let again = all[bo]
        .seal_call_signal_on_mls_lane(GROUP, &left("p-bo"))
        .unwrap();
    assert!(all[bo].call_media_keys(GROUP, &CALL_ID, false).is_ok());
    let _ = try_open(&mut all[ada], &again);
    let _ = try_open(&mut all[cy], &again);
    let joined = signed_joined(&mut all[bo], "p-bo-2", "sess-bo-2");
    let opened = try_open(&mut all[ada], &joined).expect("the new Joined opens");
    assert_eq!(joined_carries(&opened), (32, String::new()));
}

/// A `Left` naming the device's current participant still ends its keys, on
/// either sealing door; so does one sealed between `start` and the first
/// `Joined` (a hang-up before the device announced itself) when it names an
/// id that was never this device's.
#[test]
fn a_left_for_the_current_participation_still_ends_the_keys() {
    let mut all = members(3);
    let (ada, bo, cy) = (0usize, 1usize, 2usize);
    join(&mut all, ada, "p-ada", "sess-ada");
    join(&mut all, bo, "p-bo", "sess-bo");
    let _ = all[bo]
        .seal_call_signal_on_mls_lane(GROUP, &left("p-bo"))
        .unwrap();
    assert!(all[bo].call_media_keys(GROUP, &CALL_ID, false).is_err());

    let _ = all[ada].seal_call_signal(GROUP, &left("p-ada")).unwrap();
    assert!(all[ada].call_media_keys(GROUP, &CALL_ID, false).is_err());

    all[cy]
        .call_media_start(GROUP, &CALL_ID, "p-cy-from-the-server", "sess-cy", &[])
        .unwrap();
    let _ = all[cy]
        .seal_call_signal_on_mls_lane(GROUP, &left("p-cy-from-the-server"))
        .unwrap();
    assert!(all[cy].call_media_keys(GROUP, &CALL_ID, false).is_err());
}

/// A device whose own `Left` ended its keys never announces itself without a
/// call key: a `Joined` is refused on either sealing door until it asks
/// `start` again. Neither a failed `start` (its client treats that as a
/// failed join) nor `end` licenses a keyless `Joined`, and there is no
/// shared-key fall back.
#[test]
fn a_joined_after_the_devices_own_left_needs_start_first() {
    let mut all = members(3);
    let (ada, bo, cy) = (0usize, 1usize, 2usize);
    join(&mut all, ada, "p-ada", "sess-ada");
    join(&mut all, bo, "p-bo", "sess-bo");
    join(&mut all, cy, "p-cy", "sess-cy");

    // Bo hangs up, then something seals a Joined for the next session.
    let gone = all[bo]
        .seal_call_signal_on_mls_lane(GROUP, &left("p-bo"))
        .unwrap();
    settle(&mut all, bo, vec![gone]);
    let signal = joined(&all[bo], "p-bo-2", "sess-bo-2");
    assert!(all[bo]
        .seal_call_signal_on_mls_lane(GROUP, &signal)
        .is_err());
    assert!(all[bo].seal_call_signal(GROUP, &signal).is_err());
    // `start` again: the Joined goes out with its call key.
    all[bo]
        .call_media_start(GROUP, &CALL_ID, "p-bo-2", "sess-bo-2", &[])
        .unwrap();
    let rejoined = all[bo]
        .seal_call_signal_on_mls_lane(GROUP, &signal)
        .unwrap();
    let opened = try_open(&mut all[ada], &rejoined).expect("opens");
    assert_eq!(joined_carries(&opened), (32, String::new()));

    // Cy hangs up; its client asks `start`, which fails: the keyless Joined
    // is refused, so the client's join fails instead of downgrading the call.
    let gone = all[cy]
        .seal_call_signal_on_mls_lane(GROUP, &left("p-cy"))
        .unwrap();
    let _ = try_open(&mut all[bo], &gone);
    let too_long = "s".repeat(10_000);
    assert!(all[cy]
        .call_media_start(GROUP, &CALL_ID, "p-cy-2", &too_long, &[])
        .is_err());
    let fallback = joined(&all[cy], "p-cy-2", "sess-cy-2");
    for sealed in [
        all[cy].seal_call_signal_on_mls_lane(GROUP, &fallback),
        all[cy].seal_call_signal(GROUP, &fallback),
    ] {
        let err = sealed.expect_err("a failed start licensed a keyless Joined");
        assert!(err.to_string().contains(CALL_STATE_LOST), "{err}");
    }

    // Ada hangs up, then `end`s through the JSON door: still refused, and
    // the JSON door knows no `shared` op.
    let _ = all[ada]
        .seal_call_signal_on_mls_lane(GROUP, &left("p-ada"))
        .unwrap();
    let ada_joined = joined(&all[ada], "p-ada-2", "sess-ada-2");
    assert!(all[ada].seal_call_signal(GROUP, &ada_joined).is_err());
    assert_eq!(media_op(&mut all[ada], "end"), serde_json::json!({}));
    assert!(all[ada]
        .seal_call_signal_on_mls_lane(GROUP, &ada_joined)
        .is_err());
    let shared = serde_json::json!({
        "op": "shared",
        "callId": CALL_ID.iter().map(|b| format!("{b:02x}")).collect::<String>(),
    });
    let err = all[ada]
        .call_media_json(GROUP, &shared.to_string())
        .expect_err("no shared op");
    assert!(err.to_string().contains("unknown call media op"), "{err}");
    assert!(all[ada]
        .seal_call_signal_on_mls_lane(GROUP, &ada_joined)
        .is_err());
}

/// THE SWITCH RUNS ON THE MONOTONIC CLOCK. Cy leaves and Ada's rotation is
/// due 5 s on. Ada's device clock is then set back a minute (a spoofed time
/// server, or its owner): the rotation still switches 5 s after it was
/// drawn, and Cy, who kept every secret it was granted, reads nothing Ada
/// sends from then on. Setting the clock back postpones nothing.
#[test]
fn a_wall_clock_set_back_does_not_postpone_the_switch() {
    let mut all = members(3);
    let (ada, bo, cy) = (0usize, 1usize, 2usize);
    let ada_leaf = leaf(&all[ada]);
    join(&mut all, ada, "p-ada", "sess-ada");
    join(&mut all, bo, "p-bo", "sess-bo");
    let (cy_private, mut held) = join_keeping(&mut all, cy, "p-cy");
    let left = signed_left(&mut all[cy], "p-cy");
    let opened = open(&mut all[ada], &left);
    assert_eq!(opened.apply_after_ms, Some(CALL_MEDIA_ROTATE_DELAY_MS));
    let _ = try_open(&mut all[bo], &left);
    deliver_keeping(
        &mut all,
        ada,
        &[bo, cy],
        &opened.send,
        (cy, &cy_private),
        &mut held,
    );
    let before = keys(&mut all[ada]).send_key_index;

    support::step_wall_ms(-60_000);
    assert_eq!(
        media_op(&mut all[ada], "apply")["applyAfterMs"],
        CALL_MEDIA_ROTATE_DELAY_MS,
        "the wall step moved the due time"
    );
    rotation_delay_passes();
    let answer = media_op(&mut all[ada], "apply");
    assert_eq!(answer["applied"], true, "{answer}");
    assert!(answer["applyAfterMs"].is_null());
    assert_ne!(keys(&mut all[ada]).send_key_index, before);
    let after = frame(&mut all[ada], &opus(9), 9);
    assert!(!kept_secrets_open(&all[cy], &held, ada_leaf, &after));
    assert!(opens(&keys(&mut all[bo]), ada_leaf, &after), "Bo hears Ada");
}

/// The stamp and mark a signed `Joined` carried: its participation.
type Stamp = (u64, Option<Participation>);

/// Member `i` joins as `join` does, and answers its call key and the stamp
/// and mark its signed `Joined` carried (the participation), as a receiver
/// opened it.
fn join_noting(
    all: &mut [Client],
    i: usize,
    participant: &str,
    session: &str,
) -> (([u8; 32], Vec<u8>), Stamp) {
    let key = all[i]
        .call_media_start(
            GROUP,
            &CALL_ID,
            participant,
            session,
            &[format!("{session}-audio")],
        )
        .unwrap();
    let envelope = signed_joined(&mut all[i], participant, session);
    let mut stamp = None;
    let mut key_pq = Vec::new();
    let mut owed = Vec::new();
    for (j, member) in all.iter_mut().enumerate() {
        if j == i {
            continue;
        }
        let opened = open(member, &envelope);
        if let CallSignalBody::Joined {
            started_at_ms,
            media_key_pq,
            participation,
            ..
        } = &opened.signal.body
        {
            stamp = Some((*started_at_ms, *participation));
            key_pq = media_key_pq.clone();
        }
        if !opened.send.is_empty() {
            owed.push((j, opened.send));
        }
    }
    for (j, send) in owed {
        settle(all, j, send);
    }
    let grants = all[i].call_media_share(GROUP, &CALL_ID).unwrap();
    settle(all, i, grants);
    ((key, key_pq), stamp.unwrap())
}

/// A signed `Joined` a device running its own code puts on the MLS lane
/// through `encrypt`, exactly as written: a call key, a stamp and a mark of
/// its choosing, under whatever id it likes.
fn joined_as(
    member: &mut Client,
    participant: &str,
    (key, key_pq): (&[u8], &[u8]),
    (started_at_ms, participation): Stamp,
) -> Vec<u8> {
    let signal = CallSignal::new(
        CALL_ID,
        CallSignalBody::Joined {
            participant_id: participant.into(),
            session_id: String::new(),
            track_names: Vec::new(),
            leaf_index: leaf(member),
            media_key: key.to_vec(),
            started_at_ms,
            media_key_pq: key_pq.to_vec(),
            participation,
        },
    );
    let message = member
        .encrypt(GROUP, &encode_call_signal(&signal).unwrap())
        .unwrap();
    let mut inner = vec![CALL_LANE_MLS];
    inner.extend_from_slice(&message);
    seal_group_id_envelope(GROUP, ENVELOPE_KIND_CALL, &inner).unwrap()
}

/// Whether `member` lists a v2 participant `participant` at `leaf_index`,
/// granted a key by it or not yet.
fn lists_bound(member: &mut Client, leaf_index: u32, participant: &str) -> bool {
    keys(member)
        .participants
        .iter()
        .any(|p| p.leaf_index == leaf_index && p.participant_id == participant)
}

fn lists_leaf(member: &mut Client, leaf_index: u32) -> bool {
    keys(member)
        .participants
        .iter()
        .any(|p| p.leaf_index == leaf_index)
}

/// A PARTICIPATION KEEPS ITS ID. Ada, running her own code, signs a `Joined`
/// under her call key and stamp naming a fresh id, to slip out from under the
/// `Remove` an admin aims at the id every tile shows. Every member refuses
/// it and keeps her under `p-ada`, so Bo's honored `Remove` of `p-ada`
/// unbinds her leaf and rotates past her: no grant of Bo's rotation goes to
/// her leaf.
#[test]
fn a_participant_cannot_rename_itself_out_from_under_a_remove() {
    let mut all = members(3);
    let (ada, bo, cy) = (0usize, 1usize, 2usize);
    let ada_leaf = leaf(&all[ada]);
    let (ada_key, ada_stamp) = join_noting(&mut all, ada, "p-ada", "sess-ada");
    join(&mut all, bo, "p-bo", "sess-bo");
    join(&mut all, cy, "p-cy", "sess-cy");

    let renamed = joined_as(
        &mut all[ada],
        "p-ada-renamed",
        (&ada_key.0, &ada_key.1),
        ada_stamp,
    );
    for i in [bo, cy] {
        assert!(
            try_open(&mut all[i], &renamed).is_none(),
            "member {i} let Ada rename her participation"
        );
        assert!(lists_keyed(&mut all[i], ada_leaf, "p-ada"));
    }

    let rotation = all[bo]
        .call_media_remove_participant(GROUP, &CALL_ID, "p-ada")
        .unwrap();
    assert!(!rotation.is_empty(), "Bo rotated past Ada");
    assert!(!lists_leaf(&mut all[bo], ada_leaf));
    for envelope in &rotation {
        assert!(
            !addresses(&mut all[cy], envelope, ada_leaf),
            "Bo's rotation granted Ada"
        );
    }
}

/// A REMOVE NOT YET HONORED CANNOT BE DODGED BY A RENAME. Bo honors a
/// `Remove` of Ada's `p-ada`; Cy has not seen it yet. Ada's device signs her
/// same participation (same call key, same stamp) under a fresh id: at Cy it
/// is a rename, refused, so Cy keeps her under `p-ada`, the id the `Remove`
/// names.
#[test]
fn a_removed_participation_does_not_come_back_under_a_fresh_id() {
    let mut all = members(3);
    let (ada, bo, cy) = (0usize, 1usize, 2usize);
    let ada_leaf = leaf(&all[ada]);
    let (ada_key, ada_stamp) = join_noting(&mut all, ada, "p-ada", "sess-ada");
    join(&mut all, bo, "p-bo", "sess-bo");
    join(&mut all, cy, "p-cy", "sess-cy");

    let rotation = all[bo]
        .call_media_remove_participant(GROUP, &CALL_ID, "p-ada")
        .unwrap();
    assert!(!rotation.is_empty());
    assert!(!lists_leaf(&mut all[bo], ada_leaf));

    let back = joined_as(
        &mut all[ada],
        "p-ada-back",
        (&ada_key.0, &ada_key.1),
        ada_stamp,
    );
    assert!(try_open(&mut all[cy], &back).is_none());
    assert!(lists_keyed(&mut all[cy], ada_leaf, "p-ada"));
}

/// How the server keeps a leaver on a tile at Bo.
#[derive(Clone, Copy, Debug)]
enum KeptBy {
    /// Bo bound Ada and opened her signed `Left`; then the server delivers a
    /// signed `Joined` of the same participation it held back (she sends one
    /// at every epoch).
    HeldJoinedAfterLeft,
    /// Bo never saw Ada's `Joined`: her signed `Left` reaches him first and
    /// finds nothing bound, then the `Joined` and her grants.
    LeftBeforeJoined,
    /// Bo bound Ada, and her signed `Left` never reaches him.
    WithheldLeft,
}

/// A LEAVER THE SERVER KEEPS IS A GHOST UNTIL ITS HEARTBEAT LAPSES, AND
/// READS NOTHING (docs/calls.md §Participant media keys). The server decides
/// what reaches each device and when, so it can keep Ada, who left, listed
/// at Bo: by delivering a held-back `Joined` after her `Left`, the
/// `Left` before her `Joined`, or no `Left` at all. Cy, given everything in
/// order, drops her. Bo's grants then go to Ada's leaf, sealed to the call
/// key her core erased at her `Left`: her core holds no call state and takes
/// nothing from them. When Bo's client times out her heartbeat (`remove` by
/// leaf) the tile goes, and Bo's rotation past her addresses nobody at her
/// leaf.
#[test]
fn a_kept_leaver_is_a_ghost_until_its_heartbeat_lapses_and_reads_nothing() {
    for kept in [
        KeptBy::HeldJoinedAfterLeft,
        KeptBy::LeftBeforeJoined,
        KeptBy::WithheldLeft,
    ] {
        let mut all = members(4);
        let (ada, bo, cy, di) = (0usize, 1usize, 2usize, 3usize);
        let ada_leaf = leaf(&all[ada]);
        join(&mut all, bo, "p-bo", "sess-bo");
        join(&mut all, cy, "p-cy", "sess-cy");

        // Ada's participation, as the server holds it for Bo.
        let mut for_bo: Vec<Vec<u8>> = Vec::new();
        let left = match kept {
            KeptBy::HeldJoinedAfterLeft | KeptBy::WithheldLeft => {
                join(&mut all, ada, "p-ada", "sess-ada");
                let held = signed_joined(&mut all[ada], "p-ada", "sess-ada");
                let left = signed_left(&mut all[ada], "p-ada");
                for i in [cy, di] {
                    assert!(try_open(&mut all[i], &held).is_some(), "{kept:?}");
                }
                if matches!(kept, KeptBy::HeldJoinedAfterLeft) {
                    let opened = open(&mut all[bo], &left);
                    assert_eq!(opened.unbound_leaf, Some(ada_leaf), "{kept:?}");
                    for_bo.push(held);
                }
                left
            }
            KeptBy::LeftBeforeJoined => {
                all[ada]
                    .call_media_start(GROUP, &CALL_ID, "p-ada", "sess-ada", &[])
                    .unwrap();
                let joined = signed_joined(&mut all[ada], "p-ada", "sess-ada");
                let grants = all[ada].call_media_share(GROUP, &CALL_ID).unwrap();
                let left = signed_left(&mut all[ada], "p-ada");
                for envelope in std::iter::once(&joined).chain(&grants) {
                    for i in [cy, di] {
                        let _ = try_open(&mut all[i], envelope);
                    }
                }
                let opened = open(&mut all[bo], &left);
                assert_eq!(opened.unbound_leaf, None, "{kept:?}: nothing was bound");
                for_bo.push(joined);
                for_bo.extend(grants);
                left
            }
        };
        // Her core erased the participation at her Left.
        let err = all[ada]
            .call_media_keys(GROUP, &CALL_ID, false)
            .unwrap_err();
        assert!(err.to_string().contains(CALL_STATE_LOST), "{kept:?}: {err}");

        // Cy, given everything in order, drops her.
        let opened = open(&mut all[cy], &left);
        assert_eq!(opened.unbound_leaf, Some(ada_leaf), "{kept:?}");
        assert!(!lists_leaf(&mut all[cy], ada_leaf), "{kept:?}");

        // Bo keeps her on a tile, and grants her.
        let mut from_bo: Vec<Vec<u8>> = Vec::new();
        for envelope in &for_bo {
            if let Some(opened) = try_open(&mut all[bo], envelope) {
                from_bo.extend(opened.send);
            }
        }
        assert!(
            lists_bound(&mut all[bo], ada_leaf, "p-ada"),
            "{kept:?}: Bo lists the leaver"
        );
        let cy_left = signed_left(&mut all[cy], "p-cy");
        from_bo.extend(open(&mut all[bo], &cy_left).send);
        let _ = try_open(&mut all[di], &cy_left);
        assert!(
            from_bo
                .iter()
                .any(|envelope| addresses(&mut all[di], envelope, ada_leaf)),
            "{kept:?}: Bo granted the ghost"
        );

        // What reaches Ada's device opens to nothing there.
        for envelope in &from_bo {
            if let Some(opened) = try_open(&mut all[ada], envelope) {
                assert!(opened.media.is_none(), "{kept:?}: a grant opened for Ada");
            }
        }
        let err = all[ada]
            .call_media_keys(GROUP, &CALL_ID, false)
            .unwrap_err();
        assert!(err.to_string().contains(CALL_STATE_LOST), "{kept:?}: {err}");

        // Her heartbeat lapses at Bo: the tile goes, and the rotation past her
        // grants nothing to her leaf.
        let rotation = all[bo]
            .call_media_remove(GROUP, &CALL_ID, ada_leaf)
            .unwrap();
        assert!(!lists_leaf(&mut all[bo], ada_leaf), "{kept:?}");
        for envelope in &rotation {
            assert!(
                !addresses(&mut all[di], envelope, ada_leaf),
                "{kept:?}: a grant to Ada after her heartbeat lapsed"
            );
        }
    }
}

/// An honest return is a new participation, and binds: after her own `Left`
/// Ada starts again under the same id (a new call key, a later stamp); and a
/// device whose every participation names the stamp 0 comes back with a new
/// call key under a later mark. A signed `Joined` with no mark binds nothing.
#[test]
fn a_new_participation_binds_after_a_left_whatever_its_stamp() {
    let mut all = members(3);
    let (ada, bo, cy) = (0usize, 1usize, 2usize);
    let (ada_leaf, cy_leaf) = (leaf(&all[ada]), leaf(&all[cy]));
    join(&mut all, ada, "p-ada", "sess-ada");
    join(&mut all, bo, "p-bo", "sess-bo");

    let left = signed_left(&mut all[ada], "p-ada");
    let opened = open(&mut all[bo], &left);
    settle(&mut all, bo, opened.send);
    let _ = try_open(&mut all[cy], &left);
    join(&mut all, ada, "p-ada", "sess-ada-2");
    assert!(lists_keyed(&mut all[bo], ada_leaf, "p-ada"));

    // Cy's code names the stamp 0, and at first no mark.
    let (_, first, first_pq) = own_keys(0x31);
    let (_, second, second_pq) = own_keys(0x32);
    let unmarked = joined_as(&mut all[cy], "p-cy", (&first, &first_pq), (0, None));
    assert!(
        try_open(&mut all[bo], &unmarked).is_none(),
        "a Joined with no mark bound"
    );
    assert!(!lists_bound(&mut all[bo], cy_leaf, "p-cy"));
    let joined = joined_as(&mut all[cy], "p-cy", (&first, &first_pq), (0, own_mark()));
    let opened = open(&mut all[bo], &joined);
    settle(&mut all, bo, opened.send);
    assert!(lists_bound(&mut all[bo], cy_leaf, "p-cy"));
    let left = signed_left(&mut all[cy], "p-cy");
    let opened = open(&mut all[bo], &left);
    assert_eq!(opened.unbound_leaf, Some(cy_leaf));
    let again = joined_as(
        &mut all[cy],
        "p-cy-2",
        (&second, &second_pq),
        (0, own_mark()),
    );
    assert!(try_open(&mut all[bo], &again).is_some());
    assert!(lists_bound(&mut all[bo], cy_leaf, "p-cy-2"));
}

/// A fresher credential for member `tag`, issued at `iat`, and the renewal
/// commit that carries it into the group, merged by its maker.
fn renew_at(member: &mut Client, tag: u8, iat: i64) -> Vec<u8> {
    let identity = member.identity().clone();
    let (_, public) = peachy_mls_core::issuer::device_key_pair(&support::device_seed(tag));
    let token = issuer()
        .issue(
            &identity.actor_id,
            &identity.device_id,
            &public,
            iat - support::HOUR,
            iat + 30 * support::DAY,
        )
        .unwrap();
    member.update_credential(&token, None).unwrap();
    let renewal = member.refresh_credential(GROUP).unwrap();
    member.merge_pending_commit(GROUP).unwrap();
    renewal.commit
}

/// A device whose own leaf has lapsed still opens a newcomer's signed
/// `Joined` in the middle of a drain: the signal comes back, and the grant it
/// owes the newcomer, which it cannot seal on that leaf, is owed rather than
/// failing the open. The door the renewal's own epoch runs sends it, once.
#[test]
fn a_lapsed_device_opens_a_newcomers_joined_and_grants_it_once_renewed() {
    let mut all = members(2);
    join(&mut all, 0, "p-ada", "s-ada");

    // Day 25: Bo renews. Ada's credential still ends on day 30.
    support::advance_ms(25 * 24 * 3_600_000);
    let commit = renew_at(&mut all[1], 2, support::NOW + 25 * support::DAY);
    all[0].process_commit(GROUP, &commit).unwrap();
    // Day 31: Ada's leaf has lapsed on her own wall, not on the tree clock.
    support::advance_ms(6 * 24 * 3_600_000);
    assert!(matches!(
        all[0].encrypt(GROUP, b"x"),
        Err(peachy_mls_core::Error::CredentialRejected(
            peachy_mls_core::CredentialRejection::Expired
        ))
    ));

    all[1]
        .call_media_start(GROUP, &CALL_ID, "p-bo", "s-bo", &["s-bo-audio".into()])
        .unwrap();
    let bo_joined = signed_joined(&mut all[1], "p-bo", "s-bo");
    let opened = open(&mut all[0], &bo_joined);
    assert!(matches!(
        opened.signal.body,
        CallSignalBody::Joined { ref participant_id, .. } if participant_id == "p-bo"
    ));
    assert!(opened.send.is_empty(), "nothing seals on a lapsed leaf");
    // Bo's own grants still reach Ada; she owes nothing she can send yet.
    for grant in all[1].call_media_share(GROUP, &CALL_ID).unwrap() {
        assert!(open(&mut all[0], &grant).send.is_empty());
    }
    let ada_leaf = leaf(&all[0]);
    let before = frame(&mut all[0], &opus(1), 1);
    assert!(!opens(&keys(&mut all[1]), ada_leaf, &before));

    // Ada renews; the renewal's epoch door pays what she owes.
    let commit = renew_at(&mut all[0], 1, support::NOW + 31 * support::DAY);
    all[1].process_commit(GROUP, &commit).unwrap();
    let owed = all[0]
        .call_media_on_epoch(GROUP, &CALL_ID)
        .unwrap()
        .expect("the owed grants go");
    assert!(!owed.is_empty());
    for envelope in &owed {
        open(&mut all[1], envelope);
    }
    let after = frame(&mut all[0], &opus(2), 2);
    assert!(opens(&keys(&mut all[1]), ada_leaf, &after));
    // Paid once.
    assert!(all[0]
        .call_media_on_epoch(GROUP, &CALL_ID)
        .unwrap()
        .is_none_or(|send| send.is_empty()));
}
