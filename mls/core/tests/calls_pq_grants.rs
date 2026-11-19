// SPDX-License-Identifier: MIT
//! A CALL'S MEDIA KEYS ARE GRANTED POST-QUANTUM (docs/calls.md
//! §Participant media keys).
//!
//! 1. A participant's signed `Joined` names an X-Wing call key beside its
//!    X25519 one; a live heartbeat names none (it binds nothing, and stays
//!    under the ephemeral frame cap).
//! 2. Every grant to a participant that named an X-Wing key is sealed to it:
//!    the join's, the newcomer's advance and the leaver's rotation. A grant
//!    recorded today stays closed to the group's other members with a
//!    quantum computer later.
//! 3. A core binds no `Joined` without the X-Wing key or with a session,
//!    and takes no classical grant, so neither the shared key nor a
//!    classical grant is ever in use.
//! 4. A rotation to many participants splits into signals that each fit a
//!    call link log's 16 KiB entry.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::needless_range_loop,
    clippy::assertions_on_constants
)]

mod support;

use openmls_rust_crypto::RustCrypto;
use openmls_traits::crypto::OpenMlsCrypto as _;
use peachy_mls_core::call::{
    call_media_grant_info, call_media_key_pair, call_media_pq_key_pair, decode_call_signal,
    encode_call_signal, encode_media_grant_payload, open_call_media_grant, seal_call_media_grant,
    signal_from_json, signal_to_json, CallSignal, CallSignalBody, MediaGrant, MediaGrantPayload,
    OpenedCallSignal, Participation, CALL_MEDIA_HPKE, CALL_MEDIA_PQ_ENC_BYTES,
    CALL_MEDIA_PQ_PUBLIC_KEY_BYTES, CALL_MEDIA_PUBLIC_KEY_BYTES, CALL_MEDIA_ROTATE_DELAY_MS,
};
use peachy_mls_core::Client;
use support::{client, issuer};

const GROUP: &[u8] = b"peachy-call-pq-grants";

/// A grant sealed to an X25519 call key, as a peer running its own code
/// could seal one: the HPKE `seal_call_media_grant` would use, under the
/// classical suite it refuses.
fn classical_grant(
    public_key: &[u8],
    call_id: &[u8],
    sender_leaf: u32,
    to_leaf: u32,
    payload: &MediaGrantPayload,
) -> (Vec<u8>, Vec<u8>) {
    assert!(seal_call_media_grant(public_key, call_id, sender_leaf, to_leaf, payload).is_err());
    let sealed = RustCrypto::default()
        .hpke_seal(
            CALL_MEDIA_HPKE,
            public_key,
            &call_media_grant_info(call_id, sender_leaf, to_leaf),
            &[],
            &encode_media_grant_payload(payload).unwrap(),
        )
        .unwrap();
    (
        sealed.kem_output.as_slice().to_vec(),
        sealed.ciphertext.as_slice().to_vec(),
    )
}
const CALL_ID: [u8; 16] = *b"pq-grants-call!!";
const NAMES: [&str; 10] = [
    "ada", "bo", "cy", "di", "ed", "flo", "gus", "hal", "ivy", "jo",
];

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

fn try_open(
    member: &mut Client,
    envelope: &[u8],
) -> peachy_mls_core::error::Result<OpenedCallSignal> {
    let inner = member.open_envelope(envelope).unwrap().unwrap().inner;
    member.open_call_signal(GROUP, &inner)
}

fn open(member: &mut Client, envelope: &[u8]) -> OpenedCallSignal {
    try_open(member, envelope).unwrap()
}

/// Every `MediaKey` grant any member opened while settling, as
/// `(sender_leaf, grant)`.
type Seen = Vec<(u32, MediaGrant)>;

fn deliver(
    all: &mut [Client],
    from: usize,
    envelopes: &[Vec<u8>],
    seen: &mut Seen,
) -> Vec<(usize, Vec<Vec<u8>>)> {
    let mut owed = Vec::new();
    let watcher = (from + 1) % all.len();
    for envelope in envelopes {
        for (i, member) in all.iter_mut().enumerate() {
            if i == from {
                continue;
            }
            let opened = open(member, envelope);
            if i == watcher {
                if let CallSignalBody::MediaKey { grants, .. } = &opened.signal.body {
                    for grant in grants {
                        seen.push((opened.sender_leaf.unwrap(), grant.clone()));
                    }
                }
            }
            if !opened.send.is_empty() {
                owed.push((i, opened.send));
            }
        }
    }
    owed
}

fn settle(all: &mut [Client], from: usize, envelopes: Vec<Vec<u8>>, seen: &mut Seen) {
    let mut queue = vec![(from, envelopes)];
    while let Some((from, envelopes)) = queue.pop() {
        queue.extend(deliver(all, from, &envelopes, seen));
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

fn join(all: &mut [Client], i: usize, participant: &str, session: &str, seen: &mut Seen) {
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
    settle(all, i, vec![envelope], seen);
    let grants = all[i].call_media_share(GROUP, &CALL_ID).unwrap();
    settle(all, i, grants, seen);
}

fn keyed(member: &mut Client) -> Vec<(u32, bool)> {
    member
        .call_media_keys(GROUP, &CALL_ID, false)
        .unwrap()
        .participants
        .iter()
        .map(|p| (p.leaf_index, p.keyed))
        .collect()
}

/// A device on a v2 build that predates the X-Wing call key: its signed
/// `Joined` names an X25519 call key of its own and no session. Made here
/// by a member running its own code, the X25519 key pair in the test's
/// hands. Returns its private key and the envelope.
fn classical_v2_joined(member: &mut Client, participant: &str) -> (Vec<u8>, Vec<u8>) {
    let (private_key, public_key) = call_media_key_pair(&[0x51; 32]).unwrap();
    let signal = CallSignal::new(
        CALL_ID,
        CallSignalBody::Joined {
            participant_id: participant.into(),
            session_id: String::new(),
            track_names: Vec::new(),
            leaf_index: leaf(member),
            media_key: public_key.to_vec(),
            started_at_ms: 0,
            media_key_pq: Vec::new(),
            participation: Some(Participation {
                id: [0x51; 16],
                seq: 1,
            }),
        },
    );
    let envelope = member.seal_call_signal_as_written(GROUP, &signal).unwrap();
    (private_key, envelope)
}

#[test]
fn a_signed_joined_names_an_x_wing_call_key_and_a_live_one_does_not() {
    let mut all = members(2);
    all[0]
        .call_media_start(GROUP, &CALL_ID, "p-ada", "s-ada", &["s-ada-audio".into()])
        .unwrap();
    let signal = joined(&all[0], "p-ada", "s-ada");
    let signed = all[0].seal_call_signal_on_mls_lane(GROUP, &signal).unwrap();
    let opened = open(&mut all[1], &signed);
    let CallSignalBody::Joined {
        media_key,
        media_key_pq,
        session_id,
        ..
    } = &opened.signal.body
    else {
        panic!("a Joined");
    };
    assert_eq!(media_key.len(), CALL_MEDIA_PUBLIC_KEY_BYTES);
    assert_eq!(media_key_pq.len(), CALL_MEDIA_PQ_PUBLIC_KEY_BYTES);
    assert!(session_id.is_empty(), "a v2 Joined carries no session");

    let live = all[0].seal_call_signal(GROUP, &signal).unwrap();
    let opened = open(&mut all[1], &live);
    let CallSignalBody::Joined { media_key_pq, .. } = &opened.signal.body else {
        panic!("a Joined");
    };
    assert!(
        media_key_pq.is_empty(),
        "a live heartbeat names no X-Wing key"
    );
    assert!(
        live.len() <= 4096,
        "a live Joined fits the server's ephemeral frame cap: {} bytes",
        live.len()
    );
}

#[test]
fn every_grant_to_a_participant_with_an_x_wing_key_is_post_quantum() {
    let mut all = members(4);
    let mut seen = Seen::new();
    join(&mut all, 0, "p-ada", "s-ada", &mut seen);
    join(&mut all, 1, "p-bo", "s-bo", &mut seen);
    join(&mut all, 2, "p-cy", "s-cy", &mut seen);
    // Everyone holds everyone's key.
    for i in 0..3 {
        let keyed = keyed(&mut all[i]);
        assert_eq!(keyed.len(), 2, "member {i} lists the other two");
        assert!(
            keyed.iter().all(|(_, k)| *k),
            "member {i} is keyed: {keyed:?}"
        );
    }
    // A leaver's rotation is granted too.
    let left = all[2]
        .seal_call_signal_on_mls_lane(
            GROUP,
            &CallSignal::new(
                CALL_ID,
                CallSignalBody::Left {
                    participant_id: "p-cy".into(),
                },
            ),
        )
        .unwrap();
    settle(&mut all, 2, vec![left], &mut seen);
    assert!(
        seen.len() >= 5,
        "the joins and the rotation granted keys: {}",
        seen.len()
    );
    for (sender, grant) in &seen {
        assert_eq!(
            grant.enc.len(),
            CALL_MEDIA_PQ_ENC_BYTES,
            "the grant from leaf {sender} to leaf {} is X-Wing",
            grant.to_leaf
        );
    }
    // After the rotation the two that remain still read each other.
    support::advance_ms(CALL_MEDIA_ROTATE_DELAY_MS);
    for i in 0..2 {
        let keyed = keyed(&mut all[i]);
        assert_eq!(keyed.len(), 1);
        assert!(keyed[0].1);
    }
}

#[test]
fn an_x_wing_grant_opens_only_with_its_own_private_key_and_context() {
    let (pq_private, pq_public) = call_media_pq_key_pair(&[7; 32]).unwrap();
    let (classical_private, _) = call_media_key_pair(&[7; 32]).unwrap();
    assert_eq!(pq_public.len(), CALL_MEDIA_PQ_PUBLIC_KEY_BYTES);
    let payload = MediaGrantPayload {
        generation: 3,
        secret: [9; 32].into(),
        session_id: "s".into(),
        track_names: vec!["t".into()],
    };
    let (enc, ciphertext) = seal_call_media_grant(&pq_public, &CALL_ID, 1, 2, &payload).unwrap();
    assert_eq!(enc.len(), CALL_MEDIA_PQ_ENC_BYTES);
    let opened = open_call_media_grant(&pq_private, &CALL_ID, 1, 2, &enc, &ciphertext).unwrap();
    assert_eq!(opened, payload);
    // Another leaf, another call, another key: nothing opens.
    assert!(open_call_media_grant(&pq_private, &CALL_ID, 2, 2, &enc, &ciphertext).is_err());
    assert!(
        open_call_media_grant(&pq_private, b"another-call-id!", 1, 2, &enc, &ciphertext).is_err()
    );
    assert!(open_call_media_grant(&classical_private, &CALL_ID, 1, 2, &enc, &ciphertext).is_err());
    let (other_private, _) = call_media_pq_key_pair(&[8; 32]).unwrap();
    assert!(open_call_media_grant(&other_private, &CALL_ID, 1, 2, &enc, &ciphertext).is_err());
}

#[test]
fn the_codec_carries_x_wing_keys_and_grants_where_a_reader_without_them_skips_them() {
    let joined = CallSignal::new(
        CALL_ID,
        CallSignalBody::Joined {
            participant_id: "p".into(),
            session_id: String::new(),
            track_names: Vec::new(),
            leaf_index: 1,
            media_key: vec![1; CALL_MEDIA_PUBLIC_KEY_BYTES],
            started_at_ms: 5,
            media_key_pq: vec![2; CALL_MEDIA_PQ_PUBLIC_KEY_BYTES],
            participation: None,
        },
    );
    let bytes = encode_call_signal(&joined).unwrap();
    assert_eq!(decode_call_signal(&bytes).unwrap(), joined);
    assert_eq!(
        signal_from_json(&signal_to_json(&joined).unwrap()).unwrap(),
        joined
    );
    // An X-Wing key never comes alone, nor at another length.
    for (classical, pq) in [
        (Vec::new(), vec![2; CALL_MEDIA_PQ_PUBLIC_KEY_BYTES]),
        (vec![1; CALL_MEDIA_PUBLIC_KEY_BYTES], vec![2; 32]),
    ] {
        let bad = CallSignal::new(
            CALL_ID,
            CallSignalBody::Joined {
                participant_id: "p".into(),
                session_id: String::new(),
                track_names: Vec::new(),
                leaf_index: 1,
                media_key: classical,
                started_at_ms: 5,
                media_key_pq: pq,
                participation: None,
            },
        );
        assert!(encode_call_signal(&bad).is_err());
    }
    // A MediaKey mixing kinds: classical grants in field 3, X-Wing ones in
    // field 5, each list in order.
    let classical = |to_leaf| MediaGrant {
        to_leaf,
        enc: vec![3; CALL_MEDIA_PUBLIC_KEY_BYTES],
        ciphertext: vec![4; 60],
    };
    let pq = |to_leaf| MediaGrant {
        to_leaf,
        enc: vec![5; CALL_MEDIA_PQ_ENC_BYTES],
        ciphertext: vec![6; 60],
    };
    let mixed = CallSignal::new(
        CALL_ID,
        CallSignalBody::MediaKey {
            generation: 1,
            rotated: true,
            grants: vec![classical(1), pq(2), classical(3), pq(4)],
            started_at_ms: 5,
            participation: None,
        },
    );
    let bytes = encode_call_signal(&mixed).unwrap();
    let CallSignalBody::MediaKey { grants, .. } = decode_call_signal(&bytes).unwrap().body else {
        panic!("a MediaKey");
    };
    let order: Vec<(u32, usize)> = grants.iter().map(|g| (g.to_leaf, g.enc.len())).collect();
    assert_eq!(
        order,
        vec![
            (1, CALL_MEDIA_PUBLIC_KEY_BYTES),
            (3, CALL_MEDIA_PUBLIC_KEY_BYTES),
            (2, CALL_MEDIA_PQ_ENC_BYTES),
            (4, CALL_MEDIA_PQ_ENC_BYTES),
        ]
    );
    // What a build that predates field 5 reads: the grants of field 3 only,
    // every one of them a 32-byte enc it accepts.
    let field3_only = strip_field(&bytes, 5);
    let CallSignalBody::MediaKey { grants, .. } = decode_call_signal(&field3_only).unwrap().body
    else {
        panic!("a MediaKey");
    };
    assert!(grants
        .iter()
        .all(|g| g.enc.len() == CALL_MEDIA_PUBLIC_KEY_BYTES));
    assert_eq!(grants.len(), 2);
    // A grant of another enc length is refused.
    let odd = CallSignal::new(
        CALL_ID,
        CallSignalBody::MediaKey {
            generation: 1,
            rotated: false,
            grants: vec![MediaGrant {
                to_leaf: 1,
                enc: vec![1; 64],
                ciphertext: vec![1; 8],
            }],
            started_at_ms: 0,
            participation: None,
        },
    );
    assert!(encode_call_signal(&odd).is_err());
}

/// The signal with every `field` of its body message dropped: what a build
/// that does not know the field reads. Walks `CallSignal`'s length-delimited
/// body (field 14, a `MediaKey`).
fn strip_field(signal: &[u8], field: u64) -> Vec<u8> {
    fn varint(bytes: &[u8], at: &mut usize) -> u64 {
        let mut out = 0u64;
        let mut shift = 0;
        loop {
            let b = bytes[*at];
            *at += 1;
            out |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return out;
            }
            shift += 7;
        }
    }
    fn put_varint(out: &mut Vec<u8>, mut v: u64) {
        while v >= 0x80 {
            out.push(u8::try_from(v & 0x7f).unwrap() | 0x80);
            v >>= 7;
        }
        out.push(u8::try_from(v).unwrap());
    }
    fn fields(bytes: &[u8]) -> Vec<(u64, u64, Vec<u8>)> {
        let mut at = 0;
        let mut out = Vec::new();
        while at < bytes.len() {
            let key = varint(bytes, &mut at);
            let (n, wire) = (key >> 3, key & 7);
            let start = at;
            match wire {
                0 => {
                    varint(bytes, &mut at);
                }
                2 => {
                    let len = usize::try_from(varint(bytes, &mut at)).unwrap();
                    at += len;
                }
                _ => panic!("unexpected wire type"),
            }
            out.push((n, wire, bytes[start..at].to_vec()));
        }
        out
    }
    let mut out = Vec::new();
    for (n, wire, raw) in fields(signal) {
        put_varint(&mut out, (n << 3) | wire);
        if n == 14 && wire == 2 {
            let mut at = 0;
            let len = usize::try_from(varint(&raw, &mut at)).unwrap();
            let body = &raw[at..at + len];
            let mut inner = Vec::new();
            for (m, w, r) in fields(body) {
                if m == field {
                    continue;
                }
                put_varint(&mut inner, (m << 3) | w);
                inner.extend_from_slice(&r);
            }
            put_varint(&mut out, u64::try_from(inner.len()).unwrap());
            out.extend_from_slice(&inner);
        } else {
            out.extend_from_slice(&raw);
        }
    }
    out
}

/// Ada's own signed `Joined` as Bo sees it: Ada seals it again (a v2
/// participant's `Joined` goes again at every epoch) and Bo opens it.
fn ada_joined_seen_by(all: &mut [Client]) -> CallSignalBody {
    let signal = joined(&all[0], "p-ada", "s-ada");
    let envelope = all[0].seal_call_signal_on_mls_lane(GROUP, &signal).unwrap();
    open(&mut all[1], &envelope).signal.body
}

/// The participation start an opened `Joined` names: its sender's core
/// stamps it, and a `MediaKey` from that participation names the same.
fn started_at(body: &CallSignalBody) -> u64 {
    match body {
        CallSignalBody::Joined { started_at_ms, .. } => *started_at_ms,
        _ => panic!("a Joined"),
    }
}

#[test]
fn a_core_binds_no_classical_or_keyless_joined() {
    let mut all = members(3);
    all[0]
        .call_media_start(GROUP, &CALL_ID, "p-ada", "s-ada", &["s-ada-audio".into()])
        .unwrap();
    let signal = joined(&all[0], "p-ada", "s-ada");
    let envelope = all[0].seal_call_signal_on_mls_lane(GROUP, &signal).unwrap();
    for member in all.iter_mut().skip(1) {
        open(member, &envelope);
    }
    // A v2 build without the X-Wing key: refused.
    let (_, classical) = classical_v2_joined(&mut all[1], "p-bo");
    assert!(try_open(&mut all[0], &classical).is_err());
    // A keyless Joined with its session: refused.
    let cy_joined = joined(&all[2], "p-cy", "s-cy");
    let keyless = all[2]
        .seal_call_signal_as_written(GROUP, &cy_joined)
        .unwrap();
    assert!(try_open(&mut all[0], &keyless).is_err());
    // Nobody was bound.
    let keys = all[0].call_media_keys(GROUP, &CALL_ID, false).unwrap();
    assert!(keys.participants.is_empty());
}

#[test]
fn a_core_takes_no_classical_grant() {
    {
        let mut all = members(2);
        let mut seen = Seen::new();
        join(&mut all, 0, "p-ada", "s-ada", &mut seen);
        let ada_leaf = leaf(&all[0]);
        let bo_leaf = leaf(&all[1]);
        // Bo runs its own code: a signed Joined with both keys, then a grant
        // to Ada sealed to her X25519 key rather than her X-Wing one.
        let (_, bo_classical) = call_media_key_pair(&[0x61; 32]).unwrap();
        let (_, bo_pq) = call_media_pq_key_pair(&[0x62; 32]).unwrap();
        let bo_mark = Some(Participation {
            id: [0x63; 16],
            seq: 1,
        });
        let bo_joined = all[1]
            .seal_call_signal_as_written(
                GROUP,
                &CallSignal::new(
                    CALL_ID,
                    CallSignalBody::Joined {
                        participant_id: "p-bo".into(),
                        session_id: String::new(),
                        track_names: Vec::new(),
                        leaf_index: bo_leaf,
                        media_key: bo_classical.to_vec(),
                        started_at_ms: 0,
                        media_key_pq: bo_pq,
                        participation: bo_mark,
                    },
                ),
            )
            .unwrap();
        let opened = open(&mut all[0], &bo_joined);
        let bo_started = started_at(&opened.signal.body);
        // Ada's own grant to Bo is X-Wing either way.
        for envelope in &opened.send {
            if let CallSignalBody::MediaKey { grants, .. } = open(&mut all[1], envelope).signal.body
            {
                assert!(grants
                    .iter()
                    .all(|g| g.enc.len() == CALL_MEDIA_PQ_ENC_BYTES));
            }
        }
        let CallSignalBody::Joined {
            media_key: ada_key, ..
        } = ada_joined_seen_by(&mut all)
        else {
            panic!("a Joined");
        };
        let (enc, ciphertext) = classical_grant(
            &ada_key,
            &CALL_ID,
            bo_leaf,
            ada_leaf,
            &MediaGrantPayload {
                generation: 0,
                secret: [0x78; 32].into(),
                session_id: "s-bo".into(),
                track_names: Vec::new(),
            },
        );
        let grant = all[1]
            .seal_call_signal_on_mls_lane(
                GROUP,
                &CallSignal::new(
                    CALL_ID,
                    CallSignalBody::MediaKey {
                        generation: 0,
                        rotated: false,
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
        assert!(opened.media.is_none(), "a classical grant counted");
        assert_eq!(keyed(&mut all[0]), vec![(bo_leaf, false)]);
    }
}

#[test]
fn grants_to_many_participants_split_into_signals_that_fit_a_call_link_log_entry() {
    let mut all = members(10);
    let mut seen = Seen::new();
    for i in 0..9 {
        join(
            &mut all,
            i,
            &format!("p-{}", NAMES[i]),
            &format!("s-{}", NAMES[i]),
            &mut seen,
        );
    }
    // The tenth joins: its share grants nine participants, post-quantum.
    all[9]
        .call_media_start(GROUP, &CALL_ID, "p-jo", "s-jo", &["s-jo-audio".into()])
        .unwrap();
    let signal = joined(&all[9], "p-jo", "s-jo");
    let envelope = all[9].seal_call_signal_on_mls_lane(GROUP, &signal).unwrap();
    settle(&mut all, 9, vec![envelope], &mut seen);
    let share = all[9].call_media_share(GROUP, &CALL_ID).unwrap();
    assert!(
        share.len() >= 2,
        "nine X-Wing grants take more than one signal: {}",
        share.len()
    );
    for envelope in &share {
        assert!(
            envelope.len() < 16 * 1024,
            "a MediaKey envelope ({} bytes) fits a call link log entry with its tag",
            envelope.len()
        );
    }
    settle(&mut all, 9, share, &mut seen);
    // Every one of the nine holds the newcomer's key.
    for (i, member) in all.iter_mut().enumerate().take(9) {
        let keys = member.call_media_keys(GROUP, &CALL_ID, false).unwrap();
        let jo = keys
            .participants
            .iter()
            .find(|p| p.participant_id == "p-jo")
            .unwrap();
        assert!(jo.keyed, "member {i} holds the newcomer's key");
    }
}
