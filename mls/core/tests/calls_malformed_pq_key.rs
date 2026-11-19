// SPDX-License-Identifier: MIT
//! A member's call key can cost only that member its grants
//! (docs/calls.md §Participant media keys).
//!
//! A signed `Joined` naming a 1216-byte X-Wing key whose ML-KEM part fails
//! the modulus check binds nothing, so no grant batch ever includes a key no
//! grant can be sealed to. Before, a receiver checked only the length, bound
//! the participant, and every later grant batch that included it failed as a
//! whole: after the first leave nobody read anybody, and no later joiner's
//! `share` reached anyone.

#![cfg(feature = "fixture")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::needless_range_loop)]

mod support;

use peachy_mls_core::call::{
    call_media_key_pair, call_media_pq_key_pair, seal_call_media_grant, CallSignal, CallSignalBody,
    MediaGrantPayload, OpenedCallSignal, Participation, CALL_MEDIA_PQ_PUBLIC_KEY_BYTES,
    CALL_MEDIA_ROTATE_DELAY_MS,
};
use peachy_mls_core::Client;
use support::{client, issuer};

const GROUP: &[u8] = b"calls-malformed-pq-key-group";
const CALL_ID: [u8; 16] = *b"calls-bad-pq-key";
const NAMES: [&str; 5] = ["ada", "bo", "cy", "di", "ed"];
const ADA: usize = 0;
const BO: usize = 1;
const CY: usize = 2;
const DI: usize = 3;
const ED: usize = 4;

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

/// Deliver `envelopes` from `from` to everyone in `to`, then whatever each
/// open owes, until nothing more is owed. Returns each refusal as
/// `(receiver, error)`.
fn settle(
    all: &mut [Client],
    from: usize,
    envelopes: Vec<Vec<u8>>,
    to: &[usize],
) -> Vec<(usize, String)> {
    let mut refused = Vec::new();
    let mut queue = vec![(from, envelopes)];
    while let Some((from, envelopes)) = queue.pop() {
        for envelope in &envelopes {
            for &i in to {
                if i == from {
                    continue;
                }
                match try_open(&mut all[i], envelope) {
                    Ok(opened) => {
                        if !opened.send.is_empty() {
                            queue.push((i, opened.send));
                        }
                    }
                    Err(err) => refused.push((i, format!("{err}"))),
                }
            }
        }
    }
    refused
}

fn joined(member: &Client, participant: &str) -> CallSignal {
    CallSignal::new(
        CALL_ID,
        CallSignalBody::Joined {
            participant_id: participant.into(),
            session_id: String::new(),
            track_names: Vec::new(),
            leaf_index: leaf(member),
            media_key: Vec::new(),
            started_at_ms: 0,
            media_key_pq: Vec::new(),
            participation: None,
        },
    )
}

/// An honest join: start, signed Joined, share. Returns the refusals any
/// open or the share met.
fn join(all: &mut [Client], i: usize, participant: &str, to: &[usize]) -> Vec<(usize, String)> {
    let session = format!("s-{participant}");
    all[i]
        .call_media_start(
            GROUP,
            &CALL_ID,
            participant,
            &session,
            &[format!("{session}-audio")],
        )
        .unwrap();
    let signal = joined(&all[i], participant);
    let envelope = all[i].seal_call_signal_on_mls_lane(GROUP, &signal).unwrap();
    let mut refused = settle(all, i, vec![envelope], to);
    match all[i].call_media_share(GROUP, &CALL_ID) {
        Ok(grants) => refused.extend(settle(all, i, grants, to)),
        Err(err) => refused.push((i, format!("share: {err}"))),
    }
    refused
}

/// Whether `all[rx]` installs the key `all[tx]` sends under now, at its slot.
fn reads(all: &mut [Client], rx: usize, tx: usize) -> bool {
    let keys = all[tx].call_media_keys(GROUP, &CALL_ID, false).unwrap();
    let own = keys
        .senders
        .iter()
        .find(|k| k.leaf_index == keys.own_leaf && k.key_index == keys.send_key_index)
        .unwrap();
    let (leaf, slot, key) = (keys.own_leaf, keys.send_key_index, *own.key);
    let keys = all[rx].call_media_keys(GROUP, &CALL_ID, false).unwrap();
    keys.senders
        .iter()
        .any(|k| k.leaf_index == leaf && k.key_index == slot && *k.key == key)
}

fn bound(all: &mut [Client], at: usize, participant: &str) -> bool {
    all[at]
        .call_media_keys(GROUP, &CALL_ID, false)
        .unwrap()
        .participants
        .iter()
        .any(|p| p.participant_id == participant)
}

/// Di, running its own code, takes call state and signs a `Joined` naming
/// `media_key_pq` under `participation`, as written.
fn di_joins_as_written(
    all: &mut [Client],
    media_key_pq: Vec<u8>,
    participation: Option<Participation>,
) -> Vec<(usize, String)> {
    all[DI]
        .call_media_start(GROUP, &CALL_ID, "p-di", "s-di", &[])
        .unwrap();
    let (_, x25519) = call_media_key_pair(&[0x43; 32]).unwrap();
    let forged = CallSignal::new(
        CALL_ID,
        CallSignalBody::Joined {
            participant_id: "p-di".into(),
            session_id: String::new(),
            track_names: Vec::new(),
            leaf_index: leaf(&all[DI]),
            media_key: x25519.to_vec(),
            started_at_ms: 1,
            media_key_pq,
            participation,
        },
    );
    let envelope = all[DI].seal_call_signal_as_written(GROUP, &forged).unwrap();
    settle(all, DI, vec![envelope], &[ADA, BO, CY, ED])
}

fn honest_three() -> Vec<Client> {
    let mut all = members(5);
    let everyone = [ADA, BO, CY, DI, ED];
    for (i, p) in [(ADA, "p-ada"), (BO, "p-bo"), (CY, "p-cy")] {
        assert!(join(&mut all, i, p, &everyone).is_empty());
    }
    for (rx, tx) in [(ADA, BO), (BO, ADA), (ADA, CY), (CY, BO)] {
        assert!(reads(&mut all, rx, tx), "{rx} reads {tx}");
    }
    all
}

#[test]
fn a_joined_naming_an_x_wing_key_no_grant_seals_to_binds_nothing_and_blocks_nobody() {
    let mut all = honest_three();
    let (_, good_pq) = call_media_pq_key_pair(&[0x42; 32]).unwrap();
    let mut bad_pq = good_pq;
    for b in &mut bad_pq[32..96] {
        *b = 0xFF;
    }
    assert_eq!(bad_pq.len(), CALL_MEDIA_PQ_PUBLIC_KEY_BYTES);
    let payload = MediaGrantPayload {
        generation: 1,
        secret: [9; 32].into(),
        session_id: "s".into(),
        track_names: vec![],
    };
    assert!(seal_call_media_grant(&bad_pq, &CALL_ID, 0, 1, &payload).is_err());

    let refused = di_joins_as_written(
        &mut all,
        bad_pq,
        Some(Participation {
            id: [7; 16],
            seq: 1,
        }),
    );
    for i in [ADA, BO, CY] {
        assert!(
            refused
                .iter()
                .any(|(at, why)| *at == i && why.contains("X-Wing")),
            "{i} refused Di's key: {refused:?}"
        );
        assert!(!bound(&mut all, i, "p-di"), "{i} bound nothing");
    }

    // Cy leaves: Ada's and Bo's rotations reach each other.
    let left = all[CY]
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
    assert!(settle(&mut all, CY, vec![left], &[ADA, BO]).is_empty());
    support::advance_ms(CALL_MEDIA_ROTATE_DELAY_MS + 1);
    for i in [ADA, BO] {
        let owed = all[i].call_media_apply(GROUP, &CALL_ID).unwrap();
        let from = i;
        let to: Vec<usize> = [ADA, BO].into_iter().filter(|x| *x != from).collect();
        assert!(settle(&mut all, from, owed, &to).is_empty());
    }
    assert!(reads(&mut all, BO, ADA), "Bo reads Ada after the rotation");
    assert!(reads(&mut all, ADA, BO), "Ada reads Bo after the rotation");

    // Ed joins honestly: his share reaches Ada and Bo.
    let refused = join(&mut all, ED, "p-ed", &[ADA, BO, DI]);
    assert!(
        !refused
            .iter()
            .any(|(i, _)| *i == ED || *i == ADA || *i == BO),
        "Ed's join and share go through: {refused:?}"
    );
    assert!(reads(&mut all, ADA, ED), "Ada reads Ed");
    assert!(reads(&mut all, BO, ED), "Bo reads Ed");
}

/// Each grant is sealed on its own: should a bound key be one no grant can
/// be sealed to, that peer goes without its grant, and the rest of the
/// batch still goes. Binding checks the key, so the test puts the bad key
/// in place behind it.
#[test]
fn a_key_no_grant_seals_to_costs_only_that_peer_its_grant() {
    let mut all = honest_three();
    assert!(join(&mut all, ED, "p-ed", &[ADA, BO, CY, DI, ED])
        .iter()
        .all(|(i, _)| *i == DI));
    assert!(reads(&mut all, ED, ADA), "Ed reads Ada");

    let (_, good_pq) = call_media_pq_key_pair(&[0x44; 32]).unwrap();
    let mut bad_pq = good_pq;
    for b in &mut bad_pq[32..96] {
        *b = 0xFF;
    }
    let bo_leaf = leaf(&all[BO]);
    assert!(all[ADA].call_media_replace_peer_key_as_written(GROUP, &CALL_ID, bo_leaf, bad_pq));

    // Cy leaves: Ada's rotation is granted to Bo and Ed in one batch.
    let left = all[CY]
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
    let refused = settle(&mut all, CY, vec![left], &[ADA, BO, ED]);
    assert!(
        !refused.iter().any(|(i, _)| *i == ADA || *i == ED),
        "{refused:?}"
    );
    support::advance_ms(CALL_MEDIA_ROTATE_DELAY_MS + 1);
    let owed = all[ADA].call_media_apply(GROUP, &CALL_ID).unwrap();
    let refused = settle(&mut all, ADA, owed, &[BO, ED]);
    assert!(!refused.iter().any(|(i, _)| *i == ED), "{refused:?}");

    assert!(reads(&mut all, ED, ADA), "Ed reads Ada after the rotation");
    assert!(
        !reads(&mut all, BO, ADA),
        "Bo, whose key took no grant, does not"
    );
}
