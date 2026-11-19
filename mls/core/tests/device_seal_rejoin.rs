// SPDX-License-Identifier: MIT
//! WHAT A DEVICE MISSED, TOLD BY ITS SENDER ALONE (`mls/core/src/device_seal.rs`;
//! `Client::hold_envelope_sealed`, `Client::next_reopenable`).
//!
//! A version 3 envelope sealed to a copy that forked or fell behind opens for
//! nothing it holds. The gap block (`rejoin_gap.rs`) hands the missed epochs
//! back, but only if the member that reseats the device has them and puts
//! them in. The device seal rides beside the envelope, sealed to the
//! recipient device's own key by the sender: it names the group, the sender
//! and the epoch secret, so the device keeps the envelope and opens it once
//! it is back, with no other member in the path, and is not left to lose it
//! to the hold's count or age.

#![cfg(feature = "test-forgery")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use peachy_mls_core::envelope::{ENVELOPE_KIND_COMMIT, ENVELOPE_KIND_MESSAGE};
use peachy_mls_core::hint::{peek_message, resend_author_commitment, CONTENT_HINT_RESENDABLE};
use peachy_mls_core::{
    device_seal, device_seal_open, Client, Error, HeldDisposition, HeldFate, HoldAnswer, Incoming,
    MemoryKv, PeachyStorage, HELD_ENVELOPE_MAX_AGE_MS,
};
use support::{client, client_on, device_seed, issuer, RemoveLeaf, NOW};

const G: &[u8] = b"3f0d9c1e-6a2b-4c7d-8e5f-0a1b2c3d4e5f";
const H: &[u8] = b"9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d";
const MAILBOX_MESSAGE: u8 = 1;
const ID: &str = "0b7e5a52-3c1d-4f2e-9a8b-7c6d5e4f3a2b";

fn received_at() -> u64 {
    u64::try_from(NOW * 1000).unwrap()
}

fn key_of(tag: u8) -> Vec<u8> {
    peachy_mls_core::issuer::device_key_pair(&device_seed(tag))
        .1
        .to_vec()
}

fn group(ada: &mut Client, others: &mut [&mut Client]) {
    ada.create_group(G).unwrap();
    for i in 0..others.len() {
        let kp = others[i].generate_key_package().unwrap();
        let b = ada.add_member(G, &kp).unwrap();
        ada.merge_pending_commit(G).unwrap();
        for x in others.iter_mut().take(i) {
            x.process_commit(G, &b.commit).unwrap();
        }
        others[i].join_from_welcome(&b.welcome.unwrap()).unwrap();
    }
}

/// A resendable message `sender` seals to the group, with the seal it makes
/// for the device whose key is `to`.
fn sent(sender: &mut Client, text: &str, to: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let frame = [
        vec![0xFF, 0x01],
        format!(r#"{{"i":"{ID}","t":"{text}"}}"#).into_bytes(),
    ]
    .concat();
    let message = sender
        .encrypt_with_hint(G, &frame, CONTENT_HINT_RESENDABLE)
        .unwrap();
    let envelope = sender
        .seal_envelope(G, ENVELOPE_KIND_MESSAGE, &message)
        .unwrap();
    let seal = sender
        .device_seals(G, &envelope)
        .unwrap()
        .into_iter()
        .find(|(key, _)| key == to)
        .expect("a seal for every other leaf")
        .1;
    assert_eq!(seal.len(), peachy_mls_core::DEVICE_SEAL_BYTES);
    (envelope, seal)
}

fn fork_cy(ada: &mut Client, bo: &mut Client, cy: &mut Client) {
    cy.self_update(G).unwrap();
    cy.merge_pending_commit(G).unwrap();
    let main_line = ada.self_update(G).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &main_line.commit).unwrap();
}

fn reseat_cy(ada: &mut Client, bo: &mut Client, cy: &mut Client) {
    cy.forget_group(G).unwrap();
    let kp = cy.generate_key_package().unwrap();
    let cy_leaf = ada.leaf_of_device(G, "device-cy").unwrap();
    let back = ada.replace_member(G, cy_leaf, &kp).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &back.commit).unwrap();
    cy.join_from_welcome(&back.welcome.unwrap()).unwrap();
}

fn assert_from_ada(cy: &mut Client, envelope: &[u8]) {
    let opened = cy
        .open_envelope(envelope)
        .unwrap()
        .expect("opens on the secret its seal carried");
    assert_eq!(opened.group_id, G);
    assert_eq!(opened.kind, ENVELOPE_KIND_MESSAGE);
    let peek = peek_message(&opened.inner).expect("a group message");
    assert_eq!(peek.hint, Some(CONTENT_HINT_RESENDABLE));
    assert_eq!(
        peek.commitment,
        Some(resend_author_commitment(G, "actor-ada", ID.as_bytes())),
        "it commits to Ada"
    );
}

/// THE ONE THIS FILE EXISTS FOR. The member that reseats Cy hands back no
/// gap, which left the envelope unopened for good (`rejoin_gap.rs`). Its
/// seal makes up for it: Cy keeps the envelope, waits while its copy is
/// still the fork, and opens it once it is back.
#[test]
fn a_forked_device_learns_what_it_missed_from_the_sender_alone() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = client(&s, 3, "actor-cy", "device-cy");
    group(&mut ada, &mut [&mut bo, &mut cy]);
    ada.act_as_member_handing_back_no_gap();

    fork_cy(&mut ada, &mut bo, &mut cy);
    let (missed, seal) = sent(&mut ada, "while you were out of step", &key_of(3));
    assert!(cy.open_envelope(&missed).unwrap().is_none(), "Cy forked");
    assert!(cy
        .hold_envelope_sealed(MAILBOX_MESSAGE, "env-missed", received_at(), &missed, &seal)
        .unwrap()
        .is_kept());
    assert!(
        cy.next_reopenable().unwrap().is_none(),
        "Cy's copy is the fork, at the very epoch: it waits"
    );

    reseat_cy(&mut ada, &mut bo, &mut cy);
    let held = cy
        .next_reopenable()
        .unwrap()
        .expect("handed out once Cy is back, with no gap handed back");
    assert_eq!(held.id, "env-missed");
    assert!(
        cy.next_reopenable().unwrap().is_none(),
        "handed out once in the pass"
    );
    assert_from_ada(&mut cy, &held.envelope);
    assert!(
        cy.process_message(G, &cy.open_envelope(&held.envelope).unwrap().unwrap().inner)
            .is_err(),
        "the message itself stays sealed to an epoch Cy never held"
    );
    assert!(cy.release_held("env-missed").unwrap());
    assert!(
        cy.open_envelope(&held.envelope).unwrap().is_none(),
        "released: the grant is spent"
    );
}

/// Every envelope handed out on its seal opens until it is released, however
/// many are handed out first: a client that takes a whole pass's worth
/// before opening any (two hundred) loses none of them.
#[test]
fn two_hundred_handed_out_before_any_opens_all_open() {
    const SENT: usize = 200;
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = client(&s, 3, "actor-cy", "device-cy");
    group(&mut ada, &mut [&mut bo, &mut cy]);
    ada.act_as_member_handing_back_no_gap();

    fork_cy(&mut ada, &mut bo, &mut cy);
    let mut envelopes = Vec::new();
    for n in 0..SENT {
        let (missed, seal) = sent(&mut ada, &format!("missed {n}"), &key_of(3));
        assert!(cy
            .hold_envelope_sealed(
                MAILBOX_MESSAGE,
                &format!("env-{n:03}"),
                received_at() + u64::try_from(n).unwrap(),
                &missed,
                &seal
            )
            .unwrap()
            .is_kept());
        envelopes.push(missed);
    }
    reseat_cy(&mut ada, &mut bo, &mut cy);

    let mut handed = Vec::new();
    while let Some(held) = cy.next_reopenable().unwrap() {
        handed.push(held);
    }
    assert_eq!(
        handed.len(),
        SENT,
        "every sealed one, none dropped at the 100"
    );
    for held in &handed {
        assert_from_ada(&mut cy, &held.envelope);
    }
    for held in &handed {
        assert!(cy.release_held(&held.id).unwrap());
    }
    for envelope in &envelopes {
        assert!(cy.open_envelope(envelope).unwrap().is_none(), "all spent");
    }
}

/// A process that dies between handing a sealed envelope out and storing
/// what it made of it loses nothing: the seal's record stays until the
/// release, so the envelope is handed out again after the restart, granted
/// again, and opens.
#[test]
fn a_sealed_envelope_survives_a_death_before_its_placeholder_is_stored() {
    let s = issuer();
    let cy_kv = MemoryKv::new();
    let cy_on = |kv: &MemoryKv| {
        client_on(
            &s,
            3,
            "actor-cy",
            "device-cy",
            PeachyStorage::open(Box::new(kv.clone())).unwrap(),
        )
    };
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = cy_on(&cy_kv);
    group(&mut ada, &mut [&mut bo, &mut cy]);
    ada.act_as_member_handing_back_no_gap();

    fork_cy(&mut ada, &mut bo, &mut cy);
    let (missed, seal) = sent(&mut ada, "while you were out of step", &key_of(3));
    assert!(cy
        .hold_envelope_sealed(MAILBOX_MESSAGE, "env-missed", received_at(), &missed, &seal)
        .unwrap()
        .is_kept());
    reseat_cy(&mut ada, &mut bo, &mut cy);

    let held = cy
        .next_reopenable()
        .unwrap()
        .expect("opens once Cy is back");
    assert_from_ada(&mut cy, &held.envelope);
    // The process dies here, before the placeholder is written.
    drop(cy);

    let mut cy = cy_on(&cy_kv);
    assert!(
        cy.open_envelope(&missed).unwrap().is_none(),
        "no grant survives in memory"
    );
    let again = cy
        .next_reopenable()
        .unwrap()
        .expect("handed out again after the restart");
    assert_eq!(again, held);
    assert_from_ada(&mut cy, &again.envelope);
    assert!(cy.release_held("env-missed").unwrap());
    drop(cy);

    let mut cy = cy_on(&cy_kv);
    assert!(cy.next_reopenable().unwrap().is_none(), "released for good");
    assert!(cy.open_envelope(&missed).unwrap().is_none());
}

/// A seal is a member's word, not proof of who wrote the message inside. Bo
/// wraps a message of Ada's that Cy never got in an envelope of his own
/// keying and seals it to Cy as his: once the message opens, its author is
/// Ada, not the seal's sender, and it is refused as from no member, with
/// its key unspent. Bo's seal, delivered first, does not keep out Ada's
/// own: the same bytes under her seal are held again, and open to her
/// words. The same wrap sealed by Ada herself goes through.
#[test]
fn a_seal_whose_sender_is_not_the_message_author_is_refused() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = client(&s, 3, "actor-cy", "device-cy");
    group(&mut ada, &mut [&mut bo, &mut cy]);

    let long_ago = received_at() - HELD_ENVELOPE_MAX_AGE_MS - 1;
    let wrap = |sender_tag: u8, message: &[u8], secret: [u8; 32]| {
        let envelope =
            peachy_mls_core::envelope::seal_epoch_envelope(&secret, ENVELOPE_KIND_MESSAGE, message)
                .unwrap();
        let seal =
            device_seal(&device_seed(sender_tag), &key_of(3), G, &secret, &envelope).unwrap();
        (envelope, seal)
    };

    let adas = ada.encrypt(G, b"Ada's own words").unwrap();
    let (by_bo, bo_seal) = wrap(2, &adas, [0x5a; 32]);
    assert!(cy.open_envelope(&by_bo).unwrap().is_none());
    assert!(cy
        .hold_envelope_sealed(MAILBOX_MESSAGE, "env-bo", long_ago, &by_bo, &bo_seal)
        .unwrap()
        .is_kept());
    let held = cy
        .next_reopenable()
        .unwrap()
        .expect("past the age, from a member");
    let opened = cy.open_envelope(&held.envelope).unwrap().unwrap();
    assert!(
        matches!(
            cy.process_message_as(G, &opened.inner, "env-bo"),
            Err(Error::NotFromAMember(_))
        ),
        "Bo's seal over Ada's message"
    );
    assert!(cy.release_held("env-bo").unwrap());
    let adas_seal = device_seal(&device_seed(1), &key_of(3), G, &[0x5a; 32], &by_bo).unwrap();
    assert!(
        cy.hold_envelope_sealed(MAILBOX_MESSAGE, "env-honest", long_ago, &by_bo, &adas_seal)
            .unwrap()
            .is_kept(),
        "the refused seal left no release note behind"
    );
    let held = cy.next_reopenable().unwrap().expect("Ada's own seal");
    assert_eq!(held.id, "env-honest");
    let real = cy.open_envelope(&held.envelope).unwrap().unwrap();
    match cy.process_message_as(G, &real.inner, "env-honest").unwrap() {
        Incoming::Application {
            sender, plaintext, ..
        } => {
            assert_eq!(sender.actor_id, "actor-ada", "the key was not spent");
            assert_eq!(plaintext, b"Ada's own words");
        }
        other => panic!("{other:?}"),
    }
    assert!(cy.release_held("env-honest").unwrap());

    let more = ada.encrypt(G, b"and more").unwrap();
    let (by_ada, ada_seal) = wrap(1, &more, [0x6b; 32]);
    assert!(cy
        .hold_envelope_sealed(MAILBOX_MESSAGE, "env-ada", long_ago, &by_ada, &ada_seal)
        .unwrap()
        .is_kept());
    let held = cy.next_reopenable().unwrap().expect("Ada's seal");
    let opened = cy.open_envelope(&held.envelope).unwrap().unwrap();
    match cy.process_message_as(G, &opened.inner, "env-ada").unwrap() {
        Incoming::Application { sender, .. } => assert_eq!(sender.actor_id, "actor-ada"),
        other => panic!("{other:?}"),
    }
}

/// A send addresses every device, the sender's own too, so the writer seals
/// to every leaf, its own included: exactly one seal per addressed device,
/// each opening for its device alone, and no entry marks the sender.
#[test]
fn every_addressed_device_gets_exactly_one_seal() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = client(&s, 3, "actor-cy", "device-cy");
    group(&mut ada, &mut [&mut bo, &mut cy]);

    let message = ada.encrypt(G, b"to everyone").unwrap();
    let envelope = ada
        .seal_envelope(G, ENVELOPE_KIND_MESSAGE, &message)
        .unwrap();
    let seals = ada.device_seals(G, &envelope).unwrap();
    let keys: Vec<Vec<u8>> = seals.iter().map(|(key, _)| key.clone()).collect();
    assert_eq!(keys, vec![key_of(1), key_of(2), key_of(3)]);
    for (tag, (_, seal)) in (1u8..=3).zip(&seals) {
        assert_eq!(seal.len(), peachy_mls_core::DEVICE_SEAL_BYTES);
        let opened = device_seal_open(&device_seed(tag), seal, &envelope).unwrap();
        assert_eq!(opened.sender_key.to_vec(), key_of(1));
        assert_eq!(opened.group_id, G);
        for other in (1u8..=3).filter(|other| *other != tag) {
            assert!(device_seal_open(&device_seed(other), seal, &envelope).is_err());
        }
    }
}

/// THE SAME ENVELOPE UNDER A THOUSAND MAILBOX IDS IS HELD ONCE. The server
/// hands one real envelope and its seal over again and again, each time
/// under a new id: Cy keeps it once, hands it out once, and once it is
/// released does not keep it again. The same holds without a seal.
#[test]
fn a_thousand_ids_for_one_envelope_hold_it_once() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = client(&s, 3, "actor-cy", "device-cy");
    group(&mut ada, &mut [&mut bo, &mut cy]);
    ada.act_as_member_handing_back_no_gap();

    fork_cy(&mut ada, &mut bo, &mut cy);
    let (missed, seal) = sent(&mut ada, "once", &key_of(3));
    let (plain, _) = sent(&mut ada, "without a seal", &key_of(3));
    let mut kept = 0;
    let mut kept_plain = 0;
    for n in 0..1000u64 {
        let id = format!("env-{n:04}");
        if cy
            .hold_envelope_sealed(MAILBOX_MESSAGE, &id, received_at() + n, &missed, &seal)
            .unwrap()
            .is_kept()
        {
            kept += 1;
        }
        if cy
            .hold_envelope(
                MAILBOX_MESSAGE,
                &format!("plain-{n:04}"),
                received_at() + n,
                &plain,
            )
            .unwrap()
        {
            kept_plain += 1;
        }
    }
    assert_eq!(kept, 1, "held once, under the first id");
    assert_eq!(kept_plain, 1);
    assert!(
        !cy.hold_envelope(MAILBOX_MESSAGE, "env-bare", received_at(), &missed)
            .unwrap(),
        "the same bytes without their seal"
    );

    reseat_cy(&mut ada, &mut bo, &mut cy);
    let mut handed = Vec::new();
    while let Some(held) = cy.next_reopenable().unwrap() {
        handed.push(held);
    }
    assert_eq!(handed.len(), 1, "exactly one held entry");
    assert_eq!(handed[0].id, "env-0000");
    assert!(cy.release_held("env-0000").unwrap());
    assert!(
        !cy.hold_envelope_sealed(MAILBOX_MESSAGE, "env-again", received_at(), &missed, &seal)
            .unwrap()
            .is_kept(),
        "released: not held again"
    );
    assert!(cy.next_reopenable().unwrap().is_none());
}

/// Past the byte budget the oldest sealed envelope is handed out, rather
/// than waiting on a copy at its very epoch that cannot open it (a fork);
/// the newest, inside the budget, still waits.
#[test]
fn a_sealed_envelope_is_handed_out_at_the_budget() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = client(&s, 3, "actor-cy", "device-cy");
    group(&mut ada, &mut [&mut bo, &mut cy]);

    fork_cy(&mut ada, &mut bo, &mut cy);
    let (old, old_seal) = sent(&mut ada, "first", &key_of(3));
    let (new, new_seal) = sent(&mut ada, "second", &key_of(3));
    let budget = u64::try_from(old.len().max(new.len()) * 3 / 2).unwrap();
    cy.limit_sealed_hold(budget, 1000, u64::MAX);
    assert!(cy
        .hold_envelope_sealed(MAILBOX_MESSAGE, "env-old", received_at(), &old, &old_seal)
        .unwrap()
        .is_kept());
    assert!(cy.next_reopenable().unwrap().is_none(), "inside the budget");
    assert!(cy
        .hold_envelope_sealed(
            MAILBOX_MESSAGE,
            "env-new",
            received_at() + 1,
            &new,
            &new_seal
        )
        .unwrap()
        .is_kept());
    let held = cy.next_reopenable().unwrap().expect("past the budget");
    assert_eq!(held.id, "env-old");
    assert_eq!(
        cy.held_disposition("env-old"),
        Some(HeldDisposition {
            fate: HeldFate::Ordinary,
            author: None
        })
    );
    assert_from_ada(&mut cy, &held.envelope);
    assert!(cy.next_reopenable().unwrap().is_none(), "the newest waits");
}

/// A copy merely BEHIND a message waits for it, past the budget too, while
/// the envelope is young: a reseat or the next commits bring it there. Near
/// the ceiling the oldest is handed out whatever, and at the ceiling one
/// more is refused.
#[test]
fn a_copy_behind_waits_past_the_budget_until_the_ceiling_nears() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = client(&s, 3, "actor-cy", "device-cy");
    group(&mut ada, &mut [&mut bo, &mut cy]);

    let ahead = ada.self_update(G).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &ahead.commit).unwrap();
    cy.limit_sealed_hold(1, 4, u64::MAX);
    for n in 0..3u64 {
        let (missed, seal) = sent(&mut ada, &format!("behind {n}"), &key_of(3));
        assert!(cy
            .hold_envelope_sealed(
                MAILBOX_MESSAGE,
                &format!("env-{n}"),
                received_at() + n,
                &missed,
                &seal
            )
            .unwrap()
            .is_kept());
    }
    assert!(
        cy.next_reopenable().unwrap().is_none(),
        "past the budget, but behind and young: it waits"
    );
    let (fourth, fourth_seal) = sent(&mut ada, "the fourth", &key_of(3));
    assert!(cy
        .hold_envelope_sealed(
            MAILBOX_MESSAGE,
            "env-3",
            received_at() + 3,
            &fourth,
            &fourth_seal
        )
        .unwrap()
        .is_kept());
    let held = cy.next_reopenable().unwrap().expect("near the ceiling");
    assert_eq!(held.id, "env-0");
    assert!(cy.next_reopenable().unwrap().is_none());
    let (fifth, fifth_seal) = sent(&mut ada, "the fifth", &key_of(3));
    assert_eq!(
        cy.hold_envelope_sealed(
            MAILBOX_MESSAGE,
            "env-4",
            received_at() + 4,
            &fifth,
            &fifth_seal
        )
        .unwrap(),
        HoldAnswer::Full,
        "at the ceiling: held without its seal, and the page stops there"
    );
    assert!(cy.release_held("env-0").unwrap());
    assert!(
        cy.hold_envelope_sealed(
            MAILBOX_MESSAGE,
            "env-4",
            received_at() + 4,
            &fifth,
            &fifth_seal
        )
        .unwrap()
        .is_kept(),
        "delivered again once there is room: held on its seal"
    );
}

/// The same at the hold's age, for a copy behind it.
#[test]
fn a_sealed_envelope_is_handed_out_rather_than_dropped_at_the_age() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = client(&s, 3, "actor-cy", "device-cy");
    group(&mut ada, &mut [&mut bo, &mut cy]);

    let ahead = ada.self_update(G).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &ahead.commit).unwrap();
    let (missed, seal) = sent(&mut ada, "long ago", &key_of(3));
    let long_ago = received_at() - HELD_ENVELOPE_MAX_AGE_MS - 1;
    assert!(
        !cy.hold_envelope(MAILBOX_MESSAGE, "env-plain", long_ago, &missed)
            .unwrap(),
        "unsealed and too old: not kept"
    );
    assert!(cy
        .hold_envelope_sealed(MAILBOX_MESSAGE, "env-old", long_ago, &missed, &seal)
        .unwrap()
        .is_kept());
    let held = cy
        .next_reopenable()
        .unwrap()
        .expect("past the age: handed out on its seal");
    assert_eq!(held.id, "env-old");
    assert_from_ada(&mut cy, &held.envelope);
}

/// THE SENDER'S DEVICE IS NO LEAF ANY MORE, AND ITS PERSON HAS LEFT. Bo
/// seals, then is removed before Cy is back: the envelope is handed out as a
/// placeholder naming Bo, from the device key Cy saw Bo hold, not dropped.
#[test]
fn a_seal_from_a_member_who_left_names_them() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = client(&s, 3, "actor-cy", "device-cy");
    group(&mut ada, &mut [&mut bo, &mut cy]);
    ada.act_as_member_handing_back_no_gap();

    fork_cy(&mut ada, &mut bo, &mut cy);
    let (missed, seal) = sent(&mut bo, "from Bo", &key_of(3));
    assert!(cy
        .hold_envelope_sealed(MAILBOX_MESSAGE, "env-bo", received_at(), &missed, &seal)
        .unwrap()
        .is_kept());

    let bo_leaf = ada.leaf_of_device(G, "device-bo").unwrap();
    ada.remove_leaf(G, bo_leaf).unwrap();
    ada.merge_pending_commit(G).unwrap();
    cy.forget_group(G).unwrap();
    let kp = cy.generate_key_package().unwrap();
    let cy_leaf = ada.leaf_of_device(G, "device-cy").unwrap();
    let back = ada.replace_member(G, cy_leaf, &kp).unwrap();
    ada.merge_pending_commit(G).unwrap();
    cy.join_from_welcome(&back.welcome.unwrap()).unwrap();

    let held = cy
        .next_reopenable()
        .unwrap()
        .expect("Bo left: a placeholder");
    assert_eq!(held.id, "env-bo");
    assert_eq!(
        cy.held_disposition("env-bo"),
        Some(HeldDisposition {
            fate: HeldFate::FormerMember,
            author: Some("actor-bo".to_owned())
        })
    );
    let opened = cy.open_envelope(&missed).unwrap().expect("granted");
    assert_eq!(opened.group_id, G);
    assert!(cy.release_held("env-bo").unwrap());
    assert_eq!(cy.held_disposition("env-bo"), None);
}

/// THE SENDER'S DEVICE WAS REPLACED: Bo's first device sealed, and was
/// removed, but Bo holds a leaf on another. The envelope is granted as any
/// member's, and when the message inside is refused as from a device the
/// group removed, that is a loss to draw and ask for again, not silence.
#[test]
fn a_seal_from_a_replaced_device_of_a_member_is_a_loss_to_ask_for() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = client(&s, 3, "actor-cy", "device-cy");
    let mut bo2 = client(&s, 4, "actor-bo", "device-bo2");
    group(&mut ada, &mut [&mut bo, &mut cy, &mut bo2]);

    let words = bo.encrypt(G, b"from Bo's first device").unwrap();
    let secret = [0x5a; 32];
    let envelope =
        peachy_mls_core::envelope::seal_epoch_envelope(&secret, ENVELOPE_KIND_MESSAGE, &words)
            .unwrap();
    let seal = device_seal(&device_seed(2), &key_of(3), G, &secret, &envelope).unwrap();
    let long_ago = received_at() - HELD_ENVELOPE_MAX_AGE_MS - 1;

    let bo_leaf = ada.leaf_of_device(G, "device-bo").unwrap();
    let removal = ada.remove_leaf(G, bo_leaf).unwrap();
    ada.merge_pending_commit(G).unwrap();
    cy.process_commit(G, &removal.commit).unwrap();
    bo2.process_commit(G, &removal.commit).unwrap();

    assert!(cy
        .hold_envelope_sealed(MAILBOX_MESSAGE, "env-bo", long_ago, &envelope, &seal)
        .unwrap()
        .is_kept());
    let held = cy.next_reopenable().unwrap().expect("Bo is a member still");
    assert_eq!(
        cy.held_disposition(&held.id),
        Some(HeldDisposition {
            fate: HeldFate::Ordinary,
            author: Some("actor-bo".to_owned())
        })
    );
    let opened = cy.open_envelope(&held.envelope).unwrap().unwrap();
    assert!(
        matches!(
            cy.process_message_as(G, &opened.inner, "env-bo"),
            Err(Error::Mls(_))
        ),
        "a loss, asked for again"
    );
}

/// A SEAL FOR A GROUP THIS DEVICE HOLDS NO COPY OF waits for the device to
/// be seated; past the age (or the budget) it is handed out as an orphan,
/// to a placeholder in that group's conversation naming its sender.
#[test]
fn a_seal_for_a_group_not_held_becomes_an_orphan() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = client(&s, 3, "actor-cy", "device-cy");
    group(&mut ada, &mut [&mut bo, &mut cy]);
    cy.forget_group(G).unwrap();

    let (fresh, fresh_seal) = sent(&mut ada, "while you hold no copy", &key_of(3));
    assert!(cy
        .hold_envelope_sealed(
            MAILBOX_MESSAGE,
            "env-fresh",
            received_at(),
            &fresh,
            &fresh_seal
        )
        .unwrap()
        .is_kept());
    assert!(
        cy.next_reopenable().unwrap().is_none(),
        "it waits for a seat"
    );

    let (old, old_seal) = sent(&mut ada, "long ago", &key_of(3));
    let long_ago = received_at() - HELD_ENVELOPE_MAX_AGE_MS - 1;
    assert!(cy
        .hold_envelope_sealed(MAILBOX_MESSAGE, "env-old", long_ago, &old, &old_seal)
        .unwrap()
        .is_kept());
    let held = cy.next_reopenable().unwrap().expect("past the age");
    assert_eq!(held.id, "env-old");
    assert_eq!(
        cy.held_disposition("env-old"),
        Some(HeldDisposition {
            fate: HeldFate::Orphan,
            author: Some("actor-ada".to_owned())
        })
    );
    assert_eq!(cy.open_envelope(&old).unwrap().unwrap().group_id, G);
    assert!(cy.next_reopenable().unwrap().is_none());
    assert!(cy.release_held("env-old").unwrap());

    cy.limit_sealed_hold(1, 1000, u64::MAX);
    let (more, more_seal) = sent(&mut ada, "past the budget", &key_of(3));
    assert!(cy
        .hold_envelope_sealed(
            MAILBOX_MESSAGE,
            "env-more",
            received_at() + 1,
            &more,
            &more_seal
        )
        .unwrap()
        .is_kept());
    let held = cy.next_reopenable().unwrap().expect("past the budget");
    assert_eq!(held.id, "env-fresh");
    assert_eq!(
        cy.held_disposition("env-fresh").map(|d| d.fate),
        Some(HeldFate::Orphan)
    );
}

/// A GROUP LEFT ON PURPOSE keeps nobody's keys: a seal for it afterwards is
/// no orphan, and draws nothing into the conversation the person left.
#[test]
fn a_seal_for_a_group_left_on_purpose_is_dropped() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = client(&s, 3, "actor-cy", "device-cy");
    group(&mut ada, &mut [&mut bo, &mut cy]);
    let (old, old_seal) = sent(&mut ada, "before Cy left", &key_of(3));
    cy.forget_group(G).unwrap();
    cy.forget_remembered_roster(G).unwrap();

    let long_ago = received_at() - HELD_ENVELOPE_MAX_AGE_MS - 1;
    assert!(cy
        .hold_envelope_sealed(MAILBOX_MESSAGE, "env-old", long_ago, &old, &old_seal)
        .unwrap()
        .is_kept());
    assert!(
        cy.next_reopenable().unwrap().is_none(),
        "dropped, not an orphan"
    );
    assert!(cy.held_disposition("env-old").is_none());
}

/// A seal from a key no copy ever held a leaf with is nobody's word (anybody
/// can make one from a key of their own): the envelope is kept as one that
/// came with no seal, which goes at the age, and opens for nothing here. It
/// leaves no release note, so the same bytes under their author's own seal
/// are held again.
#[test]
fn a_seal_from_a_key_no_copy_held_names_nobody() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = client(&s, 3, "actor-cy", "device-cy");
    group(&mut ada, &mut [&mut bo, &mut cy]);

    let words = ada.encrypt(G, b"Ada's words").unwrap();
    let secret = [0x5a; 32];
    let envelope =
        peachy_mls_core::envelope::seal_epoch_envelope(&secret, ENVELOPE_KIND_MESSAGE, &words)
            .unwrap();
    let seal = device_seal(&device_seed(9), &key_of(3), G, &secret, &envelope).unwrap();
    let long_ago = received_at() - HELD_ENVELOPE_MAX_AGE_MS - 1;
    assert!(cy
        .hold_envelope_sealed(MAILBOX_MESSAGE, "env-stranger", long_ago, &envelope, &seal)
        .unwrap()
        .is_kept());
    assert!(cy.next_reopenable().unwrap().is_none(), "names nobody");
    assert!(cy.open_envelope(&envelope).unwrap().is_none());
    let adas_seal = device_seal(&device_seed(1), &key_of(3), G, &secret, &envelope).unwrap();
    assert!(cy
        .hold_envelope_sealed(MAILBOX_MESSAGE, "env-ada", long_ago, &envelope, &adas_seal)
        .unwrap()
        .is_kept());
    let held = cy.next_reopenable().unwrap().expect("Ada's own seal");
    assert_eq!(held.id, "env-ada");
    assert!(cy.open_envelope(&envelope).unwrap().is_some());
}

/// WORDS KEPT ARE GRANTED AGAIN. A run opened a sealed envelope, kept its
/// words in the write that spent the key, and died before releasing it; by
/// the next run its sender has left. It is granted as it was, and the words
/// come back, rather than being turned into a placeholder for a former
/// member.
#[test]
fn a_sealed_envelope_whose_words_are_kept_is_granted_again() {
    let s = issuer();
    let cy_kv = MemoryKv::new();
    let cy_on = |kv: &MemoryKv| {
        client_on(
            &s,
            3,
            "actor-cy",
            "device-cy",
            PeachyStorage::open(Box::new(kv.clone())).unwrap(),
        )
    };
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = cy_on(&cy_kv);
    group(&mut ada, &mut [&mut bo, &mut cy]);

    let words = ada.encrypt(G, b"kept").unwrap();
    let secret = [0x6b; 32];
    let envelope =
        peachy_mls_core::envelope::seal_epoch_envelope(&secret, ENVELOPE_KIND_MESSAGE, &words)
            .unwrap();
    let seal = device_seal(&device_seed(1), &key_of(3), G, &secret, &envelope).unwrap();
    let long_ago = received_at() - HELD_ENVELOPE_MAX_AGE_MS - 1;
    assert!(cy
        .hold_envelope_sealed(MAILBOX_MESSAGE, "env-ada", long_ago, &envelope, &seal)
        .unwrap()
        .is_kept());
    let held = cy.next_reopenable().unwrap().expect("from a leaf");
    let opened = cy.open_envelope(&held.envelope).unwrap().unwrap();
    assert!(matches!(
        cy.process_message_as(G, &opened.inner, "env-ada").unwrap(),
        Incoming::Application { .. }
    ));
    drop(cy);

    let ada_leaf = bo.leaf_of_device(G, "device-ada").unwrap();
    let removal = bo.remove_leaf(G, ada_leaf).unwrap();
    bo.merge_pending_commit(G).unwrap();
    let mut cy = cy_on(&cy_kv);
    cy.process_commit(G, &removal.commit).unwrap();
    let again = cy.next_reopenable().unwrap().expect("handed out again");
    assert_eq!(
        cy.held_disposition(&again.id).map(|d| d.fate),
        Some(HeldFate::Ordinary)
    );
    let opened = cy.open_envelope(&again.envelope).unwrap().unwrap();
    match cy.process_message_as(G, &opened.inner, "env-ada").unwrap() {
        Incoming::Application {
            sender, plaintext, ..
        } => {
            assert_eq!(sender.actor_id, "actor-ada");
            assert_eq!(plaintext, b"kept");
        }
        other => panic!("{other:?}"),
    }
}

/// A send's every entry carries a seal, whatever the envelope holds: a
/// commit's too, so the seal's presence tells nothing of the kind.
#[test]
fn every_kind_of_envelope_gets_its_seals() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = client(&s, 3, "actor-cy", "device-cy");
    group(&mut ada, &mut [&mut bo, &mut cy]);

    let update = ada.self_update(G).unwrap();
    let envelope = ada
        .seal_envelope(G, ENVELOPE_KIND_COMMIT, &update.commit)
        .unwrap();
    let seals = ada.device_seals(G, &envelope).unwrap();
    assert_eq!(seals.len(), 3);
    for (tag, (_, seal)) in (1u8..=3).zip(&seals) {
        assert!(device_seal_open(&device_seed(tag), seal, &envelope).is_ok());
    }
    assert!(
        !cy.hold_envelope_sealed(
            MAILBOX_MESSAGE,
            "env-commit",
            received_at(),
            &envelope,
            &seals[2].1
        )
        .unwrap()
        .is_kept(),
        "only a message is held"
    );
}

/// A group id longer than a seal's slot is refused at its founding.
#[test]
fn a_group_id_too_long_to_seal_is_refused() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    assert!(ada
        .create_group(&[b'g'; peachy_mls_core::DEVICE_SEAL_MAX_GROUP_ID_BYTES + 1])
        .is_err());
    assert!(ada
        .create_group(&[b'g'; peachy_mls_core::DEVICE_SEAL_MAX_GROUP_ID_BYTES])
        .is_ok());
}

/// A seal made for another device, or for another envelope, tells nothing:
/// the envelope is held as if none came, and opens for nothing.
#[test]
fn a_seal_for_another_device_or_envelope_is_ignored() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = client(&s, 3, "actor-cy", "device-cy");
    group(&mut ada, &mut [&mut bo, &mut cy]);
    ada.act_as_member_handing_back_no_gap();

    fork_cy(&mut ada, &mut bo, &mut cy);
    let (missed, for_bo) = sent(&mut ada, "for Bo's seal", &key_of(2));
    let (other, for_cy) = sent(&mut ada, "another", &key_of(3));
    assert!(cy
        .hold_envelope_sealed(
            MAILBOX_MESSAGE,
            "env-bo-seal",
            received_at(),
            &missed,
            &for_bo
        )
        .unwrap()
        .is_kept());
    assert!(cy
        .hold_envelope_sealed(
            MAILBOX_MESSAGE,
            "env-swapped",
            received_at() + 1,
            &other,
            &for_bo
        )
        .unwrap()
        .is_kept());
    // Cy's seal, but for `other`, beside `missed`: those bytes are held
    // already, as if no seal had come.
    assert!(!cy
        .hold_envelope_sealed(
            MAILBOX_MESSAGE,
            "env-wrong",
            received_at() + 2,
            &missed,
            &for_cy
        )
        .unwrap()
        .is_kept());
    reseat_cy(&mut ada, &mut bo, &mut cy);
    assert!(cy.next_reopenable().unwrap().is_none());
    assert!(cy.open_envelope(&missed).unwrap().is_none());
    assert!(cy.open_envelope(&other).unwrap().is_none());
}

/// What the epoch keying closed stays closed: a device removed from the
/// group is no leaf of any sender's copy, so nobody seals to it while it is
/// out.
#[test]
fn nobody_seals_to_a_device_while_it_is_out_of_the_group() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = client(&s, 3, "actor-cy", "device-cy");
    group(&mut ada, &mut [&mut bo, &mut cy]);

    let cy_leaf = ada.leaf_of_device(G, "device-cy").unwrap();
    let removal = ada.remove_leaf(G, cy_leaf).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &removal.commit).unwrap();
    let message = ada.encrypt(G, b"while you were out").unwrap();
    let envelope = ada
        .seal_envelope(G, ENVELOPE_KIND_MESSAGE, &message)
        .unwrap();
    let keys: Vec<Vec<u8>> = ada
        .device_seals(G, &envelope)
        .unwrap()
        .into_iter()
        .map(|(key, _)| key)
        .collect();
    assert_eq!(
        keys,
        vec![key_of(1), key_of(2)],
        "Ada (the sender's own device) and Bo: Cy is out"
    );
}

/// A second group, of `founder` and `others`, under its own id.
fn second_group(founder: &mut Client, others: &mut [&mut Client]) {
    founder.create_group(H).unwrap();
    for i in 0..others.len() {
        let kp = others[i].generate_key_package().unwrap();
        let b = founder.add_member(H, &kp).unwrap();
        founder.merge_pending_commit(H).unwrap();
        for x in others.iter_mut().take(i) {
            x.process_commit(H, &b.commit).unwrap();
        }
        others[i].join_from_welcome(&b.welcome.unwrap()).unwrap();
    }
}

/// An envelope of `words` under a secret no copy holds, with the seal the
/// device seeded by `sender_tag` makes for Cy (tag 3), naming `group_id`.
fn forged(sender_tag: u8, group_id: &[u8], words: &[u8], secret: [u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let envelope =
        peachy_mls_core::envelope::seal_epoch_envelope(&secret, ENVELOPE_KIND_MESSAGE, words)
            .unwrap();
    let seal = device_seal(
        &device_seed(sender_tag),
        &key_of(3),
        group_id,
        &secret,
        &envelope,
    )
    .unwrap();
    (envelope, seal)
}

/// A KEY SEEN IN ONE GROUP IS NO WORD ABOUT ANOTHER. Mallory shares group H
/// with Cy, never G. Her seals naming G, whether Cy holds G or not, name
/// nobody: no placeholder in G names her. Bo's other device, known to Cy
/// only from H, is granted in G as any envelope of Bo's, since Bo holds a
/// seat there; and it names him on nothing but that.
#[test]
fn a_key_known_only_from_another_group_names_nobody_there() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = client(&s, 3, "actor-cy", "device-cy");
    let mut mallory = client(&s, 4, "actor-mallory", "device-mallory");
    let mut bo2 = client(&s, 5, "actor-bo", "device-bo2");
    group(&mut ada, &mut [&mut bo, &mut cy]);
    second_group(&mut cy, &mut [&mut mallory, &mut bo2]);

    let long_ago = received_at() - HELD_ENVELOPE_MAX_AGE_MS - 1;
    let words = mallory.encrypt(H, b"not in G").unwrap();
    let (into_g, seal) = forged(4, G, &words, [0x11; 32]);
    assert!(cy
        .hold_envelope_sealed(MAILBOX_MESSAGE, "env-mallory", long_ago, &into_g, &seal)
        .unwrap()
        .is_kept());
    assert!(
        cy.next_reopenable().unwrap().is_none(),
        "G is held, and its record never held Mallory's key: nobody named"
    );
    assert_eq!(cy.held_disposition("env-mallory"), None);
    assert!(cy.open_envelope(&into_g).unwrap().is_none());

    let words = bo2.encrypt(H, b"from Bo's other device").unwrap();
    let (by_bo2, seal) = forged(5, G, &words, [0x22; 32]);
    assert!(cy
        .hold_envelope_sealed(MAILBOX_MESSAGE, "env-bo2", long_ago, &by_bo2, &seal)
        .unwrap()
        .is_kept());
    let held = cy.next_reopenable().unwrap().expect("Bo holds a seat in G");
    assert_eq!(held.id, "env-bo2");
    assert_eq!(
        cy.held_disposition("env-bo2"),
        Some(HeldDisposition {
            fate: HeldFate::Ordinary,
            author: Some("actor-bo".to_owned())
        })
    );
    assert!(cy.release_held("env-bo2").unwrap());

    cy.forget_group(G).unwrap();
    let words = mallory.encrypt(H, b"still not in G").unwrap();
    let (orphan, seal) = forged(4, G, &words, [0x33; 32]);
    assert!(cy
        .hold_envelope_sealed(MAILBOX_MESSAGE, "env-orphan", long_ago, &orphan, &seal)
        .unwrap()
        .is_kept());
    assert!(
        cy.next_reopenable().unwrap().is_none(),
        "G is not held, and its record never held Mallory's key: no orphan"
    );
    assert_eq!(cy.held_disposition("env-orphan"), None);
    let other_words = mallory.encrypt(H, b"for a group never held").unwrap();
    let (nowhere, seal) = forged(4, b"a-group-cy-never-held", &other_words, [0x44; 32]);
    assert!(cy
        .hold_envelope_sealed(MAILBOX_MESSAGE, "env-nowhere", long_ago, &nowhere, &seal)
        .unwrap()
        .is_kept());
    assert!(
        cy.next_reopenable().unwrap().is_none(),
        "no record at all: nobody named"
    );
}

/// A FORMER MEMBER IS NAMED FOR 30 DAYS AFTER THIS DEVICE SAW THEM GO, by
/// its own clock, whatever epoch their envelope claims: Bo, removed, gets a
/// placeholder in the month the mailbox could still hold what he sent
/// before, and nothing after it.
#[test]
fn a_former_members_seal_is_dropped_thirty_days_after_they_left() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = client(&s, 3, "actor-cy", "device-cy");
    group(&mut ada, &mut [&mut bo, &mut cy]);

    let first = bo.encrypt(G, b"before I went").unwrap();
    let second = bo.encrypt(G, b"and again").unwrap();
    let bo_leaf = ada.leaf_of_device(G, "device-bo").unwrap();
    let removal = ada.remove_leaf(G, bo_leaf).unwrap();
    ada.merge_pending_commit(G).unwrap();
    cy.process_commit(G, &removal.commit).unwrap();

    let (early, seal) = forged(2, G, &first, [0x55; 32]);
    assert!(cy
        .hold_envelope_sealed(MAILBOX_MESSAGE, "env-early", received_at(), &early, &seal)
        .unwrap()
        .is_kept());
    cy.limit_sealed_hold(1, 1000, u64::MAX);
    let (late, late_seal) = forged(2, G, &second, [0x66; 32]);
    let day = 24 * 60 * 60 * 1000;
    support::advance_ms(29 * day);
    assert!(cy
        .hold_envelope_sealed(
            MAILBOX_MESSAGE,
            "env-late",
            received_at() + 29 * day,
            &late,
            &late_seal
        )
        .unwrap()
        .is_kept());
    let held = cy.next_reopenable().unwrap().expect("29 days on: named");
    assert_eq!(held.id, "env-early");
    assert_eq!(
        cy.held_disposition("env-early").map(|d| d.fate),
        Some(HeldFate::FormerMember)
    );
    assert!(cy.release_held("env-early").unwrap());
    while cy.next_reopenable().unwrap().is_some() {}

    support::advance_ms(2 * day);
    assert!(
        cy.next_reopenable().unwrap().is_none(),
        "31 days after Cy saw Bo go: dropped"
    );
    assert_eq!(cy.held_disposition("env-late"), None);
    assert!(cy.open_envelope(&late).unwrap().is_none());
}

/// A DRAIN PAST THE CEILING LOSES NOTHING, AND KEEPS THE NEWEST. Cy, behind,
/// is handed 1,300 sealed messages, oldest first. At the ceiling the hold
/// answers full: the page stops there, unacknowledged, the pass hands out
/// what is due, and the same envelope, delivered again, is held on its
/// seal. Once Cy catches up, every one still held opens, the newest
/// included, and none went missing.
#[test]
fn a_drain_past_the_ceiling_keeps_the_newest() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = client(&s, 3, "actor-cy", "device-cy");
    group(&mut ada, &mut [&mut bo, &mut cy]);

    let ahead = ada.self_update(G).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &ahead.commit).unwrap();
    const N: usize = 1300;
    let sent_all: Vec<(Vec<u8>, Vec<u8>)> = (0..N)
        .map(|n| sent(&mut ada, &format!("message {n}"), &key_of(3)))
        .collect();

    let mut handed: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    let mut stops = 0;
    let mut n = 0;
    while n < N {
        let (envelope, seal) = &sent_all[n];
        let at = received_at() + u64::try_from(n).unwrap();
        match cy
            .hold_envelope_sealed(MAILBOX_MESSAGE, &format!("env-{n}"), at, envelope, seal)
            .unwrap()
        {
            HoldAnswer::Full => {
                // The page stops here, unacknowledged; the pass takes what
                // is due through; the drain starts again at this envelope.
                stops += 1;
                assert!(stops < 10, "the pass makes room");
                while let Some(held) = cy.next_reopenable().unwrap() {
                    assert!(cy.open_envelope(&held.envelope).unwrap().is_some());
                    let index: usize = held.id["env-".len()..].parse().unwrap();
                    assert!(handed.insert(index), "{} handed out twice", held.id);
                    assert!(cy.release_held(&held.id).unwrap());
                }
            }
            HoldAnswer::Kept => n += 1,
            HoldAnswer::NotKept => panic!("env-{n} was not kept"),
        }
    }
    assert_eq!(stops, 2, "at 1,000, then at 1,000 again after 250 went");

    cy.process_commit(G, &ahead.commit).unwrap();
    while let Some(held) = cy.next_reopenable().unwrap() {
        assert!(cy.open_envelope(&held.envelope).unwrap().is_some());
        let index: usize = held.id["env-".len()..].parse().unwrap();
        assert!(handed.insert(index), "{} handed out twice", held.id);
        assert!(cy.release_held(&held.id).unwrap());
    }
    assert!(handed.contains(&(N - 1)), "the newest is kept");
    assert_eq!(handed.len(), N, "none went missing");
}

/// A REPLAY IS NOT HELD. A message Cy took through on its seal and let go,
/// wrapped again in other bytes (so no release note knows it) and sealed
/// again, is not held: Cy opened it before.
#[test]
fn a_sealed_message_opened_before_is_not_held_again() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = client(&s, 3, "actor-cy", "device-cy");
    group(&mut ada, &mut [&mut bo, &mut cy]);

    let long_ago = received_at() - HELD_ENVELOPE_MAX_AGE_MS - 1;
    let words = ada.encrypt(G, b"once").unwrap();
    let (envelope, seal) = forged(1, G, &words, [0x77; 32]);
    assert!(cy
        .hold_envelope_sealed(MAILBOX_MESSAGE, "env-once", long_ago, &envelope, &seal)
        .unwrap()
        .is_kept());
    let held = cy.next_reopenable().unwrap().expect("Ada's seal");
    let opened = cy.open_envelope(&held.envelope).unwrap().unwrap();
    assert!(cy.process_message_as(G, &opened.inner, "env-once").is_ok());
    assert!(cy.release_held("env-once").unwrap());

    let (again, again_seal) = forged(1, G, &words, [0x78; 32]);
    assert_eq!(
        cy.hold_envelope_sealed(MAILBOX_MESSAGE, "env-again", long_ago, &again, &again_seal)
            .unwrap(),
        HoldAnswer::NotKept
    );
}

/// A CLIENT THAT STAYS OPEN PRUNES TOO: the release notes from more than 30
/// days ago go at the first reopen pass after each hour, not only at a
/// restart. Bytes released a month ago may then be held again.
#[test]
fn a_live_client_prunes_its_release_notes() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = client(&s, 3, "actor-cy", "device-cy");
    group(&mut ada, &mut [&mut bo, &mut cy]);

    let long_ago = received_at() - HELD_ENVELOPE_MAX_AGE_MS - 1;
    let words = ada.encrypt(G, b"let go unread").unwrap();
    let (envelope, seal) = forged(1, G, &words, [0x88; 32]);
    assert!(cy
        .hold_envelope_sealed(MAILBOX_MESSAGE, "env-first", long_ago, &envelope, &seal)
        .unwrap()
        .is_kept());
    let held = cy.next_reopenable().unwrap().expect("Ada's seal");
    assert!(cy.release_held(&held.id).unwrap());
    assert!(cy.next_reopenable().unwrap().is_none());
    assert_eq!(
        cy.hold_envelope_sealed(MAILBOX_MESSAGE, "env-second", long_ago, &envelope, &seal)
            .unwrap(),
        HoldAnswer::NotKept,
        "released: noted"
    );

    support::advance_ms(HELD_ENVELOPE_MAX_AGE_MS + 60 * 60 * 1000);
    // A month on Ada's credential has lapsed; her own client would renew
    // before sealing, and this test needs only a sealed message, not the
    // renewal.
    ada.act_as_build_sending_while_lapsed();
    let other = ada.encrypt(G, b"anything").unwrap();
    let (nudge, nudge_seal) = forged(1, G, &other, [0x99; 32]);
    assert!(cy
        .hold_envelope_sealed(
            MAILBOX_MESSAGE,
            "env-nudge",
            received_at(),
            &nudge,
            &nudge_seal
        )
        .unwrap()
        .is_kept());
    while let Some(held) = cy.next_reopenable().unwrap() {
        assert!(cy.release_held(&held.id).unwrap());
    }
    assert!(
        cy.hold_envelope_sealed(MAILBOX_MESSAGE, "env-third", long_ago, &envelope, &seal)
            .unwrap()
            .is_kept(),
        "the note went with the hour's sweep"
    );
}

/// Cy leaves G THROUGH THE LEAVE PATH: proposes its own removal, a member
/// commits it, and Cy follows that commit out. Following it writes who each
/// key was once more; the leave's end forgets that again, so a seal from Bo
/// for the group Cy left draws nothing, whether or not the person's client
/// forgot the roster when the leave began.
fn left_through_the_leave_path(forget_roster_at_start: bool) {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = client(&s, 3, "actor-cy", "device-cy");
    group(&mut ada, &mut [&mut bo, &mut cy]);

    let proposals = cy.begin_leave(G).unwrap();
    if forget_roster_at_start {
        cy.forget_remembered_roster(G).unwrap();
    }
    for proposal in &proposals {
        assert!(matches!(
            ada.process_message(G, proposal).unwrap(),
            Incoming::ProposalQueued { .. }
        ));
    }
    let bundle = ada
        .commit_proposed_leaves(G)
        .unwrap()
        .expect("Cy's leave committed");
    ada.merge_pending_commit(G).unwrap();
    cy.follow_leave(G, &bundle.commit).unwrap();

    let words = bo.encrypt(G, b"after Cy left").unwrap();
    let (envelope, seal) = forged(2, G, &words, [0x5a; 32]);
    let long_ago = received_at() - HELD_ENVELOPE_MAX_AGE_MS - 1;
    assert!(cy
        .hold_envelope_sealed(MAILBOX_MESSAGE, "env-after", long_ago, &envelope, &seal)
        .unwrap()
        .is_kept());
    assert!(
        cy.next_reopenable().unwrap().is_none(),
        "a group left on purpose draws nothing"
    );
    assert_eq!(cy.held_disposition("env-after"), None);
}

#[test]
fn a_seal_for_a_group_left_through_the_leave_path_draws_nothing() {
    left_through_the_leave_path(false);
}

#[test]
fn a_seal_for_a_group_left_with_its_roster_forgotten_draws_nothing() {
    left_through_the_leave_path(true);
}

/// A KEY THE GROUP'S RECORD NEVER HELD IS NOT DROPPED WHEN DUE: Dan joined
/// while Cy's copy was the fork, so no record of Cy's holds his key. His
/// sealed envelope, pressed out at three quarters of the ceiling, names
/// nobody; it is kept as one that came with no seal, and opens once the
/// member that reseats Cy hands the missed epochs back, to a message that
/// commits to Dan (what Cy draws a placeholder and asks again by).
#[test]
fn a_seal_from_a_key_joined_while_forked_is_kept_without_its_seal() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = client(&s, 3, "actor-cy", "device-cy");
    let mut dan = client(&s, 4, "actor-dan", "device-dan");
    group(&mut ada, &mut [&mut bo, &mut cy]);

    fork_cy(&mut ada, &mut bo, &mut cy);
    let kp = dan.generate_key_package().unwrap();
    let add = ada.add_member(G, &kp).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &add.commit).unwrap();
    dan.join_from_welcome(&add.welcome.unwrap()).unwrap();

    cy.limit_sealed_hold(1, 4, u64::MAX);
    let (by_dan, dan_seal) = sent(&mut dan, "hello from Dan", &key_of(3));
    assert!(cy
        .hold_envelope_sealed(
            MAILBOX_MESSAGE,
            "env-dan",
            received_at(),
            &by_dan,
            &dan_seal
        )
        .unwrap()
        .is_kept());
    for n in 1..4u64 {
        let (by_ada, ada_seal) = sent(&mut ada, "and Ada", &key_of(3));
        assert!(cy
            .hold_envelope_sealed(
                MAILBOX_MESSAGE,
                &format!("env-ada-{n}"),
                received_at() + n,
                &by_ada,
                &ada_seal
            )
            .unwrap()
            .is_kept());
    }
    assert!(
        cy.next_reopenable().unwrap().is_none(),
        "Dan's, urgent, names nobody Cy knows; Ada's wait for the copy"
    );
    assert_eq!(cy.held_disposition("env-dan"), None);
    assert!(
        !cy.hold_envelope(MAILBOX_MESSAGE, "env-dan-bare", received_at(), &by_dan)
            .unwrap(),
        "held already, as without a seal"
    );

    reseat_cy(&mut ada, &mut bo, &mut cy);
    let mut handed = Vec::new();
    while let Some(held) = cy.next_reopenable().unwrap() {
        handed.push(held);
    }
    let dans = handed
        .iter()
        .find(|held| held.id == "env-dan")
        .expect("opens on the epochs handed back");
    assert_eq!(cy.held_disposition("env-dan"), None, "on no seal's word");
    let opened = cy.open_envelope(&dans.envelope).unwrap().unwrap();
    assert_eq!(opened.group_id, G);
    let peek = peek_message(&opened.inner).expect("a group message");
    assert_eq!(
        peek.commitment,
        Some(resend_author_commitment(G, "actor-dan", ID.as_bytes())),
        "a resendable message of Dan's, to draw and ask him for again"
    );
}

/// A REPLACED DEVICE IS TAKEN ON FOR 30 DAYS, as a former member is: Bo
/// holds a seat on another device, and his first device's seal is granted
/// for the month after Cy saw that device go, and dropped after it.
#[test]
fn a_replaced_devices_seal_is_dropped_thirty_days_after_it_went() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = client(&s, 3, "actor-cy", "device-cy");
    let mut bo2 = client(&s, 4, "actor-bo", "device-bo2");
    group(&mut ada, &mut [&mut bo, &mut cy, &mut bo2]);

    let first = bo.encrypt(G, b"from Bo's first device").unwrap();
    let second = bo.encrypt(G, b"and again").unwrap();
    let bo_leaf = ada.leaf_of_device(G, "device-bo").unwrap();
    let removal = ada.remove_leaf(G, bo_leaf).unwrap();
    ada.merge_pending_commit(G).unwrap();
    cy.process_commit(G, &removal.commit).unwrap();

    let (early, seal) = forged(2, G, &first, [0x55; 32]);
    assert!(cy
        .hold_envelope_sealed(MAILBOX_MESSAGE, "env-early", received_at(), &early, &seal)
        .unwrap()
        .is_kept());
    cy.limit_sealed_hold(1, 1000, u64::MAX);
    let (late, late_seal) = forged(2, G, &second, [0x66; 32]);
    let day = 24 * 60 * 60 * 1000;
    support::advance_ms(29 * day);
    assert!(cy
        .hold_envelope_sealed(
            MAILBOX_MESSAGE,
            "env-late",
            received_at() + 29 * day,
            &late,
            &late_seal
        )
        .unwrap()
        .is_kept());
    let held = cy.next_reopenable().unwrap().expect("29 days on: granted");
    assert_eq!(held.id, "env-early");
    assert_eq!(
        cy.held_disposition("env-early"),
        Some(HeldDisposition {
            fate: HeldFate::Ordinary,
            author: Some("actor-bo".to_owned())
        })
    );
    assert!(cy.release_held("env-early").unwrap());
    while cy.next_reopenable().unwrap().is_some() {}

    support::advance_ms(2 * day);
    assert!(
        cy.next_reopenable().unwrap().is_none(),
        "31 days after Cy saw the device go: dropped, though Bo holds a seat"
    );
    assert_eq!(cy.held_disposition("env-late"), None);
    assert!(cy.open_envelope(&late).unwrap().is_none());
}

/// A CLOCK THAT RAN AHEAD DOES NOT STRETCH THE 30 DAYS: Cy's clock read 20
/// days ahead when it saw Bo go, and was then set right. The time noted is
/// taken as now from the next pass, and kept so: 31 days later, Bo's seal is
/// dropped, not granted for another 20.
#[test]
fn a_time_noted_ahead_of_the_clock_counts_from_now() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = client(&s, 3, "actor-cy", "device-cy");
    group(&mut ada, &mut [&mut bo, &mut cy]);

    let first = bo.encrypt(G, b"before I went").unwrap();
    let second = bo.encrypt(G, b"and again").unwrap();
    let day: u64 = 24 * 60 * 60 * 1000;
    let bo_leaf = ada.leaf_of_device(G, "device-bo").unwrap();
    let removal = ada.remove_leaf(G, bo_leaf).unwrap();
    ada.merge_pending_commit(G).unwrap();
    support::step_wall_ms(i64::try_from(20 * day).unwrap());
    cy.process_commit(G, &removal.commit).unwrap();
    support::step_wall_ms(-i64::try_from(20 * day).unwrap());

    cy.limit_sealed_hold(1, 1000, u64::MAX);
    let (early, seal) = forged(2, G, &first, [0x55; 32]);
    assert!(cy
        .hold_envelope_sealed(MAILBOX_MESSAGE, "env-early", received_at(), &early, &seal)
        .unwrap()
        .is_kept());
    let held = cy.next_reopenable().unwrap().expect("Bo left: named");
    assert_eq!(
        cy.held_disposition(&held.id).map(|d| d.fate),
        Some(HeldFate::FormerMember)
    );
    assert!(cy.release_held(&held.id).unwrap());
    assert!(cy.next_reopenable().unwrap().is_none());

    support::advance_ms(31 * day);
    let (late, late_seal) = forged(2, G, &second, [0x66; 32]);
    assert!(cy
        .hold_envelope_sealed(
            MAILBOX_MESSAGE,
            "env-late",
            received_at() + 31 * day,
            &late,
            &late_seal
        )
        .unwrap()
        .is_kept());
    assert!(
        cy.next_reopenable().unwrap().is_none(),
        "31 days after the pass that set the time to now: dropped"
    );
    assert_eq!(cy.held_disposition("env-late"), None);
}

/// THE NOTIFICATION EXTENSION ANSWERED FULL AND STOPPED, holding the
/// envelope without its seal. The app, a process of its own on the same
/// store, is handed the same envelope: it answers full too, once, so its
/// drain stops unacknowledged and makes room, rather than acknowledging the
/// envelope and losing its seal.
#[test]
fn full_in_one_process_is_full_in_the_next() {
    let s = issuer();
    let cy_kv = MemoryKv::new();
    let cy_on = |kv: &MemoryKv| {
        client_on(
            &s,
            3,
            "actor-cy",
            "device-cy",
            PeachyStorage::open(Box::new(kv.clone())).unwrap(),
        )
    };
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = cy_on(&cy_kv);
    group(&mut ada, &mut [&mut bo, &mut cy]);
    fork_cy(&mut ada, &mut bo, &mut cy);

    let (first, first_seal) = sent(&mut ada, "first", &key_of(3));
    let (second, second_seal) = sent(&mut ada, "second", &key_of(3));
    cy.limit_sealed_hold(u64::MAX, 1, u64::MAX);
    assert!(cy
        .hold_envelope_sealed(MAILBOX_MESSAGE, "env-1", received_at(), &first, &first_seal)
        .unwrap()
        .is_kept());
    assert_eq!(
        cy.hold_envelope_sealed(
            MAILBOX_MESSAGE,
            "env-2",
            received_at() + 1,
            &second,
            &second_seal
        )
        .unwrap(),
        HoldAnswer::Full,
        "the extension stops its page"
    );
    drop(cy);

    let mut app = cy_on(&cy_kv);
    app.limit_sealed_hold(u64::MAX, 1, u64::MAX);
    assert_eq!(
        app.hold_envelope_sealed(
            MAILBOX_MESSAGE,
            "env-2",
            received_at() + 1,
            &second,
            &second_seal
        )
        .unwrap(),
        HoldAnswer::Full,
        "held without its seal by the extension: full here too"
    );
    assert_eq!(
        app.hold_envelope_sealed(
            MAILBOX_MESSAGE,
            "env-2",
            received_at() + 1,
            &second,
            &second_seal
        )
        .unwrap(),
        HoldAnswer::NotKept,
        "once per release"
    );
}

/// A REFUSAL IS KEPT IN MEMORY ONLY: the process that refused a seal died
/// before releasing it. The next one, releasing it without having granted it,
/// does not know whether it was refused, so notes nothing, and Ada's own
/// seal over the same bytes is held again.
#[test]
fn a_release_after_a_restart_leaves_no_release_note() {
    let s = issuer();
    let cy_kv = MemoryKv::new();
    let cy_on = |kv: &MemoryKv| {
        client_on(
            &s,
            3,
            "actor-cy",
            "device-cy",
            PeachyStorage::open(Box::new(kv.clone())).unwrap(),
        )
    };
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = cy_on(&cy_kv);
    group(&mut ada, &mut [&mut bo, &mut cy]);

    let long_ago = received_at() - HELD_ENVELOPE_MAX_AGE_MS - 1;
    let adas = ada.encrypt(G, b"Ada's own words").unwrap();
    let (by_bo, bo_seal) = forged(2, G, &adas, [0x5a; 32]);
    assert!(cy
        .hold_envelope_sealed(MAILBOX_MESSAGE, "env-bo", long_ago, &by_bo, &bo_seal)
        .unwrap()
        .is_kept());
    let held = cy.next_reopenable().unwrap().expect("from a member");
    let opened = cy.open_envelope(&held.envelope).unwrap().unwrap();
    assert!(matches!(
        cy.process_message_as(G, &opened.inner, "env-bo"),
        Err(Error::NotFromAMember(_))
    ));
    // The process dies here, before the release.
    drop(cy);

    let mut cy = cy_on(&cy_kv);
    assert!(cy.release_held("env-bo").unwrap());
    let adas_seal = device_seal(&device_seed(1), &key_of(3), G, &[0x5a; 32], &by_bo).unwrap();
    assert!(
        cy.hold_envelope_sealed(MAILBOX_MESSAGE, "env-honest", long_ago, &by_bo, &adas_seal)
            .unwrap()
            .is_kept(),
        "no release note: the author's own seal is held"
    );
    let held = cy.next_reopenable().unwrap().expect("Ada's own seal");
    let real = cy.open_envelope(&held.envelope).unwrap().unwrap();
    match cy.process_message_as(G, &real.inner, "env-honest").unwrap() {
        Incoming::Application { sender, .. } => assert_eq!(sender.actor_id, "actor-ada"),
        other => panic!("{other:?}"),
    }
}

/// THE EXTENSION ANSWERED FULL WHILE THE APP STAYED UP. The app's reopen
/// pass had ended with nothing to hand out; the extension, a process of its
/// own on the same store, filled the hold and kept the next envelope without
/// its seal. The app meets that envelope and answers full too, and its next
/// pass hands out what makes room, so the same envelope delivered again is
/// held on its seal rather than acknowledged without it.
#[test]
fn full_from_the_extension_in_a_live_app_makes_room() {
    let s = issuer();
    let cy_kv = MemoryKv::new();
    let cy_on = |kv: &MemoryKv| {
        client_on(
            &s,
            3,
            "actor-cy",
            "device-cy",
            PeachyStorage::open(Box::new(kv.clone())).unwrap(),
        )
    };
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut app = cy_on(&cy_kv);
    group(&mut ada, &mut [&mut bo, &mut app]);
    fork_cy(&mut ada, &mut bo, &mut app);
    app.limit_sealed_hold(u64::MAX, 4, u64::MAX);
    let sealed: Vec<_> = (0..5u64)
        .map(|n| sent(&mut ada, &format!("m{n}"), &key_of(3)))
        .collect();
    for (n, (envelope, seal)) in sealed.iter().enumerate().take(3) {
        assert!(app
            .hold_envelope_sealed(
                MAILBOX_MESSAGE,
                &format!("env-{n}"),
                received_at() + n as u64,
                envelope,
                seal
            )
            .unwrap()
            .is_kept());
    }
    assert!(
        app.next_reopenable().unwrap().is_none(),
        "all wait for the copy: the pass ends"
    );

    let mut nse = cy_on(&cy_kv);
    nse.limit_sealed_hold(u64::MAX, 4, u64::MAX);
    let (e3, s3) = &sealed[3];
    assert!(nse
        .hold_envelope_sealed(MAILBOX_MESSAGE, "env-3", received_at() + 3, e3, s3)
        .unwrap()
        .is_kept());
    let (e4, s4) = &sealed[4];
    assert_eq!(
        nse.hold_envelope_sealed(MAILBOX_MESSAGE, "env-4", received_at() + 4, e4, s4)
            .unwrap(),
        HoldAnswer::Full
    );
    drop(nse);

    assert_eq!(
        app.hold_envelope_sealed(MAILBOX_MESSAGE, "env-4", received_at() + 4, e4, s4)
            .unwrap(),
        HoldAnswer::Full,
        "full here too"
    );
    let held = app
        .next_reopenable()
        .unwrap()
        .expect("the oldest, urgent at the ceiling, is handed out");
    assert_eq!(held.id, "env-0");
    assert!(app.release_held(&held.id).unwrap());
    assert_eq!(
        app.hold_envelope_sealed(MAILBOX_MESSAGE, "env-4", received_at() + 4, e4, s4)
            .unwrap(),
        HoldAnswer::Kept,
        "held on its seal once room was made"
    );
}

/// A COPY GIVEN UP AT ITS FOUNDING (another member founded the same id
/// first) never held anyone else's leaf, so it remembers nobody: a seal
/// naming that group afterwards names nobody, and becomes no placeholder.
#[test]
fn a_copy_given_up_at_its_founding_remembers_nobody() {
    let s = issuer();
    let mut cy = client(&s, 3, "actor-cy", "device-cy");
    cy.create_group(G).unwrap();
    let words = cy.encrypt(G, b"in a founding given up").unwrap();
    cy.forget_group(G).unwrap();

    let (envelope, seal) = forged(3, G, &words, [0x77; 32]);
    let long_ago = received_at() - HELD_ENVELOPE_MAX_AGE_MS - 1;
    assert!(cy
        .hold_envelope_sealed(MAILBOX_MESSAGE, "env-own", long_ago, &envelope, &seal)
        .unwrap()
        .is_kept());
    assert!(cy.next_reopenable().unwrap().is_none(), "names nobody");
    assert!(cy.held_disposition("env-own").is_none());
}
