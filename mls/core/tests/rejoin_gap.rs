// SPDX-License-Identifier: MIT
//! WHAT A DEVICE MISSED WHILE IT COULD NOT FOLLOW (`mls/core/src/welcome_frame.rs`
//! §The gap block; `Client::hold_envelope`, `Client::next_reopenable`,
//! `Client::release_held`).
//!
//! An envelope keyed by the epoch (version 3) opens only for a device that
//! holds that epoch. A copy that forked or fell behind does not, so the
//! envelopes sealed to it meanwhile open for nothing it holds. Keyed by the
//! group id, they still opened, and the MLS message inside, which did not,
//! carried its content hint and author's commitment: the device held a
//! placeholder and asked for the message again once it was back.
//!
//! These hold that the epoch keying loses none of it. The device keeps what
//! opened for nothing; the member that hands its seat back puts the epochs
//! its seat was held through in the Welcome; once back, the device opens
//! each kept envelope and reads, off the message it cannot decrypt, that it
//! was a message, which kind of loss it is, and whom it commits to. And none
//! of that reopens what the epoch keying closed: a device removed and added
//! back gets nothing of what was sealed while it was out.

#![cfg(feature = "test-forgery")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use peachy_mls_core::envelope::{ENVELOPE_KIND_MESSAGE, ENVELOPE_VERSION_EPOCH};
use peachy_mls_core::hint::{peek_message, resend_author_commitment, CONTENT_HINT_RESENDABLE};
use peachy_mls_core::welcome_frame::WELCOME_FRAME_GAP_MAGIC;
use peachy_mls_core::{Client, Incoming, KvEntry, KvError, KvStore, MemoryKv, PeachyStorage};
use support::{client, client_on, issuer, RemoveLeaf, NOW};

const G: &[u8] = b"3f0d9c1e-6a2b-4c7d-8e5f-0a1b2c3d4e5f";
const MAILBOX_MESSAGE: u8 = 1;
const ID: &str = "0b7e5a52-3c1d-4f2e-9a8b-7c6d5e4f3a2b";

fn received_at() -> u64 {
    u64::try_from(NOW * 1000).unwrap()
}

/// Ada founds the group and adds each of `others` in turn; every member
/// follows every add.
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

/// A transcript frame Ada sends with the resendable hint, sealed as the
/// apps seal it.
fn sent_by_ada(ada: &mut Client, text: &str) -> Vec<u8> {
    let frame = [
        vec![0xFF, 0x01],
        format!(r#"{{"i":"{ID}","t":"{text}"}}"#).into_bytes(),
    ]
    .concat();
    let message = ada
        .encrypt_with_hint(G, &frame, CONTENT_HINT_RESENDABLE)
        .unwrap();
    let envelope = ada
        .seal_envelope(G, ENVELOPE_KIND_MESSAGE, &message)
        .unwrap();
    assert_eq!(envelope[0], ENVELOPE_VERSION_EPOCH);
    envelope
}

/// Cy's copy forks: it merges a commit of its own the group never took,
/// while Ada's moves the group on and Bo follows.
fn fork_cy(ada: &mut Client, bo: &mut Client, cy: &mut Client) {
    cy.self_update(G).unwrap();
    cy.merge_pending_commit(G).unwrap();
    let main_line = ada.self_update(G).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &main_line.commit).unwrap();
}

/// Cy forgets its copy and asks back in; Ada hands its seat back, and Cy
/// takes the Welcome. Answers the Welcome.
fn reseat_cy(ada: &mut Client, bo: &mut Client, cy: &mut Client) -> Vec<u8> {
    cy.forget_group(G).unwrap();
    let kp = cy.generate_key_package().unwrap();
    let cy_leaf = ada.leaf_of_device(G, "device-cy").unwrap();
    let back = ada.replace_member(G, cy_leaf, &kp).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &back.commit).unwrap();
    let welcome = back.welcome.unwrap();
    cy.join_from_welcome(&welcome).unwrap();
    welcome
}

/// THE ONE THIS FILE EXISTS FOR. Cy forks; Ada sends while it is out of
/// step; the envelope opens for nothing Cy holds, so Cy keeps it. Ada hands
/// Cy its seat back, and the envelope opens: the message inside, from an
/// epoch Cy never held, does not decrypt, but says it is a resendable
/// message and commits to Ada, which is what Cy draws a placeholder and asks
/// again by.
#[test]
fn a_forked_device_learns_what_it_missed_and_from_whom_once_it_is_back() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = client(&s, 3, "actor-cy", "device-cy");
    group(&mut ada, &mut [&mut bo, &mut cy]);

    fork_cy(&mut ada, &mut bo, &mut cy);
    let missed = sent_by_ada(&mut ada, "while you were out of step");
    assert!(bo.open_envelope(&missed).unwrap().is_some());
    assert!(cy.open_envelope(&missed).unwrap().is_none(), "Cy forked");
    assert!(cy
        .hold_envelope(MAILBOX_MESSAGE, "env-missed", received_at(), &missed)
        .unwrap());
    // Held once only, and nothing to reopen while Cy is still out.
    assert!(!cy
        .hold_envelope(MAILBOX_MESSAGE, "env-missed", received_at(), &missed)
        .unwrap());
    assert!(cy.next_reopenable().unwrap().is_none());

    let welcome = reseat_cy(&mut ada, &mut bo, &mut cy);
    assert_eq!(welcome[..4], WELCOME_FRAME_GAP_MAGIC, "a reseat's frame");

    let held = cy
        .next_reopenable()
        .unwrap()
        .expect("the envelope opens once Cy is back");
    assert_eq!(held.id, "env-missed");
    assert_eq!(held.mailbox_kind, MAILBOX_MESSAGE);
    assert_eq!(held.received_at_ms, received_at());
    assert!(
        cy.next_reopenable().unwrap().is_none(),
        "not handed out twice in a pass"
    );

    let opened = cy
        .open_envelope(&held.envelope)
        .unwrap()
        .expect("opens under an epoch handed back");
    assert_eq!(opened.group_id, G);
    assert_eq!(opened.kind, ENVELOPE_KIND_MESSAGE);
    assert!(
        cy.process_message(G, &opened.inner).is_err(),
        "the message itself is from an epoch Cy never held"
    );
    let peek = peek_message(&opened.inner).expect("a group message");
    assert_eq!(peek.hint, Some(CONTENT_HINT_RESENDABLE));
    assert_eq!(
        peek.commitment,
        Some(resend_author_commitment(G, "actor-ada", ID.as_bytes())),
        "it commits to Ada"
    );

    // And Cy is a member again: what Ada sends now reads.
    let now = ada.encrypt(G, b"welcome back").unwrap();
    let now = ada.seal_envelope(G, ENVELOPE_KIND_MESSAGE, &now).unwrap();
    let opened = cy.open_envelope(&now).unwrap().unwrap();
    match cy.process_message(G, &opened.inner).unwrap() {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"welcome back"),
        other => panic!("expected an application message, got {other:?}"),
    }

    // Released once its placeholder is stored: kept no longer.
    assert!(cy.release_held("env-missed").unwrap());
    assert!(cy.next_reopenable().unwrap().is_none());
    assert!(cy.next_reopenable().unwrap().is_none());
}

/// A PROCESS THAT DIES between being handed a kept envelope and storing
/// what it made of it loses nothing: the envelope stays kept until it is
/// released, so the core opened again on the same store hands it out again.
/// And one handed out but not released in a pass (the caller stopped early)
/// comes back in the next.
#[test]
fn a_kept_envelope_survives_a_death_before_its_placeholder_is_stored() {
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
    let missed = sent_by_ada(&mut ada, "while you were out of step");
    assert!(cy
        .hold_envelope(MAILBOX_MESSAGE, "env-missed", received_at(), &missed)
        .unwrap());
    reseat_cy(&mut ada, &mut bo, &mut cy);

    let held = cy
        .next_reopenable()
        .unwrap()
        .expect("opens once Cy is back");
    assert_eq!(held.id, "env-missed");
    // The process dies here, before the placeholder is written.
    drop(cy);

    let mut cy = cy_on(&cy_kv);
    let again = cy
        .next_reopenable()
        .unwrap()
        .expect("handed out again after the restart");
    assert_eq!(again, held);
    // This pass stops before storing it: the next pass hands it out again.
    assert!(cy.next_reopenable().unwrap().is_none(), "the pass is over");
    let once_more = cy
        .next_reopenable()
        .unwrap()
        .expect("handed out again in the next pass");
    assert_eq!(once_more.id, "env-missed");

    assert!(cy.release_held("env-missed").unwrap());
    assert!(!cy.release_held("env-missed").unwrap(), "released once");
    assert!(cy.next_reopenable().unwrap().is_none());
    drop(cy);
    let mut cy = cy_on(&cy_kv);
    assert!(
        cy.next_reopenable().unwrap().is_none(),
        "a released envelope stays gone"
    );
}

/// A store that refuses puts and deletes while `fail` is set: a full disk
/// or a locked database at the moment a release is written.
#[derive(Debug, Clone)]
struct RefusingKv {
    inner: MemoryKv,
    fail: Arc<AtomicBool>,
}

impl RefusingKv {
    fn write(&self) -> Result<(), KvError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(KvError::new("injected: disk full"));
        }
        Ok(())
    }
}

impl KvStore for RefusingKv {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, KvError> {
        self.inner.get(key)
    }
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), KvError> {
        self.write()?;
        self.inner.put(key, value)
    }
    fn delete(&self, key: &[u8]) -> Result<(), KvError> {
        self.write()?;
        self.inner.delete(key)
    }
    fn scan(&self, prefix: &[u8]) -> Result<Vec<KvEntry>, KvError> {
        self.inner.scan(prefix)
    }
    fn flush(&self) -> Result<(), KvError> {
        self.inner.flush()
    }
    fn rollback(&self) -> Result<(), KvError> {
        self.inner.rollback()
    }
}

/// A RELEASE WHOSE WRITE FAILS is no release: the envelope stays kept, and
/// it stays handed out for the rest of the pass, so a caller looping on
/// `next_reopenable` is not handed it again (and again) in the same pass.
/// The next pass hands it out again, and a release that is stored then ends
/// it.
#[test]
fn a_release_that_is_not_stored_hands_nothing_out_again_in_the_pass() {
    let s = issuer();
    let kv = RefusingKv {
        inner: MemoryKv::new(),
        fail: Arc::new(AtomicBool::new(false)),
    };
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = client_on(
        &s,
        3,
        "actor-cy",
        "device-cy",
        PeachyStorage::open(Box::new(kv.clone())).unwrap(),
    );
    group(&mut ada, &mut [&mut bo, &mut cy]);

    fork_cy(&mut ada, &mut bo, &mut cy);
    let missed = sent_by_ada(&mut ada, "while you were out of step");
    assert!(cy
        .hold_envelope(MAILBOX_MESSAGE, "env-missed", received_at(), &missed)
        .unwrap());
    reseat_cy(&mut ada, &mut bo, &mut cy);

    let held = cy
        .next_reopenable()
        .unwrap()
        .expect("opens once Cy is back");
    assert_eq!(held.id, "env-missed");

    kv.fail.store(true, Ordering::SeqCst);
    assert!(
        cy.release_held("env-missed").is_err(),
        "the refused write is reported"
    );
    kv.fail.store(false, Ordering::SeqCst);
    assert!(
        cy.next_reopenable().unwrap().is_none(),
        "not handed out again in the pass whose release failed"
    );

    let again = cy
        .next_reopenable()
        .unwrap()
        .expect("still kept: handed out again in the next pass");
    assert_eq!(again, held);
    assert!(cy.release_held("env-missed").unwrap());
    assert!(cy.next_reopenable().unwrap().is_none());
    assert!(
        cy.next_reopenable().unwrap().is_none(),
        "released once the write is stored"
    );
}

/// The control: a member that hands back no gap leaves the envelope held
/// and unopened, the loss the gap block repairs.
#[test]
fn without_the_gap_the_missed_envelope_stays_unopened() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = client(&s, 3, "actor-cy", "device-cy");
    group(&mut ada, &mut [&mut bo, &mut cy]);
    ada.act_as_member_handing_back_no_gap();

    fork_cy(&mut ada, &mut bo, &mut cy);
    let missed = sent_by_ada(&mut ada, "lost");
    assert!(cy
        .hold_envelope(MAILBOX_MESSAGE, "env-lost", received_at(), &missed)
        .unwrap());
    reseat_cy(&mut ada, &mut bo, &mut cy);
    assert!(cy.next_reopenable().unwrap().is_none());
    assert!(cy.open_envelope(&missed).unwrap().is_none());
}

/// A device that falls behind (it misses commits, and forgets its copy to
/// ask back in) gets the epochs it missed too, several of them.
#[test]
fn a_device_that_fell_behind_gets_every_epoch_it_missed() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = client(&s, 3, "actor-cy", "device-cy");
    group(&mut ada, &mut [&mut bo, &mut cy]);

    let mut missed = Vec::new();
    for round in 0..3 {
        let c = ada.self_update(G).unwrap();
        ada.merge_pending_commit(G).unwrap();
        bo.process_commit(G, &c.commit).unwrap();
        let envelope = sent_by_ada(&mut ada, "behind");
        assert!(cy.open_envelope(&envelope).unwrap().is_none());
        let id = format!("env-{round}");
        assert!(cy
            .hold_envelope(MAILBOX_MESSAGE, &id, received_at() + round, &envelope)
            .unwrap());
        missed.push(id);
    }
    reseat_cy(&mut ada, &mut bo, &mut cy);
    let mut reopened = Vec::new();
    while let Some(held) = cy.next_reopenable().unwrap() {
        assert!(cy.open_envelope(&held.envelope).unwrap().is_some());
        assert!(cy.release_held(&held.id).unwrap());
        reopened.push(held.id);
    }
    assert_eq!(reopened, missed, "oldest first, every one");
}

/// What the epoch keying closed stays closed. Cy is removed and never told;
/// Ada sends while Cy is out. Cy is added back, then forks and is reseated:
/// the reseat hands back the epochs since the re-add, and none from before
/// it, so what was sealed while Cy was out never opens for it.
#[test]
fn a_device_removed_and_added_back_gets_nothing_sealed_while_it_was_out() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = client(&s, 3, "actor-cy", "device-cy");
    group(&mut ada, &mut [&mut bo, &mut cy]);

    let cy_leaf = ada.leaf_of_device(G, "device-cy").unwrap();
    let removal = ada.remove_leaf(G, cy_leaf).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &removal.commit).unwrap();
    let while_out = sent_by_ada(&mut ada, "while you were out");
    assert!(cy.open_envelope(&while_out).unwrap().is_none());
    assert!(cy
        .hold_envelope(MAILBOX_MESSAGE, "env-out", received_at(), &while_out)
        .unwrap());

    // Added back: an ordinary add, over a copy Cy lets go of.
    cy.forget_group(G).unwrap();
    let kp = cy.generate_key_package().unwrap();
    let readd = ada.add_member(G, &kp).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &readd.commit).unwrap();
    cy.join_from_welcome(&readd.welcome.unwrap()).unwrap();
    assert!(cy.next_reopenable().unwrap().is_none());

    // Then forked, sent to, and reseated.
    fork_cy(&mut ada, &mut bo, &mut cy);
    let during_fork = sent_by_ada(&mut ada, "during the fork");
    assert!(cy
        .hold_envelope(MAILBOX_MESSAGE, "env-fork", received_at() + 1, &during_fork)
        .unwrap());
    reseat_cy(&mut ada, &mut bo, &mut cy);

    let held = cy.next_reopenable().unwrap().expect("the fork's envelope");
    assert_eq!(held.id, "env-fork");
    assert!(cy.next_reopenable().unwrap().is_none());
    assert!(
        cy.open_envelope(&while_out).unwrap().is_none(),
        "sealed while Cy was out of the group"
    );
}
