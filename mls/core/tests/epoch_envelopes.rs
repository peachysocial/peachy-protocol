// SPDX-License-Identifier: MIT
//! ENVELOPES KEYED BY THE EPOCH (`mls/core/src/envelope.rs` §Keyed by the
//! epoch, not the group id; `Client::seal_envelope`).
//!
//! Version 2 of the envelope is keyed by the group id, which a member
//! never loses: removed from the group, it still recognizes every envelope of
//! the group's by its tag, opens each one's outer layer, and can seal
//! envelopes the members' devices take for the group's. Version 3 is keyed by
//! an MLS exporter of the epoch, which a removal takes away.
//!
//! These hold the property: a removed member opens nothing sealed after its
//! removal; every member opens what is sealed by the epoch, a commit wrapped
//! after its merge included, and a sender one epoch behind still gets
//! through; seat asks and link previews stay keyed by the group id.

#![cfg(feature = "test-forgery")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use peachy_mls_core::envelope::{
    open_envelope_for, ENVELOPE_KIND_CALL, ENVELOPE_KIND_COMMIT, ENVELOPE_KIND_LINK_PREVIEW,
    ENVELOPE_KIND_MESSAGE, ENVELOPE_KIND_SEAT_ASK, ENVELOPE_KIND_TYPING, ENVELOPE_VERSION_EPOCH,
    ENVELOPE_VERSION_PADDED,
};
use peachy_mls_core::{Client, Incoming, ENVELOPE_PAST_EPOCHS};
use support::{client, issuer, RemoveLeaf};

const G: &[u8] = b"7a1c0e2d-3b4f-4a5c-8d6e-9f0a1b2c3d4e";

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

fn opened_text(by: &mut Client, envelope: &[u8]) -> Vec<u8> {
    let opened = by
        .open_envelope(envelope)
        .unwrap()
        .expect("the envelope opens");
    assert_eq!(opened.group_id, G);
    assert_eq!(opened.kind, ENVELOPE_KIND_MESSAGE);
    match by.process_message(G, &opened.inner).unwrap() {
        Incoming::Application { plaintext, .. } => plaintext,
        other => panic!("expected an application message, got {other:?}"),
    }
}

/// THE ONE THIS FILE EXISTS FOR. Cy is removed and never shown the commit:
/// it holds the group id and a whole, active copy at the epoch before. What
/// is sealed after the removal neither routes nor opens for it, by its copy
/// or by the group id alone, while what was sealed before still does.
#[test]
fn a_removed_member_opens_nothing_sealed_after_its_removal() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut cy = client(&s, 3, "actor-cy", "device-cy");
    group(&mut ada, &mut [&mut bo, &mut cy]);

    let before = ada.encrypt(G, b"before").unwrap();
    let before = ada
        .seal_envelope(G, ENVELOPE_KIND_MESSAGE, &before)
        .unwrap();
    assert_eq!(before[0], ENVELOPE_VERSION_EPOCH);

    let cy_leaf = ada.leaf_of_device(G, "device-cy").unwrap();
    let removal = ada.remove_leaf(G, cy_leaf).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &removal.commit).unwrap();
    assert!(cy.is_active(G).unwrap(), "Cy was never told");

    let after = ada.encrypt(G, b"after").unwrap();
    let after = ada.seal_envelope(G, ENVELOPE_KIND_MESSAGE, &after).unwrap();
    assert_eq!(after[0], ENVELOPE_VERSION_EPOCH);
    assert_eq!(opened_text(&mut bo, &after), b"after");

    // The control: Cy's copy is alive, and opens what was sealed before.
    assert_eq!(opened_text(&mut cy, &before), b"before");
    // And nothing after: not through its copy, not by the group id.
    assert!(cy.open_envelope(&after).unwrap().is_none());
    assert!(open_envelope_for(G, &after).is_err());
    // Nor a typing frame, the envelope that carries no MLS message at all.
    let typing = ada.seal_envelope(G, ENVELOPE_KIND_TYPING, b"t").unwrap();
    assert!(cy.open_envelope(&typing).unwrap().is_none());
    assert!(bo.open_envelope(&typing).unwrap().is_some());
}

/// A commit is wrapped after the committer merged it, at an epoch its
/// receivers are not at yet: it is sealed under the epoch it was built in.
/// And a member one epoch behind still reaches the members who moved on.
#[test]
fn a_commit_wrapped_after_its_merge_and_a_sender_behind_both_get_through() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    group(&mut ada, &mut [&mut bo]);

    let from_bo = bo.encrypt(G, b"from the epoch before").unwrap();
    let from_bo = bo
        .seal_envelope(G, ENVELOPE_KIND_MESSAGE, &from_bo)
        .unwrap();

    let rotation = ada.self_update(G).unwrap();
    ada.merge_pending_commit(G).unwrap();
    let wrapped = ada
        .seal_envelope(G, ENVELOPE_KIND_COMMIT, &rotation.commit)
        .unwrap();
    assert_eq!(wrapped[0], ENVELOPE_VERSION_EPOCH);
    let opened = bo
        .open_envelope(&wrapped)
        .unwrap()
        .expect("Bo opens the commit");
    assert_eq!(opened.kind, ENVELOPE_KIND_COMMIT);
    assert_eq!(opened.inner, rotation.commit);

    // Ada is past the epoch Bo sealed in, and opens it from what she kept.
    assert_eq!(opened_text(&mut ada, &from_bo), b"from the epoch before");

    bo.process_commit(G, &opened.inner).unwrap();
    let now = ada.encrypt(G, b"same epoch").unwrap();
    let now = ada.seal_envelope(G, ENVELOPE_KIND_MESSAGE, &now).unwrap();
    assert_eq!(opened_text(&mut bo, &now), b"same epoch");
}

/// An envelope sealed further back than the epochs a copy keeps envelope
/// secrets for opens for nobody.
#[test]
fn an_envelope_older_than_the_kept_epochs_opens_for_nobody() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    group(&mut ada, &mut [&mut bo]);
    let old = bo.encrypt(G, b"old").unwrap();
    let old = bo.seal_envelope(G, ENVELOPE_KIND_MESSAGE, &old).unwrap();
    for _ in 0..=ENVELOPE_PAST_EPOCHS {
        let c = ada.self_update(G).unwrap();
        ada.merge_pending_commit(G).unwrap();
        bo.process_commit(G, &c.commit).unwrap();
    }
    assert!(ada.open_envelope(&old).unwrap().is_none());
}

/// Whoever opens a seat ask or a link preview holds no epoch of the group:
/// both stay keyed by the group id.
#[test]
fn seat_asks_and_link_previews_stay_keyed_by_the_group_id() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    group(&mut ada, &mut [&mut bo]);
    for kind in [ENVELOPE_KIND_SEAT_ASK, ENVELOPE_KIND_LINK_PREVIEW] {
        let e = ada.seal_envelope(G, kind, b"{}").unwrap();
        assert_eq!(e[0], ENVELOPE_VERSION_PADDED, "kind {kind}");
        assert_eq!(open_envelope_for(G, &e).unwrap().kind, kind);
    }
    // A seat ask into a group this device does not hold is keyed by the
    // group id too.
    let e = ada
        .seal_envelope(b"not-held", ENVELOPE_KIND_SEAT_ASK, b"{}")
        .unwrap();
    assert_eq!(e[0], ENVELOPE_VERSION_PADDED);
}

/// A message encrypted while the copy was held and sealed after it was
/// forgotten (the rejoin path, a stale outbox) is refused, never sealed by
/// the group id, which a removed member or a link holder would open.
#[test]
fn a_message_sealed_after_its_copy_is_forgotten_is_refused() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    group(&mut ada, &mut [&mut bo]);
    let held = ada.encrypt(G, b"queued before the forget").unwrap();
    ada.forget_group(G).unwrap();
    for kind in [
        ENVELOPE_KIND_MESSAGE,
        ENVELOPE_KIND_COMMIT,
        ENVELOPE_KIND_TYPING,
        ENVELOPE_KIND_CALL,
    ] {
        assert!(
            matches!(
                ada.seal_envelope(G, kind, &held),
                Err(peachy_mls_core::Error::NoSuchGroup)
            ),
            "kind {kind}"
        );
    }
    let ask = ada.seal_envelope(G, ENVELOPE_KIND_SEAT_ASK, b"{}").unwrap();
    assert_eq!(ask[0], ENVELOPE_VERSION_PADDED);
}

/// A message or commit made at an epoch the copy has moved past and no longer
/// keeps is refused, never sealed by the group id, where anyone who holds the
/// group id (a removed member, a link holder) would recognize and open it.
/// The client encrypts it again.
#[test]
fn a_message_or_commit_made_past_the_kept_epochs_is_refused_not_sealed_by_the_group_id() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    group(&mut ada, &mut [&mut bo]);
    let held = ada.encrypt(G, b"made earlier").unwrap();
    let old = ada.self_update(G).unwrap();
    ada.merge_pending_commit(G).unwrap();
    for _ in 0..=ENVELOPE_PAST_EPOCHS + 1 {
        ada.self_update(G).unwrap();
        ada.merge_pending_commit(G).unwrap();
    }
    let copy_epoch = ada.epoch(G).unwrap();
    for (kind, inner) in [
        (ENVELOPE_KIND_MESSAGE, &held),
        (ENVELOPE_KIND_COMMIT, &old.commit),
    ] {
        match ada.seal_envelope(G, kind, inner) {
            Err(peachy_mls_core::Error::StaleCopy {
                message_epoch,
                copy_epoch: at,
            }) => {
                assert!(message_epoch < copy_epoch, "kind {kind}");
                assert_eq!(at, copy_epoch, "kind {kind}");
            }
            other => panic!("kind {kind}: expected STALE_COPY, got {other:?}"),
        }
    }
    // Encrypted again, it seals by the epoch.
    let again = ada.encrypt(G, b"made earlier").unwrap();
    let sealed = ada.seal_envelope(G, ENVELOPE_KIND_MESSAGE, &again).unwrap();
    assert_eq!(sealed[0], ENVELOPE_VERSION_EPOCH);
}

/// A copy no longer in the group seals nothing but a seat ask or a link
/// preview: not by the group id either.
#[test]
fn a_removed_copy_seals_no_message_by_the_group_id() {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    group(&mut ada, &mut [&mut bo]);
    let bo_leaf = ada.leaf_of_device(G, "device-bo").unwrap();
    let removal = ada.remove_leaf(G, bo_leaf).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &removal.commit).unwrap();
    for kind in [
        ENVELOPE_KIND_MESSAGE,
        ENVELOPE_KIND_COMMIT,
        ENVELOPE_KIND_TYPING,
    ] {
        assert!(
            matches!(
                bo.seal_envelope(G, kind, b"x"),
                Err(peachy_mls_core::Error::NotAMember)
            ),
            "kind {kind}"
        );
    }
    let ask = bo.seal_envelope(G, ENVELOPE_KIND_SEAT_ASK, b"{}").unwrap();
    assert_eq!(ask[0], ENVELOPE_VERSION_PADDED);
}
