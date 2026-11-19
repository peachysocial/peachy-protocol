// SPDX-License-Identifier: MIT
//! LEAVING TAKES THE PERSON OUT.
//!
//! A member cannot commit its own removal (RFC 9420 §12.2), so a person who
//! leaves proposes the removal of each of their leaves (`Client::propose_leave`)
//! and another member's device commits the proposals
//! (`Client::commit_proposed_leaves`). Every member's device reads who left
//! from `CommitOutcome::left`.
//!
//! - **A leave is committed by another person's device, and the leaver is
//!   gone**: every one of their leaves leaves the tree, and the next message
//!   is not encrypted to any of them.
//! - **A leave is the one proposal by reference.** A Remove of SOMEBODY
//!   ELSE's leaf sent as a standalone proposal is still refused at the
//!   message door, and nothing is left queued for a commit to sweep in.
//! - **The leaver's own siblings never commit it**: a member cannot commit
//!   its own person's removal any more than its own.
//! - **A commit that takes the epoch first drops the leave**: the proposals
//!   were sealed at the old epoch; nothing is committed later by mistake.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;

use peachy_mls_core::{Client, Error, Incoming, ProposalKind};
use support::{client, head_of, issuer, join_at_head};

const G: &[u8] = b"88888888-8888-4888-8888-888888888888";

fn add(adder: &mut Client, joiner: &mut Client) -> Vec<u8> {
    let key_package = joiner.generate_key_package().expect("key package");
    let bundle = adder.add_member(G, &key_package).expect("add");
    adder.merge_pending_commit(G).expect("merge");
    join_at_head(joiner, &bundle.welcome.expect("welcome"), head_of(adder, G)).expect("join");
    bundle.commit
}

fn follow(client: &mut Client, commit: &[u8]) -> Incoming {
    client
        .process_commit(G, commit)
        .expect("follows the commit")
}

/// Ada (the founder), Bo on a phone and a laptop, and Cy: four devices, all
/// at one epoch.
fn group() -> (Client, Client, Client, Client) {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut bo_phone = client(&server, 2, "actor-bo", "device-bo-phone");
    let mut bo_laptop = client(&server, 3, "actor-bo", "device-bo-laptop");
    let mut cy = client(&server, 4, "actor-cy", "device-cy");
    ada.create_group(G).unwrap();
    add(&mut ada, &mut bo_phone);
    let c = add(&mut ada, &mut bo_laptop);
    follow(&mut bo_phone, &c);
    let c = add(&mut ada, &mut cy);
    follow(&mut bo_phone, &c);
    follow(&mut bo_laptop, &c);
    (ada, bo_phone, bo_laptop, cy)
}

fn queue(client: &mut Client, proposal: &[u8]) {
    match client
        .process_message(G, proposal)
        .expect("queues the leave")
    {
        Incoming::ProposalQueued { sender, kind } => {
            assert_eq!(sender.actor_id, "actor-bo");
            assert_eq!(kind, ProposalKind::Remove);
        }
        other => panic!("expected a queued proposal, got {other:?}"),
    }
}

/// Bo leaves from his phone: one proposal per leaf of his, both devices'.
fn bo_proposes(bo_phone: &mut Client) -> Vec<Vec<u8>> {
    let phone = bo_phone.leaf_of_device(G, "device-bo-phone").unwrap();
    let laptop = bo_phone.leaf_of_device(G, "device-bo-laptop").unwrap();
    vec![
        bo_phone
            .propose_leave(G, phone)
            .expect("propose the phone's leaf"),
        bo_phone
            .propose_leave(G, laptop)
            .expect("propose the laptop's leaf"),
    ]
}

fn reads(sender: &mut Client, reader: &mut Client, text: &[u8]) -> bool {
    let wire = sender.encrypt(G, text).expect("encrypt");
    match reader.process_message(G, &wire) {
        Ok(Incoming::Application { plaintext, .. }) => plaintext == text,
        _ => false,
    }
}

#[test]
fn a_leave_is_committed_by_another_member_and_the_leaver_is_gone() {
    let (mut ada, mut bo_phone, mut bo_laptop, mut cy) = group();
    let proposals = bo_proposes(&mut bo_phone);
    for proposal in &proposals {
        queue(&mut ada, proposal);
        queue(&mut cy, proposal);
        // The sibling stores them too (a commit names them by reference)…
        queue(&mut bo_laptop, proposal);
    }
    // …and never commits them: a member cannot commit its own person out.
    assert!(bo_laptop.commit_proposed_leaves(G).unwrap().is_none());
    // Nor can the leaver (whose device forgets the group instead).
    assert!(bo_phone.commit_proposed_leaves(G).unwrap().is_none());

    let bundle = cy
        .commit_proposed_leaves(G)
        .unwrap()
        .expect("Cy has a leave to commit");
    assert!(bundle.welcome.is_none());
    cy.merge_pending_commit(G).expect("merge the leave");

    match follow(&mut ada, &bundle.commit) {
        Incoming::Commit(outcome) => {
            assert_eq!(outcome.sender.actor_id, "actor-cy");
            assert_eq!(outcome.left, vec!["actor-bo".to_owned()]);
            assert_eq!(outcome.removed.len(), 2);
            assert!(!outcome.removed_self);
        }
        other => panic!("expected a commit, got {other:?}"),
    }
    // The sibling that did not forget yet reads its own removal.
    match follow(&mut bo_laptop, &bundle.commit) {
        Incoming::Commit(outcome) => {
            assert!(outcome.removed_self);
            assert_eq!(outcome.left, vec!["actor-bo".to_owned()]);
        }
        other => panic!("expected a commit, got {other:?}"),
    }

    // Bo has no leaf left, on either device's roster…
    for member in [&ada, &cy] {
        let roster = member.roster(G).unwrap();
        assert_eq!(roster.len(), 2);
        assert!(roster.iter().all(|entry| entry
            .identity
            .as_ref()
            .map(|identity| identity.actor_id != "actor-bo")
            .unwrap_or(true)));
    }
    // …and the next message is not encrypted to him: his phone, which never
    // saw the commit and still holds the old epoch, cannot open it, while
    // Cy can.
    let next = ada.encrypt(G, b"after bo left").unwrap();
    match cy.process_message(G, &next).unwrap() {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"after bo left"),
        other => panic!("expected an application message, got {other:?}"),
    }
    assert!(bo_phone.process_message(G, &next).is_err());
    assert!(reads(&mut cy, &mut ada, b"still a group of two"));
}

#[test]
fn a_remove_of_somebody_else_by_proposal_is_still_refused() {
    let (mut ada, mut bo_phone, _bo_laptop, mut cy) = group();
    // Bo cannot propose Cy out through the leave door…
    let cy_leaf = bo_phone.leaf_of_device(G, "device-cy").unwrap();
    assert!(matches!(
        bo_phone.propose_leave(G, cy_leaf),
        Err(Error::InvalidArgument(_))
    ));
    // …and a leave never reaches the store of a device that is not shown one.
    assert!(ada.commit_proposed_leaves(G).unwrap().is_none());
    assert!(cy.commit_proposed_leaves(G).unwrap().is_none());
}

#[test]
fn a_commit_that_takes_the_epoch_first_drops_the_leave() {
    let (mut ada, mut bo_phone, _bo_laptop, mut cy) = group();
    for proposal in bo_proposes(&mut bo_phone) {
        queue(&mut ada, &proposal);
        queue(&mut cy, &proposal);
    }
    // Ada commits something else first; the delivery service takes it.
    let update = ada.self_update(G).unwrap();
    ada.merge_pending_commit(G).unwrap();
    follow(&mut cy, &update.commit);
    // The proposals were sealed at the old epoch: nobody holds them now.
    assert!(cy.commit_proposed_leaves(G).unwrap().is_none());
    assert!(ada.commit_proposed_leaves(G).unwrap().is_none());
    assert_eq!(cy.roster(G).unwrap().len(), 4);
}

#[test]
fn two_members_racing_to_commit_one_leave_settle_on_one() {
    let (mut ada, mut bo_phone, _bo_laptop, mut cy) = group();
    for proposal in bo_proposes(&mut bo_phone) {
        queue(&mut ada, &proposal);
        queue(&mut cy, &proposal);
    }
    let from_ada = ada.commit_proposed_leaves(G).unwrap().expect("ada's");
    let _from_cy = cy.commit_proposed_leaves(G).unwrap().expect("cy's");
    // The delivery service takes Ada's; Cy clears its own and applies hers.
    ada.merge_pending_commit(G).unwrap();
    cy.clear_pending_commit(G).unwrap();
    match follow(&mut cy, &from_ada.commit) {
        Incoming::Commit(outcome) => assert_eq!(outcome.left, vec!["actor-bo".to_owned()]),
        other => panic!("expected a commit, got {other:?}"),
    }
    assert!(reads(&mut ada, &mut cy, b"two of us now"));
}

/// A leave of one of Bo's leaves, folded into a commit that removes his
/// other leaf inline, is the committer's removal of Bo, not Bo leaving:
/// "left" needs every leaf of his to go by a leave of his own.
#[cfg(feature = "test-forgery")]
#[test]
fn a_partial_leave_folded_into_an_inline_removal_is_not_a_leave() {
    let (mut ada, mut bo_phone, _bo_laptop, mut cy) = group();
    let phone = bo_phone.leaf_of_device(G, "device-bo-phone").unwrap();
    let laptop = ada.leaf_of_device(G, "device-bo-laptop").unwrap();
    let proposal = bo_phone.propose_leave(G, phone).unwrap();
    queue(&mut ada, &proposal);
    queue(&mut cy, &proposal);

    let bundle = ada.forge_commit_with_queued(G, &[laptop]).unwrap();
    ada.merge_pending_commit(G).unwrap();
    match follow(&mut cy, &bundle.commit) {
        Incoming::Commit(outcome) => {
            assert_eq!(outcome.sender.actor_id, "actor-ada");
            let mut removed = outcome.removed.clone();
            removed.sort_unstable();
            let mut both = vec![phone, laptop];
            both.sort_unstable();
            assert_eq!(removed, both, "both of Bo's leaves are removed");
            assert!(
                outcome.left.is_empty(),
                "drawn as Bo leaving: {:?}",
                outcome.left
            );
        }
        other => panic!("expected a commit, got {other:?}"),
    }
}
