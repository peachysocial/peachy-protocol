// SPDX-License-Identifier: MIT
//! NOTHING A MEMBER QUEUES RIDES INTO ANOTHER MEMBER'S COMMIT.
//!
//! The group's policy judges each change as its sender's. A proposal sent on
//! its own (by reference) is one member's change that a different member
//! commits, so Peachy takes none (`mls/core/src/rules.rs` §Why proposals by
//! reference are refused; `proposal_by_reference` in `mls/fixtures/rules.json`):
//!
//! - every member refuses a standalone proposal when it arrives, so it never
//!   reaches the proposal store;
//! - an honest committer never consumes the proposal store, so its commit
//!   carries exactly the change asked for, all of it inline;
//! - every member refuses a commit that names a proposal by reference, whole.
//!
//! The one exception is a LEAVE: a Remove of a leaf of the proposer's own
//! person, which a member cannot commit itself (`tests/leave.rs`). Anything
//! else on the message door is the wrong door, dropped unread.
//!
//! Before this, a non-admin's standalone proposals (make me the only admin,
//! remove Cy) were queued by everybody, swept into the admin's next ordinary
//! commit, and judged as the admin's.

#![cfg(feature = "test-forgery")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use peachy_mls_core::issuer::TestIssuer;
use peachy_mls_core::{Client, DenyReason, Error, Incoming};
use support::{client, issuer};

const GROUP: &[u8] = b"11111111-1111-4111-8111-111111111111";

fn meta(admins: &[&str]) -> Vec<u8> {
    let list: Vec<String> = admins.iter().map(|a| format!("\"{a}\"")).collect();
    format!("{{\"v\":1,\"n\":\"Walk\",\"adm\":[{}]}}", list.join(",")).into_bytes()
}

/// Ada (the only admin), Bo and Cy, all at the same epoch.
fn three(server: &TestIssuer) -> (Client, Client, Client) {
    let mut ada = client(server, 1, "actor-ada", "device-ada");
    let mut bo = client(server, 2, "actor-bo", "device-bo");
    let mut cy = client(server, 3, "actor-cy", "device-cy");
    ada.create_group(GROUP).unwrap();
    ada.set_group_meta(GROUP, &meta(&["actor-ada"])).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    let add_bo = ada
        .add_member(GROUP, &bo.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    bo.join_from_welcome(&add_bo.welcome.unwrap()).unwrap();
    let add_cy = ada
        .add_member(GROUP, &cy.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    bo.process_commit(GROUP, &add_cy.commit).unwrap();
    cy.join_from_welcome(&add_cy.welcome.unwrap()).unwrap();
    (ada, bo, cy)
}

fn by_reference(outcome: peachy_mls_core::Result<Incoming>) -> bool {
    matches!(
        outcome,
        Err(Error::PolicyRefused(DenyReason::ProposalByReference))
    )
}

fn meta_of(client: &Client) -> String {
    String::from_utf8(client.group_meta(GROUP).unwrap().unwrap()).unwrap()
}

/// Proposals by reference, end to end. Bo, not an admin, sends two standalone
/// proposals: make Bo the only admin, and remove Cy. Ada then adds Dee, an
/// ordinary commit. Ada stays the only admin, Cy stays in, and Ada can still
/// remove Bo.
#[test]
fn a_non_admins_standalone_proposals_never_reach_an_admins_commit() {
    let server = issuer();
    let (mut ada, mut bo, mut cy) = three(&server);
    let dee = client(&server, 4, "actor-dee", "device-dee");

    // Bo cannot do it himself.
    assert!(bo.set_group_meta(GROUP, &meta(&["actor-bo"])).is_err());

    // So a modified client of his sends the two changes on their own.
    let cy_leaf = bo.leaf_of_device(GROUP, "device-cy").unwrap();
    let make_bo_admin = bo
        .forge_propose_group_meta(GROUP, &meta(&["actor-bo"]))
        .unwrap();
    let remove_cy = bo.forge_propose_remove(GROUP, cy_leaf).unwrap();
    for proposal in [&make_bo_admin, &remove_cy] {
        assert!(
            by_reference(ada.forge_process_any(GROUP, proposal)),
            "ada took bo's standalone proposal"
        );
        assert!(
            by_reference(cy.forge_process_any(GROUP, proposal)),
            "cy took bo's standalone proposal"
        );
    }

    // Ada does something ordinary.
    let add_dee = ada
        .add_member(GROUP, &dee.generate_key_package().unwrap())
        .expect("ada's add");
    ada.merge_pending_commit(GROUP).unwrap();
    for (name, member) in [("bo", &mut bo), ("cy", &mut cy)] {
        match member.process_commit(GROUP, &add_dee.commit) {
            Ok(Incoming::Commit(outcome)) => {
                assert_eq!(
                    outcome.added.len(),
                    1,
                    "{name}: the add carried more than dee"
                );
                assert!(
                    outcome.removed.is_empty(),
                    "{name}: the add removed somebody"
                );
            }
            other => panic!("{name} did not merge ada's add: {other:?}"),
        }
    }

    for member in [&ada, &bo, &cy] {
        let now = meta_of(member);
        assert!(now.contains("\"adm\":[\"actor-ada\"]"), "{now}");
    }
    assert!(
        ada.leaf_of_device(GROUP, "device-cy").is_ok(),
        "cy is still in"
    );
    let bo_leaf = ada.leaf_of_device(GROUP, "device-bo").unwrap();
    ada.remove_leaf(GROUP, bo_leaf)
        .expect("ada is still the admin and may remove bo");
}

/// THE COMMITTER'S HALF. A store written before this build may still hold a
/// queued proposal; Ada's ordinary add must not carry it.
#[test]
fn an_honest_commit_never_carries_a_queued_proposal() {
    let server = issuer();
    let (mut ada, mut bo, mut cy) = three(&server);
    let dee = client(&server, 4, "actor-dee", "device-dee");

    let cy_leaf = bo.leaf_of_device(GROUP, "device-cy").unwrap();
    let make_bo_admin = bo
        .forge_propose_group_meta(GROUP, &meta(&["actor-bo"]))
        .unwrap();
    let remove_cy = bo.forge_propose_remove(GROUP, cy_leaf).unwrap();
    for proposal in [&make_bo_admin, &remove_cy] {
        ada.forge_store_proposal(GROUP, proposal).unwrap();
        cy.forge_store_proposal(GROUP, proposal).unwrap();
    }

    let add_dee = ada
        .add_member(GROUP, &dee.generate_key_package().unwrap())
        .expect("ada's add, past her own checks");
    ada.merge_pending_commit(GROUP).unwrap();
    for member in [&mut bo, &mut cy] {
        assert!(matches!(
            member.process_commit(GROUP, &add_dee.commit),
            Ok(Incoming::Commit(_))
        ));
    }
    assert!(meta_of(&ada).contains("\"adm\":[\"actor-ada\"]"));
    assert!(
        ada.leaf_of_device(GROUP, "device-cy").is_ok(),
        "cy is still in"
    );
}

/// The committer's half for the other two ordinary commits: a rotation and a
/// removal each carry their own change and nothing queued.
#[test]
fn a_rotation_and_a_removal_never_carry_a_queued_proposal() {
    let server = issuer();
    for removal in [false, true] {
        let (mut ada, mut bo, mut cy) = three(&server);
        let cy_leaf = bo.leaf_of_device(GROUP, "device-cy").unwrap();
        let make_bo_admin = bo
            .forge_propose_group_meta(GROUP, &meta(&["actor-bo"]))
            .unwrap();
        let remove_cy = bo.forge_propose_remove(GROUP, cy_leaf).unwrap();
        for proposal in [&make_bo_admin, &remove_cy] {
            ada.forge_store_proposal(GROUP, proposal).unwrap();
            cy.forge_store_proposal(GROUP, proposal).unwrap();
        }
        let bundle = if removal {
            let bo_leaf = ada.leaf_of_device(GROUP, "device-bo").unwrap();
            ada.remove_leaf(GROUP, bo_leaf).expect("ada removes bo")
        } else {
            ada.self_update(GROUP).expect("ada rotates")
        };
        assert!(bundle.welcome.is_none());
        ada.merge_pending_commit(GROUP).unwrap();
        match cy.process_commit(GROUP, &bundle.commit) {
            Ok(Incoming::Commit(outcome)) => {
                assert!(outcome.added.is_empty());
                assert_eq!(outcome.removed.len(), usize::from(removal));
            }
            other => panic!("cy did not merge ada's commit: {other:?}"),
        }
        assert!(meta_of(&cy).contains("\"adm\":[\"actor-ada\"]"));
        assert!(
            cy.leaf_of_device(GROUP, "device-cy").is_ok(),
            "cy is still in"
        );
    }
}

/// THE RECEIVERS' HALF. A modified committer that sweeps the store sends a
/// commit naming Bo's proposals by reference. Every member refuses it whole, Bo included, even where the
/// store it reads them from holds them.
#[test]
fn every_member_refuses_a_commit_that_names_a_proposal_by_reference() {
    let server = issuer();
    let (mut ada, mut bo, mut cy) = three(&server);
    let dee = client(&server, 4, "actor-dee", "device-dee");

    let cy_leaf = bo.leaf_of_device(GROUP, "device-cy").unwrap();
    let make_bo_admin = bo
        .forge_propose_group_meta(GROUP, &meta(&["actor-bo"]))
        .unwrap();
    let remove_cy = bo.forge_propose_remove(GROUP, cy_leaf).unwrap();
    for proposal in [&make_bo_admin, &remove_cy] {
        ada.forge_store_proposal(GROUP, proposal).unwrap();
        cy.forge_store_proposal(GROUP, proposal).unwrap();
    }

    let swept = ada
        .forge_add_member_sweeping(GROUP, &dee.generate_key_package().unwrap())
        .expect("the sweeping add");
    let epoch = cy.epoch(GROUP).unwrap();
    assert!(
        by_reference(cy.process_commit(GROUP, &swept.commit)),
        "cy merged it"
    );
    assert!(
        by_reference(bo.process_commit(GROUP, &swept.commit)),
        "bo merged it"
    );
    assert_eq!(cy.epoch(GROUP).unwrap(), epoch);
    assert!(meta_of(&cy).contains("\"adm\":[\"actor-ada\"]"));
}

/// A standalone proposal is refused whatever it proposes, an ordinary one
/// included: the rule is about how it arrives, not what it asks.
#[test]
fn even_an_allowed_change_is_refused_when_it_arrives_on_its_own() {
    let server = issuer();
    let (mut ada, mut bo, mut cy) = three(&server);
    // A rename, which any member may make by committing it.
    let rename = bo
        .forge_propose_group_meta(GROUP, b"{\"v\":1,\"n\":\"Run\",\"adm\":[\"actor-ada\"]}")
        .unwrap();
    assert!(by_reference(ada.forge_process_any(GROUP, &rename)));
    assert!(by_reference(cy.forge_process_any(GROUP, &rename)));
    // The same change, committed by Bo himself, goes through.
    let commit = bo
        .set_group_meta(GROUP, b"{\"v\":1,\"n\":\"Run\",\"adm\":[\"actor-ada\"]}")
        .expect("bo renames");
    bo.merge_pending_commit(GROUP).unwrap();
    assert!(matches!(
        ada.process_commit(GROUP, &commit.commit),
        Ok(Incoming::Commit(_))
    ));
}

/// The message door takes one kind of proposal, a leave (`tests/leave.rs`).
/// A Remove of SOMEBODY ELSE, or any other change, sent on its own is the
/// wrong door there: dropped unread, and nothing is queued for a leave commit
/// to carry.
#[test]
fn the_message_door_takes_no_proposal_but_a_leave() {
    let server = issuer();
    let (mut ada, mut bo, mut cy) = three(&server);
    let cy_leaf = bo.leaf_of_device(GROUP, "device-cy").unwrap();
    let remove_cy = bo.forge_propose_remove(GROUP, cy_leaf).unwrap();
    let rename = bo
        .forge_propose_group_meta(GROUP, b"{\"v\":1,\"n\":\"Run\",\"adm\":[\"actor-ada\"]}")
        .unwrap();
    for proposal in [&remove_cy, &rename] {
        assert!(matches!(
            ada.process_message(GROUP, proposal),
            Err(Error::WrongDoor(_))
        ));
        assert!(matches!(
            cy.process_message(GROUP, proposal),
            Err(Error::WrongDoor(_))
        ));
    }
    assert!(ada.commit_proposed_leaves(GROUP).unwrap().is_none());
    assert!(ada.leaf_of_device(GROUP, "device-cy").is_ok());
}
