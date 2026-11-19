// SPDX-License-Identifier: MIT
//! A MEMBER-ROSTERED GROUP'S POLICY, ENFORCED BY EVERY MEMBER.
//!
//! `mls/core/src/policy.rs` is the rule and `mls/fixtures/rosters.json` pins
//! it; this file holds that the rule is actually wired into the two places a
//! commit is judged: the committer before it sends (so an honest client never
//! builds a commit its peers refuse) and every receiver before it merges (so a
//! modified client's commit is refused by everybody else).

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use peachy_mls_core::{DenyReason, Error, Incoming};
use support::{client, issuer};

const GROUP: &[u8] = b"11111111-1111-4111-8111-111111111111";

fn meta(admins: &[&str]) -> Vec<u8> {
    let list: Vec<String> = admins.iter().map(|a| format!("\"{a}\"")).collect();
    format!("{{\"v\":1,\"n\":\"Walk\",\"adm\":[{}]}}", list.join(",")).into_bytes()
}

/// Ada (admin), Bo and Cy, all at the same epoch.
fn three() -> [peachy_mls_core::Client; 3] {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    let mut cy = client(&server, 3, "actor-cy", "device-cy");
    ada.create_group(GROUP).expect("create");
    ada.set_group_meta(GROUP, &meta(&["actor-ada"]))
        .expect("adm");
    ada.merge_pending_commit(GROUP).expect("merge adm");
    let add_bo = ada
        .add_member(GROUP, &bo.generate_key_package().unwrap())
        .expect("add bo");
    ada.merge_pending_commit(GROUP).unwrap();
    bo.join_from_welcome(&add_bo.welcome.unwrap())
        .expect("bo joins");
    let add_cy = ada
        .add_member(GROUP, &cy.generate_key_package().unwrap())
        .expect("add cy");
    ada.merge_pending_commit(GROUP).unwrap();
    bo.process_commit(GROUP, &add_cy.commit)
        .expect("bo sees cy added");
    cy.join_from_welcome(&add_cy.welcome.unwrap())
        .expect("cy joins");
    [ada, bo, cy]
}

fn leaf_of(client: &peachy_mls_core::Client, device: &str) -> u32 {
    client.leaf_of_device(GROUP, device).expect("leaf")
}

#[test]
fn a_member_cannot_build_a_removal_of_somebody_else() {
    let [_ada, mut bo, _cy] = three();
    let cy_leaf = leaf_of(&bo, "device-cy");
    let refused = bo.remove_leaf(GROUP, cy_leaf);
    assert!(
        matches!(
            refused,
            Err(Error::PolicyRefused(DenyReason::RemoveNeedsAdmin))
        ),
        "{refused:?}"
    );
    assert!(
        !bo.has_pending_commit(GROUP).unwrap(),
        "a refused commit is cleared"
    );
}

#[test]
fn an_admin_removes_and_every_member_merges_it() {
    let [mut ada, mut bo, _cy] = three();
    let cy_leaf = leaf_of(&ada, "device-cy");
    let removal = ada.remove_leaf(GROUP, cy_leaf).expect("an admin removes");
    ada.merge_pending_commit(GROUP).unwrap();
    assert!(matches!(
        bo.process_commit(GROUP, &removal.commit),
        Ok(Incoming::Commit(_))
    ));
}

#[cfg(feature = "test-forgery")]
#[test]
fn every_member_refuses_a_modified_clients_removal() {
    let [mut ada, mut bo, mut cy] = three();
    let ada_leaf = leaf_of(&bo, "device-ada");
    let forged = bo
        .forge_remove_leaf(GROUP, ada_leaf)
        .expect("a modified client builds it");
    for receiver in [&mut ada, &mut cy] {
        let refused = receiver.process_commit(GROUP, &forged.commit);
        assert!(
            matches!(
                refused,
                Err(Error::PolicyRefused(DenyReason::RemoveNeedsAdmin))
            ),
            "{refused:?}"
        );
    }
}

#[test]
fn only_an_admin_promotes_and_the_promotion_reaches_everybody() {
    let [mut ada, mut bo, mut cy] = three();
    let refused = bo.set_group_meta(GROUP, &meta(&["actor-ada", "actor-bo"]));
    assert!(
        matches!(
            refused,
            Err(Error::PolicyRefused(DenyReason::PolicyNeedsAdmin))
        ),
        "{refused:?}"
    );
    let promote = ada
        .set_group_meta(GROUP, &meta(&["actor-ada", "actor-bo"]))
        .expect("an admin promotes");
    ada.merge_pending_commit(GROUP).unwrap();
    bo.process_commit(GROUP, &promote.commit)
        .expect("bo merges");
    cy.process_commit(GROUP, &promote.commit)
        .expect("cy merges");
    // Now Bo is an admin, and may remove.
    let cy_leaf = leaf_of(&bo, "device-cy");
    bo.remove_leaf(GROUP, cy_leaf)
        .expect("a promoted admin removes");
}

#[test]
fn a_group_whose_state_names_no_admins_keeps_the_flat_rule() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    ada.create_group(GROUP).unwrap();
    let add = ada
        .add_member(GROUP, &bo.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    bo.join_from_welcome(&add.welcome.unwrap()).unwrap();
    let ada_leaf = leaf_of(&bo, "device-ada");
    bo.remove_leaf(GROUP, ada_leaf)
        .expect("no admins named: anybody removes");
}
