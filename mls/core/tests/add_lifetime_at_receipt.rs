// SPDX-License-Identifier: MIT
//! An add whose key package's leaf lifetime ends between the commit and its
//! receipt. A receiver checks the lifetime when it stages the commit, against
//! its own clock (OpenMLS `Lifetime::validate`), and refuses the add; the
//! same add staged in time is applied.
//!
//! Run: `cd mls && cargo test -p peachy-mls-core --all-features --test add_lifetime_at_receipt`.

#![cfg(feature = "test-forgery")]

mod support;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use peachy_mls_core::Incoming;
use support::{client, issuer};

const GROUP: &[u8] = b"peachy-group-expired-add";

fn wall_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after 1970")
        .as_secs()
}

#[test]
fn an_add_whose_package_lapsed_before_receipt_is_refused() {
    let server = issuer();
    let mut ada = client(&server, 41, "actor-ada", "device-ada-expired");
    let mut bo = client(&server, 42, "actor-bo", "device-bo-expired");
    let mut cy = client(&server, 43, "actor-cy", "device-cy-expired");
    let dee = client(&server, 44, "actor-dee", "device-dee-expired");

    // A, B and C in one group, all at the same epoch.
    ada.create_group(GROUP).expect("create");
    let seat_bo = ada
        .add_member(GROUP, &bo.generate_key_package().expect("bo kp"))
        .expect("add bo");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.join_from_welcome(&seat_bo.welcome.clone().expect("welcome"))
        .expect("bo joins");
    let seat_cy = ada
        .add_member(GROUP, &cy.generate_key_package().expect("cy kp"))
        .expect("add cy");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.process_commit(GROUP, &seat_cy.commit)
        .expect("bo applies cy's add");
    cy.join_from_welcome(&seat_cy.welcome.clone().expect("welcome"))
        .expect("cy joins");
    let before = ada.epoch(GROUP).expect("epoch");
    assert_eq!(bo.epoch(GROUP).expect("epoch"), before);
    assert_eq!(cy.epoch(GROUP).expect("epoch"), before);

    // A key package whose lifetime ends five seconds from now.
    let now = wall_now();
    let not_after = now + 5;
    let expiring = dee
        .forge_key_package_with_lifetime(now - 60, not_after)
        .expect("a short-lived key package");

    // Built while the package is valid, without the adder's lifetime rule.
    let add = ada
        .forge_commit(GROUP, &[], &[&expiring])
        .expect("the adder builds the add while the package is valid");
    ada.merge_pending_commit(GROUP)
        .expect("the adder merges its own add");
    let after = ada.epoch(GROUP).expect("epoch");
    assert_eq!(after, before + 1, "the adder is at the new epoch");

    // Staged after the lifetime ends.
    while wall_now() <= not_after {
        std::thread::sleep(Duration::from_millis(200));
    }

    for (name, member) in [("bo", &mut bo), ("cy", &mut cy)] {
        let refused = member
            .process_commit(GROUP, &add.commit)
            .expect_err("a member applied an add whose package had lapsed");
        let why = format!("{refused:?}");
        assert!(
            why.to_lowercase().contains("expired") || why.to_lowercase().contains("lifetime"),
            "{name} refused, but not for the lifetime — the fixture is not this case: {why}",
        );
        assert_eq!(
            member.epoch(GROUP).expect("epoch"),
            before,
            "{name} moved off the old epoch",
        );
        // The refusal comes before the commit is authenticated, so
        // commit_strands is false (docs/delivery.md §A commit this
        // device cannot apply).
        assert!(
            !member.commit_strands(GROUP, &add.commit).expect("ask"),
            "{name}: commit_strands answered true for a lapsed add",
        );
    }
    // Refused by every receiver.
    assert_eq!(ada.epoch(GROUP).expect("epoch"), before + 1);
    assert_eq!(bo.epoch(GROUP).expect("epoch"), before);
    assert_eq!(cy.epoch(GROUP).expect("epoch"), before);
}

/// The same add, staged in time, is applied.
#[test]
fn the_same_add_staged_in_time_is_applied() {
    let server = issuer();
    let mut ada = client(&server, 51, "actor-ada", "device-ada-intime");
    let mut bo = client(&server, 52, "actor-bo", "device-bo-intime");
    let dee = client(&server, 54, "actor-dee", "device-dee-intime");

    ada.create_group(GROUP).expect("create");
    let seat_bo = ada
        .add_member(GROUP, &bo.generate_key_package().expect("bo kp"))
        .expect("add bo");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.join_from_welcome(&seat_bo.welcome.clone().expect("welcome"))
        .expect("bo joins");

    let now = wall_now();
    let package = dee
        .forge_key_package_with_lifetime(now - 60, now + 600)
        .expect("a key package");
    let add = ada.forge_commit(GROUP, &[], &[&package]).expect("add");
    ada.merge_pending_commit(GROUP).expect("merge");
    match bo
        .process_commit(GROUP, &add.commit)
        .expect("bo applies it in time")
    {
        Incoming::Commit(_) => {}
        other => panic!("expected a commit, got {other:?}"),
    }
    assert_eq!(
        bo.epoch(GROUP).expect("epoch"),
        ada.epoch(GROUP).expect("epoch")
    );
}
