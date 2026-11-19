// SPDX-License-Identifier: MIT
//! A COMMIT THIS DEVICE CANNOT APPLY, and the one question that decides what
//! happens next: is the device stranded, or can it skip the entry and carry on?
//!
//! Every client replays the delivery service's stream in order. Swallowing any
//! entry the engine refuses and moving the cursor past it is right for a stale
//! duplicate. For THE commit at the device's own epoch it is a silent wedge:
//! the delivery service accepts one commit per epoch, so nothing ever replaces
//! the one that was refused, every later commit fails as a wrong-epoch commit,
//! and the device sits at the old epoch still "active" and reading nothing.
//! See
//! docs/delivery.md §A commit this device cannot apply.
//!
//! `commit_strands` is the device's own answer, and it says yes only for a
//! commit that opened and verified at this device's epoch and was then
//! refused. Everything else a device cannot apply, including a commit that
//! will not open at all, answers no, and the client asks the group's head
//! instead (docs/delivery.md §A commit this device cannot apply):
//! a message's framing is readable and writable by anyone with the group id,
//! so it cannot be what throws a group away (`group_membership_attacks.rs`).
//! These tests pin both halves, what strands and what must NOT, because a
//! false positive throws a healthy group away.

mod support;

use peachy_mls_core::Incoming;
use support::{client, issuer};

const GROUP: &[u8] = b"peachy-group-stranded";

/// The commit_race shape: this device's own accepted commit, whose staged copy
/// is gone, is the one commit it can never apply. It never opens for its
/// author, so it does not strand her on its own say-so: the head check is
/// what finds her behind (docs/delivery.md §A commit this device
/// cannot apply). What she has already left, and what is not a commit, never
/// strands either.
#[test]
fn a_commit_that_did_not_open_strands_nobody_and_the_rejoin_still_works() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-strand");
    let mut bo = client(&server, 2, "actor-bo", "device-bo-strand");

    ada.create_group(GROUP).expect("create");
    let bo_kp = bo.generate_key_package().expect("bo key package");
    let seat_bo = ada.add_member(GROUP, &bo_kp).expect("add bo");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.join_from_welcome(&seat_bo.welcome.clone().expect("welcome"))
        .expect("bo joins");
    let epoch = ada.epoch(GROUP).expect("epoch");

    // THE ADD IS NOW BEHIND BOTH OF THEM. It was built at epoch 0; replaying
    // the stream from the start hands it back, and it must be skippable.
    assert!(
        !ada.commit_strands(GROUP, &seat_bo.commit).expect("ask"),
        "a commit from an epoch ada has left is a duplicate, not a wedge",
    );
    assert!(!bo.commit_strands(GROUP, &seat_bo.commit).expect("ask"));

    // Ada stages a commit, the delivery service accepts it — and then her
    // staged copy is cleared before she merges it.
    let accepted = ada.self_update(GROUP).expect("stage");
    ada.clear_pending_commit(GROUP).expect("clear");

    // THE CONTROL: she really cannot apply it now. The commit door answers `Echo`
    // (an own PrivateMessage is never decryptable by its author, staged or
    // not — commit_race.rs), so this one is not even an error: the gap below
    // is what catches it, one commit later.
    let _ = ada.process_commit(GROUP, &accepted.commit);
    assert_eq!(
        ada.epoch(GROUP).expect("epoch"),
        epoch,
        "the fixture is not a fixture: ada applied her own cleared commit",
    );
    // Its framing says it is the commit at her own epoch, but framing is
    // anyone's to write: it was never refused after opening, so no.
    assert!(!ada.commit_strands(GROUP, &accepted.commit).expect("ask"));

    // Bo applies it, as the rest of the group does. For him it is now in the
    // past, and a second delivery of it must not throw his group away.
    match bo
        .process_commit(GROUP, &accepted.commit)
        .expect("bo applies")
    {
        Incoming::Commit(_) => {}
        other => panic!("expected a commit, got {other:?}"),
    }
    assert!(
        !bo.commit_strands(GROUP, &accepted.commit).expect("ask"),
        "a commit bo has applied, delivered again, stranded him",
    );

    // THE GAP. Bo's next commit is built at an epoch above ada's: the one for
    // hers is behind her cursor for good. That is for the head to say (an
    // epoch above hers), not for this commit's framing.
    let next = bo.self_update(GROUP).expect("bo commits");
    bo.merge_pending_commit(GROUP).expect("merge");
    assert!(ada.process_commit(GROUP, &next.commit).is_err());
    assert!(
        !ada.commit_strands(GROUP, &next.commit).expect("ask"),
        "a commit that never opened stranded her",
    );
    assert!(!bo.commit_strands(GROUP, &next.commit).expect("ask"));

    // NOT COMMITS, and never a wedge whatever the doors made of them.
    let said = bo.encrypt(GROUP, b"hello").expect("encrypt");
    assert!(!ada.commit_strands(GROUP, &said).expect("ask"));
    assert!(!ada
        .commit_strands(GROUP, b"not an mls message")
        .expect("ask"));
    assert!(!ada.commit_strands(GROUP, &[]).expect("ask"));
    // A group this device holds nothing for has nothing to strand.
    assert!(!ada
        .commit_strands(b"peachy-group-nobody", &next.commit)
        .expect("ask"));
    // A commit for SOME OTHER group, handed over under this one's id, is a
    // delivery-service mix-up and not this group's lost epoch.
    let mut cy = client(&server, 3, "actor-cy", "device-cy-strand");
    cy.create_group(b"peachy-group-elsewhere").expect("create");
    let elsewhere = cy.self_update(b"peachy-group-elsewhere").expect("stage");
    assert!(!ada.commit_strands(GROUP, &elsewhere.commit).expect("ask"));

    // THE WAY BACK, once the head has said she is behind, is the retention
    // rejoin, unchanged: forget, and be replaced by a member who is current.
    let ada_leaf = bo
        .leaf_of_device(GROUP, "device-ada-strand")
        .expect("ada is still in bo's tree");
    ada.forget_group(GROUP).expect("forget");
    assert!(!ada.commit_strands(GROUP, &next.commit).expect("ask"));
    let fresh = ada.generate_key_package().expect("fresh key package");
    let replaced = bo
        .replace_member(GROUP, ada_leaf, &fresh)
        .expect("bo replaces ada's leaf");
    bo.merge_pending_commit(GROUP).expect("merge");
    ada.join_from_welcome(&replaced.welcome.clone().expect("welcome"))
        .expect("ada rejoins");
    assert_eq!(ada.epoch(GROUP).expect("epoch"), replaced.epoch);

    // AND NO LOOP: replaying the whole stream from the start after the rejoin
    // hands her every commit that stranded her, and none of them strands her
    // again — they are all from epochs she has now left.
    for old in [
        &seat_bo.commit,
        &accepted.commit,
        &next.commit,
        &replaced.commit,
    ] {
        assert!(
            !ada.commit_strands(GROUP, old).expect("ask"),
            "a replayed commit stranded a device that had already rejoined",
        );
    }
    let back = bo.encrypt(GROUP, b"welcome back").expect("encrypt");
    match ada.process_message(GROUP, &back).expect("ada reads") {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"welcome back"),
        other => panic!("expected an application message, got {other:?}"),
    }
}

/// A plaintext commit, stored before handshakes were sealed, reaching a
/// device that updated before it applied it (docs/metadata.md
/// §Encrypted handshakes). Refused for its framing before anything was
/// verified, so it does not strand on its own say-so: the head, one epoch
/// above, is what finds the device behind.
#[cfg(feature = "test-forgery")]
#[test]
fn a_refused_plaintext_commit_leaves_the_verdict_to_the_head() {
    use openmls::prelude::{
        MIXED_PLAINTEXT_WIRE_FORMAT_POLICY, PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
    };

    let server = issuer();
    let mut ada = client(&server, 4, "actor-ada", "device-ada-clear");
    let mut bo = client(&server, 5, "actor-bo", "device-bo-clear");

    ada.create_group(GROUP).expect("create");
    let bo_kp = bo.generate_key_package().expect("bo key package");
    let seat_bo = ada.add_member(GROUP, &bo_kp).expect("add bo");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.join_from_welcome(&seat_bo.welcome.clone().expect("welcome"))
        .expect("bo joins");

    // A device that frames commits in the clear sends one, and the service
    // stores it.
    ada.forge_stored_wire_format_policy(GROUP, MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
        .expect("frame handshakes in the clear");
    let clear = ada.self_update(GROUP).expect("a plaintext commit");
    ada.merge_pending_commit(GROUP).expect("merge");
    ada.forge_stored_wire_format_policy(GROUP, PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .expect("back to today's policy");

    let refused = bo.process_commit(GROUP, &clear.commit);
    assert!(
        format!("{:?}", refused.expect_err("a plaintext commit applied")).contains("wire format"),
        "refused, but not for its framing — the fixture is not this case",
    );
    assert!(!bo.commit_strands(GROUP, &clear.commit).expect("ask"));

    // Every sealed commit after it fails for him too, and the head is ahead
    // of him for good: that is the client's signal to rejoin.
    let sealed = ada.self_update(GROUP).expect("a sealed commit");
    ada.merge_pending_commit(GROUP).expect("merge");
    assert!(bo.process_commit(GROUP, &sealed.commit).is_err());
    assert!(!bo.commit_strands(GROUP, &sealed.commit).expect("ask"));
    assert!(ada.epoch(GROUP).expect("epoch") > bo.epoch(GROUP).expect("epoch"));
}
