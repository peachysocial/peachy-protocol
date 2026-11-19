// SPDX-License-Identifier: MIT
//! A device that slept, and the two different answers depending on how long.
//!
//! A device asleep for a month must still get back in.
//! There are two cases and they are not on a spectrum — they are either
//! side of one line, the delivery service's retention window
//! (docs/delivery.md §Retention):
//!
//!  - **Inside the window.** Every commit the sleeper missed is still on the
//!    server. It replays them in order, arrives at the head epoch, and can
//!    still read what was said while it was away: in its mailbox each message
//!    sits right after the commit of the epoch it was sealed in, and a message
//!    read a few commits late opens from one of the
//!    [`peachy_mls_core::RETAINED_PAST_EPOCHS`] past epochs the group keeps.
//!    No rejoin, no new Welcome, nobody else does anything.
//!
//!  - **Past the window.** The commits are gone and nothing can bring them
//!    back: each epoch's secrets are derived from the last, the server never had
//!    them, and a server that could hand them over would be a server that could
//!    read the group. So the sleeper forgets the group and a LIVE member
//!    replaces its leaf — Remove and Add in one commit — which mints a fresh
//!    Welcome for it to join at the current epoch. What was said while it slept
//!    stays unreadable, and this file asserts that too: it is the property, not
//!    a limitation of the recovery.

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use peachy_mls_core::{Error, Incoming};
use support::{client, issuer};

const GROUP: &[u8] = b"peachy-group-rejoin";

#[test]
fn a_month_asleep_device_rejoins_by_being_replaced_and_cannot_read_what_it_missed() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(&server, 2, "actor-bo", "device-bo-phone");
    let mut cy = client(&server, 3, "actor-cy", "device-cy-phone");
    let mut dee = client(&server, 4, "actor-dee", "device-dee-phone");

    // --- three members ----------------------------------------------------
    ada.create_group(GROUP).expect("create");
    let bo_kp = bo.generate_key_package().expect("bo key package");
    let add_bo = ada.add_member(GROUP, &bo_kp).expect("add bo");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.join_from_welcome(&add_bo.welcome.clone().expect("welcome"))
        .expect("bo joins");
    let cy_kp = cy.generate_key_package().expect("cy key package");
    let add_cy = ada.add_member(GROUP, &cy_kp).expect("add cy");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.process_commit(GROUP, &add_cy.commit)
        .expect("bo sees the add");
    cy.join_from_welcome(&add_cy.welcome.clone().expect("welcome"))
        .expect("cy joins");
    assert_eq!(ada.epoch(GROUP).expect("epoch"), 2);
    assert_eq!(cy.epoch(GROUP).expect("epoch"), 2);

    // Cy's leaf, noted while Cy is still reachable. After this line Cy is
    // asleep: it processes nothing at all until the Welcome at the end.
    let cy_leaf = ada
        .leaf_of_device(GROUP, "device-cy-phone")
        .expect("cy is in the roster");

    // --- six epochs pass without Cy ---------------------------------------
    // Updates, an add, a removal: the ordinary life of a group over a month.
    let mut whispered: Vec<Vec<u8>> = Vec::new();

    // 1. Ada rotates her leaf.
    // Every one of these is stage → merge: the delivery service is standing in
    // for itself here, and it takes every commit in this test.
    let c1 = ada.self_update(GROUP).expect("ada self-update");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.process_commit(GROUP, &c1.commit).expect("bo applies");
    // Something said while Cy slept. Kept so the end of this test can prove it
    // stays unreadable.
    whispered.push(bo.encrypt(GROUP, b"cy is not here").expect("encrypt"));

    // 2. Bo rotates his.
    let c2 = bo.self_update(GROUP).expect("bo self-update");
    bo.merge_pending_commit(GROUP).expect("merge");
    ada.process_commit(GROUP, &c2.commit).expect("ada applies");

    // 3. Dee is added.
    let dee_kp = dee.generate_key_package().expect("dee key package");
    let c3 = ada.add_member(GROUP, &dee_kp).expect("add dee");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.process_commit(GROUP, &c3.commit).expect("bo applies");
    dee.join_from_welcome(&c3.welcome.clone().expect("welcome"))
        .expect("dee joins");
    whispered.push(ada.encrypt(GROUP, b"dee is here now").expect("encrypt"));

    // 4. Bo rotates again.
    let c4 = bo.self_update(GROUP).expect("bo self-update");
    bo.merge_pending_commit(GROUP).expect("merge");
    ada.process_commit(GROUP, &c4.commit).expect("ada applies");
    dee.process_commit(GROUP, &c4.commit).expect("dee applies");

    // 5. Dee is removed.
    let dee_leaf = ada
        .leaf_of_device(GROUP, "device-dee-phone")
        .expect("dee is in the roster");
    let c5 = ada.remove_leaf(GROUP, dee_leaf).expect("remove dee");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.process_commit(GROUP, &c5.commit).expect("bo applies");

    // 6. Ada rotates again.
    let c6 = ada.self_update(GROUP).expect("ada self-update");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.process_commit(GROUP, &c6.commit).expect("bo applies");

    assert_eq!(ada.epoch(GROUP).expect("epoch"), 8);
    assert_eq!(bo.epoch(GROUP).expect("epoch"), 8);
    assert_eq!(cy.epoch(GROUP).expect("epoch"), 2, "cy slept through it");

    // --- the retention line -----------------------------------------------
    // The server swept every commit built before epoch 5, so the oldest commit
    // it still holds was built at epoch 5. Cy, at epoch 2, needs the commit
    // built at epoch 2 — which is gone.
    const SERVER_OLDEST_EPOCH: u64 = 5;
    assert!(
        cy.is_behind(GROUP, SERVER_OLDEST_EPOCH).expect("is_behind"),
        "a device at epoch 2 is behind a window that starts at 5",
    );
    // Ada and Bo, at the head, are not.
    assert!(!ada
        .is_behind(GROUP, SERVER_OLDEST_EPOCH)
        .expect("is_behind"));
    assert!(!bo.is_behind(GROUP, SERVER_OLDEST_EPOCH).expect("is_behind"));
    // The boundary is inclusive on the retained side: a device sitting at
    // exactly the oldest retained epoch holds the one commit it needs.
    assert!(!cy.is_behind(GROUP, 2).expect("is_behind"));
    assert!(cy.is_behind(GROUP, 3).expect("is_behind"));

    // --- the rejoin -------------------------------------------------------
    // Cy mints a fresh key package — the one Ada used a month ago was consumed
    // by the add that is now being undone.
    let cy_fresh_kp = cy.generate_key_package().expect("cy key package");

    // A live member does the work. Cy cannot: a device off the ratchet cannot
    // sign anything the group will accept, which is why there is no
    // `leave_stale` on this API.
    let replaced = ada
        .replace_member(GROUP, cy_leaf, &cy_fresh_kp)
        .expect("ada replaces cy's leaf");
    assert_eq!(replaced.epoch, 9, "one commit, one epoch");
    ada.merge_pending_commit(GROUP).expect("merge the replace");
    let welcome = replaced
        .welcome
        .clone()
        .expect("a replace always produces a Welcome");

    // Bo sees one commit that both removes and adds — not two.
    match bo
        .process_commit(GROUP, &replaced.commit)
        .expect("bo applies")
    {
        Incoming::Commit(outcome) => {
            assert_eq!(outcome.sender.actor_id, "actor-ada");
            assert_eq!(outcome.removed, vec![cy_leaf]);
            assert_eq!(outcome.added.len(), 1);
            assert_eq!(outcome.added[0].actor_id, "actor-cy");
            assert_eq!(outcome.epoch, 9);
        }
        other => panic!("expected a commit, got {other:?}"),
    }

    // Cy drops the stale group, then joins from the Welcome.
    cy.forget_group(GROUP).expect("cy forgets");
    assert!(cy.group_ids().is_empty());
    assert!(matches!(cy.epoch(GROUP), Err(Error::NoSuchGroup)));
    let joined = cy.join_from_welcome(&welcome).expect("cy rejoins");
    assert_eq!(joined, GROUP);
    assert_eq!(cy.epoch(GROUP).expect("epoch"), 9);
    assert!(!cy.is_behind(GROUP, SERVER_OLDEST_EPOCH).expect("is_behind"));

    // The roster is three people again, and only three.
    let mut actors: Vec<String> = cy
        .roster(GROUP)
        .expect("roster")
        .into_iter()
        .map(|entry| entry.identity.expect("every leaf verifies").actor_id)
        .collect();
    actors.sort();
    assert_eq!(actors, vec!["actor-ada", "actor-bo", "actor-cy"]);

    // --- and it can talk again --------------------------------------------
    let from_bo = bo.encrypt(GROUP, b"welcome back").expect("encrypt");
    match cy.process_message(GROUP, &from_bo).expect("cy reads") {
        Incoming::Application {
            sender, plaintext, ..
        } => {
            assert_eq!(sender.actor_id, "actor-bo");
            assert_eq!(plaintext, b"welcome back");
        }
        other => panic!("expected an application message, got {other:?}"),
    }
    let reply = cy.encrypt(GROUP, b"what did i miss").expect("encrypt");
    match ada.process_message(GROUP, &reply).expect("ada reads") {
        Incoming::Application {
            sender, plaintext, ..
        } => {
            assert_eq!(sender.actor_id, "actor-cy");
            assert_eq!(sender.device_id, "device-cy-phone");
            assert_eq!(plaintext, b"what did i miss");
        }
        other => panic!("expected an application message, got {other:?}"),
    }

    // --- what it missed stays missed --------------------------------------
    // THIS IS THE PROPERTY, not a shortcoming of the recovery. Cy rejoined at
    // epoch 9 and holds no key for any epoch before it; the two messages sent
    // while it slept are sealed under secrets it never had and never will.
    for (n, sealed) in whispered.iter().enumerate() {
        let err = cy
            .process_message(GROUP, sealed)
            .expect_err("a rejoined device must not be able to read the sleeping period");
        // THE KIND MATTERS, and so does which kind it is not. `Error::Mls` is
        // "the cryptography could not open this"; a `PolicyRefused` or a
        // `CredentialRejected` here would mean the message was turned away by a
        // rule rather than by the ratchet, and a rule can be changed. OpenMLS'
        // own words for it, on this pinned version, are "Generation is too old
        // to be processed" — the secret tree has no generation for an epoch
        // this group never held. Matched loosely because the sentence is
        // OpenMLS', not ours (see `Error::Mls`).
        match err {
            Error::Mls(reason) => {
                let reason = reason.to_lowercase();
                assert!(
                    reason.contains("too old") || reason.contains("epoch"),
                    "message {n} failed for the wrong reason: {reason}",
                );
            }
            other => panic!("message {n} failed as {other:?}, not as an MLS error"),
        }
    }
}

#[test]
fn a_device_asleep_inside_the_window_catches_up_by_replaying_the_commits() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(&server, 2, "actor-bo", "device-bo-phone");
    let mut cy = client(&server, 3, "actor-cy", "device-cy-phone");

    ada.create_group(GROUP).expect("create");
    let bo_kp = bo.generate_key_package().expect("bo key package");
    let add_bo = ada.add_member(GROUP, &bo_kp).expect("add bo");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.join_from_welcome(&add_bo.welcome.clone().expect("welcome"))
        .expect("bo joins");
    let cy_kp = cy.generate_key_package().expect("cy key package");
    let add_cy = ada.add_member(GROUP, &cy_kp).expect("add cy");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.process_commit(GROUP, &add_cy.commit)
        .expect("bo sees the add");
    cy.join_from_welcome(&add_cy.welcome.clone().expect("welcome"))
        .expect("cy joins");

    // Cy sleeps for three epochs. The server keeps everything from epoch 0, so
    // the whole stream is still there when Cy wakes.
    let mut stream: Vec<Vec<u8>> = Vec::new();
    let c1 = ada.self_update(GROUP).expect("ada self-update");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.process_commit(GROUP, &c1.commit).expect("bo applies");
    stream.push(c1.commit);
    // Said at epoch 3, while Cy was away, and read here two commits late,
    // from a retained past epoch (RETAINED_PAST_EPOCHS).
    let whispered = bo
        .encrypt(GROUP, b"cy will read this later")
        .expect("encrypt");

    let c2 = bo.self_update(GROUP).expect("bo self-update");
    bo.merge_pending_commit(GROUP).expect("merge");
    ada.process_commit(GROUP, &c2.commit).expect("ada applies");
    stream.push(c2.commit);

    let c3 = ada.self_update(GROUP).expect("ada self-update");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.process_commit(GROUP, &c3.commit).expect("bo applies");
    stream.push(c3.commit);

    assert_eq!(ada.epoch(GROUP).expect("epoch"), 5);
    assert_eq!(cy.epoch(GROUP).expect("epoch"), 2);

    // Inside the window: nothing was swept, so there is nothing to rejoin.
    assert!(
        !cy.is_behind(GROUP, 0).expect("is_behind"),
        "a device inside the retention window is not behind it",
    );

    // The ordinary catch-up: replay the stream in order. No Welcome, no
    // replace_member, and no other member does anything at all.
    for commit in &stream {
        match cy.process_commit(GROUP, commit).expect("cy replays") {
            Incoming::Commit(_) => {}
            other => panic!("expected a commit, got {other:?}"),
        }
    }
    assert_eq!(cy.epoch(GROUP).expect("epoch"), 5);

    // And what was said in the middle of the sleep opens, out of order, from a
    // retained past epoch.
    match cy
        .process_message(GROUP, &whispered)
        .expect("cy reads the backlog")
    {
        Incoming::Application {
            sender, plaintext, ..
        } => {
            assert_eq!(sender.actor_id, "actor-bo");
            assert_eq!(plaintext, b"cy will read this later");
        }
        other => panic!("expected an application message, got {other:?}"),
    }

    // Still a member in good standing at the head epoch.
    let live = ada.encrypt(GROUP, b"and here is now").expect("encrypt");
    match cy.process_message(GROUP, &live).expect("cy reads") {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"and here is now"),
        other => panic!("expected an application message, got {other:?}"),
    }
}

#[test]
fn a_replace_is_refused_when_it_would_hand_the_leaf_to_somebody_else() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(&server, 2, "actor-bo", "device-bo-phone");
    let cy = client(&server, 3, "actor-cy", "device-cy-phone");

    ada.create_group(GROUP).expect("create");
    let bo_kp = bo.generate_key_package().expect("bo key package");
    let add_bo = ada.add_member(GROUP, &bo_kp).expect("add bo");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.join_from_welcome(&add_bo.welcome.clone().expect("welcome"))
        .expect("bo joins");

    // Cy is not in this group. Replacing Bo's leaf with Cy's key package would
    // be a membership change dressed as a recovery, so it is refused before any
    // commit is built.
    let bo_leaf = ada
        .leaf_of_device(GROUP, "device-bo-phone")
        .expect("bo is in the roster");
    let cy_kp = cy.generate_key_package().expect("cy key package");
    let err = ada
        .replace_member(GROUP, bo_leaf, &cy_kp)
        .expect_err("a cross-actor replace is refused");
    assert!(matches!(err, Error::InvalidArgument(_)), "got {err:?}");
    // And the group did not move.
    assert_eq!(ada.epoch(GROUP).expect("epoch"), 1);

    // Nor can a member replace its own leaf: the commit would remove its own
    // author.
    let own_leaf = ada
        .leaf_of_device(GROUP, "device-ada-phone")
        .expect("ada is in the roster");
    let ada_kp = ada.generate_key_package().expect("ada key package");
    let err = ada
        .replace_member(GROUP, own_leaf, &ada_kp)
        .expect_err("replacing your own leaf is refused");
    assert!(matches!(err, Error::InvalidArgument(_)), "got {err:?}");

    // A leaf index nobody occupies is NoSuchMember, not a panic.
    let cy_kp = cy.generate_key_package().expect("cy key package");
    assert!(matches!(
        ada.replace_member(GROUP, 97, &cy_kp),
        Err(Error::NoSuchMember)
    ));
}
