// SPDX-License-Identifier: MIT
//! A PERSON WITH A PHONE AND A LAPTOP, which is two leaves and not one.
//!
//! The failure this file pins is the one that shipped: a person's second MLS
//! device was never seated in a group their first device had already built, so
//! the laptop sat beside the phone showing an unreadable conversation forever
//! (docs/sealed-messages.md §Seating a person's second device). It was not a
//! protocol gap — MLS has never had an opinion about how many leaves one person
//! holds — it was a client comparing ACTORS where it had to compare DEVICES: an
//! actor with a leaf through their phone reads as "present", so the addition
//! pass looked no further and nothing was ever going to add the laptop.
//!
//! No single-device test can see that. The whole shape of the bug is "two
//! devices, one person, one conversation", so this file builds exactly that and
//! asserts the four things the fix depends on:
//!
//!  1. **A leaf is a DEVICE, not a person.** Two leaves of one actor coexist,
//!     each nameable by its own device id out of the signed tree
//!     (`leaf_of_device`), which is what makes a per-device diff expressible at
//!     all. Nothing here is told which leaf is which by anybody — the answer
//!     comes out of the credentials in the tree.
//!  2. **A device outside the group can read nothing**, not even its owner's
//!     own words. This is the state the laptop was stuck in.
//!  3. **Once seated it reads everything said afterwards**, including from its
//!     own person's other device.
//!  4. **And nothing said before**, which is the property rather than the gap.
//!     The Welcome carries the epoch its commit produced and not a byte before
//!     it. Nobody can hand back a past epoch's secrets — not the server, which
//!     never had them, and not another member, whose copies are sealed to key
//!     material this device has no path to. A test that tried to backfill would
//!     be a test asking for the feature to be broken.
//!
//! Its sibling `rejoin.rs` covers the device that HAD a leaf and fell off it;
//! this one covers the device that never had one. Both are answered by the same
//! sealed seat ask (envelope kind 3; see
//! docs/sealed-messages.md §Seating a person's second device)
//! and by different commits: a `replace_member` there, an ordinary
//! `add_member` here.

mod support;

use peachy_mls_core::Incoming;
use support::{client, issuer};

const GROUP: &[u8] = b"peachy-group-second-device";

#[test]
fn a_persons_second_device_gets_its_own_leaf_and_reads_only_from_there() {
    let server = issuer();
    // TWO CLIENTS, ONE ACTOR. `actor-ada` twice with two device ids is the
    // whole fixture, and it is the thing the client layer could not express:
    // one person, two installs, each with its own signing key and its own
    // credential from the same issuer.
    let mut phone = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut laptop = client(&server, 2, "actor-ada", "device-ada-laptop");
    let mut bo = client(&server, 3, "actor-bo", "device-bo-phone");

    // --- the group the phone built ----------------------------------------
    phone.create_group(GROUP).expect("create");
    let bo_kp = bo.generate_key_package().expect("bo key package");
    let add_bo = phone.add_member(GROUP, &bo_kp).expect("add bo");
    phone.merge_pending_commit(GROUP).expect("merge");
    bo.join_from_welcome(&add_bo.welcome.clone().expect("welcome"))
        .expect("bo joins");
    assert_eq!(phone.epoch(GROUP).expect("epoch"), 1);

    // Two leaves, two people. This is the state production was in: epoch 1,
    // one commit, and the laptop nowhere in it.
    assert_eq!(phone.roster(GROUP).expect("roster").len(), 2);

    // Said before the laptop exists as far as this group is concerned. Kept so
    // the end of this test can prove it stays unreadable there.
    let before_bo = bo
        .encrypt(GROUP, b"said before the laptop")
        .expect("encrypt");
    let before_phone = phone
        .encrypt(GROUP, b"and this is ada's own sentence")
        .expect("encrypt");

    // --- what the laptop can do, which is nothing -------------------------
    // Not a member: no epoch, no roster, and an application message it cannot
    // even attempt. THIS IS THE BUG, and it is permanent without a commit from
    // somebody else — the laptop cannot sign anything this group would accept,
    // so it cannot add itself however long it waits.
    assert!(laptop.group_ids().is_empty());
    assert!(laptop.epoch(GROUP).is_err());
    assert!(
        laptop.process_message(GROUP, &before_bo).is_err(),
        "a device with no leaf cannot open a message sealed to the group",
    );
    assert!(
        laptop.process_message(GROUP, &before_phone).is_err(),
        "not even its own person's words, which is the half that made the \
         on-screen apology so obviously wrong",
    );

    // --- seating it: an ordinary add, by a device that IS in the group -----
    // The phone does the work, exactly as `seatNewDevice` has it. It is not a
    // `replace_member`: there is no leaf to hand over, because this device has
    // never had one.
    let laptop_kp = laptop.generate_key_package().expect("laptop key package");
    // READING THE KEY PACKAGE'S TRUE IDENTITY OUT OF ITS OWN BYTES, which is
    // the check that makes the directory's hint safe to act on. Nothing else in
    // the exchange says whose device this is: the delivery service named an
    // actor and the directory handed over some bytes, and this is the reading
    // that decides whether the two agreed.
    let claimed = phone
        .key_package_identity(&laptop_kp)
        .expect("the bytes parse")
        .expect("the credential verifies");
    assert_eq!(claimed.actor_id, "actor-ada");
    assert_eq!(claimed.device_id, "device-ada-laptop");

    let seat = phone
        .add_member(GROUP, &laptop_kp)
        .expect("seat the laptop");
    phone.merge_pending_commit(GROUP).expect("merge");
    match bo.process_commit(GROUP, &seat.commit).expect("bo applies") {
        Incoming::Commit(outcome) => {
            assert!(outcome.removed.is_empty(), "a seat removes nobody");
            assert_eq!(outcome.added.len(), 1);
            // The added leaf is Ada — AGAIN. A second leaf for an actor who
            // already has one is the ordinary case, not an anomaly, and any
            // client that treated "this actor is already here" as a reason to
            // skip is the client this whole file exists about.
            assert_eq!(outcome.added[0].actor_id, "actor-ada");
            assert_eq!(outcome.added[0].device_id, "device-ada-laptop");
        }
        other => panic!("expected a commit, got {other:?}"),
    }
    laptop
        .join_from_welcome(&seat.welcome.clone().expect("a seat always mints a Welcome"))
        .expect("laptop joins");

    // --- three leaves, two people -----------------------------------------
    // The count is what a per-ACTOR diff can never see. Ada is one member of
    // this conversation and holds two of its three leaves, and both are
    // nameable by their own device id out of the signed tree — which is what
    // a per-device reconciliation reads, and the reason it never has to ask a
    // server who owns what.
    let roster = laptop.roster(GROUP).expect("roster");
    assert_eq!(roster.len(), 3);
    let mut seats: Vec<(String, String)> = roster
        .into_iter()
        .map(|entry| {
            let id = entry.identity.expect("every leaf verifies");
            (id.actor_id, id.device_id)
        })
        .collect();
    seats.sort();
    assert_eq!(
        seats,
        vec![
            ("actor-ada".to_string(), "device-ada-laptop".to_string()),
            ("actor-ada".to_string(), "device-ada-phone".to_string()),
            ("actor-bo".to_string(), "device-bo-phone".to_string()),
        ]
    );
    // And each is findable BY DEVICE, which is the lookup a removal needs: a
    // person's revoked laptop has to lose its leaf without taking their phone's
    // with it.
    let laptop_leaf = phone
        .leaf_of_device(GROUP, "device-ada-laptop")
        .expect("the laptop has a leaf of its own");
    let phone_leaf = phone
        .leaf_of_device(GROUP, "device-ada-phone")
        .expect("and so does the phone");
    assert_ne!(laptop_leaf, phone_leaf);

    // --- from here on, it reads -------------------------------------------
    let after_bo = bo.encrypt(GROUP, b"said after the seat").expect("encrypt");
    match laptop
        .process_message(GROUP, &after_bo)
        .expect("laptop reads")
    {
        Incoming::Application {
            sender, plaintext, ..
        } => {
            assert_eq!(sender.actor_id, "actor-bo");
            assert_eq!(plaintext, b"said after the seat");
        }
        other => panic!("expected an application message, got {other:?}"),
    }
    // Including from its own person's other device, which arrives as an
    // ordinary message from another leaf and not as an echo — the two installs
    // are two members of the tree however much they share an owner.
    let after_phone = phone
        .encrypt(GROUP, b"typed on the phone")
        .expect("encrypt");
    match laptop
        .process_message(GROUP, &after_phone)
        .expect("laptop reads")
    {
        Incoming::Application {
            sender, plaintext, ..
        } => {
            assert_eq!(sender.actor_id, "actor-ada");
            assert_eq!(sender.device_id, "device-ada-phone");
            assert_eq!(plaintext, b"typed on the phone");
        }
        other => panic!("expected an application message, got {other:?}"),
    }
    // And it can speak, which the others hear as Ada — from the laptop.
    let from_laptop = laptop
        .encrypt(GROUP, b"typed on the laptop")
        .expect("encrypt");
    match bo.process_message(GROUP, &from_laptop).expect("bo reads") {
        Incoming::Application {
            sender, plaintext, ..
        } => {
            assert_eq!(sender.actor_id, "actor-ada");
            assert_eq!(sender.device_id, "device-ada-laptop");
            assert_eq!(plaintext, b"typed on the laptop");
        }
        other => panic!("expected an application message, got {other:?}"),
    }

    // --- and what came before stays before --------------------------------
    // THE PROPERTY, NOT THE GAP. The laptop joined at the epoch its Welcome
    // sealed it into; the two sentences above were sealed under a secret
    // derived from material it has never held and can never derive. Nobody can
    // hand it over: the server never had it, and the phone — the same person's
    // own device, sitting on the same desk — cannot export it either.
    assert!(
        laptop.process_message(GROUP, &before_bo).is_err(),
        "a seated device reads nothing from before its seat",
    );
    assert!(
        laptop.process_message(GROUP, &before_phone).is_err(),
        "including its own person's words, which is the case that tempts \
         somebody to build a backfill",
    );
    // While the devices that were there all along still read them. The history
    // is not gone, it is simply not the laptop's.
    match phone
        .process_message(GROUP, &before_bo)
        .expect("the phone was there")
    {
        Incoming::Application { plaintext, .. } => {
            assert_eq!(plaintext, b"said before the laptop");
        }
        other => panic!("expected an application message, got {other:?}"),
    }
}
