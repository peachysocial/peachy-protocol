// SPDX-License-Identifier: MIT
//! A LEAVE LANDS ON EVERY DEVICE, AND KEEPS TRYING UNTIL IT DOES.
//!
//! A leave is the one proposal taken by reference (tests/leave.rs), and a
//! member that never received a proposal cannot apply a commit that names it
//! (RFC 9420 §12.4). Two halves close that:
//!
//! - **The commit carries the proposals it names** ([`peachy_mls_core::carried_commit`]):
//!   a device the leave never reached applies the commit anyway. Run both
//!   ways: with the writer on, it applies; with it off (today's writers),
//!   the same device is stranded, which is the gap.
//! - **The leaver keeps a LEAVING stub and proposes again at every epoch it
//!   reaches while still seated** (`Client::begin_leave`,
//!   `Client::follow_leave`), so a commit that takes the epoch first does not
//!   drop the leave for good. The stub is out of sight of everything but the
//!   leave, survives a restart, and goes when a commit removes the device,
//!   or when a Welcome seats it again.

#![cfg(feature = "test-forgery")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;

use peachy_mls_core::envelope::{
    seal_group_id_envelope, ENVELOPE_KIND_COMMIT, ENVELOPE_KIND_MESSAGE,
};
use peachy_mls_core::{Client, Error, Incoming, MemoryKv, PeachyStorage, ProposalKind};
use support::{client, client_on, head_of, issuer, join_at_head};

const G: &[u8] = b"99999999-9999-4999-8999-999999999999";

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

fn reads(sender: &mut Client, reader: &mut Client, text: &[u8]) -> bool {
    let wire = sender.encrypt(G, text).expect("encrypt");
    match reader.process_message(G, &wire) {
        Ok(Incoming::Application { plaintext, .. }) => plaintext == text,
        _ => false,
    }
}

/// Five devices at one epoch: Ada (the founder), Bo on a phone and a laptop,
/// Cy, and Di. Bo's phone keeps its state in `bo_kv`, so it can be rebuilt.
struct World {
    ada: Client,
    bo_phone: Client,
    bo_laptop: Client,
    cy: Client,
    di: Client,
    bo_kv: MemoryKv,
}

fn bo_phone_on(bo_kv: &MemoryKv) -> Client {
    client_on(
        &issuer(),
        2,
        "actor-bo",
        "device-bo-phone",
        PeachyStorage::open(Box::new(bo_kv.clone())).unwrap(),
    )
}

fn world() -> World {
    let server = issuer();
    let bo_kv = MemoryKv::new();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut bo_phone = bo_phone_on(&bo_kv);
    let mut bo_laptop = client(&server, 3, "actor-bo", "device-bo-laptop");
    let mut cy = client(&server, 4, "actor-cy", "device-cy");
    let mut di = client(&server, 5, "actor-di", "device-di");
    ada.create_group(G).unwrap();
    add(&mut ada, &mut bo_phone);
    let c = add(&mut ada, &mut bo_laptop);
    follow(&mut bo_phone, &c);
    let c = add(&mut ada, &mut cy);
    follow(&mut bo_phone, &c);
    follow(&mut bo_laptop, &c);
    let c = add(&mut ada, &mut di);
    follow(&mut bo_phone, &c);
    follow(&mut bo_laptop, &c);
    follow(&mut cy, &c);
    World {
        ada,
        bo_phone,
        bo_laptop,
        cy,
        di,
        bo_kv,
    }
}

/// Bo leaves from his phone; the proposals reach Ada, Cy and his laptop, but
/// never Di. Cy commits them, carried.
fn bo_leaves_and_cy_commits(w: &mut World) -> Vec<u8> {
    let proposals = w.bo_phone.begin_leave(G).expect("begin the leave");
    assert_eq!(proposals.len(), 2, "one per leaf of Bo's");
    for proposal in &proposals {
        queue(&mut w.ada, proposal);
        queue(&mut w.cy, proposal);
        queue(&mut w.bo_laptop, proposal);
    }
    let bundle =
        w.cy.commit_proposed_leaves(G)
            .unwrap()
            .expect("Cy has a leave to commit");
    w.cy.merge_pending_commit(G).expect("merge the leave");
    bundle.commit
}

fn assert_bo_left(outcome: Incoming) {
    match outcome {
        Incoming::Commit(outcome) => {
            assert_eq!(outcome.left, vec!["actor-bo".to_owned()]);
            assert_eq!(outcome.removed.len(), 2);
            assert!(!outcome.removed_self);
        }
        other => panic!("expected a commit, got {other:?}"),
    }
}

#[test]
fn a_carried_commit_lands_on_a_device_the_leave_never_reached() {
    let mut w = world();
    let commit = bo_leaves_and_cy_commits(&mut w);
    assert_eq!(
        &commit[..4],
        &peachy_mls_core::carried_commit::CARRIED_COMMIT_MAGIC,
        "the commit carries the proposals"
    );

    // Di never got a proposal, and follows the commit anyway.
    assert_bo_left(follow(&mut w.di, &commit));
    // Ada held them already; the carried copies change nothing.
    assert_bo_left(follow(&mut w.ada, &commit));
    // Bo's laptop reads its own removal.
    match follow(&mut w.bo_laptop, &commit) {
        Incoming::Commit(outcome) => assert!(outcome.removed_self),
        other => panic!("expected a commit, got {other:?}"),
    }
    // The leaver's stub follows it and is gone.
    assert!(w.bo_phone.follow_leave(G, &commit).unwrap().is_empty());
    assert!(!w.bo_phone.is_leaving(G));
    assert!(matches!(w.bo_phone.is_active(G), Err(Error::NoSuchGroup)));

    // Everyone left is at one epoch, with three people's leaves.
    assert_eq!(w.di.roster(G).unwrap().len(), 3);
    assert!(reads(&mut w.di, &mut w.ada, b"still here"));
    assert!(reads(&mut w.ada, &mut w.cy, b"and here"));
    assert!(reads(&mut w.cy, &mut w.di, b"and here too"));
}

#[test]
fn without_the_carry_the_device_the_leave_never_reached_is_stranded() {
    let mut w = world();
    // The same commit without the proposals it carries, as builds before
    // the carried commit sent it.
    let carried = bo_leaves_and_cy_commits(&mut w);
    let commit = peachy_mls_core::carried_commit::split_carried(&carried)
        .unwrap()
        .commit
        .to_vec();
    assert_ne!(
        &commit[..4],
        &peachy_mls_core::carried_commit::CARRIED_COMMIT_MAGIC
    );
    // Those that got the proposals follow it…
    assert_bo_left(follow(&mut w.ada, &commit));
    // …and Di, which did not, cannot: it is left behind at the old epoch,
    // and the group moves on without it.
    let before = w.di.epoch(G).unwrap();
    let refused =
        w.di.process_commit(G, &commit)
            .expect_err("Di cannot apply it");
    assert_eq!(w.di.epoch(G).unwrap(), before);
    assert!(
        !reads(&mut w.ada, &mut w.di, b"after the leave"),
        "{refused:?}"
    );
}

#[test]
fn the_commit_door_reads_a_carried_commit_however_it_arrives() {
    // An old proposal, a duplicate, or something that is not a proposal at
    // all, carried with a good commit: the commit still stands.
    let mut w = world();
    let commit = bo_leaves_and_cy_commits(&mut w);
    let split = peachy_mls_core::carried_commit::split_carried(&commit).unwrap();
    let mut doubled: Vec<Vec<u8>> = split.proposals.iter().map(|p| p.to_vec()).collect();
    doubled.push(split.proposals[0].to_vec());
    doubled.push(split.commit.to_vec()); // not a proposal: not opened
    let odd = peachy_mls_core::carried_commit::carry_proposals(&doubled, split.commit).unwrap();
    assert_bo_left(follow(&mut w.di, &odd));
}

#[test]
fn a_commit_that_takes_the_epoch_first_gets_the_leave_proposed_again() {
    let mut w = world();
    let first = w.bo_phone.begin_leave(G).expect("begin the leave");
    assert_eq!(first.len(), 2);
    // Calling it again proposes nothing more.
    assert!(w.bo_phone.begin_leave(G).unwrap().is_empty());

    // Before anyone commits the leave, Ada's update takes the epoch; the
    // first proposals, sealed at the old one, are dropped.
    let update = w.ada.self_update(G).expect("update");
    w.ada.merge_pending_commit(G).unwrap();
    for member in [&mut w.bo_laptop, &mut w.cy, &mut w.di] {
        follow(member, &update.commit);
    }
    assert!(w.cy.commit_proposed_leaves(G).unwrap().is_none());

    // Bo's stub follows the update and proposes again, at the new epoch.
    let again = w.bo_phone.follow_leave(G, &update.commit).unwrap();
    assert_eq!(again.len(), 2, "proposed again at the new epoch");
    // The same commit again proposes nothing more.
    assert!(w
        .bo_phone
        .follow_leave(G, &update.commit)
        .unwrap()
        .is_empty());
    assert!(w.bo_phone.is_leaving(G));

    // The new proposals reach Cy only, who commits them carried.
    for proposal in &again {
        queue(&mut w.cy, proposal);
    }
    let bundle = w.cy.commit_proposed_leaves(G).unwrap().expect("a leave");
    w.cy.merge_pending_commit(G).unwrap();
    assert_bo_left(follow(&mut w.ada, &bundle.commit));
    assert_bo_left(follow(&mut w.di, &bundle.commit));

    assert!(w
        .bo_phone
        .follow_leave(G, &bundle.commit)
        .unwrap()
        .is_empty());
    assert!(!w.bo_phone.is_leaving(G));
    assert!(w.bo_phone.group_ids().is_empty());
}

#[test]
fn the_stub_is_out_of_sight_but_its_envelopes_still_open() {
    let mut w = world();
    let message = w.ada.encrypt(G, b"after the leave").unwrap();
    w.bo_phone.begin_leave(G).expect("begin the leave");

    assert!(w.bo_phone.is_leaving(G));
    assert!(w.bo_phone.group_ids().is_empty());
    assert!(matches!(w.bo_phone.is_active(G), Err(Error::NoSuchGroup)));
    assert!(matches!(
        w.bo_phone.encrypt(G, b"hi"),
        Err(Error::NoSuchGroup)
    ));
    assert!(matches!(
        w.bo_phone.process_message(G, &message),
        Err(Error::NoSuchGroup)
    ));
    assert!(matches!(
        w.bo_phone.commit_proposed_leaves(G),
        Err(Error::NoSuchGroup) | Ok(None)
    ));
    // The roster is hidden, but the leave can still be addressed.
    assert!(matches!(w.bo_phone.roster(G), Err(Error::NoSuchGroup)));
    // In device-id order, as every send lists them, never join order.
    let to = w.bo_phone.leave_recipients(G).unwrap();
    assert_eq!(
        to.iter()
            .map(|(_, device)| device.as_str())
            .collect::<Vec<_>>(),
        vec![
            "device-ada",
            "device-bo-laptop",
            "device-bo-phone",
            "device-cy",
            "device-di"
        ]
    );
    assert!(matches!(w.ada.leave_recipients(G), Err(Error::NoSuchGroup)));
    // The envelope still opens, so the app can hand its commits to the leave.
    for kind in [ENVELOPE_KIND_MESSAGE, ENVELOPE_KIND_COMMIT] {
        let sealed = seal_group_id_envelope(G, kind, b"inner").unwrap();
        let opened = w.bo_phone.open_envelope(&sealed).unwrap().expect("opens");
        assert_eq!(opened.group_id, G);
    }
    // A group nobody is leaving has no leave to follow.
    assert!(matches!(
        w.ada.follow_leave(G, &message),
        Err(Error::NoSuchGroup)
    ));
    // Forgetting the group gives the leave up (a sign-out, say).
    w.bo_phone.forget_group(G).expect("forgets the stub");
    assert!(!w.bo_phone.is_leaving(G));
    assert!(w
        .bo_phone
        .open_envelope(&seal_group_id_envelope(G, ENVELOPE_KIND_COMMIT, b"x").unwrap())
        .unwrap()
        .is_none());
}

#[test]
fn the_leave_survives_a_restart() {
    let mut w = world();
    w.bo_phone.begin_leave(G).expect("begin the leave");
    drop(std::mem::replace(&mut w.bo_phone, bo_phone_on(&w.bo_kv)));
    assert!(w.bo_phone.is_leaving(G), "the stub is kept");
    assert!(w.bo_phone.group_ids().is_empty(), "and still out of sight");
    assert!(w.bo_phone.begin_leave(G).unwrap().is_empty());

    // It proposes again after a restart too, and the stub goes on removal.
    let update = w.ada.self_update(G).expect("update");
    w.ada.merge_pending_commit(G).unwrap();
    follow(&mut w.cy, &update.commit);
    let again = w.bo_phone.follow_leave(G, &update.commit).unwrap();
    assert_eq!(again.len(), 2);
    for proposal in &again {
        queue(&mut w.cy, proposal);
    }
    let bundle = w.cy.commit_proposed_leaves(G).unwrap().expect("a leave");
    w.cy.merge_pending_commit(G).unwrap();
    assert!(w
        .bo_phone
        .follow_leave(G, &bundle.commit)
        .unwrap()
        .is_empty());
    drop(std::mem::replace(&mut w.bo_phone, bo_phone_on(&w.bo_kv)));
    assert!(!w.bo_phone.is_leaving(G));
    assert!(w.bo_phone.group_ids().is_empty());
}

#[test]
fn a_person_alone_in_the_group_forgets_it_at_once() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut ada_laptop = client(&server, 6, "actor-ada", "device-ada-laptop");
    ada.create_group(G).unwrap();
    add(&mut ada, &mut ada_laptop);
    // Nobody but Ada holds a leaf: nobody could commit a leave.
    assert!(ada.begin_leave(G).unwrap().is_empty());
    assert!(!ada.is_leaving(G));
    assert!(ada.group_ids().is_empty());
}

#[test]
fn a_welcome_back_into_the_group_ends_the_leave() {
    let mut w = world();
    // The leave lands, but Bo's phone never sees the commit…
    let commit = bo_leaves_and_cy_commits(&mut w);
    assert_bo_left(follow(&mut w.ada, &commit));
    assert!(w.bo_phone.is_leaving(G));

    // …and Ada adds him back: the Welcome ends the leave, and he is in.
    let key_package = w.bo_phone.generate_key_package().unwrap();
    let bundle = w.ada.add_member(G, &key_package).unwrap();
    w.ada.merge_pending_commit(G).unwrap();
    join_at_head(
        &mut w.bo_phone,
        &bundle.welcome.expect("welcome"),
        head_of(&w.ada, G),
    )
    .expect("joins over the stub");
    assert!(!w.bo_phone.is_leaving(G));
    assert_eq!(w.bo_phone.group_ids(), vec![G.to_vec()]);
    assert!(reads(&mut w.ada, &mut w.bo_phone, b"welcome back"));
}

/// A device id two leaves claim (a second leaf a modified member seated) is
/// refused by every receiver; the tree of the device that seated it still
/// names that device id once in a leave's recipients, as every send lists
/// them.
#[test]
fn a_leave_names_a_device_id_two_leaves_claim_once() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    let squatter = client(&server, 9, "actor-zed", "device-bo");
    ada.create_group(G).unwrap();
    add(&mut ada, &mut bo);
    let key_package = squatter.generate_key_package().unwrap();
    let forged = ada.forge_commit(G, &[], &[&key_package]).unwrap();
    ada.merge_pending_commit(G).unwrap();
    let err = bo
        .process_commit(G, &forged.commit)
        .expect_err("a second leaf for one device id");
    assert!(err.to_string().contains("second leaf"), "{err}");
    ada.begin_leave(G).unwrap();
    let to = ada.leave_recipients(G).unwrap();
    assert_eq!(
        to,
        vec![
            ("actor-ada".to_string(), "device-ada".to_string()),
            ("actor-bo".to_string(), "device-bo".to_string()),
        ]
    );
}
