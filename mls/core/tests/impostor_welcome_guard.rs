// SPDX-License-Identifier: MIT
//! The impostor Welcome guard (docs/delivery.md §FetchVerifierAt,
//! §A Welcome into a group this device knew).
//!
//! A Welcome below the group's head was taken unconfirmed: nothing told an
//! honest one from one an ex-member founded under the same id. The server
//! now logs the send-key verifier of every epoch a head passes through, and
//! the device hands the one at the Welcome's epoch to the join: a Welcome
//! whose send key is not the logged one is refused, and one whose key is
//! gets its seat placed as if at the head. The log also names its floor, the
//! epoch from which it holds every epoch up to the head: nothing logged at or
//! above it refuses the Welcome too, and below it (or with no floor) the
//! Welcome is judged as before the log. A report a Welcome leaves is kept
//! until the app says it drew it, with the time it is drawn at fixed by its
//! first peek past every line an earlier report owns, and it names the
//! devices of kept people the new tree left out, for a seat the server's word
//! places only (never drawn: a person's devices are no row).

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use std::collections::HashMap;

use peachy_mls_core::{Client, Error};
use support::{client, head_of, issuer};

const G: &[u8] = b"0b7e5c2a-93d1-4f6a-8c2e-7d4b1a9f3e60";
const JUNK: [u8; 32] = [0x3c; 32];

/// Every epoch's verifier, as the server's log holds it for G's handle.
type Log = HashMap<u64, [u8; 32]>;

fn log_head(log: &mut Log, c: &Client) {
    let (epoch, verifier) = head_of(c, G);
    log.insert(epoch, verifier);
}

fn welcome_epoch(c: &mut Client, welcome: &[u8]) -> u64 {
    let (group, epoch) = c.welcome_group(welcome).unwrap();
    assert_eq!(group, G);
    epoch
}

/// An ex-member's group under G, founded past `past` and adding `victim`:
/// the Welcome. Its epoch is below the real head the test gives.
fn impostor_welcome(
    server: &peachy_mls_core::issuer::TestIssuer,
    victim: &Client,
    past: u64,
) -> Vec<u8> {
    let mut mal = client(server, 33, "actor-mal", "device-mal-2");
    mal.create_group(G).unwrap();
    while mal.epoch(G).unwrap() < past {
        mal.self_update(G).unwrap();
        mal.merge_pending_commit(G).unwrap();
    }
    let add = mal
        .add_member(G, &victim.generate_key_package().unwrap())
        .unwrap();
    mal.merge_pending_commit(G).unwrap();
    add.welcome.unwrap()
}

/// Bo forgot G early; the real group moved far on. An ex-member's Welcome
/// below the head was taken before; with the log it is refused.
#[test]
fn an_impostor_welcome_below_the_head_is_refused_by_the_log() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    let mut log = Log::new();
    ada.create_group(G).unwrap();
    log_head(&mut log, &ada);
    let add = ada
        .add_member(G, &bo.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    log_head(&mut log, &ada);
    bo.join_from_welcome_at_head(
        &add.welcome.unwrap(),
        head_of(&ada, G).0,
        &head_of(&ada, G).1,
    )
    .unwrap();
    bo.forget_group(G).unwrap();
    while ada.epoch(G).unwrap() < 40 {
        ada.self_update(G).unwrap();
        ada.merge_pending_commit(G).unwrap();
        log_head(&mut log, &ada);
    }
    let head = head_of(&ada, G);

    let welcome = impostor_welcome(&server, &bo, 20);
    let at = welcome_epoch(&mut bo, &welcome);
    assert!(at < head.0, "below the head");
    let logged = log[&at];
    assert!(matches!(
        bo.join_from_welcome_at_head_logged(&welcome, head.0, &head.1, &logged, Some(0)),
        Err(Error::AlreadyAMember)
    ));
    assert!(bo.group_ids().iter().all(|g| g != G), "nothing taken");
}

/// An impostor who picks an epoch the log holds no row for gains nothing
/// while the log keeps that epoch: nothing logged at or above the floor is a
/// refusal. Below the floor, or with no floor named, the Welcome is judged
/// as before the log: it has no row to match.
#[test]
fn nothing_logged_is_refused_at_or_above_the_floor_and_judged_as_before_below_it() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    ada.create_group(G).unwrap();
    while ada.epoch(G).unwrap() < 40 {
        ada.self_update(G).unwrap();
        ada.merge_pending_commit(G).unwrap();
    }
    let head = head_of(&ada, G);

    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    let welcome = impostor_welcome(&server, &bo, 20);
    let at = welcome_epoch(&mut bo, &welcome);
    assert!(at < head.0, "below the head");
    // At the floor, and above it: refused, nothing taken.
    for floor in [at, 1] {
        let welcome = impostor_welcome(&server, &bo, 20);
        assert!(matches!(
            bo.join_from_welcome_at_head_logged(&welcome, head.0, &head.1, &[], Some(floor)),
            Err(Error::AlreadyAMember)
        ));
    }
    assert!(bo.group_ids().iter().all(|g| g != G), "nothing taken");

    // Below the floor: judged without the log, and taken (unconfirmed).
    assert_eq!(
        bo.join_from_welcome_at_head_logged(&welcome, head.0, &head.1, &[], Some(at + 1))
            .unwrap(),
        G
    );

    // No floor named (an old server, or a head the log does not reach):
    // likewise.
    let mut cy = client(&server, 3, "actor-cy", "device-cy");
    let welcome = impostor_welcome(&server, &cy, 20);
    assert_eq!(
        cy.join_from_welcome_at_head_logged(&welcome, head.0, &head.1, &[], None)
            .unwrap(),
        G
    );
}

/// Bo holds a confirmed copy that fell behind; Ada takes his leaf out and
/// seats him again, and the head moves on before he reads the Welcome.
/// Answers Bo, the Welcome, the head and the verifier logged at the
/// Welcome's epoch.
fn fallen_behind(
    server: &peachy_mls_core::issuer::TestIssuer,
) -> (Client, Vec<u8>, (u64, [u8; 32]), [u8; 32]) {
    let mut ada = client(server, 1, "actor-ada", "device-ada");
    let mut bo = client(server, 2, "actor-bo", "device-bo");
    let mut log = Log::new();
    ada.create_group(G).unwrap();
    let add = ada
        .add_member(G, &bo.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    let joined_at = head_of(&ada, G);
    bo.join_from_welcome_at_head(&add.welcome.unwrap(), joined_at.0, &joined_at.1)
        .unwrap();
    assert!(bo.confirm_head(G, joined_at.0, &joined_at.1).unwrap());
    // Ada moves on without Bo, takes his leaf out and seats him again.
    for _ in 0..3 {
        ada.self_update(G).unwrap();
        ada.merge_pending_commit(G).unwrap();
    }
    let bo_leaf = ada.leaf_of_device(G, "device-bo").unwrap();
    ada.remove_leaf(G, bo_leaf).unwrap();
    ada.merge_pending_commit(G).unwrap();
    let readd = ada
        .add_member(G, &bo.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    log_head(&mut log, &ada);
    let welcome = readd.welcome.unwrap();
    ada.self_update(G).unwrap();
    ada.merge_pending_commit(G).unwrap();
    let head = head_of(&ada, G);
    let at = welcome_epoch(&mut bo, &welcome);
    assert!(at < head.0, "below the head");
    (bo, welcome, head, log[&at])
}

/// A Welcome below the head whose send key is not the logged one is
/// refused, though the device holds a copy of the group.
#[test]
fn a_welcome_the_log_contradicts_is_refused_beside_a_held_copy() {
    let server = issuer();
    let (mut bo, welcome, head, _) = fallen_behind(&server);
    assert!(matches!(
        bo.join_from_welcome_at_head_logged(&welcome, head.0, &head.1, &JUNK, Some(0)),
        Err(Error::AlreadyAMember)
    ));
}

/// With nothing logged, a Welcome below the head does not replace a copy
/// the device holds (as before); with the logged verifier it does, and its
/// report is kept until it is drawn.
#[test]
fn a_welcome_the_log_vouches_for_replaces_a_held_copy_and_its_report_waits_to_be_drawn() {
    let server = issuer();
    let (mut bo, welcome, head, _) = fallen_behind(&server);
    assert!(
        bo.join_from_welcome_at_head_logged(&welcome, head.0, &head.1, &[], None)
            .is_err(),
        "with nothing logged a held copy is not replaced below the head"
    );

    let (mut bo, welcome, head, logged) = fallen_behind(&server);
    let at = welcome_epoch(&mut bo, &welcome);
    assert_eq!(
        bo.join_from_welcome_at_head_logged(&welcome, head.0, &head.1, &logged, Some(0))
            .unwrap(),
        G
    );
    assert_eq!(bo.epoch(G).unwrap(), at);

    // The report waits to be drawn: the first peek fixes its time, a later
    // peek answers the same report at that same time, and only a drop by
    // its own id lets it go.
    let first = bo.peek_rejoin_report(G, 1_000).unwrap().expect("a report");
    assert_eq!(first.readded_by, "actor-ada");
    assert_eq!(first.drawn_at_ms, 1_000);
    assert_ne!(first.id, 0);
    let again = bo
        .peek_rejoin_report(G, 9_000)
        .unwrap()
        .expect("still kept");
    assert_eq!(again, first);
    assert!(!bo.drop_rejoin_report(G, first.id ^ 1).unwrap());
    assert!(bo.drop_rejoin_report(G, first.id).unwrap());
    assert_eq!(bo.peek_rejoin_report(G, 9_000).unwrap(), None);
}

/// Bo holds a live copy taken with no head (as a build that read none took
/// it), so no head ever vouched for it and it raised no epoch mark. An
/// earlier real Welcome, which the log vouches for and a server held back,
/// is refused: it would move the copy back to a tree that may still hold a
/// member removed since.
#[test]
fn a_logged_welcome_never_moves_an_unvouched_live_copy_back() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    let mut log = Log::new();
    ada.create_group(G).unwrap();
    log_head(&mut log, &ada);
    let first = ada
        .add_member(G, &bo.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    log_head(&mut log, &ada);
    let early = first.welcome.unwrap();
    let bo_leaf = ada.leaf_of_device(G, "device-bo").unwrap();
    ada.remove_leaf(G, bo_leaf).unwrap();
    ada.merge_pending_commit(G).unwrap();
    log_head(&mut log, &ada);
    let second = ada
        .add_member(G, &bo.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    log_head(&mut log, &ada);
    ada.self_update(G).unwrap();
    ada.merge_pending_commit(G).unwrap();
    log_head(&mut log, &ada);
    let head = head_of(&ada, G);

    assert_eq!(bo.join_from_welcome(&second.welcome.unwrap()).unwrap(), G);
    let held = bo.epoch(G).unwrap();
    let at = welcome_epoch(&mut bo, &early);
    assert!(at < held, "the late Welcome is behind the copy");
    assert!(matches!(
        bo.join_from_welcome_at_head_logged(&early, head.0, &head.1, &log[&at], Some(0)),
        Err(Error::AlreadyAMember)
    ));
    assert_eq!(
        bo.epoch(G).unwrap(),
        held,
        "the copy held did not move back"
    );
}

/// Bo is re-seated twice, each report peeked at the same time: the second
/// is drawn past every line the first owns, so no two lines share a time.
#[test]
fn two_reports_peeked_at_one_time_are_drawn_apart() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    ada.create_group(G).unwrap();
    let add = ada
        .add_member(G, &bo.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    let h = head_of(&ada, G);
    bo.join_from_welcome_at_head(&add.welcome.unwrap(), h.0, &h.1)
        .unwrap();
    assert!(bo.confirm_head(G, h.0, &h.1).unwrap());
    let mut drawn = Vec::new();
    for _ in 0..2 {
        bo.forget_group(G).unwrap();
        let bo_leaf = ada.leaf_of_device(G, "device-bo").unwrap();
        ada.remove_leaf(G, bo_leaf).unwrap();
        ada.merge_pending_commit(G).unwrap();
        let readd = ada
            .add_member(G, &bo.generate_key_package().unwrap())
            .unwrap();
        ada.merge_pending_commit(G).unwrap();
        let h = head_of(&ada, G);
        assert_eq!(
            bo.join_from_welcome_at_head(&readd.welcome.unwrap(), h.0, &h.1)
                .unwrap(),
            G
        );
        let report = bo.peek_rejoin_report(G, 5).unwrap().expect("a report");
        assert!(bo.drop_rejoin_report(G, report.id).unwrap());
        drawn.push(report);
    }
    assert_eq!(drawn[0].drawn_at_ms, 5);
    assert_eq!(drawn[1].drawn_at_ms, 5 + drawn[0].line_span());
    assert!(drawn[0].line_span() >= 4);
}

/// Ada's two devices are in G with Bo, who forgets it. Ada's first device
/// takes her second out and re-seats Bo. Answers the report his join left,
/// taken at the head (`placed`), or below it with nothing logged.
fn readded_leaving_out_a_device(placed: bool) -> peachy_mls_core::RejoinReport {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut ada2 = client(&server, 4, "actor-ada", "device-ada-2");
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    ada.create_group(G).unwrap();
    let add2 = ada
        .add_member(G, &ada2.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    let h = head_of(&ada, G);
    ada2.join_from_welcome_at_head(&add2.welcome.unwrap(), h.0, &h.1)
        .unwrap();
    let add_bo = ada
        .add_member(G, &bo.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    let h = head_of(&ada, G);
    bo.join_from_welcome_at_head(&add_bo.welcome.unwrap(), h.0, &h.1)
        .unwrap();
    assert!(bo.confirm_head(G, h.0, &h.1).unwrap());
    bo.forget_group(G).unwrap();

    let leaf2 = ada.leaf_of_device(G, "device-ada-2").unwrap();
    ada.remove_leaf(G, leaf2).unwrap();
    ada.merge_pending_commit(G).unwrap();
    let bo_leaf = ada.leaf_of_device(G, "device-bo").unwrap();
    ada.remove_leaf(G, bo_leaf).unwrap();
    ada.merge_pending_commit(G).unwrap();
    let readd = ada
        .add_member(G, &bo.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    if !placed {
        ada.self_update(G).unwrap();
        ada.merge_pending_commit(G).unwrap();
    }
    let h = head_of(&ada, G);
    let welcome = readd.welcome.unwrap();
    let joined = if placed {
        bo.join_from_welcome_at_head(&welcome, h.0, &h.1)
    } else {
        bo.join_from_welcome_at_head_logged(&welcome, h.0, &h.1, &[], None)
    };
    assert_eq!(joined.unwrap(), G);

    let report = bo.peek_rejoin_report(G, 5).unwrap().expect("a report");
    assert_eq!(report.readded_by, "actor-ada");
    assert!(report.departed_actors.is_empty(), "{report:?}");
    assert!(report.added_actors.is_empty(), "{report:?}");
    report
}

/// A seat at the head names the device the new tree left out, and draws
/// nothing for it.
#[test]
fn a_device_the_new_tree_leaves_out_is_reported_and_draws_no_line() {
    assert_eq!(
        readded_leaving_out_a_device(true).dropped_devices,
        vec![("actor-ada".to_owned(), "device-ada-2".to_owned())]
    );
}

/// A seat nothing places (below the head, nothing logged) names no device:
/// it may be in a group somebody founded under the id, and the own-seat pass
/// would add this person's other devices to it.
#[test]
fn a_seat_nothing_places_names_no_device_left_out() {
    assert!(readded_leaving_out_a_device(false)
        .dropped_devices
        .is_empty());
}
