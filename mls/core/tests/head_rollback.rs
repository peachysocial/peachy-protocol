// SPDX-License-Identifier: MIT
//! A HEAD ROLLED BACK BELOW A DEVICE'S EPOCH is no fork
//! (`Client::head_rolled_back`, docs/delivery.md §A commit the
//! server refuses).
//!
//! The server can move a group's head back to an epoch the group really
//! passed through, with the verifier it had then. Judged by epoch alone, a
//! head below the copy reads as a fork, and the device forgets the group and
//! asks back in onto the older head. A copy that the group's own head
//! vouched for above that epoch, and that came through it under that very
//! send key when the epoch is one it still keeps a verifier for, is not on a
//! branch of its own: the server rolled its head back, and the device keeps
//! its copy, however far back the head went, once the copy has kept a whole
//! window of epochs past its seat, in a group whose stamps, at least one
//! opened since the seat, never named a steward. A commit that was only
//! placed for the device, under some other handle, vouches for nothing. A
//! steward's veto below the kept epochs is pinned in insider_stall.rs.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use peachy_mls_core::steward::{self, Stamp};
use peachy_mls_core::{Client, Incoming, SEND_KEY_LABEL};
use sha2::{Digest, Sha256};
use support::{client, head_of, issuer};

const G: &[u8] = b"5c0ffee0-2b4d-4e6f-8a7b-0c1d2e3f4a5b";

/// Ada founds G and seats Bo at the head; answers both, with Bo following.
fn pair() -> (Client, Client) {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    ada.create_group(G).unwrap();
    let add = ada
        .add_member(G, &bo.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    let head = head_of(&ada, G);
    bo.join_from_welcome_at_head(&add.welcome.unwrap(), head.0, &head.1)
        .unwrap();
    (ada, bo)
}

/// Ada commits and Bo follows: both one epoch on. Nothing here says which
/// handle took Ada's commit, so it vouches for Bo's copy only once Bo reads
/// the group's head there.
fn step(ada: &mut Client, bo: &mut Client) {
    let bundle = ada.self_update(G).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &bundle.commit).unwrap();
}

/// [`step`], with the sealed stamp the server attaches to every commit,
/// naming no steward key, handed to Bo before the commit: the evidence a
/// copy needs before a head below every epoch it keeps can read as a
/// rollback.
fn stamped_step(ada: &mut Client, bo: &mut Client) {
    let epoch = ada.epoch(G).unwrap();
    let key = ada.export_secret(G, SEND_KEY_LABEL, G, 32).unwrap();
    let bundle = ada.self_update(G).unwrap();
    ada.merge_pending_commit(G).unwrap();
    let next: [u8; 32] =
        Sha256::digest(ada.export_secret(G, SEND_KEY_LABEL, G, 32).unwrap()).into();
    let stamp = Stamp {
        next_verifier: next,
        steward_pub: None,
        mac: None,
    };
    let sealed = steward::seal_stamp_with_nonce(&key, epoch, &stamp, &[0x0c; 12]).unwrap();
    bo.note_commit_stamp(G, &sealed);
    assert!(matches!(
        bo.process_commit(G, &bundle.commit).unwrap(),
        Incoming::Commit(_)
    ));
}

/// Bo reads the group's own head where his copy is.
fn read_head(bo: &mut Client) {
    let now = head_of(bo, G);
    assert!(bo.confirm_head(G, now.0, &now.1).unwrap());
}

#[test]
fn a_head_moved_back_to_an_epoch_the_copy_passed_is_a_rollback() {
    let (mut ada, mut bo) = pair();
    let old = head_of(&bo, G);
    step(&mut ada, &mut bo);
    step(&mut ada, &mut bo);
    read_head(&mut bo);
    assert_eq!(bo.epoch(G).unwrap(), old.0 + 2);

    // The server answers the head it held two commits ago.
    assert!(bo.head_rolled_back(G, old.0, &old.1).unwrap());
    // And Ada's copy, whose own commits brought it past there, says the same.
    assert!(ada.head_rolled_back(G, old.0, &old.1).unwrap());
    // Judging it changes nothing: the copy stays where it was.
    assert_eq!(bo.epoch(G).unwrap(), old.0 + 2);
}

/// THE INSIDER'S OTHER HANDLE. Ada opens a fresh handle under the verifier
/// of G's epoch N and has a commit at N placed there for Bo; G's own head
/// stays at N. Bo merges it, and his next commit to G is refused against
/// that head: (N, V_N) is an epoch and verifier his copy held, but G's head
/// never stood above it on his copy, so it is a fork and he rejoins, as
/// before, rather than staying on Ada's branch for good.
#[test]
fn a_commit_another_handle_took_vouches_for_nothing() {
    let (mut ada, mut bo) = pair();
    // Bo reads G's head at N, as every sweep does.
    read_head(&mut bo);
    let n = head_of(&bo, G);
    // Ada's commit at N, placed for Bo under a handle G's head never saw.
    step(&mut ada, &mut bo);
    assert_eq!(bo.epoch(G).unwrap(), n.0 + 1);
    // The fork check's own head read hands G's head (N, V_N) over first;
    // it vouches for N, not above it.
    bo.confirm_head(G, n.0, &n.1).unwrap();
    assert!(
        !bo.head_rolled_back(G, n.0, &n.1).unwrap(),
        "a commit only placed for the copy is no rollback of G's head"
    );
    // Two placed commits deep, the same.
    step(&mut ada, &mut bo);
    assert!(!bo.head_rolled_back(G, n.0, &n.1).unwrap());
    // Once G's own head names Bo's copy at N + 2, a head back at N is the
    // server moving it back.
    read_head(&mut bo);
    assert!(bo.head_rolled_back(G, n.0, &n.1).unwrap());
}

#[test]
fn a_merge_of_the_devices_own_commit_vouches_for_its_epoch() {
    let (mut ada, mut bo) = pair();
    let old = head_of(&bo, G);
    // Bo's own commit: the group's handle took it.
    let bundle = bo.self_update(G).unwrap();
    bo.merge_pending_commit(G).unwrap();
    ada.process_commit(G, &bundle.commit).unwrap();
    assert!(bo.head_rolled_back(G, old.0, &old.1).unwrap());
}

#[test]
fn a_head_the_copy_never_held_is_not_a_rollback() {
    let (mut ada, mut bo) = pair();
    let old = head_of(&bo, G);
    step(&mut ada, &mut bo);
    step(&mut ada, &mut bo);
    read_head(&mut bo);

    // The right epoch under another send key: a branch this copy never
    // walked, judged as a fork as before.
    let mut other = old.1;
    other[0] ^= 1;
    assert!(!bo.head_rolled_back(G, old.0, &other).unwrap());
    // A verifier that is no SHA-256.
    assert!(!bo.head_rolled_back(G, old.0, &old.1[..31]).unwrap());
    assert!(!bo.head_rolled_back(G, old.0, &[]).unwrap());
    // A group Bo does not hold.
    assert!(!bo.head_rolled_back(b"not-a-group", old.0, &old.1).unwrap());
}

#[test]
fn a_head_at_or_above_the_copy_is_not_a_rollback() {
    let (mut ada, mut bo) = pair();
    step(&mut ada, &mut bo);
    read_head(&mut bo);
    let now = head_of(&bo, G);
    assert!(!bo.head_rolled_back(G, now.0, &now.1).unwrap());
    // Ada moves on without Bo: the head is above him.
    ada.self_update(G).unwrap();
    ada.merge_pending_commit(G).unwrap();
    let ahead = head_of(&ada, G);
    assert!(!bo.head_rolled_back(G, ahead.0, &ahead.1).unwrap());
}

/// The copy keeps the verifiers of its last 64 epochs. Within them a head
/// moved back must name the copy's own verifier there; below all of them
/// there is nothing to hold it against, and a head the group's own head
/// stood above is a rollback whatever verifier it names: the server cannot
/// make a device forget a group by rolling its head back far enough.
#[test]
fn a_head_moved_back_past_the_kept_epochs_is_a_rollback() {
    let (mut ada, mut bo) = pair();
    let mut seen = vec![head_of(&bo, G)];
    stamped_step(&mut ada, &mut bo);
    seen.push(head_of(&bo, G));
    for _ in 0..64 {
        step(&mut ada, &mut bo);
        seen.push(head_of(&bo, G));
    }
    read_head(&mut bo);
    let now = bo.epoch(G).unwrap();
    // The copy's own epoch and the 63 before it: 64 kept.
    let oldest_kept = seen.iter().find(|(epoch, _)| *epoch == now - 63).unwrap();
    assert!(bo
        .head_rolled_back(G, oldest_kept.0, &oldest_kept.1)
        .unwrap());
    let mut other = oldest_kept.1;
    other[0] ^= 1;
    assert!(
        !bo.head_rolled_back(G, oldest_kept.0, &other).unwrap(),
        "within the kept epochs, another branch is a fork"
    );
    let dropped = seen.iter().find(|(epoch, _)| *epoch == now - 64).unwrap();
    assert!(bo.head_rolled_back(G, dropped.0, &dropped.1).unwrap());
    let mut forged = dropped.1;
    forged[0] ^= 1;
    assert!(bo.head_rolled_back(G, dropped.0, &forged).unwrap());
    assert!(bo.head_rolled_back(G, seen[0].0, &seen[0].1).unwrap());
    // Back to before Bo was seated.
    assert!(bo.head_rolled_back(G, seen[0].0 - 1, &seen[0].1).unwrap());
    // Still a verifier of 32 bytes only.
    assert!(!bo.head_rolled_back(G, dropped.0, &dropped.1[..31]).unwrap());
}

/// A head below the epoch a copy was seated at, while the copy still keeps
/// its seat among its epochs, is a fork: no leaf of this copy is in the
/// group at that head, and a steward's veto of the commit before the seat
/// would read just the same (insider_stall.rs).
#[test]
fn a_head_moved_back_below_a_seat_still_kept_is_a_fork() {
    let (mut ada, mut bo) = pair();
    let seat = head_of(&bo, G);
    step(&mut ada, &mut bo);
    read_head(&mut bo);
    assert!(!bo.head_rolled_back(G, seat.0 - 1, &[7u8; 32]).unwrap());
    assert!(!bo.head_rolled_back(G, seat.0 - 1, &seat.1).unwrap());
}

/// The window's edge: a copy that has entered 63 epochs past its seat keeps
/// 64, the seat among them, so a head below the seat is still a fork. One
/// more epoch, and the copy has kept 64 since its seat: the same head is a
/// rollback.
#[test]
fn a_seat_at_the_edge_of_the_kept_epochs_still_reads_a_head_below_it_forked() {
    let (mut ada, mut bo) = pair();
    let seat = head_of(&bo, G);
    stamped_step(&mut ada, &mut bo);
    for _ in 0..62 {
        step(&mut ada, &mut bo);
    }
    read_head(&mut bo);
    assert_eq!(bo.epoch(G).unwrap(), seat.0 + 63);
    assert!(!bo.head_rolled_back(G, seat.0 - 1, &[7u8; 32]).unwrap());
    step(&mut ada, &mut bo);
    read_head(&mut bo);
    assert!(bo.head_rolled_back(G, seat.0 - 1, &[7u8; 32]).unwrap());
}

/// Below the kept epochs, the group's own head must still have stood above
/// the head's epoch on this copy. Bo's only vouching is his seat; 70 placed
/// commits later the seat has left his kept epochs, and a head between the
/// seat and the oldest kept epoch is no rollback, whatever it names.
#[test]
fn a_head_below_the_kept_epochs_still_needs_the_vouching() {
    let (mut ada, mut bo) = pair();
    let seat = head_of(&bo, G);
    let mut seen = vec![seat];
    // Placed commits only: G's own head never reads Bo past the seat.
    stamped_step(&mut ada, &mut bo);
    seen.push(head_of(&bo, G));
    for _ in 0..69 {
        step(&mut ada, &mut bo);
        seen.push(head_of(&bo, G));
    }
    let between = seen.iter().find(|(epoch, _)| *epoch == seat.0 + 3).unwrap();
    assert!(!bo.head_rolled_back(G, between.0, &between.1).unwrap());
    assert!(!bo.head_rolled_back(G, seat.0, &seat.1).unwrap());
    // Below the seat, the seat's vouching stands above it.
    assert!(bo.head_rolled_back(G, seat.0 - 1, &[7u8; 32]).unwrap());
}

/// Below every epoch the copy keeps, the vouching says the head moved back
/// only on POSITIVE evidence that no steward could have vetoed there: at
/// least one stamp opened since the seat, every one naming no steward key.
/// Bo has opened none (a stamp comes with every commit the server places,
/// but these came with none), so the same heads that read rolled back in
/// `a_head_moved_back_past_the_kept_epochs_is_a_rollback` read forked.
#[test]
fn a_copy_that_opened_no_stamp_reads_a_head_below_its_window_forked() {
    let (mut ada, mut bo) = pair();
    let seat = head_of(&bo, G);
    for _ in 0..65 {
        step(&mut ada, &mut bo);
    }
    read_head(&mut bo);
    let now = bo.epoch(G).unwrap();
    assert!(!bo.head_rolled_back(G, now - 64, &[7u8; 32]).unwrap());
    assert!(!bo.head_rolled_back(G, seat.0, &seat.1).unwrap());
    // Within the kept epochs a head is held against the copy's own
    // verifiers, stamps or none.
    let kept = head_of(&bo, G);
    step(&mut ada, &mut bo);
    read_head(&mut bo);
    assert!(bo.head_rolled_back(G, kept.0, &kept.1).unwrap());
}

#[test]
fn a_forgotten_copy_has_nothing_to_roll_back() {
    let (mut ada, mut bo) = pair();
    let old = head_of(&bo, G);
    step(&mut ada, &mut bo);
    read_head(&mut bo);
    bo.forget_group(G).unwrap();
    assert!(!bo.head_rolled_back(G, old.0, &old.1).unwrap());
}

/// A stamp that names a steward key is evidence a steward exists whatever
/// the commit it came with was, so one on a commit the door refuses counts
/// too. Bo's copy is the one of
/// `a_head_moved_back_past_the_kept_epochs_is_a_rollback`, but before the
/// head moves back he is handed a commit he already merged once more, under
/// a stamp of his own epoch naming a key nobody counts: refused, and from
/// then on the same head below his window reads forked.
#[test]
fn a_refused_commits_stamp_naming_a_key_keeps_a_head_below_the_window_forked() {
    let (mut ada, mut bo) = pair();
    let seat = head_of(&bo, G);
    stamped_step(&mut ada, &mut bo);
    let mut last = Vec::new();
    for _ in 0..64 {
        let bundle = ada.self_update(G).unwrap();
        ada.merge_pending_commit(G).unwrap();
        bo.process_commit(G, &bundle.commit).unwrap();
        last = bundle.commit;
    }
    read_head(&mut bo);
    assert!(
        bo.head_rolled_back(G, seat.0, &seat.1).unwrap(),
        "the control: every stamp named none"
    );
    let epoch = bo.epoch(G).unwrap();
    let key = bo.export_secret(G, SEND_KEY_LABEL, G, 32).unwrap();
    let stamp = Stamp {
        next_verifier: [3u8; 32],
        steward_pub: Some([9u8; 32]),
        mac: None,
    };
    let sealed = steward::seal_stamp_with_nonce(&key, epoch, &stamp, &[0x0d; 12]).unwrap();
    bo.note_commit_stamp(G, &sealed);
    assert!(bo.process_commit(G, &last).is_err(), "a commit merged once");
    assert_eq!(bo.epoch(G).unwrap(), epoch);
    assert!(!bo.head_rolled_back(G, seat.0, &seat.1).unwrap());
}
