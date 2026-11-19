// SPDX-License-Identifier: MIT
//! The steward design's checks (`mls/core/src/steward.rs`,
//! docs/delivery.md §The sealed stamp).
//!
//! In a build that honors a steward (these tests stand in for one; none
//! ships), the hold engages only in a group this device counts as ENROLLED:
//! its meta names a steward key AND the server's sealed stamp named the same
//! key, which no build writes. Every build reads the rest and writes nothing:
//! the commit door checks the sealed stamp and the commit MAC and only
//! ALERTS; the veto frame is read and judged; the repair notice is judged.
//! These tests act as the server (sealing stamps) and as the steward
//! (signing vetoes) themselves, because no client does either.
//!
//! The cases are the design's: (a) a commit whose submitter named a verifier
//! its own epoch does not have, with a valid MAC (blame), a junk MAC (repair,
//! no blame) and a stamp the server forged (unopened); (b) a commit that did
//! not open, held for FetchCommitAt; (c) a commit this device refused, held
//! for a veto; (d) the veto itself, skipped by a device at the vetoed epoch
//! and sending one that merged the vetoed commit to rejoin.
//!
//! What a build with `STEWARD_READS` off does with all of it, which is
//! nothing, is the last test here.

#![allow(clippy::expect_used, clippy::unwrap_used)]
// Every device here stands in for a build that honors a steward
// (`Client::act_as_build_honoring_stewards`, `steward::STEWARD_READS`),
// which only the forgery door can make.
#![cfg(feature = "test-forgery")]

mod support;

use base64::Engine as _;
use peachy_mls_core::steward::{
    self, HoldReason, MacVerdict, RepairNotice, RepairNoticeVerdict, SignedVeto, Stamp,
    StampVerdict, StewardVerdict, VetoVerdict,
};
use peachy_mls_core::{Client, Incoming, MemoryKv, PeachyStorage, SEND_KEY_LABEL};
use sha2::{Digest, Sha256};
#[allow(unused_imports)]
use support::RemoveLeaf;
use support::{advance_ms, client, client_on, issuer, step_wall_ms};

const GROUP: &[u8] = b"22222222-2222-4222-8222-222222222222";
const STEWARD_SEED: [u8; 32] = [0x5a; 32];
const NONCE: [u8; 12] = [0x0c; 12];

fn meta(enrolled: bool, key_seed: &[u8; 32]) -> Vec<u8> {
    if !enrolled {
        return br#"{"v":1,"n":"Walk","adm":["actor-ada"]}"#.to_vec();
    }
    let k = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(steward::steward_public_key(key_seed));
    format!(r#"{{"v":1,"n":"Walk","adm":["actor-ada"],"stw":{{"k":"{k}","b":{{}}}}}}"#).into_bytes()
}

/// Ada (admin), Bo, Cy and Dee, all at the same epoch; when `enrolled` the
/// meta names a steward key and every device has merged a commit whose
/// sealed stamp named the same key ([`enroll`]).
fn four(enrolled: bool) -> [Client; 4] {
    let mut group = four_named(enrolled);
    if enrolled {
        enroll(&mut group, steward::steward_public_key(&STEWARD_SEED));
    }
    group
}

/// [`four`] with the meta naming the steward key when `named`, and no stamp
/// yet: nobody counts the group as enrolled.
fn four_named(named: bool) -> [Client; 4] {
    four_named_honoring(named, true)
}

/// [`four_named`], every device honoring a steward when `honoring` (a
/// build with `STEWARD_READS` on), and none when not (this build).
fn four_named_honoring(named: bool, honoring: bool) -> [Client; 4] {
    four_named_on(named, honoring, PeachyStorage::in_memory())
}

/// [`four_named_honoring`], Ada's device on `ada_storage`.
fn four_named_on(named: bool, honoring: bool, ada_storage: PeachyStorage) -> [Client; 4] {
    let enrolled = named;
    let server = issuer();
    let mut ada = client_on(&server, 1, "actor-ada", "device-ada", ada_storage);
    let mut others = [
        client(&server, 2, "actor-bo", "device-bo"),
        client(&server, 3, "actor-cy", "device-cy"),
        client(&server, 4, "actor-dee", "device-dee"),
    ];
    if honoring {
        ada.act_as_build_honoring_stewards();
        for other in others.iter_mut() {
            other.act_as_build_honoring_stewards();
        }
    }
    ada.create_group(GROUP).expect("create");
    ada.set_group_meta(GROUP, &meta(enrolled, &STEWARD_SEED))
        .expect("meta");
    ada.merge_pending_commit(GROUP).expect("merge meta");
    for i in 0..others.len() {
        let kp = others[i].generate_key_package().unwrap();
        let add = ada.add_member(GROUP, &kp).expect("add");
        ada.merge_pending_commit(GROUP).unwrap();
        for seated in others.iter_mut().take(i) {
            seated.process_commit(GROUP, &add.commit).expect("follow");
        }
        others[i]
            .join_from_welcome(&add.welcome.unwrap())
            .expect("join");
    }
    let [bo, cy, dee] = others;
    [ada, bo, cy, dee]
}

/// The server's part of enrollment: Bo and then Ada commit, each commit
/// stamped naming `steward_pub`, and every other device takes it, so each
/// has merged a foreign commit whose stamp named the key.
fn enroll(group: &mut [Client; 4], steward_pub: [u8; 32]) {
    for committer in [1usize, 0] {
        let epoch = group[committer].epoch(GROUP).unwrap();
        let key = send_key(&group[committer]);
        let bundle = group[committer].self_update(GROUP).expect("commits");
        group[committer].merge_pending_commit(GROUP).unwrap();
        let stamp = Stamp {
            next_verifier: verifier(&group[committer]),
            steward_pub: Some(steward_pub),
            mac: None,
        };
        let sealed = steward::seal_stamp_with_nonce(&key, epoch, &stamp, &NONCE).unwrap();
        for (i, member) in group.iter_mut().enumerate() {
            if i != committer {
                take(member, &bundle.commit, &sealed);
            }
        }
    }
}

fn send_key(client: &Client) -> Vec<u8> {
    client
        .export_secret(GROUP, SEND_KEY_LABEL, GROUP, 32)
        .unwrap()
}

fn verifier(client: &Client) -> [u8; 32] {
    Sha256::digest(send_key(client)).into()
}

fn mac_key(client: &Client) -> Vec<u8> {
    client
        .export_secret(GROUP, steward::COMMIT_MAC_LABEL, GROUP, 32)
        .unwrap()
}

/// Bo's self-update at the group's epoch, the stamp the server seals for it
/// naming `named` with `mac`, and the epoch it was built at. Bo merges.
fn bo_commits(
    bo: &mut Client,
    named: Option<[u8; 32]>,
    mac: impl FnOnce(&[u8], &[u8; 32], u64, &[u8]) -> Option<[u8; 32]>,
    steward_pub: Option<[u8; 32]>,
) -> (Vec<u8>, Vec<u8>, u64) {
    let epoch = bo.epoch(GROUP).unwrap();
    let key = send_key(bo);
    let mkey = mac_key(bo);
    let bundle = bo.self_update(GROUP).expect("bo commits");
    bo.merge_pending_commit(GROUP).unwrap();
    let honest = verifier(bo);
    let s = named.unwrap_or(honest);
    let stamp = Stamp {
        next_verifier: s,
        steward_pub,
        mac: mac(&mkey, &s, epoch, &bundle.commit),
    };
    let sealed = steward::seal_stamp_with_nonce(&key, epoch, &stamp, &NONCE).unwrap();
    (bundle.commit, sealed, epoch)
}

fn valid_mac(key: &[u8], s: &[u8; 32], epoch: u64, entry: &[u8]) -> Option<[u8; 32]> {
    Some(steward::commit_mac(key, s, epoch, entry))
}

fn take(client: &mut Client, commit: &[u8], stamp: &[u8]) -> steward::CommitCheck {
    client.note_commit_stamp(GROUP, stamp);
    match client.process_commit(GROUP, commit).expect("merges") {
        Incoming::Commit(_) => {}
        other => panic!("expected a commit, got {other:?}"),
    }
    client.take_commit_check(GROUP).expect("a check was kept")
}

/// (a) with a valid MAC: the committer named a verifier its epoch does not
/// have, and proved it was a member doing so. Blamed by account; the commit
/// still merges (nothing is refused).
#[test]
fn a_lying_committer_with_a_valid_mac_is_blamed() {
    let [_ada, mut bo, mut cy, _dee] = four(false);
    let (commit, stamp, epoch) = bo_commits(&mut bo, Some([0xee; 32]), valid_mac, None);
    let check = take(&mut cy, &commit, &stamp);
    assert_eq!(check.epoch, epoch);
    assert_eq!(check.stamp, StampVerdict::Blame);
    assert_eq!(check.mac, MacVerdict::Valid);
    assert_eq!(check.blame.as_deref(), Some("actor-bo"));
    assert!(check.alerts());
    assert_eq!(cy.epoch(GROUP).unwrap(), epoch + 1, "merged regardless");
    assert!(cy.take_commit_check(GROUP).is_none(), "taken once");
}

/// (a) with a junk MAC: the server and the committer cannot be told apart.
/// Repair, nobody blamed.
#[test]
fn a_junk_mac_blames_nobody() {
    let [_ada, mut bo, mut cy, _dee] = four(false);
    let (commit, stamp, _) = bo_commits(
        &mut bo,
        Some([0xee; 32]),
        |_, _, _, _| Some([0x01; 32]),
        None,
    );
    let check = take(&mut cy, &commit, &stamp);
    assert_eq!(check.stamp, StampVerdict::Repair);
    assert_eq!(check.mac, MacVerdict::Invalid);
    assert_eq!(check.blame, None);

    // No MAC at all (every committer): the same.
    let (commit, stamp, _) = bo_commits(&mut bo, Some([0xee; 32]), |_, _, _, _| None, None);
    let check = take(&mut cy, &commit, &stamp);
    assert_eq!(check.stamp, StampVerdict::Repair);
    assert_eq!(check.mac, MacVerdict::Missing);
    assert_eq!(check.blame, None);
}

/// A valid MAC over ANOTHER entry (a server that moved a MAC between
/// commits) does not hold for this one: no blame.
#[test]
fn a_mac_moved_from_another_commit_blames_nobody() {
    let [_ada, mut bo, mut cy, _dee] = four(false);
    let (commit, stamp, _) = bo_commits(
        &mut bo,
        Some([0xee; 32]),
        |key, s, epoch, _| Some(steward::commit_mac(key, s, epoch, b"some other entry")),
        None,
    );
    let check = take(&mut cy, &commit, &stamp);
    assert_eq!(check.stamp, StampVerdict::Repair);
    assert_eq!(check.mac, MacVerdict::Invalid);
}

/// (a) with a forged stamp: a stamp not sealed under the epoch's send key
/// does not open, and frames nobody.
#[test]
fn a_forged_stamp_does_not_open() {
    let [_ada, mut bo, mut cy, _dee] = four(false);
    let (commit, _, epoch) = bo_commits(&mut bo, Some([0xee; 32]), valid_mac, None);
    let forged = steward::seal_stamp_with_nonce(
        b"not the send key",
        epoch,
        &Stamp {
            next_verifier: [0xee; 32],
            steward_pub: None,
            mac: None,
        },
        &NONCE,
    )
    .unwrap();
    let check = take(&mut cy, &commit, &forged);
    assert_eq!(check.stamp, StampVerdict::Unopened);
    assert_eq!(check.blame, None);
    assert!(check.alerts());
}

/// The ordinary case: the head names what the commit produces. And a commit
/// with no stamp (a server before stamps) is only absent.
#[test]
fn an_honest_commit_matches_and_no_stamp_is_absent() {
    let [_ada, mut bo, mut cy, mut dee] = four(false);
    let (commit, stamp, _) = bo_commits(&mut bo, None, valid_mac, None);
    let check = take(&mut cy, &commit, &stamp);
    assert_eq!(check.stamp, StampVerdict::Match);
    assert_eq!(check.steward, StewardVerdict::None);
    assert!(!check.alerts());
    let check = take(&mut dee, &commit, &[]);
    assert_eq!(check.stamp, StampVerdict::Absent);
    assert!(!check.alerts());
}

/// THE k-AT-E CHECK: the stamp names the steward key the server holds; a
/// member compares it with the key the meta named at the commit's epoch.
#[test]
fn the_stamp_names_the_steward_key_the_meta_held() {
    let [_ada, mut bo, mut cy, mut dee] = four(true);
    let real = steward::steward_public_key(&STEWARD_SEED);
    let (commit, stamp, _) = bo_commits(&mut bo, None, valid_mac, Some(real));
    assert_eq!(
        take(&mut cy, &commit, &stamp).steward,
        StewardVerdict::Match
    );
    assert_eq!(
        take(&mut dee, &commit, &stamp).steward,
        StewardVerdict::Match
    );
    let (commit, stamp, _) = bo_commits(&mut bo, None, valid_mac, Some([0x42; 32]));
    let check = take(&mut cy, &commit, &stamp);
    assert_eq!(check.steward, StewardVerdict::Mismatch);
    assert!(check.alerts());
    // A stamp naming no key in an enrolled group is a mismatch too: the
    // server dropped the key it was given.
    take(&mut dee, &commit, &[]);
    let (commit, stamp, _) = bo_commits(&mut bo, None, valid_mac, None);
    assert_eq!(
        take(&mut dee, &commit, &stamp).steward,
        StewardVerdict::Mismatch
    );
}

/// (c), and THE HOLD IS INERT WITHOUT A KEY: a commit this device refused
/// after it opened strands it as before in a group never enrolled; in an
/// enrolled one the device holds instead, strands nobody, commits nothing,
/// and is released by hand, by a merge, or by its cap.
#[cfg(feature = "test-forgery")]
#[test]
fn a_refused_commit_holds_only_an_enrolled_group() {
    for enrolled in [false, true] {
        let [mut ada, mut bo, _cy, _dee] = four(enrolled);
        let cy_leaf = ada.leaf_of_device(GROUP, "device-cy").unwrap();
        let forged = bo.forge_remove_leaf(GROUP, cy_leaf).expect("bo forges");
        assert!(
            ada.process_commit(GROUP, &forged.commit).is_err(),
            "ada refuses it"
        );
        let held = ada.enter_hold(GROUP, HoldReason::RefusedCommit).unwrap();
        assert_eq!(held, enrolled, "only an enrolled group is held");
        assert_eq!(ada.group_hold(GROUP).unwrap().is_some(), enrolled);
        assert_eq!(
            ada.commit_strands(GROUP, &forged.commit).unwrap(),
            !enrolled,
            "held, the refused commit strands nobody; unenrolled, it strands as it always did"
        );
        if !enrolled {
            continue;
        }
        let refused = ada.self_update(GROUP);
        assert!(
            refused.is_err(),
            "a held group builds no commit: {refused:?}"
        );
        ada.release_hold(GROUP).unwrap();
        assert!(ada.group_hold(GROUP).unwrap().is_none());
        assert!(ada.commit_strands(GROUP, &forged.commit).unwrap());
        // ONE HOLD AN EPOCH: released, it is not entered again here, and the
        // device falls back to rejoining as it always did.
        assert!(!ada.enter_hold(GROUP, HoldReason::RefusedCommit).unwrap());
        assert!(ada.group_hold(GROUP).unwrap().is_none());

        // The cap: at a new epoch, an hour, then the hold lapses on its own,
        // and is not entered again at that epoch either.
        ada.self_update(GROUP).expect("released, ada commits");
        ada.merge_pending_commit(GROUP).unwrap();
        assert!(ada.enter_hold(GROUP, HoldReason::RefusedCommit).unwrap());
        assert!(
            ada.enter_hold(GROUP, HoldReason::FalseRepair).unwrap(),
            "a hold already holding keeps holding"
        );
        advance_ms(u64::try_from(steward::HOLD_CAP_SECONDS).unwrap() * 1000);
        assert!(
            ada.group_hold(GROUP).unwrap().is_none(),
            "lapsed at its cap"
        );
        assert!(
            !ada.enter_hold(GROUP, HoldReason::RefusedCommit).unwrap(),
            "re-entering after the cap would hold forever"
        );
    }
}

/// A CLOCK SET BACK does not stretch a hold: the hold lapses, and is not
/// entered again at that epoch.
#[test]
fn a_clock_set_back_lapses_a_hold() {
    let [_ada, _bo, mut cy, _dee] = four(true);
    assert!(cy.enter_hold(GROUP, HoldReason::UnopenableCommit).unwrap());
    step_wall_ms(-60_000);
    assert!(cy.group_hold(GROUP).unwrap().is_none(), "lapsed");
    assert!(!cy.enter_hold(GROUP, HoldReason::UnopenableCommit).unwrap());
    step_wall_ms(60_000);
    assert!(cy.group_hold(GROUP).unwrap().is_none(), "still lapsed");
}

/// ENROLLMENT NEEDS THE SERVER'S WORD: a meta naming a steward key enrolls
/// nobody until a stamp names the same key; a stamp naming another key, or
/// none, unenrolls; and a plain member who writes a key of their own into
/// the meta changes nothing anybody counts: the group stays enrolled under
/// the real key, and their key can neither hold it nor sign a veto anybody
/// honours.
#[test]
fn only_a_key_the_stamp_names_enrolls() {
    let real = steward::steward_public_key(&STEWARD_SEED);

    // The meta names the key; no stamp has: nothing held.
    let [_ada, _bo, mut cy, _dee] = four_named(true);
    assert!(!cy.enter_hold(GROUP, HoldReason::UnopenableCommit).unwrap());

    // A stamp naming another key unenrolls; naming none does too.
    let [_ada, mut bo, mut cy, mut dee] = four(true);
    let (commit, stamp, _) = bo_commits(&mut bo, None, valid_mac, Some([0x42; 32]));
    take(&mut cy, &commit, &stamp);
    assert!(!cy.enter_hold(GROUP, HoldReason::UnopenableCommit).unwrap());
    let (commit2, stamp2, _) = bo_commits(&mut bo, None, valid_mac, None);
    take(&mut dee, &commit, &stamp);
    take(&mut dee, &commit2, &stamp2);
    assert!(!dee.enter_hold(GROUP, HoldReason::UnopenableCommit).unwrap());
    // And one naming it again re-enrolls.
    let (commit3, stamp3, _) = bo_commits(&mut bo, None, valid_mac, Some(real));
    take(&mut dee, &commit3, &stamp3);
    assert!(dee.enter_hold(GROUP, HoldReason::UnopenableCommit).unwrap());

    // Bo, a plain member, writes his own key into an enrolled group's meta
    // (the meta policy lets him): his change does not count, and the
    // server's stamp still names the real key, so Cy stays enrolled under
    // the real key and under it alone.
    let [mut ada, mut bo, mut cy, _dee] = four(true);
    let bo_seed = [0x77; 32];
    let epoch = bo.epoch(GROUP).unwrap();
    let key = send_key(&bo);
    let rewrite = bo
        .set_group_meta(GROUP, &meta(true, &bo_seed))
        .expect("the meta policy lets any member write it");
    bo.merge_pending_commit(GROUP).unwrap();
    let sealed = steward::seal_stamp_with_nonce(
        &key,
        epoch,
        &Stamp {
            next_verifier: verifier(&bo),
            steward_pub: Some(real),
            mac: None,
        },
        &NONCE,
    )
    .unwrap();
    take(&mut cy, &rewrite.commit, &sealed);
    take(&mut ada, &rewrite.commit, &sealed);
    assert!(cy.enter_hold(GROUP, HoldReason::UnopenableCommit).unwrap());
    cy.release_hold(GROUP).unwrap();
    // A veto Bo's key signs, of a commit at Cy's epoch, means nothing.
    let at = cy.epoch(GROUP).unwrap();
    let replacement = ada.self_update(GROUP).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    let framed = veto_of(
        &bo_seed,
        at,
        [0x01; 32],
        verifier(&ada),
        &replacement.commit,
    );
    assert_eq!(cy.judge_veto(GROUP, &framed).unwrap(), VetoVerdict::None);
}

/// THE CONVERSE: a plain member who DELETES the steward key from the meta,
/// or rewrites it, does not un-enroll the group on anybody's device, while
/// an admin's change counts at once and enrolls under the new key as soon
/// as the server's stamp names it.
#[test]
fn only_an_admins_change_to_the_steward_key_counts() {
    let real = steward::steward_public_key(&STEWARD_SEED);
    let [mut ada, mut bo, mut cy, mut dee] = four(true);

    // Bo deletes `stw`; the stamp still names the real key.
    let epoch = bo.epoch(GROUP).unwrap();
    let key = send_key(&bo);
    let deleted = bo
        .set_group_meta(GROUP, &meta(false, &STEWARD_SEED))
        .expect("the meta policy lets any member write it");
    bo.merge_pending_commit(GROUP).unwrap();
    let sealed = steward::seal_stamp_with_nonce(
        &key,
        epoch,
        &Stamp {
            next_verifier: verifier(&bo),
            steward_pub: Some(real),
            mac: None,
        },
        &NONCE,
    )
    .unwrap();
    for member in [&mut ada, &mut cy, &mut dee] {
        take(member, &deleted.commit, &sealed);
    }
    assert!(
        cy.enter_hold(GROUP, HoldReason::UnopenableCommit).unwrap(),
        "still enrolled under the real key"
    );
    cy.release_hold(GROUP).unwrap();

    // Ada, the admin, rotates to a key of her own; the server's stamp names
    // it (the handle took her signed change). Everybody counts it.
    let next_seed = [0x33; 32];
    let next = steward::steward_public_key(&next_seed);
    let epoch = ada.epoch(GROUP).unwrap();
    let key = send_key(&ada);
    let rotated = ada
        .set_group_meta(GROUP, &meta(true, &next_seed))
        .expect("ada rotates");
    ada.merge_pending_commit(GROUP).unwrap();
    assert!(
        ada.enter_hold(GROUP, HoldReason::UnopenableCommit).unwrap(),
        "the rotator counts her own key: no stamp comes back to her"
    );
    ada.release_hold(GROUP).unwrap();
    let sealed = steward::seal_stamp_with_nonce(
        &key,
        epoch,
        &Stamp {
            next_verifier: verifier(&ada),
            steward_pub: Some(next),
            mac: None,
        },
        &NONCE,
    )
    .unwrap();
    for member in [&mut bo, &mut dee] {
        take(member, &rotated.commit, &sealed);
    }
    assert!(dee.enter_hold(GROUP, HoldReason::UnopenableCommit).unwrap());
    // Cy merged the same commit under a stamp still naming the old key: the
    // admin's change counts, the stamp disagrees, and she is not enrolled.
    let stale = steward::seal_stamp_with_nonce(
        &key,
        epoch,
        &Stamp {
            next_verifier: verifier(&ada),
            steward_pub: Some(real),
            mac: None,
        },
        &NONCE,
    )
    .unwrap();
    take(&mut cy, &rotated.commit, &stale);
    assert!(!cy.enter_hold(GROUP, HoldReason::UnopenableCommit).unwrap());
}

/// THE FOUNDER COUNTS ITS OWN KEY: the device whose own commit wrote the
/// steward key records it as the server's, since the server took the commit
/// and no stamp of it comes back. Devices seated by a Welcome still wait for
/// a stamp.
#[test]
fn the_founder_is_enrolled_by_its_own_commit() {
    let [mut ada, _bo, mut cy, _dee] = four_named(true);
    assert!(ada.enter_hold(GROUP, HoldReason::UnopenableCommit).unwrap());
    assert!(!cy.enter_hold(GROUP, HoldReason::UnopenableCommit).unwrap());
}

/// A REFUSED COMMIT'S STAMP COUNTS: a copy seated by a Welcome whose first
/// stamped commit is one it cannot apply is enrolled by that commit's stamp,
/// and holds rather than rejoining.
#[cfg(feature = "test-forgery")]
#[test]
fn a_refused_commits_stamp_enrolls_a_newly_seated_copy() {
    let real = steward::steward_public_key(&STEWARD_SEED);
    let [_ada, mut bo, mut cy, _dee] = four_named(true);
    let epoch = cy.epoch(GROUP).unwrap();
    let key = send_key(&cy);
    let dee_leaf = bo.leaf_of_device(GROUP, "device-dee").unwrap();
    let forged = bo.forge_remove_leaf(GROUP, dee_leaf).expect("bo forges");
    let sealed = steward::seal_stamp_with_nonce(
        &key,
        epoch,
        &Stamp {
            next_verifier: [0x09; 32],
            steward_pub: Some(real),
            mac: None,
        },
        &NONCE,
    )
    .unwrap();
    cy.note_commit_stamp(GROUP, &sealed);
    assert!(
        cy.process_commit(GROUP, &forged.commit).is_err(),
        "cy refuses it"
    );
    assert!(
        cy.enter_hold(GROUP, HoldReason::RefusedCommit).unwrap(),
        "the refused commit's stamp enrolled her"
    );

    // A refused commit whose stamp names another key changes nothing.
    let [_ada, mut bo, mut dee_side, _x] = four_named(true);
    let epoch = dee_side.epoch(GROUP).unwrap();
    let key = send_key(&dee_side);
    let dee_leaf = bo.leaf_of_device(GROUP, "device-dee").unwrap();
    let forged = bo.forge_remove_leaf(GROUP, dee_leaf).expect("bo forges");
    let other = steward::seal_stamp_with_nonce(
        &key,
        epoch,
        &Stamp {
            next_verifier: [0x09; 32],
            steward_pub: Some([0x42; 32]),
            mac: None,
        },
        &NONCE,
    )
    .unwrap();
    dee_side.note_commit_stamp(GROUP, &other);
    assert!(dee_side.process_commit(GROUP, &forged.commit).is_err());
    assert!(!dee_side
        .enter_hold(GROUP, HoldReason::RefusedCommit)
        .unwrap());
}

/// A COPY ENROLLED BY THE COMMIT IT MERGES keeps the key for the epoch that
/// commit left too, so a veto of that very commit sends it to rejoin rather
/// than leaving it on the vetoed branch.
#[test]
fn a_copy_enrolled_by_a_commit_honours_a_veto_of_it() {
    let real = steward::steward_public_key(&STEWARD_SEED);
    let [mut ada, mut bo, mut cy, _dee] = four_named(true);
    let epoch = cy.epoch(GROUP).unwrap();
    let (commit, stamp, _) = bo_commits(&mut bo, None, valid_mac, Some(real));
    take(&mut cy, &commit, &stamp);
    let vetoed_next = verifier(&cy);
    let replacement = ada.self_update(GROUP).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    let framed = veto_of(
        &STEWARD_SEED,
        epoch,
        vetoed_next,
        verifier(&ada),
        &replacement.commit,
    );
    assert_eq!(
        cy.judge_veto(GROUP, &framed).unwrap(),
        VetoVerdict::RejoinNow
    );
}

/// (b): a commit that did not open holds an enrolled group for the
/// FetchCommitAt answer, which opens with the epoch's send key and then
/// merges like any commit, releasing the hold.
#[test]
fn a_held_group_takes_the_fetched_commit_and_is_released() {
    let [_ada, mut bo, mut cy, _dee] = four(true);
    let epoch = cy.epoch(GROUP).unwrap();
    let key = send_key(&cy);
    let bundle = bo.self_update(GROUP).unwrap();
    bo.merge_pending_commit(GROUP).unwrap();
    // The commit never reached Cy: she holds.
    assert!(cy.enter_hold(GROUP, HoldReason::UnopenableCommit).unwrap());
    // The server's log copy of the envelope (here the bare entry stands for
    // the envelope: the copy is opaque to the server either way).
    let copy = steward::seal_log_copy_with_nonce(&key, epoch, &bundle.commit, &NONCE).unwrap();
    let opened = cy
        .open_fetched_commit(GROUP, &copy)
        .expect("opens at her epoch");
    assert_eq!(opened, bundle.commit);
    assert!(cy
        .open_fetched_commit(GROUP, &copy[..copy.len() - 1])
        .is_err());
    match cy.process_commit(GROUP, &opened).unwrap() {
        Incoming::Commit(_) => {}
        other => panic!("{other:?}"),
    }
    assert!(
        cy.group_hold(GROUP).unwrap().is_none(),
        "a merge releases it"
    );
}

/// The veto Ada's steward key signs, of the commit built at `epoch` whose
/// next verifier was `vetoed_next`, around `inner`.
fn veto_of(
    seed: &[u8; 32],
    epoch: u64,
    vetoed_next: [u8; 32],
    replacement_next: [u8; 32],
    inner: &[u8],
) -> Vec<u8> {
    let mut veto = SignedVeto {
        handle: peachy_mls_core::envelope::group_handle(GROUP).unwrap(),
        epoch,
        vetoed_next,
        replacement_next,
        signature: [0u8; 64],
    };
    veto.signature = steward::sign_statement(seed, &veto.statement(inner));
    steward::wrap_veto(&veto, inner).unwrap()
}

/// (d) THE VETO: a device at the vetoed epoch skips the vetoed commit and
/// takes the replacement; one that merged the vetoed commit is told to
/// rejoin at once, judged against the steward key it kept for that epoch. A
/// veto under another key, or for another group, means nothing.
#[test]
fn a_veto_is_skipped_to_or_rejoined_from() {
    let [mut ada, mut bo, mut cy, mut dee] = four(true);
    let epoch = ada.epoch(GROUP).unwrap();
    // Bo's commit at E, which Cy merges and Ada and Dee never see.
    let vetoed = bo.self_update(GROUP).unwrap();
    bo.merge_pending_commit(GROUP).unwrap();
    cy.process_commit(GROUP, &vetoed.commit).unwrap();
    let vetoed_next = verifier(&cy);
    // Ada's empty replacement at E, wrapped in the steward's veto.
    let replacement = ada.self_update(GROUP).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    let replacement_next = verifier(&ada);
    let framed = veto_of(
        &STEWARD_SEED,
        epoch,
        vetoed_next,
        replacement_next,
        &replacement.commit,
    );

    assert_eq!(
        dee.judge_veto(GROUP, &framed).unwrap(),
        VetoVerdict::SkipVetoed
    );
    assert_eq!(
        cy.judge_veto(GROUP, &framed).unwrap(),
        VetoVerdict::RejoinNow
    );
    // Under another key, nothing; and a plain commit is no veto.
    let foreign = veto_of(
        &[0x01; 32],
        epoch,
        vetoed_next,
        replacement_next,
        &replacement.commit,
    );
    assert_eq!(dee.judge_veto(GROUP, &foreign).unwrap(), VetoVerdict::None);
    assert_eq!(cy.judge_veto(GROUP, &foreign).unwrap(), VetoVerdict::None);
    assert_eq!(
        dee.judge_veto(GROUP, &replacement.commit).unwrap(),
        VetoVerdict::None
    );
    // Bo's own copy took the vetoed commit too.
    assert_eq!(
        bo.judge_veto(GROUP, &framed).unwrap(),
        VetoVerdict::RejoinNow
    );

    // The frame is read through every reader: the peek, and the door.
    let peek = peachy_mls_core::hint::peek_message(&framed).expect("peeks");
    assert_eq!(peek.epoch, epoch);
    assert!(!dee.commit_strands(GROUP, &framed).unwrap());
    match dee
        .process_commit(GROUP, &framed)
        .expect("the replacement merges")
    {
        Incoming::Commit(_) => {}
        other => panic!("{other:?}"),
    }
    assert_eq!(
        verifier(&dee),
        replacement_next,
        "dee is on the replacement's branch"
    );
}

/// A REPAIR NOTICE from an admin that names a verifier this device's copy
/// did not have, or repairs a head that needed none, holds an enrolled group
/// (once an epoch); a true one is consistent; one from a plain member is
/// nothing to judge and holds nothing.
#[test]
fn a_false_repair_notice_is_caught() {
    for enrolled in [false, true] {
        let [_ada, mut bo, mut cy, _dee] = four(enrolled);
        let named = enrolled.then(|| steward::steward_public_key(&STEWARD_SEED));
        let (commit, stamp, epoch) =
            bo_commits(&mut bo, Some([0xee; 32]), |_, _, _, _| None, named);
        take(&mut cy, &commit, &stamp);
        let own = verifier(&cy);
        let notice = |w: [u8; 32], s: [u8; 32]| {
            RepairNotice {
                epoch: epoch + 1,
                s,
                mac: None,
                w,
            }
            .to_wire()
        };
        assert_eq!(
            cy.check_repair_notice(GROUP, "actor-ada", notice(own, [0xee; 32]).as_bytes())
                .unwrap(),
            RepairNoticeVerdict::Consistent
        );
        assert!(cy.group_hold(GROUP).unwrap().is_none());
        // Bo is no admin: his false notice is not judged, and holds nothing.
        assert_eq!(
            cy.check_repair_notice(GROUP, "actor-bo", notice([0x24; 32], [0xee; 32]).as_bytes())
                .unwrap(),
            RepairNoticeVerdict::Unjudged
        );
        assert!(cy.group_hold(GROUP).unwrap().is_none());
        assert_eq!(
            cy.check_repair_notice(
                GROUP,
                "actor-ada",
                notice([0x24; 32], [0xee; 32]).as_bytes()
            )
            .unwrap(),
            RepairNoticeVerdict::Inconsistent
        );
        assert_eq!(cy.group_hold(GROUP).unwrap().is_some(), enrolled);
        cy.release_hold(GROUP).unwrap();
        assert_eq!(
            cy.check_repair_notice(GROUP, "actor-ada", notice(own, own).as_bytes())
                .unwrap(),
            RepairNoticeVerdict::Inconsistent,
            "a repair of a head that named the right verifier"
        );
        assert!(
            cy.group_hold(GROUP).unwrap().is_none(),
            "a second notice at the same epoch holds nothing"
        );
        assert_eq!(
            cy.check_repair_notice(GROUP, "actor-ada", br#"{"peachy":"hello","v":1}"#)
                .unwrap(),
            RepairNoticeVerdict::Unjudged
        );
    }
}

/// Cy's hold lapsed and Cy rejoined: forgotten, reseated by Bo, and
/// enrolled again by Bo's next stamped commit.
fn rejoin_after_lapse(bo: &mut Client, cy: &mut Client) {
    let real = steward::steward_public_key(&STEWARD_SEED);
    cy.forget_group(GROUP).unwrap();
    let key_package = cy.generate_key_package().unwrap();
    let cy_leaf = bo.leaf_of_device(GROUP, "device-cy").unwrap();
    let reseat = bo.replace_member(GROUP, cy_leaf, &key_package).unwrap();
    bo.merge_pending_commit(GROUP).unwrap();
    cy.join_from_welcome(&reseat.welcome.unwrap()).unwrap();
    let (commit, stamp, _) = bo_commits(bo, None, valid_mac, Some(real));
    take(cy, &commit, &stamp);
}

/// How long the hold Cy holds now lasts.
fn hold_length(cy: &Client) -> i64 {
    let hold = cy.group_hold(GROUP).unwrap().expect("held");
    hold.until - hold.since
}

/// A hold that ended in a rejoin repeats shorter within the day
/// (`steward::HOLD_REPEAT_SECONDS`): ten minutes, five, two and a half, then
/// none; a day on, the full hour.
#[test]
fn a_hold_that_ended_in_a_rejoin_repeats_shorter_within_a_day() {
    let real = steward::steward_public_key(&STEWARD_SEED);
    let [_ada, mut bo, mut cy, _dee] = four(true);
    assert!(cy.enter_hold(GROUP, HoldReason::UnopenableCommit).unwrap());
    assert_eq!(hold_length(&cy), steward::HOLD_CAP_SECONDS);
    advance_ms(u64::try_from(steward::HOLD_CAP_SECONDS).unwrap() * 1000);
    assert!(cy.group_hold(GROUP).unwrap().is_none(), "lapsed at its cap");

    for (repeat, cap) in [(1, 600), (2, 300), (3, 150)] {
        rejoin_after_lapse(&mut bo, &mut cy);
        assert!(
            cy.enter_hold(GROUP, HoldReason::UnopenableCommit).unwrap(),
            "repeat {repeat} within the day is held"
        );
        assert_eq!(hold_length(&cy), cap, "repeat {repeat}'s cap");
        assert_eq!(steward::repeat_hold_cap(repeat), Some(cap));
        advance_ms(u64::try_from(cap).unwrap() * 1000);
        assert!(
            cy.group_hold(GROUP).unwrap().is_none(),
            "repeat {repeat} lapsed"
        );
    }

    rejoin_after_lapse(&mut bo, &mut cy);
    assert!(
        !cy.enter_hold(GROUP, HoldReason::UnopenableCommit).unwrap(),
        "with the repeats spent, a stall within the day is not held: Cy rejoins"
    );
    advance_ms(u64::try_from(steward::HOLD_REPEAT_SECONDS).unwrap() * 1000);
    let (commit, stamp, _) = bo_commits(&mut bo, None, valid_mac, Some(real));
    take(&mut cy, &commit, &stamp);
    assert!(
        cy.enter_hold(GROUP, HoldReason::UnopenableCommit).unwrap(),
        "a day on, the copy holds again"
    );
    assert_eq!(
        hold_length(&cy),
        steward::HOLD_CAP_SECONDS,
        "for the full hour"
    );
}

/// A repeat hold settled by a merge does not restart the day: the next hold
/// within it is the next, shorter repeat.
#[test]
fn a_settled_repeat_hold_does_not_restart_the_day() {
    let real = steward::steward_public_key(&STEWARD_SEED);
    let [_ada, mut bo, mut cy, _dee] = four(true);
    assert!(cy.enter_hold(GROUP, HoldReason::UnopenableCommit).unwrap());
    advance_ms(u64::try_from(steward::HOLD_CAP_SECONDS).unwrap() * 1000);
    assert!(cy.group_hold(GROUP).unwrap().is_none(), "lapsed at its cap");
    rejoin_after_lapse(&mut bo, &mut cy);

    // A stall the device settles: the first repeat, then the commit comes.
    assert!(cy.enter_hold(GROUP, HoldReason::UnopenableCommit).unwrap());
    assert_eq!(hold_length(&cy), 600, "the first repeat");
    let (commit, stamp, _) = bo_commits(&mut bo, None, valid_mac, Some(real));
    take(&mut cy, &commit, &stamp);
    assert!(
        cy.group_hold(GROUP).unwrap().is_none(),
        "settled by the merge"
    );

    // A stall it cannot settle, at the next epoch: the second repeat.
    assert!(cy.enter_hold(GROUP, HoldReason::RefusedCommit).unwrap());
    assert_eq!(hold_length(&cy), 300, "the second repeat, not a full hour");
    advance_ms(300 * 1000);
    rejoin_after_lapse(&mut bo, &mut cy);
    assert!(cy.enter_hold(GROUP, HoldReason::RefusedCommit).unwrap());
    assert_eq!(hold_length(&cy), 150, "the third repeat");
    let (commit, stamp, _) = bo_commits(&mut bo, None, valid_mac, Some(real));
    take(&mut cy, &commit, &stamp);
    assert!(
        !cy.enter_hold(GROUP, HoldReason::RefusedCommit).unwrap(),
        "the repeats spent, settled or not: Cy rejoins"
    );

    // A day after the full hold: the full hour again.
    advance_ms(u64::try_from(steward::HOLD_REPEAT_SECONDS).unwrap() * 1000);
    rejoin_after_lapse(&mut bo, &mut cy);
    assert!(cy.enter_hold(GROUP, HoldReason::UnopenableCommit).unwrap());
    assert_eq!(hold_length(&cy), steward::HOLD_CAP_SECONDS);
}

/// A HOLD BEGUN WHILE THE CLOCK RAN AHEAD does not stretch the day: once the
/// clock comes back, the start it wrote is counted from then, so the copy
/// holds again a day later, not a day after the date the clock had shown.
#[test]
fn a_hold_begun_under_a_clock_ahead_counts_the_day_from_its_return() {
    let real = steward::steward_public_key(&STEWARD_SEED);
    let [_ada, mut bo, mut cy, _dee] = four(true);
    // Ninety days ahead.
    let ahead_ms: i64 = 90 * 24 * 3_600 * 1000;
    step_wall_ms(ahead_ms);
    assert!(cy.enter_hold(GROUP, HoldReason::UnopenableCommit).unwrap());
    // The clock comes back: the hold lapses (a clock set back lapses it).
    step_wall_ms(-ahead_ms);
    assert!(
        cy.group_hold(GROUP).unwrap().is_none(),
        "lapsed when the clock came back"
    );

    // The lapse sends Cy back in: forgotten, and reseated by Bo.
    cy.forget_group(GROUP).unwrap();
    let key_package = cy.generate_key_package().unwrap();
    let cy_leaf = bo.leaf_of_device(GROUP, "device-cy").unwrap();
    let reseat = bo.replace_member(GROUP, cy_leaf, &key_package).unwrap();
    bo.merge_pending_commit(GROUP).unwrap();
    cy.join_from_welcome(&reseat.welcome.unwrap()).unwrap();
    let (commit, stamp, _) = bo_commits(&mut bo, None, valid_mac, Some(real));
    take(&mut cy, &commit, &stamp);

    assert!(
        cy.enter_hold(GROUP, HoldReason::UnopenableCommit).unwrap(),
        "within the day of the clock's return: a repeat hold"
    );
    assert_eq!(
        hold_length(&cy),
        steward::HOLD_REPEAT_CAP_SECONDS,
        "only the first repeat's ten minutes"
    );
    // The repeat lapses and Cy rejoins again; a day after the clock came
    // back (not ninety days on) the day is over, and a hold is a full one.
    advance_ms(u64::try_from(steward::HOLD_REPEAT_CAP_SECONDS).unwrap() * 1000);
    rejoin_after_lapse(&mut bo, &mut cy);
    advance_ms(u64::try_from(steward::HOLD_REPEAT_SECONDS).unwrap() * 1000);
    let (commit, stamp, _) = bo_commits(&mut bo, None, valid_mac, Some(real));
    take(&mut cy, &commit, &stamp);
    assert!(
        cy.enter_hold(GROUP, HoldReason::UnopenableCommit).unwrap(),
        "a day after the clock came back, the copy holds again, not ninety days on"
    );
    assert_eq!(hold_length(&cy), steward::HOLD_CAP_SECONDS);
}

/// A veto of a commit more than 63 epochs behind a copy that merged it: the
/// copy's kept verifiers no longer reach `E + 1`, so the frame cannot say
/// whether the copy merged the vetoed commit. It verifies under the key the
/// copy kept for `E`, so it asks for the head at once (`CheckHead`), and the
/// veto's head (`E + 1`, `replacement_next`) is below every epoch the copy
/// keeps. In a group with a steward that reads forked, never as a rollback,
/// so the copy rejoins onto the replacement branch instead of keeping the
/// vetoed one (docs/delivery.md §A commit the server refuses). The
/// same frame signed by another key asks the same and no more: the copy
/// cannot judge it, and a head read is all any frame it cannot judge buys.
#[test]
fn a_veto_further_back_than_the_kept_epochs_reads_forked() {
    let [mut ada, mut bo, mut cy, _dee] = four(true);
    let epoch = ada.epoch(GROUP).unwrap();
    // Bo's commit at E (the one to veto), which Cy merges; Ada never sees it.
    let vetoed = bo.self_update(GROUP).unwrap();
    bo.merge_pending_commit(GROUP).unwrap();
    cy.process_commit(GROUP, &vetoed.commit).unwrap();
    let vetoed_next = verifier(&cy);
    // Bo pours 64 more commits on the group's own handle; Cy follows each.
    for _ in 0..64 {
        let b = bo.self_update(GROUP).unwrap();
        bo.merge_pending_commit(GROUP).unwrap();
        cy.process_commit(GROUP, &b.commit).unwrap();
    }
    assert_eq!(cy.epoch(GROUP).unwrap(), epoch + 65);
    // Cy's sweep reads the group's head at her own epoch: vouched.
    let (e, v) = (cy.epoch(GROUP).unwrap(), verifier(&cy));
    assert!(cy.confirm_head(GROUP, e, &v).unwrap());
    let replacement = ada.self_update(GROUP).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    let replacement_next = verifier(&ada);
    let framed = veto_of(
        &STEWARD_SEED,
        epoch,
        vetoed_next,
        replacement_next,
        &replacement.commit,
    );
    assert_eq!(
        cy.judge_veto(GROUP, &framed).unwrap(),
        VetoVerdict::CheckHead,
        "a copy 65 epochs on is asked to read the head"
    );
    let forged = veto_of(
        &[0x01; 32],
        epoch,
        vetoed_next,
        replacement_next,
        &replacement.commit,
    );
    assert_eq!(
        cy.judge_veto(GROUP, &forged).unwrap(),
        VetoVerdict::CheckHead
    );
    assert!(
        !cy.head_rolled_back(GROUP, epoch + 1, &replacement_next)
            .unwrap(),
        "the veto's head read as a rollback: Cy would keep the vetoed branch"
    );
}

/// The same veto 63 epochs back, `E + 1` still kept: the frame says rejoin,
/// and the fork check says fork.
#[test]
fn a_veto_within_the_kept_epochs_rejoins_by_its_frame() {
    let [mut ada, mut bo, mut cy, _dee] = four(true);
    let epoch = ada.epoch(GROUP).unwrap();
    let vetoed = bo.self_update(GROUP).unwrap();
    bo.merge_pending_commit(GROUP).unwrap();
    cy.process_commit(GROUP, &vetoed.commit).unwrap();
    let vetoed_next = verifier(&cy);
    for _ in 0..62 {
        let b = bo.self_update(GROUP).unwrap();
        bo.merge_pending_commit(GROUP).unwrap();
        cy.process_commit(GROUP, &b.commit).unwrap();
    }
    let (e, v) = (cy.epoch(GROUP).unwrap(), verifier(&cy));
    assert!(cy.confirm_head(GROUP, e, &v).unwrap());
    let replacement = ada.self_update(GROUP).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    let replacement_next = verifier(&ada);
    let framed = veto_of(
        &STEWARD_SEED,
        epoch,
        vetoed_next,
        replacement_next,
        &replacement.commit,
    );
    assert_eq!(
        cy.judge_veto(GROUP, &framed).unwrap(),
        VetoVerdict::RejoinNow
    );
    assert!(!cy
        .head_rolled_back(GROUP, epoch + 1, &replacement_next)
        .unwrap());
}

/// A device SEATED after the vetoed commit, by a Welcome at the group's head
/// (as every app takes one): its kept epochs begin at its seat, above
/// `E + 1`, and it kept no steward key for `E`, so it cannot judge the
/// frame, and the frame asks for the head (`CheckHead`), before any stamp
/// enrolled the copy and after. The veto's head is below its seat, and
/// reads forked: it rejoins onto the replacement branch, as Cy, who merged
/// the vetoed commit, is told to by the frame.
#[test]
fn a_device_seated_after_the_vetoed_commit_reads_the_veto_forked() {
    let [mut ada, mut bo, mut cy, mut dee] = four(true);
    let epoch = ada.epoch(GROUP).unwrap();
    let vetoed = bo.self_update(GROUP).unwrap();
    bo.merge_pending_commit(GROUP).unwrap();
    cy.process_commit(GROUP, &vetoed.commit).unwrap();
    let vetoed_next = verifier(&cy);
    // Dee was away: Bo reseats her at E + 1, on the vetoed branch.
    dee.forget_group(GROUP).unwrap();
    let key_package = dee.generate_key_package().unwrap();
    let dee_leaf = bo.leaf_of_device(GROUP, "device-dee").unwrap();
    let reseat = bo.replace_member(GROUP, dee_leaf, &key_package).unwrap();
    bo.merge_pending_commit(GROUP).unwrap();
    cy.process_commit(GROUP, &reseat.commit).unwrap();
    let head = support::head_of(&bo, GROUP);
    support::join_at_head(&mut dee, &reseat.welcome.unwrap(), head).unwrap();
    assert_eq!(dee.epoch(GROUP).unwrap(), epoch + 2);
    let replacement = ada.self_update(GROUP).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    let replacement_next = verifier(&ada);
    let framed = veto_of(
        &STEWARD_SEED,
        epoch,
        vetoed_next,
        replacement_next,
        &replacement.commit,
    );
    assert_eq!(
        cy.judge_veto(GROUP, &framed).unwrap(),
        VetoVerdict::RejoinNow
    );
    assert!(!cy
        .head_rolled_back(GROUP, epoch + 1, &replacement_next)
        .unwrap());
    assert_eq!(
        dee.judge_veto(GROUP, &framed).unwrap(),
        VetoVerdict::CheckHead,
        "a copy seated past E + 1, before any stamp enrolled it, is told nothing"
    );
    // Bo's next commit, stamped naming the steward key, enrolls Dee's copy.
    let (commit, stamp, _) = bo_commits(
        &mut bo,
        None,
        |_, _, _, _| None,
        Some(steward::steward_public_key(&STEWARD_SEED)),
    );
    take(&mut dee, &commit, &stamp);
    assert_eq!(
        dee.judge_veto(GROUP, &framed).unwrap(),
        VetoVerdict::CheckHead,
        "a copy seated past E + 1, enrolled, is asked to read the head"
    );
    assert!(
        !dee.head_rolled_back(GROUP, epoch + 1, &replacement_next)
            .unwrap(),
        "the veto's head read as a rollback: Dee would keep the vetoed branch"
    );
}

/// A plain member's own key in `stw`, counted by a copy a Welcome seated
/// after the rewrite, signs vetoes: one of an epoch below that copy's seat
/// asks it for a head read, as any frame it cannot judge does, and one of
/// the commit at its own epoch is judged under the key the copy is ENROLLED
/// under, which no stamp makes the member's, so it is no veto: the copy does
/// not skip a commit on it (who counts a group as enrolled: the steward key,
/// not part of this specification). Cy, who merged the rewrite, never counted the key, and kept
/// the steward's for the epoch, so the first frame is no veto to her.
#[test]
fn a_plain_members_key_is_not_honoured_for_a_veto() {
    const BO_SEED: [u8; 32] = [0x6b; 32];
    let [_ada, mut bo, mut cy, mut dee] = four(true);
    let epoch = bo.epoch(GROUP).unwrap();
    let rewrite = bo
        .set_group_meta(GROUP, &meta(true, &BO_SEED))
        .expect("the meta policy lets any member write it");
    bo.merge_pending_commit(GROUP).unwrap();
    cy.process_commit(GROUP, &rewrite.commit).unwrap();
    dee.forget_group(GROUP).unwrap();
    let key_package = dee.generate_key_package().unwrap();
    let dee_leaf = bo.leaf_of_device(GROUP, "device-dee").unwrap();
    let reseat = bo.replace_member(GROUP, dee_leaf, &key_package).unwrap();
    bo.merge_pending_commit(GROUP).unwrap();
    cy.process_commit(GROUP, &reseat.commit).unwrap();
    let head = support::head_of(&bo, GROUP);
    support::join_at_head(&mut dee, &reseat.welcome.unwrap(), head).unwrap();
    let inner = bo.self_update(GROUP).unwrap();
    let framed = veto_of(&BO_SEED, epoch, [1u8; 32], [2u8; 32], &inner.commit);
    assert_eq!(cy.judge_veto(GROUP, &framed).unwrap(), VetoVerdict::None);
    assert_eq!(
        dee.judge_veto(GROUP, &framed).unwrap(),
        VetoVerdict::CheckHead,
        "a frame a reseated copy cannot judge asks more than a head read"
    );
    let at_dee = dee.epoch(GROUP).unwrap();
    let own = veto_of(&BO_SEED, at_dee, [1u8; 32], [2u8; 32], &inner.commit);
    assert_eq!(
        dee.judge_veto(GROUP, &own).unwrap(),
        VetoVerdict::None,
        "a veto under a plain member's key was honoured on a reseated copy"
    );
}

/// A device seated BY the vetoed commit itself (its Welcome to `E + 1`),
/// and enrolled by a stamped commit after it, is the device a veto most
/// needs to reach: the tree at `E` does not hold it. Its kept epochs begin
/// at `E + 1`, but it kept no steward key for `E`, so it cannot judge the
/// frame: the frame asks it for the head, before its enrollment and after,
/// and the veto's head at `E + 1` reads forked, not as a rollback.
#[test]
fn a_device_seated_by_the_vetoed_commit_is_asked_to_read_the_head() {
    let [mut ada, mut bo, mut cy, mut dee] = four(true);
    let epoch = ada.epoch(GROUP).unwrap();
    dee.forget_group(GROUP).unwrap();
    let key_package = dee.generate_key_package().unwrap();
    let dee_leaf = bo.leaf_of_device(GROUP, "device-dee").unwrap();
    // The vetoed commit, at E, reseats Dee.
    let vetoed = bo.replace_member(GROUP, dee_leaf, &key_package).unwrap();
    bo.merge_pending_commit(GROUP).unwrap();
    cy.process_commit(GROUP, &vetoed.commit).unwrap();
    let vetoed_next = verifier(&cy);
    let head = support::head_of(&bo, GROUP);
    support::join_at_head(&mut dee, &vetoed.welcome.unwrap(), head).unwrap();
    assert_eq!(dee.epoch(GROUP).unwrap(), epoch + 1);
    assert_eq!(verifier(&dee), vetoed_next);
    let replacement = ada.self_update(GROUP).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    let replacement_next = verifier(&ada);
    let framed = veto_of(
        &STEWARD_SEED,
        epoch,
        vetoed_next,
        replacement_next,
        &replacement.commit,
    );
    assert_eq!(
        dee.judge_veto(GROUP, &framed).unwrap(),
        VetoVerdict::CheckHead,
        "a device seated by the vetoed commit is told nothing by the veto"
    );
    // Enrolled by Bo's next stamped commit, on the branch, before the veto.
    let (commit, stamp, _) = bo_commits(
        &mut bo,
        None,
        |_, _, _, _| None,
        Some(steward::steward_public_key(&STEWARD_SEED)),
    );
    take(&mut dee, &commit, &stamp);
    assert_eq!(
        dee.judge_veto(GROUP, &framed).unwrap(),
        VetoVerdict::CheckHead,
        "a device seated by the vetoed commit, enrolled, is told nothing by the veto"
    );
    assert!(
        !dee.head_rolled_back(GROUP, epoch + 1, &replacement_next)
            .unwrap(),
        "the veto's head read as a rollback: Dee would keep the vetoed branch"
    );
}

/// What a copy's stamps said of a steward before the veto's head reaches it
/// ([`a_copy_seated_after_a_steward_strip`]).
#[derive(Clone, Copy)]
enum StampsSeen {
    /// None: the copy made only its own commits since its seat.
    None,
    /// One stamp naming the steward key, then one naming none.
    NamedThenNone,
}

/// Bo, a plain member, strips `stw` in the commit at E, the one to veto
/// (a plain member's change to the key counts for nothing on the copies
/// that merge it, but a copy seated after it takes the meta as it stands).
/// Bo reseats Dee at E + 1 on the vetoed branch, her Welcome's meta naming
/// no steward key, and Dee then makes 64 commits of her own. Answers what Cy
/// (who merged E) and Dee each read of the veto's head at E + 1.
fn a_copy_seated_after_a_steward_strip(stamps: StampsSeen) -> (bool, VetoVerdict, bool) {
    let real = steward::steward_public_key(&STEWARD_SEED);
    let [mut ada, mut bo, mut cy, mut dee] = four(true);
    let epoch = ada.epoch(GROUP).unwrap();
    let vetoed = bo
        .set_group_meta(GROUP, &meta(false, &STEWARD_SEED))
        .expect("the meta policy lets any member write it");
    bo.merge_pending_commit(GROUP).unwrap();
    cy.process_commit(GROUP, &vetoed.commit).unwrap();
    let vetoed_next = verifier(&cy);
    dee.forget_group(GROUP).unwrap();
    let key_package = dee.generate_key_package().unwrap();
    let dee_leaf = bo.leaf_of_device(GROUP, "device-dee").unwrap();
    let reseat = bo.replace_member(GROUP, dee_leaf, &key_package).unwrap();
    bo.merge_pending_commit(GROUP).unwrap();
    cy.process_commit(GROUP, &reseat.commit).unwrap();
    let head = support::head_of(&bo, GROUP);
    support::join_at_head(&mut dee, &reseat.welcome.unwrap(), head).unwrap();
    assert_eq!(dee.epoch(GROUP).unwrap(), epoch + 2);
    if let StampsSeen::NamedThenNone = stamps {
        let (commit, stamp, _) = bo_commits(&mut bo, None, valid_mac, Some(real));
        take(&mut dee, &commit, &stamp);
        let (commit, stamp, _) = bo_commits(&mut bo, None, valid_mac, None);
        take(&mut dee, &commit, &stamp);
    }
    for _ in 0..64 {
        let _own = dee.self_update(GROUP).unwrap();
        dee.merge_pending_commit(GROUP).unwrap();
    }
    let replacement = ada.self_update(GROUP).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    let replacement_next = verifier(&ada);
    let framed = veto_of(
        &STEWARD_SEED,
        epoch,
        vetoed_next,
        replacement_next,
        &replacement.commit,
    );
    let cy_rolled = cy
        .head_rolled_back(GROUP, epoch + 1, &replacement_next)
        .unwrap();
    (
        cy_rolled,
        dee.judge_veto(GROUP, &framed).unwrap(),
        dee.head_rolled_back(GROUP, epoch + 1, &replacement_next)
            .unwrap(),
    )
}

/// A copy that opened NO stamp since its seat knows nothing of the server's
/// steward key: missing evidence is no evidence that the group has none.
/// Dee, seated after a plain member stripped `stw` and making only her own
/// commits since, reads the veto's head below her kept epochs as a fork, so
/// she rejoins onto the replacement branch instead of keeping the vetoed one.
#[test]
fn a_copy_that_opened_no_stamp_reads_a_veto_below_its_window_forked() {
    let (cy_rolled, dee_frame, dee_rolled) = a_copy_seated_after_a_steward_strip(StampsSeen::None);
    assert!(!cy_rolled, "Cy merged E: forked");
    assert_eq!(
        dee_frame,
        VetoVerdict::CheckHead,
        "Dee kept no key for E: the frame asks for the head"
    );
    assert!(
        !dee_rolled,
        "the veto's head read as a rollback: Dee would keep the vetoed branch"
    );
}

/// A stamp that once named the steward key keeps the copy failing closed,
/// whatever the stamps after it named: Dee read the key on one commit and
/// none on the next, and still reads the veto's head as a fork.
#[test]
fn one_stamp_naming_a_steward_keeps_a_veto_below_the_window_forked() {
    let (_, dee_frame, dee_rolled) = a_copy_seated_after_a_steward_strip(StampsSeen::NamedThenNone);
    assert_eq!(dee_frame, VetoVerdict::CheckHead);
    assert!(!dee_rolled, "a stamp that named a steward was forgotten");
}

/// Dee, seated by a Welcome whose meta names the steward key, opened one
/// stamp naming none and has made 64 commits of her own since: her stamps
/// say no steward, but the group COUNTS one on her copy, so a head below her
/// kept epochs still reads forked.
#[test]
fn a_counted_steward_key_keeps_a_head_below_the_window_forked() {
    let [_ada, mut bo, _cy, mut dee] = four_named(true);
    let low = dee.epoch(GROUP).unwrap();
    let (commit, stamp, _) = bo_commits(&mut bo, None, valid_mac, None);
    take(&mut dee, &commit, &stamp);
    for _ in 0..64 {
        let _own = dee.self_update(GROUP).unwrap();
        dee.merge_pending_commit(GROUP).unwrap();
    }
    assert!(!dee.head_rolled_back(GROUP, low, &[7u8; 32]).unwrap());
}

/// Ada founded the group with a steward key (her own commit enrolls her
/// copy), then her own commit, an admin's, removed `stw`: the meta counts no
/// key, and no stamp of an own commit comes back, so the one record left
/// naming a steward is the key she kept for those epochs, which a veto of
/// them is judged under. Her stamps since named none, and she has made 64
/// commits of her own: a head below her kept epochs still reads forked.
#[test]
fn a_steward_key_kept_for_an_epoch_keeps_a_head_below_the_window_forked() {
    let [mut ada, mut bo, _cy, _dee] = four_named(true);
    let low = ada.epoch(GROUP).unwrap();
    let removal = ada
        .set_group_meta(GROUP, &meta(false, &STEWARD_SEED))
        .expect("an admin may change the meta");
    ada.merge_pending_commit(GROUP).unwrap();
    bo.process_commit(GROUP, &removal.commit).unwrap();
    let (commit, stamp, _) = bo_commits(&mut bo, None, valid_mac, None);
    take(&mut ada, &commit, &stamp);
    for _ in 0..64 {
        let _own = ada.self_update(GROUP).unwrap();
        ada.merge_pending_commit(GROUP).unwrap();
    }
    assert!(!ada.head_rolled_back(GROUP, low, &[7u8; 32]).unwrap());
}

/// A person who LEAVES a group for good takes its hold history with them,
/// by either road: the client dropping the kept roster
/// (`Client::forget_remembered_roster`), or the leave itself landing
/// (`Client::begin_leave`, then `Client::follow_leave` on the commit that
/// took the device out). A store read later keeps no sign the group was
/// ever stalled on this device. Seated in it again inside the day, the
/// copy's next stall is a full hold, not the next repeat.
fn leaves_for_good_and_comes_back(through_the_leave: bool) {
    let real = steward::steward_public_key(&STEWARD_SEED);
    let [_ada, mut bo, mut cy, _dee] = four(true);
    assert!(cy.enter_hold(GROUP, HoldReason::UnopenableCommit).unwrap());
    advance_ms(u64::try_from(steward::HOLD_CAP_SECONDS).unwrap() * 1000);
    assert!(cy.group_hold(GROUP).unwrap().is_none(), "lapsed at its cap");
    rejoin_after_lapse(&mut bo, &mut cy);
    assert!(cy.enter_hold(GROUP, HoldReason::UnopenableCommit).unwrap());
    assert_eq!(hold_length(&cy), 600, "a repeat within the day");
    advance_ms(600 * 1000);

    // Cy leaves for good, and is added back later the same day.
    let welcome = if through_the_leave {
        let proposals = cy.begin_leave(GROUP).unwrap();
        assert!(!proposals.is_empty(), "Cy's leave is proposed");
        for proposal in &proposals {
            assert!(matches!(
                bo.process_message(GROUP, proposal).unwrap(),
                Incoming::ProposalQueued { .. }
            ));
        }
        let leave = bo
            .commit_proposed_leaves(GROUP)
            .unwrap()
            .expect("Cy's leave committed");
        bo.merge_pending_commit(GROUP).unwrap();
        assert!(cy.follow_leave(GROUP, &leave.commit).unwrap().is_empty());
        assert!(cy.epoch(GROUP).is_err(), "the leave took");
        let key_package = cy.generate_key_package().unwrap();
        let add = bo.add_member(GROUP, &key_package).unwrap();
        bo.merge_pending_commit(GROUP).unwrap();
        add.welcome.unwrap()
    } else {
        cy.forget_group(GROUP).unwrap();
        cy.forget_remembered_roster(GROUP).unwrap();
        let key_package = cy.generate_key_package().unwrap();
        let cy_leaf = bo.leaf_of_device(GROUP, "device-cy").unwrap();
        let reseat = bo.replace_member(GROUP, cy_leaf, &key_package).unwrap();
        bo.merge_pending_commit(GROUP).unwrap();
        reseat.welcome.unwrap()
    };
    cy.join_from_welcome(&welcome).unwrap();
    let (commit, stamp, _) = bo_commits(&mut bo, None, valid_mac, Some(real));
    take(&mut cy, &commit, &stamp);

    assert!(cy.enter_hold(GROUP, HoldReason::UnopenableCommit).unwrap());
    assert_eq!(
        hold_length(&cy),
        steward::HOLD_CAP_SECONDS,
        "the hold history outlived the person leaving the group"
    );
}

#[test]
fn leaving_a_group_for_good_drops_its_hold_history() {
    leaves_for_good_and_comes_back(false);
}

#[test]
fn a_leave_that_lands_drops_the_groups_hold_history() {
    leaves_for_good_and_comes_back(true);
}

/// The device seated by the vetoed commit, when the replacement branch has
/// moved PAST its seat before the veto frame or the weekly read reaches it.
/// The frame asks it to read the head (`CheckHead`), and that head stands
/// above the copy's epoch under another verifier: the clients' fork check
/// reads it `behind`, which nothing in the mailbox carries up, and strands
/// it on the second reading a complete drain later (rule 4 of
/// the clients' commit-refusal judge). A frame no enrolled key
/// signed is no veto at the copy's own epoch, and at an earlier one asks for
/// a head read only; to a copy that kept the steward key for the vetoed
/// epoch, only the real signature is a veto.
#[test]
fn a_copy_seated_by_the_vetoed_commit_reads_a_head_past_it() {
    let [mut ada, mut bo, mut cy, mut dee] = four(true);
    let epoch = ada.epoch(GROUP).unwrap();
    dee.forget_group(GROUP).unwrap();
    let key_package = dee.generate_key_package().unwrap();
    let dee_leaf = bo.leaf_of_device(GROUP, "device-dee").unwrap();
    let vetoed = bo.replace_member(GROUP, dee_leaf, &key_package).unwrap();
    bo.merge_pending_commit(GROUP).unwrap();
    cy.process_commit(GROUP, &vetoed.commit).unwrap();
    let vetoed_next = verifier(&cy);
    let head = support::head_of(&bo, GROUP);
    support::join_at_head(&mut dee, &vetoed.welcome.unwrap(), head).unwrap();
    let replacement = ada.self_update(GROUP).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    let replacement_next = verifier(&ada);
    // The replacement branch goes on two more epochs.
    for _ in 0..2 {
        let _ = ada.self_update(GROUP).unwrap();
        ada.merge_pending_commit(GROUP).unwrap();
    }
    let framed = veto_of(
        &STEWARD_SEED,
        epoch,
        vetoed_next,
        replacement_next,
        &replacement.commit,
    );
    assert_eq!(
        dee.judge_veto(GROUP, &framed).unwrap(),
        VetoVerdict::CheckHead
    );
    let local = dee.epoch(GROUP).unwrap();
    let head_epoch = ada.epoch(GROUP).unwrap();
    assert!(
        head_epoch > local,
        "the live head ({head_epoch}) is past the vetoed branch's copy ({local}): the fork check reads behind"
    );
    assert_ne!(verifier(&ada), verifier(&dee));
    // Frames under a key nobody enrolled.
    let junk_seed = [0x77u8; 32];
    let own = veto_of(&junk_seed, local, [1u8; 32], [2u8; 32], &replacement.commit);
    assert_eq!(dee.judge_veto(GROUP, &own).unwrap(), VetoVerdict::None);
    let earlier = veto_of(
        &junk_seed,
        epoch,
        vetoed_next,
        [2u8; 32],
        &replacement.commit,
    );
    assert_eq!(
        dee.judge_veto(GROUP, &earlier).unwrap(),
        VetoVerdict::CheckHead
    );
    // Cy merged the vetoed commit and kept the steward key for E: a junk
    // signature over the same statement is no veto to her; the real one
    // rejoins.
    let forged = veto_of(
        &junk_seed,
        epoch,
        vetoed_next,
        replacement_next,
        &replacement.commit,
    );
    assert_eq!(cy.judge_veto(GROUP, &forged).unwrap(), VetoVerdict::None);
    assert_eq!(
        cy.judge_veto(GROUP, &framed).unwrap(),
        VetoVerdict::RejoinNow
    );
}

/// A STORED HOLD (`steward::STEWARD_READS` is false): a store holds a hold
/// on an enrolled group, written by a device that honored a steward; this
/// build, opened on the same store, reads no hold there and builds its
/// commits as it always does.
#[test]
fn a_stored_hold_holds_nothing_here() {
    const { assert!(!steward::STEWARD_READS) };
    let kv = MemoryKv::new();
    let on_kv = || PeachyStorage::open(Box::new(kv.clone())).unwrap();
    let mut group = four_named_on(true, true, on_kv());
    enroll(&mut group, steward::steward_public_key(&STEWARD_SEED));
    let [mut ada, mut bo, _cy, _dee] = group;

    // A build that honors a steward refuses Bo's forged commit and holds.
    let cy_leaf = ada.leaf_of_device(GROUP, "device-cy").unwrap();
    let forged = bo.forge_remove_leaf(GROUP, cy_leaf).expect("bo forges");
    assert!(ada.process_commit(GROUP, &forged.commit).is_err());
    assert!(ada.enter_hold(GROUP, HoldReason::RefusedCommit).unwrap());
    ada.flush().unwrap();
    drop(ada);

    // The hold is on the store: that build, opened on it again, still holds.
    let mut honoring = client_on(&issuer(), 1, "actor-ada", "device-ada", on_kv());
    honoring.act_as_build_honoring_stewards();
    assert!(honoring.group_hold(GROUP).unwrap().is_some());
    assert!(
        honoring.self_update(GROUP).is_err(),
        "a held group builds no commit"
    );
    drop(honoring);

    // This build, on the same store: no hold, and it commits as it always did.
    let mut here = client_on(&issuer(), 1, "actor-ada", "device-ada", on_kv());
    assert!(here.group_hold(GROUP).unwrap().is_none());
    here.self_update(GROUP)
        .expect("not held here, a commit is built");
}

/// A BUILD HONORS NO STEWARD (`steward::STEWARD_READS`): in a group the server
/// and one member enrolled (the meta names a key and the stamps name it too),
/// a build with the switch off holds nothing and builds its commits as ever,
/// and a veto skips nothing and sends nobody to rejoin: at the device's own
/// epoch it is no verdict at all, and of an earlier epoch it only asks for
/// the head to be read, as in a group never enrolled. The same group, the
/// same frames, honored, is `a_veto_is_skipped_to_or_rejoined_from`.
#[test]
fn a_build_that_honors_no_steward_holds_nothing_and_skips_nothing() {
    const { assert!(!steward::STEWARD_READS) };
    const { assert!(!steward::STEWARD_WRITES) };
    let mut group = four_named_honoring(true, false);
    enroll(&mut group, steward::steward_public_key(&STEWARD_SEED));
    let [mut ada, mut bo, mut cy, mut dee] = group;

    // No hold, whatever the reason.
    for reason in [
        HoldReason::RefusedCommit,
        HoldReason::UnopenableCommit,
        HoldReason::FalseRepair,
    ] {
        assert!(!cy.enter_hold(GROUP, reason).unwrap());
        assert!(cy.group_hold(GROUP).unwrap().is_none());
    }

    // The veto of the earlier test, signed by the key the group is enrolled
    // under.
    let epoch = ada.epoch(GROUP).unwrap();
    let vetoed = bo.self_update(GROUP).unwrap();
    bo.merge_pending_commit(GROUP).unwrap();
    cy.process_commit(GROUP, &vetoed.commit).unwrap();
    let vetoed_next = verifier(&cy);
    let replacement = ada.self_update(GROUP).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    let replacement_next = verifier(&ada);
    let framed = veto_of(
        &STEWARD_SEED,
        epoch,
        vetoed_next,
        replacement_next,
        &replacement.commit,
    );
    assert_eq!(dee.judge_veto(GROUP, &framed).unwrap(), VetoVerdict::None);
    assert_eq!(
        cy.judge_veto(GROUP, &framed).unwrap(),
        VetoVerdict::CheckHead,
        "of an earlier epoch, only the fork check"
    );
    assert_eq!(
        bo.judge_veto(GROUP, &framed).unwrap(),
        VetoVerdict::CheckHead
    );
    // The commit inside still merges as any commit does.
    match dee.process_commit(GROUP, &framed).expect("merges") {
        Incoming::Commit(_) => {}
        other => panic!("{other:?}"),
    }
    assert_eq!(verifier(&dee), replacement_next);
}
