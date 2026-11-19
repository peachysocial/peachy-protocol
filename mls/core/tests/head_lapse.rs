// SPDX-License-Identifier: MIT
//! No answer of the delivery service's about a group's head can take away
//! what a device already knows about the group (docs/delivery.md
//! §Two seats under one group id).
//!
//! The head is the server's word. A head at a copy's own epoch under another
//! send key stops the copy counting toward the epoch mark from then on, and
//! nothing more:
//!
//! - the copy keeps naming its people to the rejoin report, so a group of
//!   somebody's own under the id, when the head names it, is still drawn
//!   with everybody it leaves out;
//! - the epochs the copy reached while confirmed stay in the mark;
//! - a forget keeps the copy's roster;
//! - a head below the copy is left alone;
//! - a Welcome never replaces a live copy at or below that copy's epoch.
//!
//! A copy no head ever matched (a seat below the head) is still drawn
//! against when a Welcome replaces it, never passed over as a first join; so
//! is a copy held before the head's record was kept, or under a record this
//! build cannot read.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use peachy_mls_core::issuer::TestIssuer;
use peachy_mls_core::storage::namespace_prefix;
use peachy_mls_core::{Client, Error, Incoming, KvStore, MemoryKv, PeachyStorage};
use support::{client, client_on, head_of, issuer, join_at_head, past_the_mark};

const G: &[u8] = b"4c2e8f10-7b3a-4d5e-9f6a-1b2c3d4e5f60";
const JUNK: [u8; 32] = [0u8; 32];

fn take(c: &mut Client, welcome: &[u8], head: (u64, [u8; 32])) -> Result<Vec<u8>, Error> {
    let (group, _epoch) = c.welcome_group(welcome)?;
    assert_eq!(group, G);
    c.join_from_welcome_at_head(welcome, head.0, &head.1)
}

fn opens(reader: &mut Client, wire: &[u8], text: &[u8]) -> bool {
    matches!(
        reader.process_message(G, wire),
        Ok(Incoming::Application { plaintext, .. }) if plaintext == text
    )
}

fn bump(c: &mut Client, times: usize) {
    for _ in 0..times {
        c.self_update(G).unwrap();
        c.merge_pending_commit(G).unwrap();
    }
}

/// Ada founds G and adds Bo at the head (Bo's copy is confirmed and active);
/// the group moves on three epochs, Bo follows, and an honest sweep confirms
/// him there. Mallory is nobody Bo ever saw in G.
fn world() -> (Client, Client, Client) {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    let mal = client(&server, 3, "actor-mal", "device-mal");
    ada.create_group(G).unwrap();
    let add = ada
        .add_member(G, &bo.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    take(&mut bo, &add.welcome.unwrap(), head_of(&ada, G)).unwrap();
    for _ in 0..3 {
        let c = ada.self_update(G).unwrap();
        ada.merge_pending_commit(G).unwrap();
        bo.process_commit(G, &c.commit).unwrap();
    }
    let (e, v) = head_of(&ada, G);
    assert!(bo.confirm_head(G, e, &v).unwrap());
    (ada, bo, mal)
}

/// Mallory founds her own G, pushes it past Bo's epoch and adds Bo. Returns
/// her Welcome and her group's head, which a lying server names as G's.
fn impostor_welcome(mal: &mut Client, bo: &Client) -> (Vec<u8>, (u64, [u8; 32])) {
    mal.create_group(G).unwrap();
    bump(mal, 8);
    let add = mal
        .add_member(G, &bo.generate_key_package().unwrap())
        .unwrap();
    mal.merge_pending_commit(G).unwrap();
    (add.welcome.unwrap(), head_of(mal, G))
}

/// Bo took Mallory's group, and its report draws it as hers: re-added by
/// Mallory, by name, with Mallory added and Ada gone.
fn drawn_as_mallorys(bo: &mut Client, taken: Result<Vec<u8>, Error>) {
    assert_eq!(taken.unwrap(), G);
    let report = bo.take_rejoin_report(G).unwrap().expect("a report");
    assert_eq!(report.readded_by, "actor-mal");
    assert!(!report.readded_by_untrusted, "{report:?}");
    assert_eq!(report.added_actors, vec!["actor-mal"]);
    assert_eq!(report.departed_actors, vec!["actor-ada"]);
}

/// The copy confirmed: the outsider's Welcome at her own head is taken, and
/// drawn as hers, with Ada gone.
#[test]
fn an_outsiders_welcome_against_a_confirmed_copy_is_drawn() {
    let (_ada, mut bo, mut mal) = world();
    let (welcome, imp_head) = impostor_welcome(&mut mal, &bo);
    let taken = take(&mut bo, &welcome, imp_head);
    drawn_as_mallorys(&mut bo, taken);
}

/// A sweep that names Bo's own epoch under a junk verifier lapses his copy,
/// and then names Mallory's group. Her Welcome is drawn the same: the
/// lapsed copy still names Ada and Bo.
#[test]
fn a_lapsing_head_does_not_suppress_the_report() {
    let (_ada, mut bo, mut mal) = world();
    let bo_epoch = bo.epoch(G).unwrap();
    assert!(!bo.confirm_head(G, bo_epoch, &JUNK).unwrap());
    let (welcome, imp_head) = impostor_welcome(&mut mal, &bo);
    assert!(!bo.confirm_head(G, imp_head.0, &imp_head.1).unwrap());
    let taken = take(&mut bo, &welcome, imp_head);
    drawn_as_mallorys(&mut bo, taken);
}

/// A group under `G` founded by `actor`'s device, its stored epoch rewritten
/// to `epoch`, as a modified client would simply write it.
fn impostor_at_epoch(
    server: &TestIssuer,
    tag: u8,
    actor: &str,
    device: &str,
    epoch: u64,
) -> Client {
    let kv = MemoryKv::new();
    {
        let storage = PeachyStorage::open(Box::new(kv.clone())).unwrap();
        let mut founder = client_on(server, tag, actor, device, storage);
        founder.create_group(G).unwrap();
    }
    let prefix = namespace_prefix(b"group_context");
    for (key, value) in kv.scan(&prefix).unwrap() {
        let mut json: serde_json::Value = serde_json::from_slice(&value).unwrap();
        json["epoch"] = serde_json::json!(epoch);
        kv.put(&key, &serde_json::to_vec(&json).unwrap()).unwrap();
    }
    kv.flush().unwrap();
    let storage = PeachyStorage::open(Box::new(kv.clone())).unwrap();
    let reopened = client_on(server, tag, actor, device, storage);
    assert_eq!(reopened.epoch(G).unwrap(), epoch);
    reopened
}

/// Ada founds G, seats Bo at the head and Mallory, then removes Mallory and
/// self-updates `extra` times; Bo follows every commit and an honest sweep
/// confirms him.
fn mallory_removed(server: &TestIssuer, extra: usize) -> (Client, Client) {
    let mut ada = client(server, 1, "actor-ada", "device-ada");
    let mut bo = client(server, 2, "actor-bo", "device-bo");
    let mut mal = client(server, 3, "actor-mal", "device-mal");
    ada.create_group(G).unwrap();
    let add_bo = ada
        .add_member(G, &bo.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    take(&mut bo, &add_bo.welcome.unwrap(), head_of(&ada, G)).unwrap();
    let add_mal = ada
        .add_member(G, &mal.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &add_mal.commit).unwrap();
    take(&mut mal, &add_mal.welcome.unwrap(), head_of(&ada, G)).unwrap();
    let leaf = ada.leaf_of_device(G, "device-mal").unwrap();
    let rm = ada.remove_leaf(G, leaf).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &rm.commit).unwrap();
    for _ in 0..extra {
        let up = ada.self_update(G).unwrap();
        ada.merge_pending_commit(G).unwrap();
        bo.process_commit(G, &up.commit).unwrap();
    }
    let (e, v) = head_of(&ada, G);
    assert!(bo.confirm_head(G, e, &v).unwrap());
    (ada, bo)
}

/// The removed member's group of her own at `epoch`, with Bo added.
fn removed_members_group(server: &TestIssuer, bo: &Client, epoch: u64) -> (Client, Vec<u8>) {
    let mut imp = impostor_at_epoch(server, 3, "actor-mal", "device-mal", epoch);
    let add = imp
        .add_member(G, &bo.generate_key_package().unwrap())
        .unwrap();
    imp.merge_pending_commit(G).unwrap();
    (imp, add.welcome.unwrap())
}

/// The removed member's group, named by a lying head, is drawn as hers with
/// Ada gone, with or without the lapsing head.
#[test]
fn a_removed_members_group_is_reported_before_and_after_a_lapse() {
    for lapse in [false, true] {
        let server = issuer();
        let (_ada, mut bo) = mallory_removed(&server, 0);
        if lapse {
            let bo_epoch = bo.epoch(G).unwrap();
            bo.confirm_head(G, bo_epoch, &JUNK).unwrap();
        }
        let (imp, welcome) = removed_members_group(&server, &bo, 40);
        let taken = take(&mut bo, &welcome, head_of(&imp, G));
        drawn_as_mallorys(&mut bo, taken);
    }
}

/// The epochs a confirmed copy reached through other members' commits stay
/// in the mark when a head lapses it. Bo is confirmed at 3, follows Ada to
/// 8, and a head at 8 under a junk verifier lapses him. A Welcome at 5 is
/// refused while he holds the live copy, and still after he forgets it.
#[test]
fn a_lapse_keeps_the_epochs_a_confirmed_copy_reached_in_the_mark() {
    let server = issuer();
    let (mut ada, mut bo) = mallory_removed(&server, 0);
    for _ in 0..5 {
        let up = ada.self_update(G).unwrap();
        ada.merge_pending_commit(G).unwrap();
        bo.process_commit(G, &up.commit).unwrap();
    }
    let reached = bo.epoch(G).unwrap();
    assert!(reached >= 8, "reached {reached}");
    assert!(!bo.confirm_head(G, reached, &JUNK).unwrap());

    let (imp, welcome) = removed_members_group(&server, &bo, 4);
    let head = head_of(&imp, G);
    assert!(head.0 < reached);
    let r = take(&mut bo, &welcome, head);
    assert!(matches!(r, Err(Error::AlreadyAMember)), "{r:?}");
    assert_eq!(bo.epoch(G).unwrap(), reached);

    bo.forget_group(G).unwrap();
    let (imp, welcome) = removed_members_group(&server, &bo, 4);
    let r = take(&mut bo, &welcome, head_of(&imp, G));
    assert!(matches!(r, Err(Error::AlreadyAMember)), "{r:?}");
}

/// Ada, Bo and Mal share G; Bo's copy is confirmed by honest sweeps.
fn three_in_a_group() -> (Client, Client, Client) {
    let s = issuer();
    let mut ada = client(&s, 1, "actor-ada", "device-ada");
    let mut bo = client(&s, 2, "actor-bo", "device-bo");
    let mut mal = client(&s, 3, "actor-mal", "device-mal");
    ada.create_group(G).unwrap();
    let add_bo = ada
        .add_member(G, &bo.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    join_at_head(&mut bo, &add_bo.welcome.unwrap(), head_of(&ada, G)).unwrap();
    let add_mal = ada
        .add_member(G, &mal.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &add_mal.commit).unwrap();
    join_at_head(&mut mal, &add_mal.welcome.unwrap(), head_of(&ada, G)).unwrap();
    for _ in 0..2 {
        let c = ada.self_update(G).unwrap();
        ada.merge_pending_commit(G).unwrap();
        bo.process_commit(G, &c.commit).unwrap();
        mal.process_commit(G, &c.commit).unwrap();
        assert!(bo
            .confirm_head(G, head_of(&ada, G).0, &head_of(&ada, G).1)
            .unwrap());
    }
    (ada, bo, mal)
}

/// Ada removes Mal and moves on three epochs; Bo applies everything. Mal, on
/// the state she was removed from, re-seats Bo in a branch of her own.
fn removed_mal_branches(ada: &mut Client, bo: &mut Client, mal: &mut Client) -> Vec<u8> {
    let leaf = ada.leaf_of_device(G, "device-mal").unwrap();
    let removal = ada.remove_leaf(G, leaf).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &removal.commit).unwrap();
    for _ in 0..3 {
        let c = ada.self_update(G).unwrap();
        ada.merge_pending_commit(G).unwrap();
        bo.process_commit(G, &c.commit).unwrap();
    }
    let bo_leaf = mal.leaf_of_device(G, "device-bo").unwrap();
    mal.remove_leaf(G, bo_leaf).unwrap();
    mal.merge_pending_commit(G).unwrap();
    let readd = mal
        .add_member(G, &bo.generate_key_package().unwrap())
        .unwrap();
    mal.merge_pending_commit(G).unwrap();
    readd.welcome.unwrap()
}

/// A lapsing head, then a removed member's branch named as the head, BELOW
/// Bo's live copy: refused. Bo stays at his epoch and Mal cannot read him.
#[test]
fn a_removed_members_branch_never_rolls_back_a_live_copy() {
    let (mut ada, mut bo, mut mal) = three_in_a_group();
    let lie_epoch = bo.epoch(G).unwrap();
    assert!(!bo.confirm_head(G, lie_epoch, &JUNK).unwrap());
    let welcome = removed_mal_branches(&mut ada, &mut bo, &mut mal);
    let live = bo.epoch(G).unwrap();
    let branch_head = head_of(&mal, G);
    assert!(branch_head.0 < live);
    let taken = bo.join_from_welcome_at_head(&welcome, branch_head.0, &branch_head.1);
    assert!(matches!(taken, Err(Error::AlreadyAMember)), "{taken:?}");
    assert_eq!(bo.epoch(G).unwrap(), live);
    assert!(bo.leaf_of_device(G, "device-mal").is_err());
    let text = b"the new door code is 4471";
    let wire = bo.encrypt(G, text).unwrap();
    assert!(opens(&mut ada, &wire, text));
    assert!(!opens(&mut mal, &wire, text));
}

/// The same branch with no lapsing head: refused.
#[test]
fn a_removed_members_branch_is_refused_against_a_confirmed_copy() {
    let (mut ada, mut bo, mut mal) = three_in_a_group();
    let welcome = removed_mal_branches(&mut ada, &mut bo, &mut mal);
    let live = bo.epoch(G).unwrap();
    let branch_head = head_of(&mal, G);
    let taken = bo.join_from_welcome_at_head(&welcome, branch_head.0, &branch_head.1);
    assert!(matches!(taken, Err(Error::AlreadyAMember)), "{taken:?}");
    assert_eq!(bo.epoch(G).unwrap(), live);
}

/// A head BELOW the copy is left alone (it can trail the copy honestly), so
/// the copy stays confirmed; Bo is then removed for real and forgets G, and
/// the removed member's branch is refused by the mark.
#[test]
fn a_head_below_the_copy_changes_nothing() {
    let (mut ada, mut bo, mut mal) = three_in_a_group();
    let epoch = bo.epoch(G).unwrap();
    assert!(
        bo.confirm_head(G, epoch - 1, &JUNK).unwrap(),
        "still confirmed"
    );
    let welcome = removed_mal_branches(&mut ada, &mut bo, &mut mal);
    let leaf = ada.leaf_of_device(G, "device-bo").unwrap();
    let removal = ada.remove_leaf(G, leaf).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &removal.commit).unwrap();
    bo.forget_group(G).unwrap();
    let branch_head = head_of(&mal, G);
    let taken = bo.join_from_welcome_at_head(&welcome, branch_head.0, &branch_head.1);
    assert!(matches!(taken, Err(Error::AlreadyAMember)), "{taken:?}");
    assert!(matches!(bo.epoch(G), Err(Error::NoSuchGroup)));
}

/// Ada founds with Bo and Eve, then removes Eve.
fn ada_bo_eve_removed(server: &TestIssuer) -> (Client, Client, Client) {
    let mut ada = client(server, 1, "actor-ada", "device-ada");
    let mut bo = client(server, 2, "actor-bo", "device-bo");
    let mut eve = client(server, 3, "actor-eve", "device-eve");
    ada.create_group(G).unwrap();
    for joiner in [&mut bo, &mut eve] {
        let kp = joiner.generate_key_package().unwrap();
        let bundle = ada.add_member(G, &kp).unwrap();
        ada.merge_pending_commit(G).unwrap();
        join_at_head(joiner, &bundle.welcome.unwrap(), head_of(&ada, G)).unwrap();
    }
    let leaf = ada.leaf_of_device(G, "device-eve").unwrap();
    let removal = ada.remove_leaf(G, leaf).unwrap();
    ada.merge_pending_commit(G).unwrap();
    assert!(matches!(
        eve.process_commit(G, &removal.commit).unwrap(),
        Incoming::Commit(o) if o.removed_self
    ));
    (ada, bo, eve)
}

fn eves_group_for(eve: &mut Client, target: &Client) -> (Vec<u8>, (u64, [u8; 32])) {
    eve.forget_group(G).unwrap();
    eve.create_group(G).unwrap();
    past_the_mark(eve, G);
    let bundle = eve
        .add_member(G, &target.generate_key_package().unwrap())
        .unwrap();
    eve.merge_pending_commit(G).unwrap();
    (bundle.welcome.unwrap(), head_of(eve, G))
}

/// A head that calls Ada's copy forked lapses it, and the fork check makes
/// her forget it. The forget still keeps the roster, so removed Eve's group
/// is drawn against it, with Bo gone, as it is with no forked head.
#[test]
fn a_forked_head_then_a_forget_keeps_the_roster() {
    for forked in [false, true] {
        let server = issuer();
        let (mut ada, _bo, mut eve) = ada_bo_eve_removed(&server);
        if forked {
            let (epoch, _) = head_of(&ada, G);
            assert!(!ada.confirm_head(G, epoch, &[0xAB; 32]).unwrap());
        }
        ada.forget_group(G).unwrap();
        let (welcome, head) = eves_group_for(&mut eve, &ada);
        assert_eq!(join_at_head(&mut ada, &welcome, head).unwrap(), G);
        let report = ada.take_rejoin_report(G).unwrap().expect("a report");
        assert_eq!(report.readded_by, "actor-eve", "forked {forked}");
        assert_eq!(report.departed_actors, vec!["actor-bo"], "forked {forked}");
    }
}

/// Bo on a store of his own, seated BELOW the head (unconfirmed), with the
/// group one epoch on. Returns Ada, Bo's store and Bo.
fn bo_seated_below_the_head(server: &TestIssuer) -> (Client, MemoryKv, Client) {
    let mut ada = client(server, 1, "actor-ada", "device-ada");
    let kv = MemoryKv::new();
    let mut bo = client_on(
        server,
        2,
        "actor-bo",
        "device-bo",
        PeachyStorage::open(Box::new(kv.clone())).unwrap(),
    );
    ada.create_group(G).unwrap();
    let add = ada
        .add_member(G, &bo.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    let welcome = add.welcome.unwrap();
    bump(&mut ada, 1);
    take(&mut bo, &welcome, head_of(&ada, G)).unwrap();
    assert!(bo.epoch(G).unwrap() < ada.epoch(G).unwrap());
    (ada, kv, bo)
}

fn reopen(server: &TestIssuer, kv: &MemoryKv) -> Client {
    kv.flush().unwrap();
    client_on(
        server,
        2,
        "actor-bo",
        "device-bo",
        PeachyStorage::open(Box::new(kv.clone())).unwrap(),
    )
}

fn rewrite_head_record(kv: &MemoryKv, value: Option<&[u8]>) {
    let prefix = namespace_prefix(b"head_confirmed");
    let entries = kv.scan(&prefix).unwrap();
    assert_eq!(entries.len(), 1, "one head record");
    for (key, _) in entries {
        match value {
            Some(value) => kv.put(&key, value).unwrap(),
            None => kv.delete(&key).unwrap(),
        }
    }
}

/// A copy no head ever matched is never a first join for the Welcome that
/// replaces it: Mallory's group at a lying head is drawn as hers.
#[test]
fn a_copy_no_head_matched_still_reports_a_replacement() {
    let server = issuer();
    let (_ada, _kv, mut bo) = bo_seated_below_the_head(&server);
    let mut mal = client(&server, 3, "actor-mal", "device-mal");
    let (welcome, imp_head) = impostor_welcome(&mut mal, &bo);
    let taken = take(&mut bo, &welcome, imp_head);
    drawn_as_mallorys(&mut bo, taken);
}

/// A copy held before the head's record was kept (no record), or under a
/// record this build cannot read, is drawn against like any other.
#[test]
fn a_copy_without_a_readable_head_record_is_drawn_against() {
    for record in [None, Some(&[7u8, 7][..])] {
        let server = issuer();
        let (_ada, kv, bo) = bo_seated_below_the_head(&server);
        drop(bo);
        rewrite_head_record(&kv, record);
        let mut bo = reopen(&server, &kv);
        let mut mal = client(&server, 3, "actor-mal", "device-mal");
        let (welcome, imp_head) = impostor_welcome(&mut mal, &bo);
        let taken = take(&mut bo, &welcome, imp_head);
        drawn_as_mallorys(&mut bo, taken);
    }
}
