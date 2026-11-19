// SPDX-License-Identifier: MIT
//! A Welcome into a group this device knew is never refused for who signed
//! it, and every one is drawn as its own lines.
//!
//! docs/delivery.md §A Welcome into a group this device knew: the
//! device takes a re-add from anybody but a device its account removed, and
//! keeps one report per Welcome, in order, until the client takes each: who
//! re-added it, who was added, who is gone, whether the admins changed. The
//! roster it kept when it forgot the group is only the baseline those lines
//! are drawn against, so a member's own copy under the id, or a server's,
//! can change what is drawn but never keep the real group's Welcome at the
//! head out.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use peachy_mls_core::issuer::{device_key_pair, TestIssuer};
use peachy_mls_core::{
    Client, ClientConfig, Error, Incoming, MemoryKv, PeachyStorage, RejoinReport,
};
use support::{
    advance_ms, client, client_on, device_seed, head_of, issuer, other_issuer, past_the_mark,
    TestClock, DAY, HOUR, NOW,
};

const G: &[u8] = b"5d0c7a2e-61f4-4b8e-9a3d-2e7c1f9b4a63";

fn meta(admins: &[&str], pol: &str) -> Vec<u8> {
    let list: Vec<String> = admins.iter().map(|a| format!("\"{a}\"")).collect();
    format!(
        "{{\"v\":1,\"n\":\"Trip\",\"adm\":[{}]{pol}}}",
        list.join(",")
    )
    .into_bytes()
}

fn take(c: &mut Client, welcome: &[u8], head: (u64, [u8; 32])) -> Result<Vec<u8>, Error> {
    c.join_from_welcome_at_head(welcome, head.0, &head.1)
}

fn opens(reader: &mut Client, wire: &[u8], text: &[u8]) -> bool {
    matches!(
        reader.process_message(G, wire),
        Ok(Incoming::Application { plaintext, .. }) if plaintext == text
    )
}

/// Every report waiting for G, oldest first, as a client drains them.
fn take_all(c: &mut Client) -> Vec<RejoinReport> {
    let mut reports = Vec::new();
    while let Some(report) = c.take_rejoin_report(G).unwrap() {
        reports.push(report);
    }
    reports
}

fn actors(list: &[&str]) -> Vec<String> {
    list.iter().map(|a| (*a).to_owned()).collect()
}

/// A fresh credential for the client built with `tag`, issued `at` (unix s).
fn renew(keys: &TestIssuer, c: &mut Client, tag: u8, actor: &str, device: &str, at: i64) {
    let (_, public) = device_key_pair(&device_seed(tag));
    let token = keys
        .issue(actor, device, &public, at - HOUR, at + 30 * DAY)
        .unwrap();
    c.update_credential(&token, None).unwrap();
}

/// Ada founds G as its only admin under `meta_bytes` and seats `joiners`;
/// every copy is confirmed at the head.
fn real_group(ada: &mut Client, meta_bytes: &[u8], joiners: &mut [&mut Client]) {
    ada.create_group(G).unwrap();
    ada.set_group_meta(G, meta_bytes).unwrap();
    ada.merge_pending_commit(G).unwrap();
    for i in 0..joiners.len() {
        let kp = joiners[i].generate_key_package().unwrap();
        let add = ada.add_member(G, &kp).unwrap();
        ada.merge_pending_commit(G).unwrap();
        for seated in joiners[..i].iter_mut() {
            seated.process_commit(G, &add.commit).unwrap();
        }
        take(joiners[i], &add.welcome.unwrap(), head_of(ada, G)).unwrap();
    }
    let (h, v) = head_of(ada, G);
    for joiner in joiners.iter_mut() {
        assert!(joiner.confirm_head(G, h, &v).unwrap());
    }
}

/// Move the real group on `n` epochs (Ada's self-updates).
fn advance_real(ada: &mut Client, others: &mut [&mut Client], n: usize) {
    for _ in 0..n {
        let b = ada.self_update(G).unwrap();
        ada.merge_pending_commit(G).unwrap();
        for o in others.iter_mut() {
            o.process_commit(G, &b.commit).unwrap();
        }
    }
}

/// `founder` founds a group of its own under G with `meta_bytes`, seats
/// `members`, moves it to at least `min_epoch`, then adds `victim`.
fn own_group(
    founder: &mut Client,
    meta_bytes: Option<&[u8]>,
    members: &mut [&mut Client],
    victim: &Client,
    min_epoch: u64,
) -> Vec<u8> {
    founder.create_group(G).unwrap();
    if let Some(m) = meta_bytes {
        founder.set_group_meta(G, m).unwrap();
        founder.merge_pending_commit(G).unwrap();
    }
    let mut seated: Vec<usize> = Vec::new();
    for i in 0..members.len() {
        let add = founder
            .add_member(G, &members[i].generate_key_package().unwrap())
            .unwrap();
        founder.merge_pending_commit(G).unwrap();
        for &j in &seated {
            members[j].process_commit(G, &add.commit).unwrap();
        }
        members[i].join_from_welcome(&add.welcome.unwrap()).unwrap();
        seated.push(i);
    }
    while founder.epoch(G).unwrap() < min_epoch {
        let b = founder.self_update(G).unwrap();
        founder.merge_pending_commit(G).unwrap();
        for m in members.iter_mut() {
            m.process_commit(G, &b.commit).unwrap();
        }
    }
    let add = founder
        .add_member(G, &victim.generate_key_package().unwrap())
        .unwrap();
    founder.merge_pending_commit(G).unwrap();
    for m in members.iter_mut() {
        m.process_commit(G, &add.commit).unwrap();
    }
    add.welcome.unwrap()
}

/// A member's own copy under the id, taken below the head, takes the real
/// admin out of the roster Bo kept (her stand-in leaves lapsed at that
/// copy's tree clock, so anybody there may remove them). The real admin's
/// Welcome at the head still replaces that copy, and is drawn as hers, with
/// the people Bo's last copy no longer named drawn as added.
#[test]
fn a_members_copy_never_keeps_out_the_real_admins_welcome() {
    let keys = issuer();
    let mut ada = client(&keys, 1, "actor-ada", "device-ada");
    let mut bo = client(&keys, 2, "actor-bo", "device-bo");
    let mut mal = client(&keys, 3, "actor-mal", "device-mal");
    let mut yara = client(&keys, 4, "actor-yara", "device-yara");
    let mut mal2 = client(&keys, 5, "actor-mal", "device-mal-laptop");
    real_group(
        &mut ada,
        &meta(&["actor-ada"], ""),
        &mut [&mut bo, &mut mal, &mut yara],
    );

    // Mal's own group under G: the real state, and Ada's and Yara's key
    // packages as anybody can fetch them.
    mal2.create_group(G).unwrap();
    mal2.set_group_meta(G, &meta(&["actor-ada"], "")).unwrap();
    mal2.merge_pending_commit(G).unwrap();
    for kp in [
        ada.generate_key_package().unwrap(),
        yara.generate_key_package().unwrap(),
    ] {
        mal2.add_member(G, &kp).unwrap();
        mal2.merge_pending_commit(G).unwrap();
    }

    let forgotten_at = bo.epoch(G).unwrap();
    bo.forget_group(G).unwrap();

    // A month on: the honest renew, and the real group moves on.
    advance_ms(u64::try_from(31 * DAY * 1000).unwrap());
    let later = NOW + 31 * DAY;
    renew(&keys, &mut ada, 1, "actor-ada", "device-ada", later);
    renew(&keys, &mut bo, 2, "actor-bo", "device-bo", later);
    renew(&keys, &mut mal2, 5, "actor-mal", "device-mal-laptop", later);
    ada.refresh_credential(G).unwrap();
    ada.merge_pending_commit(G).unwrap();
    for _ in 0..12 {
        ada.self_update(G).unwrap();
        ada.merge_pending_commit(G).unwrap();
    }
    let real_head = head_of(&ada, G);

    // Mal seats Bo below the real head.
    mal2.refresh_credential(G).unwrap();
    mal2.merge_pending_commit(G).unwrap();
    while mal2.epoch(G).unwrap() <= forgotten_at {
        mal2.self_update(G).unwrap();
        mal2.merge_pending_commit(G).unwrap();
    }
    let add_bo = mal2
        .add_member(G, &bo.generate_key_package().unwrap())
        .unwrap();
    mal2.merge_pending_commit(G).unwrap();
    take(&mut bo, &add_bo.welcome.unwrap(), real_head).expect("Mal's seat, below the head");
    // And removes Ada's and Yara's stand-ins there; Bo applies both.
    for device in ["device-ada", "device-yara"] {
        let leaf = mal2.leaf_of_device(G, device).unwrap();
        let rm = mal2.remove_leaf(G, leaf).unwrap();
        mal2.merge_pending_commit(G).unwrap();
        bo.process_commit(G, &rm.commit).unwrap();
    }

    // The real admin re-seats Bo in the real group, at the head.
    let bo_leaf = ada.leaf_of_device(G, "device-bo").unwrap();
    let rescue = ada
        .replace_member(G, bo_leaf, &bo.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    assert_eq!(
        take(&mut bo, &rescue.welcome.unwrap(), head_of(&ada, G)).unwrap(),
        G
    );

    let reports = take_all(&mut bo);
    assert_eq!(reports.len(), 2, "{reports:?}");
    assert_eq!(reports[0].readded_by, "actor-mal");
    let rescue = &reports[1];
    assert_eq!(rescue.readded_by, "actor-ada");
    assert!(!rescue.readded_by_untrusted, "{rescue:?}");
    assert_eq!(rescue.added_actors, actors(&["actor-ada", "actor-yara"]));
    assert!(rescue.departed_actors.is_empty(), "{rescue:?}");
    // Bo is back in the real group: Ada reads it, Mal's copy does not.
    let wire = bo.encrypt(G, b"meet at 7").unwrap();
    assert!(opens(&mut ada, &wire, b"meet at 7"));
    assert!(!opens(&mut mal2, &wire, b"meet at 7"));
}

/// Simpler: Mal's own group under G holding only Bo, taken below the head,
/// leaves Ada out. Ada's Welcome at the head is taken, and drawn as hers.
#[test]
fn a_members_seat_below_the_head_never_turns_the_real_group_into_strangers() {
    let keys = issuer();
    let mut ada = client(&keys, 1, "actor-ada", "device-ada");
    let mut bo = client(&keys, 2, "actor-bo", "device-bo");
    let mut mal = client(&keys, 3, "actor-mal", "device-mal");
    let mut mal2 = client(&keys, 4, "actor-mal", "device-mal-2");

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
    let (h, v) = head_of(&ada, G);
    assert!(bo.confirm_head(G, h, &v).unwrap());

    bo.forget_group(G).unwrap();
    past_the_mark(&mut ada, G);
    past_the_mark(&mut ada, G);

    mal2.create_group(G).unwrap();
    past_the_mark(&mut mal2, G);
    let add = mal2
        .add_member(G, &bo.generate_key_package().unwrap())
        .unwrap();
    mal2.merge_pending_commit(G).unwrap();
    take(&mut bo, &add.welcome.unwrap(), head_of(&ada, G)).expect("Mal's seat");
    let mal_seat = take_all(&mut bo);
    assert_eq!(mal_seat.len(), 1);
    assert_eq!(mal_seat[0].readded_by, "actor-mal");
    assert_eq!(mal_seat[0].departed_actors, actors(&["actor-ada"]));

    let bo_leaf = ada.leaf_of_device(G, "device-bo").unwrap();
    let reseat = ada
        .replace_member(G, bo_leaf, &bo.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    assert_eq!(
        take(&mut bo, &reseat.welcome.unwrap(), head_of(&ada, G)).unwrap(),
        G
    );
    let reports = take_all(&mut bo);
    assert_eq!(reports.len(), 1, "{reports:?}");
    assert_eq!(reports[0].readded_by, "actor-ada");
    assert!(!reports[0].readded_by_untrusted, "{reports:?}");
    assert_eq!(reports[0].added_actors, actors(&["actor-ada"]));
}

/// Once Bo saw everybody it kept leave (in Mal's own group: Mal adds Zed,
/// Zed removes Mal), a stranger's Welcome is taken like any other, and drawn
/// as hers, with Zed gone.
#[test]
fn a_stranger_after_an_emptied_roster_is_drawn_by_name() {
    let keys = issuer();
    let mut ada = client(&keys, 1, "actor-ada", "device-ada");
    let mut bo = client(&keys, 2, "actor-bo", "device-bo");
    let mut mal = client(&keys, 3, "actor-mal", "device-mal");
    let mut mal2 = client(&keys, 4, "actor-mal", "device-mal-2");
    let mut zed = client(&keys, 5, "actor-zed", "device-zed");
    let mut eve = client(&keys, 6, "actor-eve", "device-eve");

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
    let (h, v) = head_of(&ada, G);
    assert!(bo.confirm_head(G, h, &v).unwrap());
    bo.forget_group(G).unwrap();
    for _ in 0..4 {
        past_the_mark(&mut ada, G);
    }

    mal2.create_group(G).unwrap();
    past_the_mark(&mut mal2, G);
    let add = mal2
        .add_member(G, &bo.generate_key_package().unwrap())
        .unwrap();
    mal2.merge_pending_commit(G).unwrap();
    take(&mut bo, &add.welcome.unwrap(), head_of(&ada, G)).expect("Mal's seat");
    let add_zed = mal2
        .add_member(G, &zed.generate_key_package().unwrap())
        .unwrap();
    mal2.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &add_zed.commit).unwrap();
    take(&mut zed, &add_zed.welcome.unwrap(), head_of(&mal2, G)).unwrap();
    let mal_leaf = zed.leaf_of_device(G, "device-mal-2").unwrap();
    let rm = zed.remove_leaf(G, mal_leaf).unwrap();
    zed.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &rm.commit).unwrap();

    eve.create_group(G).unwrap();
    for _ in 0..5 {
        past_the_mark(&mut eve, G);
    }
    let add = eve
        .add_member(G, &bo.generate_key_package().unwrap())
        .unwrap();
    eve.merge_pending_commit(G).unwrap();
    assert_eq!(
        take(&mut bo, &add.welcome.unwrap(), head_of(&eve, G)).unwrap(),
        G
    );
    let reports = take_all(&mut bo);
    let eve_seat = reports.last().expect("a report");
    assert_eq!(eve_seat.readded_by, "actor-eve");
    assert!(!eve_seat.readded_by_untrusted, "{eve_seat:?}");
    assert_eq!(eve_seat.added_actors, actors(&["actor-eve"]));
    assert_eq!(eve_seat.departed_actors, actors(&["actor-zed"]));
}

/// A member whose rights let him remove people builds a group of his own
/// without the admin, an accomplice there makes herself sole admin, and a
/// member moves the head to it. Every step is taken, and every step is
/// drawn: Ada gone, then the admins changed.
#[test]
fn an_admin_change_through_a_members_copy_is_drawn() {
    let keys = issuer();
    let mut ada = client(&keys, 1, "actor-ada", "device-ada");
    let mut mal = client(&keys, 3, "actor-mal", "device-mal");
    let mut dev = client(&keys, 6, "actor-dev", "device-dev");
    let mut mal2 = client(&keys, 5, "actor-mal", "device-mal-laptop");
    let mut eve = client(&keys, 11, "actor-eve", "device-eve");
    let mut eve2 = client(&keys, 12, "actor-eve", "device-eve-2");
    let real_meta = meta(&["actor-ada"], ",\"pol\":{\"rm\":\"any\"}");
    real_group(&mut ada, &real_meta, &mut [&mut mal, &mut dev]);
    let forgot_at = dev.epoch(G).unwrap();
    dev.forget_group(G).unwrap();
    advance_real(&mut ada, &mut [&mut mal], 40);
    let head = head_of(&ada, G);

    let w1 = own_group(
        &mut mal2,
        Some(&real_meta),
        &mut [&mut eve],
        &dev,
        forgot_at + 3,
    );
    take(&mut dev, &w1, head).unwrap();
    let mal_leaf = eve.leaf_of_device(G, "device-mal-laptop").unwrap();
    let rm = eve.remove_leaf(G, mal_leaf).unwrap();
    eve.merge_pending_commit(G).unwrap();
    dev.process_commit(G, &rm.commit).unwrap();

    let seized = meta(
        &["actor-eve"],
        ",\"pol\":{\"add\":\"adm\",\"rm\":\"adm\",\"meta\":\"adm\"}",
    );
    let w2 = own_group(&mut eve2, Some(&seized), &mut [], &dev, head.0);
    assert_eq!(take(&mut dev, &w2, head_of(&eve2, G)).unwrap(), G);

    let reports = take_all(&mut dev);
    assert_eq!(reports.len(), 2, "{reports:?}");
    assert_eq!(reports[0].readded_by, "actor-mal");
    assert_eq!(reports[0].departed_actors, actors(&["actor-ada"]));
    assert_eq!(reports[0].added_actors, actors(&["actor-eve"]));
    assert_eq!(reports[1].readded_by, "actor-eve");
    assert!(reports[1].admins_changed, "{reports:?}");
}

/// TWO WELCOMES BEFORE A DRAW: a server delivers a seat in a group of its
/// own, then a second one from another device of the same account, before
/// the client draws. Both reports come back, in order: the first still says
/// Ada and Mal are gone and the admins changed.
#[test]
fn two_welcomes_before_a_draw_leave_both_reports_in_order() {
    let keys = issuer();
    let mut ada = client(&keys, 1, "actor-ada", "device-ada");
    let mut mal = client(&keys, 3, "actor-mal", "device-mal");
    let mut dev = client(&keys, 6, "actor-dev", "device-dev");
    let mut srv = client(&keys, 9, "actor-srv", "device-srv");
    let mut srv2 = client(&keys, 10, "actor-srv", "device-srv-2");
    real_group(
        &mut ada,
        &meta(&["actor-ada"], ""),
        &mut [&mut mal, &mut dev],
    );
    let forgot_at = dev.epoch(G).unwrap();
    dev.forget_group(G).unwrap();
    advance_real(&mut ada, &mut [&mut mal], 40);

    let w1 = own_group(&mut srv, None, &mut [], &dev, forgot_at + 3);
    take(&mut dev, &w1, head_of(&srv, G)).unwrap();
    let w2 = own_group(&mut srv2, None, &mut [], &dev, forgot_at + 10);
    take(&mut dev, &w2, head_of(&srv2, G)).unwrap();

    let reports = take_all(&mut dev);
    assert_eq!(reports.len(), 2, "{reports:?}");
    assert_eq!(reports[0].readded_by, "actor-srv");
    assert_eq!(reports[0].readded_by_device, "device-srv");
    assert_eq!(
        reports[0].departed_actors,
        actors(&["actor-ada", "actor-mal"])
    );
    assert!(reports[0].admins_changed, "{reports:?}");
    assert_eq!(reports[1].readded_by_device, "device-srv-2");
    assert!(dev.take_rejoin_report(G).unwrap().is_none());
}

/// A seat that is a first join, coming after a report nobody took yet,
/// leaves that report alone.
#[test]
fn a_first_join_never_drops_an_untaken_report() {
    let keys = issuer();
    let mut ada = client(&keys, 1, "actor-ada", "device-ada");
    let mut mal = client(&keys, 3, "actor-mal", "device-mal");
    let mut dev = client(&keys, 6, "actor-dev", "device-dev");
    let mut srv = client(&keys, 9, "actor-srv", "device-srv");
    real_group(
        &mut ada,
        &meta(&["actor-ada"], ""),
        &mut [&mut mal, &mut dev],
    );
    let forgot_at = dev.epoch(G).unwrap();
    dev.forget_group(G).unwrap();
    advance_real(&mut ada, &mut [&mut mal], 40);

    // The server's own group seats Dev at its own head: confirmed there, so
    // the kept roster is spent.
    let w1 = own_group(&mut srv, None, &mut [], &dev, forgot_at + 3);
    take(&mut dev, &w1, head_of(&srv, G)).unwrap();
    // It removes Dev, so Dev has no claim on that copy, and adds it again:
    // a Welcome into a group Dev knows nothing of, a first join.
    let dev_leaf = srv.leaf_of_device(G, "device-dev").unwrap();
    let rm = srv.remove_leaf(G, dev_leaf).unwrap();
    srv.merge_pending_commit(G).unwrap();
    dev.process_commit(G, &rm.commit).unwrap();
    assert!(!dev.is_active(G).unwrap());
    let again = srv
        .add_member(G, &dev.generate_key_package().unwrap())
        .unwrap();
    srv.merge_pending_commit(G).unwrap();
    take(&mut dev, &again.welcome.unwrap(), head_of(&srv, G)).unwrap();

    let reports = take_all(&mut dev);
    assert_eq!(reports.len(), 1, "{reports:?}");
    assert_eq!(
        reports[0].departed_actors,
        actors(&["actor-ada", "actor-mal"])
    );
}

/// A copy that names nobody but this device's own person is still a group
/// this device knew. Ada removed Bo and is the only person left in her live,
/// head-confirmed G. Bo founds a group of his own under G and Welcomes Ada; a
/// server names Bo's group as the head. Ada's copy is replaced (the head
/// breaks the tie), and the swap is drawn: Bo re-added her, and Bo was added.
#[test]
fn a_sole_members_live_group_replaced_at_the_head_is_drawn() {
    let keys = issuer();
    let mut ada = client(&keys, 1, "actor-ada", "device-ada");
    let mut bo = client(&keys, 2, "actor-bo", "device-bo");
    let mut bo2 = client(&keys, 3, "actor-bo", "device-bo-laptop");

    ada.create_group(G).unwrap();
    let add = ada
        .add_member(G, &bo.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    take(&mut bo, &add.welcome.unwrap(), head_of(&ada, G)).unwrap();
    let wire = bo.encrypt(G, b"hi").unwrap();
    assert!(opens(&mut ada, &wire, b"hi"));

    let leaf = ada.leaf_of_device(G, "device-bo").unwrap();
    ada.remove_leaf(G, leaf).unwrap();
    ada.merge_pending_commit(G).unwrap();
    let (h, v) = head_of(&ada, G);
    assert!(ada.confirm_head(G, h, &v).unwrap());
    let ada_epoch = ada.epoch(G).unwrap();

    bo2.create_group(G).unwrap();
    past_the_mark(&mut bo2, G);
    assert!(bo2.epoch(G).unwrap() > ada_epoch);
    let w = bo2
        .add_member(G, &ada.generate_key_package().unwrap())
        .unwrap();
    bo2.merge_pending_commit(G).unwrap();
    assert_eq!(
        take(&mut ada, &w.welcome.unwrap(), head_of(&bo2, G)).unwrap(),
        G
    );

    let reports = take_all(&mut ada);
    assert_eq!(reports.len(), 1, "the replacement is drawn: {reports:?}");
    assert_eq!(reports[0].readded_by, "actor-bo");
    assert_eq!(reports[0].added_actors, actors(&["actor-bo"]));
    assert!(reports[0].departed_actors.is_empty(), "{reports:?}");
}

/// A held leaf whose credential no longer verifies today is still its
/// person. Bo holds a live, head-confirmed G with Ada and Cy. At his next
/// launch the server publishes only a new kid, so Ada's and Cy's leaves no
/// longer verify on Bo's device; then it names a group of its own under G as
/// the head. The swap is drawn: the server's account added, Ada and Cy gone.
#[test]
fn a_withdrawn_kid_does_not_hide_the_people_a_replacement_leaves_out() {
    let k1 = issuer();
    let k2 = other_issuer();
    let kv = MemoryKv::new();
    let mut ada = client(&k1, 1, "actor-ada", "device-ada");
    let mut cy = client(&k1, 4, "actor-cy", "device-cy");
    {
        let mut bo = client_on(
            &k1,
            2,
            "actor-bo",
            "device-bo",
            PeachyStorage::open(Box::new(kv.clone())).unwrap(),
        );
        ada.create_group(G).unwrap();
        let a = ada
            .add_member(G, &bo.generate_key_package().unwrap())
            .unwrap();
        ada.merge_pending_commit(G).unwrap();
        take(&mut bo, &a.welcome.unwrap(), head_of(&ada, G)).unwrap();
        let c = ada
            .add_member(G, &cy.generate_key_package().unwrap())
            .unwrap();
        ada.merge_pending_commit(G).unwrap();
        bo.process_commit(G, &c.commit).unwrap();
        let (h, v) = head_of(&ada, G);
        take(&mut cy, &c.welcome.unwrap(), (h, v)).unwrap();
        assert!(bo.confirm_head(G, h, &v).unwrap());
    }
    // Next launch: Bo's credential is under k2, and only k2 is trusted.
    let mut bo = client_trusting(
        &k2,
        2,
        "actor-bo",
        "device-bo",
        PeachyStorage::open(Box::new(kv.clone())).unwrap(),
    );
    let bo_epoch = bo.epoch(G).unwrap();

    let mut srv = client_trusting(
        &k2,
        9,
        "actor-srv",
        "device-srv",
        PeachyStorage::in_memory(),
    );
    srv.create_group(G).unwrap();
    past_the_mark(&mut srv, G);
    assert!(srv.epoch(G).unwrap() > bo_epoch);
    let w = srv
        .add_member(G, &bo.generate_key_package().unwrap())
        .unwrap();
    srv.merge_pending_commit(G).unwrap();
    assert_eq!(
        take(&mut bo, &w.welcome.unwrap(), head_of(&srv, G)).unwrap(),
        G
    );

    let reports = take_all(&mut bo);
    assert_eq!(reports.len(), 1, "the replacement is drawn: {reports:?}");
    assert_eq!(reports[0].readded_by, "actor-srv");
    assert_eq!(reports[0].added_actors, actors(&["actor-srv"]));
    assert_eq!(
        reports[0].departed_actors,
        actors(&["actor-ada", "actor-cy"])
    );
    // Ada does not read what Bo sends now: the line is what tells him.
    let wire = bo.encrypt(G, b"meet at 7").unwrap();
    assert!(!opens(&mut ada, &wire, b"meet at 7"));
}

/// A client whose credential `keys` issued and which trusts only `keys`: a
/// launch at which the server publishes only that kid.
fn client_trusting(
    keys: &TestIssuer,
    tag: u8,
    actor: &str,
    device: &str,
    storage: PeachyStorage,
) -> Client {
    let seed = device_seed(tag);
    let (_, public) = device_key_pair(&seed);
    let token = keys
        .issue(actor, device, &public, NOW - HOUR, NOW + 30 * DAY)
        .unwrap();
    let mut config = ClientConfig::new(token, seed, keys.trusted_keys().unwrap())
        .with_storage(storage)
        .with_own_account_identity(Some(support::held_identity(actor)));
    config.clock = Some(Box::new(TestClock));
    Client::new(config).unwrap()
}
