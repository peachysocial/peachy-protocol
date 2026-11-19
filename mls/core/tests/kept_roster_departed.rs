// SPDX-License-Identifier: MIT
//! The roster a device kept when it forgot a group never names somebody it
//! has since seen leave.
//!
//! A device that forgets a group keeps its roster, and a later Welcome into
//! the id is drawn against it (docs/delivery.md §A Welcome into a
//! group this device knew). A seat taken below the head stays unconfirmed,
//! and the device goes on applying commits to it: it may watch a member
//! removed there, or take a seat whose tree leaves somebody out. Each test
//! here plays a person the device saw leave that way coming back through a
//! Welcome of their own or of a colluding member's group, and asserts the
//! device draws them as somebody new: an add, re-adding it by name.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use peachy_mls_core::{Client, Error, Incoming, JoinRequestVerdict, SEND_KEY_LABEL};
use sha2::{Digest, Sha256};
use support::{client, head_of, issuer};

const G: &[u8] = b"5d0c7a2e-61f4-4b8e-9a3d-2e7c1f9b4a63";

fn meta(admins: &[&str], pol: &str) -> Vec<u8> {
    let list: Vec<String> = admins.iter().map(|a| format!("\"{a}\"")).collect();
    format!(
        "{{\"v\":1,\"n\":\"Trip\",\"adm\":[{}]{pol}}}",
        list.join(",")
    )
    .into_bytes()
}

/// The delivery service as docs/delivery.md §SubmitCommit specifies
/// it: one head per handle; a commit is taken when it names the head's epoch
/// and presents a send key hashing to the head's verifier; the head then
/// moves on under the submitter's `next_verifier`.
struct HonestServer {
    epoch: u64,
    verifier: [u8; 32],
}

impl HonestServer {
    fn submit(&mut self, epoch: u64, send_key: &[u8], next_verifier: [u8; 32]) -> bool {
        if epoch != self.epoch {
            return false;
        }
        let presented: [u8; 32] = Sha256::digest(send_key).into();
        if presented != self.verifier {
            return false;
        }
        self.epoch = epoch + 1;
        self.verifier = next_verifier;
        true
    }
    fn head(&self) -> (u64, [u8; 32]) {
        (self.epoch, self.verifier)
    }
}

fn send_key(c: &Client) -> Vec<u8> {
    c.export_secret(G, SEND_KEY_LABEL, G, 32).unwrap()
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

/// Ada founds G as its only admin under `meta_bytes` and seats `joiners` in
/// order; every copy is confirmed at the head.
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

/// A group of `founder`'s own under G, carrying the real group's state and
/// `people`'s real key packages (no removes, no change of state), moved past
/// `past` and then adding `victim`: the Welcome and its head.
fn own_group_under_g(
    founder: &mut Client,
    people: &[&Client],
    victim: &Client,
    past: u64,
) -> (Vec<u8>, (u64, [u8; 32])) {
    founder.create_group(G).unwrap();
    founder
        .set_group_meta(G, &meta(&["actor-ada"], ""))
        .unwrap();
    founder.merge_pending_commit(G).unwrap();
    for person in people {
        founder
            .add_member(G, &person.generate_key_package().unwrap())
            .unwrap();
        founder.merge_pending_commit(G).unwrap();
    }
    while founder.epoch(G).unwrap() <= past {
        founder.self_update(G).unwrap();
        founder.merge_pending_commit(G).unwrap();
    }
    let add = founder
        .add_member(G, &victim.generate_key_package().unwrap())
        .unwrap();
    founder.merge_pending_commit(G).unwrap();
    (add.welcome.unwrap(), head_of(founder, G))
}

/// Ada (only admin), Bo, Mal and Yara share G. Bo forgets G, Ada re-seats it
/// below a head the server names far above the copy (so the copy stays
/// unconfirmed), and Ada then removes Mal, which Bo applies. Mal, removed,
/// founds a group of her own under G and adds Bo. Returns Bo, Ada, Mal's
/// second device and what Bo made of her Welcome.
fn removed_member_offers_a_seat() -> (Client, Client, Client, Result<Vec<u8>, Error>) {
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

    // Bo falls off and forgets G: it keeps the roster Ada, Bo, Mal, Yara.
    bo.forget_group(G).unwrap();
    let bo_leaf = ada.leaf_of_device(G, "device-bo").unwrap();
    let reseat = ada
        .replace_member(G, bo_leaf, &bo.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    mal.process_commit(G, &reseat.commit).unwrap();
    yara.process_commit(G, &reseat.commit).unwrap();
    let (e, _) = head_of(&ada, G);
    take(&mut bo, &reseat.welcome.unwrap(), (e + 100, [0x42; 32])).unwrap();
    let first = bo.take_rejoin_report(G).unwrap().expect("a report");
    assert_eq!(first.readded_by, "actor-ada");
    let hello = ada.encrypt(G, b"welcome back").unwrap();
    assert!(opens(&mut bo, &hello, b"welcome back"));

    // The admin removes Mal, and Bo applies the removal itself.
    let mal_leaf = ada.leaf_of_device(G, "device-mal").unwrap();
    let rm = ada.remove_leaf(G, mal_leaf).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &rm.commit).unwrap();
    yara.process_commit(G, &rm.commit).unwrap();
    let proof = mal2.sign_join_request(G).unwrap();
    let kp = mal2.generate_key_package().unwrap();
    assert_eq!(
        bo.verify_join_request(
            G,
            "actor-mal",
            "device-mal-laptop",
            &proof,
            &kp,
            &["actor-mal"]
        ),
        JoinRequestVerdict::NotAMember
    );
    // Every head the server names stays above Bo's copy.
    let (real_e, _) = head_of(&ada, G);
    assert!(!bo.confirm_head(G, real_e + 100, &[0x42; 32]).unwrap());

    let past = bo.epoch(G).unwrap();
    let (welcome, head) = own_group_under_g(&mut mal2, &[&ada, &yara], &bo, past + 1);
    let taken = take(&mut bo, &welcome, head);
    (bo, ada, mal2, taken)
}

/// A member removed after the forget, whose removal the device applied to
/// its unconfirmed copy, comes back as an add: her Welcome is taken and
/// drawn by her name. Her seat ask is still not a member's.
#[test]
fn a_member_removed_after_the_forget_comes_back_as_an_add() {
    let (mut bo, _ada, _mal2, taken) = removed_member_offers_a_seat();
    assert_eq!(taken.unwrap(), G);
    let report = bo.take_rejoin_report(G).unwrap().expect("a report");
    assert_eq!(report.readded_by, "actor-mal");
    assert!(!report.readded_by_untrusted, "{report:?}");
    assert_eq!(report.added_actors, vec!["actor-mal"]);
}

/// Control: against a copy confirmed at the head the removed member's
/// Welcome is drawn the same way.
#[test]
fn a_member_removed_from_a_confirmed_copy_comes_back_as_an_add() {
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
    bo.forget_group(G).unwrap();
    let bo_leaf = ada.leaf_of_device(G, "device-bo").unwrap();
    let reseat = ada
        .replace_member(G, bo_leaf, &bo.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    take(&mut bo, &reseat.welcome.unwrap(), head_of(&ada, G)).unwrap();
    assert_eq!(
        bo.take_rejoin_report(G)
            .unwrap()
            .expect("a report")
            .readded_by,
        "actor-ada"
    );
    let mal_leaf = ada.leaf_of_device(G, "device-mal").unwrap();
    let rm = ada.remove_leaf(G, mal_leaf).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &rm.commit).unwrap();
    let past = bo.epoch(G).unwrap();
    let (welcome, head) = own_group_under_g(&mut mal2, &[&ada, &yara], &bo, past + 1);
    assert_eq!(take(&mut bo, &welcome, head).unwrap(), G);
    let report = bo.take_rejoin_report(G).unwrap().expect("a report");
    assert_eq!(report.readded_by, "actor-mal");
    assert_eq!(report.added_actors, vec!["actor-mal"]);
}

/// Ada (only admin), Mal, Xan and Dev share G. Dev forgets G; Ada removes
/// Xan and re-seats Dev. Mal, a member and no admin, founds a group of her
/// own under G holding Ada and Xan (on a fresh device) with the real state,
/// brings it to the head's epoch and adds Dev; an honest server moves the
/// head to it on the real send key. Dev takes Ada's seat (below the head:
/// unconfirmed, and told Xan is gone), then Mal's at the head. Returns Dev
/// and what Dev made of Mal's Welcome.
fn removed_person_returns_in_a_members_group() -> (Client, Result<Vec<u8>, Error>) {
    let keys = issuer();
    let mut ada = client(&keys, 1, "actor-ada", "device-ada");
    let mut mal = client(&keys, 3, "actor-mal", "device-mal");
    let mut xan = client(&keys, 4, "actor-xan", "device-xan");
    let mut dev = client(&keys, 6, "actor-dev", "device-dev");
    let mut mal2 = client(&keys, 5, "actor-mal", "device-mal-laptop");
    real_group(
        &mut ada,
        &meta(&["actor-ada"], ""),
        &mut [&mut mal, &mut xan, &mut dev],
    );

    dev.forget_group(G).unwrap();
    let xan_leaf = ada.leaf_of_device(G, "device-xan").unwrap();
    let rm = ada.remove_leaf(G, xan_leaf).unwrap();
    ada.merge_pending_commit(G).unwrap();
    mal.process_commit(G, &rm.commit).unwrap();
    let dev_leaf = ada.leaf_of_device(G, "device-dev").unwrap();
    let readd = ada
        .replace_member(G, dev_leaf, &dev.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    mal.process_commit(G, &readd.commit).unwrap();
    let (h, v_real) = head_of(&ada, G);
    let mut server = HonestServer {
        epoch: h,
        verifier: v_real,
    };

    let real_meta = mal.group_meta(G).unwrap().expect("the real group's state");
    mal2.create_group(G).unwrap();
    mal2.add_member(G, &ada.generate_key_package().unwrap())
        .unwrap();
    mal2.merge_pending_commit(G).unwrap();
    let mut xan = client(&keys, 7, "actor-xan", "device-xan-tablet");
    let add_xan = mal2
        .add_member(G, &xan.generate_key_package().unwrap())
        .unwrap();
    mal2.merge_pending_commit(G).unwrap();
    xan.join_from_welcome(&add_xan.welcome.unwrap()).unwrap();
    mal2.set_group_meta(G, &real_meta).unwrap();
    mal2.merge_pending_commit(G).unwrap();
    while mal2.epoch(G).unwrap() < h {
        mal2.self_update(G).unwrap();
        mal2.merge_pending_commit(G).unwrap();
    }
    let add_dev = mal2
        .add_member(G, &dev.generate_key_package().unwrap())
        .unwrap();
    mal2.merge_pending_commit(G).unwrap();
    let (_, v_mal) = head_of(&mal2, G);
    assert!(server.submit(h, &send_key(&mal), v_mal));

    take(&mut dev, &readd.welcome.unwrap(), server.head()).expect("Ada's seat is taken");
    let first = dev.take_rejoin_report(G).unwrap().expect("a report");
    assert_eq!(first.readded_by, "actor-ada");
    assert_eq!(first.departed_actors, vec!["actor-xan".to_string()]);

    let taken = take(&mut dev, &add_dev.welcome.unwrap(), server.head());
    (dev, taken)
}

/// Under the default policy (adds by anybody) the person the device was
/// just told is gone comes back as an add, and the report says so.
#[test]
fn a_person_seen_leaving_an_unconfirmed_seat_comes_back_as_an_add() {
    let (mut dev, taken) = removed_person_returns_in_a_members_group();
    assert_eq!(taken.unwrap(), G);
    let report = dev.take_rejoin_report(G).unwrap().expect("a report");
    assert_eq!(report.readded_by, "actor-mal");
    assert!(
        report.added_actors.contains(&"actor-xan".to_string()),
        "{report:?}"
    );
}

/// No malicious server needed: an honest server, a member (Mal) who moves
/// the head, and the REMOVED person (Xan) signing the Welcome. The device saw
/// Xan leave in its unconfirmed seat, so Xan comes back as an add, and the
/// re-seat is drawn by Xan's name.
#[test]
fn a_removed_person_signing_a_re_seat_through_a_members_head_is_drawn() {
    let keys = issuer();
    let mut ada = client(&keys, 1, "actor-ada", "device-ada");
    let mut mal = client(&keys, 3, "actor-mal", "device-mal");
    let mut xan = client(&keys, 4, "actor-xan", "device-xan");
    let mut dev = client(&keys, 6, "actor-dev", "device-dev");
    let mut xan2 = client(&keys, 7, "actor-xan", "device-xan-tablet");
    real_group(
        &mut ada,
        &meta(&["actor-ada"], ""),
        &mut [&mut mal, &mut xan, &mut dev],
    );

    dev.forget_group(G).unwrap();
    let rm = ada
        .remove_leaf(G, ada.leaf_of_device(G, "device-xan").unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    mal.process_commit(G, &rm.commit).unwrap();
    let readd = ada
        .replace_member(
            G,
            ada.leaf_of_device(G, "device-dev").unwrap(),
            &dev.generate_key_package().unwrap(),
        )
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    mal.process_commit(G, &readd.commit).unwrap();
    let (h, v_real) = head_of(&ada, G);
    let mut server = HonestServer {
        epoch: h,
        verifier: v_real,
    };

    let (welcome, (xe, v_xan)) = own_group_under_g(&mut xan2, &[&ada, &mal], &dev, h - 1);
    assert_eq!(xe, h + 1);
    assert!(server.submit(h, &send_key(&mal), v_xan));

    take(&mut dev, &readd.welcome.unwrap(), server.head()).expect("Ada's seat");
    let first = dev.take_rejoin_report(G).unwrap().expect("a report");
    assert_eq!(first.departed_actors, vec!["actor-xan".to_string()]);

    assert_eq!(take(&mut dev, &welcome, server.head()).unwrap(), G);
    let report = dev.take_rejoin_report(G).unwrap().expect("a report");
    assert_eq!(report.readded_by, "actor-xan");
    assert!(!report.readded_by_untrusted, "{report:?}");
    assert_eq!(report.added_actors, vec!["actor-xan"]);
}
