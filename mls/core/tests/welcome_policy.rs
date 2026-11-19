// SPDX-License-Identifier: MIT
//! A Welcome that replaces or restores a group this device knew is told in
//! full: who re-added the device, who is gone, who was added, whether the
//! admins changed (docs/delivery.md §A Welcome into a group this
//! device knew).
//!
//! A member's own client can found a group of her own under the real
//! group's id and, holding the real send key, have an honest delivery
//! service move the head to it (`SubmitCommit` takes `next_verifier` on the
//! submitter's word). The device cannot tell her group from the real one by
//! anything it held, so it is never refused for that; each test here plays
//! one route to it and asserts the report says everything it changed.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use peachy_mls_core::{Client, ClientConfig, DenyReason, Error, PeachyStorage, SEND_KEY_LABEL};
use sha2::{Digest, Sha256};
use support::{client, device_seed, head_of, issuer, TestClock, DAY, HOUR, NOW};

const G: &[u8] = b"5d0c7a2e-61f4-4b8e-9a3d-2e7c1f9b4a60";

fn meta(admins: &[&str]) -> Vec<u8> {
    let list: Vec<String> = admins.iter().map(|a| format!("\"{a}\"")).collect();
    format!("{{\"v\":1,\"n\":\"Trip\",\"adm\":[{}]}}", list.join(",")).into_bytes()
}

/// The delivery service as docs/delivery.md §SubmitCommit steps 4
/// and 5 specify it: one head per handle; a commit is taken when it names the
/// head's epoch and presents a send key hashing to the head's verifier; the
/// head then moves on under the submitter's `next_verifier`.
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
    let (group, _) = c.welcome_group(welcome)?;
    assert_eq!(group, G);
    c.join_from_welcome_at_head(welcome, head.0, &head.1)
}

/// Ada founds G as its only admin and seats `joiners` in order; every copy
/// is confirmed at the head.
fn real_group(ada: &mut Client, joiners: &mut [&mut Client]) {
    ada.create_group(G).unwrap();
    ada.set_group_meta(G, &meta(&["actor-ada"])).unwrap();
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

/// Mallory's own group under G, founded on a second device of her account
/// with herself as the only admin, brought to epoch `h` and then adding
/// `victim`: the commit, its Welcome, and the verifier it produces.
fn mallorys_group(mal2: &mut Client, h: u64, victim: &Client) -> (Vec<u8>, [u8; 32]) {
    mal2.create_group(G).unwrap();
    mal2.set_group_meta(G, &meta(&["actor-mal"])).unwrap();
    mal2.merge_pending_commit(G).unwrap();
    while mal2.epoch(G).unwrap() < h {
        mal2.self_update(G).unwrap();
        mal2.merge_pending_commit(G).unwrap();
    }
    let add = mal2
        .add_member(G, &victim.generate_key_package().unwrap())
        .unwrap();
    mal2.merge_pending_commit(G).unwrap();
    let (_, verifier) = head_of(mal2, G);
    (add.welcome.unwrap(), verifier)
}

/// The stranding route: Mallory commits a removal the policy forbids. Every
/// honest device refuses it and, stranded, forgets the group and asks back
/// in; only Mallory can answer. Her re-seat is taken, and drawn as hers
/// with Yara gone.
#[test]
fn a_forbidden_commit_then_a_re_seat_is_told() {
    let keys = issuer();
    let mut ada = client(&keys, 1, "actor-ada", "device-ada");
    let mut bo = client(&keys, 2, "actor-bo", "device-bo");
    let mut mal = client(&keys, 3, "actor-mal", "device-mal");
    let mut yara = client(&keys, 4, "actor-yara", "device-yara");
    real_group(&mut ada, &mut [&mut bo, &mut mal, &mut yara]);

    let yara_leaf = mal.leaf_of_device(G, "device-yara").unwrap();
    let forged = mal.forge_remove_leaf(G, yara_leaf).unwrap();
    mal.merge_pending_commit(G).unwrap();
    let refused = bo.process_commit(G, &forged.commit);
    assert!(
        matches!(
            refused,
            Err(Error::PolicyRefused(DenyReason::RemoveNeedsAdmin))
        ),
        "{refused:?}"
    );
    assert!(bo.commit_strands(G, &forged.commit).unwrap());
    bo.forget_group(G).unwrap();

    // Mallory's device answers Bo's seat ask the way every device does:
    // replacing the leaf Bo left behind.
    let bo_leaf = mal.leaf_of_device(G, "device-bo").unwrap();
    let add_bo = mal
        .replace_member(G, bo_leaf, &bo.generate_key_package().unwrap())
        .unwrap();
    mal.merge_pending_commit(G).unwrap();
    assert_eq!(
        take(&mut bo, &add_bo.welcome.unwrap(), head_of(&mal, G)).unwrap(),
        G
    );
    let report = bo.take_rejoin_report(G).unwrap().expect("a report");
    assert_eq!(report.readded_by, "actor-mal");
    assert!(!report.readded_by_untrusted);
    assert_eq!(report.departed_actors, vec!["actor-yara"]);
}

/// The control: an admin's re-seat that leaves out a member she removed
/// while this device was away is taken, and the report names who is gone
/// and that the admins changed.
#[test]
fn an_admins_re_seat_is_taken_and_says_who_left() {
    let keys = issuer();
    let mut ada = client(&keys, 1, "actor-ada", "device-ada");
    let mut bo = client(&keys, 2, "actor-bo", "device-bo");
    let mut cy = client(&keys, 3, "actor-cy", "device-cy");
    let mut yara = client(&keys, 4, "actor-yara", "device-yara");
    real_group(&mut ada, &mut [&mut bo, &mut cy, &mut yara]);

    // Bo falls off and forgets the group; meanwhile Ada removes Yara and
    // makes Cy an admin.
    bo.forget_group(G).unwrap();
    let yara_leaf = ada.leaf_of_device(G, "device-yara").unwrap();
    ada.remove_leaf(G, yara_leaf).unwrap();
    ada.merge_pending_commit(G).unwrap();
    ada.set_group_meta(G, &meta(&["actor-ada", "actor-cy"]))
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    let bo_leaf = ada.leaf_of_device(G, "device-bo").unwrap();
    ada.remove_leaf(G, bo_leaf).unwrap();
    ada.merge_pending_commit(G).unwrap();
    let add_bo = ada
        .add_member(G, &bo.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();

    assert_eq!(
        take(&mut bo, &add_bo.welcome.unwrap(), head_of(&ada, G)).unwrap(),
        G
    );
    let report = bo.take_rejoin_report(G).unwrap().expect("a report");
    assert_eq!(report.readded_by, "actor-ada");
    assert!(!report.readded_by_untrusted);
    assert_eq!(report.departed_actors, vec!["actor-yara"]);
    assert!(report.admins_changed);
    assert!(report.added_actors.is_empty());
}

/// Mallory's group is taken, and the report says all of it: who is gone,
/// and that the admins changed.
#[test]
fn a_members_own_group_is_told_in_full() {
    let keys = issuer();
    let mut ada = client(&keys, 1, "actor-ada", "device-ada");
    let mut bo = client(&keys, 2, "actor-bo", "device-bo");
    let mut mal = client(&keys, 3, "actor-mal", "device-mal");
    let mut yara = client(&keys, 4, "actor-yara", "device-yara");
    let mut mal2 = client(&keys, 5, "actor-mal", "device-mal-laptop");
    real_group(&mut ada, &mut [&mut bo, &mut mal, &mut yara]);
    let (h, _) = head_of(&ada, G);
    let (bo_welcome, v_mal) = mallorys_group(&mut mal2, h, &bo);

    assert_eq!(take(&mut bo, &bo_welcome, (h + 1, v_mal)).unwrap(), G);
    let report = bo.take_rejoin_report(G).unwrap().expect("a report");
    assert_eq!(report.readded_by, "actor-mal");
    assert!(!report.readded_by_untrusted, "drawn by her name");
    assert_eq!(report.departed_actors, vec!["actor-ada", "actor-yara"]);
    assert!(report.admins_changed);
}

fn holds_device(c: &Client, device: &str) -> bool {
    c.leaf_of_device(G, device).is_ok()
}

/// Ada, the admin, removes Yara and later adds her back: two ordinary
/// commits every member applies, and a confirmed head after them.
fn yara_leaves_and_comes_back(
    ada: &mut Client,
    bo: &mut Client,
    mal: &mut Client,
    yara: &mut Client,
) {
    let leaf = ada.leaf_of_device(G, "device-yara").unwrap();
    let removal = ada.remove_leaf(G, leaf).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &removal.commit).unwrap();
    mal.process_commit(G, &removal.commit).unwrap();
    let readd = ada
        .add_member(G, &yara.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &readd.commit).unwrap();
    mal.process_commit(G, &readd.commit).unwrap();
    take(yara, &readd.welcome.unwrap(), head_of(ada, G)).unwrap();
    let (h, v) = head_of(ada, G);
    assert!(holds_device(bo, "device-yara"), "Yara is back in Bo's copy");
    for c in [bo, mal, yara] {
        assert!(c.confirm_head(G, h, &v).unwrap());
    }
}

/// Mallory's group under G on her second device: the real group's state
/// byte for byte (Ada the only admin), Ada seated from a fetched key
/// package, Yara left out, brought to epoch `h`, then Bo added.
fn mallorys_group_without_yara(
    mal2: &mut Client,
    h: u64,
    ada: &Client,
    bo: &Client,
) -> (Vec<u8>, [u8; 32]) {
    mal2.create_group(G).unwrap();
    mal2.set_group_meta(G, &meta(&["actor-ada"])).unwrap();
    mal2.merge_pending_commit(G).unwrap();
    mal2.add_member(G, &ada.generate_key_package().unwrap())
        .unwrap();
    mal2.merge_pending_commit(G).unwrap();
    while mal2.epoch(G).unwrap() < h {
        mal2.self_update(G).unwrap();
        mal2.merge_pending_commit(G).unwrap();
    }
    let add = mal2
        .add_member(G, &bo.generate_key_package().unwrap())
        .unwrap();
    mal2.merge_pending_commit(G).unwrap();
    let (_, verifier) = head_of(mal2, G);
    (add.welcome.unwrap(), verifier)
}

/// A person who left and was added back is a member like any other: a
/// member's group that leaves her out is taken, and the report says Yara is
/// gone. Her earlier exit, cleared when she came back, hides nothing.
#[test]
fn a_person_added_back_and_left_out_is_told() {
    let keys = issuer();
    let mut ada = client(&keys, 1, "actor-ada", "device-ada");
    let mut bo = client(&keys, 2, "actor-bo", "device-bo");
    let mut mal = client(&keys, 3, "actor-mal", "device-mal");
    let mut yara = client(&keys, 4, "actor-yara", "device-yara");
    let mut mal2 = client(&keys, 5, "actor-mal", "device-mal-laptop");
    real_group(&mut ada, &mut [&mut bo, &mut mal, &mut yara]);
    yara_leaves_and_comes_back(&mut ada, &mut bo, &mut mal, &mut yara);
    let (h, v_real) = head_of(&ada, G);
    let mut server = HonestServer {
        epoch: h,
        verifier: v_real,
    };
    let (bo_welcome, v_mal) = mallorys_group_without_yara(&mut mal2, h, &ada, &bo);
    assert!(server.submit(h, &send_key(&mal), v_mal));

    assert_eq!(take(&mut bo, &bo_welcome, server.head()).unwrap(), G);
    assert!(!holds_device(&bo, "device-yara"));
    let report = bo.take_rejoin_report(G).unwrap().expect("a report");
    assert_eq!(report.readded_by, "actor-mal");
    assert_eq!(report.departed_actors, vec!["actor-yara"]);
}

/// A device of `actor` the delivery service certified under an account
/// identity key of its own making, not the person's.
fn server_made_device(tag: u8, actor: &str, device: &str, fake_account: &[u8; 32]) -> Client {
    let keys = issuer();
    let seed = device_seed(tag);
    let (_, public) = peachy_mls_core::issuer::device_key_pair(&seed);
    let token = keys
        .issue_for_account(
            actor,
            device,
            &public,
            Some(fake_account),
            NOW - HOUR,
            NOW + 30 * DAY,
        )
        .unwrap();
    // The server's device holds the key the server made.
    let mut config = ClientConfig::new(token, seed, keys.trusted_keys().unwrap())
        .with_storage(PeachyStorage::in_memory())
        .with_own_account_identity(Some(
            peachy_mls_core::account_identity_public_key(fake_account).unwrap(),
        ));
    config.clock = Some(Box::new(TestClock));
    Client::new(config).unwrap()
}

/// A person is matched by actor AND account key. A member's group whose
/// "Ada" is a device the server certified under another account key has
/// removed the real Ada (an admin) and added somebody else under her name:
/// told in full, as one person gone and another added.
#[test]
fn a_person_under_another_account_key_is_not_the_same_person() {
    {
        let keys = issuer();
        let mut ada = client(&keys, 1, "actor-ada", "device-ada");
        let mut bo = client(&keys, 2, "actor-bo", "device-bo");
        let mut mal = client(&keys, 3, "actor-mal", "device-mal");
        let mut yara = client(&keys, 4, "actor-yara", "device-yara");
        let mut mal2 = client(&keys, 5, "actor-mal", "device-mal-laptop");
        real_group(&mut ada, &mut [&mut bo, &mut mal, &mut yara]);
        let mut fake_ada = server_made_device(6, "actor-ada", "device-ada-srv", &[0x66; 32]);
        let fake_kp = fake_ada.generate_key_package().unwrap();

        let (h, v_real) = head_of(&ada, G);
        let mut server = HonestServer {
            epoch: h,
            verifier: v_real,
        };
        mal2.create_group(G).unwrap();
        mal2.set_group_meta(G, &meta(&["actor-ada"])).unwrap();
        mal2.merge_pending_commit(G).unwrap();
        let add_fake = mal2.add_member(G, &fake_kp).unwrap();
        mal2.merge_pending_commit(G).unwrap();
        fake_ada
            .join_from_welcome(&add_fake.welcome.unwrap())
            .unwrap();
        mal2.add_member(G, &yara.generate_key_package().unwrap())
            .unwrap();
        mal2.merge_pending_commit(G).unwrap();
        while mal2.epoch(G).unwrap() < h {
            mal2.self_update(G).unwrap();
            mal2.merge_pending_commit(G).unwrap();
        }
        let add_bo = mal2
            .add_member(G, &bo.generate_key_package().unwrap())
            .unwrap();
        mal2.merge_pending_commit(G).unwrap();
        let (_, v_mal) = head_of(&mal2, G);
        assert!(server.submit(h, &send_key(&mal), v_mal));

        let taken = take(&mut bo, &add_bo.welcome.unwrap(), server.head());
        assert_eq!(taken.unwrap(), G);
        let report = bo.take_rejoin_report(G).unwrap().expect("a report");
        assert_eq!(report.readded_by, "actor-mal");
        assert_eq!(report.departed_actors, vec!["actor-ada"]);
        assert_eq!(report.added_actors, vec!["actor-ada"]);
    }
}

/// Bo, having forgotten the group, is seated below the head in a member's
/// fork that adds Xav (adds are anybody's): `real_head` is the head the
/// seat was taken against.
fn bo_seated_in_a_fork(
    ada: &mut Client,
    bo: &mut Client,
    mal: &mut Client,
    yara: &mut Client,
    mal2: &mut Client,
    xav: &Client,
) -> (u64, [u8; 32]) {
    real_group(ada, &mut [&mut *bo, &mut *mal, &mut *yara]);
    let (h0, _) = head_of(ada, G);
    bo.forget_group(G).unwrap();
    for _ in 0..3 {
        let up = ada.self_update(G).unwrap();
        ada.merge_pending_commit(G).unwrap();
        mal.process_commit(G, &up.commit).unwrap();
        yara.process_commit(G, &up.commit).unwrap();
    }
    let real_head = head_of(ada, G);
    mal2.create_group(G).unwrap();
    mal2.set_group_meta(G, &meta(&["actor-ada"])).unwrap();
    mal2.merge_pending_commit(G).unwrap();
    for kp in [
        ada.generate_key_package().unwrap(),
        yara.generate_key_package().unwrap(),
        xav.generate_key_package().unwrap(),
    ] {
        mal2.add_member(G, &kp).unwrap();
        mal2.merge_pending_commit(G).unwrap();
    }
    while mal2.epoch(G).unwrap() < h0 {
        mal2.self_update(G).unwrap();
        mal2.merge_pending_commit(G).unwrap();
    }
    let add_bo = mal2
        .add_member(G, &bo.generate_key_package().unwrap())
        .unwrap();
    mal2.merge_pending_commit(G).unwrap();
    assert!(mal2.epoch(G).unwrap() < real_head.0);
    assert_eq!(take(bo, &add_bo.welcome.unwrap(), real_head).unwrap(), G);
    let report = bo.take_rejoin_report(G).unwrap().expect("a report");
    assert_eq!(report.added_actors, vec!["actor-xav"]);
    real_head
}

/// The real group's re-seat by a plain member, over a fork a member seated
/// the device in below the head, is taken, with the fork's Xav reported
/// gone.
#[test]
fn an_unvouched_copys_roster_refuses_nobody() {
    let keys = issuer();
    let mut ada = client(&keys, 1, "actor-ada", "device-ada");
    let mut bo = client(&keys, 2, "actor-bo", "device-bo");
    let mut mal = client(&keys, 3, "actor-mal", "device-mal");
    let mut yara = client(&keys, 4, "actor-yara", "device-yara");
    let mut mal2 = client(&keys, 5, "actor-mal", "device-mal-laptop");
    let xav = client(&keys, 7, "actor-xav", "device-xav");
    bo_seated_in_a_fork(&mut ada, &mut bo, &mut mal, &mut yara, &mut mal2, &xav);

    let bo_leaf = yara.leaf_of_device(G, "device-bo").unwrap();
    let reseat = yara
        .replace_member(G, bo_leaf, &bo.generate_key_package().unwrap())
        .unwrap();
    yara.merge_pending_commit(G).unwrap();
    assert_eq!(
        take(&mut bo, &reseat.welcome.unwrap(), head_of(&yara, G)).unwrap(),
        G
    );
    assert_eq!(
        head_of(&bo, G),
        head_of(&yara, G),
        "Bo is back in the real group"
    );
    let report = bo.take_rejoin_report(G).unwrap().expect("a report");
    assert_eq!(report.readded_by, "actor-yara");
    assert_eq!(report.departed_actors, vec!["actor-xav"]);
}

/// The report reads people, not devices, so a member's group that
/// keeps a person through one device and leaves out another of theirs draws
/// no removal. The dropped device's seat ask still holds at the
/// re-seated device, since its person holds a leaf there, so it is back in
/// once it asks.
#[test]
fn a_device_dropped_from_a_kept_person_asks_back_in() {
    let keys = issuer();
    let mut ada = client(&keys, 1, "actor-ada", "device-ada");
    let mut bo = client(&keys, 2, "actor-bo", "device-bo");
    let mut mal = client(&keys, 3, "actor-mal", "device-mal");
    let mut yara = client(&keys, 4, "actor-yara", "device-yara");
    let mut yara2 = client(&keys, 6, "actor-yara", "device-yara-laptop");
    let mut mal2 = client(&keys, 5, "actor-mal", "device-mal-laptop");
    real_group(&mut ada, &mut [&mut bo, &mut mal, &mut yara, &mut yara2]);
    let (h, v_real) = head_of(&ada, G);
    let mut server = HonestServer {
        epoch: h,
        verifier: v_real,
    };
    mal2.create_group(G).unwrap();
    mal2.set_group_meta(G, &meta(&["actor-ada"])).unwrap();
    mal2.merge_pending_commit(G).unwrap();
    for kp in [
        ada.generate_key_package().unwrap(),
        yara.generate_key_package().unwrap(),
    ] {
        mal2.add_member(G, &kp).unwrap();
        mal2.merge_pending_commit(G).unwrap();
    }
    while mal2.epoch(G).unwrap() < h {
        mal2.self_update(G).unwrap();
        mal2.merge_pending_commit(G).unwrap();
    }
    let add_bo = mal2
        .add_member(G, &bo.generate_key_package().unwrap())
        .unwrap();
    mal2.merge_pending_commit(G).unwrap();
    let (_, v_mal) = head_of(&mal2, G);
    assert!(server.submit(h, &send_key(&mal), v_mal));
    assert_eq!(
        take(&mut bo, &add_bo.welcome.unwrap(), server.head()).unwrap(),
        G
    );
    assert!(!holds_device(&bo, "device-yara-laptop"));
    let ask = yara2.sign_join_request(G).unwrap();
    let kp = yara2.generate_key_package().unwrap();
    assert!(bo
        .verify_join_request(G, "actor-yara", "device-yara-laptop", &ask, &kp, &[])
        .is_accepted());
}
