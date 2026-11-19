// SPDX-License-Identifier: MIT
//! Only the approval chain vouches for a device of the person's own account
//! (`own_devices.rs` §Which keys this device trusts).
//!
//! The account key never rotates when a device is removed, so a removed
//! device that kept it can certify a FRESH key under a FRESH id. Nobody ever
//! saw that key, so nobody forgot it. Once such a device sits in a tree this
//! device joins by a Welcome (a group it founds itself, or one an honest
//! contact starts with every device the server lists), it must still be:
//!
//! - refused the account's history (`check_own_device_key`);
//! - refused a seat, and unable to vouch for further devices
//!   (`check_own_device_approval`);
//! - marked untrusted when it re-adds this device into a group it knew.
//!
//! And the person's honest devices keep working: the first device, a normal
//! link, "I don't have my other devices", PIN restore, with no false
//! new-device notice. The cost is the documented one: a sibling with no
//! chain evidence here gets no history from here.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use peachy_mls_core::issuer::{device_key_pair, TestIssuer};
use peachy_mls_core::{
    generate_account_key, sign_device_approval, Client, ClientConfig, Error, FixedClock, Incoming,
    OwnDeviceVerdict, PeachyStorage, SEND_KEY_LABEL,
};
use sha2::{Digest, Sha256};
use support::{client, device_seed, issuer, past_the_mark, DAY, HOUR, NOW};

const G: &[u8] = b"66666666-6666-4666-8666-666666666666";
const F: &[u8] = b"88888888-8888-4888-8888-888888888888";
const H: &[u8] = b"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

fn public(tag: u8) -> [u8; 32] {
    device_key_pair(&device_seed(tag)).1
}

/// A device whose certificate is signed with `account`, as the server issues
/// one for any device that presents a self-certificate under that key.
fn certified(server: &TestIssuer, tag: u8, actor: &str, device: &str, account: &[u8]) -> Client {
    let seed = device_seed(tag);
    let (_, public) = device_key_pair(&seed);
    let token = server
        .issue_for_account(
            actor,
            device,
            &public,
            Some(account),
            NOW - HOUR,
            NOW + 30 * DAY,
        )
        .expect("mint");
    let mut config = ClientConfig::new(token, seed, server.trusted_keys().expect("keys"))
        .with_storage(PeachyStorage::in_memory())
        .with_own_account_identity(Some(
            peachy_mls_core::account_identity_public_key(account).expect("derive"),
        ));
    config.clock = Some(Box::new(FixedClock(NOW)));
    Client::new(config).expect("client")
}

fn add(adder: &mut Client, joiner: &mut Client, group: &[u8]) -> Vec<u8> {
    let key_package = joiner.generate_key_package().expect("key package");
    let bundle = adder.add_member(group, &key_package).expect("add");
    adder.merge_pending_commit(group).expect("merge");
    // Through the head, as the apps take a Welcome: the adder's commit was
    // the last the delivery service took.
    support::join_at_head(
        joiner,
        &bundle.welcome.expect("welcome"),
        support::head_of(adder, group),
    )
    .expect("join");
    bundle.commit
}

/// An own-device add as a gated client makes it: only on a verdict that
/// seats. Answers the commit.
fn gated_add(
    adder: &mut Client,
    joiner: &mut Client,
    group: &[u8],
    approver: &str,
    approval: &[u8],
) -> Vec<u8> {
    let key_package = joiner.generate_key_package().unwrap();
    let verdict = adder.check_own_device_approval(&key_package, approver, approval);
    assert!(verdict.seats(), "{verdict:?}");
    let bundle = adder.add_member(group, &key_package).unwrap();
    adder.merge_pending_commit(group).unwrap();
    support::join_at_head(
        joiner,
        &bundle.welcome.unwrap(),
        support::head_of(adder, group),
    )
    .unwrap();
    bundle.commit
}

fn reads(sender: &mut Client, reader: &mut Client, group: &[u8], text: &[u8]) -> bool {
    let Ok(wire) = sender.encrypt(group, text) else {
        return false;
    };
    matches!(
        reader.process_message(group, &wire),
        Ok(Incoming::Application { plaintext, .. }) if plaintext == text
    )
}

fn head_of(c: &Client, group: &[u8]) -> (u64, [u8; 32]) {
    let epoch = c.epoch(group).unwrap();
    let verifier: [u8; 32] =
        Sha256::digest(c.export_secret(group, SEND_KEY_LABEL, group, 32).unwrap()).into();
    (epoch, verifier)
}

/// What `mls/fixtures/formats/self-note-trust.json` says a device sends a
/// sibling with own-device verdict `name`.
fn answer_for(name: &str) -> String {
    let table: serde_json::Value =
        serde_json::from_str(include_str!("../../fixtures/formats/self-note-trust.json")).unwrap();
    table["answers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["verdict"] == name)
        .unwrap()["expect"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn no_long_form(leaves: &[String]) -> bool {
    leaves.iter().all(|leaf| !leaf.contains('#'))
}

// ---- A removed device's fresh key, seated by a malicious server ------------

/// Bo's group G holds Ada's laptop and phone. Ada removes the phone on the
/// laptop: the laptop forgets it by id and key and sweeps its leaf.
fn phone_removed() -> (Client, Client, Client) {
    let server = issuer();
    let mut laptop = client(&server, 1, "actor-ada", "device-ada-laptop");
    let mut phone = client(&server, 2, "actor-ada", "device-ada-phone");
    let mut bo = client(&server, 3, "actor-bo", "device-bo");
    bo.create_group(G).unwrap();
    add(&mut bo, &mut laptop, G);
    let c = add(&mut bo, &mut phone, G);
    laptop.process_commit(G, &c).unwrap();
    laptop
        .remember_own_approver("device-ada-phone", &public(2))
        .unwrap();
    assert!(laptop
        .forget_own_device_with_key("device-ada-phone", &public(2))
        .unwrap());
    let leaf = laptop.leaf_of_device(G, "device-ada-phone").unwrap();
    let removal = laptop.remove_leaf(G, leaf).unwrap();
    laptop.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &removal.commit).unwrap();
    phone.process_commit(G, &removal.commit).unwrap();
    (laptop, phone, bo)
}

/// The removed phone's fresh device: a new key under a new id, with Ada's
/// account certificate and a leaf credential the server issued.
fn fresh_device() -> Client {
    client(&issuer(), 9, "actor-ada", "device-ada-new")
}

/// It founds F with the laptop in it: a first join, which nobody judges.
fn found_with(new: &mut Client, laptop: &mut Client) {
    new.create_group(F).unwrap();
    add(new, laptop, F);
}

#[test]
fn founding_a_group_with_this_device_gets_a_fresh_key_no_history() {
    let (mut laptop, _phone, _bo) = phone_removed();
    let mut new = fresh_device();
    assert_eq!(
        laptop.check_own_device_key("device-ada-new", &public(9), "", &[]),
        OwnDeviceVerdict::Unanchored
    );
    found_with(&mut new, &mut laptop);
    let verdict = laptop.check_own_device_key("device-ada-new", &public(9), "", &[]);
    assert_eq!(verdict, OwnDeviceVerdict::Unanchored);
    assert_eq!(answer_for(verdict.name()), "none");
    // Still seen: the notice names it.
    assert!(laptop
        .own_sibling_leaves()
        .unwrap()
        .contains(&"device-ada-new".to_string()));
}

#[test]
fn a_founded_device_is_not_seated_and_vouches_for_nobody() {
    let (mut laptop, _phone, _bo) = phone_removed();
    let mut new = fresh_device();
    found_with(&mut new, &mut laptop);

    let kp = new.generate_key_package().unwrap();
    assert_eq!(
        laptop.check_own_device_approval(&kp, "", &[]),
        OwnDeviceVerdict::Unanchored
    );
    // Added on a verdict that does not seat; that seat makes it no anchor.
    let bundle = laptop.add_member(G, &kp).unwrap();
    laptop.merge_pending_commit(G).unwrap();
    new.join_from_welcome(&bundle.welcome.unwrap()).unwrap();

    let other = client(&issuer(), 10, "actor-ada", "device-ada-other");
    let approval = sign_device_approval(&device_seed(9), "device-ada-other", &public(10)).unwrap();
    assert_eq!(
        laptop.check_own_device_approval(
            &other.generate_key_package().unwrap(),
            "device-ada-new",
            &approval
        ),
        OwnDeviceVerdict::Unanchored
    );
    assert_eq!(
        laptop.check_own_device_key("device-ada-other", &public(10), "device-ada-new", &approval),
        OwnDeviceVerdict::Unanchored
    );
    assert_eq!(
        laptop.check_own_device_key("device-ada-new", &public(9), "", &[]),
        OwnDeviceVerdict::Unanchored
    );
}

/// The impostor under G's id, Welcomed to the laptop, with the server
/// reporting the impostor's head.
fn impostor_contest(laptop: &mut Client, new: &mut Client) -> Result<Vec<u8>, Error> {
    new.create_group(G).unwrap();
    past_the_mark(new, G);
    let w = new
        .add_member(G, &laptop.generate_key_package().unwrap())
        .unwrap();
    new.merge_pending_commit(G).unwrap();
    assert!(matches!(
        laptop.join_from_welcome(&w.welcome.unwrap()),
        Err(Error::AlreadyAMember)
    ));
    let (e, v) = head_of(new, G);
    laptop.join_contested_welcome(e, &v)
}

#[test]
fn a_founded_devices_replace_is_reported_untrusted() {
    let (mut laptop, _phone, _bo) = phone_removed();
    let mut new = fresh_device();
    found_with(&mut new, &mut laptop);
    assert_eq!(impostor_contest(&mut laptop, &mut new).unwrap(), G);
    let report = laptop.take_rejoin_report(G).unwrap().expect("report");
    assert_eq!(report.readded_by_device, "device-ada-new");
    assert!(report.readded_by_untrusted);
}

// ---- The same device, seated by an honest server and contact ---------------

/// The laptop remembers the phone as its approver, then forgets it. The
/// thief kept the account key and certifies a fresh key itself.
fn laptop_and_thief(server: &TestIssuer, account: &[u8]) -> (Client, Client) {
    let mut laptop = certified(server, 1, "actor-ada", "device-ada-laptop", account);
    laptop
        .remember_own_approver("device-ada-phone", &public(2))
        .unwrap();
    assert!(laptop
        .forget_own_device_with_key("device-ada-phone", &public(2))
        .unwrap());
    let thief = certified(server, 9, "actor-ada", "device-ada-new", account);
    (laptop, thief)
}

/// Bo, an honest contact, starts a group with every device the server
/// lists for Ada: the thief's leaf is in the tree before the laptop joins.
#[test]
fn a_contacts_new_group_gets_a_removed_devices_fresh_key_no_history() {
    let server = issuer();
    let ada_key = generate_account_key().unwrap();
    let (mut laptop, mut thief) = laptop_and_thief(&server, &ada_key);
    let mut bo = certified(
        &server,
        3,
        "actor-bo",
        "device-bo",
        &generate_account_key().unwrap(),
    );
    bo.create_group(G).unwrap();
    add(&mut bo, &mut thief, G);
    let kp = laptop.generate_key_package().unwrap();
    let b = bo.add_member(G, &kp).unwrap();
    bo.merge_pending_commit(G).unwrap();
    thief.process_commit(G, &b.commit).unwrap();
    laptop.join_from_welcome(&b.welcome.unwrap()).unwrap();

    let verdict = laptop.check_own_device_key("device-ada-new", &public(9), "", &[]);
    assert_eq!(verdict, OwnDeviceVerdict::Unanchored);
    assert_eq!(answer_for(verdict.name()), "none");

    // A watched contact seat stays gated too.
    let mut thief2 = certified(&server, 10, "actor-ada", "device-ada-new2", &ada_key);
    let kp2 = thief2.generate_key_package().unwrap();
    let b3 = bo.add_member(G, &kp2).unwrap();
    bo.merge_pending_commit(G).unwrap();
    laptop.process_commit(G, &b3.commit).unwrap();
    thief2.join_from_welcome(&b3.welcome.unwrap()).unwrap();
    assert_eq!(
        laptop.check_own_device_key("device-ada-new2", &public(10), "", &[]),
        OwnDeviceVerdict::Unanchored
    );

    // The thief vouches for no further row.
    let approval = sign_device_approval(&device_seed(9), "device-ada-x", &public(11)).unwrap();
    assert_eq!(
        laptop.check_own_device_key("device-ada-x", &public(11), "device-ada-new", &approval),
        OwnDeviceVerdict::Unanchored
    );
}

/// No contact needed: the thief founds a group itself and adds the laptop.
#[test]
fn a_thief_that_founds_a_group_is_not_known() {
    let server = issuer();
    let ada_key = generate_account_key().unwrap();
    let (mut laptop, mut thief) = laptop_and_thief(&server, &ada_key);
    thief.create_group(G).unwrap();
    add(&mut thief, &mut laptop, G);
    assert_eq!(
        laptop.check_own_device_key("device-ada-new", &public(9), "", &[]),
        OwnDeviceVerdict::Unanchored
    );
}

/// Nor do the thief's own seats, watched by the laptop, vouch for the
/// devices they seat.
#[test]
fn a_thiefs_watched_seats_vouch_for_nobody() {
    let server = issuer();
    let ada_key = generate_account_key().unwrap();
    let mut laptop = certified(&server, 1, "actor-ada", "device-ada-laptop", &ada_key);
    let mut thief = certified(&server, 9, "actor-ada", "device-ada-new", &ada_key);
    thief.create_group(G).unwrap();
    add(&mut thief, &mut laptop, G);
    thief.create_group(H).unwrap();
    add(&mut thief, &mut laptop, H);

    let mut extra = certified(&server, 12, "actor-ada", "device-ada-extra", &ada_key);
    let kp = extra.generate_key_package().unwrap();
    let b = thief.add_member(H, &kp).unwrap();
    thief.merge_pending_commit(H).unwrap();
    laptop.process_commit(H, &b.commit).unwrap();
    extra.join_from_welcome(&b.welcome.unwrap()).unwrap();
    assert_eq!(
        laptop.check_own_device_key("device-ada-extra", &public(12), "", &[]),
        OwnDeviceVerdict::Unanchored
    );
    assert_eq!(
        laptop.check_own_device_approval(&extra.generate_key_package().unwrap(), "", &[]),
        OwnDeviceVerdict::Unanchored
    );
}

/// A sibling's seat of a key off the chain: the laptop watches the phone, its
/// own approver, commit it. A watched seat is no evidence, so the new key
/// gets no history and vouches for nobody.
#[test]
fn a_seat_an_honest_sibling_makes_on_no_verdict_vouches_for_nobody() {
    let server = issuer();
    let ada_key = generate_account_key().unwrap();
    let mut phone = certified(&server, 2, "actor-ada", "device-ada-phone", &ada_key);
    let mut laptop = certified(&server, 1, "actor-ada", "device-ada-laptop", &ada_key);
    let mut thief = certified(&server, 9, "actor-ada", "device-ada-new", &ada_key);
    let mut bo = certified(
        &server,
        3,
        "actor-bo",
        "device-bo",
        &generate_account_key().unwrap(),
    );
    laptop
        .remember_own_approver("device-ada-phone", &public(2))
        .unwrap();
    bo.create_group(G).unwrap();
    add(&mut bo, &mut phone, G);
    let c = add(&mut bo, &mut laptop, G);
    phone.process_commit(G, &c).unwrap();

    // `unanchored`; the phone adds it anyway.
    let kp = thief.generate_key_package().unwrap();
    assert_eq!(
        phone.check_own_device_approval(&kp, "", &[]),
        OwnDeviceVerdict::Unanchored
    );
    let b = phone.add_member(G, &kp).unwrap();
    phone.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &b.commit).unwrap();
    laptop.process_commit(G, &b.commit).unwrap();
    thief.join_from_welcome(&b.welcome.unwrap()).unwrap();

    let verdict = laptop.check_own_device_key("device-ada-new", &public(9), "", &[]);
    assert_eq!(verdict, OwnDeviceVerdict::Unanchored);
    assert_eq!(answer_for(verdict.name()), "none");
    let approval = sign_device_approval(&device_seed(9), "device-ada-x", &public(11)).unwrap();
    assert_eq!(
        laptop.check_own_device_key("device-ada-x", &public(11), "device-ada-new", &approval),
        OwnDeviceVerdict::Unanchored
    );
    // It is still a device the laptop has seen: the notice names it.
    assert!(laptop
        .own_sibling_leaves()
        .unwrap()
        .contains(&"device-ada-new".to_string()));
}

// ---- Honest devices keep working --------------------------------------------

/// The account's first device approves a second: each holds the other on
/// its chain, and neither sees a device it does not know.
#[test]
fn the_first_device_and_the_device_it_links_trust_each_other() {
    let server = issuer();
    let mut first = client(&server, 1, "actor-ada", "device-ada-first");
    let mut second = client(&server, 2, "actor-ada", "device-ada-second");
    let mut bo = client(&server, 3, "actor-bo", "device-bo");
    bo.create_group(G).unwrap();
    add(&mut bo, &mut first, G);

    let approval = sign_device_approval(&device_seed(1), "device-ada-second", &public(2)).unwrap();
    second
        .remember_own_approver("device-ada-first", &public(1))
        .unwrap();
    let c = gated_add(&mut first, &mut second, G, "device-ada-first", &approval);
    bo.process_commit(G, &c).unwrap();

    assert_eq!(
        second.check_own_device_key("device-ada-first", &public(1), "", &[]),
        OwnDeviceVerdict::Known
    );
    assert_eq!(answer_for("known"), "history");
    assert_eq!(
        first.check_own_device_key("device-ada-second", &public(2), "", &[]),
        OwnDeviceVerdict::Known
    );
    assert_eq!(
        second.own_sibling_leaves().unwrap(),
        vec!["device-ada-first"]
    );
    assert_eq!(
        first.own_sibling_leaves().unwrap(),
        vec!["device-ada-second"]
    );
}

/// A normal link: the phone approves a third device and seats it where the
/// laptop watches. Each sibling's approval puts it on every chain, and every
/// notice names every sibling by its bare id.
#[test]
fn a_normal_link_puts_the_new_device_and_its_siblings_on_every_chain() {
    let server = issuer();
    let mut phone = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut laptop = client(&server, 2, "actor-ada", "device-ada-laptop");
    let mut tablet = client(&server, 4, "actor-ada", "device-ada-tablet");
    let mut bo = client(&server, 3, "actor-bo", "device-bo");
    bo.create_group(G).unwrap();
    add(&mut bo, &mut phone, G);

    let laptop_approval =
        sign_device_approval(&device_seed(1), "device-ada-laptop", &public(2)).unwrap();
    laptop
        .remember_own_approver("device-ada-phone", &public(1))
        .unwrap();
    let c = gated_add(
        &mut phone,
        &mut laptop,
        G,
        "device-ada-phone",
        &laptop_approval,
    );
    bo.process_commit(G, &c).unwrap();

    let tablet_approval =
        sign_device_approval(&device_seed(1), "device-ada-tablet", &public(4)).unwrap();
    tablet
        .remember_own_approver("device-ada-phone", &public(1))
        .unwrap();
    let c = gated_add(
        &mut phone,
        &mut tablet,
        G,
        "device-ada-phone",
        &tablet_approval,
    );
    bo.process_commit(G, &c).unwrap();
    laptop.process_commit(G, &c).unwrap();

    // The laptop watched the phone seat the tablet: a seat is no evidence,
    // the tablet's approval under the phone, on the laptop's chain, is.
    assert_eq!(
        laptop.check_own_device_key("device-ada-tablet", &public(4), "", &[]),
        OwnDeviceVerdict::Unanchored
    );
    assert_eq!(
        laptop.check_own_device_key(
            "device-ada-tablet",
            &public(4),
            "device-ada-phone",
            &tablet_approval
        ),
        OwnDeviceVerdict::Approved
    );
    assert_eq!(answer_for("approved"), "history");
    assert_eq!(
        laptop.check_own_device_approval(
            &tablet.generate_key_package().unwrap(),
            "device-ada-phone",
            &tablet_approval
        ),
        OwnDeviceVerdict::Approved
    );
    assert_eq!(
        laptop.check_own_device_approval(&tablet.generate_key_package().unwrap(), "", &[]),
        OwnDeviceVerdict::Known
    );
    // The tablet saw the laptop only in the tree: its approval, under the
    // phone, vouches for it, and then it is on the tablet's chain.
    assert_eq!(
        tablet.check_own_device_key("device-ada-laptop", &public(2), "", &[]),
        OwnDeviceVerdict::Unanchored
    );
    assert_eq!(
        tablet.check_own_device_key(
            "device-ada-laptop",
            &public(2),
            "device-ada-phone",
            &laptop_approval
        ),
        OwnDeviceVerdict::Approved
    );
    assert_eq!(
        tablet.check_own_device_approval(
            &laptop.generate_key_package().unwrap(),
            "device-ada-phone",
            &laptop_approval
        ),
        OwnDeviceVerdict::Approved
    );
    assert_eq!(
        tablet.check_own_device_key("device-ada-laptop", &public(2), "", &[]),
        OwnDeviceVerdict::Known
    );

    // A device the laptop approves is vouched for by the tablet through it.
    let mut watch = client(&server, 5, "actor-ada", "device-ada-watch");
    let watch_approval =
        sign_device_approval(&device_seed(2), "device-ada-watch", &public(5)).unwrap();
    assert_eq!(
        tablet.check_own_device_key(
            "device-ada-watch",
            &public(5),
            "device-ada-laptop",
            &watch_approval
        ),
        OwnDeviceVerdict::Approved
    );
    let c = gated_add(
        &mut laptop,
        &mut watch,
        G,
        "device-ada-laptop",
        &watch_approval,
    );
    bo.process_commit(G, &c).unwrap();
    phone.process_commit(G, &c).unwrap();
    tablet.process_commit(G, &c).unwrap();

    for (device, leaves) in [
        ("phone", phone.own_sibling_leaves().unwrap()),
        ("laptop", laptop.own_sibling_leaves().unwrap()),
        ("tablet", tablet.own_sibling_leaves().unwrap()),
        ("watch", watch.own_sibling_leaves().unwrap()),
    ] {
        assert_eq!(leaves.len(), 3, "{device}: {leaves:?}");
        assert!(no_long_form(&leaves), "{device}: {leaves:?}");
    }
}

/// A third device approved by the second joins a contact's group holding the
/// first, approval-less device: the notice names the first device by its
/// bare id, and the first device's history ask here gets nothing, the
/// accepted cost of a sibling with no chain evidence.
#[test]
fn a_sibling_seen_only_in_a_tree_is_named_plainly_and_gets_no_history() {
    let server = issuer();
    let mut first = client(&server, 1, "actor-ada", "device-ada-first");
    let mut third = client(&server, 4, "actor-ada", "device-ada-third");
    let mut bo = client(&server, 3, "actor-bo", "device-bo");
    third
        .remember_own_approver("device-ada-second", &public(2))
        .unwrap();
    bo.create_group(H).unwrap();
    add(&mut bo, &mut first, H);
    let c = add(&mut bo, &mut third, H);
    first.process_commit(H, &c).unwrap();

    let leaves = third.own_sibling_leaves().unwrap();
    assert_eq!(leaves, vec!["device-ada-first"]);
    let verdict = third.check_own_device_key("device-ada-first", &public(1), "", &[]);
    assert_eq!(verdict, OwnDeviceVerdict::Unanchored);
    assert_eq!(answer_for(verdict.name()), "none");
}

/// A device that took the account key with no other device to approve it
/// ("I don't have my other devices", or a PIN restore that signed the others
/// out): it forgets the old devices, links a new one, and the two hold each
/// other on their chains, and its re-add of the new device is trusted.
fn a_device_alone_relinks(old_signed_out: bool) {
    let server = issuer();
    let mut restored = client(&server, 1, "actor-ada", "device-ada-restored");
    let mut old = client(&server, 6, "actor-ada", "device-ada-old");
    let mut fresh = client(&server, 2, "actor-ada", "device-ada-fresh");
    let mut bo = client(&server, 3, "actor-bo", "device-bo");
    if old_signed_out {
        assert!(restored
            .forget_own_device_with_key("device-ada-old", &public(6))
            .unwrap());
    }
    bo.create_group(G).unwrap();
    add(&mut bo, &mut restored, G);
    if !old_signed_out {
        let c = add(&mut bo, &mut old, G);
        restored.process_commit(G, &c).unwrap();
    }

    let approval = sign_device_approval(&device_seed(1), "device-ada-fresh", &public(2)).unwrap();
    fresh
        .remember_own_approver("device-ada-restored", &public(1))
        .unwrap();
    let c = gated_add(
        &mut restored,
        &mut fresh,
        G,
        "device-ada-restored",
        &approval,
    );
    bo.process_commit(G, &c).unwrap();
    if !old_signed_out {
        old.process_commit(G, &c).unwrap();
    }

    assert_eq!(
        fresh.check_own_device_key("device-ada-restored", &public(1), "", &[]),
        OwnDeviceVerdict::Known
    );
    assert_eq!(
        restored.check_own_device_key("device-ada-fresh", &public(2), "", &[]),
        OwnDeviceVerdict::Known
    );
    let leaves = fresh.own_sibling_leaves().unwrap();
    assert!(no_long_form(&leaves), "{leaves:?}");
    assert!(leaves.contains(&"device-ada-restored".to_string()));

    // The restored device re-adds the fresh one into the group it forgot.
    fresh.forget_group(G).unwrap();
    let leaf = restored.leaf_of_device(G, "device-ada-fresh").unwrap();
    let bundle = restored
        .replace_member(G, leaf, &fresh.generate_key_package().unwrap())
        .unwrap();
    restored.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &bundle.commit).unwrap();
    assert_eq!(
        fresh.join_from_welcome(&bundle.welcome.unwrap()).unwrap(),
        G
    );
    let report = fresh.take_rejoin_report(G).unwrap().expect("a report");
    assert_eq!(report.readded_by_device, "device-ada-restored");
    assert!(!report.readded_by_untrusted);
    assert!(reads(&mut bo, &mut fresh, G, b"welcome back"));
}

#[test]
fn a_device_with_no_other_devices_relinks_and_keeps_working() {
    a_device_alone_relinks(false);
}

#[test]
fn a_pin_restore_that_signed_the_others_out_relinks_and_keeps_working() {
    a_device_alone_relinks(true);
}
