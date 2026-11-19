// SPDX-License-Identifier: MIT
//! A device id names one install, under one key
//! (docs/identity.md §What the adder checks).
//!
//! The attacker throughout is a server that issues `pdc1` credentials as it
//! likes and holds a copy of Ada's account key (a removed device keeps it).
//! With them it can mint a credential naming any device id of Ada's under a
//! key of its own. Two things must then hold:
//!
//! - a leaf naming a device's OWN id under another key is never that device:
//!   not an anchor, not a trusted committer, and the new-device notice is told;
//! - a seat ask under a live sibling's id and another key cannot take that
//!   sibling's seat, and a key swap a member's core lets through anyway still
//!   reaches the notice, which is keyed on the device AND its key.
//!
//! Every client seats its own siblings only on a verdict whose `seats()` is
//! true. A member's client that skips the
//! adder's checks (a modified one) is played by the
//! `forge_*` doors, so the receivers' side is proven on its own.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use peachy_mls_core::issuer::device_key_pair;
use peachy_mls_core::{
    sign_device_approval, Client, Incoming, JoinRequestVerdict, OwnDeviceVerdict,
};
use support::{client, device_seed, issuer};

const G: &[u8] = b"66666666-6666-4666-8666-666666666666";
const H: &[u8] = b"77777777-7777-4777-8777-777777777777";
const K: &[u8] = b"88888888-8888-4888-8888-888888888888";

fn public(tag: u8) -> Vec<u8> {
    device_key_pair(&device_seed(tag)).1.to_vec()
}

/// How the notice input names a leaf under a key its id was not first seen
/// holding.
fn long_form(device_id: &str, tag: u8) -> String {
    format!("{device_id}#{}", hex::encode(public(tag)))
}

fn add(adder: &mut Client, joiner: &mut Client, group: &[u8]) -> Vec<u8> {
    let key_package = joiner.generate_key_package().expect("key package");
    let bundle = adder.add_member(group, &key_package).expect("add");
    adder.merge_pending_commit(group).expect("merge");
    joiner
        .join_from_welcome(&bundle.welcome.expect("welcome"))
        .expect("join");
    bundle.commit
}

/// The adder approved `joiner` (its own sibling) and checks that approval
/// before it seats it, as every client's sweep does: an own add on no
/// seating verdict anchors nothing.
fn vouch(adder: &mut Client, adder_tag: u8, joiner: &Client, joiner_tag: u8) {
    let approver = adder.identity().device_id.clone();
    let device = joiner.identity().device_id.clone();
    let approval =
        sign_device_approval(&device_seed(adder_tag), &device, &public(joiner_tag)).unwrap();
    let kp = joiner.generate_key_package().unwrap();
    assert_eq!(
        adder.check_own_device_approval(&kp, &approver, &approval),
        OwnDeviceVerdict::Approved
    );
}

/// An add as a client that skips the adder's checks builds it.
#[cfg(feature = "test-forgery")]
fn unchecked_add(adder: &mut Client, joiner: &mut Client, group: &[u8]) -> Vec<u8> {
    let key_package = joiner.generate_key_package().expect("key package");
    let bundle = adder
        .forge_commit(group, &[], &[&key_package])
        .expect("unchecked add");
    adder.merge_pending_commit(group).expect("merge");
    joiner
        .join_from_welcome(&bundle.welcome.expect("welcome"))
        .expect("join");
    bundle.commit
}

fn gated_own_add(
    adder: &mut Client,
    group: &[u8],
    key_package: &[u8],
    approver: &str,
    approval: &[u8],
) -> Option<(Vec<u8>, Vec<u8>)> {
    let verdict = adder.check_own_device_approval(key_package, approver, approval);
    if !verdict.seats() {
        return None;
    }
    let bundle = adder.add_member(group, key_package).expect("add");
    adder.merge_pending_commit(group).expect("merge");
    Some((bundle.commit, bundle.welcome.expect("welcome")))
}

fn reads(sender: &mut Client, reader: &mut Client, group: &[u8], text: &[u8]) -> bool {
    let Ok(wire) = sender.encrypt(group, text) else {
        return false;
    };
    match reader.process_message(group, &wire) {
        Ok(Incoming::Application { plaintext, .. }) => plaintext == text,
        _ => false,
    }
}

fn keys_for(c: &Client, group: &[u8], device: &str) -> Vec<Vec<u8>> {
    c.roster(group)
        .unwrap()
        .into_iter()
        .filter_map(|e| e.identity.ok())
        .filter(|id| id.device_id == device)
        .map(|id| id.device_key.to_vec())
        .collect()
}

/// The adder's core refuses a second leaf for a device id the group already
/// seats, under any key: a contact's app that does not skip a duplicate the
/// server listed seats nobody.
#[test]
fn a_second_leaf_for_a_seated_device_id_is_refused_by_the_adder() {
    let server = issuer();
    let mut phone = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(&server, 3, "actor-bo", "device-bo");
    let impostor = client(&server, 9, "actor-ada", "device-ada-phone");

    phone.create_group(G).unwrap();
    add(&mut phone, &mut bo, G);
    let kp = impostor.generate_key_package().unwrap();
    assert!(bo.add_member(G, &kp).is_err());
    assert_eq!(keys_for(&bo, G, "device-ada-phone"), vec![public(1)]);

    // The same through group creation: two packages naming one device id.
    let mut impostor = client(&server, 9, "actor-ada", "device-ada-phone");
    bo.create_group(K).unwrap();
    add(&mut bo, &mut impostor, K);
    let real = phone.generate_key_package().unwrap();
    assert!(bo.add_member(K, &real).is_err());
    assert_eq!(keys_for(&bo, K, "device-ada-phone"), vec![public(9)]);
}

/// A leaf naming this device's own id under another key, seated by a member
/// whose client skipped the adder's check: the device and its sibling refuse
/// the commit, so it is never an anchor, an approval its key signs seats
/// nothing, and the notice input has nothing new to report.
#[cfg(feature = "test-forgery")]
#[test]
fn a_leaf_under_this_devices_id_and_another_key_is_never_trusted() {
    let server = issuer();
    let mut phone = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut laptop = client(&server, 2, "actor-ada", "device-ada-laptop");
    let mut bo = client(&server, 3, "actor-bo", "device-bo");
    let mut cy = client(&server, 4, "actor-cy", "device-cy");

    phone.create_group(G).unwrap();
    add(&mut phone, &mut bo, G);
    vouch(&mut phone, 1, &laptop, 2);
    let seat = add(&mut phone, &mut laptop, G);
    bo.process_commit(G, &seat).unwrap();
    phone.create_group(H).unwrap();
    add(&mut phone, &mut cy, H);
    assert_eq!(
        phone.own_sibling_leaves().unwrap(),
        vec!["device-ada-laptop".to_string()]
    );

    let mut impostor = client(&server, 9, "actor-ada", "device-ada-phone");
    let seat = unchecked_add(&mut bo, &mut impostor, G);
    for member in [&mut phone, &mut laptop] {
        let err = member
            .process_commit(G, &seat)
            .expect_err("a second leaf for one device id");
        assert!(err.to_string().contains("second leaf"), "{err}");
    }

    let impostor_pair = ("device-ada-phone".to_string(), public(9));
    assert!(!phone.own_device_anchors().unwrap().contains(&impostor_pair));
    assert!(!laptop
        .own_device_anchors()
        .unwrap()
        .contains(&impostor_pair));
    assert_eq!(
        phone.own_sibling_leaves().unwrap(),
        vec!["device-ada-laptop".to_string()]
    );

    // An approval the impostor's key signs, under the phone's id.
    let mut next = client(&server, 10, "actor-ada", "device-ada-next");
    let next_kp = next.generate_key_package().unwrap();
    let approval = sign_device_approval(&device_seed(9), "device-ada-next", &public(10)).unwrap();
    assert_eq!(
        phone.check_own_device_approval(&next_kp, "device-ada-phone", &approval),
        OwnDeviceVerdict::BadApproval
    );
    assert!(!laptop
        .check_own_device_approval(&next_kp, "device-ada-phone", &approval)
        .seats());
    assert!(gated_own_add(&mut phone, H, &next_kp, "device-ada-phone", &approval).is_none());
    assert!(!reads(&mut cy, &mut next, H, b"cy to ada, in H"));
}

/// The same leaf as a COMMITTER: the phone refused its seat, and the devices
/// it seats where the commit was taken are not trusted on the phone.
#[cfg(feature = "test-forgery")]
#[test]
fn devices_seated_by_a_leaf_wearing_this_devices_id_are_not_known() {
    let server = issuer();
    let mut phone = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(&server, 3, "actor-bo", "device-bo");
    let mut cy = client(&server, 4, "actor-cy", "device-cy");

    phone.create_group(G).unwrap();
    add(&mut phone, &mut bo, G);
    phone.create_group(H).unwrap();
    add(&mut phone, &mut cy, H);

    let mut impostor = client(&server, 9, "actor-ada", "device-ada-phone");
    let seat = unchecked_add(&mut bo, &mut impostor, G);
    assert!(phone.process_commit(G, &seat).is_err());

    let mut planted = client(&server, 11, "actor-ada", "device-ada-planted");
    let seat = add(&mut impostor, &mut planted, G);
    bo.process_commit(G, &seat).unwrap();

    let kp = planted.generate_key_package().unwrap();
    assert_eq!(
        phone.check_own_device_approval(&kp, "", &[]),
        OwnDeviceVerdict::Unanchored
    );
    assert!(gated_own_add(&mut phone, H, &kp, "", &[]).is_none());
    assert!(!reads(&mut cy, &mut planted, H, b"cy to ada, in H"));
}

/// A Welcome into a group whose tree already holds a leaf under this
/// device's id and another key (a contact's client that added both packages
/// a server listed for it): the device joins, but the other leaf is no
/// anchor of its own id, and the notice is told.
#[cfg(feature = "test-forgery")]
#[test]
fn a_welcome_with_a_leaf_under_this_devices_id_does_not_make_it_an_anchor() {
    let server = issuer();
    let mut phone = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(&server, 3, "actor-bo", "device-bo");
    let mut impostor = client(&server, 9, "actor-ada", "device-ada-phone");

    bo.create_group(K).unwrap();
    add(&mut bo, &mut impostor, K);
    unchecked_add(&mut bo, &mut phone, K);
    assert_eq!(keys_for(&phone, K, "device-ada-phone").len(), 2);

    assert!(!phone
        .own_device_anchors()
        .unwrap()
        .contains(&("device-ada-phone".to_string(), public(9))));
    assert_eq!(
        phone.own_sibling_leaves().unwrap(),
        vec![long_form("device-ada-phone", 9)]
    );
    let next = client(&server, 10, "actor-ada", "device-ada-next");
    let next_kp = next.generate_key_package().unwrap();
    let approval = sign_device_approval(&device_seed(9), "device-ada-next", &public(10)).unwrap();
    assert!(!phone
        .check_own_device_approval(&next_kp, "device-ada-phone", &approval)
        .seats());
}

/// A seat ask naming a live sibling's id, signed by a key minted under the
/// retained account key. Bo serves it as the delivery rules say; the ask
/// itself verifies (Ada holds a leaf), but the replace is refused because
/// the key is not the seat's. The real laptop keeps its seat and the
/// impostor reads nothing.
#[test]
fn a_seat_ask_under_a_siblings_id_and_another_key_cannot_take_its_seat() {
    let server = issuer();
    let mut phone = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut laptop = client(&server, 2, "actor-ada", "device-ada-laptop");
    let mut bo = client(&server, 3, "actor-bo", "device-bo");

    phone.create_group(G).unwrap();
    add(&mut phone, &mut bo, G);
    vouch(&mut phone, 1, &laptop, 2);
    let seat = add(&mut phone, &mut laptop, G);
    bo.process_commit(G, &seat).unwrap();

    let impostor = client(&server, 9, "actor-ada", "device-ada-laptop");
    let proof = impostor.sign_join_request(G).unwrap();
    assert!(bo.first_sight_of_join_request(G, &proof).unwrap());
    let kp = impostor.generate_key_package().unwrap();
    assert_eq!(
        bo.verify_join_request(G, "actor-ada", "device-ada-laptop", &proof, &kp, &[]),
        JoinRequestVerdict::Accepted
    );
    let leaf = bo.leaf_of_device(G, "device-ada-laptop").unwrap();
    assert!(bo.replace_member(G, leaf, &kp).is_err());
    // Nor may it come in beside the laptop as an ordinary add.
    assert!(bo.add_member(G, &kp).is_err());

    assert_eq!(keys_for(&bo, G, "device-ada-laptop"), vec![public(2)]);
    assert!(laptop.is_active(G).unwrap());
    assert!(reads(
        &mut phone,
        &mut laptop,
        G,
        b"ada's phone to the group"
    ));
}

/// The same key swap, committed by a member whose client skips the
/// replace's key check: the phone refuses the commit, so the laptop's seat
/// keeps its key there and the swapped-in key is no device of Ada's.
#[cfg(feature = "test-forgery")]
#[test]
fn a_key_swap_in_a_siblings_seat_is_refused_by_the_sibling() {
    let server = issuer();
    let mut phone = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut laptop = client(&server, 2, "actor-ada", "device-ada-laptop");
    let mut bo = client(&server, 3, "actor-bo", "device-bo");

    phone.create_group(G).unwrap();
    add(&mut phone, &mut bo, G);
    vouch(&mut phone, 1, &laptop, 2);
    let seat = add(&mut phone, &mut laptop, G);
    bo.process_commit(G, &seat).unwrap();

    let impostor = client(&server, 9, "actor-ada", "device-ada-laptop");
    let kp = impostor.generate_key_package().unwrap();
    let leaf = bo.leaf_of_device(G, "device-ada-laptop").unwrap();
    let bundle = bo.forge_commit(G, &[leaf], &[&kp]).unwrap();
    bo.merge_pending_commit(G).unwrap();
    let err = phone
        .process_commit(G, &bundle.commit)
        .expect_err("a key swap in a sibling's seat");
    assert!(
        err.to_string().contains("under another device key"),
        "{err}"
    );
    assert_eq!(keys_for(&phone, G, "device-ada-laptop"), vec![public(2)]);
    assert_eq!(
        phone.own_sibling_leaves().unwrap(),
        vec!["device-ada-laptop".to_string()]
    );
    assert!(!phone
        .own_device_anchors()
        .unwrap()
        .contains(&("device-ada-laptop".to_string(), public(9))));
    let next = client(&server, 10, "actor-ada", "device-ada-next");
    let next_kp = next.generate_key_package().unwrap();
    let approval = sign_device_approval(&device_seed(9), "device-ada-next", &public(10)).unwrap();
    assert!(!phone
        .check_own_device_approval(&next_kp, "device-ada-laptop", &approval)
        .seats());
}

/// An honest rejoin keeps its device key: the replace goes through, the
/// laptop is back under the key it had, and the notice input still names it
/// by its id alone.
#[test]
fn an_honest_rejoin_keeps_its_key_and_its_seat() {
    let server = issuer();
    let mut phone = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut laptop = client(&server, 2, "actor-ada", "device-ada-laptop");
    let mut bo = client(&server, 3, "actor-bo", "device-bo");

    phone.create_group(G).unwrap();
    add(&mut phone, &mut bo, G);
    vouch(&mut phone, 1, &laptop, 2);
    let seat = add(&mut phone, &mut laptop, G);
    bo.process_commit(G, &seat).unwrap();
    let before = phone.own_sibling_leaves().unwrap();
    assert_eq!(before, vec!["device-ada-laptop".to_string()]);

    laptop.forget_group(G).unwrap();
    let proof = laptop.sign_join_request(G).unwrap();
    let kp = laptop.generate_key_package().unwrap();
    assert_eq!(
        bo.verify_join_request(G, "actor-ada", "device-ada-laptop", &proof, &kp, &[]),
        JoinRequestVerdict::Accepted
    );
    let leaf = bo.leaf_of_device(G, "device-ada-laptop").unwrap();
    let bundle = bo.replace_member(G, leaf, &kp).unwrap();
    bo.merge_pending_commit(G).unwrap();
    phone.process_commit(G, &bundle.commit).unwrap();
    laptop.join_from_welcome(&bundle.welcome.unwrap()).unwrap();

    assert_eq!(keys_for(&phone, G, "device-ada-laptop"), vec![public(2)]);
    assert_eq!(phone.own_sibling_leaves().unwrap(), before);
    assert!(reads(&mut bo, &mut laptop, G, b"bo to ada"));
}

/// A new device of Ada's that a contact seats is reported by its id, with
/// its key in the long form beside it until an approval for it verifies: a
/// contact's seat is no evidence of which key that id holds. Once the
/// approval verifies, the id alone.
#[test]
fn a_new_device_a_contact_seats_is_reported_by_its_id() {
    let server = issuer();
    let mut phone = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(&server, 3, "actor-bo", "device-bo");

    phone.create_group(G).unwrap();
    add(&mut phone, &mut bo, G);
    let mut tablet = client(&server, 5, "actor-ada", "device-ada-tablet");
    let seat = add(&mut bo, &mut tablet, G);
    phone.process_commit(G, &seat).unwrap();

    assert_eq!(
        phone.own_sibling_leaves().unwrap(),
        vec![
            "device-ada-tablet".to_string(),
            long_form("device-ada-tablet", 5)
        ]
    );
    // Still counted for nothing until an approval vouches for it.
    let kp = tablet.generate_key_package().unwrap();
    assert_eq!(
        phone.check_own_device_approval(&kp, "", &[]),
        OwnDeviceVerdict::Unanchored
    );
    let approval = sign_device_approval(&device_seed(1), "device-ada-tablet", &public(5)).unwrap();
    assert_eq!(
        phone.check_own_device_approval(&kp, "device-ada-phone", &approval),
        OwnDeviceVerdict::Approved
    );
    assert_eq!(
        phone.own_sibling_leaves().unwrap(),
        vec!["device-ada-tablet".to_string()]
    );
}

/// The notice input's world for the tests below: Ada's phone holds G with
/// Bo and H with Cy; her real laptop's approval is signed by the phone.
struct Linking {
    phone: Client,
    laptop: Client,
    bo: Client,
    cy: Client,
    approval: Vec<u8>,
}

fn linking() -> Linking {
    let server = issuer();
    let mut phone = client(&server, 1, "actor-ada", "device-ada-phone");
    let laptop = client(&server, 2, "actor-ada", "device-ada-laptop");
    let mut bo = client(&server, 3, "actor-bo", "device-bo");
    let mut cy = client(&server, 4, "actor-cy", "device-cy");
    phone.create_group(G).unwrap();
    add(&mut phone, &mut bo, G);
    phone.create_group(H).unwrap();
    add(&mut phone, &mut cy, H);
    let approval = sign_device_approval(&device_seed(1), "device-ada-laptop", &public(2))
        .unwrap()
        .to_vec();
    Linking {
        phone,
        laptop,
        bo,
        cy,
        approval,
    }
}

/// A device minted under the retained account key, wearing the laptop's id.
fn laptop_impostor() -> Client {
    client(&issuer(), 9, "actor-ada", "device-ada-laptop")
}

/// The phone's own sweep: the real laptop's approval verifies, and the
/// phone seats it in H.
fn phone_seats_the_real_laptop(w: &mut Linking) {
    let kp = w.laptop.generate_key_package().unwrap();
    assert_eq!(
        w.phone
            .check_own_device_approval(&kp, "device-ada-phone", &w.approval),
        OwnDeviceVerdict::Approved
    );
    let bundle = w.phone.add_member(H, &kp).unwrap();
    w.phone.merge_pending_commit(H).unwrap();
    w.cy.process_commit(H, &bundle.commit).unwrap();
    w.laptop
        .join_from_welcome(&bundle.welcome.unwrap())
        .unwrap();
}

/// The sweep order the clients use (read the notice input, then seat): a
/// contact seats the impostor under the laptop's id first, the phone reads,
/// then seats the real laptop, then reads again. The impostor is never the
/// laptop's bare name; the real laptop is.
#[test]
fn a_contact_seated_device_under_a_siblings_id_never_takes_its_bare_name() {
    let mut w = linking();
    let mut impostor = laptop_impostor();
    let seat = add(&mut w.bo, &mut impostor, G);
    w.phone.process_commit(G, &seat).unwrap();
    assert_eq!(
        w.phone.own_sibling_leaves().unwrap(),
        vec![
            "device-ada-laptop".to_string(),
            long_form("device-ada-laptop", 9)
        ]
    );
    phone_seats_the_real_laptop(&mut w);
    assert_eq!(
        w.phone.own_sibling_leaves().unwrap(),
        vec![
            "device-ada-laptop".to_string(),
            long_form("device-ada-laptop", 9)
        ]
    );
}

/// The server never serves the phone the real laptop's package, only the
/// impostor's under the laptop's id (whose approval does not verify). The
/// real key is never in any tree the phone holds, and the impostor is still
/// reported in the long form on every read.
#[test]
fn a_contact_seated_device_is_reported_when_the_real_one_is_never_seen() {
    let mut w = linking();
    let mut impostor = laptop_impostor();
    let seat = add(&mut w.bo, &mut impostor, G);
    w.phone.process_commit(G, &seat).unwrap();
    let kp = laptop_impostor().generate_key_package().unwrap();
    assert_eq!(
        w.phone
            .check_own_device_approval(&kp, "device-ada-phone", &w.approval),
        OwnDeviceVerdict::BadApproval
    );
    for _ in 0..3 {
        assert_eq!(
            w.phone.own_sibling_leaves().unwrap(),
            vec![
                "device-ada-laptop".to_string(),
                long_form("device-ada-laptop", 9)
            ]
        );
    }
    assert!(!w
        .phone
        .own_device_anchors()
        .unwrap()
        .contains(&("device-ada-laptop".to_string(), public(9))));
}

/// A contact seats the impostor and removes it again before the real laptop
/// exists. The removal records nothing for the id, so the real laptop is its
/// bare name when the phone links it, and the impostor's later seat is
/// reported in the long form.
#[test]
fn a_contact_seated_key_a_removal_takes_out_records_nothing() {
    let mut w = linking();
    let mut impostor = laptop_impostor();
    let seat = add(&mut w.bo, &mut impostor, G);
    w.phone.process_commit(G, &seat).unwrap();
    let leaf = w.bo.leaf_of_device(G, "device-ada-laptop").unwrap();
    let removal = w.bo.remove_leaf(G, leaf).unwrap();
    w.bo.merge_pending_commit(G).unwrap();
    w.phone.process_commit(G, &removal.commit).unwrap();

    phone_seats_the_real_laptop(&mut w);
    assert_eq!(
        w.phone.own_sibling_leaves().unwrap(),
        vec!["device-ada-laptop".to_string()]
    );

    let mut again = laptop_impostor();
    let seat = add(&mut w.bo, &mut again, G);
    w.phone.process_commit(G, &seat).unwrap();
    assert_eq!(
        w.phone.own_sibling_leaves().unwrap(),
        vec![
            "device-ada-laptop".to_string(),
            long_form("device-ada-laptop", 9)
        ]
    );
}

/// A key recorded from a tree gives way to one an approval vouches for,
/// never the reverse: the phone first sees the laptop's id (taken from a
/// Welcome's tree, under the impostor's key), then the real laptop's
/// approval verifies and the phone seats it.
#[test]
fn an_approved_key_replaces_one_taken_from_a_tree() {
    let server = issuer();
    let mut phone = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut laptop = client(&server, 2, "actor-ada", "device-ada-laptop");
    let mut bo = client(&server, 3, "actor-bo", "device-bo");
    let mut impostor = laptop_impostor();

    // Bo's group already holds the impostor when the phone joins it, so the
    // phone takes that leaf as the tree shows it.
    bo.create_group(K).unwrap();
    add(&mut bo, &mut impostor, K);
    let seat = add(&mut bo, &mut phone, K);
    impostor.process_commit(K, &seat).unwrap();
    assert_eq!(
        phone.own_sibling_leaves().unwrap(),
        vec!["device-ada-laptop".to_string()]
    );

    let approval = sign_device_approval(&device_seed(1), "device-ada-laptop", &public(2)).unwrap();
    let kp = laptop.generate_key_package().unwrap();
    assert_eq!(
        phone.check_own_device_approval(&kp, "device-ada-phone", &approval),
        OwnDeviceVerdict::Approved
    );
    phone.create_group(G).unwrap();
    let bundle = phone.add_member(G, &kp).unwrap();
    phone.merge_pending_commit(G).unwrap();
    laptop.join_from_welcome(&bundle.welcome.unwrap()).unwrap();

    let out = phone.own_sibling_leaves().unwrap();
    assert!(out.contains(&"device-ada-laptop".to_string()));
    assert!(out.contains(&long_form("device-ada-laptop", 9)));
    assert!(!out.contains(&long_form("device-ada-laptop", 2)));
}

/// ONE DEVICE, ONE LEAF, receiver side: a commit that seats a second leaf
/// under a device id the group already seats is refused whole, and the
/// receiver stays at its epoch.
#[cfg(feature = "test-forgery")]
#[test]
fn a_second_leaf_under_one_device_id_is_refused() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    let mut cy = client(&server, 3, "actor-cy", "device-cy");
    let squatter = client(&server, 9, "actor-zed", "device-bo");
    ada.create_group(G).unwrap();
    add(&mut ada, &mut bo, G);
    let seat = add(&mut ada, &mut cy, G);
    bo.process_commit(G, &seat).unwrap();
    let before = cy.epoch(G).unwrap();

    let kp = squatter.generate_key_package().unwrap();
    let forged = ada.forge_commit(G, &[], &[&kp]).unwrap();
    ada.merge_pending_commit(G).unwrap();
    for receiver in [&mut bo, &mut cy] {
        let refused = receiver.process_commit(G, &forged.commit);
        assert!(
            matches!(&refused, Err(e) if e.to_string().contains("second leaf")),
            "{refused:?}"
        );
        assert_eq!(receiver.epoch(G).unwrap(), before);
    }
    assert_eq!(keys_for(&cy, G, "device-bo"), vec![public(2)]);
}

/// A RESEAT UNDER ANOTHER DEVICE KEY, receiver side: a replace that seats a
/// device id under a new device key (the same actor, device id and account
/// key) is refused whole, in a group with no policy as in one with.
#[cfg(feature = "test-forgery")]
#[test]
fn a_reseat_under_another_device_key_is_refused() {
    reseat_under_another_device_key(None);
}

/// The same, in a group whose meta names a policy (Ada its one admin): the
/// policy calls the replace a reseat and passes it, and the receiver still
/// judges the new key on its own.
#[cfg(feature = "test-forgery")]
#[test]
fn a_reseat_under_another_device_key_is_refused_in_a_group_with_a_policy() {
    reseat_under_another_device_key(Some(b"{\"v\":1,\"n\":\"Walk\",\"adm\":[\"actor-ada\"]}"));
}

#[cfg(feature = "test-forgery")]
fn reseat_under_another_device_key(meta: Option<&[u8]>) {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    let mut cy = client(&server, 3, "actor-cy", "device-cy");
    let mut dee = client(&server, 4, "actor-dee", "device-dee");
    ada.create_group(G).unwrap();
    if let Some(meta) = meta {
        ada.set_group_meta(G, meta).unwrap();
        ada.merge_pending_commit(G).unwrap();
    }
    add(&mut ada, &mut bo, G);
    let seat = add(&mut ada, &mut cy, G);
    bo.process_commit(G, &seat).unwrap();
    let seat = add(&mut ada, &mut dee, G);
    bo.process_commit(G, &seat).unwrap();
    cy.process_commit(G, &seat).unwrap();

    // Dee's id under a new key, seated in Dee's place.
    let dee_again = client(&server, 14, "actor-dee", "device-dee");
    let kp = dee_again.generate_key_package().unwrap();
    let dee_leaf = ada.leaf_of_device(G, "device-dee").unwrap();
    assert!(ada.replace_member(G, dee_leaf, &kp).is_err());
    let forged = ada.forge_commit(G, &[dee_leaf], &[&kp]).unwrap();
    ada.merge_pending_commit(G).unwrap();
    let before = cy.epoch(G).unwrap();
    for receiver in [&mut bo, &mut cy] {
        let refused = receiver.process_commit(G, &forged.commit);
        assert!(
            matches!(&refused, Err(e) if e.to_string().contains("another device key")),
            "{refused:?}"
        );
        assert_eq!(receiver.epoch(G).unwrap(), before);
        assert_eq!(keys_for(receiver, G, "device-dee"), vec![public(4)]);
    }
}
