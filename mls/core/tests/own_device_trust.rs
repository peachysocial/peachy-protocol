// SPDX-License-Identifier: MIT
//! Which of its own account's devices a device keeps trusting
//! (docs/identity.md §What the adder checks).
//!
//! The account key never rotates when a device is removed, so a removed
//! device, or anyone who took it, can certify new device keys under the
//! person's own identity, and a server that is itself hostile lists them. Two
//! things must then hold on every remaining device:
//!
//! - a device the account removed is forgotten: not trusted as the device
//!   that let this one in, never seated again, and its approvals vouch for
//!   nobody;
//! - a leaf of the person's own account that a contact seated (a contact
//!   cannot check another account's approvals) is no evidence the person let
//!   that device in, so the person's own devices do not spread it into every
//!   group they hold.
//!
//! Each scenario runs the way a gated client would: it seats a sibling only
//! on a verdict whose `seats()` is true.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use peachy_mls_core::issuer::device_key_pair;
use peachy_mls_core::{
    sign_device_approval, Client, Incoming, JoinRequestVerdict, OwnDeviceVerdict,
};
use support::{client, device_seed, issuer};

const G: &[u8] = b"44444444-4444-4444-8444-444444444444";
const H: &[u8] = b"55555555-5555-4555-8555-555555555555";

fn add(adder: &mut Client, joiner: &mut Client, group: &[u8]) -> Vec<u8> {
    let key_package = joiner.generate_key_package().expect("key package");
    let bundle = adder.add_member(group, &key_package).expect("add");
    adder.merge_pending_commit(group).expect("merge");
    joiner
        .join_from_welcome(&bundle.welcome.expect("welcome"))
        .expect("join");
    bundle.commit
}

/// An own-device add as a gated client makes it: refused unless the
/// gate's verdict seats.
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

fn reads(sender: &mut Client, reader: &mut Client, group: &[u8], text: &[u8]) -> bool {
    let wire = sender.encrypt(group, text).expect("encrypt");
    match reader.process_message(group, &wire) {
        Ok(Incoming::Application { plaintext, .. }) => plaintext == text,
        _ => false,
    }
}

fn public(tag: u8) -> [u8; 32] {
    device_key_pair(&device_seed(tag)).1
}

fn remove_device(remover: &mut Client, group: &[u8], device: &str, others: &mut [&mut Client]) {
    let leaf = remover.leaf_of_device(group, device).expect("leaf");
    let removal = remover.remove_leaf(group, leaf).expect("remove");
    remover.merge_pending_commit(group).expect("merge");
    for other in others.iter_mut() {
        other
            .process_commit(group, &removal.commit)
            .expect("apply removal");
    }
}

/// The phone let the laptop in, so the laptop remembers it. The phone is
/// stolen and removed, and the laptop forgets it. From then on neither the
/// phone itself nor a device it "approves" with its own key is seated by the
/// laptop, in a group made after the removal, whatever the server lists.
#[test]
fn a_removed_device_that_let_this_one_in_is_forgotten() {
    let server = issuer();
    let mut phone = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut laptop = client(&server, 2, "actor-ada", "device-ada-laptop");
    let mut bo = client(&server, 3, "actor-bo", "device-bo");
    let mut cy = client(&server, 4, "actor-cy", "device-cy");

    laptop
        .remember_own_approver("device-ada-phone", &public(1))
        .unwrap();

    laptop.create_group(G).unwrap();
    add(&mut laptop, &mut bo, G);
    let seat = add(&mut laptop, &mut phone, G);
    bo.process_commit(G, &seat).unwrap();
    remove_device(&mut laptop, G, "device-ada-phone", &mut [&mut bo]);

    // Before the laptop hears of the removal it still knows the phone as the
    // device that let it in.
    let phone_kp = phone.generate_key_package().unwrap();
    assert_eq!(
        laptop.check_own_device_approval(&phone_kp, "", &[]),
        OwnDeviceVerdict::Known
    );

    // The removal reaches the laptop (its own RevokeDevice, or the device
    // list's revoked row). Forgetting is idempotent.
    assert!(laptop.forget_own_device("device-ada-phone").unwrap());
    assert!(!laptop.forget_own_device("device-ada-phone").unwrap());

    laptop.create_group(H).unwrap();
    add(&mut laptop, &mut cy, H);

    // The server lists the removed phone as live again.
    let phone_kp = phone.generate_key_package().unwrap();
    assert_eq!(
        laptop.check_own_device_approval(&phone_kp, "", &[]),
        OwnDeviceVerdict::Unanchored
    );
    assert!(gated_own_add(&mut laptop, H, &phone_kp, "", &[]).is_none());

    // A device minted under the retained account key, "approved" with the
    // stolen phone's own device key.
    let thief = client(&server, 9, "actor-ada", "device-ada-thief");
    let thief_kp = thief.generate_key_package().unwrap();
    let approval = sign_device_approval(&device_seed(1), "device-ada-thief", &public(9)).unwrap();
    assert_eq!(
        laptop.check_own_device_approval(&thief_kp, "device-ada-phone", &approval),
        OwnDeviceVerdict::Unanchored
    );
    assert!(gated_own_add(&mut laptop, H, &thief_kp, "device-ada-phone", &approval).is_none());

    // Nobody but Cy and the laptop holds H.
    assert_eq!(laptop.roster(H).unwrap().len(), 2);
    assert!(reads(&mut cy, &mut laptop, H, b"for ada's laptop only"));
}

/// A forgotten device stays unseated even when the device list still
/// carries the approval a live sibling once made for it, which verifies.
#[test]
fn a_forgotten_device_is_not_seated_on_its_old_approval() {
    let server = issuer();
    let mut phone = client(&server, 1, "actor-ada", "device-ada-phone");
    let tablet = client(&server, 5, "actor-ada", "device-ada-tablet");

    let by_phone = sign_device_approval(&device_seed(1), "device-ada-tablet", &public(5)).unwrap();
    let tablet_kp = tablet.generate_key_package().unwrap();
    assert_eq!(
        phone.check_own_device_approval(&tablet_kp, "device-ada-phone", &by_phone),
        OwnDeviceVerdict::Approved
    );
    assert!(phone.forget_own_device("device-ada-tablet").unwrap());
    assert_eq!(
        phone.check_own_device_approval(&tablet_kp, "device-ada-phone", &by_phone),
        OwnDeviceVerdict::Unanchored
    );
}

/// Forgetting a device takes back the vouching it did: a device that is on
/// this device's approval chain only because the forgotten one approved it
/// leaves the chain with it, and so does every device that one approved in
/// turn. Whoever holds a removed device could have linked those. A device
/// still on the chain approving it again puts it back, and the devices it
/// approved come back with it.
#[test]
fn forgetting_a_device_takes_back_the_devices_it_vouched_for() {
    let server = issuer();
    let mut laptop = client(&server, 2, "actor-ada", "device-ada-laptop");
    let tablet = client(&server, 5, "actor-ada", "device-ada-tablet");
    let watch = client(&server, 6, "actor-ada", "device-ada-watch");

    laptop
        .remember_own_approver("device-ada-phone", &public(1))
        .unwrap();
    let by_phone = sign_device_approval(&device_seed(1), "device-ada-tablet", &public(5)).unwrap();
    let tablet_kp = tablet.generate_key_package().unwrap();
    assert_eq!(
        laptop.check_own_device_approval(&tablet_kp, "device-ada-phone", &by_phone),
        OwnDeviceVerdict::Approved
    );
    let by_tablet = sign_device_approval(&device_seed(5), "device-ada-watch", &public(6)).unwrap();
    let watch_kp = watch.generate_key_package().unwrap();
    assert_eq!(
        laptop.check_own_device_approval(&watch_kp, "device-ada-tablet", &by_tablet),
        OwnDeviceVerdict::Approved
    );

    assert!(laptop.forget_own_device("device-ada-phone").unwrap());
    for (id, tag) in [("device-ada-tablet", 5), ("device-ada-watch", 6)] {
        assert_eq!(
            laptop.check_own_device_key(id, &public(tag), "", &[]),
            OwnDeviceVerdict::Unanchored,
            "{id} stayed on the chain its forgotten approver put it on"
        );
    }
    assert_eq!(
        laptop.check_own_device_approval(&watch_kp, "device-ada-tablet", &by_tablet),
        OwnDeviceVerdict::Unanchored
    );

    // The laptop, on the chain itself, approves the tablet again.
    let by_laptop = sign_device_approval(&device_seed(2), "device-ada-tablet", &public(5)).unwrap();
    assert_eq!(
        laptop.check_own_device_approval(&tablet_kp, "device-ada-laptop", &by_laptop),
        OwnDeviceVerdict::Approved
    );
    assert_eq!(
        laptop.check_own_device_key("device-ada-watch", &public(6), "", &[]),
        OwnDeviceVerdict::Known
    );
}

/// A chain record written before records named their approver cannot say
/// who vouched, so forgetting a device leaves it where it was.
#[test]
fn a_chain_record_that_names_no_approver_stays_on_the_chain() {
    use peachy_mls_core::{storage_key, KvStore, MemoryKv, PeachyStorage};
    let server = issuer();
    let kv = MemoryKv::new();
    let mut record = public(7).to_vec();
    record.extend_from_slice(b"device-ada-old");
    kv.put(&storage_key(b"own_vouched", &record), &[1]).unwrap();
    kv.flush().unwrap();
    let mut laptop = support::client_on(
        &server,
        2,
        "actor-ada",
        "device-ada-laptop",
        PeachyStorage::open(Box::new(kv)).unwrap(),
    );
    laptop
        .remember_own_approver("device-ada-phone", &public(1))
        .unwrap();
    assert!(laptop.forget_own_device("device-ada-phone").unwrap());
    assert_eq!(
        laptop.check_own_device_key("device-ada-old", &public(7), "", &[]),
        OwnDeviceVerdict::Known
    );
}

/// Forgetting the device that let this one in does not take back the
/// devices this device already holds on its own approval: the person's
/// other devices keep their seats.
#[test]
fn forgetting_one_device_keeps_the_siblings_already_known() {
    let server = issuer();
    let mut phone = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut laptop = client(&server, 2, "actor-ada", "device-ada-laptop");
    let mut tablet = client(&server, 5, "actor-ada", "device-ada-tablet");

    laptop
        .remember_own_approver("device-ada-phone", &public(1))
        .unwrap();
    laptop.create_group(G).unwrap();
    add(&mut laptop, &mut phone, G);
    // The phone, trusted here, seats the tablet; the laptop watches, and
    // checks the tablet's approval by the laptop itself, which puts it on the
    // chain on the laptop's own say.
    let seat = add(&mut phone, &mut tablet, G);
    laptop.process_commit(G, &seat).unwrap();
    let by_laptop = sign_device_approval(&device_seed(2), "device-ada-tablet", &public(5)).unwrap();
    assert_eq!(
        laptop.check_own_device_approval(
            &tablet.generate_key_package().unwrap(),
            "device-ada-laptop",
            &by_laptop
        ),
        OwnDeviceVerdict::Approved
    );

    assert!(laptop.forget_own_device("device-ada-phone").unwrap());
    let tablet_kp = tablet.generate_key_package().unwrap();
    assert_eq!(
        laptop.check_own_device_approval(&tablet_kp, "", &[]),
        OwnDeviceVerdict::Known
    );
}

#[test]
fn a_device_forgets_only_another_device_by_a_real_id() {
    let server = issuer();
    let mut phone = client(&server, 1, "actor-ada", "device-ada-phone");
    assert!(phone.forget_own_device("").is_err());
    assert!(phone.forget_own_device("device-ada-phone").is_err());
}

/// The laptop is removed and a device is minted under its retained key. A
/// contact answers that device's seat ask into an old group, as the seat-ask
/// rules tell it to: Ada is a member there. The phone watches the contact
/// seat it, and still does not trust it: it does not seat it in a group made
/// after the removal. The phone does see it, so the new device notice fires.
#[test]
fn a_leaf_a_contact_seated_does_not_become_known() {
    let server = issuer();
    let mut phone = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut laptop = client(&server, 2, "actor-ada", "device-ada-laptop");
    let mut bo = client(&server, 3, "actor-bo", "device-bo");
    let mut cy = client(&server, 4, "actor-cy", "device-cy");

    phone.create_group(G).unwrap();
    add(&mut phone, &mut bo, G);
    let seat = add(&mut phone, &mut laptop, G);
    bo.process_commit(G, &seat).unwrap();
    remove_device(&mut phone, G, "device-ada-laptop", &mut [&mut bo]);
    assert!(phone.forget_own_device("device-ada-laptop").unwrap());

    phone.create_group(H).unwrap();
    add(&mut phone, &mut cy, H);

    let mut thief = client(&server, 9, "actor-ada", "device-ada-thief");
    let kp = thief.generate_key_package().unwrap();
    assert_eq!(
        phone.check_own_device_approval(&kp, "", &[]),
        OwnDeviceVerdict::Unanchored
    );

    // The seat ask into G, answered by Bo with no pending actors at all.
    let proof = thief.sign_join_request(G).unwrap();
    assert!(bo.first_sight_of_join_request(G, &proof).unwrap());
    let kp = thief.generate_key_package().unwrap();
    assert_eq!(
        bo.verify_join_request(G, "actor-ada", "device-ada-thief", &proof, &kp, &[]),
        JoinRequestVerdict::Accepted
    );
    let bundle = bo.add_member(G, &kp).unwrap();
    bo.merge_pending_commit(G).unwrap();
    phone.process_commit(G, &bundle.commit).unwrap();
    thief.join_from_welcome(&bundle.welcome.unwrap()).unwrap();

    // The phone sees it, so its notice has something to fire on.
    assert!(phone
        .own_sibling_leaves()
        .unwrap()
        .contains(&"device-ada-thief".to_string()));

    // And does not trust it.
    let kp = thief.generate_key_package().unwrap();
    assert_eq!(
        phone.check_own_device_approval(&kp, "", &[]),
        OwnDeviceVerdict::Unanchored
    );
    assert!(gated_own_add(&mut phone, H, &kp, "", &[]).is_none());
    // Nor does it vouch for anything the seated leaf signs.
    let tablet = client(&server, 5, "actor-ada", "device-ada-tablet");
    let by_thief = sign_device_approval(&device_seed(9), "device-ada-tablet", &public(5)).unwrap();
    assert_eq!(
        phone.check_own_device_approval(
            &tablet.generate_key_package().unwrap(),
            "device-ada-thief",
            &by_thief
        ),
        OwnDeviceVerdict::Unanchored
    );
    assert_eq!(phone.roster(H).unwrap().len(), 2);
    assert!(reads(
        &mut cy,
        &mut phone,
        H,
        b"a group made after the removal"
    ));
}

/// A contact-seated leaf counts again once an approval this device can check
/// vouches for the same device and key: the person really let it in.
#[test]
fn an_approval_vouches_for_a_leaf_a_contact_seated() {
    let server = issuer();
    let mut phone = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(&server, 3, "actor-bo", "device-bo");
    let mut tablet = client(&server, 5, "actor-ada", "device-ada-tablet");

    bo.create_group(G).unwrap();
    add(&mut bo, &mut phone, G);
    let seat = add(&mut bo, &mut tablet, G);
    phone.process_commit(G, &seat).unwrap();

    let kp = tablet.generate_key_package().unwrap();
    assert_eq!(
        phone.check_own_device_approval(&kp, "", &[]),
        OwnDeviceVerdict::Unanchored
    );
    let by_phone = sign_device_approval(&device_seed(1), "device-ada-tablet", &public(5)).unwrap();
    assert_eq!(
        phone.check_own_device_approval(&kp, "device-ada-phone", &by_phone),
        OwnDeviceVerdict::Approved
    );
    let kp = tablet.generate_key_package().unwrap();
    assert_eq!(
        phone.check_own_device_approval(&kp, "", &[]),
        OwnDeviceVerdict::Known
    );
}

/// A sibling this device trusts seats a new device. The watched seat alone
/// vouches for nothing; the new device's approval by that sibling does, and
/// from then on it is known.
#[test]
fn a_leaf_a_trusted_sibling_seated_is_known_once_its_approval_verifies() {
    let server = issuer();
    let mut phone = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut laptop = client(&server, 2, "actor-ada", "device-ada-laptop");
    let mut bo = client(&server, 3, "actor-bo", "device-bo");
    let mut tablet = client(&server, 5, "actor-ada", "device-ada-tablet");

    phone.create_group(G).unwrap();
    add(&mut phone, &mut bo, G);
    vouch(&mut phone, 1, &laptop, 2);
    let seat = add(&mut phone, &mut laptop, G);
    bo.process_commit(G, &seat).unwrap();
    let seat = add(&mut laptop, &mut tablet, G);
    phone.process_commit(G, &seat).unwrap();
    bo.process_commit(G, &seat).unwrap();

    let kp = tablet.generate_key_package().unwrap();
    assert_eq!(
        phone.check_own_device_approval(&kp, "", &[]),
        OwnDeviceVerdict::Unanchored
    );
    let by_laptop = sign_device_approval(&device_seed(2), "device-ada-tablet", &public(5)).unwrap();
    assert_eq!(
        phone.check_own_device_approval(&kp, "device-ada-laptop", &by_laptop),
        OwnDeviceVerdict::Approved
    );
    let kp = tablet.generate_key_package().unwrap();
    assert_eq!(
        phone.check_own_device_approval(&kp, "", &[]),
        OwnDeviceVerdict::Known
    );
}

/// A device this device already trusts that a contact seats again (it asked
/// back into a group it had fallen off) stays trusted: only a leaf this
/// device did not already know is held back.
#[test]
fn a_known_sibling_a_contact_seats_again_stays_known() {
    let server = issuer();
    let mut phone = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut laptop = client(&server, 2, "actor-ada", "device-ada-laptop");
    let mut bo = client(&server, 3, "actor-bo", "device-bo");

    phone.create_group(G).unwrap();
    vouch(&mut phone, 1, &laptop, 2);
    add(&mut phone, &mut laptop, G);
    phone.create_group(H).unwrap();
    add(&mut phone, &mut bo, H);
    let seat = add(&mut phone, &mut laptop, H);
    bo.process_commit(H, &seat).unwrap();

    // The laptop falls off H and Bo seats it again.
    remove_device(
        &mut phone,
        H,
        "device-ada-laptop",
        &mut [&mut bo, &mut laptop],
    );
    laptop.forget_group(H).unwrap();
    let kp = laptop.generate_key_package().unwrap();
    let bundle = bo.add_member(H, &kp).unwrap();
    bo.merge_pending_commit(H).unwrap();
    phone.process_commit(H, &bundle.commit).unwrap();
    laptop.join_from_welcome(&bundle.welcome.unwrap()).unwrap();

    let kp = laptop.generate_key_package().unwrap();
    assert_eq!(
        phone.check_own_device_approval(&kp, "", &[]),
        OwnDeviceVerdict::Known
    );
}
