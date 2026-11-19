// SPDX-License-Identifier: MIT
//! A device the account removed is forgotten by every device that hears of
//! it (`Client::forget_own_device`), and once forgotten nothing it held counts
//! again: not its id, not its key, at any door. And an id is a name for a
//! row, never free text, so it cannot hide one device behind another.
//!
//! - **The Welcome gate judges this device's own person as a device.** A
//!   Welcome signed by a forgotten device (by id or key) is refused into any
//!   group, known or new. A Welcome into a group this device knew, signed by
//!   any other device of its own person that it does not trust (its own id,
//!   a leaf it saw seated from outside the gate), is taken and marked
//!   untrusted in the rejoin report: the account key all of the person's
//!   devices share proves nothing about which signed.
//! - **Forgetting is by key as well as id.** The account's certificate covers
//!   a device key, never the id the server files it under, so a removed
//!   device's key listed again under a fresh id is the same removed device.
//! - **Ids are 1-64 bytes of `[A-Za-z0-9._-]`.** A credential naming any
//!   other id is malformed, so no id can carry a list separator or the `#`
//!   of the long form the new-device notice is told.
//! - **A seat this device made on no verdict is no anchor.** An own add on
//!   a verdict that does not seat is not evidence.
//! - **A forgotten device's seat ask is not a member's.**
//! - **No add of this device seats a forgotten device**, a founding's
//!   included, whatever the own-device check answers: a founding names its package among
//!   the refusals like any other, and the later ordinary add refuses it too.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use peachy_mls_core::issuer::device_key_pair;
use peachy_mls_core::{
    is_valid_id, sign_device_approval, Client, CredentialRejection, DeviceCredential, Error,
    Incoming, JoinRequestVerdict, OwnDeviceVerdict, SEND_KEY_LABEL,
};
use sha2::{Digest, Sha256};
use support::{client, credential_token, device_seed, issuer, past_the_mark};

const G: &[u8] = b"66666666-6666-4666-8666-666666666666";
const H: &[u8] = b"77777777-7777-4777-8777-777777777777";

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

fn reads(sender: &mut Client, reader: &mut Client, group: &[u8], text: &[u8]) -> bool {
    let Ok(wire) = sender.encrypt(group, text) else {
        return false;
    };
    match reader.process_message(group, &wire) {
        Ok(Incoming::Application { plaintext, .. }) => plaintext == text,
        _ => false,
    }
}

fn head_of(c: &Client, group: &[u8]) -> (u64, [u8; 32]) {
    let epoch = c.epoch(group).unwrap();
    let verifier: [u8; 32] =
        Sha256::digest(c.export_secret(group, SEND_KEY_LABEL, group, 32).unwrap()).into();
    (epoch, verifier)
}

fn public(tag: u8) -> [u8; 32] {
    device_key_pair(&device_seed(tag)).1
}

/// Bo's group G holds Ada's laptop, phone and tablet. The phone is stolen:
/// Ada removes it on the laptop, which forgets it and sweeps its leaf; the
/// tablet hears of the removal and forgets it too.
fn phone_removed() -> (Client, Client, Client, Client) {
    let server = issuer();
    let mut laptop = client(&server, 1, "actor-ada", "device-ada-laptop");
    let mut phone = client(&server, 2, "actor-ada", "device-ada-phone");
    let mut tablet = client(&server, 5, "actor-ada", "device-ada-tablet");
    let mut bo = client(&server, 3, "actor-bo", "device-bo");
    bo.create_group(G).unwrap();
    add(&mut bo, &mut laptop, G);
    let c1 = add(&mut bo, &mut phone, G);
    laptop.process_commit(G, &c1).unwrap();
    let c2 = add(&mut bo, &mut tablet, G);
    laptop.process_commit(G, &c2).unwrap();
    phone.process_commit(G, &c2).unwrap();

    assert!(laptop.forget_own_device("device-ada-phone").unwrap());
    assert!(tablet.forget_own_device("device-ada-phone").unwrap());
    let leaf = laptop.leaf_of_device(G, "device-ada-phone").unwrap();
    let removal = laptop.remove_leaf(G, leaf).unwrap();
    laptop.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &removal.commit).unwrap();
    tablet.process_commit(G, &removal.commit).unwrap();
    match phone.process_commit(G, &removal.commit).unwrap() {
        Incoming::Commit(outcome) => assert!(outcome.removed_self),
        other => panic!("{other:?}"),
    }
    (laptop, phone, tablet, bo)
}

// ---------------------------------------------------------------------------
// The Welcome gate
// ---------------------------------------------------------------------------

/// No honest build sends from a device the account removed (the server signs
/// it out with the removal), so a forgotten device's Welcome is refused:
/// otherwise the laptop's next message to Bo's group would go to the stolen
/// phone, and the report would name only Ada.
#[test]
fn a_forgotten_own_device_cannot_move_this_device_into_its_own_group() {
    let (mut laptop, mut phone, _tablet, _bo) = phone_removed();
    laptop.forget_group(G).unwrap();
    phone.forget_group(G).unwrap();
    phone.create_group(G).unwrap();
    past_the_mark(&mut phone, G);
    let kp = laptop.generate_key_package().unwrap();
    let by_phone = phone.add_member(G, &kp).unwrap();
    phone.merge_pending_commit(G).unwrap();
    assert!(matches!(
        laptop.join_from_welcome(&by_phone.welcome.unwrap()),
        Err(Error::WelcomeFromOutsider)
    ));
    assert!(!laptop.is_active(G).unwrap_or(false));
    assert!(!reads(
        &mut laptop,
        &mut phone,
        G,
        b"meet at 7, door code 4411"
    ));
    assert_eq!(laptop.take_rejoin_report(G).unwrap(), None);
    assert_eq!(laptop.welcome_sender(G).unwrap(), None);
}

#[test]
fn a_forgotten_own_device_cannot_replace_an_active_group_by_the_contested_path() {
    let (mut laptop, mut phone, _tablet, _bo) = phone_removed();
    phone.forget_group(G).unwrap();
    phone.create_group(G).unwrap();
    past_the_mark(&mut phone, G);
    let w = phone
        .add_member(G, &laptop.generate_key_package().unwrap())
        .unwrap();
    phone.merge_pending_commit(G).unwrap();
    assert!(matches!(
        laptop.join_from_welcome(&w.welcome.unwrap()),
        Err(Error::AlreadyAMember)
    ));
    // The server reports the impostor's head; the gate still refuses.
    let (e, v) = head_of(&phone, G);
    assert!(matches!(
        laptop.join_contested_welcome(e, &v),
        Err(Error::WelcomeFromOutsider)
    ));
    assert!(laptop.is_active(G).unwrap());
}

/// Nor does a forgotten device seat this one in a group it never knew,
/// where it would read as one of the person's own devices founding it
/// (`welcome_sender` is the person's own actor).
#[test]
fn a_forgotten_device_cannot_seat_this_device_in_a_new_group() {
    let (mut laptop, mut phone, _tablet, _bo) = phone_removed();
    phone.create_group(H).unwrap();
    let w = phone
        .add_member(H, &laptop.generate_key_package().unwrap())
        .unwrap();
    phone.merge_pending_commit(H).unwrap();
    assert!(matches!(
        laptop.join_from_welcome(&w.welcome.unwrap()),
        Err(Error::WelcomeFromOutsider)
    ));
    assert!(!laptop.is_active(H).unwrap_or(false));
    assert_eq!(laptop.welcome_sender(H).unwrap(), None);
}

/// Forgotten by key too: the removed phone's key re-certified under a fresh
/// id seats nobody in a new group.
#[test]
fn a_forgotten_key_under_a_fresh_id_seats_nobody() {
    let (mut laptop, _phone, _tablet, _bo) = phone_removed();
    let server = issuer();
    let mut ghost = client(&server, 2, "actor-ada", "device-ada-ghost");
    ghost.create_group(H).unwrap();
    let w = ghost
        .add_member(H, &laptop.generate_key_package().unwrap())
        .unwrap();
    ghost.merge_pending_commit(H).unwrap();
    assert!(matches!(
        laptop.join_from_welcome(&w.welcome.unwrap()),
        Err(Error::WelcomeFromOutsider)
    ));
}

/// A device of the person's own that this device does not trust but did not
/// forget (here, one a contact seated) is taken, and the report says so, so
/// the conversation can tell it from one of the person's own devices. A trusted sibling's re-add is not marked
/// (`a_trusted_sibling_known_only_in_the_forgotten_group_still_re_adds_this_device`).
#[test]
fn an_untrusted_own_devices_re_add_is_reported_untrusted() {
    let server = issuer();
    let mut laptop = client(&server, 1, "actor-ada", "device-ada-laptop");
    let mut bo = client(&server, 3, "actor-bo", "device-bo");
    bo.create_group(G).unwrap();
    add(&mut bo, &mut laptop, G);
    let mut stranger = client(&server, 8, "actor-ada", "device-ada-stranger");
    let c = add(&mut bo, &mut stranger, G);
    laptop.process_commit(G, &c).unwrap();
    laptop.forget_group(G).unwrap();

    let leaf = stranger.leaf_of_device(G, "device-ada-laptop").unwrap();
    let bundle = stranger
        .replace_member(G, leaf, &laptop.generate_key_package().unwrap())
        .unwrap();
    stranger.merge_pending_commit(G).unwrap();
    assert_eq!(
        laptop.join_from_welcome(&bundle.welcome.unwrap()).unwrap(),
        G
    );
    let report = laptop.take_rejoin_report(G).unwrap().expect("a report");
    assert_eq!(report.readded_by, "actor-ada");
    assert_eq!(report.readded_by_device, "device-ada-stranger");
    assert!(report.readded_by_untrusted);
}

#[test]
fn a_trusted_sibling_known_only_in_the_forgotten_group_still_re_adds_this_device() {
    let server = issuer();
    let mut laptop = client(&server, 1, "actor-ada", "device-ada-laptop");
    let mut tablet = client(&server, 5, "actor-ada", "device-ada-tablet");
    let mut bo = client(&server, 3, "actor-bo", "device-bo");
    bo.create_group(G).unwrap();
    add(&mut bo, &mut laptop, G);
    // The laptop approved the tablet, and seats it on that approval.
    let approval = sign_device_approval(&device_seed(1), "device-ada-tablet", &public(5)).unwrap();
    let kp = tablet.generate_key_package().unwrap();
    assert_eq!(
        laptop.check_own_device_approval(&kp, "device-ada-laptop", &approval),
        OwnDeviceVerdict::Approved
    );
    let bundle = laptop.add_member(G, &kp).unwrap();
    laptop.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &bundle.commit).unwrap();
    tablet.join_from_welcome(&bundle.welcome.unwrap()).unwrap();

    // G is the only group the laptop holds, so once it forgets G the tablet
    // is known to it only through what it kept of G.
    laptop.forget_group(G).unwrap();
    let leaf = tablet.leaf_of_device(G, "device-ada-laptop").unwrap();
    let bundle = tablet
        .replace_member(G, leaf, &laptop.generate_key_package().unwrap())
        .unwrap();
    tablet.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &bundle.commit).unwrap();
    assert_eq!(
        laptop.join_from_welcome(&bundle.welcome.unwrap()).unwrap(),
        G
    );
    let report = laptop.take_rejoin_report(G).unwrap().expect("a report");
    assert_eq!(report.readded_by, "actor-ada");
    assert_eq!(report.readded_by_device, "device-ada-tablet");
    assert!(!report.readded_by_untrusted);
    assert!(reads(&mut bo, &mut laptop, G, b"welcome back"));
}

// ---------------------------------------------------------------------------
// Forgetting by key
// ---------------------------------------------------------------------------

#[test]
fn a_forgotten_key_under_a_fresh_id_is_never_trusted() {
    let (mut laptop, _phone, _tablet, mut bo) = phone_removed();
    let server = issuer();

    // The server re-certifies the removed phone's KEY (seed 2) under an id it
    // chose. The account certificate covers the key only.
    let mut ghost = client(&server, 2, "actor-ada", "device-ada-ghost");

    // The contested path refuses it.
    ghost.create_group(G).unwrap();
    past_the_mark(&mut ghost, G);
    let w = ghost
        .add_member(G, &laptop.generate_key_package().unwrap())
        .unwrap();
    ghost.merge_pending_commit(G).unwrap();
    assert!(matches!(
        laptop.join_from_welcome(&w.welcome.unwrap()),
        Err(Error::AlreadyAMember)
    ));
    let (e, v) = head_of(&ghost, G);
    assert!(matches!(
        laptop.join_contested_welcome(e, &v),
        Err(Error::WelcomeFromOutsider)
    ));

    // A contact seats the ghost in a group the laptop then joins: a leaf it
    // takes as the tree shows it. The key is still forgotten.
    bo.create_group(H).unwrap();
    add(&mut bo, &mut ghost, H);
    add(&mut bo, &mut laptop, H);
    let kp = ghost.generate_key_package().unwrap();
    assert_eq!(
        laptop.check_own_device_approval(&kp, "", &[]),
        OwnDeviceVerdict::Unanchored
    );
    assert!(!laptop
        .own_device_anchors()
        .unwrap()
        .iter()
        .any(|(_, key)| key.as_slice() == public(2)));
    // Nor do its approvals vouch for anybody.
    let next = client(&server, 9, "actor-ada", "device-ada-next");
    let approval = sign_device_approval(&device_seed(2), "device-ada-next", &public(9)).unwrap();
    assert_eq!(
        laptop.check_own_device_approval(
            &next.generate_key_package().unwrap(),
            "device-ada-ghost",
            &approval
        ),
        OwnDeviceVerdict::Unanchored
    );
}

#[test]
fn the_device_lists_key_is_forgotten_with_the_id() {
    let server = issuer();
    let laptop = client(&server, 1, "actor-ada", "device-ada-laptop");
    let mut bo = client(&server, 3, "actor-bo", "device-bo");
    let mut laptop = laptop;
    // The laptop never shared a group with the phone; the list names its key.
    assert!(laptop
        .forget_own_device_with_key("device-ada-phone", &public(2))
        .unwrap());
    // Forgetting again with no new key is a no-op; a key not seen before
    // for the id is news.
    assert!(!laptop
        .forget_own_device_with_key("device-ada-phone", &public(2))
        .unwrap());
    assert!(!laptop.forget_own_device("device-ada-phone").unwrap());
    assert!(laptop
        .forget_own_device_with_key("device-ada-phone", &public(12))
        .unwrap());
    let mut ghost = client(&server, 2, "actor-ada", "device-ada-ghost");
    bo.create_group(H).unwrap();
    add(&mut bo, &mut ghost, H);
    add(&mut bo, &mut laptop, H);
    let kp = ghost.generate_key_package().unwrap();
    assert_eq!(
        laptop.check_own_device_approval(&kp, "", &[]),
        OwnDeviceVerdict::Unanchored
    );
    // The laptop's own key is never forgotten, whoever lists it.
    assert!(laptop
        .forget_own_device_with_key("device-ada-other", &public(1))
        .unwrap());
    assert!(laptop
        .own_device_anchors()
        .unwrap()
        .iter()
        .any(|(id, key)| id == "device-ada-laptop" && key.as_slice() == public(1)));
    // A key that is not 32 bytes is refused.
    assert!(laptop
        .forget_own_device_with_key("device-ada-x", &[1, 2, 3])
        .is_err());
}

// ---------------------------------------------------------------------------
// Ids
// ---------------------------------------------------------------------------

#[test]
fn ids_outside_the_charset_are_malformed() {
    let server = issuer();
    for (actor, device) in [
        ("actor-ada", "a\nb"),
        ("actor-ada", "a\u{0}b"),
        ("actor-ada", "a#00ff"),
        ("actor-ada", "a/b"),
        ("actor-ada", " "),
        ("actor-ada", "device-ada-phone\ndevice-ada-tablet"),
        ("actor-bo\nactor-zed", "device-bo"),
        ("actor-ada", &"x".repeat(65)),
    ] {
        let token = credential_token(&server, 6, actor, device);
        assert!(
            matches!(
                DeviceCredential::parse(&token),
                Err(Error::CredentialRejected(CredentialRejection::Malformed))
            ),
            "{actor:?} / {device:?}"
        );
    }
    for good in [
        "0f1e2d3c-4b5a-4968-8776-655443322110",
        "device-ada-laptop",
        "a.b_c-D9",
        &"x".repeat(64),
    ] {
        assert!(is_valid_id(good), "{good:?}");
        let token = credential_token(&server, 6, "actor-ada", good);
        assert!(DeviceCredential::parse(&token).is_ok(), "{good:?}");
    }
}

#[test]
fn an_id_argument_outside_the_charset_is_refused() {
    let server = issuer();
    let mut laptop = client(&server, 1, "actor-ada", "device-ada-laptop");
    laptop.create_group(G).unwrap();
    for bad in ["", "a\nb", "a#b", "a b"] {
        assert!(laptop.forget_own_device(bad).is_err(), "{bad:?}");
        assert!(laptop.leaf_of_device(G, bad).is_err(), "{bad:?}");
        assert!(
            laptop.remember_own_approver(bad, &public(2)).is_err(),
            "{bad:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// A seat made on no verdict
// ---------------------------------------------------------------------------

#[test]
fn a_seat_this_device_made_on_no_verdict_is_no_anchor() {
    let server = issuer();
    let mut laptop = client(&server, 1, "actor-ada", "device-ada-laptop");
    let mut phone = client(&server, 2, "actor-ada", "device-ada-phone");
    laptop.create_group(G).unwrap();
    add(&mut laptop, &mut phone, G);

    // A device minted with a retained account key, no approval.
    let mut thief = client(&server, 9, "actor-ada", "device-ada-thief");
    let thief_kp = thief.generate_key_package().unwrap();
    assert_eq!(
        laptop.check_own_device_approval(&thief_kp, "", &[]),
        OwnDeviceVerdict::Unanchored
    );
    // Added on a verdict that does not seat; that seat makes it no anchor.
    let bundle = laptop.add_member(G, &thief_kp).unwrap();
    laptop.merge_pending_commit(G).unwrap();
    phone.process_commit(G, &bundle.commit).unwrap();
    thief.join_from_welcome(&bundle.welcome.unwrap()).unwrap();

    // Once enforcement starts, the laptop does not take its approvals, and
    // does not know it.
    let second = client(&server, 10, "actor-ada", "device-ada-thief-2");
    let approval =
        sign_device_approval(&device_seed(9), "device-ada-thief-2", &public(10)).unwrap();
    assert_eq!(
        laptop.check_own_device_approval(
            &second.generate_key_package().unwrap(),
            "device-ada-thief",
            &approval
        ),
        OwnDeviceVerdict::Unanchored
    );
    assert_eq!(
        laptop.check_own_device_approval(&thief.generate_key_package().unwrap(), "", &[]),
        OwnDeviceVerdict::Unanchored
    );
}

#[test]
fn a_seat_this_device_made_on_a_verdict_still_vouches() {
    let server = issuer();
    let mut laptop = client(&server, 1, "actor-ada", "device-ada-laptop");
    laptop.create_group(G).unwrap();
    let mut phone = client(&server, 2, "actor-ada", "device-ada-phone");
    // The laptop approved the phone and checks that approval before seating.
    let approval = sign_device_approval(&device_seed(1), "device-ada-phone", &public(2)).unwrap();
    let kp = phone.generate_key_package().unwrap();
    assert_eq!(
        laptop.check_own_device_approval(&kp, "device-ada-laptop", &approval),
        OwnDeviceVerdict::Approved
    );
    let bundle = laptop.add_member(G, &kp).unwrap();
    laptop.merge_pending_commit(G).unwrap();
    phone.join_from_welcome(&bundle.welcome.unwrap()).unwrap();
    // The phone's own approval of a tablet vouches on the laptop.
    let tablet = client(&server, 5, "actor-ada", "device-ada-tablet");
    let approval = sign_device_approval(&device_seed(2), "device-ada-tablet", &public(5)).unwrap();
    assert_eq!(
        laptop.check_own_device_approval(
            &tablet.generate_key_package().unwrap(),
            "device-ada-phone",
            &approval
        ),
        OwnDeviceVerdict::Approved
    );
}

// ---------------------------------------------------------------------------
// Seat asks
// ---------------------------------------------------------------------------

#[test]
fn a_forgotten_devices_seat_ask_is_not_a_members() {
    let (laptop, phone, _tablet, _bo) = phone_removed();
    let proof = phone.sign_join_request(G).unwrap();
    let kp = phone.generate_key_package().unwrap();
    assert_eq!(
        laptop.verify_join_request(G, "actor-ada", "device-ada-phone", &proof, &kp, &[]),
        JoinRequestVerdict::NotAMember
    );
    // The same key under a fresh id is the same removed device.
    let server = issuer();
    let ghost = client(&server, 2, "actor-ada", "device-ada-ghost");
    let proof = ghost.sign_join_request(G).unwrap();
    let kp = ghost.generate_key_package().unwrap();
    assert_eq!(
        laptop.verify_join_request(G, "actor-ada", "device-ada-ghost", &proof, &kp, &[]),
        JoinRequestVerdict::NotAMember
    );
}

// ---------------------------------------------------------------------------
// Adds and foundings
// ---------------------------------------------------------------------------

const FOUNDING_STATE: &str = r#"{"v":1,"n":"","adm":["actor-ada","actor-bo"],"dm":true}"#;

#[test]
fn founding_and_the_later_add_refuse_a_forgotten_own_device() {
    let server = issuer();
    let mut laptop = client(&server, 1, "actor-ada", "device-ada-laptop");
    let phone = client(&server, 2, "actor-ada", "device-ada-phone");
    let tablet = client(&server, 4, "actor-ada", "device-ada-tablet");
    let bo = client(&server, 3, "actor-bo", "device-bo");

    let phone_key = phone.identity().device_key;
    laptop
        .forget_own_device_with_key("device-ada-phone", &phone_key)
        .unwrap();

    let own = laptop.generate_key_package().unwrap();
    let phone_kp = phone.generate_key_package().unwrap();
    let bo_kp = bo.generate_key_package().unwrap();
    let tablet_kp = tablet.generate_key_package().unwrap();

    laptop.create_group(H).unwrap();
    let all = vec![phone_kp.clone(), bo_kp.clone(), tablet_kp.clone()];
    // Named among the refusals, by index, like any other refused package.
    assert_eq!(laptop.founding_refusals(H, &all).unwrap(), vec![0]);
    laptop.set_group_meta(H, FOUNDING_STATE.as_bytes()).unwrap();
    laptop.merge_pending_commit(H).unwrap();
    // A founding that carries it is refused whole.
    assert!(laptop.seat_founding(H, &all, &own).is_err());
    let kept = vec![bo_kp, tablet_kp];
    laptop.seat_founding(H, &kept, &own).unwrap();
    laptop.merge_pending_commit(H).unwrap();
    // The sibling it did not forget is seated; the forgotten phone is not.
    assert!(laptop.leaf_of_device(H, "device-ada-tablet").is_ok());
    assert!(laptop.leaf_of_device(H, "device-ada-phone").is_err());
    // The ordinary add that follows a founding refuses it too.
    assert!(laptop.add_member(H, &phone_kp).is_err());
    assert!(laptop.leaf_of_device(H, "device-ada-phone").is_err());
}

#[test]
fn a_forgotten_key_under_a_fresh_id_is_left_out_of_a_founding() {
    let server = issuer();
    let mut laptop = client(&server, 1, "actor-ada", "device-ada-laptop");
    let phone = client(&server, 2, "actor-ada", "device-ada-phone");
    // Same seed, so the same device key, filed under a fresh id.
    let relabelled = client(&server, 2, "actor-ada", "device-ada-new");
    let bo = client(&server, 3, "actor-bo", "device-bo");

    let phone_key = phone.identity().device_key;
    laptop
        .forget_own_device_with_key("device-ada-phone", &phone_key)
        .unwrap();

    let relabelled_kp = relabelled.generate_key_package().unwrap();
    let bo_kp = bo.generate_key_package().unwrap();
    laptop.create_group(H).unwrap();
    let all = vec![bo_kp, relabelled_kp];
    assert_eq!(laptop.founding_refusals(H, &all).unwrap(), vec![1]);
}
