// SPDX-License-Identifier: MIT
//! An own-account device that is on no approval chain never moves this
//! device into a group of its own unannounced.
//!
//! An own-account device on no approval chain that Welcomes this device into
//! a group of its own under the same id is drawn as from a device of this
//! person's that this device does not trust; the real group's Welcome at the
//! head then replaces it.
//! docs/delivery.md §A Welcome into a group this device knew.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use peachy_mls_core::issuer::{device_key_pair, TestIssuer};
use peachy_mls_core::{
    generate_account_key, Client, ClientConfig, Error, FixedClock, Incoming, OwnDeviceVerdict,
    PeachyStorage, SEND_KEY_LABEL,
};
use sha2::{Digest, Sha256};
use support::{device_seed, issuer, past_the_mark, DAY, HOUR, NOW};

const G: &[u8] = b"66666666-6666-4666-8666-666666666666";

fn public(tag: u8) -> [u8; 32] {
    device_key_pair(&device_seed(tag)).1
}

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

fn reads(sender: &mut Client, reader: &mut Client, group: &[u8], text: &[u8]) -> bool {
    let Ok(wire) = sender.encrypt(group, text) else {
        return false;
    };
    matches!(
        reader.process_message(group, &wire),
        Ok(Incoming::Application { plaintext, .. }) if plaintext == text
    )
}

fn head_of(c: &Client) -> (u64, [u8; 32]) {
    let e = c.epoch(G).unwrap();
    let v: [u8; 32] = Sha256::digest(c.export_secret(G, SEND_KEY_LABEL, G, 32).unwrap()).into();
    (e, v)
}

/// Ada's laptop; its approver, removed and forgotten; a sibling of Ada's on
/// no chain (`device-ada-new`), seated by Bo before the laptop joins.
fn setup() -> (Client, Client, Client) {
    let server = issuer();
    let ada_key = generate_account_key().unwrap();
    let mut laptop = certified(&server, 1, "actor-ada", "device-ada-laptop", &ada_key);
    laptop
        .remember_own_approver("device-ada-phone", &public(2))
        .unwrap();
    assert!(laptop
        .forget_own_device_with_key("device-ada-phone", &public(2))
        .unwrap());
    let mut sibling = certified(&server, 9, "actor-ada", "device-ada-new", &ada_key);
    let mut bo = certified(
        &server,
        3,
        "actor-bo",
        "device-bo",
        &generate_account_key().unwrap(),
    );
    bo.create_group(G).unwrap();
    let kp = sibling.generate_key_package().unwrap();
    let a = bo.add_member(G, &kp).unwrap();
    bo.merge_pending_commit(G).unwrap();
    support::join_at_head(&mut sibling, &a.welcome.unwrap(), head_of(&bo)).unwrap();
    let kp = laptop.generate_key_package().unwrap();
    let b = bo.add_member(G, &kp).unwrap();
    bo.merge_pending_commit(G).unwrap();
    sibling.process_commit(G, &b.commit).unwrap();
    support::join_at_head(&mut laptop, &b.welcome.unwrap(), head_of(&bo)).unwrap();
    // The sibling is on no chain here: no history, no seat, no approvals.
    assert_eq!(
        laptop.check_own_device_key("device-ada-new", &public(9), "", &[]),
        OwnDeviceVerdict::Unanchored
    );
    (laptop, sibling, bo)
}

/// The sibling removes the laptop from the real G; Bo and the laptop apply it.
fn sibling_removes_laptop(laptop: &mut Client, sibling: &mut Client, bo: &mut Client) {
    let leaf = sibling.leaf_of_device(G, "device-ada-laptop").unwrap();
    let removal = sibling
        .remove_leaf(G, leaf)
        .expect("own-account removal is allowed");
    sibling.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &removal.commit).expect("Bo takes it");
    match laptop
        .process_commit(G, &removal.commit)
        .expect("laptop takes it")
    {
        Incoming::Commit(outcome) => assert!(outcome.removed_self),
        other => panic!("{other:?}"),
    }
    assert!(!laptop.is_active(G).unwrap());
}

/// The sibling's group under G's id, with the laptop in it, pumped well past
/// the real group's epoch so the epoch mark refuses none of it.
fn impostor_welcome(sibling: &mut Client, laptop: &Client) -> Vec<u8> {
    sibling.forget_group(G).unwrap();
    sibling.create_group(G).unwrap();
    past_the_mark(sibling, G);
    let w = sibling
        .add_member(G, &laptop.generate_key_package().unwrap())
        .unwrap();
    sibling.merge_pending_commit(G).unwrap();
    w.welcome.unwrap()
}

/// An unchained sibling's Welcome replaces a group the laptop is still
/// active in only at a head the server names, and is drawn untrusted.
#[test]
fn an_unchained_siblings_replace_of_a_live_group_is_reported_untrusted() {
    let (mut laptop, mut sibling, _bo) = setup();
    let welcome = impostor_welcome(&mut sibling, &laptop);
    assert!(matches!(
        laptop.join_from_welcome(&welcome),
        Err(Error::AlreadyAMember)
    ));
    let (epoch, verifier) = head_of(&sibling);
    assert_eq!(laptop.join_contested_welcome(epoch, &verifier).unwrap(), G);
    let report = laptop.take_rejoin_report(G).unwrap().expect("report");
    assert_eq!(report.readded_by_device, "device-ada-new");
    assert!(report.readded_by_untrusted, "{report:?}");
}

/// The sibling removes the laptop first, then Welcomes it into its own G,
/// before or after the laptop's app forgets the group: the Welcome is taken,
/// and the report says so: the unchained sibling is NOT reported as trusted.
#[test]
fn an_unchained_siblings_restore_is_reported_untrusted() {
    for forget in [false, true] {
        let (mut laptop, mut sibling, mut bo) = setup();
        sibling_removes_laptop(&mut laptop, &mut sibling, &mut bo);
        if forget {
            laptop.forget_group(G).unwrap();
        }
        let welcome = impostor_welcome(&mut sibling, &laptop);
        assert_eq!(laptop.join_from_welcome(&welcome).unwrap(), G);
        let report = laptop.take_rejoin_report(G).unwrap().expect("report");
        assert_eq!(report.readded_by, "actor-ada");
        assert_eq!(report.readded_by_device, "device-ada-new");
        assert!(report.readded_by_untrusted, "forget: {forget}");
    }
}

/// The genuine re-add after the sibling's: Bo answers the laptop's seat ask
/// with an add into the real G, and the laptop takes it at the head, before
/// and after forgetting the group. Both re-adds are drawn, in order.
#[test]
fn the_real_groups_re_add_still_seats_this_device() {
    for forget in [false, true] {
        let (mut laptop, mut sibling, mut bo) = setup();
        sibling_removes_laptop(&mut laptop, &mut sibling, &mut bo);
        let welcome = impostor_welcome(&mut sibling, &laptop);
        assert_eq!(laptop.join_from_welcome(&welcome).unwrap(), G);
        if forget {
            laptop.forget_group(G).unwrap();
        }

        let kp = laptop.generate_key_package().unwrap();
        let real = bo.add_member(G, &kp).unwrap();
        bo.merge_pending_commit(G).unwrap();
        assert_eq!(
            support::join_at_head(&mut laptop, &real.welcome.unwrap(), head_of(&bo)).unwrap(),
            G,
            "forget: {forget}"
        );
        let report = laptop.take_rejoin_report(G).unwrap().expect("report");
        assert!(report.readded_by_untrusted, "the sibling's, first");
        let report = laptop.take_rejoin_report(G).unwrap().expect("report");
        assert_eq!(report.readded_by, "actor-bo");
        assert!(!report.readded_by_untrusted);
        assert_eq!(head_of(&laptop), head_of(&bo));
        assert!(reads(&mut laptop, &mut bo, G, b"back in the real G"));
    }
}
