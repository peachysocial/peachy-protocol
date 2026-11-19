// SPDX-License-Identifier: MIT
//! The last-resort key package: reusable until rotated, like a last-resort
//! prekey.
//!
//! A device publishes a pool of one-time packages and one last-resort package.
//! The directory hands out one-time packages first and the last-resort one
//! only when they are gone, without consuming it (`handOutKeyPackages` in
//! the delivery service). These tests hold the core's half: a last-resort
//! package opens any number of Welcomes, a one-time package still opens one,
//! a seat opened with the last-resort package is due a fresh leaf, the
//! rotation clock runs on two days, and a replaced package's private half
//! survives until the thirty-day archive rule drops it.
//!
//! docs/mls-core.md §Last-resort key packages

mod support;

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use peachy_mls_core::issuer::{device_key_pair, TestIssuer};
use peachy_mls_core::{
    Client, ClientConfig, Clock, Incoming, PeachyStorage, LAST_RESORT_ARCHIVE_AGE_SECONDS,
    LAST_RESORT_ROTATION_INTERVAL_SECONDS,
};
use support::{device_seed, issuer, DAY, HOUR, NOW};

#[derive(Debug, Clone)]
struct SharedClock(Arc<AtomicI64>);

impl SharedClock {
    fn new() -> Self {
        Self(Arc::new(AtomicI64::new(NOW)))
    }
    fn set(&self, unix: i64) {
        self.0.store(unix, Ordering::SeqCst);
    }
}

impl Clock for SharedClock {
    fn now_unix(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

const ADA: (u8, &str, &str) = (1, "actor-ada", "device-ada-phone");
const BO: (u8, &str, &str) = (2, "actor-bo", "device-bo-phone");

fn token(server: &TestIssuer, clock: &SharedClock, who: (u8, &str, &str)) -> Vec<u8> {
    let now = clock.now_unix();
    let (_, public) = device_key_pair(&device_seed(who.0));
    server
        .issue(who.1, who.2, &public, now - HOUR, now + 30 * DAY)
        .expect("mint")
}

fn client(server: &TestIssuer, clock: &SharedClock, who: (u8, &str, &str)) -> Client {
    let mut config = ClientConfig::new(
        token(server, clock, who),
        device_seed(who.0),
        server.trusted_keys().expect("trusted keys"),
    )
    .with_storage(PeachyStorage::in_memory())
    .with_own_account_identity(Some(support::held_identity(who.1)));
    config.clock = Some(Box::new(clock.clone()));
    Client::new(config).expect("client")
}

/// The directory's hand-out, in miniature: a one-time package while any is
/// left (consumed), else the last-resort one (not consumed).
struct Directory {
    one_time: Vec<Vec<u8>>,
    last_resort: Vec<u8>,
}

impl Directory {
    fn take(&mut self) -> (Vec<u8>, bool) {
        match self.one_time.pop() {
            Some(package) => (package, false),
            None => (self.last_resort.clone(), true),
        }
    }
}

fn group_id(n: usize) -> Vec<u8> {
    format!("peachy-group-last-resort-{n}").into_bytes()
}

/// Ada founds `group`, adds Bo from `package`, and Bo joins from the Welcome.
fn seat(ada: &mut Client, group: &[u8], package: &[u8]) -> Vec<u8> {
    ada.create_group(group).expect("create");
    let added = ada.add_member(group, package).expect("add bo");
    ada.merge_pending_commit(group).expect("merge");
    added.welcome.expect("welcome")
}

fn talk(ada: &mut Client, bo: &mut Client, group: &[u8]) {
    let words = ada.encrypt(group, b"hello").expect("encrypt");
    match bo.process_message(group, &words).expect("bo reads") {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"hello"),
        other => panic!("expected an application message, got {other:?}"),
    }
    let words = bo.encrypt(group, b"hi").expect("encrypt");
    match ada.process_message(group, &words).expect("ada reads") {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"hi"),
        other => panic!("expected an application message, got {other:?}"),
    }
}

/// Added to more groups than the pool held, with no replenish in between, a
/// last-resort package that opened only ONE Welcome would make every add
/// after it fail with "No matching key package". Fifteen groups from three
/// one-time packages and one last-resort package all join.
#[test]
fn one_package_set_seats_more_than_twelve_groups_with_no_replenish() {
    let server = issuer();
    let clock = SharedClock::new();
    let mut ada = client(&server, &clock, ADA);
    let mut bo = client(&server, &clock, BO);

    let mut directory = Directory {
        one_time: (0..3)
            .map(|_| bo.generate_key_package_with_ref().expect("kp").0)
            .collect(),
        last_resort: bo
            .generate_last_resort_key_package_with_ref()
            .expect("last-resort kp")
            .0,
    };

    let mut served_last_resort = 0;
    for n in 0..15 {
        let group = group_id(n);
        let (package, last_resort) = directory.take();
        served_last_resort += usize::from(last_resort);
        let welcome = seat(&mut ada, &group, &package);
        let joined = bo
            .join_from_welcome(&welcome)
            .unwrap_or_else(|err| panic!("join {n} (last resort: {last_resort}): {err}"));
        assert_eq!(joined, group);
        // A seat opened with the reused package shares its leaf key with every
        // other such seat, so it is due a fresh leaf at once; a one-time seat
        // is as fresh as a rotation.
        assert_eq!(
            bo.leaf_rotation_due(&group).expect("due?"),
            last_resort,
            "group {n}"
        );
        talk(&mut ada, &mut bo, &group);
    }
    assert_eq!(served_last_resort, 12);

    // The fresh leaf the last-resort seats owe is an ordinary self-update.
    let group = group_id(14);
    let update = bo.refresh_credential(&group).expect("rotate");
    bo.merge_pending_commit(&group).expect("merge");
    ada.process_commit(&group, &update.commit)
        .expect("ada applies");
    assert!(!bo.leaf_rotation_due(&group).expect("due?"));
    talk(&mut ada, &mut bo, &group);
}

/// One-time packages are still single-use: the same one served twice opens
/// only the first Welcome.
#[test]
fn a_one_time_package_still_opens_one_welcome() {
    let server = issuer();
    let clock = SharedClock::new();
    let mut ada = client(&server, &clock, ADA);
    let mut bo = client(&server, &clock, BO);
    let package = bo.generate_key_package_with_ref().expect("kp").0;

    let first = seat(&mut ada, &group_id(1), &package);
    bo.join_from_welcome(&first).expect("first join");
    let second = seat(&mut ada, &group_id(2), &package);
    assert!(
        bo.join_from_welcome(&second).is_err(),
        "a one-time package's private half is gone after its first Welcome"
    );
}

/// The rotation clock: due before any last-resort package exists, not due
/// for two days after one is minted, due again from then on.
#[test]
fn the_last_resort_package_rotates_every_two_days() {
    let server = issuer();
    let clock = SharedClock::new();
    let bo = client(&server, &clock, BO);
    assert!(bo.last_resort_rotation_due().expect("due?"));
    // A one-time package is not one.
    bo.generate_key_package_with_ref().expect("kp");
    assert!(bo.last_resort_rotation_due().expect("due?"));

    bo.generate_last_resort_key_package_with_ref().expect("kp");
    assert!(!bo.last_resort_rotation_due().expect("due?"));
    clock.set(NOW + LAST_RESORT_ROTATION_INTERVAL_SECONDS - 1);
    assert!(!bo.last_resort_rotation_due().expect("due?"));
    clock.set(NOW + LAST_RESORT_ROTATION_INTERVAL_SECONDS);
    assert!(bo.last_resort_rotation_due().expect("due?"));

    bo.generate_last_resort_key_package_with_ref().expect("kp");
    assert!(!bo.last_resort_rotation_due().expect("due?"));
    // A clock that went backwards is due.
    clock.set(NOW - HOUR);
    assert!(bo.last_resort_rotation_due().expect("due?"));
}

/// A replaced last-resort package keeps opening Welcomes sealed to it before
/// the rotation, until the archive rule drops it: older than thirty
/// days, not the current one, and not the youngest of those.
#[test]
fn a_replaced_last_resort_package_opens_welcomes_until_archived() {
    let server = issuer();
    let clock = SharedClock::new();
    let mut ada = client(&server, &clock, ADA);
    let mut bo = client(&server, &clock, BO);

    let first = bo
        .generate_last_resort_key_package_with_ref()
        .expect("kp")
        .0;
    clock.set(NOW + LAST_RESORT_ROTATION_INTERVAL_SECONDS);
    let second = bo
        .generate_last_resort_key_package_with_ref()
        .expect("kp")
        .0;

    // An adder that fetched the first package before the rotation.
    let welcome = seat(&mut ada, &group_id(1), &first);
    bo.join_from_welcome(&welcome)
        .expect("the replaced package still opens");

    // Two more Welcomes sealed now and read only after the archive runs.
    let late_to_first = seat(&mut ada, &group_id(2), &first);
    let late_to_second = seat(&mut ada, &group_id(3), &second);

    // Forty days on, a third rotation archives: the first (40 days old) goes,
    // the second (38 days, the youngest past the age) stays, the third is
    // current. Bo renews first: no core mints under a dead credential.
    let later = NOW + 40 * DAY;
    clock.set(later);
    assert!(
        later - (NOW + LAST_RESORT_ROTATION_INTERVAL_SECONDS) > LAST_RESORT_ARCHIVE_AGE_SECONDS
    );
    bo.update_credential(&token(&server, &clock, BO), None)
        .expect("bo renews");
    bo.generate_last_resort_key_package_with_ref().expect("kp");

    bo.join_from_welcome(&late_to_second)
        .expect("the youngest archived package is kept");
    assert!(
        bo.join_from_welcome(&late_to_first).is_err(),
        "a package past the archive age is deleted"
    );
}
