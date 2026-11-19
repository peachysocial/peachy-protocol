// SPDX-License-Identifier: MIT
//! The periodic leaf rotation: post-compromise security on a schedule.
//!
//! An attacker who copies a device's leaf HPKE key reads every epoch of the
//! group until that device commits a new leaf. These tests hold the schedule
//! that makes it do so — after LEAF_ROTATION_INTERVAL_SECONDS, or after
//! LEAF_ROTATION_FRAME_BUDGET frames sealed on one leaf, or, in a group that
//! seats two people, once the other person was heard from and the leaf is
//! ROUND_TRIP_ROTATION_MIN_SECONDS old — and that the
//! rotation rides the renewal door every client already calls before a send
//! and at app start or foreground (never on opening a conversation), so it
//! needs no client code of its own.
//!
//! docs/mls-core.md §Periodic leaf rotation

mod support;

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use peachy_mls_core::issuer::{device_key_pair, TestIssuer};
use peachy_mls_core::{
    Client, ClientConfig, Clock, Incoming, MemoryKv, PeachyStorage, LEAF_ROTATION_FRAME_BUDGET,
    LEAF_ROTATION_INTERVAL_SECONDS, ROUND_TRIP_ROTATION_MIN_SECONDS,
};
use support::{device_seed, issuer, DAY, HOUR, NOW};

const GROUP: &[u8] = b"peachy-group-leaf-rotation";

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

fn client(server: &TestIssuer, clock: &SharedClock, tag: u8, actor: &str, device: &str) -> Client {
    let now = clock.now_unix();
    let (_, public) = device_key_pair(&device_seed(tag));
    let token = server
        .issue(actor, device, &public, now - HOUR, now + 30 * DAY)
        .expect("mint");
    let mut config = ClientConfig::new(
        token,
        device_seed(tag),
        server.trusted_keys().expect("trusted keys"),
    )
    .with_storage(PeachyStorage::in_memory())
    .with_own_account_identity(Some(support::held_identity(actor)));
    config.clock = Some(Box::new(clock.clone()));
    Client::new(config).expect("client")
}

fn pair(server: &TestIssuer, clock: &SharedClock) -> (Client, Client) {
    let mut ada = client(server, clock, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(server, clock, 2, "actor-bo", "device-bo-phone");
    ada.create_group(GROUP).expect("create");
    let added = ada
        .add_member(GROUP, &bo.generate_key_package().expect("kp"))
        .expect("add bo");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.join_from_welcome(&added.welcome.expect("welcome"))
        .expect("bo joins");
    (ada, bo)
}

/// `ada` and `bo`, and `newcomer` added by `ada` and applied by `bo`.
fn add(ada: &mut Client, bo: &mut Client, newcomer: &mut Client) {
    let added = ada
        .add_member(GROUP, &newcomer.generate_key_package().expect("kp"))
        .expect("add");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.process_commit(GROUP, &added.commit).expect("bo applies");
    newcomer
        .join_from_welcome(&added.welcome.expect("welcome"))
        .expect("joins");
}

/// `from` says something and `to` opens it.
fn say(from: &mut Client, to: &mut Client) {
    let words = from.encrypt(GROUP, b"hello").expect("encrypt");
    match to.process_message(GROUP, &words).expect("readable") {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"hello"),
        other => panic!("expected an application message, got {other:?}"),
    }
}

/// `ada` rotates through the renewal door; `bo` applies it; both still talk.
fn rotate(ada: &mut Client, bo: &mut Client) {
    rotate_in(ada, &mut [bo]);
}

/// `ada` rotates through the renewal door; every one of `others` applies it,
/// and the first reads what she says next.
fn rotate_in(ada: &mut Client, others: &mut [&mut Client]) {
    let committer = ada.identity().actor_id.clone();
    assert!(ada.leaf_credential_expiring(GROUP).expect("expiring?"));
    assert!(ada.credential_refresh_due(GROUP).expect("due?"));
    let exp_before = ada.own_leaf_credential_expires_at(GROUP).expect("leaf");
    let epoch = ada.epoch(GROUP).expect("epoch");
    let bundle = ada.refresh_credential(GROUP).expect("rotate");
    assert!(bundle.welcome.is_none(), "a rotation adds nobody");
    assert!(
        !ada.leaf_rotation_due(GROUP).expect("due?"),
        "a staged rotation is not a second one due"
    );
    ada.merge_pending_commit(GROUP).expect("merge");
    assert_eq!(ada.epoch(GROUP).expect("epoch"), epoch + 1);
    // The same credential rides the new leaf: the HPKE key is what moved.
    assert_eq!(
        ada.own_leaf_credential_expires_at(GROUP).expect("leaf"),
        exp_before
    );
    for other in others.iter_mut() {
        match other
            .process_commit(GROUP, &bundle.commit)
            .expect("a member applies")
        {
            Incoming::Commit(outcome) => {
                assert!(outcome.added.is_empty() && outcome.removed.is_empty());
                assert_eq!(outcome.sender.actor_id, committer);
            }
            other => panic!("expected a commit, got {other:?}"),
        }
    }
    assert!(!ada.leaf_rotation_due(GROUP).expect("due?"));
    assert!(!ada.credential_refresh_due(GROUP).expect("due?"));
    let words = ada.encrypt(GROUP, b"after").expect("encrypt");
    match others[0].process_message(GROUP, &words).expect("readable") {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"after"),
        other => panic!("expected an application message, got {other:?}"),
    }
}

/// In a group of three people the schedule is weekly, whatever anybody says
/// in between: the round trip is a two-person rule.
#[test]
fn a_leaf_rotates_after_seven_days() {
    let server = issuer();
    let clock = SharedClock::new();
    let (mut ada, mut bo) = pair(&server, &clock);
    let mut cy = client(&server, &clock, 3, "actor-cy", "device-cy-phone");
    add(&mut ada, &mut bo, &mut cy);
    assert!(!ada.leaf_rotation_due(GROUP).expect("due?"));
    assert!(!bo.leaf_rotation_due(GROUP).expect("due?"));

    clock.set(NOW + LEAF_ROTATION_INTERVAL_SECONDS - HOUR);
    say(&mut bo, &mut ada);
    say(&mut cy, &mut ada);
    assert!(!ada.leaf_rotation_due(GROUP).expect("due?"));
    assert!(!ada.leaf_credential_expiring(GROUP).expect("expiring?"));

    clock.set(NOW + LEAF_ROTATION_INTERVAL_SECONDS);
    assert!(ada.leaf_rotation_due(GROUP).expect("due?"));
    // Bo joined at the same moment, from a Welcome: due too.
    assert!(bo.leaf_rotation_due(GROUP).expect("due?"));
    rotate_in(&mut ada, &mut [&mut bo, &mut cy]);
    // Ada's rotation does not heal Bo's leaf: he still owes his own.
    assert!(bo.leaf_rotation_due(GROUP).expect("due?"));
    rotate_in(&mut bo, &mut [&mut ada, &mut cy]);

    // The clock restarts at the rotation, not at the group's birth.
    clock.set(NOW + 2 * LEAF_ROTATION_INTERVAL_SECONDS - HOUR);
    assert!(!ada.leaf_rotation_due(GROUP).expect("due?"));
    clock.set(NOW + 2 * LEAF_ROTATION_INTERVAL_SECONDS);
    assert!(ada.leaf_rotation_due(GROUP).expect("due?"));
}

#[test]
fn a_leaf_rotates_after_its_frame_budget() {
    let server = issuer();
    let clock = SharedClock::new();
    let (mut ada, mut bo) = pair(&server, &clock);
    for n in 0..LEAF_ROTATION_FRAME_BUDGET {
        assert!(
            !ada.leaf_rotation_due(GROUP).expect("due?"),
            "due after only {n} frames"
        );
        let words = ada.encrypt(GROUP, b"x").expect("encrypt");
        bo.process_message(GROUP, &words).expect("readable");
    }
    assert!(ada.leaf_rotation_due(GROUP).expect("due?"));
    // Receiving is not sending: Bo's leaf sealed nothing.
    assert!(!bo.leaf_rotation_due(GROUP).expect("due?"));
    rotate(&mut ada, &mut bo);
}

#[test]
fn any_commit_of_ones_own_with_a_path_counts_as_a_rotation() {
    let server = issuer();
    let clock = SharedClock::new();
    let (mut ada, mut bo) = pair(&server, &clock);
    clock.set(NOW + LEAF_ROTATION_INTERVAL_SECONDS);
    assert!(ada.leaf_rotation_due(GROUP).expect("due?"));
    let update = ada.self_update(GROUP).expect("self update");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.process_commit(GROUP, &update.commit)
        .expect("bo applies");
    assert!(!ada.leaf_rotation_due(GROUP).expect("due?"));
}

#[test]
fn the_rotation_record_survives_a_restart() {
    let server = issuer();
    let clock = SharedClock::new();
    let kv = MemoryKv::new();
    let (_, public) = device_key_pair(&device_seed(1));
    let config = |kv: MemoryKv| {
        let token = server
            .issue(
                "actor-ada",
                "device-ada-phone",
                &public,
                NOW - HOUR,
                NOW + 30 * DAY,
            )
            .expect("mint");
        let mut config = ClientConfig::new(
            token,
            device_seed(1),
            server.trusted_keys().expect("trusted keys"),
        )
        .with_storage(PeachyStorage::open(Box::new(kv)).expect("store"))
        .with_own_account_identity(Some(support::held_identity("actor-ada")));
        config.clock = Some(Box::new(clock.clone()));
        config
    };
    let mut ada = Client::new(config(kv.clone())).expect("client");
    ada.create_group(GROUP).expect("create");
    for _ in 0..LEAF_ROTATION_FRAME_BUDGET {
        ada.encrypt(GROUP, b"x").expect("encrypt");
    }
    assert!(ada.leaf_rotation_due(GROUP).expect("due?"));
    drop(ada);
    let reopened = Client::new(config(kv)).expect("reopen");
    assert!(
        reopened.leaf_rotation_due(GROUP).expect("due?"),
        "the frame count is kept with the group, not in memory"
    );
}

/// The round trip: in a group that seats two people, a device that has heard
/// from the other person replaces its leaf at its next renewal moment, once
/// the leaf is ROUND_TRIP_ROTATION_MIN_SECONDS old, instead of waiting out
/// the week. What it sends next is under a leaf a copy of the old one does
/// not hold.
#[test]
fn a_two_person_leaf_rotates_once_the_other_person_was_heard_from() {
    let server = issuer();
    let clock = SharedClock::new();
    let (mut ada, mut bo) = pair(&server, &clock);

    // Heard from at once, but the leaf is new: the floor holds.
    say(&mut bo, &mut ada);
    assert!(!ada.leaf_rotation_due(GROUP).expect("due?"));
    clock.set(NOW + ROUND_TRIP_ROTATION_MIN_SECONDS - 1);
    assert!(!ada.leaf_rotation_due(GROUP).expect("due?"));

    // Past the floor, the renewal door every client already asks schedules it.
    clock.set(NOW + ROUND_TRIP_ROTATION_MIN_SECONDS);
    assert!(ada.leaf_rotation_due(GROUP).expect("due?"));
    // Bo sent and heard nothing back: his leaf is not due.
    assert!(!bo.leaf_rotation_due(GROUP).expect("due?"));
    rotate(&mut ada, &mut bo);

    // The rotation spent what was heard: nothing more is due until Bo speaks
    // again, however long the leaf gets.
    clock.set(NOW + 2 * HOUR);
    assert!(!ada.leaf_rotation_due(GROUP).expect("due?"));
    // Bo heard Ada's "after" (the rotation's own last line), so he is due.
    assert!(bo.leaf_rotation_due(GROUP).expect("due?"));
    rotate(&mut bo, &mut ada);
    // And now Ada heard Bo's: due again, once her leaf is old enough.
    assert!(ada.leaf_rotation_due(GROUP).expect("due?"));
}

/// Two people, however many devices: a DM with one person's phone and laptop
/// is still a round trip between two people, and a line from one's own other
/// device is not the other person speaking.
#[test]
fn ones_own_other_device_is_not_the_other_person() {
    let server = issuer();
    let clock = SharedClock::new();
    let (mut ada, mut bo) = pair(&server, &clock);
    let mut laptop = client(&server, &clock, 3, "actor-ada", "device-ada-laptop");
    add(&mut ada, &mut bo, &mut laptop);

    say(&mut laptop, &mut ada);
    clock.set(NOW + HOUR);
    assert!(
        !ada.leaf_rotation_due(GROUP).expect("due?"),
        "her own laptop is not a round trip"
    );
    say(&mut bo, &mut ada);
    assert!(ada.leaf_rotation_due(GROUP).expect("due?"));
}

/// The mark that the other person was heard from is kept with the group.
#[test]
fn what_was_heard_survives_a_restart() {
    let server = issuer();
    let clock = SharedClock::new();
    let kv = MemoryKv::new();
    let (_, public) = device_key_pair(&device_seed(1));
    let config = |kv: MemoryKv| {
        let token = server
            .issue(
                "actor-ada",
                "device-ada-phone",
                &public,
                NOW - HOUR,
                NOW + 30 * DAY,
            )
            .expect("mint");
        let mut config = ClientConfig::new(
            token,
            device_seed(1),
            server.trusted_keys().expect("trusted keys"),
        )
        .with_storage(PeachyStorage::open(Box::new(kv)).expect("store"))
        .with_own_account_identity(Some(support::held_identity("actor-ada")));
        config.clock = Some(Box::new(clock.clone()));
        config
    };
    let mut ada = Client::new(config(kv.clone())).expect("client");
    let mut bo = client(&server, &clock, 2, "actor-bo", "device-bo-phone");
    ada.create_group(GROUP).expect("create");
    let added = ada
        .add_member(GROUP, &bo.generate_key_package().expect("kp"))
        .expect("add bo");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.join_from_welcome(&added.welcome.expect("welcome"))
        .expect("bo joins");
    say(&mut bo, &mut ada);
    drop(ada);
    clock.set(NOW + ROUND_TRIP_ROTATION_MIN_SECONDS);
    let reopened = Client::new(config(kv)).expect("reopen");
    assert!(reopened.leaf_rotation_due(GROUP).expect("due?"));
}
