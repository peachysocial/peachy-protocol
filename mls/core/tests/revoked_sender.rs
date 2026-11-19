// SPDX-License-Identifier: MIT
//! A revoked leaf's messages are refused once its revocation took effect,
//! and what it sent before is still read.
//!
//! A leaf a member could not remove yet (no live device of its own, an epoch
//! it has not caught up to) stayed able to talk on a signed revocation until
//! a removal commit landed. These tests pin the rule that closes it
//! (docs/identity.md §A revoked leaf's messages): a receiver that
//! holds the account's verified revocation of a key refuses that key's
//! application messages received at or after the revocation took effect, in
//! every group, and reads those received before it. An unknown receive time
//! or revocation time counts as after.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use peachy_mls_core::issuer::{device_key_pair, TestIssuer};
use peachy_mls_core::{
    sign_device_revocation, Client, ClientConfig, Clock, Error, Incoming, PeachyStorage,
};
use support::{device_seed, issuer, DAY, HOUR, NOW};

const GROUP: &[u8] = b"peachy-group-revoked-sender";
const OTHER: &[u8] = b"peachy-group-revoked-sender-other";

/// The second the delivery service says Bo's phone was revoked.
const REVOKED_AT: i64 = NOW + HOUR;

#[derive(Debug, Clone)]
struct SharedClock(Arc<AtomicI64>);

impl SharedClock {
    fn new() -> Self {
        Self(Arc::new(AtomicI64::new(NOW)))
    }
}

impl Clock for SharedClock {
    fn now_unix(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

fn token(server: &TestIssuer, tag: u8, actor: &str, device: &str, iat: i64, exp: i64) -> Vec<u8> {
    let (_, public) = device_key_pair(&device_seed(tag));
    server
        .issue(actor, device, &public, iat, exp)
        .expect("the test issuer should mint")
}

fn config(
    server: &TestIssuer,
    clock: &SharedClock,
    tag: u8,
    actor: &str,
    device: &str,
) -> ClientConfig {
    let now = clock.now_unix();
    let mut config = ClientConfig::new(
        token(server, tag, actor, device, now - HOUR, now + 30 * DAY),
        device_seed(tag),
        server.trusted_keys().expect("trusted keys"),
    )
    .with_storage(PeachyStorage::in_memory())
    .with_own_account_identity(Some(support::held_identity(actor)));
    config.clock = Some(Box::new(clock.clone()));
    config
}

fn client(server: &TestIssuer, clock: &SharedClock, tag: u8, actor: &str, device: &str) -> Client {
    Client::new(config(server, clock, tag, actor, device))
        .expect("a fresh credential builds a client")
}

fn add(adder: &mut Client, joiner: &mut Client, group: &[u8], others: &mut [&mut Client]) {
    let bundle = adder
        .add_member(group, &joiner.generate_key_package().expect("kp"))
        .expect("add");
    adder.merge_pending_commit(group).expect("merge");
    for other in others.iter_mut() {
        other.process_commit(group, &bundle.commit).expect("sees");
    }
    joiner
        .join_from_welcome(&bundle.welcome.expect("welcome"))
        .expect("joins");
}

/// Ada, Bo and Cy in GROUP, all at the same epoch.
fn three(server: &TestIssuer, clock: &SharedClock) -> (Client, Client, Client) {
    let mut ada = client(server, clock, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(server, clock, 2, "actor-bo", "device-bo-phone");
    let mut cy = client(server, clock, 3, "actor-cy", "device-cy-phone");
    ada.create_group(GROUP).expect("create");
    add(&mut ada, &mut bo, GROUP, &mut []);
    add(&mut ada, &mut cy, GROUP, &mut [&mut bo]);
    (ada, bo, cy)
}

fn says(receiver: &mut Client, ciphertext: &[u8], received_at: i64) -> Vec<u8> {
    match receiver
        .process_message_received_at(GROUP, ciphertext, received_at)
        .expect("readable")
    {
        Incoming::Application { plaintext, .. } => plaintext,
        other => panic!("expected an application message, got {other:?}"),
    }
}

fn refused(result: peachy_mls_core::Result<Incoming>) -> bool {
    matches!(result, Err(Error::NotFromAMember(_)))
}

fn bo_revocation(by_actor: &str) -> Vec<u8> {
    let (_, bo_key) = device_key_pair(&device_seed(2));
    sign_device_revocation(&TestIssuer::test_account_key(by_actor), &bo_key)
        .expect("sign")
        .to_vec()
}

/// The revoked device still holds a live credential and the epoch's keys,
/// and nobody has removed its leaf. A member that has seen its account's
/// signed revocation refuses what the delivery service received from it
/// after the revocation, in every group, without waiting for a removal; a
/// member that has not still reads it.
#[test]
fn a_member_holding_the_signed_revocation_refuses_what_came_after_it() {
    let server = issuer();
    let clock = SharedClock::new();
    let (mut ada, mut bo, mut cy) = three(&server, &clock);
    ada.create_group(OTHER).expect("create");
    {
        let bundle = ada
            .add_member(OTHER, &bo.generate_key_package().expect("kp"))
            .expect("add");
        ada.merge_pending_commit(OTHER).expect("merge");
        bo.join_from_welcome(&bundle.welcome.expect("welcome"))
            .expect("joins");
    }

    // A signature by somebody else's account is no revocation of Bo, and
    // keeps nothing: Bo is still heard.
    let bo_leaf = ada.leaf_of_device(GROUP, "device-bo-phone").expect("bo");
    assert!(!ada
        .stale_leaf_removable(GROUP, bo_leaf, &bo_revocation("actor-cy"), REVOKED_AT)
        .expect("judged"));
    let still = bo.encrypt(GROUP, b"still bo").expect("encrypt");
    assert_eq!(says(&mut ada, &still, REVOKED_AT + 60), b"still bo");

    // Bo's own account signs his key out, and Ada's device sees it.
    assert!(ada
        .stale_leaf_removable(GROUP, bo_leaf, &bo_revocation("actor-bo"), REVOKED_AT)
        .expect("judged"));

    let after = bo
        .encrypt(GROUP, b"after")
        .expect("a device that ignores its revocation seals");
    assert!(refused(ada.process_message_received_at(
        GROUP,
        &after,
        REVOKED_AT + 60
    )));
    // Refused again, not spent: the refusal is the rule, not a lost key.
    assert!(refused(ada.process_message_received_at(
        GROUP,
        &after,
        REVOKED_AT + 60
    )));
    // Received in the very second it took effect is not before it.
    assert!(refused(
        ada.process_message_received_at(GROUP, &after, REVOKED_AT)
    ));
    // Cy has not seen the revocation, and reads it.
    assert_eq!(says(&mut cy, &after, REVOKED_AT + 60), b"after");

    // In every group, not only the one the revocation was judged in.
    let elsewhere = bo.encrypt(OTHER, b"elsewhere").expect("encrypt");
    assert!(refused(ada.process_message_received_at(
        OTHER,
        &elsewhere,
        REVOKED_AT + 60
    )));
}

/// What the device sent while it was still the account's is read, however
/// late: a backlog the delivery service received before the revocation took
/// effect, opened only after this device learned of it.
#[test]
fn what_a_revoked_device_sent_before_its_revocation_is_still_read() {
    let server = issuer();
    let clock = SharedClock::new();
    let (mut ada, mut bo, _cy) = three(&server, &clock);
    let first = bo.encrypt(GROUP, b"first").expect("encrypt");
    let second = bo.encrypt(GROUP, b"second").expect("encrypt");

    let bo_leaf = ada.leaf_of_device(GROUP, "device-bo-phone").expect("bo");
    assert!(ada
        .stale_leaf_removable(GROUP, bo_leaf, &bo_revocation("actor-bo"), REVOKED_AT)
        .expect("judged"));

    assert_eq!(says(&mut ada, &first, REVOKED_AT - 120), b"first");
    assert_eq!(says(&mut ada, &second, REVOKED_AT - 1), b"second");
}

/// A receive time this device does not know, or a revocation that came
/// without the time it took effect, places nothing before the revocation:
/// both are refused.
#[test]
fn an_unknown_time_counts_as_after_the_revocation() {
    let server = issuer();
    let clock = SharedClock::new();
    let (mut ada, mut bo, mut cy) = three(&server, &clock);
    let words = bo.encrypt(GROUP, b"when?").expect("encrypt");

    // Ada knows when it took effect, but not when this was received.
    let bo_leaf = ada.leaf_of_device(GROUP, "device-bo-phone").expect("bo");
    assert!(ada
        .stale_leaf_removable(GROUP, bo_leaf, &bo_revocation("actor-bo"), REVOKED_AT)
        .expect("judged"));
    assert!(refused(ada.process_message(GROUP, &words)));
    assert!(refused(ada.process_message_received_at(GROUP, &words, 0)));

    // Cy knows when this was received, but not when the revocation took
    // effect.
    let bo_leaf = cy.leaf_of_device(GROUP, "device-bo-phone").expect("bo");
    assert!(cy
        .stale_leaf_removable(GROUP, bo_leaf, &bo_revocation("actor-bo"), 0)
        .expect("judged"));
    assert!(refused(cy.process_message_received_at(
        GROUP,
        &words,
        REVOKED_AT - 120
    )));
}

/// Of two times the delivery service gives for one revocation, the earlier
/// stands, and an answer without one takes nothing back: a later answer can
/// only refuse more.
#[test]
fn a_revocations_time_only_moves_earlier() {
    let server = issuer();
    let clock = SharedClock::new();
    let (mut ada, mut bo, _cy) = three(&server, &clock);
    let early = bo.encrypt(GROUP, b"early").expect("encrypt");
    let between = bo.encrypt(GROUP, b"between").expect("encrypt");
    let bo_leaf = ada.leaf_of_device(GROUP, "device-bo-phone").expect("bo");
    let revocation = bo_revocation("actor-bo");

    assert!(ada
        .stale_leaf_removable(GROUP, bo_leaf, &revocation, REVOKED_AT)
        .expect("judged"));
    // A later time, and then none at all: neither moves it.
    assert!(ada
        .stale_leaf_removable(GROUP, bo_leaf, &revocation, REVOKED_AT + DAY)
        .expect("judged"));
    assert!(ada
        .stale_leaf_removable(GROUP, bo_leaf, &revocation, 0)
        .expect("judged"));
    assert!(refused(ada.process_message_received_at(
        GROUP,
        &between,
        REVOKED_AT + 60
    )));
    // An earlier one does.
    assert!(ada
        .stale_leaf_removable(GROUP, bo_leaf, &revocation, REVOKED_AT - HOUR)
        .expect("judged"));
    assert!(refused(ada.process_message_received_at(
        GROUP,
        &between,
        REVOKED_AT - 60
    )));
    assert_eq!(says(&mut ada, &early, REVOKED_AT - 2 * HOUR), b"early");
}

/// A revocation is kept in the device's store, with its time, so a device
/// that opens again still refuses the key and still reads its earlier
/// messages.
#[test]
fn a_kept_revocation_outlives_the_process() {
    let server = issuer();
    let clock = SharedClock::new();
    let kv = peachy_mls_core::MemoryKv::new();
    let open_ada = |clock: &SharedClock| {
        let config = config(&server, clock, 1, "actor-ada", "device-ada-phone")
            .with_storage(PeachyStorage::open(Box::new(kv.clone())).expect("open"));
        Client::new(config).expect("ada opens")
    };
    let mut ada = open_ada(&clock);
    let mut bo = client(&server, &clock, 2, "actor-bo", "device-bo-phone");
    ada.create_group(GROUP).expect("create");
    add(&mut ada, &mut bo, GROUP, &mut []);
    let bo_leaf = ada.leaf_of_device(GROUP, "device-bo-phone").expect("bo");
    assert!(ada
        .stale_leaf_removable(GROUP, bo_leaf, &bo_revocation("actor-bo"), REVOKED_AT)
        .expect("judged"));
    drop(ada);

    let mut ada = open_ada(&clock);
    let before = bo.encrypt(GROUP, b"before").expect("encrypt");
    let after = bo.encrypt(GROUP, b"after a restart").expect("encrypt");
    assert!(refused(ada.process_message_received_at(
        GROUP,
        &after,
        REVOKED_AT + 60
    )));
    assert_eq!(says(&mut ada, &before, REVOKED_AT - 60), b"before");
}
