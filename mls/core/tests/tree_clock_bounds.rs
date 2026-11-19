// SPDX-License-Identifier: MIT
//! The tree clock's bounds.
//!
//! The tree clock is the latest issuer-signed `iat` among a group's person
//! leaves and the leaves a commit brings in, and every verdict on a received
//! commit is judged at it
//! (docs/identity.md §A received commit is judged on the tree clock).
//! These are the ways it could be pushed, or read, wrong. Each test goes red
//! without the bound it names.

mod support;

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use peachy_mls_core::issuer::{device_key_pair, TestIssuer};
use peachy_mls_core::{
    Client, ClientConfig, Clock, CredentialRejection, Error, PeachyStorage,
    EXPIRED_LEAF_GRACE_SECONDS, MAX_TREE_CLOCK_JUMP_SECONDS, RENEWAL_CUTOFF_MARGIN_SECONDS,
};
use support::{device_seed, issuer, DAY, HOUR, NOW};

const GROUP: &[u8] = b"peachy-group-tree-clock-bounds";

#[derive(Debug, Clone)]
struct SharedClock(Arc<AtomicI64>);

impl SharedClock {
    fn at(unix: i64) -> Self {
        Self(Arc::new(AtomicI64::new(unix)))
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

fn token(server: &TestIssuer, tag: u8, actor: &str, device: &str, iat: i64, exp: i64) -> Vec<u8> {
    let (_, public) = device_key_pair(&device_seed(tag));
    server
        .issue(actor, device, &public, iat, exp)
        .expect("the test issuer should mint")
}

/// A person's client on `clock`, holding a credential minted at `iat`.
#[allow(clippy::too_many_arguments)]
fn person(
    server: &TestIssuer,
    clock: &SharedClock,
    tag: u8,
    actor: &str,
    device: &str,
    iat: i64,
    exp: i64,
) -> Client {
    let mut config = ClientConfig::new(
        token(server, tag, actor, device, iat, exp),
        device_seed(tag),
        server.trusted_keys().expect("trusted keys"),
    )
    .with_storage(PeachyStorage::in_memory())
    .with_own_account_identity(Some(support::held_identity(actor)));
    config.clock = Some(Box::new(clock.clone()));
    Client::new(config).expect("a live credential builds a client")
}

/// Ada and Bo in one group.
fn pair(ada: &mut Client, bo: &mut Client) {
    ada.create_group(GROUP).expect("create");
    let add = ada
        .add_member(GROUP, &bo.generate_key_package().expect("kp"))
        .expect("add bo");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.join_from_welcome(&add.welcome.expect("welcome"))
        .expect("bo joins");
}

/// The jump bound. No commit may carry the tree clock forward by the
/// issuer's shortest lifetime plus the grace less the renewal margin
/// (eighty-five days) or more — whatever the committer's own grace would
/// allow. With a bound of eighty-six, a leaf at the clock plus 85.9 days
/// would put the group's newest thirty-day leaf past its renewal cutoff
/// (exp + grace - margin = clock + 85), so nobody could renew and membership
/// would freeze until the forger stepped again. A committer holding a credential
/// longer than the others (31 days against 30) could get there through a
/// lapsed renewal; a modified client is refused by every receiver.
#[cfg(feature = "test-forgery")]
#[test]
fn a_commit_may_not_jump_the_tree_clock_eighty_five_days() {
    assert_eq!(MAX_TREE_CLOCK_JUMP_SECONDS, 85 * DAY);
    let server = issuer();
    let clock = SharedClock::at(NOW);
    // Both issued yesterday at midnight; Ada's is the issuer's longest.
    let issued = NOW - DAY;
    let mut ada = person(
        &server,
        &clock,
        1,
        "actor-ada",
        "device-ada-phone",
        issued,
        issued + 31 * DAY,
    );
    let mut bo = person(
        &server,
        &clock,
        2,
        "actor-bo",
        "device-bo-phone",
        issued,
        issued + 30 * DAY,
    );
    pair(&mut ada, &mut bo);

    // Exactly 85 days past the clock: inside Ada's own grace (31 + 56 = 87),
    // and exactly Bo's renewal cutoff (30 + 56 - 1), so only the bound
    // refuses it.
    let jump = issued + 30 * DAY + EXPIRED_LEAF_GRACE_SECONDS - RENEWAL_CUTOFF_MARGIN_SECONDS;
    let far = token(
        &server,
        1,
        "actor-ada",
        "device-ada-phone",
        jump,
        jump + 30 * DAY,
    );
    let forged = ada
        .forge_refresh_credential(GROUP, &far)
        .expect("a modified client builds it");
    assert!(matches!(
        bo.process_commit(GROUP, &forged.commit),
        Err(Error::CredentialRejected(CredentialRejection::Expired))
    ));
    ada.clear_pending_commit(GROUP).expect("clear");

    // A second short of it is an ordinary (if late) renewal — and Bo, the
    // newest thirty-day leaf, is still short of his cutoff on the clock it
    // leaves behind, so he can renew after it.
    let near = token(
        &server,
        1,
        "actor-ada",
        "device-ada-phone",
        jump - 1,
        jump - 1 + 30 * DAY,
    );
    let renewal = ada.forge_refresh_credential(GROUP, &near).expect("built");
    bo.process_commit(GROUP, &renewal.commit)
        .expect("inside the bound, a lapsed leaf's renewal is taken");
    ada.merge_pending_commit(GROUP).expect("merge");
    clock.set(jump - 1);
    assert!(
        !bo.leaf_credential_past_grace(GROUP).expect("past?"),
        "the newest thirty-day leaf keeps a second of its renewal window"
    );
    bo.update_credential(
        &token(
            &server,
            2,
            "actor-bo",
            "device-bo-phone",
            jump - 1,
            jump - 1 + 30 * DAY,
        ),
        None,
    )
    .expect("bo's fresh credential");
    let bo_renewal = bo.refresh_credential(GROUP).expect("bo can still renew");
    bo.merge_pending_commit(GROUP).expect("merge");
    ada.process_commit(GROUP, &bo_renewal.commit)
        .expect("and every receiver takes it");
}

/// The lifetime bound, through a group rather than the fixture: a credential longer
/// than the issuer ever gives is refused at the door where it would first be
/// believed, however well it is signed.
#[test]
fn a_key_package_with_an_implausible_lifetime_is_refused_at_the_add() {
    let server = issuer();
    let clock = SharedClock::at(NOW);
    let mut ada = person(
        &server,
        &clock,
        1,
        "actor-ada",
        "device-ada-phone",
        NOW - HOUR,
        NOW + 30 * DAY,
    );
    ada.create_group(GROUP).expect("create");
    let seed = device_seed(2);
    let (_, public) = device_key_pair(&seed);
    let long = server
        .issue(
            "actor-bo",
            "device-bo-phone",
            &public,
            NOW - HOUR,
            NOW + 365 * DAY,
        )
        .expect("mint");
    // Bo cannot even open a client on it.
    let mut config = ClientConfig::new(long, seed, server.trusted_keys().expect("trusted"))
        .with_storage(PeachyStorage::in_memory())
        .with_own_account_identity(Some(support::held_identity("actor-bo")));
    config.clock = Some(Box::new(clock.clone()));
    assert!(matches!(
        Client::new(config),
        Err(Error::CredentialRejected(
            CredentialRejection::ImplausibleLifetime
        ))
    ));
}

/// A slow wall clock. A device whose clock runs slow read only its own wall when deciding
/// whether it was past its grace, so it built a renewal every receiver
/// refuses — they judge it on the tree clock — while the delivery service took
/// it: a fork. Bo's credential lapsed on day 30; the group's tree clock reads
/// day 86 (Ada renewed that day), past his grace; his wall reads day 60.
#[test]
fn a_device_whose_clock_runs_slow_does_not_build_a_renewal_past_the_grace() {
    let server = issuer();
    let ada_clock = SharedClock::at(NOW);
    let bo_clock = SharedClock::at(NOW);
    let mut ada = person(
        &server,
        &ada_clock,
        1,
        "actor-ada",
        "device-ada-phone",
        NOW - HOUR,
        NOW + 30 * DAY,
    );
    let mut bo = person(
        &server,
        &bo_clock,
        2,
        "actor-bo",
        "device-bo-phone",
        NOW - HOUR,
        NOW + 30 * DAY,
    );
    pair(&mut ada, &mut bo);
    for day in [25, 50, 75, 86] {
        ada_clock.set(NOW + day * DAY);
        ada.update_credential(
            &token(
                &server,
                1,
                "actor-ada",
                "device-ada-phone",
                NOW + day * DAY,
                NOW + (day + 30) * DAY,
            ),
            None,
        )
        .expect("ada's fresh credential");
        let renewal = ada.refresh_credential(GROUP).expect("ada renews");
        ada.merge_pending_commit(GROUP).expect("merge");
        bo.process_commit(GROUP, &renewal.commit).expect("bo");
    }

    bo_clock.set(NOW + 60 * DAY);
    bo.update_credential(
        &token(
            &server,
            2,
            "actor-bo",
            "device-bo-phone",
            NOW + 59 * DAY,
            NOW + 89 * DAY,
        ),
        None,
    )
    .expect("a credential his own wall calls live");
    assert!(
        bo.leaf_credential_past_grace(GROUP).expect("past?"),
        "the tree clock is past his grace even though his wall is not"
    );
    assert!(matches!(
        bo.refresh_credential(GROUP),
        Err(Error::CredentialRejected(CredentialRejection::Expired))
    ));
    assert!(!bo.has_pending_commit(GROUP).expect("pending?"));
}

/// The tree clock a renewal is judged on includes the renewal's OWN leaf.
/// A device whose wall runs slow, in a group nobody else has touched
/// since its leaf lapsed, read the wall and the pre-commit tree clock — both
/// short of its cutoff — and answered "not past the grace". Its renewal, whose
/// `iat` is past the cutoff, was then refused by its own mirror of the
/// receivers' tests, so it could neither renew nor learn to ask for a seat.
/// Bo's leaf lapsed on day 30; he holds a credential issued on day 86 (his
/// wall read that when he fetched it, and has since been set back to day 60).
#[test]
fn a_held_credential_past_the_cutoff_reads_as_past_the_grace() {
    let server = issuer();
    let ada_clock = SharedClock::at(NOW);
    let bo_clock = SharedClock::at(NOW);
    let mut ada = person(
        &server,
        &ada_clock,
        1,
        "actor-ada",
        "device-ada-phone",
        NOW - HOUR,
        NOW + 30 * DAY,
    );
    let mut bo = person(
        &server,
        &bo_clock,
        2,
        "actor-bo",
        "device-bo-phone",
        NOW - HOUR,
        NOW + 30 * DAY,
    );
    pair(&mut ada, &mut bo);

    let held_iat = NOW + 30 * DAY + EXPIRED_LEAF_GRACE_SECONDS;
    bo_clock.set(held_iat);
    bo.update_credential(
        &token(
            &server,
            2,
            "actor-bo",
            "device-bo-phone",
            held_iat,
            held_iat + 30 * DAY,
        ),
        None,
    )
    .expect("a credential his wall called live when he fetched it");
    bo_clock.set(NOW + 60 * DAY);

    assert!(
        bo.leaf_credential_past_grace(GROUP).expect("past?"),
        "the renewal would carry the clock past his cutoff, so he must ask for a seat"
    );
    assert!(bo.refresh_credential(GROUP).is_err());
    assert!(!bo.has_pending_commit(GROUP).expect("pending?"));
}
