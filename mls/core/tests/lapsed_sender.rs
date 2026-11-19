// SPDX-License-Identifier: MIT
//! A lapsed leaf's NEW application messages, and nobody's history.
//!
//! A leaf whose credential lapsed stays heard through the 56-day grace, so
//! that what it sent while live is not lost to a late reader. These tests
//! pin which of its messages are NEW (docs/identity.md §A lapsed
//! leaf's new messages):
//!
//! - one the delivery service received at or after the sender's `exp`,
//!   whatever epoch it was sealed in, or, with no receive time, one read at
//!   or after it;
//! - one sealed in the epoch the group is in now, whose tree clock is at or
//!   past the sender's `exp`: a date the delivery service cannot move.
//!
//! A new message is refused as `expired`. An honest
//! client will not seal one the tree clock already calls lapsed, and a
//! member holding a credential minted past a lapsed leaf's `exp` renews to
//! carry the tree clock there.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use peachy_mls_core::identity::CLOCK_SKEW_SECONDS;
use peachy_mls_core::issuer::{device_key_pair, TestIssuer};
use peachy_mls_core::{
    Client, ClientConfig, Clock, CredentialRejection, Error, Incoming, PeachyStorage,
};
use support::{device_seed, issuer, DAY, HOUR, NOW};

const GROUP: &[u8] = b"peachy-group-lapsed-sender";

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

fn token(server: &TestIssuer, tag: u8, actor: &str, device: &str, iat: i64, exp: i64) -> Vec<u8> {
    let (_, public) = device_key_pair(&device_seed(tag));
    server
        .issue(actor, device, &public, iat, exp)
        .expect("the test issuer should mint")
}

fn client(server: &TestIssuer, clock: &SharedClock, tag: u8, actor: &str, device: &str) -> Client {
    let now = clock.now_unix();
    let mut config = ClientConfig::new(
        token(server, tag, actor, device, now - HOUR, now + 30 * DAY),
        device_seed(tag),
        server.trusted_keys().expect("trusted keys"),
    )
    .with_storage(PeachyStorage::in_memory())
    .with_own_account_identity(Some(support::held_identity(actor)));
    config.clock = Some(Box::new(clock.clone()));
    Client::new(config).expect("a fresh credential builds a client")
}

fn add(adder: &mut Client, joiner: &mut Client, others: &mut [&mut Client]) {
    let bundle = adder
        .add_member(GROUP, &joiner.generate_key_package().expect("kp"))
        .expect("add");
    adder.merge_pending_commit(GROUP).expect("merge");
    for other in others.iter_mut() {
        other.process_commit(GROUP, &bundle.commit).expect("sees");
    }
    joiner
        .join_from_welcome(&bundle.welcome.expect("welcome"))
        .expect("joins");
}

/// Ada, Bo and Cy in GROUP, all at the same epoch. Every credential runs
/// thirty days from NOW, so Bo's `exp` is day 30.
fn three(server: &TestIssuer, clock: &SharedClock) -> (Client, Client, Client) {
    let mut ada = client(server, clock, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(server, clock, 2, "actor-bo", "device-bo-phone");
    let mut cy = client(server, clock, 3, "actor-cy", "device-cy-phone");
    ada.create_group(GROUP).expect("create");
    add(&mut ada, &mut bo, &mut []);
    add(&mut ada, &mut cy, &mut [&mut bo]);
    (ada, bo, cy)
}

fn renewal(
    server: &TestIssuer,
    who: &mut Client,
    tag: u8,
    actor: &str,
    device: &str,
    iat: i64,
) -> Vec<u8> {
    who.update_credential(
        &token(server, tag, actor, device, iat, iat + 30 * DAY),
        None,
    )
    .expect("a fresher credential");
    let renewal = who.refresh_credential(GROUP).expect("renew");
    who.merge_pending_commit(GROUP).expect("merge");
    renewal.commit
}

fn renew(
    server: &TestIssuer,
    who: &mut Client,
    tag: u8,
    actor: &str,
    device: &str,
    iat: i64,
    others: &mut [&mut Client],
) {
    let commit = renewal(server, who, tag, actor, device, iat);
    for other in others.iter_mut() {
        other.process_commit(GROUP, &commit).expect("applies");
    }
}

/// What `receiver` read.
fn reads(receiver: &mut Client, ciphertext: &[u8], received_at: i64) -> Vec<u8> {
    match receiver
        .process_message_received_at(GROUP, ciphertext, received_at)
        .expect("readable")
    {
        Incoming::Application { plaintext, .. } => plaintext,
        other => panic!("expected an application message, got {other:?}"),
    }
}

fn expired(result: peachy_mls_core::Result<Incoming>) -> bool {
    matches!(
        result,
        Err(Error::CredentialRejected(CredentialRejection::Expired))
    )
}

/// Bo's leaf lapses on day 30 and is never renewed: a phone in a drawer.
/// Ada renews on day 25 and Cy on day 35, which puts the tree clock past
/// Bo's `exp`.
fn bo_lapsed_on_the_tree_clock(
    server: &TestIssuer,
    clock: &SharedClock,
) -> (Client, Client, Client) {
    let (mut ada, mut bo, mut cy) = three(server, clock);
    clock.set(NOW + 25 * DAY);
    renew(
        server,
        &mut ada,
        1,
        "actor-ada",
        "device-ada-phone",
        NOW + 25 * DAY,
        &mut [&mut bo, &mut cy],
    );
    clock.set(NOW + 35 * DAY);
    renew(
        server,
        &mut cy,
        3,
        "actor-cy",
        "device-cy-phone",
        NOW + 35 * DAY,
        &mut [&mut ada, &mut bo],
    );
    (ada, bo, cy)
}

/// A lapsed leaf's own client will not seal on a leaf the tree clock calls
/// lapsed. A message sealed where the tree clock is past the sender's `exp`
/// anyway is refused on every wall, whatever receive time the
/// delivery service gives it, and the refusal spends nothing. A renewed
/// leaf is heard again.
#[cfg(feature = "test-forgery")]
#[test]
fn a_message_sealed_past_the_tree_clock_is_refused_however_it_is_dated() {
    let server = issuer();
    let clock = SharedClock::new();
    let (mut ada, mut bo, mut cy) = bo_lapsed_on_the_tree_clock(&server, &clock);

    // The sender's half: Bo's own client will not seal on a leaf the tree
    // clock calls lapsed, and says so before anything is sealed.
    clock.set(NOW + 31 * DAY);
    assert!(matches!(
        bo.encrypt(GROUP, b"from the drawer"),
        Err(Error::CredentialRejected(CredentialRejection::Expired))
    ));

    bo.act_as_build_sending_while_lapsed();
    let forged = bo.encrypt(GROUP, b"from the drawer").expect("sealed");
    // Ada's wall is a day past Bo's exp and Cy's slow one a day before it;
    // the delivery service backdates the message to day 29, or gives no
    // time at all. Every one is refused, and twice: nothing is spent.
    for (receiver, wall) in [(&mut ada, NOW + 31 * DAY), (&mut cy, NOW + 29 * DAY)] {
        clock.set(wall);
        for received_at in [NOW + 29 * DAY, 0, NOW + 29 * DAY] {
            assert!(
                expired(receiver.process_message_received_at(GROUP, &forged, received_at)),
                "{} read a message sealed past the tree clock, received at {received_at}",
                receiver.identity().device_id
            );
        }
    }

    // Renewing is what an honest lapsed device does, and it is heard again.
    clock.set(NOW + 40 * DAY);
    renew(
        &server,
        &mut bo,
        2,
        "actor-bo",
        "device-bo-phone",
        NOW + 40 * DAY,
        &mut [&mut ada, &mut cy],
    );
    let words = bo.encrypt(GROUP, b"renewed").expect("encrypt");
    assert_eq!(reads(&mut ada, &words, NOW + 40 * DAY), b"renewed".to_vec());
}

/// The tree clock stops nothing until some member renews past `exp`. The
/// receive time covers that gap: a message the delivery service received
/// after Bo lapsed is new whatever epoch it was sealed in, in the one the
/// reader is in or one it has left. One received before is history. Bo's
/// own client refuses to seal once its wall reaches his `exp`; a client
/// that seals anyway is what the receivers judge here.
#[cfg(feature = "test-forgery")]
#[test]
fn a_message_received_after_exp_is_new_whatever_its_epoch() {
    let server = issuer();
    let clock = SharedClock::new();
    let (mut ada, mut bo, mut cy) = three(&server, &clock);
    clock.set(NOW + 25 * DAY);
    renew(
        &server,
        &mut ada,
        1,
        "actor-ada",
        "device-ada-phone",
        NOW + 25 * DAY,
        &mut [&mut bo, &mut cy],
    );

    // Day 29 Bo is live; day 31 he has lapsed, though the tree clock (day
    // 25) does not say so. His own client refuses on its wall; a client
    // that seals anyway is judged by the receive time.
    clock.set(NOW + 29 * DAY);
    let on_time = bo.encrypt(GROUP, b"on time").expect("encrypt");
    clock.set(NOW + 31 * DAY);
    assert!(matches!(
        bo.encrypt(GROUP, b"late"),
        Err(Error::CredentialRejected(CredentialRejection::Expired))
    ));
    bo.act_as_build_sending_while_lapsed();
    let late = bo
        .encrypt(GROUP, b"late")
        .expect("sealed past the sender's own guard");
    let late_too = bo.encrypt(GROUP, b"late too").expect("encrypt");

    // Ada, in the epoch both were sealed in.
    assert!(expired(ada.process_message_received_at(
        GROUP,
        &late,
        NOW + 31 * DAY
    )));
    // With no receive time, the reader's wall stands in for it.
    assert!(expired(
        ada.process_message_received_at(GROUP, &late_too, 0)
    ));
    assert_eq!(
        reads(&mut ada, &on_time, NOW + 29 * DAY),
        b"on time".to_vec()
    );

    // Cy renews first, so for him both come from an epoch the group has
    // left: still judged by when they were received.
    let _ = renewal(
        &server,
        &mut cy,
        3,
        "actor-cy",
        "device-cy-phone",
        NOW + 31 * DAY,
    );
    assert!(expired(cy.process_message_received_at(
        GROUP,
        &late,
        NOW + 31 * DAY
    )));
    assert_eq!(
        reads(&mut cy, &on_time, NOW + 29 * DAY),
        b"on time".to_vec()
    );
}

/// A sender's own client stops sealing [`CLOCK_SKEW_SECONDS`] before its
/// leaf's `exp` on its own wall, before any receiver would call what it
/// sends new, and fails the send loudly rather than going quiet. The
/// renewal the app runs then falls due, and once it lands the same device
/// sends again and is read.
#[test]
fn a_sender_stops_sealing_at_its_own_exp_and_sends_again_once_renewed() {
    let server = issuer();
    let clock = SharedClock::new();
    let (mut ada, mut bo, mut cy) = three(&server, &clock);
    let exp = NOW + 30 * DAY;

    let last_live = exp - CLOCK_SKEW_SECONDS - 1;
    clock.set(last_live);
    let words = bo
        .encrypt(GROUP, b"just in time")
        .expect("live, with the skew to spare");
    assert_eq!(reads(&mut ada, &words, last_live), b"just in time".to_vec());

    for wall in [exp - CLOCK_SKEW_SECONDS, exp, exp + DAY] {
        clock.set(wall);
        assert!(
            matches!(
                bo.encrypt(GROUP, b"too late"),
                Err(Error::CredentialRejected(CredentialRejection::Expired))
            ),
            "refused at {wall}"
        );
    }

    // The app's answer: a fresher credential, then the renewal commit.
    bo.update_credential(
        &token(
            &server,
            2,
            "actor-bo",
            "device-bo-phone",
            exp,
            exp + 30 * DAY,
        ),
        None,
    )
    .expect("a fresher credential");
    assert!(bo.credential_refresh_due(GROUP).expect("due"));
    let renewal = bo.refresh_credential(GROUP).expect("renew");
    bo.merge_pending_commit(GROUP).expect("merge");
    for other in [&mut ada, &mut cy] {
        other
            .process_commit(GROUP, &renewal.commit)
            .expect("applies");
    }
    let words = bo.encrypt(GROUP, b"back").expect("renewed");
    assert_eq!(reads(&mut ada, &words, exp + DAY), b"back".to_vec());
}

/// What Bo sealed and the delivery service received while his credential
/// was live is read, however late a member reads it: in the epoch it was sealed in, whose tree clock is before his `exp`,
/// and after the member has moved on to an epoch whose tree clock is past
/// it.
#[cfg(feature = "test-forgery")]
#[test]
fn what_a_leaf_sealed_while_live_is_read_after_it_lapsed() {
    let server = issuer();
    let clock = SharedClock::new();
    let (mut ada, mut bo, mut cy) = three(&server, &clock);
    clock.set(NOW + 25 * DAY);
    renew(
        &server,
        &mut ada,
        1,
        "actor-ada",
        "device-ada-phone",
        NOW + 25 * DAY,
        &mut [&mut bo, &mut cy],
    );

    // Day 29: Bo's last words before his phone goes in the drawer.
    clock.set(NOW + 29 * DAY);
    let first = bo.encrypt(GROUP, b"first").expect("encrypt");
    let second = bo.encrypt(GROUP, b"second").expect("encrypt");

    // Day 35: Cy renews, and the tree clock passes Bo's exp.
    clock.set(NOW + 35 * DAY);
    let commit = renewal(
        &server,
        &mut cy,
        3,
        "actor-cy",
        "device-cy-phone",
        NOW + 35 * DAY,
    );

    // Ada reads the backlog on day 45, still in the epoch it was sealed in.
    clock.set(NOW + 45 * DAY);
    assert_eq!(reads(&mut ada, &first, NOW + 29 * DAY), b"first".to_vec());
    // Cy, already past the renewal, reads it as history.
    assert_eq!(reads(&mut cy, &first, NOW + 29 * DAY), b"first".to_vec());
    // And Ada, taking the renewal before the rest of the backlog.
    ada.process_commit(GROUP, &commit).expect("applies");
    assert_eq!(reads(&mut ada, &second, NOW + 29 * DAY), b"second".to_vec());
}

/// The tree clock moves past a lapsed leaf's `exp` only when some member
/// renews. A member holding a credential minted after that `exp` is due a
/// renewal for that reason alone, once, and from that epoch on the lapsed
/// leaf's new messages are new however the delivery service dates them.
#[cfg(feature = "test-forgery")]
#[test]
fn a_renewal_falls_due_to_carry_the_tree_clock_past_a_lapsed_leaf() {
    let server = issuer();
    let clock = SharedClock::new();
    let (mut ada, mut bo, mut cy) = three(&server, &clock);
    clock.set(NOW + 25 * DAY);
    renew(
        &server,
        &mut ada,
        1,
        "actor-ada",
        "device-ada-phone",
        NOW + 25 * DAY,
        &mut [&mut bo, &mut cy],
    );
    clock.set(NOW + 26 * DAY);
    renew(
        &server,
        &mut cy,
        3,
        "actor-cy",
        "device-cy-phone",
        NOW + 26 * DAY,
        &mut [&mut ada, &mut bo],
    );

    // Day 29: a credential minted before Bo's exp moves nothing for him.
    clock.set(NOW + 29 * DAY);
    ada.update_credential(
        &token(
            &server,
            1,
            "actor-ada",
            "device-ada-phone",
            NOW + 29 * DAY,
            NOW + 59 * DAY,
        ),
        None,
    )
    .expect("fresh");
    assert!(!ada.leaf_credential_expiring(GROUP).expect("expiring?"));
    assert!(!ada.credential_refresh_due(GROUP).expect("due?"));

    // Day 31: Bo lapsed yesterday, and the tree clock (day 26) does not know.
    clock.set(NOW + 31 * DAY);
    ada.update_credential(
        &token(
            &server,
            1,
            "actor-ada",
            "device-ada-phone",
            NOW + 31 * DAY,
            NOW + 61 * DAY,
        ),
        None,
    )
    .expect("fresh");
    // Ada's own leaf is 24 days from its exp and 6 days old: only Bo makes
    // it due.
    assert!(ada.leaf_credential_expiring(GROUP).expect("expiring?"));
    assert!(ada.credential_refresh_due(GROUP).expect("due?"));
    let renewal = ada.refresh_credential(GROUP).expect("renew");
    ada.merge_pending_commit(GROUP).expect("merge");
    cy.process_commit(GROUP, &renewal.commit).expect("applies");
    bo.process_commit(GROUP, &renewal.commit).expect("applies");
    assert!(!ada.credential_refresh_due(GROUP).expect("due once"));

    // From this epoch on, a receive time backdated to day 29 hides nothing.
    bo.act_as_build_sending_while_lapsed();
    let after = bo.encrypt(GROUP, b"after").expect("sealed");
    assert!(expired(ada.process_message_received_at(
        GROUP,
        &after,
        NOW + 29 * DAY
    )));
    assert!(expired(cy.process_message_received_at(
        GROUP,
        &after,
        NOW + 29 * DAY
    )));
}
