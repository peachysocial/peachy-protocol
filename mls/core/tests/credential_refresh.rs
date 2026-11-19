// SPDX-License-Identifier: MIT
//! A seated leaf's credential, renewed before it lapses — and what happens
//! when it is not.
//!
//! The bug this file exists for: every leaf carries the `pdc1` its device held
//! when the leaf was made, that credential lives thirty days, and every
//! receiver checks the SENDER's leaf credential on every message. Nothing
//! renewed a seated leaf, so every sealed conversation would have gone mute
//! thirty days after it sealed. These tests run a group across that line on a
//! clock they move.
//!
//! docs/identity.md §Refreshing a seated leaf

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use peachy_mls_core::issuer::{device_key_pair, TestIssuer};
use peachy_mls_core::{
    Client, ClientConfig, Clock, CredentialRejection, DenyReason, Error, Incoming, PeachyStorage,
    CREDENTIAL_REFRESH_WINDOW_SECONDS, EXPIRED_LEAF_GRACE_SECONDS, LEAF_ROTATION_INTERVAL_SECONDS,
};
use support::{device_seed, issuer, DAY, HOUR, NOW};

const GROUP: &[u8] = b"peachy-group-credential-refresh";

/// A clock every client in a test shares, so "a month passes" is one line.
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

/// A credential for `tag`'s key, as `RegisterDevice` would mint it at `iat`.
fn token(server: &TestIssuer, tag: u8, actor: &str, device: &str, iat: i64, exp: i64) -> Vec<u8> {
    let (_, public) = device_key_pair(&device_seed(tag));
    server
        .issue(actor, device, &public, iat, exp)
        .expect("the test issuer should mint")
}

/// A client on the shared clock, holding a thirty-day credential minted now.
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

/// Ada, Bo and Cy in one group, all at the same epoch.
fn three(server: &TestIssuer, clock: &SharedClock) -> (Client, Client, Client) {
    let mut ada = client(server, clock, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(server, clock, 2, "actor-bo", "device-bo-phone");
    let mut cy = client(server, clock, 3, "actor-cy", "device-cy-phone");
    ada.create_group(GROUP).expect("create");
    let add_bo = ada
        .add_member(GROUP, &bo.generate_key_package().expect("kp"))
        .expect("add bo");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.join_from_welcome(&add_bo.welcome.expect("welcome"))
        .expect("bo joins");
    let add_cy = ada
        .add_member(GROUP, &cy.generate_key_package().expect("kp"))
        .expect("add cy");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.process_commit(GROUP, &add_cy.commit)
        .expect("bo sees cy");
    cy.join_from_welcome(&add_cy.welcome.expect("welcome"))
        .expect("cy joins");
    (ada, bo, cy)
}

fn says(receiver: &mut Client, ciphertext: &[u8]) -> Vec<u8> {
    match receiver
        .process_message(GROUP, ciphertext)
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

#[test]
fn a_member_near_expiry_renews_its_leaf_and_keeps_talking_long_past_the_old_exp() {
    let server = issuer();
    let clock = SharedClock::new();
    let (mut ada, mut bo, mut cy) = three(&server, &clock);
    let first_exp = ada
        .own_leaf_credential_expires_at(GROUP)
        .expect("ada's leaf");
    assert_eq!(first_exp, NOW + 30 * DAY);

    // Day 15: nothing is due, and a fresher credential does not make it so.
    clock.set(NOW + 15 * DAY);
    ada.update_credential(
        &token(
            &server,
            1,
            "actor-ada",
            "device-ada-phone",
            NOW + 15 * DAY,
            NOW + 45 * DAY,
        ),
        None,
    )
    .expect("a newer credential for the same device");
    // Fifteen days left is outside the window; what makes a commit due now is
    // only the periodic rotation (tests/leaf_rotation.rs), which this test
    // leaves undone so the renewal below is the leaf's first.
    assert!(ada.leaf_rotation_due(GROUP).expect("rotation due?"));
    let before = NOW + LEAF_ROTATION_INTERVAL_SECONDS - HOUR;
    clock.set(before);
    assert!(
        !ada.credential_refresh_due(GROUP).expect("due?"),
        "a leaf younger than the rotation interval and outside the window is not due"
    );

    // Day 25: inside the ten-day window, and RegisterDevice has handed Ada a
    // credential good to day 55.
    clock.set(NOW + 25 * DAY);
    assert!(first_exp - clock.now_unix() < CREDENTIAL_REFRESH_WINDOW_SECONDS);
    ada.update_credential(
        &token(
            &server,
            1,
            "actor-ada",
            "device-ada-phone",
            NOW + 25 * DAY,
            NOW + 55 * DAY,
        ),
        None,
    )
    .expect("today's credential");
    assert!(ada.credential_refresh_due(GROUP).expect("due?"));
    // Bo's client holds nothing fresher than his leaf, so no RENEWAL is due
    // for him even though his leaf is just as close to its end. A commit is
    // due all the same — his leaf is past the rotation interval — and it
    // would carry the credential he already has.
    assert!(bo.leaf_rotation_due(GROUP).expect("rotation due?"));
    assert!(bo.credential_refresh_due(GROUP).expect("due?"));

    let renewal = ada.refresh_credential(GROUP).expect("ada renews");
    assert!(renewal.welcome.is_none(), "a renewal adds nobody");
    assert!(
        !ada.credential_refresh_due(GROUP).expect("due?"),
        "a staged commit is not a second one due"
    );
    ada.merge_pending_commit(GROUP).expect("the server took it");
    for receiver in [&mut bo, &mut cy] {
        match receiver
            .process_commit(GROUP, &renewal.commit)
            .expect("applies")
        {
            Incoming::Commit(outcome) => {
                assert!(outcome.added.is_empty() && outcome.removed.is_empty());
                assert_eq!(outcome.sender.actor_id, "actor-ada");
            }
            other => panic!("expected a commit, got {other:?}"),
        }
    }
    assert_eq!(
        ada.own_leaf_credential_expires_at(GROUP).expect("leaf"),
        NOW + 55 * DAY
    );
    assert!(!ada.credential_refresh_due(GROUP).expect("due?"));
    // Every member sees the renewed leaf, verified, with its new expiry.
    let seen = bo
        .roster(GROUP)
        .expect("roster")
        .into_iter()
        .filter_map(|entry| entry.identity.ok())
        .find(|identity| identity.actor_id == "actor-ada")
        .expect("ada verifies in bo's roster");
    assert_eq!(seen.expires_at, NOW + 55 * DAY);

    // Day 50: twenty days past Ada's OLD exp. She reads as herself on a
    // credential that is simply valid — no grace involved (the next test
    // stands past the grace itself).
    clock.set(first_exp + 20 * DAY);
    assert!(ada.roster(GROUP).expect("roster").iter().any(|entry| entry
        .identity
        .as_ref()
        .is_ok_and(|id| id.actor_id == "actor-ada")));
    let words = ada.encrypt(GROUP, b"still here").expect("encrypt");
    assert_eq!(says(&mut bo, &words), b"still here");
    assert_eq!(says(&mut cy, &words), b"still here");
}

#[test]
fn past_the_grace_an_unrenewed_leaf_is_refused_and_a_renewed_one_is_not() {
    let server = issuer();
    let clock = SharedClock::new();
    let (mut ada, mut bo, _cy) = three(&server, &clock);

    // Ada renews every twenty-five days on ordinary thirty-day credentials,
    // so that the test can stand past Bo's exp PLUS the whole grace while
    // hers still holds.
    for day in [25, 50, 75] {
        clock.set(NOW + day * DAY);
        renew(
            &server,
            &mut ada,
            1,
            "actor-ada",
            "device-ada-phone",
            NOW + day * DAY,
            NOW + (day + 30) * DAY,
            &mut [&mut bo],
        );
    }

    // One second past Bo's exp plus the grace.
    clock.set(NOW + 30 * DAY + EXPIRED_LEAF_GRACE_SECONDS);
    let from_ada = ada.encrypt(GROUP, b"renewed").expect("encrypt");
    assert_eq!(says(&mut bo, &from_ada), b"renewed");
    // His own client will not seal what every receiver refuses...
    assert!(matches!(
        bo.encrypt(GROUP, b"not renewed"),
        Err(Error::CredentialRejected(CredentialRejection::Expired))
    ));
    // ...and what a build that does seals is refused.
    #[cfg(feature = "test-forgery")]
    {
        bo.act_as_build_sending_while_lapsed();
        let from_bo = bo.encrypt(GROUP, b"not renewed").expect("encrypt");
        assert!(
            expired(ada.process_message(GROUP, &from_bo)),
            "an unrenewed leaf past the grace is refused, exactly as before"
        );
    }

    // Bo's own client KNOWS, so it can stop claiming a seal and ask for a
    // seat — and it will not build the renewal every receiver would refuse
    // while the delivery service (which reads no credentials) took it.
    assert!(bo.leaf_credential_past_grace(GROUP).expect("past grace?"));
    assert!(!ada.leaf_credential_past_grace(GROUP).expect("ada?"));
    let now = NOW + 30 * DAY + EXPIRED_LEAF_GRACE_SECONDS;
    bo.update_credential(
        &token(
            &server,
            2,
            "actor-bo",
            "device-bo-phone",
            now,
            now + 30 * DAY,
        ),
        None,
    )
    .expect("today's credential is still his to hold");
    assert!(!bo.credential_refresh_due(GROUP).expect("due?"));
    assert!(
        matches!(
            bo.refresh_credential(GROUP),
            Err(Error::CredentialRejected(CredentialRejection::Expired))
        ),
        "a renewal past the grace would fork him off the group"
    );
    assert!(!bo.has_pending_commit(GROUP).expect("pending?"));
    // And every other member reads his leaf as unidentified, which is what
    // makes their reconcile evict it and seat his fresh key package.
    assert!(ada
        .roster(GROUP)
        .expect("roster")
        .iter()
        .any(|entry| entry.identity == Err(CredentialRejection::Expired)));
}

#[test]
fn inside_the_grace_a_lapsed_leaf_may_renew_and_nothing_else() {
    let server = issuer();
    let clock = SharedClock::new();
    let (mut ada, mut bo, mut cy) = three(&server, &clock);
    // Ada and Cy renew in time; Bo is the phone that was in a drawer.
    clock.set(NOW + 25 * DAY);
    for (who, tag, actor, device) in [
        (&mut ada, 1u8, "actor-ada", "device-ada-phone"),
        (&mut cy, 3u8, "actor-cy", "device-cy-phone"),
    ] {
        who.update_credential(
            &token(&server, tag, actor, device, NOW + 25 * DAY, NOW + 55 * DAY),
            None,
        )
        .expect("fresh credential");
    }
    let a = ada.refresh_credential(GROUP).expect("ada renews");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.process_commit(GROUP, &a.commit).expect("bo");
    cy.process_commit(GROUP, &a.commit).expect("cy");
    let c = cy.refresh_credential(GROUP).expect("cy renews");
    cy.merge_pending_commit(GROUP).expect("merge");
    ada.process_commit(GROUP, &c.commit).expect("ada");
    bo.process_commit(GROUP, &c.commit).expect("bo");

    // Day 40: Bo's credential lapsed ten days ago.
    clock.set(NOW + 40 * DAY);
    // 1. His own client will not seal until he renews: a receiver calls
    //    what he sends now new, so the send fails where he can see it.
    assert!(matches!(
        bo.encrypt(GROUP, b"back from the drawer"),
        Err(Error::CredentialRejected(CredentialRejection::Expired))
    ));
    // His leaf is still IDENTIFIED in everybody's roster, with the past
    // expiry showing, so no member's reconcile evicts him for having lapsed
    // and his seat is still findable by device.
    let bo_entry = ada
        .roster(GROUP)
        .expect("roster")
        .into_iter()
        .filter_map(|entry| entry.identity.ok())
        .find(|identity| identity.actor_id == "actor-bo")
        .expect("bo's lapsed leaf is identified inside the grace");
    assert_eq!(bo_entry.expires_at, NOW + 30 * DAY);
    assert!(bo_entry.expires_at < NOW + 40 * DAY);
    ada.leaf_of_device(GROUP, "device-bo-phone")
        .expect("findable by device");
    // Bo's own client sees his leaf is expiring but holds nothing fresher:
    // the cue to fetch today's credential from RegisterDevice.
    assert!(bo.leaf_credential_expiring(GROUP).expect("expiring?"));
    assert!(!bo.credential_refresh_due(GROUP).expect("due?"));

    // 2. He may not do anything to anybody else: his own client will not
    //    build a Remove from a lapsed leaf. (Receivers refuse one too, but on
    //    the group's tree clock rather than their own wall — see
    //    every_member_refuses_a_remove_from_a_leaf_the_tree_clock_says_has_lapsed.)
    let cy_leaf = bo.leaf_of_device(GROUP, "device-cy-phone").expect("cy");
    assert!(matches!(
        bo.remove_leaf(GROUP, cy_leaf),
        Err(Error::CredentialRejected(CredentialRejection::Expired))
    ));
    assert!(!bo.has_pending_commit(GROUP).expect("pending?"));

    // 3. A plain key rotation keeps the lapsed credential on the new leaf,
    //    so it renews nothing and is not built either.
    assert!(matches!(
        bo.self_update(GROUP),
        Err(Error::CredentialRejected(CredentialRejection::Expired))
    ));
    assert!(!bo.has_pending_commit(GROUP).expect("pending?"));

    // 4. What he CAN do: his app starts, RegisterDevice hands him today's
    //    credential, and the renewal goes through for everybody.
    bo.update_credential(
        &token(
            &server,
            2,
            "actor-bo",
            "device-bo-phone",
            NOW + 40 * DAY,
            NOW + 70 * DAY,
        ),
        None,
    )
    .expect("bo's credential");
    assert!(bo.credential_refresh_due(GROUP).expect("due?"));
    let renewal = bo.refresh_credential(GROUP).expect("bo renews");
    bo.merge_pending_commit(GROUP).expect("merge");
    ada.process_commit(GROUP, &renewal.commit)
        .expect("ada takes a lapsed leaf's renewal");
    cy.process_commit(GROUP, &renewal.commit)
        .expect("cy takes it too");
    assert!(ada
        .roster(GROUP)
        .expect("roster")
        .iter()
        .all(|entry| entry.identity.is_ok()));

    // And he is now an ordinary member again: his Remove would be judged on
    // its merits, not on his clock.
    let words = bo.encrypt(GROUP, b"renewed").expect("encrypt");
    assert_eq!(says(&mut cy, &words), b"renewed");
}

#[test]
fn a_renewal_that_changes_whose_seat_it_is_is_refused_on_both_sides() {
    let server = issuer();
    let clock = SharedClock::new();
    let (mut ada, mut bo, _cy) = three(&server, &clock);
    let later = NOW + 31 * DAY;

    // Outgoing: the client will not take a credential for another device or
    // another actor, even one that binds its own key and is certified under
    // the account key it holds.
    let (_, bos_key) = device_key_pair(&device_seed(2));
    for (actor, device) in [
        ("actor-bo", "device-bo-laptop"),
        ("actor-eve", "device-bo-phone"),
    ] {
        let swapped = server
            .issue_for_account(
                actor,
                device,
                &bos_key,
                Some(&TestIssuer::test_account_key("actor-bo")),
                NOW,
                later,
            )
            .expect("mint");
        assert!(matches!(
            bo.update_credential(&swapped, None),
            Err(Error::PolicyRefused(DenyReason::UpdateOfAnotherLeaf))
        ));
    }
    // Nor one for somebody else's key.
    assert!(matches!(
        bo.update_credential(
            &token(&server, 9, "actor-bo", "device-bo-phone", NOW, later),
            None
        ),
        Err(Error::CredentialRejected(
            CredentialRejection::LeafKeyMismatch
        ))
    ));
    // Nor an older one.
    assert!(bo
        .update_credential(
            &token(
                &server,
                2,
                "actor-bo",
                "device-bo-phone",
                NOW - DAY,
                NOW + DAY
            ),
            None
        )
        .is_err());
    // And a client holding nothing fresher than its leaf builds no renewal.
    assert!(bo.refresh_credential(GROUP).is_err());

    // Incoming: a forged renewal that re-badges Bo's seat as Eve's — a
    // perfectly valid credential, signed by the server, binding Bo's own key —
    // is refused by every receiver.
    let eve = token(&server, 2, "actor-eve", "device-eve-phone", NOW, later);
    let forged = bo.forge_refresh_credential(GROUP, &eve).expect("forged");
    assert!(matches!(
        ada.process_commit(GROUP, &forged.commit),
        Err(Error::PolicyRefused(DenyReason::UpdateOfAnotherLeaf))
    ));
    bo.clear_pending_commit(GROUP).expect("refused");

    // The same seat, but an EXPIRED new credential: a renewal that renews
    // nothing is refused as expired.
    clock.set(NOW + 10 * DAY);
    let stale = token(
        &server,
        2,
        "actor-bo",
        "device-bo-phone",
        NOW - 29 * DAY,
        NOW + DAY,
    );
    let forged = bo.forge_refresh_credential(GROUP, &stale).expect("forged");
    assert!(expired(ada.process_commit(GROUP, &forged.commit)));
    bo.clear_pending_commit(GROUP).expect("refused");

    // An untrusted issuer's credential for the right seat.
    let foreign = support::other_issuer()
        .issue(
            "actor-bo",
            "device-bo-phone",
            &device_key_pair(&device_seed(2)).1,
            NOW,
            later,
        )
        .expect("mint");
    let forged = bo
        .forge_refresh_credential(GROUP, &foreign)
        .expect("forged");
    assert!(matches!(
        ada.process_commit(GROUP, &forged.commit),
        Err(Error::CredentialRejected(CredentialRejection::UnknownKid))
    ));
}

#[test]
fn a_device_past_the_grace_comes_back_through_a_replace_by_another_member() {
    // THE RECOVERY for a device whose own leaf lapsed past the grace. It
    // cannot renew — every receiver refuses its commit — and it does not need
    // to: it is the same case as a device that slept past the retention
    // window, and it takes the same road (tests/rejoin.rs). It forgets the
    // group, publishes a key package under its FRESH credential, and the next
    // member to open the thread replaces its leaf.
    let server = issuer();
    let clock = SharedClock::new();
    let (mut ada, mut bo, mut cy) = three(&server, &clock);
    // Ada and Cy renew every twenty-five days; Bo never does.
    for day in [25, 50, 75] {
        clock.set(NOW + day * DAY);
        renew(
            &server,
            &mut ada,
            1,
            "actor-ada",
            "device-ada-phone",
            NOW + day * DAY,
            NOW + (day + 30) * DAY,
            &mut [&mut bo, &mut cy],
        );
        renew(
            &server,
            &mut cy,
            3,
            "actor-cy",
            "device-cy-phone",
            NOW + day * DAY,
            NOW + (day + 30) * DAY,
            &mut [&mut ada, &mut bo],
        );
    }

    let far = NOW + 30 * DAY + EXPIRED_LEAF_GRACE_SECONDS + DAY;
    clock.set(far);
    bo.update_credential(
        &token(
            &server,
            2,
            "actor-bo",
            "device-bo-phone",
            far,
            far + 30 * DAY,
        ),
        None,
    )
    .expect("bo's new credential");
    // His own client will not build the renewal: the delivery service would
    // take it and every member refuse it, forking him off the group.
    assert!(bo.leaf_credential_past_grace(GROUP).expect("past grace?"));
    assert!(matches!(
        bo.refresh_credential(GROUP),
        Err(Error::CredentialRejected(CredentialRejection::Expired))
    ));
    // And the receivers do refuse one — built here past the client's check.
    let fresh_bo = token(
        &server,
        2,
        "actor-bo",
        "device-bo-phone",
        far,
        far + 30 * DAY,
    );
    let too_late = bo
        .forge_refresh_credential(GROUP, &fresh_bo)
        .expect("forged past the check");
    assert!(
        expired(ada.process_commit(GROUP, &too_late.commit)),
        "past the grace the renewal itself is refused"
    );
    bo.clear_pending_commit(GROUP).expect("refused");

    // The replace. Ada finds Bo's leaf even though it no longer verifies — and
    // the same-actor guard still holds on a lapsed leaf: a replace handing
    // Bo's seat to somebody else is refused.
    let bo_leaf = ada
        .roster(GROUP)
        .expect("roster")
        .into_iter()
        .find(|entry| entry.identity == Err(CredentialRejection::Expired))
        .expect("bo's lapsed leaf")
        .leaf_index;
    let mut eve = client(&server, &clock, 5, "actor-eve", "device-eve-phone");
    assert!(ada
        .replace_member(GROUP, bo_leaf, &eve.generate_key_package().expect("kp"))
        .is_err());

    bo.forget_group(GROUP).expect("bo forgets");
    let kp = bo.generate_key_package().expect("fresh key package");
    let replace = ada.replace_member(GROUP, bo_leaf, &kp).expect("replace");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.join_from_welcome(&replace.welcome.expect("welcome"))
        .expect("bo is back");
    let words = bo.encrypt(GROUP, b"rejoined").expect("encrypt");
    assert_eq!(says(&mut ada, &words), b"rejoined");
    let _ = &mut eve;
}

#[test]
fn a_newcomer_joins_past_a_lapsed_member_inside_the_grace_but_not_past_it() {
    let server = issuer();
    let clock = SharedClock::new();
    let (mut ada, _bo, _cy) = three(&server, &clock);
    // Ada renews; Bo and Cy never do (devices that never renew).
    clock.set(NOW + 25 * DAY);
    renew(
        &server,
        &mut ada,
        1,
        "actor-ada",
        "device-ada-phone",
        NOW + 25 * DAY,
        NOW + 55 * DAY,
        &mut [],
    );

    // Day 40: Bo and Cy lapsed ten days ago. Dee can still be added.
    clock.set(NOW + 40 * DAY);
    let mut dee = client(&server, &clock, 4, "actor-dee", "device-dee-phone");
    let add = ada
        .add_member(GROUP, &dee.generate_key_package().expect("kp"))
        .expect("add dee");
    ada.merge_pending_commit(GROUP).expect("merge");
    dee.join_from_welcome(&add.welcome.expect("welcome"))
        .expect("a lapsed member inside the grace does not bar the door");

    // Ada keeps renewing, on ordinary thirty-day credentials.
    for day in [50, 75] {
        clock.set(NOW + day * DAY);
        renew(
            &server,
            &mut ada,
            1,
            "actor-ada",
            "device-ada-phone",
            NOW + day * DAY,
            NOW + (day + 30) * DAY,
            &mut [],
        );
    }

    // Past the grace the old, strict answer stands: the group holds a member
    // nobody can vouch for any more, and a newcomer will not join it.
    clock.set(NOW + 30 * DAY + EXPIRED_LEAF_GRACE_SECONDS);
    let mut fay = client(&server, &clock, 6, "actor-fay", "device-fay-phone");
    let add = ada
        .add_member(GROUP, &fay.generate_key_package().expect("kp"))
        .expect("add fay");
    ada.merge_pending_commit(GROUP).expect("merge");
    assert!(matches!(
        fay.join_from_welcome(&add.welcome.expect("welcome")),
        Err(Error::CredentialRejected(CredentialRejection::Expired))
    ));
}

// ---- Clock forks and unidentified leaves ------------------------------------
//
// Each test below goes red without the rule it names. The first two are
// forks: a commit every other member merged, refused by one member for a
// reason that belonged to that member's clock rather than to the commit.

/// A client on `clock` holding a credential minted at `iat`, expiring `exp`.
#[allow(clippy::too_many_arguments)]
fn client_holding(
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

#[test]
fn a_member_catching_up_after_a_leaf_lapsed_applies_what_the_rest_merged() {
    // Ada's leaf is good to day 30. On day 25 she rotates her key
    // (a commit whose update path carries that same credential) and adds Dee,
    // whose key package expires on day 27 — live when Ada checked it. Cy is
    // online and takes both. Bo is offline from day 24 and catches up on day
    // 37: a week after Ada's leaf lapsed and ten days after Dee's package did.
    // He must land where Cy is, or he sits on the old epoch forever.
    let server = issuer();
    let clock = SharedClock::new();
    let (mut ada, mut bo, mut cy) = three(&server, &clock);

    clock.set(NOW + 25 * DAY);
    let rotation = ada.self_update(GROUP).expect("ada rotates on a live leaf");
    ada.merge_pending_commit(GROUP).expect("merge");
    cy.process_commit(GROUP, &rotation.commit)
        .expect("cy, on time");

    let mut dee = client_holding(
        &server,
        &clock,
        4,
        "actor-dee",
        "device-dee-phone",
        NOW - 3 * DAY,
        NOW + 27 * DAY,
    );
    let add = ada
        .add_member(GROUP, &dee.generate_key_package().expect("kp"))
        .expect("a package with two days left is addable");
    ada.merge_pending_commit(GROUP).expect("merge");
    cy.process_commit(GROUP, &add.commit).expect("cy, on time");
    dee.join_from_welcome(&add.welcome.expect("welcome"))
        .expect("dee joins");

    clock.set(NOW + 37 * DAY);
    bo.process_commit(GROUP, &rotation.commit)
        .expect("a path leaf that lapsed after the commit was made is still that commit's");
    match bo
        .process_commit(GROUP, &add.commit)
        .expect("the add applies late")
    {
        Incoming::Commit(outcome) => {
            assert_eq!(outcome.added.len(), 1);
            assert_eq!(outcome.added[0].actor_id, "actor-dee");
        }
        other => panic!("expected a commit, got {other:?}"),
    }
    assert_eq!(
        bo.epoch(GROUP).expect("epoch"),
        cy.epoch(GROUP).expect("epoch"),
        "bo is on the epoch everybody else is on"
    );
    // Ada's own client will not seal on her lapsed leaf: what she sent now
    // would be new to every receiver. She renews first, as her app does.
    assert!(matches!(
        ada.encrypt(GROUP, b"welcome back"),
        Err(Error::CredentialRejected(CredentialRejection::Expired))
    ));

    // What the lapsed leaf may NOT do is still refused — by its own client,
    // on the one clock that decides it.
    assert!(matches!(
        ada.add_member(
            GROUP,
            &client(&server, &clock, 5, "actor-eve", "device-eve-phone")
                .generate_key_package()
                .expect("kp")
        ),
        Err(Error::CredentialRejected(CredentialRejection::Expired))
    ));
}

#[test]
fn a_receiver_whose_clock_runs_slow_still_takes_a_renewal_minted_a_moment_ago() {
    // The renewal leaf's credential is minted seconds before the
    // commit, so its `iat` is in the future for any member whose clock is
    // more than a minute slow. Bo's is ten minutes slow.
    let server = issuer();
    let ada_clock = SharedClock::new();
    let bo_clock = SharedClock::new();
    bo_clock.set(NOW - 10 * 60);
    let mut ada = client(&server, &ada_clock, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(&server, &bo_clock, 2, "actor-bo", "device-bo-phone");
    ada.create_group(GROUP).expect("create");
    let add = ada
        .add_member(GROUP, &bo.generate_key_package().expect("kp"))
        .expect("add bo");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.join_from_welcome(&add.welcome.expect("welcome"))
        .expect("bo joins");

    let day25 = NOW + 25 * DAY;
    ada_clock.set(day25);
    bo_clock.set(day25 - 10 * 60);
    ada.update_credential(
        &token(
            &server,
            1,
            "actor-ada",
            "device-ada-phone",
            day25,
            day25 + 30 * DAY,
        ),
        None,
    )
    .expect("today's credential, by ada's clock");
    let renewal = ada.refresh_credential(GROUP).expect("renew");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.process_commit(GROUP, &renewal.commit)
        .expect("a slow clock does not refuse a renewal everybody else merged");

    // After it, her messages carry the new credential, and his roster names
    // her — neither may read that `iat` as a forgery either.
    let words = ada.encrypt(GROUP, b"on time").expect("encrypt");
    assert_eq!(says(&mut bo, &words), b"on time");
    let seen = bo
        .roster(GROUP)
        .expect("roster")
        .into_iter()
        .find(|entry| {
            entry
                .identity
                .as_ref()
                .is_ok_and(|id| id.actor_id == "actor-ada")
        })
        .expect("ada is identified on a slow clock");
    assert_eq!(
        seen.identity.expect("ok").expires_at,
        day25 + 30 * DAY,
        "the renewed leaf, not the old one"
    );
}

#[test]
fn a_renewal_may_not_wind_a_seat_back_to_an_older_credential() {
    // The rule that bounds the relaxation above: a received leaf's
    // credential may be lapsed (inside the grace) or from the reader's future,
    // but never older than the one it replaces.
    let server = issuer();
    let clock = SharedClock::new();
    let (mut ada, mut bo, _cy) = three(&server, &clock);
    clock.set(NOW + 5 * DAY);
    let older = token(
        &server,
        2,
        "actor-bo",
        "device-bo-phone",
        NOW - 2 * DAY,
        NOW + 28 * DAY,
    );
    let forged = bo.forge_refresh_credential(GROUP, &older).expect("forged");
    assert!(expired(ada.process_commit(GROUP, &forged.commit)));
}

#[test]
fn a_device_stops_renewing_a_day_before_the_grace_ends() {
    // The sender's last renewal and every receiver's cutoff are
    // two lines a day apart, so a renewal built at the very edge cannot be
    // taken by some members and refused by others.
    let server = issuer();
    let clock = SharedClock::new();
    let (mut ada, mut bo, _cy) = three(&server, &clock);
    for day in [25, 50, 75] {
        clock.set(NOW + day * DAY);
        renew(
            &server,
            &mut ada,
            1,
            "actor-ada",
            "device-ada-phone",
            NOW + day * DAY,
            NOW + (day + 30) * DAY,
            &mut [&mut bo],
        );
    }

    let bo_exp = NOW + 30 * DAY;
    // Two days before the grace ends: still renewable.
    let early = bo_exp + EXPIRED_LEAF_GRACE_SECONDS - 2 * DAY;
    clock.set(early);
    bo.update_credential(
        &token(
            &server,
            2,
            "actor-bo",
            "device-bo-phone",
            early,
            early + 30 * DAY,
        ),
        None,
    )
    .expect("bo's fresh credential");
    assert!(!bo.leaf_credential_past_grace(GROUP).expect("past?"));
    assert!(bo.credential_refresh_due(GROUP).expect("due?"));

    // Twelve hours before it ends: the sender has stopped...
    clock.set(bo_exp + EXPIRED_LEAF_GRACE_SECONDS - 12 * HOUR);
    assert!(bo.leaf_credential_past_grace(GROUP).expect("past?"));
    assert!(!bo.credential_refresh_due(GROUP).expect("due?"));
    assert!(matches!(
        bo.refresh_credential(GROUP),
        Err(Error::CredentialRejected(CredentialRejection::Expired))
    ));
    // ...while every receiver still reads his leaf as identified, so nobody
    // evicts him before the seat he asks for can be handed back by a replace.
    assert!(ada
        .roster(GROUP)
        .expect("roster")
        .iter()
        .all(|entry| entry.identity.is_ok()));
    assert_eq!(peachy_mls_core::RENEWAL_CUTOFF_MARGIN_SECONDS, DAY);
}

#[test]
fn a_replace_refuses_a_seat_whose_owner_cannot_be_read() {
    // A leaf whose issuer key rotated out of the trusted set cannot be
    // identified. If the same-actor guard skipped it, the one seat nobody
    // could vouch for would be the one a replace would hand to anybody.
    let server = issuer();
    let retired = support::other_issuer();
    let clock = SharedClock::new();
    let kv = peachy_mls_core::MemoryKv::new();
    let both = {
        let mut keys = server.trusted_keys().expect("trusted");
        keys.insert(retired.kid(), &retired.public_key())
            .expect("trust the retiring key too");
        keys
    };
    let open_ada = |trusted: peachy_mls_core::TrustedServerKeys| {
        let mut config = ClientConfig::new(
            token(
                &server,
                1,
                "actor-ada",
                "device-ada-phone",
                NOW - HOUR,
                NOW + 30 * DAY,
            ),
            device_seed(1),
            trusted,
        )
        .with_storage(PeachyStorage::open(Box::new(kv.clone())).expect("open"))
        .with_own_account_identity(Some(support::held_identity("actor-ada")));
        config.clock = Some(Box::new(clock.clone()));
        Client::new(config).expect("ada")
    };

    // Bo's credential is signed by the key that is about to be retired.
    let bo_token = {
        let (_, public) = device_key_pair(&device_seed(2));
        retired
            .issue(
                "actor-bo",
                "device-bo-phone",
                &public,
                NOW - HOUR,
                NOW + 30 * DAY,
            )
            .expect("mint")
    };
    let mut bo_config = ClientConfig::new(bo_token, device_seed(2), both.clone())
        .with_storage(PeachyStorage::in_memory())
        .with_own_account_identity(Some(support::held_identity("actor-bo")));
    bo_config.clock = Some(Box::new(clock.clone()));
    let bo = Client::new(bo_config).expect("bo");
    {
        let mut ada = open_ada(both);
        ada.create_group(GROUP).expect("create");
        ada.add_member(GROUP, &bo.generate_key_package().expect("kp"))
            .expect("add bo");
        ada.merge_pending_commit(GROUP).expect("merge");
    }

    // The key rotates out. Ada's reopened client can no longer read Bo's leaf.
    let mut ada = open_ada(server.trusted_keys().expect("trusted"));
    let bo_leaf = ada
        .roster(GROUP)
        .expect("roster")
        .into_iter()
        .find(|entry| entry.identity.is_err())
        .expect("bo's leaf is unidentified")
        .leaf_index;
    let eve = client(&server, &clock, 5, "actor-eve", "device-eve-phone");
    assert!(
        ada.replace_member(GROUP, bo_leaf, &eve.generate_key_package().expect("kp"))
            .is_err(),
        "an unreadable seat is removed, never handed to somebody else"
    );
    assert!(!ada.has_pending_commit(GROUP).expect("pending?"));
    // Removal is still open to it: that is the road back for its device.
    ada.remove_leaf(GROUP, bo_leaf)
        .expect("an unidentified leaf can be removed");
}

// ---- The TREE CLOCK ---------------------------------------------------------
//
// Every verdict on a received commit is judged at the group's tree clock — the
// latest issuer-signed `iat` in the tree or in the commit — so it comes out
// the same on every member whatever their wall says.

/// Renew `who`'s credential to (`iat`, `exp`) and commit it; everybody in
/// `others` applies it.
#[allow(clippy::too_many_arguments)]
fn renew(
    server: &TestIssuer,
    who: &mut Client,
    tag: u8,
    actor: &str,
    device: &str,
    iat: i64,
    exp: i64,
    others: &mut [&mut Client],
) {
    who.update_credential(&token(server, tag, actor, device, iat, exp), None)
        .expect("a fresher credential");
    let renewal = who.refresh_credential(GROUP).expect("renew");
    who.merge_pending_commit(GROUP).expect("merge");
    for other in others.iter_mut() {
        other
            .process_commit(GROUP, &renewal.commit)
            .expect("applies");
    }
}

/// Bo's leaf lapses on day 30 and is not renewed — a phone stolen and
/// revoked, so RegisterDevice will never renew it again. Cy renews on day 35,
/// which puts the tree clock past Bo's `exp`.
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
        NOW + 55 * DAY,
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
        NOW + 65 * DAY,
        &mut [&mut ada, &mut bo],
    );
    (ada, bo, cy)
}

/// A lapsed leaf's client refusing to build a Remove binds only an honest
/// client. A modified build skips that check, and SubmitCommit's
/// senderDeviceId is the caller's claim, so the delivery service takes it.
/// Every RECEIVER must refuse it — on the tree clock, so the refusal does not
/// depend on when each of them reads it.
#[cfg(feature = "test-forgery")]
#[test]
fn every_member_refuses_a_remove_from_a_leaf_the_tree_clock_says_has_lapsed() {
    let server = issuer();
    let clock = SharedClock::new();
    let (mut ada, mut bo, mut cy) = bo_lapsed_on_the_tree_clock(&server, &clock);

    clock.set(NOW + 40 * DAY);
    let cy_leaf = bo.leaf_of_device(GROUP, "device-cy-phone").expect("cy");
    let forged = bo
        .forge_remove_leaf(GROUP, cy_leaf)
        .expect("a modified client builds it");
    let epoch = ada.epoch(GROUP).expect("epoch");
    for (receiver, wall) in [(&mut ada, NOW + 31 * DAY), (&mut cy, NOW + 80 * DAY)] {
        // Whatever the receiver's wall says — a day after the exp, or deep
        // into the grace — the answer is the same.
        clock.set(wall);
        assert!(
            expired(receiver.process_commit(GROUP, &forged.commit)),
            "{} applied a lapsed leaf's Remove",
            receiver.identity().device_id
        );
        assert_eq!(receiver.epoch(GROUP).expect("epoch"), epoch);
    }
    assert!(cy.is_active(GROUP).expect("active"), "cy is still in");

    // What a lapsed leaf may still do is renew: no proposals, a path leaf.
    clock.set(NOW + 40 * DAY);
    bo.clear_pending_commit(GROUP).expect("clear");
    renew(
        &server,
        &mut bo,
        2,
        "actor-bo",
        "device-bo-phone",
        NOW + 40 * DAY,
        NOW + 70 * DAY,
        &mut [&mut ada, &mut cy],
    );
}

/// The committer-side mirror of the test above. Bo's clock runs slow — it reads day 29, a day
/// before his `exp` — but the group has a leaf minted on day 35, so every
/// receiver would call him lapsed. His own client must not build a Remove
/// the rest will refuse.
#[test]
fn a_device_whose_clock_runs_slow_does_not_build_what_the_tree_clock_refuses() {
    let server = issuer();
    let clock = SharedClock::new();
    let (_ada, mut bo, _cy) = bo_lapsed_on_the_tree_clock(&server, &clock);

    clock.set(NOW + 29 * DAY);
    let cy_leaf = bo.leaf_of_device(GROUP, "device-cy-phone").expect("cy");
    assert!(matches!(
        bo.remove_leaf(GROUP, cy_leaf),
        Err(Error::CredentialRejected(CredentialRejection::Expired))
    ));
    assert!(!bo.has_pending_commit(GROUP).expect("pending?"));
}

/// The fork of `a_member_catching_up_after_a_leaf_lapsed_applies_what_the_rest_merged`,
/// fifty-six days further out. Ada adds Dee on day 25, on a leaf good to day
/// 30, with a package that expires on day 27; Cy takes it on time. Bo was
/// offline until day 90 — past Ada's exp PLUS the whole grace, and past Dee's
/// too. Judged on his wall he would refuse the sender and the package and sit
/// on the old epoch for good; judged on the tree clock
/// (which reads roughly the day the group was made), he lands where Cy is.
#[test]
fn a_member_catching_up_past_the_grace_applies_what_the_rest_merged() {
    let server = issuer();
    let clock = SharedClock::new();
    let (mut ada, mut bo, mut cy) = three(&server, &clock);

    clock.set(NOW + 25 * DAY);
    let mut dee = client_holding(
        &server,
        &clock,
        4,
        "actor-dee",
        "device-dee-phone",
        NOW - 3 * DAY,
        NOW + 27 * DAY,
    );
    let add = ada
        .add_member(GROUP, &dee.generate_key_package().expect("kp"))
        .expect("addable on day 25");
    ada.merge_pending_commit(GROUP).expect("merge");
    cy.process_commit(GROUP, &add.commit).expect("cy, on time");
    dee.join_from_welcome(&add.welcome.expect("welcome"))
        .expect("dee joins");

    clock.set(NOW + 90 * DAY);
    match bo
        .process_commit(GROUP, &add.commit)
        .expect("the add applies ninety days late")
    {
        Incoming::Commit(outcome) => {
            assert_eq!(outcome.added.len(), 1);
            assert_eq!(outcome.added[0].actor_id, "actor-dee");
        }
        other => panic!("expected a commit, got {other:?}"),
    }
    assert_eq!(
        bo.epoch(GROUP).expect("epoch"),
        cy.epoch(GROUP).expect("epoch"),
        "bo is on the epoch everybody else is on"
    );
    // A MESSAGE is still judged on the reader's wall: no state forks on it,
    // and past the grace Ada's unrenewed leaf is not heard. Her own client
    // will not seal one there, and what a build that does seals is refused.
    assert!(matches!(
        ada.encrypt(GROUP, b"anyone?"),
        Err(Error::CredentialRejected(CredentialRejection::Expired))
    ));
    #[cfg(feature = "test-forgery")]
    {
        ada.act_as_build_sending_while_lapsed();
        let words = ada.encrypt(GROUP, b"anyone?").expect("encrypt");
        assert!(expired(bo.process_message(GROUP, &words)));
    }
}

/// A standalone proposal is judged on the tree clock too, and every
/// member reaches the same verdict on it whatever its wall. Bo's leaf is good
/// to day 30 and he proposes an Update on day 29. Ada reads it on day 29 and
/// Cy on day 31; on their walls they disagreed. On the tree clock his leaf is
/// live for both, and both refuse the proposal for the one reason that does
/// not depend on time: it arrived by reference, and Peachy takes none
/// (`mls/core/tests/proposals_by_reference.rs`).
#[cfg(feature = "test-forgery")]
#[test]
fn every_member_reaches_the_same_verdict_on_a_proposal_whatever_its_wall() {
    let server = issuer();
    let clock = SharedClock::new();
    let (mut ada, mut bo, mut cy) = three(&server, &clock);

    clock.set(NOW + 29 * DAY);
    let proposal = bo.forge_propose_self_update(GROUP).expect("proposal");
    for (receiver, wall) in [(&mut ada, NOW + 29 * DAY), (&mut cy, NOW + 31 * DAY)] {
        clock.set(wall);
        assert!(
            matches!(
                receiver.forge_process_any(GROUP, &proposal),
                Err(Error::PolicyRefused(DenyReason::ProposalByReference))
            ),
            "{} judged a proposal the tree clock calls live as anything but by reference",
            receiver.identity().device_id
        );
    }
}

/// The other half of the test above: once the tree clock has passed Bo's exp, his proposal is
/// refused by everybody — including a member whose wall still reads a day
/// before it.
#[cfg(feature = "test-forgery")]
#[test]
fn every_member_refuses_a_proposal_from_a_leaf_the_tree_clock_says_has_lapsed() {
    let server = issuer();
    let clock = SharedClock::new();
    let (mut ada, mut bo, mut cy) = bo_lapsed_on_the_tree_clock(&server, &clock);

    clock.set(NOW + 40 * DAY);
    let proposal = bo.forge_propose_self_update(GROUP).expect("proposal");
    for (receiver, wall) in [(&mut ada, NOW + 29 * DAY), (&mut cy, NOW + 40 * DAY)] {
        clock.set(wall);
        assert!(
            expired(receiver.forge_process_any(GROUP, &proposal)),
            "{} stored a lapsed leaf's proposal",
            receiver.identity().device_id
        );
    }
}
