// SPDX-License-Identifier: MIT
//! A KeyPackage's lifetime is checked by the member that adds it, on its
//! own clock (`peachy_mls_core::key_package_lifetime`;
//! docs/identity.md §A KeyPackage's lifetime is checked by its
//! adder).
//!
//! - **The adder refuses a window no honest device mints**: one that lapses
//!   inside the mailbox horizon, one longer than RFC 9420's maximum, one that
//!   starts after the adder's now, and one that started less than fifty
//!   minutes before it (no backdate), which a reader whose clock lags the
//!   adder's by seconds would refuse. At an add, a founding's checks and
//!   `key_package_identity` alike, so nothing is committed that a late
//!   member could read as lapsed.
//! - **A joiner does not judge the Welcome's tree on its clock**, so a leaf
//!   whose member never renewed it does not shut the group to every later
//!   join.
//! - **A package the founding commit refuses claims nothing**: not the device
//!   id or account key of a later package of the same device.
//!
//! OpenMLS reads a lifetime on the wall clock, and the core on its own,
//! which the other tests fix at [`NOW`]. So each test here first steps the
//! core's clock onto the wall ([`on_the_wall`]) and issues its credentials
//! there: both then judge one instant, as on a device.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod support;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openmls::prelude::{
    BasicCredential, Capabilities, Ciphersuite, Credential, CredentialWithKey, KeyPackage,
    Lifetime, MlsMessageOut,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::types::SignatureScheme;
use peachy_mls_core::group_meta::group_meta_extension_type;
use peachy_mls_core::key_package_lifetime::{
    ADDER_BACKDATE_SECONDS, ADDER_HORIZON_SECONDS, MAX_LIFETIME_RANGE_SECONDS,
};
use peachy_mls_core::{Client, Incoming, PEACHY_CIPHERSUITE};
use peachy_mls_core::{ClientConfig, PeachyStorage};
use support::{
    advance_ms, device_seed, head_of, held_identity, issuer, join_at_head, step_wall_ms, TestClock,
    DAY, HOUR, NOW,
};

const G: &[u8] = b"3c1f6e0a-7b2d-4c8e-9a5f-1e0d2c4b6a88";
const ALICE: &str = "aaaaaaaa-0000-4000-8000-000000000001";
const BOB: &str = "bbbbbbbb-0000-4000-8000-000000000002";
const CAROL: &str = "cccccccc-0000-4000-8000-000000000003";
const MALLORY: &str = "ffffffff-0000-4000-8000-000000000006";
const ALICE_PHONE: &str = "aaaaaaaa-1111-4111-8111-000000000001";
const BOB_PHONE: &str = "bbbbbbbb-1111-4111-8111-000000000003";
const CAROL_PHONE: &str = "cccccccc-1111-4111-8111-000000000004";
const MALLORY_PHONE: &str = "ffffffff-1111-4111-8111-000000000006";
const MALLORY_TAG: u8 = 66;

fn secs(t: i64) -> u64 {
    u64::try_from(t).unwrap()
}

/// A package of `(actor, device)`, the device seeded by `tag`, signed by
/// that device under `token`, in `suite`, with the window its own (modified)
/// client chose.
fn package(
    tag: u8,
    token: Vec<u8>,
    suite: Ciphersuite,
    not_before: i64,
    not_after: i64,
) -> Vec<u8> {
    let seed = device_seed(tag);
    let (_, public) = peachy_mls_core::issuer::device_key_pair(&seed);
    let signer =
        SignatureKeyPair::from_raw(SignatureScheme::ED25519, seed.to_vec(), public.to_vec());
    let credential_with_key = CredentialWithKey {
        credential: Credential::from(BasicCredential::new(token)),
        signature_key: public.to_vec().into(),
    };
    let meta = [group_meta_extension_type()];
    let bundle = KeyPackage::builder()
        .leaf_node_capabilities(Capabilities::new(
            None,
            Some(&[suite]),
            Some(&meta[..]),
            None,
            None,
        ))
        .key_package_lifetime(Lifetime::init(secs(not_before), secs(not_after)))
        .build(
            suite,
            &OpenMlsRustCrypto::default(),
            &signer,
            credential_with_key,
        )
        .unwrap();
    MlsMessageOut::from(bundle.key_package().clone())
        .to_bytes()
        .unwrap()
}

/// The wall clock, in seconds: the clock OpenMLS reads a lifetime on.
fn wall_now() -> i64 {
    let since = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    i64::try_from(since.as_secs()).unwrap()
}

/// Step the core's clock (every client this test builds) onto the wall
/// clock, and answer that instant.
fn on_the_wall() -> i64 {
    let now = wall_now();
    step_wall_ms((now - NOW) * 1_000);
    now
}

/// The credential of `(actor, device)`, the device seeded by `tag`, issued
/// an hour before `t` for thirty days.
fn token_at(tag: u8, actor: &str, device: &str, t: i64) -> Vec<u8> {
    let (_, public) = peachy_mls_core::issuer::device_key_pair(&device_seed(tag));
    issuer()
        .issue(actor, device, &public, t - HOUR, t + 30 * DAY)
        .unwrap()
}

/// A client whose credential was issued at `t`, on the test's clock.
fn client_at(tag: u8, actor: &str, device: &str, t: i64) -> Client {
    let token = token_at(tag, actor, device, t);
    let mut config = ClientConfig::new(token, device_seed(tag), issuer().trusted_keys().unwrap())
        .with_storage(PeachyStorage::in_memory())
        .with_own_account_identity(Some(held_identity(actor)));
    config.clock = Some(Box::new(TestClock));
    Client::new(config).unwrap()
}

/// Mallory's package, under her own credential issued at `t`, with the
/// window her (modified) client chose.
fn mallory(t: i64, not_before: i64, not_after: i64) -> Vec<u8> {
    let token = token_at(MALLORY_TAG, MALLORY, MALLORY_PHONE, t);
    package(
        MALLORY_TAG,
        token,
        PEACHY_CIPHERSUITE,
        not_before,
        not_after,
    )
}

fn reads(sender: &mut Client, reader: &mut Client, text: &[u8]) -> bool {
    let wire = sender.encrypt(G, text).unwrap();
    matches!(
        reader.process_message(G, &wire),
        Ok(Incoming::Application { plaintext, .. }) if plaintext == text
    )
}

#[test]
fn the_adder_refuses_a_window_no_device_mints_at_every_door() {
    let t = on_the_wall();
    let mut alice = client_at(1, ALICE, ALICE_PHONE, t);
    let bob = client_at(2, BOB, BOB_PHONE, t);
    let horizon = i64::try_from(ADDER_HORIZON_SECONDS).unwrap();
    let range = i64::try_from(MAX_LIFETIME_RANGE_SECONDS).unwrap();
    let backdate = i64::try_from(ADDER_BACKDATE_SECONDS).unwrap();
    let refused = [
        // Lapsing within the hour: live for OpenMLS at the add, lapsed for
        // whoever reads the Add later.
        mallory(t, t - HOUR, t + HOUR),
        // Lapsing inside the mailbox horizon.
        mallory(t, t - HOUR, t + horizon - 1),
        // Longer than RFC 9420's maximum (and than any device mints).
        mallory(t, t - HOUR, t - HOUR + range + 1),
        // Starting after the adder's now (OpenMLS refuses this one).
        mallory(t, t + 2 * 60, t + 84 * DAY),
        // Starting at the adder's now, with no backdate: OpenMLS takes it
        // here, and a member whose clock is seconds behind refuses the Add.
        mallory(t, wall_now(), t + 84 * DAY),
        // Backdated by less than the adder's fifty minutes.
        mallory(t, t - backdate + 5 * 60, t + 84 * DAY),
    ];
    let good = bob.generate_key_package().unwrap();

    alice.create_group(G).unwrap();
    let mut listed = refused.to_vec();
    listed.push(good.clone());
    assert_eq!(
        alice.founding_refusals(G, &listed).unwrap(),
        vec![0, 1, 2, 3, 4, 5],
        "a founding leaves out every such package, and keeps the honest one"
    );
    for bytes in &refused {
        assert!(alice.key_package_identity(bytes).is_err());
    }
    let state = format!(r#"{{"v":1,"n":"","adm":["{ALICE}"],"dm":false}}"#);
    alice.set_group_meta(G, state.as_bytes()).unwrap();
    alice.merge_pending_commit(G).unwrap();
    for bytes in &refused {
        assert!(alice.add_member(G, bytes).is_err(), "add_member refuses it");
    }
    assert!(alice.leaf_of_device(G, MALLORY_PHONE).is_err());
    // The longest honest window is added, and so is one backdated by just
    // the adder's fifty minutes.
    let edge = mallory(t, t - HOUR, t - HOUR + range);
    alice.add_member(G, &edge).unwrap();
    alice.merge_pending_commit(G).unwrap();
    let late = package(
        3,
        token_at(3, CAROL, CAROL_PHONE, t),
        PEACHY_CIPHERSUITE,
        t - backdate,
        t + 84 * DAY,
    );
    alice.add_member(G, &late).unwrap();
    alice.merge_pending_commit(G).unwrap();
}

#[test]
fn an_honest_package_is_added_a_month_after_it_was_minted() {
    let t = on_the_wall();
    let mut alice = client_at(1, ALICE, ALICE_PHONE, t);
    let bob = client_at(2, BOB, BOB_PHONE, t);
    let package = bob.generate_key_package().unwrap();
    alice.create_group(G).unwrap();
    // Twenty-nine days on, inside both credentials' thirty.
    advance_ms(29 * 24 * 3_600 * 1_000);
    assert!(alice.key_package_identity(&package).unwrap().is_ok());
    alice.add_member(G, &package).unwrap();
    alice.merge_pending_commit(G).unwrap();
}

#[test]
fn a_leaf_whose_window_closed_does_not_shut_the_group_to_joiners() {
    let t = on_the_wall();
    let mut alice = client_at(1, ALICE, ALICE_PHONE, t);
    let mut carol = client_at(3, CAROL, CAROL_PHONE, t);
    alice.create_group(G).unwrap();
    let state = format!(r#"{{"v":1,"n":"","adm":["{ALICE}"],"dm":false}}"#);
    alice.set_group_meta(G, state.as_bytes()).unwrap();
    alice.merge_pending_commit(G).unwrap();
    // A leaf seated past the adder's door, never renewed, whose window
    // closes on the wall clock seconds after it is seated.
    let closes = wall_now() + 5;
    alice
        .forge_commit(G, &[], &[&mallory(t, t - HOUR, closes)])
        .unwrap();
    alice.merge_pending_commit(G).unwrap();
    while wall_now() <= closes {
        std::thread::sleep(Duration::from_millis(250));
    }
    let add = alice
        .add_member(G, &carol.generate_key_package().unwrap())
        .unwrap();
    alice.merge_pending_commit(G).unwrap();
    join_at_head(&mut carol, &add.welcome.unwrap(), head_of(&alice, G))
        .expect("the joiner takes its seat");
    assert!(reads(&mut alice, &mut carol, b"in"));
}

#[test]
fn a_package_the_founding_commit_refuses_claims_no_device_id() {
    let t = on_the_wall();
    let mut alice = client_at(1, ALICE, ALICE_PHONE, t);
    let bob = client_at(2, BOB, BOB_PHONE, t);
    let carol = client_at(3, CAROL, CAROL_PHONE, t);
    // Bob's own credential, in a package of another cipher suite: every
    // check of the founding passes it, and only the MLS commit refuses it.
    let spoiled = package(
        2,
        token_at(2, BOB, BOB_PHONE, t),
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        t - HOUR,
        t + 84 * DAY,
    );
    let packages = vec![
        spoiled,
        bob.generate_key_package().unwrap(),
        carol.generate_key_package().unwrap(),
    ];
    alice.create_group(G).unwrap();
    assert_eq!(
        alice.founding_refusals(G, &packages).unwrap(),
        vec![0],
        "only the spoiled package is left out; Bob's own is not shadowed by it"
    );
}
