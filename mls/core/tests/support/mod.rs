// SPDX-License-Identifier: MIT
//! Shared scaffolding for the integration tests.
//!
//! One issuer, deterministic seeds, and a fixed clock, so that every assertion
//! in this suite is about the code and none of them is about what day it is.
//!
//! Each test binary compiles this module separately, so whatever one file does
//! not use is dead code in that build — hence the blanket allow, rather than a
//! per-file list that goes stale.

#![allow(dead_code)]

use std::cell::Cell;

use peachy_mls_core::issuer::TestIssuer;
use peachy_mls_core::{
    account_identity_public_key, Client, ClientConfig, Clock, PeachyStorage, TrustedServerKeys,
};

thread_local! {
    /// How far this test has moved the clock past [`NOW`], in milliseconds.
    /// Per thread, so tests running side by side never move each other's.
    static AHEAD_MS: Cell<i64> = const { Cell::new(0) };
    /// How far this test has stepped the WALL clock alone (a device whose
    /// clock was set back or forward), in milliseconds.
    static WALL_STEP_MS: Cell<i64> = const { Cell::new(0) };
}

fn wall_ahead_ms() -> i64 {
    AHEAD_MS.with(Cell::get) + WALL_STEP_MS.with(Cell::get)
}

/// The clock every [`client`] reads: [`NOW`], plus whatever this test moved
/// it on with [`advance_ms`] (and, on the wall clock alone, stepped it with
/// [`step_wall_ms`]). Until a test does, it is a fixed clock.
#[derive(Debug, Clone, Copy)]
pub struct TestClock;

impl Clock for TestClock {
    fn now_unix(&self) -> i64 {
        NOW + wall_ahead_ms().div_euclid(1000)
    }
    fn now_unix_ms(&self) -> i64 {
        NOW * 1000 + wall_ahead_ms()
    }
    /// Only [`advance_ms`] moves it; [`step_wall_ms`] does not.
    fn monotonic_ms(&self) -> u64 {
        u64::try_from(AHEAD_MS.with(Cell::get)).unwrap_or(0)
    }
}

/// Move the clock of every client this test (thread) built on by `ms`: time
/// passes, on the wall clock and the monotonic one alike.
pub fn advance_ms(ms: u64) {
    let ms = i64::try_from(ms).expect("a step that fits");
    AHEAD_MS.with(|ahead| ahead.set(ahead.get() + ms));
}

/// Step only the WALL clock of every client this test built on by `ms`
/// (negative: back), as when a device's clock is set: no time passes.
pub fn step_wall_ms(ms: i64) {
    WALL_STEP_MS.with(|step| step.set(step.get() + ms));
}

/// The instant every test pretends it is: 2026-09-16T00:00:00Z. Any fixed
/// value would do; one shared instant is easier to recognize in a failure.
pub const NOW: i64 = 1_789_516_800;

pub const HOUR: i64 = 3_600;
pub const DAY: i64 = 24 * HOUR;

/// The one test issuer. Seeded, so its `kid` is the same on every machine.
pub fn issuer() -> TestIssuer {
    TestIssuer::from_seed(&[7u8; 32])
}

/// A second issuer, for "signed by a key you do not trust".
pub fn other_issuer() -> TestIssuer {
    TestIssuer::from_seed(&[9u8; 32])
}

/// A device seed derived from one byte, so `device(1)` is stable and readable.
pub fn device_seed(tag: u8) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[0] = tag;
    seed[1] = 0xA5;
    seed
}

/// Build a client with a freshly minted, currently-valid credential, over a
/// store that dies with it.
pub fn client(issuer: &TestIssuer, tag: u8, actor: &str, device: &str) -> Client {
    client_on(issuer, tag, actor, device, PeachyStorage::in_memory())
}

/// The exact `pdc1` token a [`client`] built with these arguments carries in
/// its leaf credential.
///
/// Issuance is deterministic here — a seeded issuer, a seeded device key and a
/// fixed clock — so this is the same byte string, not merely an equivalent one.
/// It exists so that a test asserting a credential is ABSENT from some bytes
/// has a needle it did not have to pick out of the thing it is searching.
pub fn credential_token(issuer: &TestIssuer, tag: u8, actor: &str, device: &str) -> Vec<u8> {
    let seed = device_seed(tag);
    let (_, public) = peachy_mls_core::issuer::device_key_pair(&seed);
    issuer
        .issue(actor, device, &public, NOW - HOUR, NOW + 30 * DAY)
        .expect("the test issuer should mint")
}

/// The same, over a store the caller chose — a SQLite file, or a shared
/// [`peachy_mls_core::MemoryKv`] that outlives the client.
pub fn client_on(
    issuer: &TestIssuer,
    tag: u8,
    actor: &str,
    device: &str,
    storage: PeachyStorage,
) -> Client {
    let seed = device_seed(tag);
    let (_, public) = peachy_mls_core::issuer::device_key_pair(&seed);
    let token = issuer
        .issue(actor, device, &public, NOW - HOUR, NOW + 30 * DAY)
        .expect("the test issuer should mint");
    let mut config = ClientConfig::new(token, seed, issuer.trusted_keys().expect("trusted keys"))
        .with_storage(storage)
        .with_own_account_identity(Some(held_identity(actor)));
    config.clock = Some(Box::new(TestClock));
    Client::new(config).expect("a freshly minted credential should build a client")
}

/// The account identity key a test device of `actor` holds: the one derived
/// from the account key [`TestIssuer::issue`] certifies it under. A device
/// holding no key refuses any certified credential, so every client opened on
/// such a credential names this.
pub fn held_identity(actor: &str) -> [u8; 32] {
    account_identity_public_key(&TestIssuer::test_account_key(actor))
        .expect("a test account key derives an identity key")
}

/// A trusted-key set that trusts nobody.
pub fn empty_trust() -> TrustedServerKeys {
    TrustedServerKeys::new()
}

/// Move `founder`'s group `group_id`, freshly founded, eight epochs on, past
/// any epoch a test's other devices held under the same id. A device refuses
/// a Welcome at or below the highest epoch it has held a group at
/// (`tests/stale_welcome.rs`), so a test about who may sign a Welcome into a
/// group a device knew founds its impostor past that mark: an impostor can,
/// and the check the test is about must hold even then.
pub fn past_the_mark(founder: &mut Client, group_id: &[u8]) {
    for _ in 0..8 {
        founder
            .self_update(group_id)
            .expect("a founder can update its own group");
        founder
            .merge_pending_commit(group_id)
            .expect("its own update merges");
    }
}

/// The head the delivery service holds for `group` once `client`'s last
/// commit was taken: its epoch, and the SHA-256 of that epoch's send key
/// (`docs/delivery.md` §FetchConversationHead).
pub fn head_of(client: &Client, group: &[u8]) -> (u64, [u8; 32]) {
    use sha2::{Digest, Sha256};
    let epoch = client.epoch(group).expect("the client holds the group");
    let secret = client
        .export_secret(group, peachy_mls_core::SEND_KEY_LABEL, group, 32)
        .expect("the client exports its send key");
    (epoch, Sha256::digest(secret).into())
}

/// Take `welcome` the way the apps take a Welcome from the mailbox: against
/// the group's head (`Client::join_from_welcome_at_head`).
pub fn join_at_head(
    joiner: &mut Client,
    welcome: &[u8],
    head: (u64, [u8; 32]),
) -> Result<Vec<u8>, peachy_mls_core::Error> {
    joiner.join_from_welcome_at_head(welcome, head.0, &head.1)
}

/// Remove by index the way a client does: with the leaf key read from the
/// same roster entry (`Client::remove_member` refuses a leaf that moved).
pub trait RemoveLeaf {
    fn remove_leaf(
        &mut self,
        group_id: &[u8],
        leaf_index: u32,
    ) -> peachy_mls_core::Result<peachy_mls_core::CommitBundle>;
    #[cfg(feature = "test-forgery")]
    fn forge_remove_leaf(
        &mut self,
        group_id: &[u8],
        leaf_index: u32,
    ) -> peachy_mls_core::Result<peachy_mls_core::CommitBundle>;
}

/// The leaf key the roster shows at `leaf_index`, or empty when none.
pub fn leaf_key_at(client: &Client, group_id: &[u8], leaf_index: u32) -> Vec<u8> {
    client
        .roster(group_id)
        .ok()
        .and_then(|roster| {
            roster
                .into_iter()
                .find(|entry| entry.leaf_index == leaf_index)
        })
        .map(|entry| entry.leaf_key)
        .unwrap_or_default()
}

impl RemoveLeaf for Client {
    fn remove_leaf(
        &mut self,
        group_id: &[u8],
        leaf_index: u32,
    ) -> peachy_mls_core::Result<peachy_mls_core::CommitBundle> {
        let key = leaf_key_at(self, group_id, leaf_index);
        self.remove_member(group_id, leaf_index, &key)
    }
    #[cfg(feature = "test-forgery")]
    fn forge_remove_leaf(
        &mut self,
        group_id: &[u8],
        leaf_index: u32,
    ) -> peachy_mls_core::Result<peachy_mls_core::CommitBundle> {
        let key = leaf_key_at(self, group_id, leaf_index);
        self.forge_remove_member(group_id, leaf_index, &key)
    }
}
