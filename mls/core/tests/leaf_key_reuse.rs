// SPDX-License-Identifier: MIT
//! A leaf seated on another leaf's keys under someone else's credential is
//! still a change (docs/identity.md §Security code changed).
//!
//! The security-code notice keeps, per conversation, the leaves it has
//! settled. Those records once named a leaf by its signature key and HPKE key
//! alone, so a server that certified a device key for a person under an
//! account key it minted could seat that person on the keys of a leaf the
//! conversation had already reported for someone else (its own puppet), in
//! the commit that removed that leaf, and no notice named the person. The
//! records now name a leaf by its keys AND its credential, which carries the
//! actor and the account key.

#![cfg(feature = "test-forgery")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use std::cell::Cell;

use openmls::prelude::{
    BasicCredential, Capabilities, Credential, CredentialWithKey, ExtensionType, KeyPackage,
    KeyPackageIn, MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, ProtocolVersion,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::{MemoryStorage, RustCrypto};
use openmls_traits::random::OpenMlsRand;
use openmls_traits::types::SignatureScheme;
use openmls_traits::OpenMlsProvider;
use peachy_mls_core::issuer::{device_key_pair, TestIssuer};
use peachy_mls_core::{
    account_identity_public_key, Client, ClientConfig, MemoryKv, PeachyStorage, PEACHY_CIPHERSUITE,
    PEACHY_GROUP_META_EXTENSION_TYPE, PEACHY_READS_EPOCH_ENVELOPES,
};
use sha2::{Digest, Sha256};
use support::{client, client_on, device_seed, issuer, DAY, HOUR, NOW};
use tls_codec::Deserialize as _;

const G0: &[u8] = b"leaf-reuse-ada-meets-bo";
const G: &[u8] = b"leaf-reuse-shared-group";
const G2: &[u8] = b"leaf-reuse-mal-new-key";

/// A randomness source that replays one stream: two providers built with the
/// same seed hand out the same bytes in the same order, so two key packages
/// built with one seed carry the same leaf HPKE key.
struct ReplayRand {
    seed: u8,
    calls: Cell<u64>,
}

impl ReplayRand {
    fn bytes(&self, len: usize) -> Vec<u8> {
        let call = self.calls.get();
        self.calls.set(call + 1);
        let mut out = Vec::with_capacity(len);
        let mut block = 0u64;
        while out.len() < len {
            let mut h = Sha256::new();
            h.update([self.seed]);
            h.update(call.to_be_bytes());
            h.update(block.to_be_bytes());
            out.extend_from_slice(&h.finalize());
            block += 1;
        }
        out.truncate(len);
        out
    }
}

impl OpenMlsRand for ReplayRand {
    type Error = std::convert::Infallible;
    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        let mut a = [0u8; N];
        a.copy_from_slice(&self.bytes(N));
        Ok(a)
    }
    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        Ok(self.bytes(len))
    }
}

struct ReplayProvider {
    crypto: RustCrypto,
    rand: ReplayRand,
    storage: MemoryStorage,
}

impl OpenMlsProvider for ReplayProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = ReplayRand;
    type StorageProvider = MemoryStorage;
    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }
    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }
    fn rand(&self) -> &Self::RandProvider {
        &self.rand
    }
}

/// A key package signed by the device key of `tag`, carrying `token` as its
/// credential, its leaf HPKE key drawn from the replayed stream `rand_seed`.
/// What a modified client holding that device key can publish.
fn raw_key_package(tag: u8, token: Vec<u8>, rand_seed: u8) -> Vec<u8> {
    let seed = device_seed(tag);
    let (_, public) = device_key_pair(&seed);
    let signer =
        SignatureKeyPair::from_raw(SignatureScheme::ED25519, seed.to_vec(), public.to_vec());
    let cwk = CredentialWithKey {
        credential: Credential::from(BasicCredential::new(token)),
        signature_key: public.to_vec().into(),
    };
    let provider = ReplayProvider {
        crypto: RustCrypto::default(),
        rand: ReplayRand {
            seed: rand_seed,
            calls: Cell::new(0),
        },
        storage: MemoryStorage::default(),
    };
    let caps = Capabilities::new(
        None,
        Some(&[PEACHY_CIPHERSUITE]),
        Some(&[
            ExtensionType::Unknown(PEACHY_GROUP_META_EXTENSION_TYPE),
            ExtensionType::Unknown(PEACHY_READS_EPOCH_ENVELOPES),
        ]),
        None,
        None,
    );
    let bundle = KeyPackage::builder()
        .leaf_node_capabilities(caps)
        .build(PEACHY_CIPHERSUITE, &provider, &signer, cwk)
        .expect("build key package");
    MlsMessageOut::from(bundle.key_package().clone())
        .to_bytes()
        .expect("serialize")
}

/// The raw leaf HPKE key a package seats.
fn leaf_encryption_key(package: &[u8]) -> Vec<u8> {
    let MlsMessageBodyIn::KeyPackage(kp) = MlsMessageIn::tls_deserialize_exact(package)
        .expect("parse")
        .extract()
    else {
        panic!("not a key package")
    };
    let kp: KeyPackageIn = kp;
    let kp = kp
        .validate(&RustCrypto::default(), ProtocolVersion::Mls10)
        .expect("valid");
    let encoded =
        tls_codec::Serialize::tls_serialize_detached(kp.leaf_node().encryption_key()).expect("ser");
    tls_codec::VLBytes::tls_deserialize_exact(&encoded)
        .expect("one length-prefixed key")
        .as_slice()
        .to_vec()
}

fn token_for(
    server: &TestIssuer,
    tag: u8,
    actor: &str,
    device: &str,
    account: &[u8],
    issued_at: i64,
) -> Vec<u8> {
    let (_, public) = device_key_pair(&device_seed(tag));
    server
        .issue_for_account(
            actor,
            device,
            &public,
            Some(account),
            issued_at,
            issued_at + 30 * DAY,
        )
        .expect("mint")
}

fn client_under(
    server: &TestIssuer,
    tag: u8,
    actor: &str,
    device: &str,
    account: &[u8],
    issued_at: i64,
) -> Client {
    let token = token_for(server, tag, actor, device, account, issued_at);
    let held = account_identity_public_key(account).expect("derive");
    let mut config = ClientConfig::new(token, device_seed(tag), server.trusted_keys().unwrap())
        .with_storage(PeachyStorage::in_memory())
        .with_own_account_identity(Some(held));
    config.clock = Some(Box::new(support::TestClock));
    Client::new(config).expect("client")
}

fn add(adder: &mut Client, joiner: &mut Client, group: &[u8]) {
    let kp = joiner.generate_key_package().expect("kp");
    let bundle = adder.add_member(group, &kp).expect("add");
    adder.merge_pending_commit(group).expect("merge");
    joiner
        .join_from_welcome(&bundle.welcome.expect("welcome"))
        .expect("join");
}

/// Mal-1's package: the server's puppet account's first device, its leaf HPKE
/// key from the replayed stream 0x11.
fn mal1_package(server: &TestIssuer) -> Vec<u8> {
    raw_key_package(
        4,
        token_for(
            server,
            4,
            "actor-mal",
            "device-mal-1",
            &TestIssuer::test_account_key("actor-mal"),
            NOW - HOUR,
        ),
        0x11,
    )
}

/// The impostor: a credential the server issued for Bo under an account key
/// it minted, bound to Mal-1's device key, its leaf HPKE key from `rand_seed`
/// (0x11 reuses Mal-1's).
fn impostor_package(server: &TestIssuer, rand_seed: u8) -> Vec<u8> {
    raw_key_package(
        4,
        token_for(
            server,
            4,
            "actor-bo",
            "device-bo-seized",
            &[0x5e; 32],
            NOW - 60,
        ),
        rand_seed,
    )
}

/// Ada has pinned Bo's real key in G0. G holds Ada, Cy (a member with a
/// stable key) and Mal-1; Mal then shows Ada a device under a new key in G2,
/// so G reports Mal-1's leaf once. Returns Cy.
fn setup(server: &TestIssuer, ada: &mut Client) -> Client {
    let mut bo = client(server, 2, "actor-bo", "device-bo-phone");
    ada.create_group(G0).expect("create");
    add(ada, &mut bo, G0);
    assert!(ada.observe_account_keys(G0).unwrap().is_empty());

    let mut cy = client(server, 3, "actor-cy", "device-cy-phone");
    ada.create_group(G).expect("create");
    add(ada, &mut cy, G);
    let bundle = ada
        .add_member(G, &mal1_package(server))
        .expect("ada adds mal-1");
    ada.merge_pending_commit(G).expect("merge");
    cy.process_commit(G, &bundle.commit).expect("cy follows");
    assert!(ada.observe_account_keys(G).unwrap().is_empty());

    let mut mal3 = client_under(
        server,
        5,
        "actor-mal",
        "device-mal-3",
        &[0x77; 32],
        NOW - 60,
    );
    ada.create_group(G2).expect("create");
    add(ada, &mut mal3, G2);
    assert_eq!(ada.observe_account_keys(G2).unwrap(), vec!["actor-mal"]);
    assert_eq!(ada.observe_account_keys(G).unwrap(), vec!["actor-mal"]);
    assert!(ada.observe_account_keys(G).unwrap().is_empty());
    cy
}

/// `committer` removes Mal-1 and adds the impostor in one commit; Ada
/// applies it. Returns what Ada's notice says for G.
fn swap(
    server: &TestIssuer,
    ada: &mut Client,
    committer: &mut Client,
    rand_seed: u8,
) -> Vec<String> {
    let mal1_leaf = ada.leaf_of_device(G, "device-mal-1").expect("mal-1 leaf");
    let impostor = impostor_package(server, rand_seed);
    assert_eq!(
        leaf_encryption_key(&impostor) == leaf_encryption_key(&mal1_package(server)),
        rand_seed == 0x11
    );
    let swap = committer
        .forge_commit(G, &[mal1_leaf], &[&impostor])
        .expect("the swap");
    committer.merge_pending_commit(G).expect("merge");
    ada.process_commit(G, &swap.commit)
        .expect("ada applies the swap");
    let minted = account_identity_public_key(&[0x5e; 32]).unwrap();
    assert!(
        ada.roster(G).unwrap().iter().any(|e| e
            .identity
            .as_ref()
            .is_ok_and(|id| id.actor_id == "actor-bo" && id.account_key == Some(minted))),
        "Bo sits in G under a key Ada never accepted"
    );
    ada.observe_account_keys(G).unwrap()
}

/// The impostor reuses the reported leaf's signature key and HPKE key: Bo's
/// change is still said.
#[test]
fn a_leaf_on_a_reported_leafs_keys_under_another_persons_credential_is_a_change() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut cy = setup(&server, &mut ada);
    assert_eq!(swap(&server, &mut ada, &mut cy, 0x11), vec!["actor-bo"]);
}

/// The same swap with a fresh HPKE key, as it always was.
#[test]
fn a_leaf_on_fresh_keys_under_a_minted_account_key_is_a_change() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut cy = setup(&server, &mut ada);
    assert_eq!(swap(&server, &mut ada, &mut cy, 0x22), vec!["actor-bo"]);
}

/// A group whose meta names Ada its only admin: any member may add, and a
/// member may remove its own account's leaves. The server's puppet Mal holds
/// two devices there; Mal-2 removes Mal-1 and seats the impostor on its
/// keys, with nobody else's help.
fn puppet_alone(rand_seed: u8) -> Vec<String> {
    let server = issuer();
    let mal_key = TestIssuer::test_account_key("actor-mal");
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(&server, 2, "actor-bo", "device-bo-phone");
    ada.create_group(G0).expect("create");
    add(&mut ada, &mut bo, G0);
    assert!(ada.observe_account_keys(G0).unwrap().is_empty());

    ada.create_group(G).expect("create");
    ada.set_group_meta(G, br#"{"v":1,"n":"Walk","adm":["actor-ada"]}"#)
        .expect("meta");
    ada.merge_pending_commit(G).expect("merge meta");
    ada.add_member(G, &mal1_package(&server))
        .expect("ada adds mal-1");
    ada.merge_pending_commit(G).expect("merge");
    let mut mal2 = client_under(
        &server,
        6,
        "actor-mal",
        "device-mal-2",
        &mal_key,
        NOW - HOUR,
    );
    add(&mut ada, &mut mal2, G);
    assert!(ada.observe_account_keys(G).unwrap().is_empty());

    let mut mal3 = client_under(
        &server,
        5,
        "actor-mal",
        "device-mal-3",
        &[0x77; 32],
        NOW - 60,
    );
    ada.create_group(G2).expect("create");
    add(&mut ada, &mut mal3, G2);
    assert_eq!(ada.observe_account_keys(G2).unwrap(), vec!["actor-mal"]);
    assert_eq!(ada.observe_account_keys(G).unwrap(), vec!["actor-mal"]);
    assert!(ada.observe_account_keys(G).unwrap().is_empty());

    swap(&server, &mut ada, &mut mal2, rand_seed)
}

/// Mal-2's own path update re-keys a leaf still under Mal's retired key, so
/// Mal is named too; Bo is named either way.
#[test]
fn the_servers_puppet_alone_cannot_seat_a_person_on_its_reported_leaf() {
    assert_eq!(puppet_alone(0x11), vec!["actor-bo", "actor-mal"]);
    assert_eq!(puppet_alone(0x22), vec!["actor-bo", "actor-mal"]);
}

/// SHA-256 over the label the records used before, the signature key's
/// u64be length, the signature key and the HPKE key.
fn leaf_digest_v1(signature_key: &[u8], encryption_key: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"peachy account leaf v1");
    digest.update((signature_key.len() as u64).to_be_bytes());
    digest.update(signature_key);
    digest.update(encryption_key);
    digest.finalize().into()
}

/// A store in the version-1 layout, its records naming Mal-1's leaf by its
/// keys alone, is carried over at open. Mal-1 sits under a key Mal moved
/// away from, and a version-1 record cannot tell the leaf it reported from
/// another seated on its keys, so only its `known` record is carried: G
/// names Mal once more, as for any settled leaf left behind under such a
/// key, and then stays quiet. The old records are gone, and the impostor on
/// that leaf's keys is a change all the same.
#[test]
fn version_1_records_are_carried_over_at_open() {
    let server = issuer();
    let kv = MemoryKv::new();
    let shared = || PeachyStorage::open(Box::new(kv.clone())).expect("open");
    let mut ada = client_on(&server, 1, "actor-ada", "device-ada-phone", shared());
    let mut cy = setup(&server, &mut ada);
    ada.flush().expect("flush");
    drop(ada);

    // Rewrite G's records in the version-1 layout.
    let (_, mal1_device_key) = device_key_pair(&device_seed(4));
    let old = leaf_digest_v1(
        &mal1_device_key,
        &leaf_encryption_key(&mal1_package(&server)),
    );
    {
        let store = shared();
        store.forget_account_leaf_records(G).expect("forget");
        store
            .set_account_leaf_records_v1(G, Some(&[old]), Some(&[old]))
            .expect("old records");
        store.flush().expect("flush");
    }

    let mut ada = client_on(&server, 1, "actor-ada", "device-ada-phone", shared());
    assert_eq!(
        ada.observe_account_keys(G).unwrap(),
        vec!["actor-mal"],
        "a leaf reported under a key its person moved away from is named once more"
    );
    assert!(
        ada.observe_account_keys(G).unwrap().is_empty(),
        "and then settled"
    );
    assert_eq!(
        shared().account_leaf_records_v1(G).expect("read"),
        (None, None),
        "the old records are gone"
    );
    assert_eq!(swap(&server, &mut ada, &mut cy, 0x11), vec!["actor-bo"]);
}

/// Stand in for a device that took the swap while it kept the version-1
/// records, which settled the impostor in silence: apply the swap, judge
/// nothing, and leave G's records in the version-1 layout when `write_v1`.
/// Returns the store.
fn store_after_swap_under_version_1_records(server: &TestIssuer, write_v1: bool) -> MemoryKv {
    let kv = MemoryKv::new();
    let shared = || PeachyStorage::open(Box::new(kv.clone())).expect("open");
    let mut ada = client_on(server, 1, "actor-ada", "device-ada-phone", shared());
    let mut cy = setup(server, &mut ada);
    let mal1_leaf = ada.leaf_of_device(G, "device-mal-1").expect("mal-1 leaf");
    let impostor = impostor_package(server, 0x11);
    let swap = cy
        .forge_commit(G, &[mal1_leaf], &[&impostor])
        .expect("the swap");
    cy.merge_pending_commit(G).expect("merge");
    ada.process_commit(G, &swap.commit)
        .expect("ada applies the swap");
    ada.flush().expect("flush");
    drop(ada);
    if write_v1 {
        // The impostor sits on Mal-1's keys, so its version-1 digest is the
        // one the version-1 records reported for Mal-1 and kept after the swap.
        let (_, mal1_device_key) = device_key_pair(&device_seed(4));
        let old = leaf_digest_v1(
            &mal1_device_key,
            &leaf_encryption_key(&mal1_package(server)),
        );
        let store = shared();
        store.forget_account_leaf_records(G).expect("forget");
        store
            .set_account_leaf_records_v1(G, Some(&[old]), Some(&[old]))
            .expect("old records");
        store.flush().expect("flush");
    }
    kv
}

fn bo_sits_under_the_minted_key(ada: &mut Client) -> bool {
    let minted = account_identity_public_key(&[0x5e; 32]).unwrap();
    ada.roster(G).unwrap().iter().any(|e| {
        e.identity
            .as_ref()
            .is_ok_and(|id| id.actor_id == "actor-bo" && id.account_key == Some(minted))
    })
}

/// A version-1 record settles a leaf only under a key this device accepted
/// for its actor: an impostor the version-1 records settled in silence,
/// under a key it never accepted for Bo, is named at the first read after
/// the carry.
#[test]
fn an_impostor_version_1_records_settled_is_named_after_the_carry() {
    let server = issuer();
    let kv = store_after_swap_under_version_1_records(&server, true);
    let open = || PeachyStorage::open(Box::new(kv.clone())).expect("open");
    let mut ada = client_on(&server, 1, "actor-ada", "device-ada-phone", open());
    assert!(bo_sits_under_the_minted_key(&mut ada));
    assert_eq!(ada.observe_account_keys(G).unwrap(), vec!["actor-bo"]);
    assert!(ada.observe_account_keys(G).unwrap().is_empty(), "once");
}

/// The same store with the swap judged under the current records names Bo
/// too.
#[test]
fn the_same_swap_judged_under_the_current_records_names_bo() {
    let server = issuer();
    let kv = store_after_swap_under_version_1_records(&server, false);
    let open = || PeachyStorage::open(Box::new(kv.clone())).expect("open");
    let mut ada = client_on(&server, 1, "actor-ada", "device-ada-phone", open());
    assert!(bo_sits_under_the_minted_key(&mut ada));
    assert_eq!(ada.observe_account_keys(G).unwrap(), vec!["actor-bo"]);
}

const G3: &[u8] = b"leaf-reuse-bo-new-key";

/// Someone who kept Bo's OLD account key (the thief of the phone Bo lost
/// before he moved to a new key) certifies Mal-1's device key under it,
/// with Mal-1's leaf HPKE key (0x11).
fn old_key_thief_package(server: &TestIssuer) -> Vec<u8> {
    raw_key_package(
        4,
        token_for(
            server,
            4,
            "actor-bo",
            "device-bo-thief",
            &TestIssuer::test_account_key("actor-bo"),
            NOW - 60,
        ),
        0x11,
    )
}

/// As [`setup`], and then Bo moves to a new account key in G3 (Ada is told
/// once there), so Bo's old key is retired on Ada. While the version-1
/// records are kept, Cy swaps Mal-1 for the thief's leaf under Bo's old key
/// on Mal-1's keys, and Ada applies it, judging nothing.
/// Returns the store, G's records in the version-1 layout when `write_v1`.
fn store_after_retired_key_swap(server: &TestIssuer, write_v1: bool) -> MemoryKv {
    let kv = MemoryKv::new();
    let shared = || PeachyStorage::open(Box::new(kv.clone())).expect("open");
    let mut ada = client_on(server, 1, "actor-ada", "device-ada-phone", shared());
    let mut cy = setup(server, &mut ada);

    let mut bo_new = client_under(
        server,
        7,
        "actor-bo",
        "device-bo-new",
        &[0x66; 32],
        NOW - 60,
    );
    ada.create_group(G3).expect("create");
    add(&mut ada, &mut bo_new, G3);
    assert_eq!(ada.observe_account_keys(G3).unwrap(), vec!["actor-bo"]);
    let old_bo = account_identity_public_key(&TestIssuer::test_account_key("actor-bo")).unwrap();
    let new_bo = account_identity_public_key(&[0x66; 32]).unwrap();
    {
        let store = shared();
        assert_eq!(store.account_pins("actor-bo").unwrap(), vec![new_bo]);
        assert!(store.account_retired("actor-bo").unwrap().contains(&old_bo));
    }

    let mal1_leaf = ada.leaf_of_device(G, "device-mal-1").expect("mal-1 leaf");
    let thief = old_key_thief_package(server);
    let swap = cy
        .forge_commit(G, &[mal1_leaf], &[&thief])
        .expect("the swap");
    cy.merge_pending_commit(G).expect("merge");
    ada.process_commit(G, &swap.commit)
        .expect("ada applies the swap");
    ada.flush().expect("flush");
    drop(ada);
    if write_v1 {
        let (_, mal1_device_key) = device_key_pair(&device_seed(4));
        let old = leaf_digest_v1(
            &mal1_device_key,
            &leaf_encryption_key(&mal1_package(server)),
        );
        let store = shared();
        store.forget_account_leaf_records(G).expect("forget");
        store
            .set_account_leaf_records_v1(G, Some(&[old]), Some(&[old]))
            .expect("old records");
        store.flush().expect("flush");
    }
    kv
}

fn thief_sits_in_g(ada: &mut Client) -> bool {
    let old_bo = account_identity_public_key(&TestIssuer::test_account_key("actor-bo")).unwrap();
    ada.roster(G).unwrap().iter().any(|e| {
        e.identity.as_ref().is_ok_and(|id| {
            id.actor_id == "actor-bo"
                && id.device_id == "device-bo-thief"
                && id.account_key == Some(old_bo)
        })
    })
}

/// A version-1 report settles a leaf only under its actor's CURRENT key: a
/// leaf under a key Bo moved away from, seated on a reported leaf's keys
/// while the version-1 records were kept, is named at the first read after
/// the carry, once.
#[test]
fn a_leaf_under_a_retired_key_seated_on_a_reported_leafs_keys_is_named_after_the_carry() {
    let server = issuer();
    let kv = store_after_retired_key_swap(&server, true);
    let open = || PeachyStorage::open(Box::new(kv.clone())).expect("open");
    let mut ada = client_on(&server, 1, "actor-ada", "device-ada-phone", open());
    assert!(thief_sits_in_g(&mut ada));
    assert_eq!(ada.observe_account_keys(G).unwrap(), vec!["actor-bo"]);
    assert!(ada.observe_account_keys(G).unwrap().is_empty(), "once");
}

/// The same store with the swap judged under the current records names Bo
/// too.
#[test]
fn the_same_retired_key_swap_judged_under_the_current_records_names_bo() {
    let server = issuer();
    let kv = store_after_retired_key_swap(&server, false);
    let open = || PeachyStorage::open(Box::new(kv.clone())).expect("open");
    let mut ada = client_on(&server, 1, "actor-ada", "device-ada-phone", open());
    assert!(thief_sits_in_g(&mut ada));
    assert_eq!(ada.observe_account_keys(G).unwrap(), vec!["actor-bo"]);
}

/// The same swap, in a store whose version-1 records hold a `known` list
/// for G and no `reported` list: the carry still writes a `reported`
/// record (empty here), so the first read does not fill one from `known`
/// and settle the leaf under the retired key in silence. Bo is named, once.
#[test]
fn a_store_with_no_version_1_report_still_names_a_leaf_under_a_retired_key() {
    let server = issuer();
    let kv = store_after_retired_key_swap(&server, false);
    {
        let store = PeachyStorage::open(Box::new(kv.clone())).expect("open");
        let (_, mal1_device_key) = device_key_pair(&device_seed(4));
        let old = leaf_digest_v1(
            &mal1_device_key,
            &leaf_encryption_key(&mal1_package(&server)),
        );
        store.forget_account_leaf_records(G).expect("forget");
        store
            .set_account_leaf_records_v1(G, Some(&[old]), None)
            .expect("old records");
        store.flush().expect("flush");
    }
    let open = || PeachyStorage::open(Box::new(kv.clone())).expect("open");
    let mut ada = client_on(&server, 1, "actor-ada", "device-ada-phone", open());
    assert!(thief_sits_in_g(&mut ada));
    assert_eq!(ada.observe_account_keys(G).unwrap(), vec!["actor-bo"]);
    assert!(ada.observe_account_keys(G).unwrap().is_empty(), "once");
}

/// As [`store_after_retired_key_swap`], but the swap lands while Bo's key is
/// still his CURRENT one: the thief of his phone, with Mal colluding, seats
/// a leaf under Bo's key on Mal-1's keys ([`old_key_thief_package`]), which
/// a version-1 report names. Ada applies it, judging nothing.
/// Returns the store, G's records in the version-1 layout when `write_v1`.
fn store_after_current_key_swap(server: &TestIssuer, write_v1: bool) -> MemoryKv {
    let kv = MemoryKv::new();
    let shared = || PeachyStorage::open(Box::new(kv.clone())).expect("open");
    let mut ada = client_on(server, 1, "actor-ada", "device-ada-phone", shared());
    let mut cy = setup(server, &mut ada);
    let mal1_leaf = ada.leaf_of_device(G, "device-mal-1").expect("mal-1 leaf");
    let thief = old_key_thief_package(server);
    let swap = cy
        .forge_commit(G, &[mal1_leaf], &[&thief])
        .expect("the swap");
    cy.merge_pending_commit(G).expect("merge");
    ada.process_commit(G, &swap.commit)
        .expect("ada applies the swap");
    ada.flush().expect("flush");
    drop(ada);
    if write_v1 {
        let (_, mal1_device_key) = device_key_pair(&device_seed(4));
        let old = leaf_digest_v1(
            &mal1_device_key,
            &leaf_encryption_key(&mal1_package(server)),
        );
        let store = shared();
        store.forget_account_leaf_records(G).expect("forget");
        store
            .set_account_leaf_records_v1(G, Some(&[old]), Some(&[old]))
            .expect("old records");
        store.flush().expect("flush");
    }
    kv
}

/// Ada opens the store (the carry runs while Bo's stolen key is his current
/// one), reads G when `read_before_move`, and then Bo moves to a new key (he
/// lost the phone), which Ada is told in G3. Returns what G says after the
/// move, asserting it then stays quiet.
fn g_after_bo_moves(server: &TestIssuer, kv: &MemoryKv, read_before_move: bool) -> Vec<String> {
    let open = || PeachyStorage::open(Box::new(kv.clone())).expect("open");
    let mut ada = client_on(server, 1, "actor-ada", "device-ada-phone", open());
    assert!(thief_sits_in_g(&mut ada));
    let old_bo = account_identity_public_key(&TestIssuer::test_account_key("actor-bo")).unwrap();
    assert_eq!(
        open().account_pins("actor-bo").unwrap(),
        vec![old_bo],
        "the stolen key is current at the carry"
    );
    if read_before_move {
        assert!(
            ada.observe_account_keys(G).unwrap().is_empty(),
            "a leaf under the current key is no change"
        );
    }
    let mut bo_new = client_under(
        server,
        7,
        "actor-bo",
        "device-bo-new",
        &[0x66; 32],
        NOW - 60,
    );
    ada.create_group(G3).expect("create");
    add(&mut ada, &mut bo_new, G3);
    assert_eq!(ada.observe_account_keys(G3).unwrap(), vec!["actor-bo"]);
    assert!(
        thief_sits_in_g(&mut ada),
        "G still encrypts to the thief's leaf under the key Bo moved off"
    );
    let after = ada.observe_account_keys(G).unwrap();
    assert!(ada.observe_account_keys(G).unwrap().is_empty(), "once");
    after
}

/// A leaf a conversation settled while its key was current is named once
/// the person moves off that key, whatever a version-1 record reported on
/// its keys: the carry brings no report over, and a read drops any report
/// under the key current then. The same store judged under the current
/// records is the control. Read before the move or not, so neither alone
/// does the work.
#[test]
fn a_leaf_carried_under_the_current_key_is_named_once_the_person_moves_off_it() {
    let server = issuer();
    for read_before_move in [true, false] {
        let native = store_after_current_key_swap(&server, false);
        assert_eq!(
            g_after_bo_moves(&server, &native, read_before_move),
            vec!["actor-bo"],
            "control: the current records name Bo in G (read before the move: {read_before_move})"
        );
        let carried = store_after_current_key_swap(&server, true);
        assert_eq!(
            g_after_bo_moves(&server, &carried, read_before_move),
            vec!["actor-bo"],
            "the carried store names Bo in G (read before the move: {read_before_move})"
        );
    }
}

/// Bo's device under a new key K2 joins G. `first_in_g`: G is the first
/// conversation to show K2, so G reports it and the pin moves to K2 there;
/// else Ada learned K2 in G2 first and G settles the leaf in silence. Bo
/// then starts over under K3, shown in G3, while G still seats the K2 leaf.
/// Returns what G says after that move, asserting it then stays quiet.
fn g_after_a_second_move(first_in_g: bool) -> Vec<String> {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut bo1 = client(&server, 2, "actor-bo", "device-bo-1");
    ada.create_group(G0).unwrap();
    add(&mut ada, &mut bo1, G0);
    assert!(ada.observe_account_keys(G0).unwrap().is_empty());

    ada.create_group(G).unwrap();
    let mut bo2 = client_under(
        &server,
        6,
        "actor-bo",
        "device-bo-2",
        &[0x61; 32],
        NOW - 120,
    );
    if first_in_g {
        add(&mut ada, &mut bo2, G);
        assert_eq!(ada.observe_account_keys(G).unwrap(), vec!["actor-bo"]);
    } else {
        let mut bo2b = client_under(
            &server,
            8,
            "actor-bo",
            "device-bo-2b",
            &[0x61; 32],
            NOW - 120,
        );
        ada.create_group(G2).unwrap();
        add(&mut ada, &mut bo2b, G2);
        assert_eq!(ada.observe_account_keys(G2).unwrap(), vec!["actor-bo"]);
        add(&mut ada, &mut bo2, G);
        assert!(ada.observe_account_keys(G).unwrap().is_empty());
    }
    assert!(ada.observe_account_keys(G).unwrap().is_empty());

    let mut bo3 = client_under(&server, 7, "actor-bo", "device-bo-3", &[0x66; 32], NOW - 60);
    ada.create_group(G3).unwrap();
    add(&mut ada, &mut bo3, G3);
    assert_eq!(ada.observe_account_keys(G3).unwrap(), vec!["actor-bo"]);
    assert!(
        ada.leaf_of_device(G, "device-bo-2").is_ok(),
        "G still seats the K2 leaf"
    );
    let after = ada.observe_account_keys(G).unwrap();
    assert!(ada.observe_account_keys(G).unwrap().is_empty(), "once");
    after
}

/// A leaf a conversation reported when it arrived under the person's new
/// key is settled while that key is current, and named once when the person
/// moves off it again, as one another conversation showed first is (the
/// control).
#[test]
fn a_leaf_reported_at_its_arrival_is_named_once_the_person_moves_off_its_key() {
    assert_eq!(g_after_a_second_move(false), vec!["actor-bo"], "control");
    assert_eq!(g_after_a_second_move(true), vec!["actor-bo"]);
}
