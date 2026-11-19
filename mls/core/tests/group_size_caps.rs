// SPDX-License-Identifier: MIT
//! THE GROUP AND LEAF SIZE CAPS (docs/delivery.md §SubmitCommit).
//!
//! The delivery service takes no send or commit naming more than 1,024
//! devices or 256 accounts, and every commit names every device in the tree.
//! So a commit leaving more than that in the tree is one after which no
//! member could commit again, the commit that would undo it included. A
//! device refuses to stage one, and a receiver refuses one.
//!
//! Every member's commit is padded to a bound counting the tree's largest
//! leaf, so a leaf over [`MAX_LEAF_NODE_BYTES`] is held to the same rule: a
//! device brings none into a tree, and a receiver refuses one.

#![cfg(feature = "test-forgery")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use openmls::prelude::{
    BasicCredential, Capabilities, CredentialWithKey, ExtensionType, KeyPackage, MlsMessageOut,
    SignatureScheme,
};
use openmls_basic_credential::SignatureKeyPair;
use peachy_mls_core::issuer::{device_key_pair, TestIssuer};
use peachy_mls_core::policy::{MAX_GROUP_ACCOUNTS, MAX_GROUP_LEAVES, MAX_LEAF_NODE_BYTES};
use peachy_mls_core::{
    Client, ClientConfig, PeachyProvider, PEACHY_CIPHERSUITE, PEACHY_GROUP_META_EXTENSION_TYPE,
    PEACHY_READS_EPOCH_ENVELOPES,
};
use support::{held_identity, issuer, TestClock, DAY, HOUR, NOW};

const G: &[u8] = b"77777777-7777-4777-8777-777777777777";

fn seed(n: u16) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[..2].copy_from_slice(&n.to_be_bytes());
    seed[2] = 0x5C;
    seed
}

fn token(server: &TestIssuer, n: u16, actor: &str) -> Vec<u8> {
    let (_, public) = device_key_pair(&seed(n));
    server
        .issue(
            actor,
            &format!("device-{n}"),
            &public,
            NOW - HOUR,
            NOW + 30 * DAY,
        )
        .unwrap()
}

/// Device `n` of `actor`, its key and device id its own.
fn device(server: &TestIssuer, n: u16, actor: &str) -> Client {
    let mut config = ClientConfig::new(
        token(server, n, actor),
        seed(n),
        server.trusted_keys().unwrap(),
    )
    .with_own_account_identity(Some(held_identity(actor)));
    config.clock = Some(Box::new(TestClock));
    Client::new(config).unwrap()
}

fn key_package(server: &TestIssuer, n: u16, actor: &str) -> Vec<u8> {
    device(server, n, actor).generate_key_package().unwrap()
}

/// A key package for device `n` of `actor` built with OpenMLS directly, as a
/// modified client could: its leaf lists `extra` more extension types than
/// any build advertises, two bytes each.
fn padded_key_package(server: &TestIssuer, n: u16, actor: &str, extra: u16) -> Vec<u8> {
    let (signing, public) = device_key_pair(&seed(n));
    let signer = SignatureKeyPair::from_raw(
        SignatureScheme::ED25519,
        signing.to_bytes().to_vec(),
        public.to_vec(),
    );
    let mut extensions = vec![
        ExtensionType::Unknown(PEACHY_GROUP_META_EXTENSION_TYPE),
        ExtensionType::Unknown(PEACHY_READS_EPOCH_ENVELOPES),
    ];
    extensions.extend((0..extra).map(|i| ExtensionType::Unknown(0xA000 + i)));
    let capabilities = Capabilities::new(
        None,
        Some(&[PEACHY_CIPHERSUITE]),
        Some(&extensions),
        None,
        None,
    );
    let bundle = KeyPackage::builder()
        .leaf_node_capabilities(capabilities)
        .build(
            PEACHY_CIPHERSUITE,
            &PeachyProvider::ephemeral(),
            &signer,
            CredentialWithKey {
                credential: BasicCredential::new(token(server, n, actor)).into(),
                signature_key: public.to_vec().into(),
            },
        )
        .unwrap();
    MlsMessageOut::from(bundle.key_package().clone())
        .to_bytes()
        .unwrap()
}

/// Ada founds the group and adds Bo; the rest come in through `forge_commit`,
/// which skips the committer's checks, so a test reaches the cap in one
/// commit rather than a thousand.
fn ada_and_bo(server: &TestIssuer) -> (Client, Client) {
    let mut ada = device(server, 0, "actor-0");
    let mut bo = device(server, 1, "actor-1");
    ada.create_group(G).unwrap();
    let kp = bo.generate_key_package().unwrap();
    let added = ada.add_member(G, &kp).unwrap();
    ada.merge_pending_commit(G).unwrap();
    support::join_at_head(&mut bo, &added.welcome.unwrap(), support::head_of(&ada, G)).unwrap();
    (ada, bo)
}

fn forge_in(
    ada: &mut Client,
    bo: &mut Client,
    packages: &[Vec<u8>],
) -> peachy_mls_core::Result<()> {
    let refs: Vec<&[u8]> = packages.iter().map(Vec::as_slice).collect();
    let forged = ada.forge_commit(G, &[], &refs).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &forged.commit).map(|_| ())
}

#[test]
fn a_device_stages_no_commit_past_the_account_cap() {
    let server = issuer();
    let (mut ada, mut bo) = ada_and_bo(&server);
    // Accounts 2 to 255: 256 in all.
    let packages: Vec<Vec<u8>> = (2..MAX_GROUP_ACCOUNTS as u16)
        .map(|n| key_package(&server, n, &format!("actor-{n}")))
        .collect();
    forge_in(&mut ada, &mut bo, &packages).unwrap();

    // Another device of an account already in the group still comes in.
    let second = key_package(&server, 1000, "actor-1");
    let added = ada.add_member(G, &second).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &added.commit).unwrap();

    // A 257th account does not.
    let outsider = key_package(&server, 1001, "actor-outsider");
    let err = ada.add_member(G, &outsider).unwrap_err().to_string();
    assert!(err.contains("accounts in the group, over 256"), "{err}");

    // A modified member's commit past the cap: refused.
    assert!(forge_in(&mut ada, &mut bo, &[outsider]).is_err());
}

#[test]
fn a_device_stages_no_commit_past_the_device_cap() {
    let server = issuer();
    let (mut ada, mut bo) = ada_and_bo(&server);
    // 256 accounts of four devices each: 1,024 leaves.
    let packages: Vec<Vec<u8>> = (2..MAX_GROUP_LEAVES as u16)
        .map(|n| key_package(&server, n, &format!("actor-{}", n % 256)))
        .collect();
    forge_in(&mut ada, &mut bo, &packages).unwrap();

    let fifth = key_package(&server, 2000, "actor-7");
    let err = ada.add_member(G, &fifth).unwrap_err().to_string();
    assert!(err.contains("devices in the group, over 1024"), "{err}");

    // A modified member's commit past the cap: refused.
    assert!(forge_in(&mut ada, &mut bo, &[fifth]).is_err());
}

#[test]
fn a_device_brings_no_leaf_over_the_cap_into_a_tree() {
    let server = issuer();
    let (mut ada, mut bo) = ada_and_bo(&server);
    let extra = u16::try_from(MAX_LEAF_NODE_BYTES / 2).unwrap();
    let padded = padded_key_package(&server, 5, "actor-5", extra);
    let err = ada.add_member(G, &padded).unwrap_err().to_string();
    assert!(err.contains("the commit carries a leaf of"), "{err}");

    // Within the cap, the same kind of package comes in.
    let modest = padded_key_package(&server, 6, "actor-6", 64);
    let added = ada.add_member(G, &modest).unwrap();
    ada.merge_pending_commit(G).unwrap();
    bo.process_commit(G, &added.commit).unwrap();

    // A modified member's commit bringing one in: refused.
    assert!(forge_in(&mut ada, &mut bo, &[padded]).is_err());
}
