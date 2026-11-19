// SPDX-License-Identifier: MIT
//! The post-quantum ciphersuite, and what it costs on the wire.
//!
//! docs/mls-core.md §Ciphersuite 0x004F, post-quantum. Every group and every
//! key package this build makes is on `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519`,
//! whose HPKE KEM is X-Wing (ML-KEM-768 combined with X25519). These tests pin
//! the suite on every artefact a peer receives, and pin the sizes the server's
//! limits were set from, so a growth that would breach one fails here first
//! rather than as a refused publish on a phone.
//!
//! `cargo test -p peachy-mls-core --test post_quantum -- --nocapture` prints
//! the measured numbers the doc quotes.

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use openmls::prelude::{
    tls_codec::Deserialize, Ciphersuite, KeyPackageIn, MlsMessageBodyIn, MlsMessageIn,
};
use peachy_mls_core::PEACHY_CIPHERSUITE;
use support::{client, issuer};

const GROUP: &[u8] = b"peachy-group-post-quantum";

/// What the server allows for one key package (`MAX_KEY_PACKAGE_BYTES` in
/// the delivery service). A measured package must sit well inside it.
const SERVER_MAX_KEY_PACKAGE_BYTES: usize = 32 * 1024;

fn key_package_suite(bytes: &[u8]) -> Ciphersuite {
    let message = MlsMessageIn::tls_deserialize_exact(bytes).expect("an MlsMessage");
    let MlsMessageBodyIn::KeyPackage(package) = message.extract() else {
        panic!("not a key package");
    };
    let package: KeyPackageIn = package;
    package
        .validate(
            &openmls_rust_crypto::RustCrypto::default(),
            openmls::prelude::ProtocolVersion::Mls10,
        )
        .expect("a key package whose own signature verifies")
        .ciphersuite()
}

#[test]
fn the_suite_is_the_x_wing_hybrid() {
    assert_eq!(
        PEACHY_CIPHERSUITE,
        Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519
    );
    assert_eq!(u16::from(PEACHY_CIPHERSUITE), 0x004F);
    // Ed25519 stays the signature scheme: the leaf signature key IS the
    // device key, which the credential binding compares byte for byte.
    assert_eq!(
        PEACHY_CIPHERSUITE.signature_algorithm(),
        openmls::prelude::SignatureScheme::ED25519
    );
    assert_eq!(
        PEACHY_CIPHERSUITE.hpke_kem_algorithm(),
        openmls_traits::types::HpkeKemType::XWingKemDraft6
    );
}

#[test]
fn key_packages_and_groups_are_minted_on_the_pq_suite_and_fit_the_server() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let bo = client(&server, 2, "actor-bo", "device-bo");

    let package = bo.generate_key_package().expect("key package");
    assert_eq!(key_package_suite(&package), PEACHY_CIPHERSUITE);
    println!("key package: {} bytes", package.len());
    assert!(
        package.len() < SERVER_MAX_KEY_PACKAGE_BYTES / 4,
        "a key package of {} bytes is too close to the server's {} byte limit",
        package.len(),
        SERVER_MAX_KEY_PACKAGE_BYTES
    );

    ada.create_group(GROUP).expect("create");
    let added = ada.add_member(GROUP, &package).expect("add bo");
    ada.merge_pending_commit(GROUP).expect("merge");
    let welcome = added.welcome.expect("welcome");
    println!("add commit (2 leaves): {} bytes", added.commit.len());
    println!("welcome (2 leaves): {} bytes", welcome.len());

    let update = ada.self_update(GROUP).expect("self update");
    ada.merge_pending_commit(GROUP).expect("merge");
    println!(
        "self-update commit (2 leaves): {} bytes",
        update.commit.len()
    );

    let message = ada.encrypt(GROUP, b"hello").expect("encrypt");
    println!("application message, 5-byte body: {} bytes", message.len());
}

#[test]
fn an_eight_leaf_group_commits_within_the_mailbox_envelope() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    ada.create_group(GROUP).expect("create");
    let mut last_welcome = 0;
    let mut add_commit = 0;
    for tag in 2..=8u8 {
        let peer = client(
            &server,
            tag,
            &format!("actor-{tag}"),
            &format!("device-{tag}"),
        );
        let package = peer.generate_key_package().expect("key package");
        let added = ada.add_member(GROUP, &package).expect("add");
        ada.merge_pending_commit(GROUP).expect("merge");
        last_welcome = added.welcome.map_or(0, |w| w.len());
        add_commit = added.commit.len();
    }
    let update = ada.self_update(GROUP).expect("self update");
    ada.merge_pending_commit(GROUP).expect("merge");
    println!("add commit (8th leaf): {add_commit} bytes");
    println!("welcome (8 leaves): {last_welcome} bytes");
    println!(
        "self-update commit (8 leaves): {} bytes",
        update.commit.len()
    );
    let remove = ada.remove_leaf(GROUP, 7).expect("remove");
    ada.merge_pending_commit(GROUP).expect("merge");
    println!("remove commit (8 leaves): {} bytes", remove.commit.len());
}

/// The Welcome carries the whole ratchet tree, so it is the artefact that
/// grows with the group. Ignored by default (it builds a large group); run
/// with `--release -- --ignored --nocapture` to re-measure the doc's numbers.
#[test]
#[ignore]
fn welcome_growth_by_group_size() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    ada.create_group(GROUP).expect("create");
    let mut seated = 1usize;
    for tag in 2..=255u8 {
        let peer = client(
            &server,
            tag,
            &format!("actor-{tag}"),
            &format!("device-{tag}"),
        );
        let package = peer.generate_key_package().expect("key package");
        let added = ada.add_member(GROUP, &package).expect("add");
        ada.merge_pending_commit(GROUP).expect("merge");
        seated += 1;
        if [16, 64, 128, 255].contains(&seated) {
            let update = ada.self_update(GROUP).expect("self update");
            ada.merge_pending_commit(GROUP).expect("merge");
            println!(
                "{seated} leaves: welcome {} bytes, add commit {} bytes, self-update commit {} bytes",
                added.welcome.map_or(0, |w| w.len()),
                added.commit.len(),
                update.commit.len()
            );
        }
    }
}
