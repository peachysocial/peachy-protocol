// SPDX-License-Identifier: MIT
//! A refused Welcome leaves the store free for another connection to write.
//!
//! Joining spends the key package the Welcome was sealed to before anything
//! about the Welcome can be checked (`Client::join_from_welcome`), and on
//! `SqliteKv` that spend opens the store's deferred transaction and takes the
//! file's write lock. The Apple apps keep this file in a container the
//! notification extension also opens, so a refusal that returned with the
//! transaction still open left the extension unable to write anything (a
//! received message included) until some unrelated operation flushed, and a
//! suspended app holding that lock is one the platform kills.
//!
//! Each test drives one kind of refusal against a client on a SQLite file and
//! then opens a second connection to the same file, as the extension does,
//! and requires it to write and commit. A lock still held would make that
//! write wait out the busy timeout and fail with "database is locked".

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use std::path::PathBuf;

use peachy_mls_core::welcome_frame::{frame_welcome, unframe_welcome};
use peachy_mls_core::{Client, Error, Incoming, KvStore, PeachyStorage, SqliteKv, SEND_KEY_LABEL};
use sha2::{Digest, Sha256};
use support::{client, client_on, issuer, past_the_mark};

const GROUP: &[u8] = b"77777777-7777-4777-8777-777777777777";

fn store_path(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "peachy-welcome-refusal-{}-{name}.sqlite",
        std::process::id()
    ));
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
    path
}

fn on_file(tag: u8, actor: &str, device: &str, path: &PathBuf) -> Client {
    let storage = PeachyStorage::open(Box::new(SqliteKv::open(path).expect("open the store")))
        .expect("storage");
    client_on(&issuer(), tag, actor, device, storage)
}

/// A second connection to the same file writes and commits.
fn another_connection_can_write(path: &PathBuf) -> bool {
    let other = SqliteKv::open(path).expect("open a second connection");
    match other
        .put(b"\x01probe\x1fother", b"x")
        .and_then(|()| other.flush())
    {
        Ok(()) => true,
        Err(err) => {
            println!("the second connection could not write: {err}");
            false
        }
    }
}

fn add(adder: &mut Client, joiner: &mut Client, group: &[u8]) -> Vec<u8> {
    let key_package = joiner.generate_key_package().expect("key package");
    let bundle = adder.add_member(group, &key_package).expect("add");
    adder.merge_pending_commit(group).expect("merge");
    // Through the head, as the apps take a Welcome: the adder's commit was
    // the last the delivery service took.
    support::join_at_head(
        joiner,
        &bundle.welcome.expect("welcome"),
        support::head_of(adder, group),
    )
    .expect("join");
    bundle.commit
}

fn head_of(client: &Client, group: &[u8]) -> (u64, [u8; 32]) {
    let epoch = client.epoch(group).unwrap();
    let verifier: [u8; 32] = Sha256::digest(
        client
            .export_secret(group, SEND_KEY_LABEL, group, 32)
            .unwrap(),
    )
    .into();
    (epoch, verifier)
}

/// Ada founds the group with Bo (on `path`) and Eve, then removes Eve, who
/// keeps the group id.
fn ada_bo_on_file_and_removed_eve(path: &PathBuf) -> (Client, Client, Client) {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut bo = on_file(2, "actor-bo", "device-bo", path);
    let mut eve = client(&server, 3, "actor-eve", "device-eve");
    ada.create_group(GROUP).unwrap();
    add(&mut ada, &mut bo, GROUP);
    let commit = add(&mut ada, &mut eve, GROUP);
    bo.process_commit(GROUP, &commit).unwrap();
    let eve_leaf = ada.leaf_of_device(GROUP, "device-eve").unwrap();
    let removal = ada.remove_leaf(GROUP, eve_leaf).unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    bo.process_commit(GROUP, &removal.commit).unwrap();
    match eve.process_commit(GROUP, &removal.commit).unwrap() {
        Incoming::Commit(outcome) => assert!(outcome.removed_self),
        other => panic!("{other:?}"),
    }
    (ada, bo, eve)
}

/// Eve founds a group of her own under the real id and seats Bo in it.
fn eves_welcome_to(eve: &mut Client, bo: &Client) -> Vec<u8> {
    if eve.group_ids().iter().any(|id| id == GROUP) {
        eve.forget_group(GROUP).unwrap();
        eve.create_group(GROUP).unwrap();
        past_the_mark(eve, GROUP);
    }
    let bundle = eve
        .add_member(GROUP, &bo.generate_key_package().unwrap())
        .unwrap();
    eve.merge_pending_commit(GROUP).unwrap();
    bundle.welcome.unwrap()
}

#[test]
fn a_welcome_that_does_not_open_leaves_the_store_free() {
    // Anybody who can fetch one of Bo's key packages can address a Welcome to
    // it. One byte flipped in the sealed GroupInfo: the package is spent, and
    // then the Welcome does not open.
    let path = store_path("corrupted");
    let mut bo = on_file(2, "actor-bo", "device-bo", &path);
    let mut stranger = client(&issuer(), 9, "actor-stranger", "device-stranger");
    stranger.create_group(GROUP).unwrap();
    let sent = stranger
        .add_member(GROUP, &bo.generate_key_package().unwrap())
        .unwrap()
        .welcome
        .unwrap();
    // A byte flipped in the MLS Welcome inside the frame, framed again: a
    // flipped fill byte would be the frame's own refusal, not a Welcome that
    // does not open.
    let mut inner = unframe_welcome(&sent).unwrap().to_vec();
    let last = inner.len() - 1;
    inner[last] ^= 0x01;
    let welcome = frame_welcome(&inner, sent.len()).unwrap();
    assert!(another_connection_can_write(&path), "free before the join");

    assert!(matches!(bo.join_from_welcome(&welcome), Err(Error::Mls(_))));
    assert!(another_connection_can_write(&path));

    // Bytes that are not a Welcome at all are refused before any write.
    assert!(bo.join_from_welcome(b"\x00\x01not a welcome").is_err());
    assert!(another_connection_can_write(&path));

    // And a Welcome that is taken leaves it free too.
    let mut ada = client(&issuer(), 1, "actor-ada", "device-ada");
    ada.create_group(GROUP).unwrap();
    let bundle = ada
        .add_member(GROUP, &bo.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(GROUP).unwrap();
    assert_eq!(
        bo.join_from_welcome(&bundle.welcome.unwrap()).unwrap(),
        GROUP
    );
    assert!(another_connection_can_write(&path));
}

#[test]
fn a_welcome_into_a_group_already_held_leaves_the_store_free() {
    let path = store_path("held");
    let (ada, mut bo, mut eve) = ada_bo_on_file_and_removed_eve(&path);
    let welcome = eves_welcome_to(&mut eve, &bo);
    assert!(another_connection_can_write(&path), "free before the join");

    assert!(matches!(
        bo.join_from_welcome(&welcome),
        Err(Error::AlreadyAMember)
    ));
    assert!(bo.is_active(GROUP).unwrap());
    assert!(another_connection_can_write(&path));

    // The head names the group Bo holds: the contested Welcome is refused.
    let (head_epoch, head_verifier) = head_of(&ada, GROUP);
    assert!(matches!(
        bo.join_contested_welcome(head_epoch, &head_verifier),
        Err(Error::AlreadyAMember)
    ));
    assert!(another_connection_can_write(&path));

    // Nothing is waiting any more: refused before anything is read.
    assert!(matches!(
        bo.join_contested_welcome(head_epoch, &head_verifier),
        Err(Error::InvalidArgument(_))
    ));
    assert!(another_connection_can_write(&path));
}

#[test]
fn a_welcome_from_a_removed_own_device_leaves_the_store_free() {
    let path = store_path("forgotten");
    let server = issuer();
    let mut laptop = on_file(2, "actor-bo", "device-bo-laptop", &path);
    let mut phone = client(&server, 3, "actor-bo", "device-bo-phone");
    let other: &[u8] = b"78787878-7878-4878-8878-787878787878";
    phone.create_group(other).unwrap();
    add(&mut phone, &mut laptop, other);
    assert!(laptop.forget_own_device("device-bo-phone").unwrap());
    assert!(another_connection_can_write(&path), "free before the join");

    // The removed phone seats the laptop in a group of its own: refused.
    phone.create_group(GROUP).unwrap();
    let welcome = phone
        .add_member(GROUP, &laptop.generate_key_package().unwrap())
        .unwrap()
        .welcome
        .unwrap();
    assert!(matches!(
        laptop.join_from_welcome(&welcome),
        Err(Error::WelcomeFromOutsider)
    ));
    assert!(another_connection_can_write(&path));
}

#[cfg(feature = "test-forgery")]
#[test]
fn a_welcome_into_a_tree_holding_another_key_for_this_person_leaves_the_store_free() {
    use peachy_mls_core::issuer::device_key_pair;
    use peachy_mls_core::{ClientConfig, DenyReason, FixedClock};
    use support::{device_seed, DAY, HOUR, NOW};

    let server = issuer();
    let path = store_path("account-key");
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    let mut bo = client(&server, 2, "actor-bo", "device-bo-phone");
    ada.create_group(GROUP).unwrap();
    add(&mut ada, &mut bo, GROUP);

    // A device the server certified as Ada's, under an account key of its
    // own making, seated by a modified Bo; then Ada's real laptop.
    let seed = device_seed(9);
    let (_, public) = device_key_pair(&seed);
    let token = server
        .issue_for_account(
            "actor-ada",
            "device-ghost",
            &public,
            Some(&[0x99; 32]),
            NOW - HOUR,
            NOW + 30 * DAY,
        )
        .unwrap();
    // The server's device holds the key the server made.
    let mut config = ClientConfig::new(token, seed, server.trusted_keys().unwrap())
        .with_storage(PeachyStorage::in_memory())
        .with_own_account_identity(Some(
            peachy_mls_core::account_identity_public_key(&[0x99; 32]).unwrap(),
        ));
    config.clock = Some(Box::new(FixedClock(NOW)));
    let ghost = Client::new(config).unwrap();
    bo.forge_commit(GROUP, &[], &[&ghost.generate_key_package().unwrap()])
        .unwrap();
    bo.merge_pending_commit(GROUP).unwrap();

    let mut laptop = on_file(3, "actor-ada", "device-ada-laptop", &path);
    let forged = bo
        .forge_commit(GROUP, &[], &[&laptop.generate_key_package().unwrap()])
        .unwrap();
    assert!(another_connection_can_write(&path), "free before the join");
    assert!(matches!(
        laptop.join_from_welcome(&forged.welcome.unwrap()),
        Err(Error::PolicyRefused(DenyReason::AccountKeyConflict))
    ));
    assert!(another_connection_can_write(&path));
}
