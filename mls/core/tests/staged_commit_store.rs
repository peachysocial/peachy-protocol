// SPDX-License-Identifier: MIT
//! No store transaction spans the request to the delivery service.
//!
//! A commit is staged, submitted, and then merged or cleared on the server's
//! answer (`mls/core/src/group.rs` §The commit lifecycle). The stage is a
//! write: OpenMLS keeps the pending commit in the group's stored state, and
//! encrypting the commit advances the handshake ratchet. On `SqliteKv` the
//! first write opens a deferred transaction and takes the file's write lock,
//! so a stage that returned without committing held that lock for the whole
//! round trip, and every other connection to the file (a notification
//! extension) could open no message until the verdict came back.
//!
//! These tests probe the lock with a raw SQLite connection taking
//! `BEGIN IMMEDIATE` with a busy timeout of zero: SQLite's own answer, with no
//! five-second wait.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use peachy_mls_core::{
    Client, DenyReason, Error, Incoming, PeachyStorage, SavedCommit, SqliteKv, SEND_KEY_LABEL,
};
use support::{client, client_on, issuer, DAY, HOUR, NOW};

const G1: &[u8] = b"66666666-6666-4666-8666-666666666661";
const G2: &[u8] = b"66666666-6666-4666-8666-666666666662";

fn fresh_path(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "peachy-staged-commit-{}-{name}.sqlite",
        std::process::id()
    ));
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
    path
}

fn plain_store(path: &Path) -> PeachyStorage {
    PeachyStorage::open(Box::new(SqliteKv::open(path).expect("open"))).expect("storage")
}

/// The Apple apps' store: SQLCipher with a 32-byte plaintext header.
fn apple_keyspec() -> [u8; 48] {
    let mut keyspec = [0x42u8; 48];
    keyspec[32..].copy_from_slice(&[0x17u8; 16]);
    keyspec
}

fn apple_store(path: &Path, keyspec: &[u8; 48]) -> PeachyStorage {
    PeachyStorage::open(Box::new(
        SqliteKv::open_encrypted_with_plaintext_header(path, keyspec).expect("open"),
    ))
    .expect("storage")
}

/// Can ANOTHER connection take the write lock right now?
fn write_lock_free(path: &Path, keyspec: Option<&[u8; 48]>) -> bool {
    let connection = rusqlite::Connection::open(path).expect("raw open");
    if let Some(spec) = keyspec {
        let hex: String = spec.iter().map(|b| format!("{b:02X}")).collect();
        connection
            .execute_batch(&format!(
                "PRAGMA key = \"x'{hex}'\"; PRAGMA cipher_plaintext_header_size = 32;"
            ))
            .expect("key");
    }
    connection.busy_timeout(Duration::ZERO).expect("timeout");
    match connection.execute_batch("BEGIN IMMEDIATE; ROLLBACK;") {
        Ok(()) => true,
        Err(err) => {
            let text = err.to_string();
            assert!(text.contains("locked") || text.contains("busy"), "{text}");
            false
        }
    }
}

/// What COMMITTED state says about a group: whether its stored OpenMLS
/// `group_state` row holds a pending commit. Read on a connection of its
/// own, so only what was committed is visible.
fn committed_stage(path: &Path, group: &[u8]) -> bool {
    let connection = rusqlite::Connection::open(path).expect("raw open");
    let mut key = vec![1u8];
    key.extend_from_slice(b"group_state");
    key.push(0x1f);
    // `serde_json` of an OpenMLS `GroupId`, built by hand.
    let numbers: Vec<String> = group.iter().map(u8::to_string).collect();
    key.extend_from_slice(format!("{{\"value\":{{\"vec\":[{}]}}}}", numbers.join(",")).as_bytes());
    let value: Vec<u8> = connection
        .query_row("SELECT v FROM mls_kv WHERE k = ?1", [&key], |row| {
            row.get(0)
        })
        .expect("a group_state row for the group");
    value.windows(13).any(|window| window == b"PendingCommit")
}

fn seat(adder: &mut Client, joiner: &mut Client, group: &[u8]) {
    let package = joiner.generate_key_package().expect("kp");
    let bundle = adder.add_member(group, &package).expect("add");
    adder.merge_pending_commit(group).expect("merge");
    joiner
        .join_from_welcome(&bundle.welcome.expect("welcome"))
        .expect("join");
}

/// A credential for Ada's device a day fresher than the one she was built
/// with, as `RegisterDevice` hands out on a later launch.
fn fresher_credential(server: &peachy_mls_core::issuer::TestIssuer) -> Vec<u8> {
    let (_, public) = peachy_mls_core::issuer::device_key_pair(&support::device_seed(1));
    server
        .issue(
            "actor-ada",
            "device-ada",
            &public,
            NOW,
            NOW + 30 * DAY + HOUR,
        )
        .expect("mint")
}

/// Every stage door returns with the store free and the stage committed:
/// pending in memory and on disk, the write lock released. The clear then
/// commits the group back to where it was.
#[test]
fn every_stage_door_returns_with_the_store_free() {
    let server = issuer();
    let path = fresh_path("doors");
    let mut ada = client_on(&server, 1, "actor-ada", "device-ada", plain_store(&path));
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    let mut cy = client(&server, 3, "actor-cy", "device-cy");
    let dee = client(&server, 4, "actor-dee", "device-dee");
    ada.create_group(G1).unwrap();
    seat(&mut ada, &mut bo, G1);
    seat(&mut ada, &mut cy, G1);
    assert!(write_lock_free(&path, None), "free after the merges");

    let cy_leaf = ada.leaf_of_device(G1, "device-cy").unwrap();
    let dee_package = dee.generate_key_package().unwrap();
    let cy_package = cy.generate_key_package().unwrap();
    let fresher = fresher_credential(&server);
    type Door = Box<dyn Fn(&mut Client) -> peachy_mls_core::Result<()>>;
    let doors: Vec<(&str, Door)> = vec![
        (
            "add_member",
            Box::new(move |c: &mut Client| c.add_member(G1, &dee_package).map(|_| ())),
        ),
        (
            "remove_member",
            Box::new(move |c: &mut Client| c.remove_leaf(G1, cy_leaf).map(|_| ())),
        ),
        (
            "replace_member",
            Box::new(move |c: &mut Client| c.replace_member(G1, cy_leaf, &cy_package).map(|_| ())),
        ),
        (
            "self_update",
            Box::new(|c: &mut Client| c.self_update(G1).map(|_| ())),
        ),
        (
            "refresh_credential",
            Box::new(move |c: &mut Client| {
                c.update_credential(&fresher, None)?;
                c.refresh_credential(G1).map(|_| ())
            }),
        ),
        (
            "set_group_meta",
            Box::new(|c: &mut Client| c.set_group_meta(G1, b"{\"n\":\"x\"}").map(|_| ())),
        ),
    ];
    for (name, door) in &doors {
        let epoch = ada.epoch(G1).unwrap();
        door(&mut ada).unwrap_or_else(|err| panic!("{name}: {err}"));
        assert!(ada.has_pending_commit(G1).unwrap(), "{name}: staged");
        assert!(
            write_lock_free(&path, None),
            "{name} returned with the store's write lock held"
        );
        assert!(committed_stage(&path, G1), "{name}: the stage is committed");

        ada.clear_pending_commit(G1).unwrap();
        assert!(write_lock_free(&path, None), "{name}: free after the clear");
        assert!(
            !committed_stage(&path, G1),
            "{name}: the clear is committed"
        );
        assert_eq!(ada.epoch(G1).unwrap(), epoch, "{name}: nothing moved");
    }

    // And the merge, after a stage that is already on disk.
    let rotation = ada.self_update(G1).unwrap();
    let epoch = ada.merge_pending_commit(G1).unwrap();
    assert!(write_lock_free(&path, None));
    assert!(!committed_stage(&path, G1));
    // Cy joined at the epoch the stages were built at (Bo was seated one
    // before it and never shown Cy's add).
    let applied = cy.process_commit(G1, &rotation.commit);
    assert!(matches!(applied, Ok(Incoming::Commit(_))), "{applied:?}");
    assert_eq!(cy.epoch(G1).unwrap(), epoch);
}

/// A stage the receivers would refuse is built, judged, cleared and refused
/// (`refuse_own_commit_receivers_would_refuse`): two writes, and a refusal
/// after them. It returns with both committed and the store free.
#[test]
fn a_stage_refused_after_it_was_built_returns_with_the_store_free() {
    let server = issuer();
    let path = fresh_path("refused");
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut bo = client_on(&server, 2, "actor-bo", "device-bo", plain_store(&path));
    let mut cy = client(&server, 3, "actor-cy", "device-cy");
    ada.create_group(G1).unwrap();
    // Ada is the group's one admin.
    ada.set_group_meta(G1, b"{\"v\":1,\"n\":\"Walk\",\"adm\":[\"actor-ada\"]}")
        .unwrap();
    ada.merge_pending_commit(G1).unwrap();
    seat(&mut ada, &mut bo, G1);
    let add_cy = ada
        .add_member(G1, &cy.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G1).unwrap();
    bo.process_commit(G1, &add_cy.commit).unwrap();
    cy.join_from_welcome(&add_cy.welcome.unwrap()).unwrap();
    assert!(write_lock_free(&path, None), "free before");

    let cy_leaf = bo.leaf_of_device(G1, "device-cy").unwrap();
    let removal = bo.remove_leaf(G1, cy_leaf);
    assert!(
        matches!(
            removal,
            Err(Error::PolicyRefused(DenyReason::RemoveNeedsAdmin))
        ),
        "{removal:?}"
    );
    assert!(!bo.has_pending_commit(G1).unwrap());
    assert!(
        write_lock_free(&path, None),
        "a refused removal returned with the store's write lock held"
    );
    assert!(!committed_stage(&path, G1));

    let promotion = bo.set_group_meta(
        G1,
        b"{\"v\":1,\"n\":\"Walk\",\"adm\":[\"actor-ada\",\"actor-bo\"]}",
    );
    assert!(
        matches!(
            promotion,
            Err(Error::PolicyRefused(DenyReason::PolicyNeedsAdmin))
        ),
        "{promotion:?}"
    );
    assert!(
        write_lock_free(&path, None),
        "a refused rename returned with the store's write lock held"
    );

    // Nothing was left behind: Bo still reads the group and writes to it.
    let hello = ada.encrypt(G1, b"still here").unwrap();
    assert!(matches!(
        bo.process_message(G1, &hello),
        Ok(Incoming::Application { .. })
    ));
}

/// The Apple store shape, on the honest renewal path. While the app waits on
/// the server's verdict, a second client on the same file (the notification
/// extension) opens and decrypts a message at once. Its open keeps the app's
/// stage as a saved commit and writes nothing for it, and the app's merge
/// takes the group forward for everybody. The merge starts from the group as
/// the extension left it, so the key the extension spent stays spent: neither
/// the live app nor a client opened afterwards opens that message again.
#[test]
fn the_extension_opens_a_message_while_a_commit_waits_on_the_server() {
    let server = issuer();
    let path = fresh_path("extension");
    let keyspec = apple_keyspec();
    let mut app = client_on(
        &server,
        1,
        "actor-ada",
        "device-ada",
        apple_store(&path, &keyspec),
    );
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    app.create_group(G1).unwrap();
    app.create_group(G2).unwrap();
    seat(&mut app, &mut bo, G1);
    seat(&mut app, &mut bo, G2);

    app.update_credential(&fresher_credential(&server), None)
        .unwrap();
    let renewal = app.refresh_credential(G1).unwrap();
    assert!(
        write_lock_free(&path, Some(&keyspec)),
        "the stage returned with the store's write lock held"
    );

    let message = bo.encrypt(G1, b"running late").unwrap();
    let elsewhere = bo.encrypt(G2, b"and here").unwrap();
    {
        let mut extension = client_on(
            &server,
            1,
            "actor-ada",
            "device-ada",
            apple_store(&path, &keyspec),
        );
        let started = Instant::now();
        let opened = extension.process_message(G1, &message);
        assert!(
            matches!(opened, Ok(Incoming::Application { .. })),
            "the extension could not open a message during the wait: {opened:?}"
        );
        assert!(matches!(
            extension.process_message(G2, &elsewhere),
            Ok(Incoming::Application { .. })
        ));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the extension waited on a lock: {:?}",
            started.elapsed()
        );
        // The app's stage, kept: a second process never settles a commit it
        // did not stage.
        assert!(extension.has_saved_commit(G1).unwrap());
    }

    // The server accepted: the app merges its stage, from the group as the
    // extension wrote it.
    let epoch = app.merge_pending_commit(G1).unwrap();
    assert!(write_lock_free(&path, Some(&keyspec)));
    assert!(matches!(
        bo.process_commit(G1, &renewal.commit),
        Ok(Incoming::Commit(_))
    ));
    assert_eq!(bo.epoch(G1).unwrap(), epoch);
    let after = app.encrypt(G1, b"on my way").unwrap();
    assert!(matches!(
        bo.process_message(G1, &after),
        Ok(Incoming::Application { .. })
    ));
    let reply = bo.encrypt(G1, b"see you").unwrap();
    assert!(matches!(
        app.process_message(G1, &reply),
        Ok(Incoming::Application { .. })
    ));
    let replayed = app.process_message(G1, &message);
    assert!(
        !matches!(replayed, Ok(Incoming::Application { .. })),
        "the app opened again a message the extension had opened: {replayed:?}"
    );

    // And a client opened afterwards finds the merged epoch on disk.
    drop(app);
    let mut reopened = client_on(
        &server,
        1,
        "actor-ada",
        "device-ada",
        apple_store(&path, &keyspec),
    );
    assert_eq!(reopened.epoch(G1).unwrap(), epoch);
    assert!(!reopened.has_pending_commit(G1).unwrap());
    let replayed = reopened.process_message(G1, &message);
    assert!(
        !matches!(replayed, Ok(Incoming::Application { .. })),
        "the store gave back the key the extension spent: {replayed:?}"
    );
}

/// An open that finds another client's stage on disk keeps it, as a saved
/// commit, writes nothing and leaves the store free; the live client, whose
/// stage it is, then clears its own (the server refused) and goes on.
#[test]
fn an_open_keeps_a_stage_it_finds_and_writes_nothing() {
    let server = issuer();
    let path = fresh_path("open");
    let mut app = client_on(&server, 1, "actor-ada", "device-ada", plain_store(&path));
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    app.create_group(G1).unwrap();
    app.create_group(G2).unwrap();
    seat(&mut app, &mut bo, G1);
    seat(&mut app, &mut bo, G2);

    app.self_update(G2).unwrap();
    assert!(committed_stage(&path, G2));
    assert!(
        !app.has_saved_commit(G2).unwrap(),
        "a stage of this run's own"
    );
    let second = client_on(&server, 1, "actor-ada", "device-ada", plain_store(&path));
    assert!(
        committed_stage(&path, G2),
        "the open kept the stage it found"
    );
    assert!(write_lock_free(&path, None), "the open left the store free");
    assert!(second.has_saved_commit(G2).unwrap());
    assert!(!second.has_saved_commit(G1).unwrap());
    drop(second);

    // The server refused: the live client clears its own stage and sends.
    let epoch = app.epoch(G2).unwrap();
    app.clear_pending_commit(G2).unwrap();
    assert!(write_lock_free(&path, None));
    assert!(!committed_stage(&path, G2));
    assert_eq!(app.epoch(G2).unwrap(), epoch);
    let hello = app.encrypt(G2, b"hello").unwrap();
    assert!(matches!(
        bo.process_message(G2, &hello),
        Ok(Incoming::Application { .. })
    ));
}

// ---- A crash between the stage and the verdict ------------------------------

const CHILD_ENV: &str = "PEACHY_STAGED_COMMIT_CRASH_CHILD";

/// The child half of the crash tests: stage a rotation and die without
/// unwinding, as a killed process does. A no-op unless the parent set the
/// variable.
#[test]
fn crash_child_stages_then_aborts() {
    let Ok(path) = std::env::var(CHILD_ENV) else {
        return;
    };
    let path = PathBuf::from(path);
    let mut ada = client_on(&issuer(), 1, "actor-ada", "device-ada", plain_store(&path));
    let bundle = ada.self_update(G1).unwrap();
    let free = write_lock_free(&path, None);
    std::fs::write(format!("{}.commit", path.display()), &bundle.commit).unwrap();
    std::fs::write(format!("{}.lockfree", path.display()), free.to_string()).unwrap();
    std::process::abort();
}

fn copy_store(from: &Path, to: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", to.display()));
        let source = format!("{}{suffix}", from.display());
        if Path::new(&source).exists() {
            std::fs::copy(&source, format!("{}{suffix}", to.display())).unwrap();
        }
    }
}

/// Ada and Bo in G1 at epoch 1; then Ada's process stages a rotation and is
/// killed while it waits on the server.
struct Crash {
    server: peachy_mls_core::issuer::TestIssuer,
    /// Ada's store as the killed process left it.
    ada: PathBuf,
    /// Bo's store, at epoch 1.
    bo: PathBuf,
    /// The rotation Ada submitted.
    commit: Vec<u8>,
}

impl Crash {
    fn new(name: &str) -> Self {
        let server = issuer();
        let ada_path = fresh_path(&format!("{name}-ada"));
        let bo_path = fresh_path(&format!("{name}-bo"));
        {
            let mut ada = client_on(
                &server,
                1,
                "actor-ada",
                "device-ada",
                plain_store(&ada_path),
            );
            let mut bo = client_on(&server, 2, "actor-bo", "device-bo", plain_store(&bo_path));
            ada.create_group(G1).unwrap();
            seat(&mut ada, &mut bo, G1);
        }
        let crashed = fresh_path(&format!("{name}-ada-child"));
        copy_store(&ada_path, &crashed);
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "crash_child_stages_then_aborts",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_ENV, &crashed)
            .output()
            .unwrap();
        assert!(!child.status.success(), "the child must have died");
        let commit = std::fs::read(format!("{}.commit", crashed.display())).unwrap();
        let free = std::fs::read_to_string(format!("{}.lockfree", crashed.display())).unwrap();
        assert_eq!(
            free, "true",
            "the stage returned with the store's write lock held"
        );
        assert!(committed_stage(&crashed, G1), "the stage reached the disk");
        Self {
            server,
            ada: crashed,
            bo: bo_path,
            commit,
        }
    }

    /// Ada's next launch. The open keeps the stage and writes nothing.
    fn reopen_ada(&self) -> Client {
        let ada = client_on(
            &self.server,
            1,
            "actor-ada",
            "device-ada",
            plain_store(&self.ada),
        );
        assert!(ada.has_saved_commit(G1).unwrap(), "the open kept the stage");
        assert!(committed_stage(&self.ada, G1));
        assert!(write_lock_free(&self.ada, None));
        assert_eq!(ada.epoch(G1).unwrap(), 1, "nothing moved yet");
        ada
    }

    fn bo(&self) -> Client {
        client_on(
            &self.server,
            2,
            "actor-bo",
            "device-bo",
            plain_store(&self.bo),
        )
    }
}

/// The head as the delivery service reports it, read off a member at it:
/// its epoch and the SHA-256 of its send key.
fn head_of(member: &Client) -> (u64, Vec<u8>) {
    use sha2::Digest as _;
    let key = member.export_secret(G1, SEND_KEY_LABEL, G1, 32).unwrap();
    (
        member.epoch(G1).unwrap(),
        sha2::Sha256::digest(key).to_vec(),
    )
}

fn talk(ada: &mut Client, bo: &mut Client) {
    let there = ada.encrypt(G1, b"after the crash").unwrap();
    assert!(matches!(
        bo.process_message(G1, &there),
        Ok(Incoming::Application { .. })
    ));
    let back = bo.encrypt(G1, b"welcome back").unwrap();
    assert!(matches!(
        ada.process_message(G1, &back),
        Ok(Incoming::Application { .. })
    ));
}

/// The server TOOK the commit before the process died: the head is the epoch
/// and send key it makes, and settling merges it. Before, the open cleared
/// it and the device had to rejoin.
#[test]
fn a_saved_commit_the_server_took_is_merged_by_the_head() {
    if std::env::var(CHILD_ENV).is_ok() {
        return;
    }
    let crash = Crash::new("took");
    let mut bo = crash.bo();
    assert!(matches!(
        bo.process_commit(G1, &crash.commit),
        Ok(Incoming::Commit(_))
    ));
    let (head_epoch, verifier) = head_of(&bo);
    assert_eq!(head_epoch, 2);

    let mut ada = crash.reopen_ada();
    let settled = ada.settle_saved_commit(G1, head_epoch, &verifier).unwrap();
    assert_eq!(settled, SavedCommit::Merged);
    assert_eq!(ada.epoch(G1).unwrap(), 2);
    assert!(!ada.has_pending_commit(G1).unwrap());
    assert!(!committed_stage(&crash.ada, G1), "the merge is committed");
    assert!(write_lock_free(&crash.ada, None));
    talk(&mut ada, &mut bo);

    // Its echo, still in the mailbox, moves nothing now.
    let _ = ada.process_commit(G1, &crash.commit);
    assert_eq!(ada.epoch(G1).unwrap(), 2);
    talk(&mut ada, &mut bo);
}

/// The server REFUSED it, or never saw it: the head is the group's own epoch,
/// and settling clears it. Another member's commit won the epoch instead:
/// the head is the next epoch under another send key, and settling clears it
/// too; the winner's commit then applies.
#[test]
fn a_saved_commit_the_server_refused_is_cleared_by_the_head() {
    if std::env::var(CHILD_ENV).is_ok() {
        return;
    }
    let crash = Crash::new("refused");
    let mut bo = crash.bo();
    let (head_epoch, verifier) = head_of(&bo);
    let mut ada = crash.reopen_ada();
    let settled = ada.settle_saved_commit(G1, head_epoch, &verifier).unwrap();
    assert_eq!(settled, SavedCommit::Cleared);
    assert_eq!(ada.epoch(G1).unwrap(), 1);
    assert!(!ada.has_pending_commit(G1).unwrap());
    assert!(!committed_stage(&crash.ada, G1), "the clear is committed");
    assert!(write_lock_free(&crash.ada, None));
    talk(&mut ada, &mut bo);

    // Another member won the epoch.
    let crash = Crash::new("lost");
    let mut bo = crash.bo();
    let winner = bo.self_update(G1).unwrap();
    bo.merge_pending_commit(G1).unwrap();
    let (head_epoch, verifier) = head_of(&bo);
    let mut ada = crash.reopen_ada();
    assert_eq!(
        ada.settle_saved_commit(G1, head_epoch, &verifier).unwrap(),
        SavedCommit::Cleared
    );
    assert!(matches!(
        ada.process_commit(G1, &winner.commit),
        Ok(Incoming::Commit(_))
    ));
    assert_eq!(ada.epoch(G1).unwrap(), 2);
    talk(&mut ada, &mut bo);
}

/// The server could not be reached: nothing is settled, and the commit stays
/// exactly as it was. Nothing clears it (the error path of a stage that the
/// saved commit blocks included), no other commit is staged over it, another
/// launch keeps it again, and the head settles it once it can be read.
#[test]
fn a_saved_commit_is_kept_while_the_server_cannot_be_reached() {
    if std::env::var(CHILD_ENV).is_ok() {
        return;
    }
    let crash = Crash::new("unreachable");
    let mut bo = crash.bo();
    assert!(bo.process_commit(G1, &crash.commit).is_ok());

    let mut ada = crash.reopen_ada();
    assert!(
        ada.self_update(G1).is_err(),
        "no commit is staged over a saved one"
    );
    ada.clear_pending_commit(G1).unwrap();
    assert!(ada.has_saved_commit(G1).unwrap(), "a clear leaves it");
    assert!(committed_stage(&crash.ada, G1));
    assert!(write_lock_free(&crash.ada, None));
    drop(ada);

    let mut ada = crash.reopen_ada();
    let (head_epoch, verifier) = head_of(&bo);
    assert_eq!(
        ada.settle_saved_commit(G1, head_epoch, &verifier).unwrap(),
        SavedCommit::Merged
    );
    talk(&mut ada, &mut bo);
    assert!(
        ada.settle_saved_commit(G1, head_epoch, &verifier).is_err(),
        "nothing left to settle"
    );
}

/// The head has moved past the commit's epoch: it cannot say whose commit
/// made the epoch after Ada's, so the commit is kept. Its own echo, first in
/// the mailbox, then merges it; or, had it lost, the winner's commit at its
/// epoch replaces it.
#[test]
fn a_saved_commit_the_head_has_passed_is_decided_by_the_commit_door() {
    if std::env::var(CHILD_ENV).is_ok() {
        return;
    }
    let crash = Crash::new("passed");
    let mut bo = crash.bo();
    assert!(bo.process_commit(G1, &crash.commit).is_ok());
    let later = bo.self_update(G1).unwrap();
    bo.merge_pending_commit(G1).unwrap();
    let (head_epoch, verifier) = head_of(&bo);
    assert_eq!(head_epoch, 3);

    let mut ada = crash.reopen_ada();
    assert_eq!(
        ada.settle_saved_commit(G1, head_epoch, &verifier).unwrap(),
        SavedCommit::Waiting
    );
    assert!(ada.has_saved_commit(G1).unwrap());
    assert!(matches!(
        ada.process_commit(G1, &crash.commit),
        Ok(Incoming::Echo)
    ));
    assert_eq!(ada.epoch(G1).unwrap(), 2, "the echo merged it");
    assert!(!ada.has_saved_commit(G1).unwrap());
    assert!(!committed_stage(&crash.ada, G1));
    assert!(matches!(
        ada.process_commit(G1, &later.commit),
        Ok(Incoming::Commit(_))
    ));
    assert_eq!(ada.epoch(G1).unwrap(), 3);
    talk(&mut ada, &mut bo);

    // Lost instead: Bo's own commit took epoch 2, and another after it.
    let crash = Crash::new("passed-lost");
    let mut bo = crash.bo();
    let won = bo.self_update(G1).unwrap();
    bo.merge_pending_commit(G1).unwrap();
    let after = bo.self_update(G1).unwrap();
    bo.merge_pending_commit(G1).unwrap();
    let (head_epoch, verifier) = head_of(&bo);
    let mut ada = crash.reopen_ada();
    assert_eq!(
        ada.settle_saved_commit(G1, head_epoch, &verifier).unwrap(),
        SavedCommit::Waiting
    );
    assert!(matches!(
        ada.process_commit(G1, &won.commit),
        Ok(Incoming::Commit(_))
    ));
    assert!(!ada.has_saved_commit(G1).unwrap(), "the winner replaced it");
    assert!(!ada.has_pending_commit(G1).unwrap());
    assert!(matches!(
        ada.process_commit(G1, &after.commit),
        Ok(Incoming::Commit(_))
    ));
    talk(&mut ada, &mut bo);
}

/// Nothing drops or replaces a group that holds a saved commit: the commit
/// may be one the server took, and forgetting the group, or a Welcome taking
/// its place, would throw it away for a rejoin. Both refuse with
/// `SettleFirst` and change nothing (a contested Welcome is still kept), and
/// both go through once the head has settled the commit.
#[test]
fn a_group_with_a_saved_commit_is_neither_forgotten_nor_replaced_until_settled() {
    if std::env::var(CHILD_ENV).is_ok() {
        return;
    }
    // FORGET: the server took the commit; a forget would have cost a rejoin.
    let crash = Crash::new("forget");
    let mut bo = crash.bo();
    assert!(bo.process_commit(G1, &crash.commit).is_ok());
    let mut ada = crash.reopen_ada();
    assert!(matches!(ada.forget_group(G1), Err(Error::SettleFirst)));
    assert!(
        ada.has_saved_commit(G1).unwrap(),
        "the forget changed nothing"
    );
    assert_eq!(ada.epoch(G1).unwrap(), 1);
    assert!(committed_stage(&crash.ada, G1));
    assert!(write_lock_free(&crash.ada, None));
    let (head_epoch, verifier) = head_of(&bo);
    assert_eq!(
        ada.settle_saved_commit(G1, head_epoch, &verifier).unwrap(),
        SavedCommit::Merged
    );
    talk(&mut ada, &mut bo);
    ada.forget_group(G1).expect("a settled group forgets");

    // REPLACE: the server refused the commit, and a member re-seated Ada
    // meanwhile. The Welcome is contested and kept until the head settles
    // the commit; then the head decides between the two seats as always.
    let crash = Crash::new("replace");
    let mut bo = crash.bo();
    let mut ada = crash.reopen_ada();
    let ada_leaf = bo.leaf_of_device(G1, "device-ada").unwrap();
    let fresh = ada.generate_key_package().unwrap();
    let reseat = bo.replace_member(G1, ada_leaf, &fresh).unwrap();
    bo.merge_pending_commit(G1).unwrap();
    assert!(matches!(
        ada.join_from_welcome(&reseat.welcome.clone().unwrap()),
        Err(Error::AlreadyAMember)
    ));
    assert_eq!(ada.contested_welcome_group_id(), Some(G1.to_vec()));
    let (head_epoch, verifier) = head_of(&bo);
    assert!(matches!(
        ada.join_contested_welcome(head_epoch, &verifier),
        Err(Error::SettleFirst)
    ));
    assert_eq!(
        ada.contested_welcome_group_id(),
        Some(G1.to_vec()),
        "the Welcome is still kept"
    );
    assert!(ada.has_saved_commit(G1).unwrap());
    assert_eq!(
        ada.settle_saved_commit(G1, head_epoch, &verifier).unwrap(),
        SavedCommit::Cleared
    );
    ada.join_contested_welcome(head_epoch, &verifier)
        .expect("the head's seat replaces the held copy once settled");
    assert_eq!(ada.epoch(G1).unwrap(), head_epoch);
    talk(&mut ada, &mut bo);
}
