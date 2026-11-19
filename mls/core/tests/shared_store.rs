// SPDX-License-Identifier: MIT
//! A store two processes share: the app and its notification extension, each
//! with a `Client` open on one SQLite file (docs/mls-core.md §A store
//! two processes share).
//!
//! Each client keeps its groups in memory between operations, and OpenMLS
//! writes a group's state back whole. A client that acted on the copy it
//! loaded before the other one wrote would put that older copy back: a
//! message key the other process spent (so a replay of that message opens
//! again), or an epoch the group has left. Every write door now takes the
//! store's write lock first and loads the groups again when another
//! connection has committed since, so each test below drives a second client
//! across the other's write and asserts the store keeps what that write did.
//!
//! The one-process controls are the same steps with no second client.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use peachy_mls_core::{
    storage_key, Client, Incoming, KvEntry, KvError, KvStore, PeachyStorage, RejoinReport, SqliteKv,
};
use support::{client, client_on, head_of, issuer, past_the_mark};

const G1: &[u8] = b"77777777-7777-4777-8777-777777777771";
const G2: &[u8] = b"77777777-7777-4777-8777-777777777772";

fn fresh_path(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "peachy-shared-store-{}-{name}.sqlite",
        std::process::id()
    ));
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
    path
}

fn store(path: &Path) -> PeachyStorage {
    PeachyStorage::open(Box::new(SqliteKv::open(path).expect("open"))).expect("storage")
}

fn ada_on(server: &peachy_mls_core::issuer::TestIssuer, path: &Path) -> Client {
    client_on(server, 1, "actor-ada", "device-ada", store(path))
}

fn seat(adder: &mut Client, joiner: &mut Client, group: &[u8]) {
    let package = joiner.generate_key_package().expect("kp");
    let bundle = adder.add_member(group, &package).expect("add");
    adder.merge_pending_commit(group).expect("merge");
    joiner
        .join_from_welcome(&bundle.welcome.expect("welcome"))
        .expect("join");
}

fn opens(result: &peachy_mls_core::Result<Incoming>) -> bool {
    matches!(result, Ok(Incoming::Application { .. }))
}

/// Control: one process on the store. A message whose key was spent does not
/// open again, not even from a client rebuilt from the file.
#[test]
fn control_a_spent_key_stays_spent_with_one_process() {
    let server = issuer();
    let path = fresh_path("control");
    let mut app = ada_on(&server, &path);
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    app.create_group(G1).unwrap();
    seat(&mut app, &mut bo, G1);

    let m1 = bo.encrypt(G1, b"first").unwrap();
    let m2 = bo.encrypt(G1, b"second").unwrap();
    assert!(opens(&app.process_message(G1, &m1)));
    assert!(opens(&app.process_message(G1, &m2)));
    drop(app);

    let mut seized = ada_on(&server, &path);
    let again = seized.process_message(G1, &m1);
    assert!(!opens(&again), "a spent key must stay spent: {again:?}");
}

/// The extension opens m1 and spends its key. The app, whose groups were
/// loaded before that, then opens m2: its write must start from the group
/// the extension wrote, so m1's key is not put back on disk, and neither a
/// client rebuilt from the file nor the live app opens m1 again.
#[test]
fn a_second_process_does_not_bring_back_a_spent_message_key() {
    let server = issuer();
    let path = fresh_path("resurrect");
    let mut app = ada_on(&server, &path);
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    app.create_group(G1).unwrap();
    seat(&mut app, &mut bo, G1);

    let m1 = bo.encrypt(G1, b"read in the notification").unwrap();
    let m2 = bo.encrypt(G1, b"read in the app").unwrap();
    {
        let mut extension = ada_on(&server, &path);
        assert!(
            opens(&extension.process_message(G1, &m1)),
            "the extension opens m1"
        );
    }

    assert!(opens(&app.process_message(G1, &m2)), "the app opens m2");
    let replay = app.process_message(G1, &m1);
    assert!(!opens(&replay), "the live app opened m1 again: {replay:?}");
    drop(app);

    let mut seized = ada_on(&server, &path);
    let replay = seized.process_message(G1, &m1);
    assert!(
        !opens(&replay),
        "m1's spent key came back to disk and m1 opens again: {replay:?}"
    );
}

/// A delivery service that re-sends a message the extension already opened,
/// under a fresh envelope, straight to the live app: the app's first write
/// door after the extension's write sees the key spent.
#[test]
fn the_live_app_refuses_a_replay_the_extension_already_opened() {
    let server = issuer();
    let path = fresh_path("live");
    let mut app = ada_on(&server, &path);
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    app.create_group(G1).unwrap();
    seat(&mut app, &mut bo, G1);

    let m1 = bo.encrypt(G1, b"once").unwrap();
    {
        let mut extension = ada_on(&server, &path);
        assert!(opens(&extension.process_message(G1, &m1)));
    }
    let replay = app.process_message(G1, &m1);
    assert!(
        !opens(&replay),
        "the app opened m1 a second time: {replay:?}"
    );
}

/// The app stages a commit, the extension opens m1 while it waits on the
/// server, and the app merges: the merge starts from the group as the
/// extension left it, so m1's key stays spent across the new epoch.
#[test]
fn a_merge_after_the_extension_wrote_keeps_its_spent_key_spent() {
    let server = issuer();
    let path = fresh_path("wait");
    let mut app = ada_on(&server, &path);
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    app.create_group(G1).unwrap();
    seat(&mut app, &mut bo, G1);

    let m1 = bo.encrypt(G1, b"read in the notification").unwrap();
    let rotation = app.self_update(G1).unwrap();
    {
        let mut extension = ada_on(&server, &path);
        assert!(opens(&extension.process_message(G1, &m1)));
        assert!(extension.has_saved_commit(G1).unwrap());
    }
    let epoch = app.merge_pending_commit(G1).unwrap();
    bo.process_commit(G1, &rotation.commit).unwrap();
    assert_eq!(bo.epoch(G1).unwrap(), epoch);
    assert!(
        !opens(&app.process_message(G1, &m1)),
        "the live app opened m1 again"
    );
    drop(app);

    let mut seized = ada_on(&server, &path);
    assert_eq!(seized.epoch(G1).unwrap(), epoch);
    let replay = seized.process_message(G1, &m1);
    assert!(
        !opens(&replay),
        "m1's spent key is back on disk: {replay:?}"
    );
}

/// The other direction: an extension client opened at epoch e and kept open
/// while the app merges e+1. When the extension then opens a late message
/// sealed at e, it reads it from the past epoch's retained secrets of the
/// group as the app left it, and the store stays at e+1: a client opened
/// afterwards reads the live epoch and is read by the group.
#[test]
fn a_long_lived_second_client_does_not_roll_the_group_back_an_epoch() {
    let server = issuer();
    let path = fresh_path("rollback");
    let mut app = ada_on(&server, &path);
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    app.create_group(G1).unwrap();
    seat(&mut app, &mut bo, G1);
    let before = app.epoch(G1).unwrap();

    let mut extension = ada_on(&server, &path);
    let late = bo.encrypt(G1, b"sent before the rotation").unwrap();

    let rotation = app.self_update(G1).unwrap();
    let after = app.merge_pending_commit(G1).unwrap();
    assert_eq!(after, before + 1);
    bo.process_commit(G1, &rotation.commit).unwrap();

    let read = extension.process_message(G1, &late);
    assert!(
        opens(&read),
        "the extension could not open the late message: {read:?}"
    );
    assert_eq!(
        extension.epoch(G1).unwrap(),
        after,
        "the extension did not reload"
    );
    drop(extension);

    // The live app goes on at the new epoch, both ways.
    let fresh = bo.encrypt(G1, b"after the rotation").unwrap();
    assert!(opens(&app.process_message(G1, &fresh)));
    let sent = app.encrypt(G1, b"still here").unwrap();
    assert!(opens(&bo.process_message(G1, &sent)));
    drop(app);

    let mut reopened = ada_on(&server, &path);
    assert_eq!(
        reopened.epoch(G1).unwrap(),
        after,
        "the stored group regressed"
    );
    let fresh = bo.encrypt(G1, b"and after the reopen").unwrap();
    let read = reopened.process_message(G1, &fresh);
    assert!(
        opens(&read),
        "the reopened client cannot read the live epoch: {read:?}"
    );
    let sent = reopened.encrypt(G1, b"hello?").unwrap();
    let read = bo.process_message(G1, &sent);
    assert!(
        opens(&read),
        "Bo cannot read what the reopened client sends: {read:?}"
    );
    let replay = reopened.process_message(G1, &late);
    assert!(
        !opens(&replay),
        "the late message's key came back: {replay:?}"
    );
}

/// A group the other process joined, after this client opened, is there at
/// this client's next write door, and one it forgot is gone.
#[test]
fn a_join_and_a_forget_by_the_other_process_reach_the_open_client() {
    let server = issuer();
    let path = fresh_path("membership");
    let mut app = ada_on(&server, &path);
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    bo.create_group(G1).unwrap();
    app.create_group(G2).unwrap();
    seat(&mut app, &mut bo, G2);

    let mut extension = ada_on(&server, &path);
    seat(&mut bo, &mut app, G1);
    let hello = bo.encrypt(G1, b"welcome in").unwrap();
    let read = extension.process_message(G1, &hello);
    assert!(
        opens(&read),
        "the extension does not see the app's join: {read:?}"
    );

    extension.forget_group(G2).unwrap();
    let there = bo.encrypt(G2, b"still there?").unwrap();
    assert!(
        matches!(
            app.process_message(G2, &there),
            Err(peachy_mls_core::Error::NoSuchGroup)
        ),
        "the app acted on a group the extension forgot"
    );
    assert!(!app.group_ids().contains(&G2.to_vec()));
}

/// The backend's half: `foreign_generation` moves when another connection
/// commits and not for this connection's own commits, and `begin_write`
/// holds the write lock until the flush.
#[test]
fn the_generation_moves_only_for_another_connections_commit() {
    let path = fresh_path("generation");
    let one = SqliteKv::open(&path).unwrap();
    let two = SqliteKv::open(&path).unwrap();
    let start = one.foreign_generation().unwrap();
    assert!(start.is_some());

    one.put(b"k", b"mine").unwrap();
    one.flush().unwrap();
    assert_eq!(
        one.foreign_generation().unwrap(),
        start,
        "its own commit moved it"
    );

    two.put(b"k", b"theirs").unwrap();
    two.flush().unwrap();
    let moved = one.foreign_generation().unwrap();
    assert_ne!(moved, start, "another connection's commit did not move it");

    one.begin_write().unwrap();
    assert!(
        !write_lock_free(&path),
        "begin_write did not take the write lock"
    );
    one.flush().unwrap();
    assert!(
        write_lock_free(&path),
        "the flush did not release the write lock"
    );
}

/// A fixed clock that panics while `armed` is set: stands in for any panic
/// inside a write door (OpenMLS, a dependency, an arithmetic bug).
#[derive(Debug)]
struct TrippableClock {
    armed: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl peachy_mls_core::Clock for TrippableClock {
    fn now_unix(&self) -> i64 {
        if self.armed.load(std::sync::atomic::Ordering::SeqCst) {
            panic!("injected panic inside a write door");
        }
        support::NOW
    }
}

fn ada_with_clock(
    server: &peachy_mls_core::issuer::TestIssuer,
    path: &Path,
    armed: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Client {
    let seed = support::device_seed(1);
    let (_, public) = peachy_mls_core::issuer::device_key_pair(&seed);
    let token = server
        .issue(
            "actor-ada",
            "device-ada",
            &public,
            support::NOW - support::HOUR,
            support::NOW + 30 * support::DAY,
        )
        .expect("mint");
    let mut config =
        peachy_mls_core::ClientConfig::new(token, seed, server.trusted_keys().expect("keys"))
            .with_storage(store(path))
            .with_own_account_identity(Some(support::held_identity("actor-ada")));
    config.clock = Some(Box::new(TrippableClock { armed }));
    Client::new(config).expect("client")
}

/// A door that panics part-way does not switch the shared-store check off.
///
/// The app's client panics once inside `process_message`, caught as the C
/// ABI's guard catches it, and is used again. The extension then opens m2 on
/// the same file and spends its key. The app's next write door must still
/// take the write lock and load the extension's copy, so m2's spent key never
/// comes back: a replay to the live app does not open, and neither does m2 on
/// a client rebuilt from the file.
#[test]
fn a_door_that_panicked_leaves_the_shared_store_check_on() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let server = issuer();
    let path = fresh_path("panic-sync");
    let armed = Arc::new(AtomicBool::new(false));
    let mut app = ada_with_clock(&server, &path, armed.clone());
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    app.create_group(G1).unwrap();
    seat(&mut app, &mut bo, G1);

    let m0 = bo.encrypt(G1, b"m0: the panicking read").unwrap();
    let m1 = bo.encrypt(G1, b"m1: the app reads it").unwrap();
    let m2 = bo.encrypt(G1, b"m2: the extension reads it").unwrap();
    let m3 = bo.encrypt(G1, b"m3: the app reads it later").unwrap();

    let quiet = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    armed.store(true, Ordering::SeqCst);
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        app.process_message(G1, &m0)
    }));
    armed.store(false, Ordering::SeqCst);
    std::panic::set_hook(quiet);
    assert!(caught.is_err(), "the injected panic did not fire");

    // What the panicked door wrote was rolled back, not left open: another
    // connection can take the write lock at once.
    assert!(
        write_lock_free(&path),
        "the panicked door left its transaction open"
    );

    // m0's door never finished, so its key is unspent: it opens now.
    assert!(
        opens(&app.process_message(G1, &m0)),
        "the app opens m0 on the retry"
    );
    assert!(opens(&app.process_message(G1, &m1)), "the app opens m1");
    {
        let mut extension = ada_on(&server, &path);
        assert!(
            opens(&extension.process_message(G1, &m2)),
            "extension opens m2"
        );
    }
    assert!(opens(&app.process_message(G1, &m3)), "the app opens m3");

    let live_replay = app.process_message(G1, &m2);
    assert!(
        !opens(&live_replay),
        "the live app opened m2 again after the extension spent it: {live_replay:?}"
    );
    drop(app);
    let mut rebuilt = ada_on(&server, &path);
    let disk_replay = rebuilt.process_message(G1, &m2);
    assert!(
        !opens(&disk_replay),
        "m2's spent key came back to disk: {disk_replay:?}"
    );
}

/// A call's keys follow a removal the other process applied. The extension
/// processes Bo's commit removing Cy while the app sits in a call; the app's
/// group in memory still holds Cy's leaf, so its keys would still serve
/// Cy's sender key until some write door reloaded it. Catching up with the
/// store first (as the C ABI's call-key and call-media doors now do) answers
/// from the epoch the store holds, without Cy.
#[test]
fn call_keys_read_after_catching_up_drop_a_leaf_the_extension_removed() {
    let server = issuer();
    let path = fresh_path("call-keys");
    let mut app = ada_on(&server, &path);
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    let mut cy = client(&server, 3, "actor-cy", "device-cy");
    app.create_group(G1).unwrap();
    seat(&mut app, &mut bo, G1);
    let package = cy.generate_key_package().unwrap();
    let add = app.add_member(G1, &package).unwrap();
    app.merge_pending_commit(G1).unwrap();
    bo.process_commit(G1, &add.commit).unwrap();
    cy.join_from_welcome(&add.welcome.unwrap()).unwrap();

    let call = b"call-0001-in-g1!";
    let before = app.call_keys(G1, call).unwrap();
    assert_eq!(before.senders.len(), 3);

    let removal = bo.remove_leaf(G1, 2).unwrap();
    bo.merge_pending_commit(G1).unwrap();
    {
        let mut extension = ada_on(&server, &path);
        extension.process_commit(G1, &removal.commit).unwrap();
    }

    let stale = app.call_keys(G1, call).unwrap();
    assert_eq!(stale.epoch, before.epoch, "the app had not caught up yet");

    app.catch_up_with_store().unwrap();
    let after = app.call_keys(G1, call).unwrap();
    let bos = bo.call_keys(G1, call).unwrap();
    assert_eq!(
        after.epoch,
        before.epoch + 1,
        "the keys are not at the store's epoch"
    );
    assert!(
        after.senders.iter().all(|sender| sender.leaf_index != 2),
        "the removed leaf still has a sender key"
    );
    assert_eq!(
        after.call_root, bos.call_root,
        "the app and Bo disagree on the call root"
    );
    assert!(
        write_lock_free(&path),
        "the catch-up left the write lock held"
    );
}

/// Whether a raw connection can take the write lock at once, with no wait.
fn write_lock_free(path: &Path) -> bool {
    let connection = rusqlite::Connection::open(path).expect("raw open");
    connection
        .busy_timeout(std::time::Duration::ZERO)
        .expect("timeout");
    match connection.execute_batch("BEGIN IMMEDIATE; ROLLBACK;") {
        Ok(()) => true,
        Err(err) => {
            let text = err.to_string();
            assert!(text.contains("locked") || text.contains("busy"), "{text}");
            false
        }
    }
}

/// A [`SqliteKv`] that, once armed, runs a hook right after it answers a
/// read of a record in namespace `on` (the `rejoin_report` record, say): the
/// other process acting between this client's read and its write.
struct HookedKv {
    inner: SqliteKv,
    on: &'static [u8],
    hook: Hook,
}

type Hook = Arc<Mutex<Option<Box<dyn FnOnce() + Send>>>>;

impl std::fmt::Debug for HookedKv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HookedKv")
    }
}

impl KvStore for HookedKv {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, KvError> {
        let value = self.inner.get(key)?;
        if key.starts_with(&storage_key(self.on, b"")) {
            let hook = self.hook.lock().unwrap().take();
            if let Some(hook) = hook {
                hook();
            }
        }
        Ok(value)
    }
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), KvError> {
        self.inner.put(key, value)
    }
    fn delete(&self, key: &[u8]) -> Result<(), KvError> {
        self.inner.delete(key)
    }
    fn scan(&self, prefix: &[u8]) -> Result<Vec<KvEntry>, KvError> {
        self.inner.scan(prefix)
    }
    fn flush(&self) -> Result<(), KvError> {
        self.inner.flush()
    }
    fn rollback(&self) -> Result<(), KvError> {
        self.inner.rollback()
    }
    fn erase_superseded(&self) -> Result<bool, KvError> {
        self.inner.erase_superseded()
    }
    fn begin_write(&self) -> Result<(), KvError> {
        self.inner.begin_write()
    }
    fn foreign_generation(&self) -> Result<Option<u64>, KvError> {
        self.inner.foreign_generation()
    }
}

fn bo_on(server: &peachy_mls_core::issuer::TestIssuer, storage: PeachyStorage) -> Client {
    client_on(server, 2, "actor-bo", "device-bo", storage)
}

/// Every report waiting for G1, oldest first.
fn take_reports(c: &mut Client) -> Vec<RejoinReport> {
    let mut reports = Vec::new();
    while let Some(report) = c.take_rejoin_report(G1).unwrap() {
        reports.push(report);
    }
    reports
}

/// A rejoin report the extension keeps while the app is taking an earlier
/// one is not written over. Bo's app holds a report of Ada re-seating it;
/// while it takes that one, the extension, on the same file, joins Mal's
/// group under the id at a head a server names, which leaves a second
/// report (Mal added, Ada and Cy gone). The take holds the store's write
/// lock, so the extension's join waits and is refused with the Welcome
/// unspent; its retry after the take lands, and both reports are drawn.
#[test]
fn a_report_the_extension_keeps_during_the_apps_take_is_drawn() {
    let server = issuer();
    let path = fresh_path("rejoin-report-take");
    let hook: Hook = Arc::new(Mutex::new(None));
    let app_kv = HookedKv {
        inner: SqliteKv::open(&path).unwrap(),
        on: b"rejoin_report",
        hook: hook.clone(),
    };
    let mut app = bo_on(&server, PeachyStorage::open(Box::new(app_kv)).unwrap());

    // Ada founds G1 with Bo and Cy, every copy confirmed at the head.
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut cy = client(&server, 3, "actor-cy", "device-cy");
    let mut mal = client(&server, 4, "actor-mal", "device-mal");
    ada.create_group(G1).unwrap();
    let add_bo = ada
        .add_member(G1, &app.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G1).unwrap();
    let h = head_of(&ada, G1);
    app.join_from_welcome_at_head(&add_bo.welcome.unwrap(), h.0, &h.1)
        .unwrap();
    let add_cy = ada
        .add_member(G1, &cy.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G1).unwrap();
    app.process_commit(G1, &add_cy.commit).unwrap();
    let h = head_of(&ada, G1);
    cy.join_from_welcome_at_head(&add_cy.welcome.unwrap(), h.0, &h.1)
        .unwrap();
    assert!(app.confirm_head(G1, h.0, &h.1).unwrap());

    // Bo falls off and forgets; Ada re-seats it at the head: report one.
    app.forget_group(G1).unwrap();
    let bo_leaf = ada.leaf_of_device(G1, "device-bo").unwrap();
    let reseat = ada
        .replace_member(G1, bo_leaf, &app.generate_key_package().unwrap())
        .unwrap();
    ada.merge_pending_commit(G1).unwrap();
    let h = head_of(&ada, G1);
    app.join_from_welcome_at_head(&reseat.welcome.unwrap(), h.0, &h.1)
        .unwrap();

    // Mal's own group under G1, past Bo's epoch, Welcoming Bo.
    mal.create_group(G1).unwrap();
    past_the_mark(&mut mal, G1);
    let add = mal
        .add_member(G1, &app.generate_key_package().unwrap())
        .unwrap();
    mal.merge_pending_commit(G1).unwrap();
    let mal_welcome = add.welcome.unwrap();
    let mal_head = head_of(&mal, G1);

    // The extension tries to join while the app is inside its take.
    let mut extension = bo_on(&server, store(&path));
    let during: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    {
        let during = during.clone();
        let welcome = mal_welcome.clone();
        *hook.lock().unwrap() = Some(Box::new(move || {
            let outcome = extension.join_from_welcome_at_head(&welcome, mal_head.0, &mal_head.1);
            *during.lock().unwrap() = Some(format!("{outcome:?}"));
        }));
    }
    let first = app.take_rejoin_report(G1).unwrap().expect("Ada's report");
    assert_eq!(first.readded_by, "actor-ada");
    let during = during.lock().unwrap().clone().expect("the hook ran");
    assert!(
        during.contains("locked") || during.contains("busy"),
        "the extension's join was not held off by the take: {during}"
    );

    // The Welcome is still waiting in the mailbox; the extension's next
    // try lands.
    let mut extension = bo_on(&server, store(&path));
    extension
        .join_from_welcome_at_head(&mal_welcome, mal_head.0, &mal_head.1)
        .expect("the retry joins");

    let left = take_reports(&mut app);
    assert_eq!(left.len(), 1, "{left:?}");
    assert_eq!(left[0].readded_by, "actor-mal");
    assert_eq!(left[0].added_actors, vec!["actor-mal".to_owned()]);
    assert_eq!(
        left[0].departed_actors,
        vec!["actor-ada".to_owned(), "actor-cy".to_owned()]
    );
}

/// The open's repair is one step against the store. Bo's extension holds a
/// copy of G1 with no head record (held before the record was kept), which
/// the app's open repairs as a lapsed copy. The extension forgets G1 just
/// after the app's open has read that record: the app takes the write lock,
/// sees the store moved, and reads again, so it writes no head record for a
/// group nobody holds, and holds no G1 itself.
#[test]
fn the_open_repair_reads_again_after_the_extension_forgets_a_group() {
    let server = issuer();
    let path = fresh_path("open-repair");
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    let mut extension = bo_on(&server, store(&path));
    ada.create_group(G1).unwrap();
    seat(&mut ada, &mut extension, G1);

    // The copy's head record goes, as a build before the record left it.
    let head_records = storage_key(b"head_confirmed", b"");
    {
        let raw = SqliteKv::open(&path).unwrap();
        for (key, _) in raw.scan(&head_records).unwrap() {
            raw.delete(&key).unwrap();
        }
        raw.flush().unwrap();
    }

    let hook: Hook = Arc::new(Mutex::new(Some(Box::new(move || {
        extension.forget_group(G1).unwrap();
    }))));
    let app_kv = HookedKv {
        inner: SqliteKv::open(&path).unwrap(),
        on: b"head_confirmed",
        hook: hook.clone(),
    };
    let app = bo_on(&server, PeachyStorage::open(Box::new(app_kv)).unwrap());
    assert!(hook.lock().unwrap().is_none(), "the hook never ran");

    assert!(
        !app.group_ids().contains(&G1.to_vec()),
        "the app holds a group the extension forgot"
    );
    let raw = SqliteKv::open(&path).unwrap();
    assert!(
        raw.scan(&head_records).unwrap().is_empty(),
        "the open wrote a head record for a group nobody holds"
    );
}

/// Ada, Bo and Cy in G1, with Ada's app on `path`. Bo's tablet signs a seat
/// ask and the app judges it while Bo still holds a leaf; then Cy removes Bo
/// and Ada's extension applies it, as can happen while the app awaits the
/// tablet's package. Returns the app, not caught up, and the tablet's package.
fn an_ask_judged_before_the_extension_removed_its_person(path: &Path) -> (Client, Vec<u8>) {
    let server = issuer();
    let mut app = ada_on(&server, path);
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    let mut cy = client(&server, 3, "actor-cy", "device-cy");
    let tablet = client(&server, 4, "actor-bo", "device-bo-tablet");
    app.create_group(G1).unwrap();
    seat(&mut app, &mut bo, G1);
    let package = cy.generate_key_package().unwrap();
    let add = app.add_member(G1, &package).unwrap();
    app.merge_pending_commit(G1).unwrap();
    bo.process_commit(G1, &add.commit).unwrap();
    cy.join_from_welcome(&add.welcome.unwrap()).unwrap();

    let proof = tablet.sign_join_request(G1).unwrap();
    let tablet_package = tablet.generate_key_package().unwrap();
    assert!(
        app.verify_join_request(
            G1,
            "actor-bo",
            "device-bo-tablet",
            &proof,
            &tablet_package,
            &[]
        )
        .is_accepted(),
        "the ask holds while Bo is seated"
    );

    let bo_leaf = cy.leaf_of_device(G1, "device-bo").unwrap();
    let removal = cy.remove_leaf(G1, bo_leaf).unwrap();
    cy.merge_pending_commit(G1).unwrap();
    {
        let mut extension = ada_on(&server, path);
        extension.process_commit(G1, &removal.commit).unwrap();
    }
    (app, tablet_package)
}

/// The ask's add judges membership again on the store it commits on: the
/// person the extension just removed is not put back by the verdict the app
/// read before, not even when the app names them as still being invited
/// (this device saw their last leaf leave).
#[test]
fn an_asks_add_refuses_a_person_the_extension_removed_meanwhile() {
    let path = fresh_path("ask-after-removal");
    let (mut app, tablet_package) = an_ask_judged_before_the_extension_removed_its_person(&path);

    let refused = app.add_member_for_ask(G1, &tablet_package, &[]);
    assert!(
        refused.is_err(),
        "the ask's add put back a person the extension removed"
    );
    let refused = app.add_member_for_ask(G1, &tablet_package, &["actor-bo"]);
    assert!(
        refused.is_err(),
        "a pending list put back a person this device saw leave"
    );
    assert!(
        app.leaf_of_device(G1, "device-bo-tablet").is_err()
            && app.leaf_of_device(G1, "device-bo").is_err(),
        "Bo holds a leaf"
    );
    assert!(
        write_lock_free(&path),
        "the refusal left the write lock held"
    );
}

/// Control: with nobody removed, the ask's add seats the tablet, and refuses
/// a person who is no member and whom nobody is inviting.
#[test]
fn control_an_asks_add_seats_a_member_with_no_removal() {
    let server = issuer();
    let path = fresh_path("ask-control");
    let mut app = ada_on(&server, &path);
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    let tablet = client(&server, 4, "actor-bo", "device-bo-tablet");
    let stranger = client(&server, 5, "actor-di", "device-di");
    app.create_group(G1).unwrap();
    seat(&mut app, &mut bo, G1);

    let outsider = stranger.generate_key_package().unwrap();
    assert!(
        app.add_member_for_ask(G1, &outsider, &[]).is_err(),
        "the ask's add seated somebody who is no member"
    );
    let package = tablet.generate_key_package().unwrap();
    let bundle = app.add_member_for_ask(G1, &package, &[]).unwrap();
    assert!(bundle.welcome.is_some(), "the ask's add staged no Welcome");
    app.merge_pending_commit(G1).unwrap();
    assert!(app.leaf_of_device(G1, "device-bo-tablet").is_ok());
}
