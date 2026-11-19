// SPDX-License-Identifier: MIT
//! A store step that fails part-way through an operation leaves nothing of
//! that operation behind (`mls/core/src/storage.rs` §A step that fails
//! part-way).
//!
//! OpenMLS writes one operation as many rows. A full disk or an I/O error can
//! refuse any one of them, after the ones before it went into the transaction.
//! Committing that transaction left a group whose tree had advanced and whose
//! secrets had not: it could neither read the new epoch nor apply the commit
//! again, and the documented "hold and try again" never repaired it.
//!
//! The first tests here arm a store that fails at the k-th write, for EVERY k
//! an operation reaches, and assert that afterwards the group is still
//! readable and the retry succeeds, both on the same client and on a client
//! reopened from the file. The rest hold the smaller doors to the same rule:
//! a verdict whose record was refused is no verdict, a value that does not
//! decode fails its operation, and no door returns with writes left open.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;

use peachy_mls_core::issuer::TestIssuer;
use peachy_mls_core::{
    Client, ClientConfig, Incoming, KvEntry, KvError, KvStore, PeachyStorage, SqliteKv,
};
use support::{client, device_seed, issuer, DAY, HOUR, NOW};

const G: &[u8] = b"77777777-7777-4777-8777-77777777c0de";

/// A SQLite store whose puts and deletes fail once `budget` writes have gone
/// through (budget < 0: never). Stands in for a full disk or an I/O error
/// part-way through an operation.
#[derive(Debug)]
struct FaultyKv {
    inner: SqliteKv,
    budget: Arc<AtomicI64>,
}

impl FaultyKv {
    fn spend(&self) -> Result<(), KvError> {
        let left = self.budget.load(Ordering::SeqCst);
        if left < 0 {
            return Ok(());
        }
        if left == 0 {
            return Err(KvError::new("injected: disk full"));
        }
        self.budget.store(left - 1, Ordering::SeqCst);
        Ok(())
    }
}

impl KvStore for FaultyKv {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, KvError> {
        self.inner.get(key)
    }
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), KvError> {
        self.spend()?;
        self.inner.put(key, value)
    }
    fn delete(&self, key: &[u8]) -> Result<(), KvError> {
        self.spend()?;
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

fn fresh_path(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "peachy-store-fault-{}-{name}.sqlite",
        std::process::id()
    ));
    remove_db(&path);
    path
}

fn remove_db(path: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}

fn copy_db(from: &Path, to: &Path) {
    remove_db(to);
    for suffix in ["", "-wal", "-shm"] {
        let src = format!("{}{suffix}", from.display());
        if Path::new(&src).exists() {
            std::fs::copy(&src, format!("{}{suffix}", to.display())).unwrap();
        }
    }
}

#[derive(Debug)]
struct Fixed;

impl peachy_mls_core::Clock for Fixed {
    fn now_unix(&self) -> i64 {
        NOW
    }
}

fn ada(server: &TestIssuer, path: &Path, budget: Arc<AtomicI64>) -> Client {
    let seed = device_seed(1);
    let (_, public) = peachy_mls_core::issuer::device_key_pair(&seed);
    let token = server
        .issue(
            "actor-ada",
            "device-ada",
            &public,
            NOW - HOUR,
            NOW + 30 * DAY,
        )
        .expect("mint");
    let kv = FaultyKv {
        inner: SqliteKv::open(path).expect("open"),
        budget,
    };
    let mut config = ClientConfig::new(token, seed, server.trusted_keys().expect("keys"))
        .with_storage(PeachyStorage::open(Box::new(kv)).expect("storage"))
        .with_own_account_identity(Some(support::held_identity("actor-ada")));
    config.clock = Some(Box::new(Fixed));
    Client::new(config).expect("client")
}

fn opens(result: &peachy_mls_core::Result<Incoming>) -> bool {
    matches!(result, Ok(Incoming::Application { .. }))
}

/// Ada and Bo share a group, written to `base`. Ada's copy is at the epoch
/// before Bo's self-update.
struct World {
    server: TestIssuer,
    base: PathBuf,
    epoch_before: u64,
    commit: Vec<u8>,
    after: Vec<u8>,
}

fn world(name: &str) -> World {
    let server = issuer();
    let base = fresh_path(&format!("{name}-base"));
    let mut bo = client(&server, 2, "actor-bo", "device-bo");
    let epoch_before;
    {
        let mut a = ada(&server, &base, Arc::new(AtomicI64::new(-1)));
        a.create_group(G).unwrap();
        let package = bo.generate_key_package().unwrap();
        let bundle = a.add_member(G, &package).unwrap();
        a.merge_pending_commit(G).unwrap();
        bo.join_from_welcome(&bundle.welcome.unwrap()).unwrap();
        epoch_before = a.epoch(G).unwrap();
    }
    let commit = bo.self_update(G).unwrap().commit;
    bo.merge_pending_commit(G).unwrap();
    let after = bo.encrypt(G, b"after the commit").unwrap();
    World {
        server,
        base,
        epoch_before,
        commit,
        after,
    }
}

/// Every write position in `process_commit`: the commit fails there, and
/// then the group is exactly where it was (epoch e), the retry applies the
/// commit, and the new epoch's message opens. Checked twice per position:
/// on the live client that saw the failure (which must have rolled back its
/// own memory too), and on a client reopened from the file (which must hold
/// no part of the failed commit).
#[test]
fn a_commit_cut_short_at_any_write_leaves_the_group_whole_and_retryable() {
    let w = world("commit");
    let mut positions = 0;
    let mut broken = Vec::new();
    for k in 0..200i64 {
        let path = fresh_path(&format!("commit-k{k}"));
        copy_db(&w.base, &path);
        let budget = Arc::new(AtomicI64::new(-1));
        let mut live = ada(&w.server, &path, budget.clone());
        budget.store(k, Ordering::SeqCst);
        let outcome = live.process_commit(G, &w.commit);
        budget.store(-1, Ordering::SeqCst);
        if outcome.is_ok() {
            // No fault reached: k is past the last write. Done.
            assert!(positions > 0, "the fault never fired");
            drop(live);
            remove_db(&path);
            break;
        }
        positions += 1;

        // The live client: back at epoch e in memory, and the retry works.
        let live_epoch = live.epoch(G).ok();
        let live_retry = live.process_commit(G, &w.commit).is_ok();
        let live_reads = opens(&live.process_message(G, &w.after));
        drop(live);

        // A client reopened from a copy of the file taken right after the
        // failure would be the same check; reopening the file after the live
        // client's retry would see the retry. So check the file as the
        // failure left it, from a second copy made before the retry.
        let path_after = fresh_path(&format!("commit-k{k}-file"));
        copy_db(&w.base, &path_after);
        {
            let budget = Arc::new(AtomicI64::new(-1));
            let mut cut = ada(&w.server, &path_after, budget.clone());
            budget.store(k, Ordering::SeqCst);
            assert!(
                cut.process_commit(G, &w.commit).is_err(),
                "k={k}: same fault"
            );
            budget.store(-1, Ordering::SeqCst);
        }
        let mut reopened = ada(&w.server, &path_after, Arc::new(AtomicI64::new(-1)));
        let file_epoch = reopened.epoch(G).ok();
        let file_retry = reopened.process_commit(G, &w.commit).is_ok();
        let file_reads = opens(&reopened.process_message(G, &w.after));
        drop(reopened);
        remove_db(&path);
        remove_db(&path_after);

        println!(
            "k={k}: live epoch {live_epoch:?} retry {live_retry} reads {live_reads} | \
             file epoch {file_epoch:?} retry {file_retry} reads {file_reads}"
        );
        let whole = live_epoch == Some(w.epoch_before)
            && live_retry
            && live_reads
            && file_epoch == Some(w.epoch_before)
            && file_retry
            && file_reads;
        if !whole {
            broken.push(k);
        }
    }
    remove_db(&w.base);
    println!("write positions in the commit: {positions}");
    assert!(
        positions >= 10,
        "the sweep reached only {positions} write positions; the probe found 14"
    );
    assert!(
        broken.is_empty(),
        "a commit cut short left the group unusable at write positions {broken:?}"
    );
}

/// The same for an application message: a fault at any write of
/// `process_message` leaves the message unopened and its key unspent, so the
/// retry opens it, on the live client and from the file.
#[test]
fn a_message_cut_short_at_any_write_opens_on_the_retry() {
    let w = world("message");
    // Ada at the new epoch, with the message not yet read.
    {
        let mut a = ada(&w.server, &w.base, Arc::new(AtomicI64::new(-1)));
        a.process_commit(G, &w.commit).unwrap();
    }
    let mut positions = 0;
    let mut broken = Vec::new();
    for k in 0..100i64 {
        let path = fresh_path(&format!("message-k{k}"));
        copy_db(&w.base, &path);
        let budget = Arc::new(AtomicI64::new(-1));
        let mut live = ada(&w.server, &path, budget.clone());
        budget.store(k, Ordering::SeqCst);
        let outcome = live.process_message(G, &w.after);
        budget.store(-1, Ordering::SeqCst);
        if opens(&outcome) {
            assert!(positions > 0, "the fault never fired");
            drop(live);
            remove_db(&path);
            break;
        }
        positions += 1;
        let live_reads = opens(&live.process_message(G, &w.after));
        drop(live);
        let mut reopened = ada(&w.server, &path, Arc::new(AtomicI64::new(-1)));
        // The live retry spent the key on disk: a replay must not open.
        let replay_refused = !opens(&reopened.process_message(G, &w.after));
        drop(reopened);
        remove_db(&path);
        println!(
            "k={k}: live retry reads {live_reads}, replay from the file refused {replay_refused}"
        );
        if !(live_reads && replay_refused) {
            broken.push(k);
        }
    }
    remove_db(&w.base);
    assert!(positions >= 1, "the sweep reached no write position");
    assert!(
        broken.is_empty(),
        "a message cut short was lost or replayable at write positions {broken:?}"
    );
}

/// An in-memory store that refuses puts and deletes while `fail` is set,
/// counts `begin_write` (the write lock a door takes), and counts writes not
/// yet committed or rolled back (`open`) and every write (`written`).
#[derive(Debug, Clone)]
struct SwitchKv {
    inner: peachy_mls_core::MemoryKv,
    fail: Arc<AtomicBool>,
    locks: Arc<AtomicU64>,
    open: Arc<AtomicU64>,
    written: Arc<AtomicU64>,
}

impl SwitchKv {
    fn new() -> Self {
        Self {
            inner: peachy_mls_core::MemoryKv::new(),
            fail: Arc::new(AtomicBool::new(false)),
            locks: Arc::new(AtomicU64::new(0)),
            open: Arc::new(AtomicU64::new(0)),
            written: Arc::new(AtomicU64::new(0)),
        }
    }

    fn write(&self) -> Result<(), KvError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(KvError::new("injected: database is locked"));
        }
        self.open.fetch_add(1, Ordering::SeqCst);
        self.written.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

impl KvStore for SwitchKv {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, KvError> {
        self.inner.get(key)
    }
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), KvError> {
        self.write()?;
        self.inner.put(key, value)
    }
    fn delete(&self, key: &[u8]) -> Result<(), KvError> {
        self.write()?;
        self.inner.delete(key)
    }
    fn scan(&self, prefix: &[u8]) -> Result<Vec<KvEntry>, KvError> {
        self.inner.scan(prefix)
    }
    fn flush(&self) -> Result<(), KvError> {
        self.open.store(0, Ordering::SeqCst);
        self.inner.flush()
    }
    fn rollback(&self) -> Result<(), KvError> {
        self.open.store(0, Ordering::SeqCst);
        self.inner.rollback()
    }
    fn begin_write(&self) -> Result<(), KvError> {
        self.locks.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn public(tag: u8) -> [u8; 32] {
    peachy_mls_core::issuer::device_key_pair(&device_seed(tag)).1
}

fn on_account(
    server: &TestIssuer,
    tag: u8,
    device: &str,
    account: &[u8],
    clock: i64,
    storage: PeachyStorage,
) -> Client {
    let seed = device_seed(tag);
    let token = server
        .issue_for_account(
            "actor-ada",
            device,
            &public(tag),
            Some(account),
            NOW - HOUR,
            NOW + 30 * DAY,
        )
        .expect("mint");
    let mut config = ClientConfig::new(token, seed, server.trusted_keys().expect("keys"))
        .with_storage(storage)
        .with_own_account_identity(Some(
            peachy_mls_core::account_identity_public_key(account).expect("derive"),
        ));
    config.clock = Some(Box::new(peachy_mls_core::FixedClock(clock)));
    Client::new(config).expect("client")
}

/// The approval verdict writes its chain record under the write lock, and a
/// record the store refused is no verdict: the door answers one that seats
/// nobody, leaves no failed step behind it, and the same check answers
/// `Approved` once the store takes writes again, with the device on the
/// chain so its own approvals vouch in turn.
#[test]
fn an_approval_whose_chain_record_was_refused_seats_nobody() {
    use peachy_mls_core::{generate_account_key, sign_device_approval, OwnDeviceVerdict};
    let server = issuer();
    let account = generate_account_key().unwrap();
    let kv = SwitchKv::new();
    let mut laptop = on_account(
        &server,
        1,
        "device-ada-laptop",
        &account,
        NOW,
        PeachyStorage::open(Box::new(kv.clone())).unwrap(),
    );
    laptop
        .remember_own_approver("device-ada-phone", &public(2))
        .unwrap();
    let new = on_account(
        &server,
        3,
        "device-ada-new",
        &account,
        NOW,
        PeachyStorage::in_memory(),
    );
    let package = new.generate_key_package().unwrap();
    let approval = sign_device_approval(&device_seed(2), "device-ada-new", &public(3)).unwrap();

    let locks = kv.locks.load(Ordering::SeqCst);
    kv.fail.store(true, Ordering::SeqCst);
    let verdict = laptop.check_own_device_approval(&package, "device-ada-phone", &approval);
    kv.fail.store(false, Ordering::SeqCst);
    assert_eq!(
        verdict,
        OwnDeviceVerdict::Unanchored,
        "a verdict that seats"
    );
    assert!(
        kv.locks.load(Ordering::SeqCst) > locks,
        "the verdict door wrote without the write lock"
    );
    assert_eq!(
        kv.open.load(Ordering::SeqCst),
        0,
        "the door left writes open"
    );
    assert!(!laptop
        .own_device_anchors()
        .unwrap()
        .iter()
        .any(|(id, _)| id == "device-ada-new"));

    // Nothing of the failed step is carried into the next door.
    assert_eq!(
        laptop.check_own_device_approval(&package, "device-ada-phone", &approval),
        OwnDeviceVerdict::Approved
    );
    assert!(laptop
        .own_device_anchors()
        .unwrap()
        .iter()
        .any(|(id, key)| id == "device-ada-new" && key.as_slice() == public(3).as_slice()));
    let child = sign_device_approval(&device_seed(3), "device-ada-child", &public(4)).unwrap();
    assert_eq!(
        laptop.check_own_device_key("device-ada-child", &public(4), "device-ada-new", &child),
        OwnDeviceVerdict::Approved
    );
}

/// A stored value that does not decode is a failed step like a refused
/// write (`mls/core/src/storage.rs` §A step that fails part-way): the writes
/// after it in the same operation are refused, its flush rolls back, and the
/// next operation starts clean.
#[test]
fn a_value_that_does_not_decode_fails_its_operation() {
    use openmls::group::MlsGroupState;
    use openmls::prelude::GroupId;
    use openmls_traits::storage::{StorageProvider, CURRENT_VERSION};
    let kv = peachy_mls_core::MemoryKv::new();
    let storage = PeachyStorage::open(Box::new(kv.clone())).unwrap();
    let gid = GroupId::from_slice(b"group-with-a-bad-value");
    let key = peachy_mls_core::storage_key(b"group_state", &serde_json::to_vec(&gid).unwrap());
    kv.put(&key, b"{ this is not json").unwrap();
    kv.flush().unwrap();

    let read = <PeachyStorage as StorageProvider<CURRENT_VERSION>>::group_state::<
        MlsGroupState,
        GroupId,
    >(&storage, &gid);
    assert!(read.is_err(), "the value does not decode");
    assert!(
        storage
            .set_welcome_sender(b"group-with-a-bad-value", "actor-mallory")
            .is_err(),
        "a write after the failed step went into the transaction"
    );
    assert!(storage.flush().is_err(), "the flush committed");
    assert_eq!(
        storage.welcome_sender(b"group-with-a-bad-value").unwrap(),
        None
    );

    storage
        .set_welcome_sender(b"group-with-a-bad-value", "actor-ada")
        .unwrap();
    storage.flush().unwrap();
    assert_eq!(
        storage.welcome_sender(b"group-with-a-bad-value").unwrap(),
        Some("actor-ada".to_string())
    );
}

/// Asking whether a seat ask was already taken in prunes the records that
/// aged out on the way, and closes that step before it returns: nothing is
/// left open on the store for a later flush or rollback to decide.
#[test]
fn asking_after_a_seat_ask_leaves_nothing_open() {
    let server = issuer();
    let account = peachy_mls_core::generate_account_key().unwrap();
    let kv = SwitchKv::new();
    let asker = client(&server, 2, "actor-bo", "device-bo");
    let group = b"a-group-with-a-join-inbox";
    let old = asker.sign_join_request(group).unwrap();
    {
        let mut ada = on_account(
            &server,
            1,
            "device-ada",
            &account,
            NOW,
            PeachyStorage::open(Box::new(kv.clone())).unwrap(),
        );
        assert!(ada.first_sight_of_join_request(group, &old).unwrap());
        assert_eq!(kv.open.load(Ordering::SeqCst), 0);
    }
    // Two days on, the record has aged out; this pass prunes it.
    let mut ada = on_account(
        &server,
        1,
        "device-ada",
        &account,
        NOW + 2 * DAY,
        PeachyStorage::open(Box::new(kv.clone())).unwrap(),
    );
    let locks = kv.locks.load(Ordering::SeqCst);
    let written = kv.written.load(Ordering::SeqCst);
    assert!(!ada.join_request_seen(group, &old).unwrap());
    assert!(
        kv.written.load(Ordering::SeqCst) > written,
        "nothing was pruned"
    );
    assert!(
        kv.locks.load(Ordering::SeqCst) > locks,
        "pruned without the write lock"
    );
    assert_eq!(kv.open.load(Ordering::SeqCst), 0, "the prune was left open");
}
