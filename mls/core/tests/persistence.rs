// SPDX-License-Identifier: MIT
//! State that survives the process.
//!
//! The point of `mls/core/src/storage.rs`, asserted rather than described. The
//! shape of every test here is the same and it is deliberately blunt: build a
//! client on a store, do something, **drop the client entirely**, build a
//! second client on the same store, and carry on as if nothing happened.
//!
//! Dropping is what makes the test mean anything. `Client` owns its provider,
//! which owns the storage, which owns the connection — so after the drop there
//! is nothing left in this process that could be answering, and a passing
//! assertion is an assertion about bytes on disk.
//!
//! The four things that have to come back: groups, key packages, epochs and
//! signature keys.

mod support;

use std::path::PathBuf;

use peachy_mls_core::{Incoming, MemoryKv, PeachyStorage, SqliteKv};
use support::{client, client_on, issuer};

const GROUP: &[u8] = b"peachy-group-persist";

/// A directory this test file owns, named after the test using it so that two
/// running at once cannot collide.
fn scratch(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("peachy-mls-persist-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

fn sqlite_storage(path: &PathBuf) -> PeachyStorage {
    PeachyStorage::open(Box::new(SqliteKv::open(path).expect("open the store")))
        .expect("open the MLS store")
}

/// The headline: a group created by one process is usable by the next.
///
/// Ada creates a group and adds Bo. Ada's process then ends — client dropped,
/// SQLite connection closed — and a fresh Ada opens the same file, encrypts to
/// the group and reads Bo's reply. Bo never restarted and never learns that Ada
/// did, which is the property: persistence is a local concern and nothing about
/// it reaches the wire.
#[test]
fn a_group_survives_a_process_restart_and_can_still_send_and_receive() {
    let dir = scratch("restart");
    let path = dir.join("ada.sqlite3");
    let server = issuer();
    let mut bo = client(&server, 2, "actor-bo", "device-bo-phone");

    let bo_kp = bo.generate_key_package().expect("bo key package");
    let epoch_before;
    {
        let mut ada = client_on(
            &server,
            1,
            "actor-ada",
            "device-ada-phone",
            sqlite_storage(&path),
        );
        ada.create_group(GROUP).expect("create");
        let add = ada.add_member(GROUP, &bo_kp).expect("add bo");
        ada.merge_pending_commit(GROUP).expect("merge the add");
        bo.join_from_welcome(&add.welcome.clone().expect("welcome"))
            .expect("bo joins");
        epoch_before = ada.epoch(GROUP).expect("epoch");
        // And Ada's process ends here.
    }

    let mut ada = client_on(
        &server,
        1,
        "actor-ada",
        "device-ada-phone",
        sqlite_storage(&path),
    );

    assert_eq!(
        ada.group_ids(),
        vec![GROUP.to_vec()],
        "the reopened client should hold the group it created"
    );
    assert_eq!(
        ada.epoch(GROUP).expect("epoch"),
        epoch_before,
        "and be at the epoch it left off at"
    );
    assert_eq!(
        ada.roster(GROUP).expect("roster").len(),
        2,
        "with both members still in the tree"
    );

    // The real check: the epoch secrets came back, not just the tree.
    let ciphertext = ada
        .encrypt(GROUP, b"back from the dead")
        .expect("the reopened client should still encrypt");
    match bo.process_message(GROUP, &ciphertext).expect("bo reads it") {
        Incoming::Application {
            sender, plaintext, ..
        } => {
            assert_eq!(plaintext, b"back from the dead");
            assert_eq!(sender.device_id, "device-ada-phone");
        }
        other => panic!("expected an application message, got {other:?}"),
    }

    // And the other direction, which needs the RECEIVER ratchets back.
    let reply = bo.encrypt(GROUP, b"welcome back").expect("bo encrypts");
    match ada.process_message(GROUP, &reply).expect("ada reads it") {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"welcome back"),
        other => panic!("expected an application message, got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// A key package published before a restart is still openable after one.
///
/// This is the case a group cannot recover from by re-fetching: the private
/// init and encryption halves of a published key package live only in the
/// publisher's own store, so if they do not survive, every Welcome minted
/// against that key package is undecryptable forever — and the publisher has no
/// way to know until somebody tries to add them.
#[test]
fn a_key_package_published_before_a_restart_still_opens_its_welcome() {
    let dir = scratch("keypackage");
    let path = dir.join("bo.sqlite3");
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada-phone");
    ada.create_group(GROUP).expect("create");

    let bo_kp = {
        let bo = client_on(
            &server,
            2,
            "actor-bo",
            "device-bo-phone",
            sqlite_storage(&path),
        );
        bo.generate_key_package().expect("bo key package")
    };

    let add = ada.add_member(GROUP, &bo_kp).expect("add bo");
    ada.merge_pending_commit(GROUP).expect("merge the add");

    let mut bo = client_on(
        &server,
        2,
        "actor-bo",
        "device-bo-phone",
        sqlite_storage(&path),
    );
    let joined = bo
        .join_from_welcome(&add.welcome.clone().expect("welcome"))
        .expect("a key package minted before the restart should still open its Welcome");
    assert_eq!(joined, GROUP.to_vec());

    let ciphertext = ada.encrypt(GROUP, b"hello Bo").expect("encrypt");
    match bo.process_message(GROUP, &ciphertext).expect("bo reads it") {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"hello Bo"),
        other => panic!("expected an application message, got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// Forgetting a group takes it off disk, not just out of the open map.
///
/// `forget_group` is half of the rejoin (`mls/core/tests/rejoin.rs`), and a
/// half-forgotten group would be the worst outcome: invisible to the caller and
/// still occupying the id a fresh Welcome is about to want.
#[test]
fn a_forgotten_group_does_not_come_back_on_reopen() {
    let dir = scratch("forget");
    let path = dir.join("ada.sqlite3");
    let server = issuer();
    {
        let mut ada = client_on(
            &server,
            1,
            "actor-ada",
            "device-ada-phone",
            sqlite_storage(&path),
        );
        ada.create_group(GROUP).expect("create");
        ada.create_group(b"other").expect("create the second");
        ada.forget_group(GROUP).expect("forget");
    }
    let ada = client_on(
        &server,
        1,
        "actor-ada",
        "device-ada-phone",
        sqlite_storage(&path),
    );
    assert_eq!(
        ada.group_ids(),
        vec![b"other".to_vec()],
        "only the group that was not forgotten should come back"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The same journey over the in-memory KV, which is what the wasm binding's
/// backend behaves like once IndexedDB has been read into it.
///
/// Worth its own test rather than being folded into the SQLite one: it is the
/// only place the store is provably the SAME store — a cloned `MemoryKv` is one
/// map behind two handles — so a pass here is about `PeachyStorage` and the
/// group index, with nothing that could be SQLite doing the work.
#[test]
fn a_shared_in_memory_store_reopens_the_same_groups() {
    let server = issuer();
    let kv = MemoryKv::new();
    let mut bo = client(&server, 2, "actor-bo", "device-bo-phone");
    let bo_kp = bo.generate_key_package().expect("bo key package");

    {
        let mut ada = client_on(
            &server,
            1,
            "actor-ada",
            "device-ada-phone",
            PeachyStorage::open(Box::new(kv.clone())).expect("open"),
        );
        ada.create_group(GROUP).expect("create");
        let add = ada.add_member(GROUP, &bo_kp).expect("add bo");
        ada.merge_pending_commit(GROUP).expect("merge the add");
        bo.join_from_welcome(&add.welcome.clone().expect("welcome"))
            .expect("bo joins");
    }
    assert!(!kv.is_empty(), "the store should hold the group's rows");

    let mut ada = client_on(
        &server,
        1,
        "actor-ada",
        "device-ada-phone",
        PeachyStorage::open(Box::new(kv)).expect("reopen"),
    );
    assert_eq!(ada.group_ids(), vec![GROUP.to_vec()]);
    let ciphertext = ada.encrypt(GROUP, b"still here").expect("encrypt");
    match bo.process_message(GROUP, &ciphertext).expect("bo reads it") {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"still here"),
        other => panic!("expected an application message, got {other:?}"),
    }
}

/// Two clients on two files do not see each other's groups.
///
/// The negative half of the same property, and the one that would catch a
/// backend keying its rows by something other than the file — a process-global
/// cache, a static map, a path that got normalised away.
#[test]
fn two_stores_are_two_devices() {
    let dir = scratch("isolation");
    let server = issuer();
    let mut one = client_on(
        &server,
        1,
        "actor-ada",
        "device-ada-phone",
        sqlite_storage(&dir.join("one.sqlite3")),
    );
    one.create_group(GROUP).expect("create");

    let two = client_on(
        &server,
        1,
        "actor-ada",
        "device-ada-phone",
        sqlite_storage(&dir.join("two.sqlite3")),
    );
    assert!(
        two.group_ids().is_empty(),
        "a second store must not see the first's groups"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A store that counts the writes that reach it.
#[derive(Debug)]
struct CountingKv {
    inner: SqliteKv,
    writes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl peachy_mls_core::KvStore for CountingKv {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, peachy_mls_core::KvError> {
        self.inner.get(key)
    }
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), peachy_mls_core::KvError> {
        self.writes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.put(key, value)
    }
    fn delete(&self, key: &[u8]) -> Result<(), peachy_mls_core::KvError> {
        self.writes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.delete(key)
    }
    fn scan(
        &self,
        prefix: &[u8],
    ) -> Result<Vec<peachy_mls_core::KvEntry>, peachy_mls_core::KvError> {
        self.inner.scan(prefix)
    }
    fn flush(&self) -> Result<(), peachy_mls_core::KvError> {
        self.inner.flush()
    }
}

/// Reopening a store that already holds a group writes nothing.
///
/// On SQLite a write opens the transaction the open's final flush commits, so
/// a single write at the top of `Client::new` held the WAL write lock across
/// the read of every group. iOS kills a process suspended holding that lock on
/// an app-group file, and a shipped iOS build died in that window
/// (docs/mls-core.md §Storage layout). A reopen is reads only.
#[test]
fn reopening_a_store_writes_nothing() {
    let dir = scratch("read-only-reopen");
    let path = dir.join("ada.sqlite3");
    let server = issuer();
    {
        let mut ada = client_on(
            &server,
            1,
            "actor-ada",
            "device-ada-phone",
            sqlite_storage(&path),
        );
        ada.create_group(GROUP).expect("create");
    }
    let writes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = CountingKv {
        inner: SqliteKv::open(&path).expect("open the store"),
        writes: writes.clone(),
    };
    let storage = PeachyStorage::open(Box::new(counted)).expect("open the MLS store");
    let ada = client_on(&server, 1, "actor-ada", "device-ada-phone", storage);
    assert_eq!(ada.group_ids().len(), 1, "the group came back");
    assert_eq!(
        writes.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "reopening an existing store must not write"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The device's signing key in the two forms a store could hold it: the raw
/// 32-byte seed, and the JSON array OpenMLS' `SignatureKeyPair` serializes
/// its private half as.
fn seed_forms(tag: u8) -> [Vec<u8>; 2] {
    let seed = support::device_seed(tag);
    [
        seed.to_vec(),
        serde_json::to_vec(&seed.to_vec()).expect("a JSON array"),
    ]
}

fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// The prefix every signature key pair record sits under.
fn signature_key_prefix() -> Vec<u8> {
    peachy_mls_core::storage_key(b"signature_key", b"")
}

/// What a build before this one wrote at open: the device's key pair, private
/// half included, under its public key's storage id.
fn write_old_signer_record(kv: &dyn peachy_mls_core::KvStore, tag: u8) {
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_traits::types::SignatureScheme;
    let seed = support::device_seed(tag);
    let (_, public) = peachy_mls_core::issuer::device_key_pair(&seed);
    let signer =
        SignatureKeyPair::from_raw(SignatureScheme::ED25519, seed.to_vec(), public.to_vec());
    let key = peachy_mls_core::storage_key(
        b"signature_key",
        &serde_json::to_vec(&signer.id()).expect("the storage id"),
    );
    kv.put(&key, &serde_json::to_vec(&signer).expect("the key pair"))
        .expect("write the old record");
    kv.flush().expect("flush");
}

/// No store holds the device's private key. The signer is built from the
/// seed handed in at open and lives in memory; a client that opened, made a
/// group, added a member, sealed a message and published key packages has
/// written neither a `signature_key` record nor the seed in any form
/// (docs/identity.md §Security considerations).
#[test]
fn the_store_never_holds_the_device_signing_key() {
    use peachy_mls_core::KvStore as _;
    let server = issuer();
    let kv = MemoryKv::new();
    let mut bo = client(&server, 2, "actor-bo", "device-bo-phone");
    let bo_kp = bo.generate_key_package().expect("bo key package");
    {
        let mut ada = client_on(
            &server,
            1,
            "actor-ada",
            "device-ada-phone",
            PeachyStorage::open(Box::new(kv.clone())).expect("open"),
        );
        ada.create_group(GROUP).expect("create");
        let add = ada.add_member(GROUP, &bo_kp).expect("add bo");
        ada.merge_pending_commit(GROUP).expect("merge the add");
        bo.join_from_welcome(&add.welcome.clone().expect("welcome"))
            .expect("bo joins");
        ada.encrypt(GROUP, b"hello").expect("encrypt");
        ada.generate_key_package().expect("a key package");
        ada.generate_last_resort_key_package_with_ref()
            .expect("a last-resort key package");
    }
    // And once more: a reopen of the store does not put it back.
    drop(client_on(
        &server,
        1,
        "actor-ada",
        "device-ada-phone",
        PeachyStorage::open(Box::new(kv.clone())).expect("reopen"),
    ));

    assert!(
        kv.scan(&signature_key_prefix()).expect("scan").is_empty(),
        "the store must hold no signature key pair"
    );
    for (key, value) in kv.scan(&[]).expect("scan everything") {
        for form in seed_forms(1) {
            assert!(
                !holds(&value, &form) && !holds(&key, &form),
                "the device seed must not sit in the store (under {key:?})"
            );
        }
    }
}

/// Every file of the store in `dir`, concatenated.
fn files(dir: &PathBuf) -> Vec<u8> {
    let mut all = Vec::new();
    for entry in std::fs::read_dir(dir).expect("read the scratch dir") {
        all.extend(std::fs::read(entry.expect("an entry").path()).unwrap_or_default());
    }
    all
}

/// A store holding a signing key kept beside the seed loses it at
/// the next open: the record is deleted, the delete is committed, and the
/// file is erased of it (the WAL cut and freed pages zeroed), so neither the
/// store nor its files hold the seed afterwards. The groups still load and
/// the device still signs.
#[test]
fn a_stored_copy_of_the_signing_key_is_erased_at_open() {
    use peachy_mls_core::KvStore as _;
    let dir = scratch("old-signer-copy");
    let path = dir.join("ada.sqlite3");
    let server = issuer();
    let mut bo = client(&server, 2, "actor-bo", "device-bo-phone");
    let bo_kp = bo.generate_key_package().expect("bo key package");
    {
        let mut ada = client_on(
            &server,
            1,
            "actor-ada",
            "device-ada-phone",
            sqlite_storage(&path),
        );
        ada.create_group(GROUP).expect("create");
        let add = ada.add_member(GROUP, &bo_kp).expect("add bo");
        ada.merge_pending_commit(GROUP).expect("merge the add");
        bo.join_from_welcome(&add.welcome.clone().expect("welcome"))
            .expect("bo joins");
    }
    {
        let kv = SqliteKv::open(&path).expect("open the store");
        write_old_signer_record(&kv, 1);
    }
    // The instrument: the old record is on disk before the open.
    assert!(
        holds(&files(&dir), &seed_forms(1)[1]),
        "the kept key pair should be in the file before the open"
    );

    let mut ada = client_on(
        &server,
        1,
        "actor-ada",
        "device-ada-phone",
        sqlite_storage(&path),
    );
    assert_eq!(ada.group_ids(), vec![GROUP.to_vec()], "the group came back");
    let ciphertext = ada.encrypt(GROUP, b"signed from memory").expect("encrypt");
    match bo.process_message(GROUP, &ciphertext).expect("bo reads it") {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"signed from memory"),
        other => panic!("expected an application message, got {other:?}"),
    }
    drop(ada);

    let kv = SqliteKv::open(&path).expect("open the store again");
    assert!(
        kv.scan(&signature_key_prefix()).expect("scan").is_empty(),
        "the open must erase the kept signature key pair"
    );
    drop(kv);
    for form in seed_forms(1) {
        assert!(
            !holds(&files(&dir), &form),
            "no file of the store may still hold the device seed"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A store that refuses every write while `busy` is set, as SQLite does past
/// its busy timeout while another process holds the write lock, or a full
/// disk does.
#[derive(Debug)]
struct BusyKv {
    inner: SqliteKv,
    busy: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl BusyKv {
    fn refuse(&self) -> Result<(), peachy_mls_core::KvError> {
        if self.busy.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(peachy_mls_core::KvError::new(
                "injected: database is locked",
            ));
        }
        Ok(())
    }
}

impl peachy_mls_core::KvStore for BusyKv {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, peachy_mls_core::KvError> {
        self.inner.get(key)
    }
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), peachy_mls_core::KvError> {
        self.refuse()?;
        self.inner.put(key, value)
    }
    fn delete(&self, key: &[u8]) -> Result<(), peachy_mls_core::KvError> {
        self.refuse()?;
        self.inner.delete(key)
    }
    fn scan(
        &self,
        prefix: &[u8],
    ) -> Result<Vec<peachy_mls_core::KvEntry>, peachy_mls_core::KvError> {
        self.inner.scan(prefix)
    }
    fn flush(&self) -> Result<(), peachy_mls_core::KvError> {
        self.inner.flush()
    }
    fn rollback(&self) -> Result<(), peachy_mls_core::KvError> {
        self.inner.rollback()
    }
    fn erase_superseded(&self) -> Result<bool, peachy_mls_core::KvError> {
        self.inner.erase_superseded()
    }
}

/// The erase of a key pair kept beside the seed never costs the open. A store that
/// cannot take the delete (busy under another process, or a full disk) is
/// opened anyway with its groups, the delete rolled back, and the next open
/// that can write erases it. A notification extension's first open after an
/// update reads its chats even while the app holds the write lock.
#[test]
fn a_store_that_cannot_take_the_erase_still_opens_and_erases_it_later() {
    use peachy_mls_core::KvStore as _;
    let dir = scratch("busy-erase");
    let path = dir.join("ada.sqlite3");
    let server = issuer();
    {
        let mut ada = client_on(
            &server,
            1,
            "actor-ada",
            "device-ada-phone",
            sqlite_storage(&path),
        );
        ada.create_group(GROUP).expect("create");
    }
    {
        let kv = SqliteKv::open(&path).expect("open the store");
        write_old_signer_record(&kv, 1);
    }

    let busy = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let open = |busy: &std::sync::Arc<std::sync::atomic::AtomicBool>| {
        let kv = BusyKv {
            inner: SqliteKv::open(&path).expect("open the store"),
            busy: busy.clone(),
        };
        PeachyStorage::open(Box::new(kv)).expect("open the MLS store")
    };
    let ada = client_on(&server, 1, "actor-ada", "device-ada-phone", open(&busy));
    assert_eq!(
        ada.group_ids(),
        vec![GROUP.to_vec()],
        "a store that cannot take the erase still opens with its groups"
    );
    drop(ada);
    {
        let kv = SqliteKv::open(&path).expect("open the store");
        assert!(
            !kv.scan(&signature_key_prefix()).expect("scan").is_empty(),
            "the refused delete was rolled back, not half-applied"
        );
    }

    busy.store(false, std::sync::atomic::Ordering::SeqCst);
    let ada = client_on(&server, 1, "actor-ada", "device-ada-phone", open(&busy));
    assert_eq!(ada.group_ids(), vec![GROUP.to_vec()], "the group came back");
    drop(ada);
    let kv = SqliteKv::open(&path).expect("open the store");
    assert!(
        kv.scan(&signature_key_prefix()).expect("scan").is_empty(),
        "the next open that can write erases the old key pair"
    );
    drop(kv);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The same with a real second connection holding the write lock, as the
/// app holds it while its notification extension opens: the open neither
/// fails nor waits out the busy timeout (five seconds) for the erase, and
/// the first open after the lock is released erases the key pair.
#[test]
fn an_open_under_another_connections_write_lock_does_not_wait_for_the_erase() {
    use peachy_mls_core::KvStore as _;
    let dir = scratch("locked-erase");
    let path = dir.join("ada.sqlite3");
    let server = issuer();
    {
        let mut ada = client_on(
            &server,
            1,
            "actor-ada",
            "device-ada-phone",
            sqlite_storage(&path),
        );
        ada.create_group(GROUP).expect("create");
    }
    {
        let kv = SqliteKv::open(&path).expect("open the store");
        write_old_signer_record(&kv, 1);
    }

    let holder = SqliteKv::open(&path).expect("the other process's connection");
    holder
        .begin_write()
        .expect("the other process takes the write lock");
    let started = std::time::Instant::now();
    let ada = client_on(
        &server,
        1,
        "actor-ada",
        "device-ada-phone",
        sqlite_storage(&path),
    );
    let took = started.elapsed();
    assert_eq!(
        ada.group_ids(),
        vec![GROUP.to_vec()],
        "it opened with its groups"
    );
    assert!(
        took < std::time::Duration::from_secs(2),
        "the open waited {took:?} on the other connection's write lock"
    );
    drop(ada);
    holder.rollback().expect("the other process lets go");
    drop(holder);
    {
        let kv = SqliteKv::open(&path).expect("open the store");
        assert!(
            !kv.scan(&signature_key_prefix()).expect("scan").is_empty(),
            "nothing was written under the other connection's lock"
        );
    }

    let ada = client_on(
        &server,
        1,
        "actor-ada",
        "device-ada-phone",
        sqlite_storage(&path),
    );
    drop(ada);
    let kv = SqliteKv::open(&path).expect("open the store");
    assert!(
        kv.scan(&signature_key_prefix()).expect("scan").is_empty(),
        "the first open after the lock is released erases the old key pair"
    );
    drop(kv);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Version-1 leaf records are carried under the open's write lock, which
/// it never waits for: with another connection holding it, the open
/// neither fails nor waits out the busy timeout, and leaves the records
/// for the first open after the lock is released, which carries them.
#[cfg(feature = "fixture")]
#[test]
fn an_open_under_another_connections_write_lock_leaves_the_carry_for_later() {
    use peachy_mls_core::KvStore as _;
    let dir = scratch("locked-carry");
    let path = dir.join("ada.sqlite3");
    let server = issuer();
    {
        let mut ada = client_on(
            &server,
            1,
            "actor-ada",
            "device-ada-phone",
            sqlite_storage(&path),
        );
        ada.create_group(GROUP).expect("create");
    }
    {
        let store = sqlite_storage(&path);
        store.forget_account_leaf_records(GROUP).expect("forget");
        store
            .set_account_leaf_records_v1(GROUP, Some(&[[7; 32]]), Some(&[[7; 32]]))
            .expect("old records");
        store.flush().expect("flush");
    }

    let holder = SqliteKv::open(&path).expect("the other process's connection");
    holder
        .begin_write()
        .expect("the other process takes the write lock");
    let started = std::time::Instant::now();
    let ada = client_on(
        &server,
        1,
        "actor-ada",
        "device-ada-phone",
        sqlite_storage(&path),
    );
    let took = started.elapsed();
    assert_eq!(
        ada.group_ids(),
        vec![GROUP.to_vec()],
        "it opened with its groups"
    );
    assert!(
        took < std::time::Duration::from_secs(2),
        "the open waited {took:?} on the other connection's write lock"
    );
    drop(ada);
    holder.rollback().expect("the other process lets go");
    drop(holder);
    {
        let store = sqlite_storage(&path);
        assert!(
            store
                .account_leaf_records_v1(GROUP)
                .expect("read")
                .0
                .is_some(),
            "nothing was carried under the other connection's lock"
        );
    }

    drop(client_on(
        &server,
        1,
        "actor-ada",
        "device-ada-phone",
        sqlite_storage(&path),
    ));
    let store = sqlite_storage(&path);
    assert_eq!(
        store.account_leaf_records_v1(GROUP).expect("read"),
        (None, None),
        "the first open after the lock is released carries them"
    );
    assert!(
        store.account_known_leaves(GROUP).expect("read").is_some(),
        "into the current records"
    );
    drop(store);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A SQLite store that refuses one key's write, as a full disk or a store
/// that refuses one record would.
#[cfg(feature = "fixture")]
#[derive(Debug)]
struct RefusesOneKey {
    inner: SqliteKv,
    refused: Vec<u8>,
}

#[cfg(feature = "fixture")]
impl peachy_mls_core::KvStore for RefusesOneKey {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, peachy_mls_core::KvError> {
        self.inner.get(key)
    }
    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), peachy_mls_core::KvError> {
        if key == self.refused.as_slice() {
            return Err(peachy_mls_core::KvError::new("refused: disk full"));
        }
        self.inner.put(key, value)
    }
    fn delete(&self, key: &[u8]) -> Result<(), peachy_mls_core::KvError> {
        self.inner.delete(key)
    }
    fn scan(
        &self,
        prefix: &[u8],
    ) -> Result<Vec<peachy_mls_core::KvEntry>, peachy_mls_core::KvError> {
        self.inner.scan(prefix)
    }
    fn flush(&self) -> Result<(), peachy_mls_core::KvError> {
        self.inner.flush()
    }
    fn rollback(&self) -> Result<(), peachy_mls_core::KvError> {
        self.inner.rollback()
    }
    fn erase_superseded(&self) -> Result<bool, peachy_mls_core::KvError> {
        self.inner.erase_superseded()
    }
    fn begin_write(&self) -> Result<(), peachy_mls_core::KvError> {
        self.inner.begin_write()
    }
    fn try_begin_write(&self) -> Result<bool, peachy_mls_core::KvError> {
        self.inner.try_begin_write()
    }
    fn foreign_generation(&self) -> Result<Option<u64>, peachy_mls_core::KvError> {
        self.inner.foreign_generation()
    }
}

/// The carry is best effort, as the erase of the old signing key is: one
/// that fails part-way (the first group's record written, the second's
/// refused) is rolled back whole and the open goes on, with every group;
/// no transaction is left open, the version-1 records stay, and the next
/// open with a store that writes carries them all.
#[cfg(feature = "fixture")]
#[test]
fn a_carry_that_fails_part_way_does_not_fail_the_open() {
    use peachy_mls_core::KvStore as _;
    const OTHER: &[u8] = b"peachy-group-persist-other";
    let dir = scratch("failed-carry");
    let path = dir.join("ada.sqlite3");
    let server = issuer();
    {
        let mut ada = client_on(
            &server,
            1,
            "actor-ada",
            "device-ada-phone",
            sqlite_storage(&path),
        );
        ada.create_group(GROUP).expect("create");
        ada.create_group(OTHER).expect("create");
    }
    {
        let store = sqlite_storage(&path);
        for group in [GROUP, OTHER] {
            store.forget_account_leaf_records(group).expect("forget");
            store
                .set_account_leaf_records_v1(group, Some(&[[7; 32]]), Some(&[[7; 32]]))
                .expect("old records");
        }
        store.flush().expect("flush");
    }

    // Groups are carried in id order, so GROUP's record is written first.
    let refused = peachy_mls_core::storage_key(b"account_known_leaves_v2", OTHER);
    let kv = RefusesOneKey {
        inner: SqliteKv::open(&path).expect("open the store"),
        refused,
    };
    let ada = client_on(
        &server,
        1,
        "actor-ada",
        "device-ada-phone",
        PeachyStorage::open(Box::new(kv)).expect("open the MLS store"),
    );
    let mut held = ada.group_ids();
    held.sort();
    let mut expected = vec![GROUP.to_vec(), OTHER.to_vec()];
    expected.sort();
    assert_eq!(held, expected, "it opened with its groups");
    drop(ada);
    {
        let other = SqliteKv::open(&path).expect("another connection");
        assert!(
            other.try_begin_write().expect("try"),
            "the failed carry left a transaction open"
        );
        other.rollback().expect("let go");
    }
    {
        let store = sqlite_storage(&path);
        assert_eq!(
            store.account_known_leaves(GROUP).expect("read"),
            None,
            "part of a failed carry was kept"
        );
        for group in [GROUP, OTHER] {
            assert!(
                store
                    .account_leaf_records_v1(group)
                    .expect("read")
                    .0
                    .is_some(),
                "a version-1 record was lost"
            );
        }
    }

    drop(client_on(
        &server,
        1,
        "actor-ada",
        "device-ada-phone",
        sqlite_storage(&path),
    ));
    let store = sqlite_storage(&path);
    for group in [GROUP, OTHER] {
        assert_eq!(
            store.account_leaf_records_v1(group).expect("read"),
            (None, None),
            "the next open carries them"
        );
        assert!(store.account_known_leaves(group).expect("read").is_some());
    }
    drop(store);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The store refuses a signature key pair outright, so no caller (OpenMLS's
/// `SignatureKeyPair::store` included) can put the device's private key back.
#[test]
fn the_store_refuses_to_keep_a_signature_key_pair() {
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_traits::types::SignatureScheme;
    let seed = support::device_seed(1);
    let (_, public) = peachy_mls_core::issuer::device_key_pair(&seed);
    let signer =
        SignatureKeyPair::from_raw(SignatureScheme::ED25519, seed.to_vec(), public.to_vec());
    let storage = PeachyStorage::in_memory();
    assert!(
        signer.store(&storage).is_err(),
        "the store must refuse a signature key pair"
    );
}
