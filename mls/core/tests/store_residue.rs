// SPDX-License-Identifier: MIT
//! Forward secrecy on the real backend: what a seized SQLite store gives back.
//!
//! `calls_negative.rs` holds N3 (docs/calls.md) over `MemoryKv`,
//! which keeps only current values. The store the Apple and Android clients
//! open is `SqliteKv` in WAL mode under SQLCipher, where a commit appends new
//! pages to the `-wal` file and leaves the old ones behind. Until the store
//! erased what each operation replaced, a client rebuilt from the main file
//! and a prefix of that log, with the store key, derived a previous epoch's
//! call root (`mls/core/src/sqlite.rs` §Erasing what an operation replaced).
//!
//! These tests take the attacker's side, a seizure of the running device with
//! its store key, and assert it now yields only the current epoch: on both
//! keyed doors, after commits, a Welcome, received messages and a forgotten
//! group, and with a second connection holding the file busy.

mod support;

use std::path::{Path, PathBuf};

use peachy_mls_core::{Client, KvStore, PeachyStorage, SqliteKv};
use support::{client, client_on, issuer};

const GROUP: &[u8] = b"peachy-store-residue-group";
const CALL_ID: [u8; 16] = *b"0123456789abcdef";
const KEY: [u8; 32] = [0x42; 32];
const KEYSPEC: [u8; 48] = [0x5a; 48];

/// The two keyed doors the C ABI opens: a 32-byte key (Android) and a 48-byte
/// keyspec with a plaintext header (Apple).
#[derive(Clone, Copy, Debug)]
enum Door {
    Key,
    Keyspec,
}

impl Door {
    fn open(self, path: &Path) -> SqliteKv {
        match self {
            Door::Key => SqliteKv::open_encrypted(path, &KEY).expect("open"),
            Door::Keyspec => {
                SqliteKv::open_encrypted_with_plaintext_header(path, &KEYSPEC).expect("open")
            }
        }
    }

    fn sql_key(self) -> String {
        let bytes: &[u8] = match self {
            Door::Key => &KEY,
            Door::Keyspec => &KEYSPEC,
        };
        bytes.iter().map(|b| format!("{b:02X}")).collect()
    }

    fn header(self) -> u8 {
        match self {
            Door::Key => 0,
            Door::Keyspec => 32,
        }
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("peachy-residue-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn wal_of(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push("-wal");
    PathBuf::from(name)
}

fn wal_len(path: &Path) -> u64 {
    std::fs::metadata(wal_of(path))
        .map(|m| m.len())
        .unwrap_or(0)
}

fn ada_on(door: Door, path: &Path) -> Client {
    client_on(
        &issuer(),
        1,
        "actor-ada",
        "device-ada-phone",
        PeachyStorage::open(Box::new(door.open(path))).expect("storage"),
    )
}

/// Copy the files of the running device, as a seizure would: the main file
/// and its log, whatever they hold right now.
fn seize(door: Door, path: &Path, name: &str) -> Vec<Client> {
    let image = scratch(name);
    let main = std::fs::read(path).expect("read the main file");
    let wal = std::fs::read(wal_of(path)).unwrap_or_default();
    // Every way the copy could be put back together: the main file alone,
    // and the main file with each frame-aligned prefix of the log (the
    // attacker chooses where a replay stops). A SQLCipher page is 4096 bytes
    // and a frame carries a 24-byte header; the log's own header is 32.
    let mut cuts = vec![0usize];
    let mut at = 32usize;
    while at + 24 + 4096 <= wal.len() {
        at += 24 + 4096;
        cuts.push(at);
    }
    cuts.into_iter()
        .enumerate()
        .map(|(n, cut)| {
            let copy = image.join(format!("copy-{n}.sqlite3"));
            std::fs::write(&copy, &main).expect("write the copy");
            if cut > 0 {
                std::fs::write(wal_of(&copy), &wal[..cut]).expect("write the log");
            }
            ada_on(door, &copy)
        })
        .collect()
}

/// A seized store yields only the current epoch: three epochs on with the
/// store open the whole time, the seized files derive epoch e+3 and never
/// epoch e.
fn a_seized_store_derives_only_the_current_epoch(door: Door) {
    let dir = scratch(&format!("seize-{door:?}"));
    let path = dir.join("ada.sqlite3");
    let server = issuer();
    let mut bo = client(&server, 2, "actor-bo", "device-bo-phone");
    let bo_kp = bo.generate_key_package().expect("key package");

    let mut ada = ada_on(door, &path);
    ada.create_group(GROUP).expect("create");
    let added = ada.add_member(GROUP, &bo_kp).expect("add");
    ada.merge_pending_commit(GROUP).expect("merge");
    bo.join_from_welcome(&added.welcome.clone().expect("welcome"))
        .expect("join");

    let old = ada.call_keys(GROUP, &CALL_ID).expect("call keys at e");
    let mut olds = vec![old.clone()];
    for _ in 0..3 {
        let update = ada.self_update(GROUP).expect("update");
        ada.merge_pending_commit(GROUP).expect("merge");
        assert_eq!(wal_len(&path), 0, "a merged commit leaves no log behind");
        bo.process_commit(GROUP, &update.commit)
            .expect("bo follows");
        olds.push(ada.call_keys(GROUP, &CALL_ID).expect("call keys"));
    }
    // And the other direction: bo's commit, processed by ada's store, and an
    // application message opened there.
    let update = bo.self_update(GROUP).expect("bo update");
    bo.merge_pending_commit(GROUP).expect("bo merge");
    ada.process_commit(GROUP, &update.commit)
        .expect("ada follows");
    assert_eq!(wal_len(&path), 0, "a processed commit leaves no log behind");
    let sealed = bo.encrypt(GROUP, b"after the commit").expect("encrypt");
    ada.process_message(GROUP, &sealed).expect("open");
    assert_eq!(wal_len(&path), 0, "an opened message leaves no log behind");

    let now = ada.call_keys(GROUP, &CALL_ID).expect("call keys now");
    assert_eq!(now.epoch, old.epoch + 4);
    // Epochs e to e+3: everything ada's store held before bo's commit.
    let superseded = &olds[..];

    let rebuilt = seize(door, &path, &format!("seize-{door:?}-image"));
    // The whole image is the device as it is now.
    let whole = rebuilt.last().expect("at least the main file");
    let current = whole.call_keys(GROUP, &CALL_ID).expect("rebuilt call keys");
    assert_eq!(
        current.epoch, now.epoch,
        "a rebuilt client is at the current epoch"
    );
    assert_eq!(current.call_root, now.call_root);
    // And no cut of it is the device as it was. A cut that yields no group
    // at all gives the attacker nothing, which is the point.
    for seized in &rebuilt {
        let Ok(recovered) = seized.call_keys(GROUP, &CALL_ID) else {
            continue;
        };
        for past in superseded {
            assert_ne!(
                recovered.call_root, past.call_root,
                "epoch {}'s call root came back from the seized store",
                past.epoch
            );
            for sender in &past.senders {
                assert!(
                    !recovered.senders.iter().any(|s| s.key == sender.key),
                    "an epoch-{} sender key came back from the seized store",
                    past.epoch
                );
            }
        }
    }
    drop(ada);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_seized_store_derives_only_the_current_epoch_under_a_key() {
    a_seized_store_derives_only_the_current_epoch(Door::Key);
}

#[test]
fn a_seized_store_derives_only_the_current_epoch_under_a_keyspec() {
    a_seized_store_derives_only_the_current_epoch(Door::Keyspec);
}

/// A second connection on the same file, holding a read snapshot (what a
/// notification extension in another process looks like mid-read), makes the
/// checkpoint busy. The operation still succeeds, and the next flush once the
/// reader has gone erases what the first could not.
#[test]
fn a_busy_store_never_fails_an_operation_and_erases_at_the_next_flush() {
    for door in [Door::Key, Door::Keyspec] {
        let dir = scratch(&format!("busy-{door:?}"));
        let path = dir.join("ada.sqlite3");
        let server = issuer();
        let mut bo = client(&server, 2, "actor-bo", "device-bo-phone");
        let bo_kp = bo.generate_key_package().expect("key package");
        let mut ada = ada_on(door, &path);
        ada.create_group(GROUP).expect("create");
        let added = ada.add_member(GROUP, &bo_kp).expect("add");
        ada.merge_pending_commit(GROUP).expect("merge");
        bo.join_from_welcome(&added.welcome.clone().expect("welcome"))
            .expect("join");
        let old = ada.call_keys(GROUP, &CALL_ID).expect("call keys at e");

        let reader = rusqlite::Connection::open(&path).expect("reader");
        reader
            .execute_batch(&format!(
                "PRAGMA key = \"x'{}'\"; PRAGMA cipher_plaintext_header_size = {};",
                door.sql_key(),
                door.header()
            ))
            .expect("key the reader");
        reader.execute_batch("BEGIN;").expect("begin");
        let _: i64 = reader
            .query_row("SELECT count(*) FROM mls_kv;", [], |row| row.get(0))
            .expect("a read snapshot");

        let update = ada.self_update(GROUP).expect("update");
        ada.merge_pending_commit(GROUP)
            .expect("a busy checkpoint must not fail the merge");
        bo.process_commit(GROUP, &update.commit)
            .expect("bo follows");
        let sealed = bo
            .encrypt(GROUP, b"while the reader reads")
            .expect("encrypt");
        ada.process_message(GROUP, &sealed)
            .expect("a busy checkpoint must not fail a receive");
        ada.encrypt(GROUP, b"and a send").expect("nor a send");
        assert!(
            wal_len(&path) > 0,
            "the instrument: with a reader on an old snapshot the log cannot be cut"
        );

        reader.execute_batch("COMMIT;").expect("end the read");
        drop(reader);
        // Any next flush retries, even one with nothing to commit: the store
        // remembered that its last checkpoint did not finish.
        ada.flush().expect("flush");
        assert_eq!(wal_len(&path), 0, "the retry erased the log");

        for seized in seize(door, &path, &format!("busy-{door:?}-image")) {
            let recovered = seized
                .call_keys(GROUP, &CALL_ID)
                .expect("rebuilt call keys");
            assert_ne!(recovered.call_root, old.call_root);
        }
        drop(ada);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// A process killed without closing leaves its log behind; the next open
/// erases it before anything else reads the store.
#[test]
fn opening_a_store_erases_the_log_a_killed_process_left() {
    let dir = scratch("killed");
    let path = dir.join("ada.sqlite3");
    let kv = Door::Key.open(&path);
    kv.put(b"group-secret", &[0x11; 3000]).expect("put");
    kv.flush().expect("flush");
    kv.put(b"group-secret", &[0x22; 3000]).expect("replace");
    kv.flush().expect("flush");
    assert!(
        wal_len(&path) > 0,
        "the instrument: a flush alone leaves a log"
    );
    // Killed, not closed: no checkpoint at close, no log deleted.
    std::mem::forget(kv);
    assert!(wal_len(&path) > 0);

    let reopened = Door::Key.open(&path);
    assert_eq!(wal_len(&path), 0, "the open erased the log");
    assert_eq!(
        reopened.get(b"group-secret").expect("get"),
        Some(vec![0x22; 3000])
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Byte-level, on an unkeyed store where the bytes can be read: a replaced
/// and a deleted value leave nothing in the main file or the log once the
/// store has erased. This is `secure_delete` and the truncating checkpoint
/// together; the keyed doors run the same SQLite underneath.
#[test]
fn a_replaced_or_deleted_value_leaves_no_bytes_on_disk() {
    let dir = scratch("bytes");
    let path = dir.join("plain.sqlite3");
    let kv = SqliteKv::open(&path).expect("open");
    let replaced = b"canary-epoch-secret-replaced-0123456789".repeat(40);
    let deleted = b"canary-key-package-private-deleted-9876".repeat(3);
    kv.put(b"epoch_secrets", &replaced).expect("put");
    kv.put(b"key_package", &deleted).expect("put");
    kv.put(b"other", &[0x33; 500]).expect("put");
    kv.flush().expect("flush");
    assert!(kv.erase_superseded().expect("erase"));

    kv.put(b"epoch_secrets", &[0x44; 1600]).expect("replace");
    kv.delete(b"key_package").expect("delete");
    kv.flush().expect("flush");
    assert!(kv.erase_superseded().expect("erase"));

    let main = std::fs::read(&path).expect("main");
    let wal = std::fs::read(wal_of(&path)).unwrap_or_default();
    for (name, bytes) in [("main file", &main), ("log", &wal)] {
        for needle in [&replaced[..39], &deleted[..39]] {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle),
                "a superseded value is still in the {name}"
            );
        }
    }
    assert_eq!(
        kv.get(b"epoch_secrets").expect("get"),
        Some(vec![0x44; 1600])
    );
    drop(kv);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A forgotten group's state is erased with it, not left in the log.
#[test]
fn a_forgotten_group_leaves_no_log_behind() {
    let dir = scratch("forget");
    let path = dir.join("ada.sqlite3");
    let mut ada = ada_on(Door::Key, &path);
    ada.create_group(GROUP).expect("create");
    let before = ada.call_keys(GROUP, &CALL_ID).expect("call keys");
    ada.forget_group(GROUP).expect("forget");
    assert_eq!(wal_len(&path), 0);
    for seized in seize(Door::Key, &path, "forget-image") {
        assert!(
            seized.call_keys(GROUP, &CALL_ID).is_err(),
            "the group came back"
        );
    }
    let _ = before;
    drop(ada);
    let _ = std::fs::remove_dir_all(&dir);
}
