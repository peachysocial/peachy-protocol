// SPDX-License-Identifier: MIT
//! A store written in the clear, and the way out of it
//! (`mls/core/src/sqlite.rs` §Encrypting a store in place):
//!
//! - opened under a key, it is `PlaintextStore`, never touched, and not the
//!   `Storage` failure a caller may retry; a wrong key stays `Storage`;
//! - `store_encrypt_in_place` keeps every row, leaves no plaintext file, log
//!   or index, and the store then opens under the key, in both layouts;
//! - an open that asks for an existing store creates nothing.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};

use peachy_mls_core::sqlite::store_encrypt_in_place;
use peachy_mls_core::storage::KvStore;
use peachy_mls_core::{Error, SqliteKv};

const MAGIC: &[u8; 16] = b"SQLite format 3\0";

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "peachy-store-encryption-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir.join("mls.sqlite3")
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// A store in the clear holding `n` rows.
fn plaintext_store(path: &Path, n: u8) {
    let kv = SqliteKv::open(path).expect("open in the clear");
    for i in 0..n {
        kv.put(&[b'k', i], &[i; 40]).expect("put");
    }
    kv.flush().expect("flush");
}

fn rows(kv: &SqliteKv, n: u8) {
    for i in 0..n {
        assert_eq!(
            kv.get(&[b'k', i]).expect("get"),
            Some(vec![i; 40]),
            "row {i}"
        );
    }
}

#[test]
fn a_store_in_the_clear_is_its_own_refusal_and_encrypts_in_place() {
    for key in [vec![0x11u8; 32], vec![0x22u8; 48]] {
        let path = scratch(&format!("layout-{}", key.len()));
        plaintext_store(&path, 5);
        assert!(SqliteKv::is_plaintext_store(&path));

        // Under a key it is PlaintextStore, and the file is untouched.
        let before = std::fs::read(&path).unwrap();
        match SqliteKv::open_store(&path, &key, true) {
            Err(Error::PlaintextStore) => {}
            other => panic!("expected PlaintextStore, got {other:?}"),
        }
        assert_eq!(std::fs::read(&path).unwrap(), before);

        store_encrypt_in_place(&path, &key).expect("encrypt in place");
        for suffix in ["-wal", "-shm", ".encrypting"] {
            assert!(
                !sidecar(&path, suffix).exists(),
                "{suffix} left behind ({})",
                key.len()
            );
        }
        assert!(!SqliteKv::is_plaintext_store(&path));
        for suffix in ["-wal", "-shm"] {
            assert!(
                !sidecar(&path, suffix).exists(),
                "{suffix} made by the probe ({})",
                key.len()
            );
        }
        let head = std::fs::read(&path).unwrap();
        if key.len() == 32 {
            assert!(
                !head.starts_with(MAGIC),
                "the file is ciphertext from its first byte"
            );
        }
        let kv = SqliteKv::open_store(&path, &key, true).expect("opens under the key");
        rows(&kv, 5);
        drop(kv);

        // Once encrypted it is not encrypted again, and another key is the
        // ordinary failure.
        assert!(matches!(
            store_encrypt_in_place(&path, &key),
            Err(Error::InvalidArgument(_))
        ));
        let mut other = key.clone();
        other[0] ^= 0xFF;
        assert!(matches!(
            SqliteKv::open_store(&path, &other, true),
            Err(Error::Storage(_))
        ));
    }
}

#[test]
fn an_open_of_an_existing_store_creates_nothing() {
    let path = scratch("missing");
    let key = [0x33u8; 32];
    assert!(matches!(
        SqliteKv::open_store(&path, &key, true),
        Err(Error::InvalidArgument(_))
    ));
    assert!(!path.exists(), "nothing was created");
    assert!(matches!(
        store_encrypt_in_place(&path, &key),
        Err(Error::InvalidArgument(_))
    ));
    // Without must_exist a new store is made, under the key.
    drop(SqliteKv::open_store(&path, &key, false).expect("a new store"));
    assert!(path.exists());
    assert!(!SqliteKv::is_plaintext_store(&path));
}

#[test]
fn an_interrupted_attempt_leaves_the_store_in_the_clear_and_a_retry_finishes() {
    let path = scratch("retry");
    plaintext_store(&path, 3);
    // What a crash before the rename leaves: a partial file beside the store.
    std::fs::write(sidecar(&path, ".encrypting"), b"half a file").unwrap();
    assert!(SqliteKv::is_plaintext_store(&path));
    let key = [0x44u8; 32];
    store_encrypt_in_place(&path, &key).expect("the retry");
    assert!(!sidecar(&path, ".encrypting").exists());
    rows(&SqliteKv::open_store(&path, &key, true).expect("open"), 3);
}

/// Set `path`'s permission bits.
#[cfg(unix)]
fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

// RUSTSEC-2026-0459: the bundled SQLite trusts a `-wal` beside the store, so
// a store any of whose files group or others can write is refused, typed,
// and nothing is opened (`mls/core/src/sqlite.rs` §Only this process's user
// writes the files).
#[cfg(unix)]
#[test]
fn a_store_others_can_write_is_refused_until_it_is_the_owners_alone() {
    use peachy_mls_core::sqlite::check_store_permissions;
    use std::os::unix::fs::PermissionsExt;

    let path = scratch("permissions");
    let key = [0x55u8; 32];
    {
        let kv = SqliteKv::open_store(&path, &key, false).expect("a new store");
        kv.put(b"k", b"v").expect("put");
        kv.flush().expect("flush");
    }
    // What the core makes is its owner's alone to write, whatever the umask.
    for suffix in ["", "-wal", "-shm"] {
        if let Ok(meta) = std::fs::metadata(sidecar(&path, suffix)) {
            assert_eq!(
                meta.permissions().mode() & 0o022,
                0,
                "{suffix:?} made writable by others"
            );
        }
    }
    check_store_permissions(&path).expect("the core's own store passes");

    for (suffix, mode) in [
        ("", 0o664),
        ("", 0o646),
        ("-wal", 0o666),
        ("-shm", 0o620),
        ("-journal", 0o602),
    ] {
        let file = sidecar(&path, suffix);
        let made = !file.exists();
        if made {
            std::fs::write(&file, b"").unwrap();
        }
        let before = std::fs::metadata(&file).unwrap().permissions().mode();
        chmod(&file, mode);
        match SqliteKv::open_store(&path, &key, true) {
            Err(Error::InsecureStore(why)) => {
                let which = if suffix.is_empty() { "file" } else { suffix };
                assert!(why.contains(which), "{why} names {which}");
                assert!(
                    why.contains(&format!("{mode:04o}")),
                    "{why} names {mode:04o}"
                );
            }
            other => panic!("{suffix:?} at {mode:o}: expected InsecureStore, got {other:?}"),
        }
        if made {
            std::fs::remove_file(&file).unwrap();
        } else {
            chmod(&file, before & 0o7777);
        }
    }
    assert_eq!(Error::InsecureStore(String::new()).code(), 22);
    let kv = SqliteKv::open_store(&path, &key, true).expect("the owner's alone again: opens");
    assert_eq!(kv.get(b"k").expect("get"), Some(b"v".to_vec()));

    // Encrypting in place asks the same of a store in the clear.
    let clear = scratch("permissions-clear");
    plaintext_store(&clear, 2);
    chmod(&clear, 0o666);
    assert!(matches!(
        store_encrypt_in_place(&clear, &key),
        Err(Error::InsecureStore(_))
    ));
    assert!(SqliteKv::is_plaintext_store(&clear), "left as it was");
}

// A symbolic link in the store's place passes on the mode of a file someone
// else chose: refused, whatever it points at.
#[cfg(unix)]
#[test]
fn a_store_file_that_is_a_symbolic_link_is_refused() {
    let path = scratch("symlink");
    let key = [0x56u8; 32];
    {
        let kv = SqliteKv::open_store(&path, &key, false).expect("a new store");
        kv.put(b"k", b"v").expect("put");
        kv.flush().expect("flush");
    }
    let elsewhere = path.with_file_name("planted-log");
    std::fs::write(&elsewhere, b"").unwrap();
    chmod(&elsewhere, 0o600);
    let wal = sidecar(&path, "-wal");
    let _ = std::fs::remove_file(&wal);
    std::os::unix::fs::symlink(&elsewhere, &wal).unwrap();
    match SqliteKv::open_store(&path, &key, true) {
        Err(Error::InsecureStore(why)) => assert!(why.contains("symbolic link"), "{why}"),
        other => panic!("expected InsecureStore, got {other:?}"),
    }
    std::fs::remove_file(&wal).unwrap();
    SqliteKv::open_store(&path, &key, true).expect("without the link: opens");
}

// A store its owner kept private stays private once encrypted in place.
#[cfg(unix)]
#[test]
fn encrypting_in_place_keeps_the_stores_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let path = scratch("keeps-mode");
    plaintext_store(&path, 2);
    chmod(&path, 0o600);
    store_encrypt_in_place(&path, &[0x57u8; 32]).expect("encrypts");
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}
