// SPDX-License-Identifier: MIT
//! WHEN A DEVICE LAST READ A GROUP'S HEAD is kept in the group's own records
//! (`Client::note_head_read`, `Client::last_head_read`,
//! docs/delivery.md §A commit the server refuses).
//!
//! Opening a conversation reads its head again when the last finished read
//! is older than a week. The time lives in the MLS store, beside the copy it
//! describes: both processes sharing the store see it, it is excluded from
//! backup with the rest of the store, and it goes when the copy goes, so a
//! copy joined again starts with no read on record.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;
#[allow(unused_imports)]
use support::RemoveLeaf;

use std::path::{Path, PathBuf};

use peachy_mls_core::{Client, Error, PeachyStorage, SqliteKv};
use support::{client, client_on, issuer};

const G: &[u8] = b"9e4d1c2b-3a5f-4e6d-8c7b-6a5f4e3d2c1b";
const H: &[u8] = b"9e4d1c2b-3a5f-4e6d-8c7b-6a5f4e3d2c1c";

fn fresh_path(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "peachy-head-read-{}-{name}.sqlite",
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

#[test]
fn a_read_is_kept_per_group_and_the_last_one_counts() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    ada.create_group(G).unwrap();
    ada.create_group(H).unwrap();
    assert_eq!(ada.last_head_read(G).unwrap(), None);

    ada.note_head_read(G, 1_000).unwrap();
    assert_eq!(ada.last_head_read(G).unwrap(), Some(1_000));
    assert_eq!(ada.last_head_read(H).unwrap(), None);

    ada.note_head_read(G, 2_000).unwrap();
    assert_eq!(ada.last_head_read(G).unwrap(), Some(2_000));
}

#[test]
fn a_group_not_held_has_no_read_and_takes_none() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    assert_eq!(ada.last_head_read(G).unwrap(), None);
    assert!(matches!(
        ada.note_head_read(G, 1_000),
        Err(Error::NoSuchGroup)
    ));
}

#[test]
fn forgetting_the_group_drops_its_read() {
    let server = issuer();
    let mut ada = client(&server, 1, "actor-ada", "device-ada");
    ada.create_group(G).unwrap();
    ada.note_head_read(G, 1_000).unwrap();
    ada.forget_group(G).unwrap();
    assert_eq!(ada.last_head_read(G).unwrap(), None);
}

#[test]
fn the_read_outlives_the_client_and_reaches_the_other_process() {
    let server = issuer();
    let path = fresh_path("shared");
    let mut app = ada_on(&server, &path);
    app.create_group(G).unwrap();
    // The notification extension, open on the same file before the read.
    let extension = ada_on(&server, &path);
    app.note_head_read(G, 7_000).unwrap();
    assert_eq!(extension.last_head_read(G).unwrap(), Some(7_000));
    drop(app);
    drop(extension);

    let reopened = ada_on(&server, &path);
    assert_eq!(reopened.last_head_read(G).unwrap(), Some(7_000));
}

#[test]
fn a_read_the_other_process_forgot_with_the_group_is_gone() {
    let server = issuer();
    let path = fresh_path("forgotten");
    let mut app = ada_on(&server, &path);
    app.create_group(G).unwrap();
    app.note_head_read(G, 7_000).unwrap();
    let mut extension = ada_on(&server, &path);
    extension.forget_group(G).unwrap();
    assert_eq!(app.last_head_read(G).unwrap(), None);
}
