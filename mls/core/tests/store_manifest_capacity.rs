// SPDX-License-Identifier: MIT
//! The account store's manifest holds as many ids as the server holds records.
//!
//! A manifest is the JSON `{"version":N,"ids":[...]}` every client writes
//! (sorted 32-hex ids, no whitespace). Sealed under the record cap of 65,536
//! bytes, it would stop a store at about 1,870 ids: past that, every write
//! that added a subject (a block, a mute, a leave, a verified code) would fail
//! before it reached the server, while writes that only changed an existing
//! subject still landed. This pins that the manifest seals at the server's
//! 10,000-record limit, that what it seals opens, and that the write loop a
//! client runs does not freeze once many people have written to the account.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;

use peachy_mls_core::account_store::{
    store_open, store_seal, MANIFEST_ID, MAX_MANIFEST_PLAINTEXT_BYTES, MAX_STORE_PLAINTEXT_BYTES,
};

const KEY: [u8; 32] = [0x11; 32];
/// The server's record limit (`MAX_RECORDS`).
const SERVER_MAX_RECORDS: usize = 10_000;
/// The server's sealed-manifest limit (`MAX_MANIFEST_BYTES`).
const SERVER_MAX_MANIFEST: usize = 512 * 1024;

fn rand_id() -> String {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).unwrap();
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn manifest(version: u64, ids: &BTreeSet<String>) -> Vec<u8> {
    let list: Vec<String> = ids.iter().map(|i| format!("\"{i}\"")).collect();
    format!("{{\"version\":{version},\"ids\":[{}]}}", list.join(",")).into_bytes()
}

/// One client write: `replace` names the subject's current record (a change
/// to an existing subject) or None (a new subject). Every write re-seals the
/// whole manifest. Returns the sealed manifest's length, or the seal error a
/// client would meet before any rpc.
fn write(
    store: &mut BTreeSet<String>,
    version: &mut u64,
    replace: Option<&str>,
) -> Result<usize, String> {
    let mut next = store.clone();
    if let Some(old) = replace {
        assert!(next.remove(old));
    }
    next.insert(rand_id());
    let sealed = store_seal(&KEY, &MANIFEST_ID, &manifest(*version + 1, &next))
        .map_err(|e| e.to_string())?;
    *store = next;
    *version += 1;
    Ok(sealed.len())
}

#[test]
fn a_manifest_of_ten_thousand_ids_seals_under_the_server_limit_and_opens() {
    // A large version number too, so the frame is at its widest in practice.
    let ids: BTreeSet<String> = (0..SERVER_MAX_RECORDS).map(|_| rand_id()).collect();
    let plain = manifest(u64::from(u32::MAX), &ids);
    assert!(plain.len() > MAX_STORE_PLAINTEXT_BYTES, "past the old cap");
    assert!(
        plain.len() <= MAX_MANIFEST_PLAINTEXT_BYTES,
        "{} bytes",
        plain.len()
    );
    let sealed = store_seal(&KEY, &MANIFEST_ID, &plain).expect("10,000 ids seal");
    assert!(
        sealed.len() <= SERVER_MAX_MANIFEST,
        "{} bytes sealed",
        sealed.len()
    );
    assert_eq!(
        store_open(&KEY, &MANIFEST_ID, &sealed).expect("and open"),
        plain
    );
}

#[test]
fn many_senders_no_longer_freeze_new_subjects() {
    // A realistic store (the account record, 450 chats and contacts), then
    // one new subject per stranger whose key arrived, past the old wall of
    // about 1,870 ids.
    let mut store = BTreeSet::new();
    let mut version = 0u64;
    store.insert(rand_id());
    for _ in 0..450 {
        store.insert(rand_id());
    }
    for n in 0..1_500 {
        write(&mut store, &mut version, None)
            .unwrap_or_else(|e| panic!("new subject {n} at {} ids: {e}", store.len()));
    }
    assert!(store.len() > 1_900, "past the old wall");

    // A block, mute or leave of someone new (a new subject) still lands...
    write(&mut store, &mut version, None).expect("a new subject");
    // ...and so does a change to an existing one.
    let existing = store.iter().next().unwrap().clone();
    write(&mut store, &mut version, Some(&existing)).expect("a change");

    // A queued batch of one new subject and one change seals as a whole.
    let mut batch = store.clone();
    let existing = batch.iter().next().unwrap().clone();
    batch.remove(&existing);
    batch.insert(rand_id());
    batch.insert(rand_id());
    store_seal(&KEY, &MANIFEST_ID, &manifest(version + 1, &batch)).expect("a mixed batch");
}
