// SPDX-License-Identifier: MIT
//! What the core's storage glue writes to and reads back from a store is
//! wiped from every heap block it frees: a value as it is written, a value
//! read back once it is decoded (an epoch's HPKE key pairs among them), and a
//! stored list's elements as they are appended to, read (with every smaller
//! buffer one grew out of) and removed.
//!
//! OpenMLS hands the glue its state to keep (epoch secrets, ratchet keys,
//! private keys) through the `StorageProvider` trait. Here the trait's values
//! are this test's own types, each spelling a needle, so what the glue does
//! with a value is watched apart from what OpenMLS's own types do when they
//! are made and read (docs/mls-core.md §Security considerations).
//! No needle is ever part of a key, and the
//! store this test runs on keeps its values wiped, so what is counted is the
//! glue's own copies of values.
//!
//! An allocator stands in front of the system's for this test binary and
//! looks at every block as it is freed; one holding a needle is counted. One
//! test in this file, so no other test's frees run beside it.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use openmls_traits::storage::{traits, Entity, Key, StorageProvider, CURRENT_VERSION};
use peachy_mls_core::{KvEntry, KvError, KvStore, PeachyStorage};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

struct Watching;

static ARMED: AtomicBool = AtomicBool::new(false);
static UNWIPED: AtomicUsize = AtomicUsize::new(0);
const NEEDLES: [&[u8]; 4] = [
    b"tree-needle",
    b"proposal-needle",
    b"leaf-needle",
    b"epoch-pair-needle",
];
/// A proposal reference spelling a needle. A reference is also part of the
/// queued proposal's KEY, which no one wipes, so only a block that BEGINS
/// with the reference as a list element (its JSON string) is counted: the
/// element a removal takes out of the stored list.
const REF_ELEMENT: &[u8] = b"\"ref-needle";

unsafe impl GlobalAlloc for Watching {
    /// Zeroed: a block holds only what was written to it since.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc_zeroed(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::SeqCst) {
            let block = std::slice::from_raw_parts(ptr, layout.size());
            for needle in NEEDLES {
                if block.windows(needle.len()).any(|w| w == needle) {
                    UNWIPED.fetch_add(1, Ordering::SeqCst);
                }
            }
            if block.starts_with(REF_ELEMENT) {
                UNWIPED.fetch_add(1, Ordering::SeqCst);
            }
        }
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static ALLOCATOR: Watching = Watching;

/// A store whose values wipe themselves when replaced or dropped, so its own
/// copies are not counted.
#[derive(Default)]
struct WipingKv(Mutex<BTreeMap<Vec<u8>, Zeroizing<Vec<u8>>>>);

impl std::fmt::Debug for WipingKv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WipingKv")
    }
}

impl KvStore for WipingKv {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, KvError> {
        Ok(self.0.lock().unwrap().get(key).map(|value| value.to_vec()))
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<(), KvError> {
        self.0
            .lock()
            .unwrap()
            .insert(key.to_vec(), Zeroizing::new(value.to_vec()));
        Ok(())
    }

    fn delete(&self, key: &[u8]) -> Result<(), KvError> {
        self.0.lock().unwrap().remove(key);
        Ok(())
    }

    fn scan(&self, prefix: &[u8]) -> Result<Vec<KvEntry>, KvError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.clone(), value.to_vec()))
            .collect())
    }

    fn rollback(&self) -> Result<(), KvError> {
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct Group(u32);
impl Key<CURRENT_VERSION> for Group {}
impl traits::GroupId<CURRENT_VERSION> for Group {}

/// A value OpenMLS would keep, spelling a needle.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Kept(String);
impl Entity<CURRENT_VERSION> for Kept {}
impl traits::TreeSync<CURRENT_VERSION> for Kept {}
impl traits::QueuedProposal<CURRENT_VERSION> for Kept {}
impl traits::LeafNode<CURRENT_VERSION> for Kept {}
impl traits::HpkeKeyPair<CURRENT_VERSION> for Kept {}

#[derive(Serialize, Deserialize)]
struct Epoch(u64);
impl Key<CURRENT_VERSION> for Epoch {}
impl traits::EpochKey<CURRENT_VERSION> for Epoch {}

/// A proposal reference spelling `REF_ELEMENT`'s needle.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct NamedRef(String);
impl Entity<CURRENT_VERSION> for NamedRef {}
impl Key<CURRENT_VERSION> for NamedRef {}
impl traits::ProposalRef<CURRENT_VERSION> for NamedRef {}

/// A proposal reference: part of a key, so it spells no needle.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Ref(u32);
impl Entity<CURRENT_VERSION> for Ref {}
impl Key<CURRENT_VERSION> for Ref {}
impl traits::ProposalRef<CURRENT_VERSION> for Ref {}

/// A needle, long enough (about 300 bytes, as JSON over 300) that a list
/// element read a byte at a time outgrows its first buffers while holding
/// it, as OpenMLS's leaf nodes and proposal references do.
fn spelled(needle: &[u8], n: u32) -> Kept {
    Kept(format!(
        "{}-{n}-{}",
        String::from_utf8(needle.to_vec()).unwrap(),
        "x".repeat(300)
    ))
}

#[test]
fn the_storage_glue_wipes_every_value_it_writes_and_reads() {
    let storage = PeachyStorage::open(Box::new(WipingKv::default())).unwrap();
    let group = Group(7);
    let tree = spelled(NEEDLES[0], 0);
    let proposals: Vec<(Ref, Kept)> = (0..3).map(|n| (Ref(n), spelled(NEEDLES[1], n))).collect();
    let leaves: Vec<Kept> = (0..3).map(|n| spelled(NEEDLES[2], n)).collect();
    let pairs: Vec<Kept> = (0..2).map(|n| spelled(NEEDLES[3], n)).collect();
    let named = Group(8);
    let refs: Vec<NamedRef> = (0..3)
        .map(|n| NamedRef(format!("ref-needle-{n}-{}", "y".repeat(300))))
        .collect();
    let unnamed = Kept("a proposal".into());
    for reference in &refs {
        storage.queue_proposal(&named, reference, &unnamed).unwrap();
    }
    // What the test reads back is its own, and is dropped after it disarms.
    let mut read = Vec::with_capacity(16);

    UNWIPED.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    storage.write_tree(&group, &tree).unwrap();
    read.extend(storage.tree::<Group, Kept>(&group).unwrap());
    for (reference, proposal) in &proposals {
        storage.queue_proposal(&group, reference, proposal).unwrap();
    }
    read.extend(
        storage
            .queued_proposals::<Group, Ref, Kept>(&group)
            .unwrap()
            .into_iter()
            .map(|(_, proposal)| proposal),
    );
    for leaf in &leaves {
        storage.append_own_leaf_node(&group, leaf).unwrap();
    }
    read.extend(storage.own_leaf_nodes::<Group, Kept>(&group).unwrap());
    storage
        .write_encryption_epoch_key_pairs(&group, &Epoch(3), 0, &pairs)
        .unwrap();
    read.extend(
        storage
            .encryption_epoch_key_pairs::<Group, Epoch, Kept>(&group, &Epoch(3), 0)
            .unwrap(),
    );
    storage.remove_proposal(&named, &refs[1]).unwrap();
    ARMED.store(false, Ordering::SeqCst);
    let unwiped = UNWIPED.load(Ordering::SeqCst);

    let mut expected = vec![&tree];
    expected.extend(proposals.iter().map(|(_, proposal)| proposal));
    expected.extend(&leaves);
    expected.extend(&pairs);
    assert_eq!(read.iter().collect::<Vec<_>>(), expected);
    let left: Vec<NamedRef> = storage
        .queued_proposals::<Group, NamedRef, Kept>(&named)
        .unwrap()
        .into_iter()
        .map(|(reference, _)| reference)
        .collect();
    assert_eq!(left.iter().collect::<Vec<_>>(), [&refs[0], &refs[2]]);
    assert_eq!(
        unwiped, 0,
        "a block the storage glue freed still held a value"
    );
}
