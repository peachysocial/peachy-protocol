// SPDX-License-Identifier: MIT
//! The device seal tries each envelope secret a copy holds, the current
//! epoch's and the past ones it keeps, and a commit wrapped after its merge
//! is sealed under the past one it was built at; neither leaves a past secret
//! in a heap block it frees (docs/mls-core.md §Security considerations):
//! it reads them where they lie, never into a list
//! that grows or is walked by value.
//!
//! An allocator stands in front of the system's for this test binary and
//! looks at every block as it is freed. A freed block that holds a past
//! epoch's secret is counted. The current epoch's secret is derived by
//! OpenMLS, in buffers of its own, so it is counted against what deriving it
//! alone frees: the seal may free it no more often than that. The store is a
//! SQLite file, whose own allocations go through its C allocator and are not
//! looked at here. One test in this file, so no other test's frees run
//! beside it.

mod support;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use peachy_mls_core::envelope::{
    seal_epoch_envelope, ENVELOPE_KIND_COMMIT, ENVELOPE_KIND_MESSAGE, EPOCH_ENVELOPE_EXPORTER_LABEL,
};
use peachy_mls_core::{Client, PeachyStorage, SqliteKv};
use support::{client_on, issuer};

struct Watching;

static ARMED: AtomicBool = AtomicBool::new(false);
static UNWIPED: AtomicUsize = AtomicUsize::new(0);
static NEEDLES: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

unsafe impl GlobalAlloc for Watching {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::SeqCst) {
            if let Ok(needles) = NEEDLES.try_lock() {
                let block = std::slice::from_raw_parts(ptr, layout.size());
                for needle in needles.iter() {
                    if block.windows(needle.len()).any(|w| w == &needle[..]) {
                        UNWIPED.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
        }
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static ALLOCATOR: Watching = Watching;

const GROUP: &[u8] = b"peachy-group-wipe-device-seal";

fn envelope_secret(client: &Client) -> Vec<u8> {
    client
        .export_secret(GROUP, EPOCH_ENVELOPE_EXPORTER_LABEL, GROUP, 32)
        .expect("the epoch's envelope secret")
}

/// A self update, merged: the commit.
fn commit(client: &mut Client) -> Vec<u8> {
    let bundle = client.self_update(GROUP).expect("a self update");
    client.merge_pending_commit(GROUP).expect("merge it");
    bundle.commit
}

/// Run `f` armed, watching for `needles`; what it answers, and how many
/// freed blocks held one.
fn counted<T>(needles: &[Vec<u8>], f: impl FnOnce() -> T) -> (T, usize) {
    *NEEDLES.lock().expect("needles") = needles.to_vec();
    UNWIPED.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    let out = f();
    ARMED.store(false, Ordering::SeqCst);
    (out, UNWIPED.load(Ordering::SeqCst))
}

#[test]
fn the_device_seal_frees_no_envelope_secret_it_tried() {
    let path = std::env::temp_dir().join(format!(
        "peachy-device-seal-wipe-{}.sqlite",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let storage = PeachyStorage::open(Box::new(SqliteKv::open(&path).expect("open the store")))
        .expect("open the MLS store");
    let mut ada = client_on(&issuer(), 1, "actor-ada", "device-ada-phone", storage);
    ada.create_group(GROUP).expect("create");

    let mut past = Vec::new();
    let mut last = Vec::new();
    for _ in 0..3 {
        past.push(envelope_secret(&ada));
        last = commit(&mut ada);
    }
    let current = envelope_secret(&ada);
    // Sealed at the newest past epoch: the current secret and the older
    // kept ones are tried first.
    let envelope = seal_epoch_envelope(&past[2], ENVELOPE_KIND_MESSAGE, b"words").expect("seal");

    let (seals, past_freed) = counted(&past, || ada.device_seals(GROUP, &envelope));
    assert_eq!(
        seals.expect("seals").len(),
        1,
        "one seal, for ada's one device"
    );
    // The last commit, wrapped after its merge: sealed under past[2], read
    // from the kept list.
    let (wrapped, wrapped_freed) = counted(&past, || {
        ada.seal_envelope(GROUP, ENVELOPE_KIND_COMMIT, &last)
    });
    assert_eq!(
        wrapped.expect("wrapped")[0],
        peachy_mls_core::envelope::ENVELOPE_VERSION_EPOCH,
        "sealed under an epoch secret"
    );
    let (derived, alone) = counted(std::slice::from_ref(&current), || envelope_secret(&ada));
    assert_eq!(derived, current);
    let (seals, current_freed) = counted(std::slice::from_ref(&current), || {
        ada.device_seals(GROUP, &envelope)
    });
    assert_eq!(seals.expect("seals").len(), 1);

    drop(ada);
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
    assert_eq!(
        past_freed, 0,
        "a block the device seal freed still held a past epoch's envelope secret"
    );
    assert_eq!(
        wrapped_freed, 0,
        "a block the commit wrap freed still held a past epoch's envelope secret"
    );
    assert_eq!(
        current_freed, alone,
        "the device seal freed the current envelope secret more often than deriving it does"
    );
}
