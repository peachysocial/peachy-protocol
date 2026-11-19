// SPDX-License-Identifier: MIT
//! The envelope secrets of past epochs, which the core keeps so an envelope
//! sealed at one still opens, are wiped from every heap block it frees as it
//! keeps that record (docs/mls-core.md §Security considerations).
//!
//! An allocator stands in front of the system's for this test binary, hands
//! out every block zeroed, and looks at every block as it is freed. The record is filled past the number
//! of epochs it keeps while unarmed; then, armed, each commit rewrites it,
//! replacing one epoch and dropping the oldest. A freed block that holds the
//! secret of an epoch before the current one is counted. The current epoch's
//! secret is left out: OpenMLS derives it in buffers of its own. The store is
//! a SQLite file, whose own allocations go through its C allocator and are
//! not looked at here. One test in this file, so no other test's frees run
//! beside it.

mod support;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use peachy_mls_core::envelope::EPOCH_ENVELOPE_EXPORTER_LABEL;
use peachy_mls_core::{Client, PeachyStorage, SqliteKv, ENVELOPE_PAST_EPOCHS};
use support::{client_on, issuer};

struct Watching;

static ARMED: AtomicBool = AtomicBool::new(false);
static UNWIPED: AtomicUsize = AtomicUsize::new(0);
static NEEDLES: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

unsafe impl GlobalAlloc for Watching {
    /// Zeroed: a block holds only what was written to it since, never what
    /// an earlier owner of that memory left there. glibc hands a freed block
    /// back as it was (macOS clears it on free), so a block the core used
    /// for a few bytes and freed would otherwise carry, past them, a past
    /// epoch's secret that OpenMLS's buffers or SQLite's own allocator freed
    /// before the test armed, which neither this block's owner nor anything
    /// watched here ever held: a count that varied run to run on Linux.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc_zeroed(layout)
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

const GROUP: &[u8] = b"peachy-group-wipe-epochs";

fn envelope_secret(client: &Client) -> Vec<u8> {
    client
        .export_secret(GROUP, EPOCH_ENVELOPE_EXPORTER_LABEL, GROUP, 32)
        .expect("the epoch's envelope secret")
}

fn commit(client: &mut Client) {
    client.self_update(GROUP).expect("a self update");
    client.merge_pending_commit(GROUP).expect("merge it");
}

#[test]
fn the_core_wipes_past_envelope_secrets_as_it_keeps_its_record_of_them() {
    let path = std::env::temp_dir().join(format!(
        "peachy-secret-wipe-epochs-{}.sqlite",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let storage = PeachyStorage::open(Box::new(SqliteKv::open(&path).expect("open the store")))
        .expect("open the MLS store");
    let mut ada = client_on(&issuer(), 1, "actor-ada", "device-ada-phone", storage);
    ada.create_group(GROUP).expect("create");

    // The record full, and past it: the oldest epochs already dropped.
    let mut past = Vec::new();
    for _ in 0..ENVELOPE_PAST_EPOCHS + 3 {
        past.push(envelope_secret(&ada));
        commit(&mut ada);
    }

    *NEEDLES.lock().expect("needles") = past.clone();
    UNWIPED.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    for _ in 0..3 {
        commit(&mut ada);
    }
    ARMED.store(false, Ordering::SeqCst);
    drop(ada);
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
    assert_eq!(
        UNWIPED.load(Ordering::SeqCst),
        0,
        "a block the core freed keeping its record of past epochs still held a past envelope secret"
    );
}
