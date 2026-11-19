// SPDX-License-Identifier: MIT
//! Every value the binding's store cache frees is wiped: one it replaces, one
//! a delete or a rollback drops, what it owed the host once that landed, and
//! the rest when the cache goes (docs/mls-core.md §Security considerations).
//!
//! The cache's source is compiled into this test crate, since the binding
//! forbids the `unsafe` an allocator needs. An allocator stands in front of
//! the system's and counts freed blocks still holding the value; the value's
//! only other copies are the test's own, made before it arms and dropped
//! after. The cache's own unit tests run beside this one in the binary, and
//! none of them holds the value. On the host only: it is the same code on
//! wasm32.

#![cfg(not(target_arch = "wasm32"))]

#[path = "../src/kv.rs"]
#[allow(dead_code)]
mod kv;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use kv::CacheKv;
use peachy_mls_core::KvStore;

struct Watching;

static ARMED: AtomicBool = AtomicBool::new(false);
static UNWIPED: AtomicUsize = AtomicUsize::new(0);
/// 32 bytes with no zero in them, so a wiped block cannot match.
const SECRET: [u8; 32] = *b"peachy cache value, wiped please";

unsafe impl GlobalAlloc for Watching {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::SeqCst) {
            let block = std::slice::from_raw_parts(ptr, layout.size());
            if block.windows(SECRET.len()).any(|w| w == SECRET) {
                UNWIPED.fetch_add(1, Ordering::SeqCst);
            }
        }
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static ALLOCATOR: Watching = Watching;

#[test]
fn every_value_the_cache_frees_is_wiped() {
    let hydrated = vec![(b"held".to_vec(), SECRET.to_vec())];
    UNWIPED.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    {
        let kv = CacheKv::hydrated(hydrated);
        // Replaced, in the map and in what is owed.
        kv.put(b"k", &SECRET).expect("a put");
        kv.put(b"k", b"other").expect("a put");
        // Deleted, then put back by a rollback, then deleted for good.
        kv.delete(b"held").expect("a delete");
        kv.rollback().expect("a rollback");
        kv.put(b"j", &SECRET).expect("a put");
        let pending = kv.peek_pending();
        kv.commit_pending(&pending);
        drop(pending);
        kv.flush().expect("the operation ends");
        kv.delete(b"held").expect("a delete");
        kv.flush().expect("the operation ends");
        // The rest goes with the cache.
        drop(kv);
    }
    ARMED.store(false, Ordering::SeqCst);
    assert_eq!(
        UNWIPED.load(Ordering::SeqCst),
        0,
        "a block the cache freed still held a value"
    );
}
