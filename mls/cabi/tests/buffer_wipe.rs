// SPDX-License-Identifier: MIT
//! What the C door hands out is wiped before its memory goes back.
//!
//! An allocator stands in front of the system's for this test binary and
//! looks at every block as it is freed. While a door call and its
//! `peachy_mls_buffer_free` run, a freed block that still holds the secret
//! the door handed out is counted: the bytes outlived the free in memory
//! any later allocation can be given. One test in this file, so no other
//! test's frees run beside it.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use peachy_mls_cabi::*;

struct Watching;

static ARMED: AtomicBool = AtomicBool::new(false);
static UNWIPED: AtomicUsize = AtomicUsize::new(0);
static NEEDLE: Mutex<Vec<u8>> = Mutex::new(Vec::new());

unsafe impl GlobalAlloc for Watching {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::SeqCst) {
            // `try_lock`: the needle's own vector is never freed while armed,
            // and a dealloc must not wait on a lock.
            if let Ok(needle) = NEEDLE.try_lock() {
                let block = std::slice::from_raw_parts(ptr, layout.size());
                if !needle.is_empty() && block.windows(needle.len()).any(|w| w == &needle[..]) {
                    UNWIPED.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static ALLOCATOR: Watching = Watching;

fn watch_for(secret: &[u8]) {
    let mut needle = NEEDLE.lock().expect("the needle");
    needle.clear();
    needle.extend_from_slice(secret);
}

#[test]
fn the_buffers_the_door_hands_out_are_wiped_when_freed() {
    // A decrypted store record: the core opens it into a vector with spare
    // capacity (the padding is cut off in place), which the door copies into
    // an exact allocation for the caller.
    let account_key = [0x42u8; 32];
    let id = [0x07u8; 16];
    let plaintext: Vec<u8> = b"peachy wipe marker: a sentence nobody else writes".to_vec();
    let mut sealed = PeachyMlsBuffer {
        data: std::ptr::null_mut(),
        len: 0,
    };
    let status = unsafe {
        peachy_mls_store_seal(
            account_key.as_ptr(),
            account_key.len(),
            id.as_ptr(),
            id.len(),
            plaintext.as_ptr(),
            plaintext.len(),
            &mut sealed,
        )
    };
    assert_eq!(status, PEACHY_MLS_OK, "seal the record");

    watch_for(&plaintext);
    UNWIPED.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    let mut opened = PeachyMlsBuffer {
        data: std::ptr::null_mut(),
        len: 0,
    };
    let status = unsafe {
        peachy_mls_store_open(
            account_key.as_ptr(),
            account_key.len(),
            id.as_ptr(),
            id.len(),
            sealed.data,
            sealed.len,
            &mut opened,
        )
    };
    let read = unsafe { std::slice::from_raw_parts(opened.data, opened.len) } == &plaintext[..];
    unsafe { peachy_mls_buffer_free(&mut opened) };
    ARMED.store(false, Ordering::SeqCst);
    assert_eq!(status, PEACHY_MLS_OK, "open the record");
    assert!(read, "the record opens to its plaintext");
    assert_eq!(
        UNWIPED.load(Ordering::SeqCst),
        0,
        "a freed block still held the opened plaintext"
    );
    unsafe { peachy_mls_buffer_free(&mut sealed) };

    // A fresh account key: an exact allocation, handed out as it is.
    UNWIPED.store(0, Ordering::SeqCst);
    let mut key = PeachyMlsBuffer {
        data: std::ptr::null_mut(),
        len: 0,
    };
    let status = unsafe { peachy_mls_generate_account_key(&mut key) };
    assert_eq!(status, PEACHY_MLS_OK, "generate an account key");
    let mut copy = [0u8; 32];
    copy.copy_from_slice(unsafe { std::slice::from_raw_parts(key.data, key.len) });
    watch_for(&copy);
    ARMED.store(true, Ordering::SeqCst);
    unsafe { peachy_mls_buffer_free(&mut key) };
    ARMED.store(false, Ordering::SeqCst);
    assert!(
        key.data.is_null() && key.len == 0,
        "the buffer reads as empty"
    );
    assert_eq!(
        UNWIPED.load(Ordering::SeqCst),
        0,
        "the freed account key buffer still held the key"
    );
}
