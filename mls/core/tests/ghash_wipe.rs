// SPDX-License-Identifier: MIT
//! An AES-GCM cipher wipes its GHASH key when it drops, on every target the
//! core builds for (docs/mls-core.md §Security considerations).
//!
//! The key is POLYVAL's `h`, derived from the cipher key as
//! `mulx(reverse(AES_K(0^128)))`. Only polyval's portable backend wipes it:
//! ARM runs that one (the PMULL backend is opt-in), and on x86, where polyval
//! picks a backend at run time and that dispatch never drops it,
//! mls/.cargo/config.toml forces the portable one. CI runs this test on
//! both: ARM in its Swift job, on a Mac, and x86_64 in its Rust job, so
//! dropping the config, or turning the PMULL backend on, turns it red there.
//!
//! An allocator stands in front of the system's and counts freed blocks that
//! still hold the key. One test in this file, so no other test's frees run
//! beside it.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use aes::cipher::BlockEncrypt;
use aes_gcm::{Aes256Gcm, KeyInit};

struct Watching;
static ARMED: AtomicBool = AtomicBool::new(false);
static HITS: AtomicUsize = AtomicUsize::new(0);
static NEEDLE: Mutex<Vec<u8>> = Mutex::new(Vec::new());

unsafe impl GlobalAlloc for Watching {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::SeqCst) {
            // `try_lock`: the needle is never freed while armed, and a
            // dealloc must not wait on a lock.
            if let Ok(needle) = NEEDLE.try_lock() {
                let block = std::slice::from_raw_parts(ptr, layout.size());
                if !needle.is_empty() && block.windows(needle.len()).any(|w| w == &needle[..]) {
                    HITS.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static ALLOCATOR: Watching = Watching;

/// How many freed blocks held the needle while `run` ran.
fn hits(run: impl FnOnce()) -> usize {
    HITS.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    run();
    ARMED.store(false, Ordering::SeqCst);
    HITS.load(Ordering::SeqCst)
}

#[test]
fn a_dropped_aes_gcm_cipher_leaves_no_copy_of_its_ghash_key() {
    let key = [0x5Au8; 32];
    let mut h = aes::Block::default();
    aes::Aes256::new(&key.into()).encrypt_block(&mut h);
    h.reverse();
    let ghash_key = polyval::mulx(&h);
    *NEEDLE.lock().expect("needle") = ghash_key.to_vec();

    // The instrument sees an unwiped copy.
    let copy: [u8; 16] = ghash_key.into();
    assert_eq!(
        hits(|| drop(std::hint::black_box(Box::new(copy)))),
        1,
        "the instrument"
    );

    // A cipher on the heap, as the core keeps one across a call.
    let cipher = Box::new(Aes256Gcm::new(&key.into()));
    assert_eq!(
        hits(|| drop(std::hint::black_box(cipher))),
        0,
        "a dropped AES-GCM cipher freed its GHASH key unwiped on {}",
        std::env::consts::ARCH
    );
}
