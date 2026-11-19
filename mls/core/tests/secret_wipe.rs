// SPDX-License-Identifier: MIT
//! The device seed is wiped from every heap block the core frees.
//!
//! An allocator stands in front of the system's for this test binary and
//! looks at every block as it is freed. While a client opens on a seed, makes
//! a group, publishes key packages, seals a message and is dropped, a freed
//! block that still holds the seed, or the X25519 secret derived from it, is
//! counted: those bytes outlived the core's use of them in memory a later
//! allocation can be handed. One test in this file, so no other test's frees
//! run beside it.
//!
//! The seed half is a guard rather than a pin: the seed travels on the stack
//! and in wiping buffers, and no path today puts a plain copy of it on the
//! heap. The account-key half pins the box opener's buffer. The secrets the
//! core seals and opens for others are pinned in `secret_wipe_frames.rs`.

mod support;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use peachy_mls_core::{Client, ClientConfig, PeachyStorage};
use sha2::Digest as _;
use support::{held_identity, issuer, TestClock, DAY, HOUR, NOW};

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
            // `try_lock`: the needles are never freed while armed, and a
            // dealloc must not wait on a lock.
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

#[test]
fn the_core_wipes_the_device_seed_and_the_account_key_from_what_it_frees() {
    // A seed with no run of zeros in it, so a wiped block cannot match it.
    let seed: [u8; 32] = sha2::Sha256::digest(b"peachy secret wipe test seed").into();
    let x25519: [u8; 32] = sha2::Sha512::digest(seed)[..32]
        .try_into()
        .expect("32 bytes");
    let server = issuer();
    let (_, public) = peachy_mls_core::issuer::device_key_pair(&seed);
    let token = server
        .issue(
            "actor-ada",
            "device-ada-phone",
            &public,
            NOW - HOUR,
            NOW + 30 * DAY,
        )
        .expect("mint");
    let trusted = server.trusted_keys().expect("trusted keys");
    *NEEDLES.lock().expect("needles") = vec![seed.to_vec(), x25519.to_vec()];

    ARMED.store(true, Ordering::SeqCst);
    {
        let mut config = ClientConfig::new(token, seed, trusted)
            .with_storage(PeachyStorage::in_memory())
            .with_own_account_identity(Some(held_identity("actor-ada")));
        config.clock = Some(Box::new(TestClock));
        let mut ada = Client::new(config).expect("open");
        ada.create_group(b"peachy-group-wipe").expect("create");
        ada.generate_key_package().expect("a key package");
        ada.encrypt(b"peachy-group-wipe", b"hello")
            .expect("encrypt");
    }
    ARMED.store(false, Ordering::SeqCst);

    assert_eq!(
        UNWIPED.load(Ordering::SeqCst),
        0,
        "a block the core freed still held the device seed or its X25519 secret"
    );

    // The account key, opened out of the box an approver sealed to this
    // device: the core decrypts it into a buffer of its own before handing
    // the 32 bytes back, and that buffer is wiped.
    let account_key: [u8; 32] = sha2::Sha256::digest(b"peachy secret wipe account key").into();
    let approver_seed: [u8; 32] = sha2::Sha256::digest(b"peachy secret wipe approver").into();
    let (_, approver_public) = peachy_mls_core::issuer::device_key_pair(&approver_seed);
    let sealed = peachy_mls_core::account_key_seal(
        &approver_seed,
        &public,
        "device-ada-phone",
        &account_key,
    )
    .expect("seal the account key");
    *NEEDLES.lock().expect("needles") = vec![account_key.to_vec()];
    UNWIPED.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    let opened =
        peachy_mls_core::account_key_open(&seed, &approver_public, "device-ada-phone", &sealed);
    ARMED.store(false, Ordering::SeqCst);
    assert_eq!(opened.expect("open the box"), account_key);
    assert_eq!(
        UNWIPED.load(Ordering::SeqCst),
        0,
        "a block the core freed still held the opened account key"
    );
}
