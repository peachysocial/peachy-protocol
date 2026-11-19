// SPDX-License-Identifier: MIT
//! What a wrapper is allowed to assume about threads.
//!
//! The C ABI is not thread-safe and says so: one client is one device's MLS
//! state, and callers serialise (`mls/cabi/src/lib.rs`, module header). But
//! "serialise" is two different promises, and a wrapper needs to know which
//! one it can make:
//!
//!   - `Sync` would mean two threads may be inside the library on one client
//!     at the same time. This crate does not claim it and a wrapper must not
//!     assume it.
//!   - `Send` means one client may MOVE between threads, one at a time. That
//!     is what a lock in a wrapper buys, and it is the difference between
//!     Swift's `MLSClient` being safely `@unchecked Sendable` and being a data
//!     race with a lock drawn around it.
//!
//! So this file is the compile-time half of `docs/mls-core.md` §Swift binding:
//! if a future storage provider or a dependency bump makes `Client` non-`Send`
//! — an `Rc` somewhere is all it takes — this stops compiling, here, rather
//! than becoming a rare crash in an app that shared one across a task boundary.

use peachy_mls_core::Client;

fn assert_send<T: Send>() {}

#[test]
fn a_client_may_move_between_threads() {
    assert_send::<Client>();
}

/// And the move is real, not just a trait bound: build a client, hand it to
/// another thread, and drive a whole group from there.
#[test]
fn a_client_works_after_moving_to_another_thread() {
    use peachy_mls_core::issuer::{device_key_pair, TestIssuer};
    use peachy_mls_core::ClientConfig;

    let issuer = TestIssuer::from_seed(&[19u8; 32]);
    let trusted = issuer.trusted_keys().expect("trusted keys");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let seed = [23u8; 32];
    let (_, public) = device_key_pair(&seed);
    let token = issuer
        .issue("actor-ada", "device-ada", &public, now - 3_600, now + 3_600)
        .expect("mint");
    // The device holds the account key `issue` certifies it under.
    let held =
        peachy_mls_core::account_identity_public_key(&TestIssuer::test_account_key("actor-ada"))
            .expect("derive");
    let client =
        Client::new(ClientConfig::new(token, seed, trusted).with_own_account_identity(Some(held)))
            .expect("client");

    let handle = std::thread::spawn(move || {
        let mut client = client;
        client.create_group(b"moved").expect("create");
        let message = client.encrypt(b"moved", b"hello from another thread");
        message.expect("encrypt").len()
    });
    assert!(handle.join().expect("the thread should not panic") > 0);
}
