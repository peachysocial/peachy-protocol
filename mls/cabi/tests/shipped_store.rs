// SPDX-License-Identifier: MIT
//! The store door as a shipped archive builds it: no
//! `insecure-plaintext-store`, so a store path with no store key is refused
//! before any file is made. A file in
//! the clear would hold every group secret for any reader of the disk.
//!
//! Its own test target, and not one of `tests/abi.rs`, because that suite
//! opens files in the clear on purpose and so needs `insecure-plaintext-store`.
//! The release checks run this one with no features; under that feature it
//! checks that the test build still opens such a file.

use std::ffi::{CStr, CString};

use peachy_mls_cabi::*;
use peachy_mls_core::issuer::{device_key_pair, TestIssuer};

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn last_error() -> String {
    let ptr = peachy_mls_last_error();
    if ptr.is_null() {
        return "(no error)".to_string();
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

#[test]
fn a_store_path_with_no_store_key_opens_only_in_a_test_build() {
    let issuer = TestIssuer::from_seed(&[7u8; 32]);
    let trusted = CString::new(issuer.published_json()).expect("no NUL");
    let mut seed = [0u8; 32];
    seed[0] = 1;
    seed[1] = 0xA5;
    let (_, public) = device_key_pair(&seed);
    let token = issuer
        .issue(
            "actor-ada",
            "device-ada",
            &public,
            now_unix() - 3_600,
            now_unix() + 86_400,
        )
        .expect("mint");
    let held =
        peachy_mls_core::account_identity_public_key(&TestIssuer::test_account_key("actor-ada"))
            .expect("derive");

    let dir = std::env::temp_dir().join(format!("peachy-mls-shipped-store-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let path = dir.join("ada.sqlite3");
    let path_c = CString::new(path.to_str().expect("a UTF-8 path")).expect("no NUL");

    let mut client: *mut PeachyMlsClient = std::ptr::null_mut();
    let status = unsafe {
        peachy_mls_client_open(
            token.as_ptr(),
            token.len(),
            seed.as_ptr(),
            seed.len(),
            trusted.as_ptr(),
            path_c.as_ptr(),
            std::ptr::null(),
            0,
            held.as_ptr(),
            held.len(),
            &mut client,
        )
    };
    if cfg!(feature = "insecure-plaintext-store") {
        assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
        assert!(!client.is_null());
        unsafe { peachy_mls_client_free(client) };
    } else {
        assert_eq!(status, PEACHY_MLS_ERR_INVALID_ARGUMENT, "{}", last_error());
        assert!(client.is_null());
        assert!(
            !path.exists(),
            "the refused open made no file to hold secrets in the clear"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The unvouched account-key opener refuses in a shipped archive, whatever it
/// is handed: whoever lists the approver would pick the key it opens to. A
/// `fixture` build opens with it (tests/abi.rs).
#[test]
fn the_unvouched_account_key_opener_refuses_in_a_shipped_build() {
    let seed = [1u8; 32];
    let approver = [2u8; 32];
    let id = CString::new("device-ada").expect("no NUL");
    let sealed = [1u8; 93];
    let mut out = PeachyMlsBuffer {
        data: std::ptr::null_mut(),
        len: 0,
    };
    let status = unsafe {
        peachy_mls_account_key_open(
            seed.as_ptr(),
            seed.len(),
            approver.as_ptr(),
            approver.len(),
            id.as_ptr(),
            sealed.as_ptr(),
            sealed.len(),
            &mut out,
        )
    };
    if cfg!(feature = "fixture") {
        // Garbage still does not open; the door is there.
        assert_ne!(status, PEACHY_MLS_ERR_UNSUPPORTED, "{}", last_error());
    } else {
        assert_eq!(status, PEACHY_MLS_ERR_UNSUPPORTED, "{}", last_error());
    }
    assert_eq!(out.len, 0);
}
