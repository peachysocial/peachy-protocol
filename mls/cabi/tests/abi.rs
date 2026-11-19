// SPDX-License-Identifier: MIT
//! The same journey as `peachy-mls-core`'s end-to-end test, driven entirely
//! through the C entry points.
//!
//! Rust calling its own `extern "C"` functions is not a C compiler, and this
//! test does not pretend otherwise: what it exercises is the ownership
//! discipline — out-parameters, explicit frees, the status codes, the
//! last-error slot — which is where a C ABI goes wrong long before the calling
//! convention does.

use std::ffi::{CStr, CString};

use peachy_mls_cabi::*;
use peachy_mls_core::issuer::{device_key_pair, TestIssuer};

const DAY: i64 = 24 * 3_600;

/// The C ABI has no clock override, deliberately — nothing outside a test
/// would want one, and an injectable clock at that boundary is a foot-gun
/// shaped like a feature. So these tests mint against the real clock instead
/// of the fixed instant `peachy-mls-core`'s own tests use.
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

struct Fixture {
    issuer: TestIssuer,
    trusted_json: CString,
}

impl Fixture {
    fn new() -> Self {
        let issuer = TestIssuer::from_seed(&[7u8; 32]);
        let trusted_json =
            CString::new(issuer.published_json()).expect("the published JSON has no NUL");
        Self {
            issuer,
            trusted_json,
        }
    }

    /// The account identity key a device of `actor` holds: the one derived
    /// from the stand-in account key [`TestIssuer::issue`] certifies it under.
    /// A device holding no key opens only an uncertified credential, so every
    /// client opened on one of these names it.
    fn held(actor: &str) -> [u8; 32] {
        peachy_mls_core::account_identity_public_key(&TestIssuer::test_account_key(actor))
            .expect("derive")
    }

    /// Open a client through `peachy_mls_client_open`, in memory, naming the
    /// account identity key `own` (or none).
    fn open_in_memory(
        &self,
        token: &[u8],
        seed: &[u8; 32],
        own: Option<&[u8; 32]>,
    ) -> (i32, *mut PeachyMlsClient) {
        let mut client: *mut PeachyMlsClient = std::ptr::null_mut();
        let status = unsafe {
            peachy_mls_client_open(
                token.as_ptr(),
                token.len(),
                seed.as_ptr(),
                seed.len(),
                self.trusted_json.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                own.map_or(std::ptr::null(), |key| key.as_ptr()),
                own.map_or(0, |key| key.len()),
                &mut client,
            )
        };
        (status, client)
    }

    /// The `pdc1` token and seed for a device, minted fresh.
    fn identity(&self, tag: u8, actor: &str, device: &str) -> ([u8; 32], Vec<u8>) {
        let mut seed = [0u8; 32];
        seed[0] = tag;
        seed[1] = 0xA5;
        let (_, public) = device_key_pair(&seed);
        let token = self
            .issuer
            .issue(
                actor,
                device,
                &public,
                now_unix() - DAY,
                now_unix() + 30 * DAY,
            )
            .expect("mint");
        (seed, token)
    }

    /// A client through the C door, in memory, naming the account identity
    /// key its device holds. Returns the raw pointer the ABI hands out.
    ///
    /// Through `peachy_mls_client_open` with a null path rather than
    /// `peachy_mls_client_new`: that door names no key, so it opens only an
    /// uncertified credential (`a_client_holding_no_key_opens_only_uncertified`
    /// keeps it exercised).
    fn client(&self, tag: u8, actor: &str, device: &str) -> *mut PeachyMlsClient {
        let (seed, token) = self.identity(tag, actor, device);
        let (status, client) = self.open_in_memory(&token, &seed, Some(&Self::held(actor)));
        assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
        assert!(!client.is_null());
        client
    }

    /// [`Fixture::client`] under an account identity key of the caller's
    /// choosing: the same person after losing every device and coming back
    /// under a new account key.
    fn client_for_account(
        &self,
        tag: u8,
        actor: &str,
        device: &str,
        account_key: &[u8; 32],
    ) -> *mut PeachyMlsClient {
        let mut seed = [0u8; 32];
        seed[0] = tag;
        seed[1] = 0xA5;
        let (_, public) = device_key_pair(&seed);
        let token = self
            .issuer
            .issue_for_account(
                actor,
                device,
                &public,
                Some(account_key),
                now_unix() - DAY,
                now_unix() + 30 * DAY,
            )
            .expect("mint");
        let held = peachy_mls_core::account_identity_public_key(account_key).expect("derive");
        let (status, client) = self.open_in_memory(&token, &seed, Some(&held));
        assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
        assert!(!client.is_null());
        client
    }

    /// A client through `peachy_mls_client_open`, with a store path when there
    /// is one and a null pointer when there is not.
    fn client_on(
        &self,
        tag: u8,
        actor: &str,
        device: &str,
        store_path: Option<&str>,
    ) -> *mut PeachyMlsClient {
        self.client_keyed(tag, actor, device, store_path, None)
    }

    /// [`Fixture::client_on`] with a SQLCipher store key.
    fn client_keyed(
        &self,
        tag: u8,
        actor: &str,
        device: &str,
        store_path: Option<&str>,
        store_key: Option<&[u8]>,
    ) -> *mut PeachyMlsClient {
        let status_and_client = self.try_client_keyed(tag, actor, device, store_path, store_key);
        assert_eq!(status_and_client.0, PEACHY_MLS_OK, "{}", last_error());
        assert!(!status_and_client.1.is_null());
        status_and_client.1
    }

    fn try_client_keyed(
        &self,
        tag: u8,
        actor: &str,
        device: &str,
        store_path: Option<&str>,
        store_key: Option<&[u8]>,
    ) -> (i32, *mut PeachyMlsClient) {
        let (seed, token) = self.identity(tag, actor, device);
        let held = Self::held(actor);
        let path = store_path.map(|path| CString::new(path).expect("a path with no NUL"));
        let path_ptr = path
            .as_ref()
            .map(|path| path.as_ptr())
            .unwrap_or(std::ptr::null());

        let mut client: *mut PeachyMlsClient = std::ptr::null_mut();
        let status = unsafe {
            peachy_mls_client_open(
                token.as_ptr(),
                token.len(),
                seed.as_ptr(),
                seed.len(),
                self.trusted_json.as_ptr(),
                path_ptr,
                store_key.map_or(std::ptr::null(), |key| key.as_ptr()),
                store_key.map_or(0, |key| key.len()),
                held.as_ptr(),
                held.len(),
                &mut client,
            )
        };
        (status, client)
    }
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

fn empty_buffer() -> PeachyMlsBuffer {
    PeachyMlsBuffer {
        data: std::ptr::null_mut(),
        len: 0,
    }
}

fn bytes_of(buffer: &PeachyMlsBuffer) -> Vec<u8> {
    if buffer.data.is_null() || buffer.len == 0 {
        return Vec::new();
    }
    unsafe { std::slice::from_raw_parts(buffer.data, buffer.len) }.to_vec()
}

/// A string list as the boundary carries it, written independently of the
/// library's own encoder: a u32 big-endian count, then each item as a u32
/// big-endian length and its bytes.
fn string_list(items: &[&str]) -> Vec<u8> {
    let mut out = (items.len() as u32).to_be_bytes().to_vec();
    for item in items {
        out.extend_from_slice(&(item.len() as u32).to_be_bytes());
        out.extend_from_slice(item.as_bytes());
    }
    out
}

/// Read a string list the library wrote; an empty buffer is no list.
fn read_string_list(bytes: &[u8]) -> Vec<String> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let u32_at = |at: usize| u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
    let count = u32_at(0);
    let mut at = 4;
    let mut items = Vec::new();
    for _ in 0..count {
        let len = u32_at(at);
        at += 4;
        items.push(String::from_utf8(bytes[at..at + len].to_vec()).expect("UTF-8"));
        at += len;
    }
    assert_eq!(at, bytes.len(), "consumed exactly");
    items
}

/// The delivery service said yes. Every commit-producing door here STAGES
/// (`mls/core/src/group.rs` §The commit lifecycle), so every one of them is
/// followed by this or by `clear`; these tests stand in for a server that takes
/// everything. Returns the new epoch.
fn merge(client: *mut PeachyMlsClient, group: &[u8]) -> u64 {
    let mut epoch = 0u64;
    assert_eq!(
        unsafe {
            peachy_mls_group_merge_pending_commit(client, group.as_ptr(), group.len(), &mut epoch)
        },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    epoch
}

#[test]
fn the_whole_journey_through_the_c_entry_points() {
    let fixture = Fixture::new();
    let ada = fixture.client(1, "actor-ada", "device-ada");
    let bo = fixture.client(2, "actor-bo", "device-bo");
    let cy = fixture.client(3, "actor-cy", "device-cy");
    let group = b"peachy-cabi";

    // Identity comes back as two buffers the caller owns.
    let mut actor = empty_buffer();
    let mut device = empty_buffer();
    assert_eq!(
        unsafe { peachy_mls_client_identity(ada, &mut actor, &mut device) },
        PEACHY_MLS_OK
    );
    assert_eq!(bytes_of(&actor), b"actor-ada");
    assert_eq!(bytes_of(&device), b"device-ada");
    unsafe {
        peachy_mls_buffer_free(&mut actor);
        peachy_mls_buffer_free(&mut device);
    }
    // Freed twice on purpose: the second must be a no-op, not a crash.
    unsafe { peachy_mls_buffer_free(&mut actor) };
    assert!(actor.data.is_null());

    // create
    assert_eq!(
        unsafe { peachy_mls_group_create(ada, group.as_ptr(), group.len()) },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );

    // add Bo
    let mut bo_kp = empty_buffer();
    assert_eq!(
        unsafe { peachy_mls_key_package(bo, &mut bo_kp) },
        PEACHY_MLS_OK
    );
    let mut commit = empty_buffer();
    let mut welcome = empty_buffer();
    assert_eq!(
        unsafe {
            peachy_mls_group_add_member(
                ada,
                group.as_ptr(),
                group.len(),
                bo_kp.data,
                bo_kp.len,
                &mut commit,
                &mut welcome,
            )
        },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    assert!(!welcome.data.is_null(), "adding produces a Welcome");
    assert_eq!(merge(ada, group), 1, "the delivery service takes the add");

    let mut joined = empty_buffer();
    assert_eq!(
        unsafe { peachy_mls_group_join(bo, welcome.data, welcome.len, &mut joined) },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    assert_eq!(bytes_of(&joined), group);
    unsafe {
        peachy_mls_buffer_free(&mut bo_kp);
        peachy_mls_buffer_free(&mut commit);
        peachy_mls_buffer_free(&mut welcome);
        peachy_mls_buffer_free(&mut joined);
    }

    // add Cy, so somebody is left after the removal
    let mut cy_kp = empty_buffer();
    assert_eq!(
        unsafe { peachy_mls_key_package(cy, &mut cy_kp) },
        PEACHY_MLS_OK
    );
    let mut commit = empty_buffer();
    let mut welcome = empty_buffer();
    assert_eq!(
        unsafe {
            peachy_mls_group_add_member(
                ada,
                group.as_ptr(),
                group.len(),
                cy_kp.data,
                cy_kp.len,
                &mut commit,
                &mut welcome,
            )
        },
        PEACHY_MLS_OK
    );
    assert_eq!(merge(ada, group), 2);
    // Bo follows the commit.
    let mut incoming = process(bo, group, &commit, PEACHY_MLS_DOOR_COMMIT);
    assert_eq!(incoming.kind, PEACHY_MLS_INCOMING_COMMIT);
    assert_eq!(bytes_of(&incoming.sender_actor_id), b"actor-ada");
    assert!(!incoming.removed_self);
    unsafe { peachy_mls_incoming_free(&mut incoming) };

    let mut joined = empty_buffer();
    assert_eq!(
        unsafe { peachy_mls_group_join(cy, welcome.data, welcome.len, &mut joined) },
        PEACHY_MLS_OK
    );
    unsafe {
        peachy_mls_buffer_free(&mut cy_kp);
        peachy_mls_buffer_free(&mut commit);
        peachy_mls_buffer_free(&mut welcome);
        peachy_mls_buffer_free(&mut joined);
    }

    // The roster is reachable, and it identifies everybody.
    let mut count = 0usize;
    assert_eq!(
        unsafe { peachy_mls_group_member_count(ada, group.as_ptr(), group.len(), &mut count) },
        PEACHY_MLS_OK
    );
    assert_eq!(count, 3);
    let mut actors = Vec::new();
    let mut bo_leaf = u32::MAX;
    let mut bo_roster_key = Vec::new();
    for position in 0..count {
        let mut leaf = 0u32;
        let mut actor = empty_buffer();
        let mut device = empty_buffer();
        let mut device_key = empty_buffer();
        let mut leaf_key = empty_buffer();
        let mut rejection = 1u32;
        assert_eq!(
            unsafe {
                peachy_mls_group_member(
                    ada,
                    group.as_ptr(),
                    group.len(),
                    position,
                    &mut leaf,
                    &mut actor,
                    &mut device,
                    &mut device_key,
                    &mut leaf_key,
                    &mut rejection,
                )
            },
            PEACHY_MLS_OK
        );
        assert_eq!(rejection, 0, "every leaf in this group verifies");
        assert_eq!(
            device_key.len, 32,
            "every verified leaf hands back an Ed25519 public key"
        );
        assert_eq!(
            bytes_of(&leaf_key),
            bytes_of(&device_key),
            "a verified leaf's tree key is the device key its credential binds"
        );
        unsafe { peachy_mls_buffer_free(&mut leaf_key) };
        if bytes_of(&device) == b"device-bo" {
            bo_leaf = leaf;
            bo_roster_key = bytes_of(&device_key);
        }
        actors.push(String::from_utf8(bytes_of(&actor)).expect("utf-8"));
        unsafe {
            peachy_mls_buffer_free(&mut actor);
            peachy_mls_buffer_free(&mut device);
            peachy_mls_buffer_free(&mut device_key);
        }
    }
    actors.sort();
    assert_eq!(actors, vec!["actor-ada", "actor-bo", "actor-cy"]);
    assert_ne!(bo_leaf, u32::MAX);

    // THE assertion this out-parameter exists for: the 32 bytes the roster
    // hands back are Bo's real signing key, the one his own seed derives — the
    // same value `mls/wasm/src/lib.rs`'s `IdentityDto` serializes as
    // `device_key` on every roster entry, so the bindings cannot disagree
    // about which key a seated leaf holds. An adder checking a device approval
    // against a leaf ALREADY in the group has nowhere else to get this from:
    // a key taken from the directory that served the approval is a key the
    // directory got to choose.
    let (_, bo_public) = device_key_pair(&{
        let mut seed = [0u8; 32];
        seed[0] = 2;
        seed[1] = 0xA5;
        seed
    });
    assert_eq!(
        bo_roster_key,
        bo_public.to_vec(),
        "the roster's device key is the leaf's own signing key"
    );

    // And a caller that wants only some of it may pass NULL for the rest,
    // exactly as for the other out-parameters.
    let mut only_key = empty_buffer();
    assert_eq!(
        unsafe {
            peachy_mls_group_member(
                ada,
                group.as_ptr(),
                group.len(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut only_key,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        },
        PEACHY_MLS_OK
    );
    assert_eq!(only_key.len, 32);
    unsafe { peachy_mls_buffer_free(&mut only_key) };

    // Every certified leaf names its ACCOUNT identity key, the security
    // code's input (docs/identity.md §The security code): 32 bytes,
    // one per actor, so three actors give three distinct keys.
    let mut account_keys = Vec::new();
    for position in 0..count {
        let mut account_key = empty_buffer();
        assert_eq!(
            unsafe {
                peachy_mls_group_member_account_key(
                    ada,
                    group.as_ptr(),
                    group.len(),
                    position,
                    &mut account_key,
                )
            },
            PEACHY_MLS_OK
        );
        assert_eq!(
            account_key.len, 32,
            "a certified leaf names its account key"
        );
        account_keys.push(bytes_of(&account_key));
        unsafe { peachy_mls_buffer_free(&mut account_key) };
    }
    account_keys.sort();
    account_keys.dedup();
    assert_eq!(
        account_keys.len(),
        3,
        "each actor has an account key of its own"
    );
    let mut past_the_end = empty_buffer();
    assert_ne!(
        unsafe {
            peachy_mls_group_member_account_key(
                ada,
                group.as_ptr(),
                group.len(),
                count,
                &mut past_the_end,
            )
        },
        PEACHY_MLS_OK
    );

    // application messages, both directions
    let mut message = empty_buffer();
    let plaintext = b"through the boundary";
    assert_eq!(
        unsafe {
            peachy_mls_group_encrypt(
                ada,
                group.as_ptr(),
                group.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                &mut message,
            )
        },
        PEACHY_MLS_OK
    );
    let mut incoming = process(bo, group, &message, PEACHY_MLS_DOOR_MESSAGE);
    assert_eq!(incoming.kind, PEACHY_MLS_INCOMING_APPLICATION);
    assert_eq!(bytes_of(&incoming.plaintext), plaintext);
    assert_eq!(bytes_of(&incoming.sender_device_id), b"device-ada");
    unsafe { peachy_mls_incoming_free(&mut incoming) };
    unsafe { peachy_mls_buffer_free(&mut message) };

    let mut back = empty_buffer();
    let reply = b"and back";
    assert_eq!(
        unsafe {
            peachy_mls_group_encrypt(
                bo,
                group.as_ptr(),
                group.len(),
                reply.as_ptr(),
                reply.len(),
                &mut back,
            )
        },
        PEACHY_MLS_OK
    );
    let mut incoming = process(ada, group, &back, PEACHY_MLS_DOOR_MESSAGE);
    assert_eq!(bytes_of(&incoming.plaintext), reply);
    unsafe { peachy_mls_incoming_free(&mut incoming) };
    unsafe { peachy_mls_buffer_free(&mut back) };

    // exported secrets agree
    let label = CString::new("peachy cabi test").expect("no NUL");
    let mut mine = empty_buffer();
    let mut theirs = empty_buffer();
    assert_eq!(
        unsafe {
            peachy_mls_group_export_secret(
                ada,
                group.as_ptr(),
                group.len(),
                label.as_ptr(),
                std::ptr::null(),
                0,
                32,
                &mut mine,
            )
        },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    assert_eq!(
        unsafe {
            peachy_mls_group_export_secret(
                bo,
                group.as_ptr(),
                group.len(),
                label.as_ptr(),
                std::ptr::null(),
                0,
                32,
                &mut theirs,
            )
        },
        PEACHY_MLS_OK
    );
    assert_eq!(bytes_of(&mine), bytes_of(&theirs));
    assert_eq!(mine.len, 32);
    unsafe {
        peachy_mls_buffer_free(&mut mine);
        peachy_mls_buffer_free(&mut theirs);
    }

    // a typing frame: sealed and signed by Ada, opened by Bo once
    let mut frame = empty_buffer();
    assert_eq!(
        unsafe { peachy_mls_group_typing_seal(ada, group.as_ptr(), group.len(), true, &mut frame) },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    let frame_bytes = bytes_of(&frame);
    unsafe { peachy_mls_buffer_free(&mut frame) };
    let open_typing = |frame: &[u8]| {
        let mut json = empty_buffer();
        assert_eq!(
            unsafe {
                peachy_mls_group_typing_open(
                    bo,
                    group.as_ptr(),
                    group.len(),
                    frame.as_ptr(),
                    frame.len(),
                    &mut json,
                )
            },
            PEACHY_MLS_OK,
            "{}",
            last_error()
        );
        let text = String::from_utf8(bytes_of(&json)).expect("utf-8");
        unsafe { peachy_mls_buffer_free(&mut json) };
        text
    };
    assert_eq!(
        open_typing(&frame_bytes),
        r#"{"actorId":"actor-ada","typing":true}"#
    );
    assert_eq!(open_typing(&frame_bytes), "null", "a replay is dropped");

    // a resendable message commits to its author, readable with no key
    let said = b"\xff\x05{\"i\":\"0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d\",\"t\":\"hi\",\"a\":[]}";
    let mut sealed = empty_buffer();
    assert_eq!(
        unsafe {
            peachy_mls_group_encrypt_with_hint(
                ada,
                group.as_ptr(),
                group.len(),
                said.as_ptr(),
                said.len(),
                1,
                &mut sealed,
            )
        },
        PEACHY_MLS_OK
    );
    let sealed_bytes = bytes_of(&sealed);
    let mut carried = empty_buffer();
    assert_eq!(
        unsafe {
            peachy_mls_peek_commitment(sealed_bytes.as_ptr(), sealed_bytes.len(), &mut carried)
        },
        PEACHY_MLS_OK
    );
    let actor = CString::new("actor-ada").expect("no NUL");
    let secret = b"0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
    let mut expected = empty_buffer();
    assert_eq!(
        unsafe {
            peachy_mls_resend_author_commitment(
                group.as_ptr(),
                group.len(),
                actor.as_ptr(),
                secret.as_ptr(),
                secret.len(),
                &mut expected,
            )
        },
        PEACHY_MLS_OK
    );
    assert_eq!(carried.len, 16);
    assert_eq!(bytes_of(&carried), bytes_of(&expected));
    unsafe {
        peachy_mls_buffer_free(&mut carried);
        peachy_mls_buffer_free(&mut expected);
    }
    let mut incoming = process(bo, group, &sealed, PEACHY_MLS_DOOR_MESSAGE);
    assert_eq!(bytes_of(&incoming.plaintext), said);
    unsafe {
        peachy_mls_incoming_free(&mut incoming);
        peachy_mls_buffer_free(&mut sealed);
    }

    // self-update moves the epoch for everybody
    let mut before = 0u64;
    assert_eq!(
        unsafe { peachy_mls_group_epoch(ada, group.as_ptr(), group.len(), &mut before) },
        PEACHY_MLS_OK
    );
    let mut commit = empty_buffer();
    assert_eq!(
        unsafe { peachy_mls_group_self_update(ada, group.as_ptr(), group.len(), &mut commit) },
        PEACHY_MLS_OK
    );
    // Staged, so Ada has not moved yet — and `has_pending_commit` says so.
    let mut pending = false;
    assert_eq!(
        unsafe {
            peachy_mls_group_has_pending_commit(ada, group.as_ptr(), group.len(), &mut pending)
        },
        PEACHY_MLS_OK
    );
    assert!(pending, "a staged commit is pending until it is resolved");
    let mut still = 0u64;
    assert_eq!(
        unsafe { peachy_mls_group_epoch(ada, group.as_ptr(), group.len(), &mut still) },
        PEACHY_MLS_OK
    );
    assert_eq!(still, before, "a stage is not an epoch");
    assert_eq!(merge(ada, group), before + 1);
    for member in [bo, cy] {
        let mut incoming = process(member, group, &commit, PEACHY_MLS_DOOR_COMMIT);
        assert_eq!(incoming.kind, PEACHY_MLS_INCOMING_COMMIT);
        assert_eq!(incoming.epoch, before + 1);
        unsafe { peachy_mls_incoming_free(&mut incoming) };
    }
    unsafe { peachy_mls_buffer_free(&mut commit) };

    // remove Bo
    let mut commit = empty_buffer();
    assert_eq!(
        unsafe {
            peachy_mls_group_remove_member(
                ada,
                group.as_ptr(),
                group.len(),
                bo_leaf,
                bo_roster_key.as_ptr(),
                bo_roster_key.len(),
                &mut commit,
            )
        },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    merge(ada, group);
    let mut incoming = process(bo, group, &commit, PEACHY_MLS_DOOR_COMMIT);
    assert_eq!(incoming.kind, PEACHY_MLS_INCOMING_COMMIT);
    assert!(incoming.removed_self, "bo should see his own removal");
    unsafe { peachy_mls_incoming_free(&mut incoming) };
    let mut incoming = process(cy, group, &commit, PEACHY_MLS_DOOR_COMMIT);
    assert!(!incoming.removed_self);
    unsafe { peachy_mls_incoming_free(&mut incoming) };
    unsafe { peachy_mls_buffer_free(&mut commit) };

    // the removed member can neither read nor send
    let mut after = empty_buffer();
    let last = b"just us now";
    assert_eq!(
        unsafe {
            peachy_mls_group_encrypt(
                ada,
                group.as_ptr(),
                group.len(),
                last.as_ptr(),
                last.len(),
                &mut after,
            )
        },
        PEACHY_MLS_OK
    );
    let mut incoming = PeachyMlsIncoming {
        kind: 0,
        sender_actor_id: empty_buffer(),
        sender_device_id: empty_buffer(),
        plaintext: empty_buffer(),
        proposal_kind: 0,
        removed_self: false,
        epoch: 0,
        left_actor_ids: empty_buffer(),
    };
    assert_eq!(
        unsafe {
            peachy_mls_group_process_door(
                bo,
                group.as_ptr(),
                group.len(),
                after.data,
                after.len,
                PEACHY_MLS_DOOR_MESSAGE,
                0,
                &mut incoming,
            )
        },
        PEACHY_MLS_ERR_NOT_A_MEMBER
    );
    assert!(last_error().contains("not an active member"));
    let mut refused = empty_buffer();
    assert_eq!(
        unsafe {
            peachy_mls_group_encrypt(
                bo,
                group.as_ptr(),
                group.len(),
                last.as_ptr(),
                last.len(),
                &mut refused,
            )
        },
        PEACHY_MLS_ERR_NOT_A_MEMBER
    );
    // Cy still reads it.
    let mut incoming = process(cy, group, &after, PEACHY_MLS_DOOR_MESSAGE);
    assert_eq!(bytes_of(&incoming.plaintext), last);
    unsafe { peachy_mls_incoming_free(&mut incoming) };
    unsafe { peachy_mls_buffer_free(&mut after) };

    unsafe {
        peachy_mls_client_free(ada);
        peachy_mls_client_free(bo);
        peachy_mls_client_free(cy);
    }
}

#[test]
fn null_arguments_are_errors_and_not_faults() {
    let fixture = Fixture::new();
    let ada = fixture.client(9, "actor-ada", "device-ada");

    // A null client.
    assert_eq!(
        unsafe { peachy_mls_key_package(std::ptr::null_mut(), &mut empty_buffer()) },
        PEACHY_MLS_ERR_INVALID_ARGUMENT
    );
    assert!(last_error().contains("client"));

    // A null out-parameter. `a_null_out_parameter_costs_nothing_irreversible`
    // below is the one that proves nothing happened; this only pins the code.
    assert_eq!(
        unsafe { peachy_mls_key_package(ada, std::ptr::null_mut()) },
        PEACHY_MLS_ERR_INVALID_ARGUMENT
    );

    // A null group id.
    assert_eq!(
        unsafe { peachy_mls_group_create(ada, std::ptr::null(), 4) },
        PEACHY_MLS_ERR_INVALID_ARGUMENT
    );

    // A group nobody opened.
    assert_eq!(
        unsafe { peachy_mls_group_epoch(ada, b"nope".as_ptr(), 4, &mut 0u64) },
        PEACHY_MLS_ERR_NO_SUCH_GROUP
    );

    // Freeing null is a no-op on every free function.
    unsafe {
        peachy_mls_buffer_free(std::ptr::null_mut());
        peachy_mls_incoming_free(std::ptr::null_mut());
        peachy_mls_client_free(std::ptr::null_mut());
        peachy_mls_client_free(ada);
    }
}

/// The own-device verdict doors fail closed: `KNOWN` is code 0, so a binding
/// that zero-initialized the verdict and ignored the return code would seat
/// a device (or hand it the history) on any failure. Every failure leaves
/// `UNANCHORED` instead.
#[test]
fn a_failed_own_device_check_leaves_a_verdict_that_seats_nobody() {
    let key = [7u8; 32];
    let id = CString::new("device-ada-other").unwrap();
    let none = CString::new("").unwrap();

    let mut verdict = PEACHY_MLS_OWN_DEVICE_KNOWN;
    let status = unsafe {
        peachy_mls_check_own_device_key(
            std::ptr::null_mut(),
            id.as_ptr(),
            key.as_ptr(),
            key.len(),
            none.as_ptr(),
            std::ptr::null(),
            0,
            &mut verdict,
        )
    };
    assert_eq!(status, PEACHY_MLS_ERR_INVALID_ARGUMENT);
    assert_eq!(verdict, PEACHY_MLS_OWN_DEVICE_UNANCHORED);

    let mut verdict = PEACHY_MLS_OWN_DEVICE_KNOWN;
    let status = unsafe {
        peachy_mls_check_own_device_approval(
            std::ptr::null_mut(),
            key.as_ptr(),
            key.len(),
            none.as_ptr(),
            std::ptr::null(),
            0,
            &mut verdict,
        )
    };
    assert_eq!(status, PEACHY_MLS_ERR_INVALID_ARGUMENT);
    assert_eq!(verdict, PEACHY_MLS_OWN_DEVICE_UNANCHORED);
}

/// Every other door whose out-parameter is a verdict fails closed the same
/// way: where the accepting answer is 0 (a seat ask ACCEPTED, a credential
/// that verifies, a pairing's ANSWER or COMMIT), a failure leaves a refusal,
/// never the zero a caller initialized it to.
#[test]
fn a_failed_verdict_door_leaves_a_refusal_not_zero() {
    let gid = b"group";
    let actor = CString::new("actor-ada").unwrap();
    let device = CString::new("device-ada-phone").unwrap();
    let empty = CString::new("").unwrap();
    let bytes = [7u8; 32];

    let mut verdict = PEACHY_MLS_JOIN_REQUEST_ACCEPTED;
    let status = unsafe {
        peachy_mls_verify_join_request(
            std::ptr::null_mut(),
            gid.as_ptr(),
            gid.len(),
            actor.as_ptr(),
            device.as_ptr(),
            bytes.as_ptr(),
            bytes.len(),
            bytes.as_ptr(),
            bytes.len(),
            std::ptr::null(),
            0,
            &mut verdict,
        )
    };
    assert_ne!(status, PEACHY_MLS_OK);
    assert_eq!(verdict, PEACHY_MLS_JOIN_REQUEST_MALFORMED);

    let mut verdict = PEACHY_MLS_JOIN_REQUEST_ACCEPTED;
    let status = unsafe {
        peachy_mls_verify_admitted_join_request(
            std::ptr::null_mut(),
            gid.as_ptr(),
            gid.len(),
            actor.as_ptr(),
            device.as_ptr(),
            bytes.as_ptr(),
            bytes.len(),
            bytes.as_ptr(),
            bytes.len(),
            &mut verdict,
        )
    };
    assert_ne!(status, PEACHY_MLS_OK);
    assert_eq!(verdict, PEACHY_MLS_JOIN_REQUEST_MALFORMED);

    let mut rejection = 0u32;
    let status = unsafe {
        peachy_mls_group_member(
            std::ptr::null_mut(),
            gid.as_ptr(),
            gid.len(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut rejection,
        )
    };
    assert_ne!(status, PEACHY_MLS_OK);
    assert_ne!(rejection, 0);

    let mut rejection = 0u32;
    let status = unsafe {
        peachy_mls_key_package_identity(
            std::ptr::null_mut(),
            bytes.as_ptr(),
            bytes.len(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut rejection,
        )
    };
    assert_ne!(status, PEACHY_MLS_OK);
    assert_ne!(rejection, 0);

    let mut first = true;
    let status = unsafe {
        peachy_mls_first_sight_of_join_request(
            std::ptr::null_mut(),
            gid.as_ptr(),
            gid.len(),
            bytes.as_ptr(),
            bytes.len(),
            &mut first,
        )
    };
    assert_ne!(status, PEACHY_MLS_OK);
    assert!(!first);

    let mut seen = false;
    let status = unsafe {
        peachy_mls_join_request_seen(
            std::ptr::null_mut(),
            gid.as_ptr(),
            gid.len(),
            bytes.as_ptr(),
            bytes.len(),
            &mut seen,
        )
    };
    assert_ne!(status, PEACHY_MLS_OK);
    assert!(seen);

    // An approver id with no key: half a binding, refused.
    let mut step = PEACHY_MLS_LINK_ANSWER;
    let status = unsafe {
        peachy_mls_device_link_waiter_step(
            device.as_ptr(),
            std::ptr::null(),
            0,
            std::ptr::null(),
            0,
            empty.as_ptr(),
            bytes.as_ptr(),
            3,
            bytes.as_ptr(),
            3,
            &mut step,
        )
    };
    assert_ne!(status, PEACHY_MLS_OK);
    assert_eq!(step, PEACHY_MLS_LINK_IGNORE);

    let mut step = PEACHY_MLS_APPROVER_COMMIT;
    let status = unsafe {
        peachy_mls_device_link_approver_step(
            bytes.as_ptr(),
            3,
            bytes.as_ptr(),
            3,
            bytes.as_ptr(),
            0,
            bytes.as_ptr(),
            0,
            bytes.as_ptr(),
            0,
            bytes.as_ptr(),
            0,
            bytes.as_ptr(),
            0,
            &mut step,
        )
    };
    assert_ne!(status, PEACHY_MLS_OK);
    assert_eq!(step, PEACHY_MLS_APPROVER_WAIT);
}

/// Rule 5 in `mls/cabi/src/lib.rs`: a null out-parameter is noticed BEFORE the
/// irreversible half, not after it.
///
/// The old shape of this test called each door with null and asserted the
/// status code — which passed just as happily while the call minted a key
/// package, joined a group or staged a commit and then threw the answer away.
/// It leaked a key pair into the store on every run and said nothing about it.
///
/// So every assertion here is about state, not about a number:
///
///  - the key-package store is read directly out of the SQLite file, because
///    a stranded private half is a row and nothing in the ABI would show it;
///  - a Welcome refused with a null out-parameter must still open afterward,
///    which is only true if its key package was not spent;
///  - a commit refused with a null out-parameter must leave nothing pending,
///    because a staged commit whose bytes were discarded can never be
///    submitted and never be resolved.
#[test]
fn a_null_out_parameter_costs_nothing_irreversible() {
    use peachy_mls_core::{storage_key, KvStore, SqliteKv};

    let fixture = Fixture::new();
    let dir = std::env::temp_dir().join(format!("peachy-mls-rule5-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let path = dir.join("ada.sqlite3");
    let path_str = path.to_str().expect("a UTF-8 path").to_string();
    let group = b"cabi-rule5";

    // The `key_package` namespace holds one row per minted package's private
    // half. Same key layout as the core's, by construction.
    let stranded = || -> usize {
        let kv = SqliteKv::open(&path_str).expect("read the store back");
        kv.scan(&storage_key(b"key_package", b""))
            .expect("scan")
            .len()
    };

    let ada = fixture.client_on(1, "actor-ada", "device-ada", Some(&path_str));

    // --- minting ----------------------------------------------------------
    assert_eq!(stranded(), 0, "a fresh store holds no key packages");
    assert_eq!(
        unsafe { peachy_mls_key_package(ada, std::ptr::null_mut()) },
        PEACHY_MLS_ERR_INVALID_ARGUMENT
    );
    assert_eq!(
        stranded(),
        0,
        "a refused mint must not leave a private half in the store",
    );
    // And the door still works, so the check is an ordering fix and not a
    // disabled feature.
    let mut minted = empty_buffer();
    assert_eq!(
        unsafe { peachy_mls_key_package(ada, &mut minted) },
        PEACHY_MLS_OK
    );
    assert_eq!(stranded(), 1, "a real mint does leave one");
    unsafe { peachy_mls_buffer_free(&mut minted) };

    // --- staging a commit -------------------------------------------------
    assert_eq!(
        unsafe { peachy_mls_group_create(ada, group.as_ptr(), group.len()) },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    assert_eq!(
        unsafe {
            peachy_mls_group_self_update(ada, group.as_ptr(), group.len(), std::ptr::null_mut())
        },
        PEACHY_MLS_ERR_INVALID_ARGUMENT
    );
    let mut pending = true;
    assert_eq!(
        unsafe {
            peachy_mls_group_has_pending_commit(ada, group.as_ptr(), group.len(), &mut pending)
        },
        PEACHY_MLS_OK
    );
    assert!(
        !pending,
        "a commit whose bytes were thrown away can never be submitted or resolved",
    );

    // --- encrypting -------------------------------------------------------
    let plaintext = b"nobody will read this";
    assert_eq!(
        unsafe {
            peachy_mls_group_encrypt(
                ada,
                group.as_ptr(),
                group.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                std::ptr::null_mut(),
            )
        },
        PEACHY_MLS_ERR_INVALID_ARGUMENT
    );

    // --- joining ----------------------------------------------------------
    // Bo is added to a second group, and his Welcome is offered twice: once
    // with a null out-parameter, once properly. The second must work, which it
    // only can if the first did not spend his key package.
    let bo_group = b"cabi-rule5-bo";
    let bo = fixture.client(2, "actor-bo", "device-bo");
    let mut bo_kp = empty_buffer();
    assert_eq!(
        unsafe { peachy_mls_key_package(bo, &mut bo_kp) },
        PEACHY_MLS_OK
    );
    assert_eq!(
        unsafe { peachy_mls_group_create(ada, bo_group.as_ptr(), bo_group.len()) },
        PEACHY_MLS_OK
    );
    let mut commit = empty_buffer();
    let mut welcome = empty_buffer();
    assert_eq!(
        unsafe {
            peachy_mls_group_add_member(
                ada,
                bo_group.as_ptr(),
                bo_group.len(),
                bo_kp.data,
                bo_kp.len,
                &mut commit,
                &mut welcome,
            )
        },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    merge(ada, bo_group);

    assert_eq!(
        unsafe { peachy_mls_group_join(bo, welcome.data, welcome.len, std::ptr::null_mut()) },
        PEACHY_MLS_ERR_INVALID_ARGUMENT
    );
    let mut joined = empty_buffer();
    assert_eq!(
        unsafe { peachy_mls_group_join(bo, welcome.data, welcome.len, &mut joined) },
        PEACHY_MLS_OK,
        "the Welcome must still open: {}",
        last_error()
    );
    assert_eq!(bytes_of(&joined), bo_group);

    unsafe {
        peachy_mls_buffer_free(&mut bo_kp);
        peachy_mls_buffer_free(&mut commit);
        peachy_mls_buffer_free(&mut welcome);
        peachy_mls_buffer_free(&mut joined);
        peachy_mls_client_free(ada);
        peachy_mls_client_free(bo);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Rule 6: no call returns with a store transaction open, a stage's
/// included: while a staged commit waits on the server's verdict, and after
/// a call that fails, another connection to the file can write.
#[test]
fn no_call_leaves_a_store_transaction_open() {
    use peachy_mls_core::{KvStore, SqliteKv};

    let fixture = Fixture::new();
    let dir = std::env::temp_dir().join(format!("peachy-mls-rule6-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let path = dir.join("ada.sqlite3");
    let path_str = path.to_str().expect("a UTF-8 path").to_string();
    let group = b"cabi-rule6";

    let another_connection_can_write = || -> bool {
        let other = SqliteKv::open(&path_str).expect("open a second connection");
        other
            .put(b"\x01probe\x1fother", b"x")
            .and_then(|()| other.flush())
            .is_ok()
    };

    let ada = fixture.client_on(1, "actor-ada", "device-ada", Some(&path_str));
    assert_eq!(
        unsafe { peachy_mls_group_create(ada, group.as_ptr(), group.len()) },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    let mut commit = empty_buffer();
    assert_eq!(
        unsafe { peachy_mls_group_self_update(ada, group.as_ptr(), group.len(), &mut commit) },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    assert!(
        another_connection_can_write(),
        "a staged commit returned with the store's transaction open"
    );

    let unknown = b"cabi-rule6-unknown";
    let mut epoch = 0u64;
    assert_eq!(
        unsafe { peachy_mls_group_epoch(ada, unknown.as_ptr(), unknown.len(), &mut epoch) },
        PEACHY_MLS_ERR_NO_SUCH_GROUP
    );
    assert!(
        another_connection_can_write(),
        "a failed call returned with the store's transaction open"
    );

    // The stage itself is untouched: it still merges.
    assert_eq!(merge(ada, group), 1);
    assert!(another_connection_can_write());

    unsafe {
        peachy_mls_buffer_free(&mut commit);
        peachy_mls_client_free(ada);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The saved-commit doors: a stage left on disk by a client that went away
/// is a saved commit to the next one, which settles it against the head.
/// Here the head is still the group's own epoch, so it is cleared.
#[test]
fn a_saved_commit_is_settled_through_the_c_door() {
    let fixture = Fixture::new();
    let dir = std::env::temp_dir().join(format!("peachy-mls-saved-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let path = dir.join("ada.sqlite3");
    let path_str = path.to_str().expect("a UTF-8 path").to_string();
    let group = b"cabi-saved";

    let ada = fixture.client_on(1, "actor-ada", "device-ada", Some(&path_str));
    assert_eq!(
        unsafe { peachy_mls_group_create(ada, group.as_ptr(), group.len()) },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    let mut commit = empty_buffer();
    assert_eq!(
        unsafe { peachy_mls_group_self_update(ada, group.as_ptr(), group.len(), &mut commit) },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    let mut saved = true;
    assert_eq!(
        unsafe { peachy_mls_group_has_saved_commit(ada, group.as_ptr(), group.len(), &mut saved) },
        PEACHY_MLS_OK
    );
    assert!(!saved, "a stage of this client's own");
    unsafe {
        peachy_mls_buffer_free(&mut commit);
        peachy_mls_client_free(ada);
    }

    let ada = fixture.client_on(1, "actor-ada", "device-ada", Some(&path_str));
    assert_eq!(
        unsafe { peachy_mls_group_has_saved_commit(ada, group.as_ptr(), group.len(), &mut saved) },
        PEACHY_MLS_OK
    );
    assert!(saved, "the open kept the stage");
    let verifier = [0u8; 32];
    let mut verdict = 0u32;
    assert_eq!(
        unsafe {
            peachy_mls_group_settle_saved_commit(
                ada,
                group.as_ptr(),
                group.len(),
                0,
                verifier.as_ptr(),
                verifier.len(),
                &mut verdict,
            )
        },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    assert_eq!(verdict, PEACHY_MLS_SAVED_COMMIT_CLEARED);
    let mut pending = true;
    assert_eq!(
        unsafe {
            peachy_mls_group_has_pending_commit(ada, group.as_ptr(), group.len(), &mut pending)
        },
        PEACHY_MLS_OK
    );
    assert!(!pending);
    assert_eq!(
        unsafe {
            peachy_mls_group_settle_saved_commit(
                ada,
                group.as_ptr(),
                group.len(),
                0,
                verifier.as_ptr(),
                verifier.len(),
                &mut verdict,
            )
        },
        PEACHY_MLS_ERR_INVALID_ARGUMENT,
        "nothing left to settle"
    );
    unsafe { peachy_mls_client_free(ada) };
    let _ = std::fs::remove_dir_all(&dir);
}

/// The head of `group` as `member` holds it: its epoch and the SHA-256 of its
/// send key, which is what the delivery service records.
fn head_of(member: *mut PeachyMlsClient, group: &[u8]) -> (u64, Vec<u8>) {
    use sha2::{Digest, Sha256};
    let mut epoch = 0u64;
    assert_eq!(
        unsafe { peachy_mls_group_epoch(member, group.as_ptr(), group.len(), &mut epoch) },
        PEACHY_MLS_OK
    );
    let label = CString::new(peachy_mls_core::SEND_KEY_LABEL).expect("no NUL");
    let mut key = empty_buffer();
    assert_eq!(
        unsafe {
            peachy_mls_group_export_secret(
                member,
                group.as_ptr(),
                group.len(),
                label.as_ptr(),
                group.as_ptr(),
                group.len(),
                32,
                &mut key,
            )
        },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    let verifier = Sha256::digest(bytes_of(&key)).to_vec();
    unsafe { peachy_mls_buffer_free(&mut key) };
    (epoch, verifier)
}

#[test]
fn a_welcome_is_taken_against_the_head_through_the_c_door() {
    let fixture = Fixture::new();
    let ada = fixture.client(1, "actor-ada", "device-ada");
    let bo = fixture.client(2, "actor-bo", "device-bo");
    let cy = fixture.client(3, "actor-cy", "device-cy");
    let group = b"cabi-at-head";
    assert_eq!(
        unsafe { peachy_mls_group_create(ada, group.as_ptr(), group.len()) },
        PEACHY_MLS_OK
    );
    let add = |joiner: *mut PeachyMlsClient| -> Vec<u8> {
        let mut kp = empty_buffer();
        assert_eq!(
            unsafe { peachy_mls_key_package(joiner, &mut kp) },
            PEACHY_MLS_OK
        );
        let mut commit = empty_buffer();
        let mut welcome = empty_buffer();
        assert_eq!(
            unsafe {
                peachy_mls_group_add_member(
                    ada,
                    group.as_ptr(),
                    group.len(),
                    kp.data,
                    kp.len,
                    &mut commit,
                    &mut welcome,
                )
            },
            PEACHY_MLS_OK,
            "{}",
            last_error()
        );
        merge(ada, group);
        let bytes = bytes_of(&welcome);
        unsafe {
            peachy_mls_buffer_free(&mut kp);
            peachy_mls_buffer_free(&mut commit);
            peachy_mls_buffer_free(&mut welcome);
        }
        bytes
    };

    // Bo's Welcome, read without taking it, then refused under a head below
    // its epoch: it is no seat the delivery service holds.
    let welcome = add(bo);
    let mut named = empty_buffer();
    let mut epoch = 0u64;
    assert_eq!(
        unsafe {
            peachy_mls_group_welcome_group(
                bo,
                welcome.as_ptr(),
                welcome.len(),
                &mut named,
                &mut epoch,
            )
        },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    assert_eq!(bytes_of(&named), group);
    assert_eq!(epoch, 1);
    unsafe { peachy_mls_buffer_free(&mut named) };
    let mut joined = empty_buffer();
    let stale = [0u8; 32];
    assert_eq!(
        unsafe {
            peachy_mls_group_join_at_head(
                bo,
                welcome.as_ptr(),
                welcome.len(),
                0,
                stale.as_ptr(),
                stale.len(),
                &mut joined,
            )
        },
        PEACHY_MLS_ERR_ALREADY_A_MEMBER
    );
    assert!(joined.data.is_null());

    // Cy's, at the head: taken and confirmed.
    let welcome = add(cy);
    let (head_epoch, verifier) = head_of(ada, group);
    assert_eq!(
        unsafe {
            peachy_mls_group_join_at_head(
                cy,
                welcome.as_ptr(),
                welcome.len(),
                head_epoch,
                verifier.as_ptr(),
                verifier.len(),
                &mut joined,
            )
        },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    assert_eq!(bytes_of(&joined), group);
    unsafe { peachy_mls_buffer_free(&mut joined) };
    let mut confirmed = false;
    assert_eq!(
        unsafe {
            peachy_mls_group_confirm_head(
                cy,
                group.as_ptr(),
                group.len(),
                head_epoch,
                verifier.as_ptr(),
                verifier.len(),
                &mut confirmed,
            )
        },
        PEACHY_MLS_OK
    );
    assert!(confirmed);
    // A head under another send key un-confirms nothing below it, and names
    // a branch at it.
    assert_eq!(
        unsafe {
            peachy_mls_group_confirm_head(
                cy,
                group.as_ptr(),
                group.len(),
                head_epoch,
                stale.as_ptr(),
                stale.len(),
                &mut confirmed,
            )
        },
        PEACHY_MLS_OK
    );
    assert!(!confirmed);

    // Ada moves on; a head moved back to the epoch she came through is a
    // rollback, the same epoch under another key is not.
    let mut commit = empty_buffer();
    assert_eq!(
        unsafe { peachy_mls_group_self_update(ada, group.as_ptr(), group.len(), &mut commit) },
        PEACHY_MLS_OK
    );
    unsafe { peachy_mls_buffer_free(&mut commit) };
    merge(ada, group);
    let rolled_back = |verifier: &[u8]| -> bool {
        let mut out = false;
        assert_eq!(
            unsafe {
                peachy_mls_group_head_rolled_back(
                    ada,
                    group.as_ptr(),
                    group.len(),
                    head_epoch,
                    verifier.as_ptr(),
                    verifier.len(),
                    &mut out,
                )
            },
            PEACHY_MLS_OK,
            "{}",
            last_error()
        );
        out
    };
    assert!(rolled_back(&verifier));
    assert!(!rolled_back(&stale));
    assert_eq!(
        unsafe {
            peachy_mls_group_head_rolled_back(
                ada,
                group.as_ptr(),
                group.len(),
                head_epoch,
                verifier.as_ptr(),
                verifier.len(),
                std::ptr::null_mut(),
            )
        },
        PEACHY_MLS_ERR_INVALID_ARGUMENT
    );
    unsafe {
        peachy_mls_client_free(ada);
        peachy_mls_client_free(bo);
        peachy_mls_client_free(cy);
    }
}

#[test]
fn a_bad_credential_is_a_credential_error_with_a_readable_message() {
    let fixture = Fixture::new();
    let mut seed = [0u8; 32];
    seed[0] = 11;
    let (_, public) = device_key_pair(&seed);
    let expired = fixture
        .issuer
        .issue(
            "actor-ada",
            "device-ada",
            &public,
            now_unix() - 40 * DAY,
            now_unix() - DAY,
        )
        .expect("mint");

    let mut client: *mut PeachyMlsClient = std::ptr::null_mut();
    let status = unsafe {
        peachy_mls_client_new(
            expired.as_ptr(),
            expired.len(),
            seed.as_ptr(),
            seed.len(),
            fixture.trusted_json.as_ptr(),
            &mut client,
        )
    };
    assert_eq!(status, PEACHY_MLS_ERR_CREDENTIAL);
    assert!(client.is_null(), "a failed build writes no out-parameter");
    assert!(
        last_error().contains("expired"),
        "the message should name the check, got {}",
        last_error()
    );

    // A seed of the wrong length is caught before anything cryptographic.
    let status = unsafe {
        peachy_mls_client_new(
            expired.as_ptr(),
            expired.len(),
            seed.as_ptr(),
            16,
            fixture.trusted_json.as_ptr(),
            &mut client,
        )
    };
    assert_eq!(status, PEACHY_MLS_ERR_INVALID_ARGUMENT);
    assert!(last_error().contains("32 bytes"));
}

#[test]
fn the_error_slot_is_cleared_by_a_success() {
    let fixture = Fixture::new();
    let ada = fixture.client(12, "actor-ada", "device-ada");

    assert_eq!(
        unsafe { peachy_mls_group_epoch(ada, b"nope".as_ptr(), 4, &mut 0u64) },
        PEACHY_MLS_ERR_NO_SUCH_GROUP
    );
    assert!(!peachy_mls_last_error().is_null());

    assert_eq!(
        unsafe { peachy_mls_group_create(ada, b"yes".as_ptr(), 3) },
        PEACHY_MLS_OK
    );
    assert!(
        peachy_mls_last_error().is_null(),
        "a success must not leave a stale message behind"
    );

    unsafe { peachy_mls_client_free(ada) };
}

/// The `test-issuer` door, driven exactly as a wrapper's test suite drives it:
/// mint an issuer, ask it for the published-keys JSON, mint a credential for a
/// device seed, and build a client out of the three. Nothing here touches the
/// Rust issuer API — if this passes, Swift can do the same through C.
#[cfg(feature = "test-issuer")]
#[test]
fn the_test_issuer_door_mints_a_usable_credential() {
    let issuer_seed = [21u8; 32];
    let mut issuer: *mut PeachyMlsTestIssuer = std::ptr::null_mut();
    assert_eq!(
        unsafe { peachy_mls_test_issuer_new(issuer_seed.as_ptr(), issuer_seed.len(), &mut issuer) },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );

    let mut keys = empty_buffer();
    assert_eq!(
        unsafe { peachy_mls_test_issuer_published_keys(issuer, &mut keys) },
        PEACHY_MLS_OK
    );
    let keys_json = CString::new(bytes_of(&keys)).expect("no NUL in the published JSON");
    assert!(keys_json.to_str().expect("utf-8").contains("\"kid\""));
    unsafe { peachy_mls_buffer_free(&mut keys) };

    let mut device_seed = [0u8; 32];
    device_seed[0] = 33;
    let actor = CString::new("actor-ada").expect("no NUL");
    let device = CString::new("device-ada").expect("no NUL");
    let mut token = empty_buffer();
    assert_eq!(
        unsafe {
            peachy_mls_test_issuer_issue(
                issuer,
                actor.as_ptr(),
                device.as_ptr(),
                device_seed.as_ptr(),
                device_seed.len(),
                now_unix() - DAY,
                now_unix() + DAY,
                &mut token,
            )
        },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    assert!(bytes_of(&token).starts_with(b"pdc1."));

    let held = Fixture::held("actor-ada");
    let mut client: *mut PeachyMlsClient = std::ptr::null_mut();
    assert_eq!(
        unsafe {
            peachy_mls_client_open(
                token.data,
                token.len,
                device_seed.as_ptr(),
                device_seed.len(),
                keys_json.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                held.as_ptr(),
                held.len(),
                &mut client,
            )
        },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );

    // And an expired one is refused, which is the error path a wrapper's
    // error-surfacing test needs to be able to produce.
    let mut expired = empty_buffer();
    assert_eq!(
        unsafe {
            peachy_mls_test_issuer_issue(
                issuer,
                actor.as_ptr(),
                device.as_ptr(),
                device_seed.as_ptr(),
                device_seed.len(),
                now_unix() - 40 * DAY,
                now_unix() - DAY,
                &mut expired,
            )
        },
        PEACHY_MLS_OK
    );
    let mut refused: *mut PeachyMlsClient = std::ptr::null_mut();
    assert_eq!(
        unsafe {
            peachy_mls_client_new(
                expired.data,
                expired.len,
                device_seed.as_ptr(),
                device_seed.len(),
                keys_json.as_ptr(),
                &mut refused,
            )
        },
        PEACHY_MLS_ERR_CREDENTIAL
    );
    assert!(refused.is_null());

    // A seed of the wrong length is caught before anything is minted.
    let mut nothing = empty_buffer();
    assert_eq!(
        unsafe {
            peachy_mls_test_issuer_issue(
                issuer,
                actor.as_ptr(),
                device.as_ptr(),
                device_seed.as_ptr(),
                16,
                now_unix(),
                now_unix() + DAY,
                &mut nothing,
            )
        },
        PEACHY_MLS_ERR_INVALID_ARGUMENT
    );
    assert!(nothing.data.is_null());
    let mut short_seeded: *mut PeachyMlsTestIssuer = std::ptr::null_mut();
    assert_eq!(
        unsafe { peachy_mls_test_issuer_new(issuer_seed.as_ptr(), 16, &mut short_seeded) },
        PEACHY_MLS_ERR_INVALID_ARGUMENT
    );
    assert!(short_seeded.is_null());

    unsafe {
        peachy_mls_buffer_free(&mut token);
        peachy_mls_buffer_free(&mut expired);
        peachy_mls_client_free(client);
        peachy_mls_test_issuer_free(issuer);
        // Freeing null is a no-op here too.
        peachy_mls_test_issuer_free(std::ptr::null_mut());
    }
}

/// A client opened on a file, freed, and opened again on the same file keeps
/// its group — through the C door, which is the door Swift and Kotlin use.
///
/// `peachy_mls_client_free` is what makes this a real restart: it drops the
/// `Client`, which drops the provider, which closes the SQLite connection. What
/// the second `peachy_mls_client_open` reads is a file and nothing else.
#[test]
fn a_client_opened_on_a_file_keeps_its_group_across_a_free() {
    let fixture = Fixture::new();
    let dir = std::env::temp_dir().join(format!("peachy-mls-cabi-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let path = dir.join("ada.sqlite3");
    let path_str = path.to_str().expect("a UTF-8 path");
    let group = b"cabi-persist";

    // Bo is ephemeral and never restarts: the peer must not need to know.
    let bo = fixture.client(2, "actor-bo", "device-bo");
    let mut bo_kp = empty_buffer();
    assert_eq!(
        unsafe { peachy_mls_key_package(bo, &mut bo_kp) },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );

    let ada = fixture.client_on(1, "actor-ada", "device-ada", Some(path_str));
    assert_eq!(
        unsafe { peachy_mls_group_create(ada, group.as_ptr(), group.len()) },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    let mut commit = empty_buffer();
    let mut welcome = empty_buffer();
    assert_eq!(
        unsafe {
            peachy_mls_group_add_member(
                ada,
                group.as_ptr(),
                group.len(),
                bo_kp.data,
                bo_kp.len,
                &mut commit,
                &mut welcome,
            )
        },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    merge(ada, group);
    let mut joined = empty_buffer();
    assert_eq!(
        unsafe { peachy_mls_group_join(bo, welcome.data, welcome.len, &mut joined) },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    let mut epoch_before = 0u64;
    assert_eq!(
        unsafe { peachy_mls_group_epoch(ada, group.as_ptr(), group.len(), &mut epoch_before) },
        PEACHY_MLS_OK
    );
    unsafe {
        peachy_mls_buffer_free(&mut commit);
        peachy_mls_buffer_free(&mut welcome);
        peachy_mls_buffer_free(&mut joined);
        peachy_mls_buffer_free(&mut bo_kp);
        // The restart.
        peachy_mls_client_free(ada);
    }

    let ada = fixture.client_on(1, "actor-ada", "device-ada", Some(path_str));
    let mut epoch_after = 0u64;
    assert_eq!(
        unsafe { peachy_mls_group_epoch(ada, group.as_ptr(), group.len(), &mut epoch_after) },
        PEACHY_MLS_OK,
        "the group should still be open after the reopen: {}",
        last_error()
    );
    assert_eq!(epoch_after, epoch_before);

    let mut message = empty_buffer();
    let plaintext = b"still here after a free";
    assert_eq!(
        unsafe {
            peachy_mls_group_encrypt(
                ada,
                group.as_ptr(),
                group.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                &mut message,
            )
        },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    let mut incoming = process(bo, group, &message, PEACHY_MLS_DOOR_MESSAGE);
    assert_eq!(incoming.kind, PEACHY_MLS_INCOMING_APPLICATION);
    assert_eq!(bytes_of(&incoming.plaintext), plaintext);
    unsafe {
        peachy_mls_incoming_free(&mut incoming);
        peachy_mls_buffer_free(&mut message);
        peachy_mls_client_free(ada);
        peachy_mls_client_free(bo);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A null or empty store path is the ephemeral client, not an error, so a
/// caller with an optional path needs one call site.
#[test]
fn an_absent_store_path_is_an_ephemeral_client() {
    let fixture = Fixture::new();
    for path in [None, Some("")] {
        let client = fixture.client_on(3, "actor-cy", "device-cy", path);
        let group = b"ephemeral";
        assert_eq!(
            unsafe { peachy_mls_group_create(client, group.as_ptr(), group.len()) },
            PEACHY_MLS_OK,
            "{}",
            last_error()
        );
        unsafe { peachy_mls_client_free(client) };
    }
}

/// A device that holds its account key opens only on a credential certified
/// under the identity key derived from it (docs/identity.md §The
/// account identity key): the server's own key is refused at the door, and
/// the key reaches `update_credential` as well.
#[test]
fn a_client_refuses_a_credential_under_an_account_key_it_does_not_hold() {
    let fixture = Fixture::new();
    let mut seed = [0u8; 32];
    seed[0] = 31;
    seed[1] = 0xA5;
    let (_, public) = device_key_pair(&seed);
    let held = peachy_mls_core::account_identity_public_key(&[0xA1; 32]).expect("derive");
    let mint = |account: Option<&[u8]>, exp: i64| {
        fixture
            .issuer
            .issue_for_account(
                "actor-ada",
                "device-ada",
                &public,
                account,
                now_unix() - DAY,
                exp,
            )
            .expect("mint")
    };
    let open = |token: &[u8], own: Option<&[u8; 32]>| {
        let mut client: *mut PeachyMlsClient = std::ptr::null_mut();
        let status = unsafe {
            peachy_mls_client_open(
                token.as_ptr(),
                token.len(),
                seed.as_ptr(),
                seed.len(),
                fixture.trusted_json.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                own.map_or(std::ptr::null(), |key| key.as_ptr()),
                own.map_or(0, |key| key.len()),
                &mut client,
            )
        };
        (status, client)
    };

    let forged = mint(Some(&[0x99; 32]), now_unix() + 30 * DAY);
    let (status, client) = open(&forged, Some(&held));
    assert_eq!(status, PEACHY_MLS_ERR_CREDENTIAL, "{}", last_error());
    assert!(client.is_null());
    assert!(
        last_error().contains("not_own_account_key"),
        "{}",
        last_error()
    );

    // Holding no key, there is nothing to check a certificate against, so
    // any certified credential is refused, the honest one included.
    for token in [&forged, &mint(Some(&[0xA1; 32]), now_unix() + 30 * DAY)] {
        let (status, client) = open(token, None);
        assert_eq!(status, PEACHY_MLS_ERR_CREDENTIAL, "{}", last_error());
        assert!(client.is_null());
        assert!(
            last_error().contains("not_own_account_key"),
            "{}",
            last_error()
        );
    }

    // Waiting with the key held; a certificate under another key is refused
    // when it arrives, a key of the wrong length is an argument error, and
    // the honest one installs.
    let (status, waiting) = open(&mint(None, now_unix() + 20 * DAY), Some(&held));
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    let forged_later = mint(Some(&[0x99; 32]), now_unix() + 30 * DAY);
    assert_eq!(
        unsafe {
            peachy_mls_client_update_credential(
                waiting,
                forged_later.as_ptr(),
                forged_later.len(),
                std::ptr::null(),
                0,
            )
        },
        PEACHY_MLS_ERR_CREDENTIAL
    );
    let honest = mint(Some(&[0xA1; 32]), now_unix() + 30 * DAY);
    assert_eq!(
        unsafe {
            peachy_mls_client_update_credential(
                waiting,
                honest.as_ptr(),
                honest.len(),
                held.as_ptr(),
                31,
            )
        },
        PEACHY_MLS_ERR_INVALID_ARGUMENT
    );
    assert_eq!(
        unsafe {
            peachy_mls_client_update_credential(
                waiting,
                honest.as_ptr(),
                honest.len(),
                held.as_ptr(),
                32,
            )
        },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    unsafe { peachy_mls_client_free(waiting) };
}

/// `peachy_mls_client_new` names no account key, so it opens only what a
/// device holding none may run on: an uncertified credential. A certified one
/// is refused as `not_own_account_key`.
#[test]
fn a_client_holding_no_key_opens_only_uncertified() {
    let fixture = Fixture::new();
    let mut seed = [0u8; 32];
    seed[0] = 32;
    seed[1] = 0xA5;
    let (_, public) = device_key_pair(&seed);
    let new_client = |account: Option<&[u8]>| {
        let token = fixture
            .issuer
            .issue_for_account(
                "actor-ada",
                "device-ada",
                &public,
                account,
                now_unix() - DAY,
                now_unix() + 30 * DAY,
            )
            .expect("mint");
        let mut client: *mut PeachyMlsClient = std::ptr::null_mut();
        let status = unsafe {
            peachy_mls_client_new(
                token.as_ptr(),
                token.len(),
                seed.as_ptr(),
                seed.len(),
                fixture.trusted_json.as_ptr(),
                &mut client,
            )
        };
        (status, client)
    };

    let (status, client) = new_client(None);
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    unsafe { peachy_mls_client_free(client) };

    let (status, client) = new_client(Some(&TestIssuer::test_account_key("actor-ada")));
    assert_eq!(status, PEACHY_MLS_ERR_CREDENTIAL);
    assert!(client.is_null());
    assert!(
        last_error().contains("not_own_account_key"),
        "{}",
        last_error()
    );
}

/// A store path pointing at a directory that does not exist fails as STORAGE,
/// with a sentence naming the file — not as a panic, and not as a silent
/// ephemeral client that loses everything at the next launch.
#[test]
fn an_unopenable_store_is_a_storage_error_and_not_a_silent_fallback() {
    let fixture = Fixture::new();
    let (seed, token) = fixture.identity(4, "actor-dee", "device-dee");
    let path = CString::new("/nonexistent-peachy-directory/mls.sqlite3").expect("no NUL");
    let mut client: *mut PeachyMlsClient = std::ptr::null_mut();
    let status = unsafe {
        peachy_mls_client_open(
            token.as_ptr(),
            token.len(),
            seed.as_ptr(),
            seed.len(),
            fixture.trusted_json.as_ptr(),
            path.as_ptr(),
            std::ptr::null(),
            0,
            std::ptr::null(),
            0,
            &mut client,
        )
    };
    assert_eq!(status, PEACHY_MLS_ERR_STORAGE, "{}", last_error());
    assert!(client.is_null(), "a failure must not write the pointer");
    assert!(
        last_error().contains("could not open the MLS store"),
        "{}",
        last_error()
    );
}

#[test]
fn the_version_is_readable() {
    let version = unsafe { CStr::from_ptr(peachy_mls_version()) }
        .to_str()
        .expect("utf-8");
    assert_eq!(version, env!("CARGO_PKG_VERSION"));
    assert_eq!(peachy_mls_abi_version(), PEACHY_MLS_ABI_VERSION);
}

/// The carried server keys, through the C door: a published list holding the
/// production set plus one key it does not carry reports that kid, and
/// narrows to the production set alone.
#[test]
fn the_server_key_pins_cross_the_c_door() {
    let carried = peachy_mls_core::TrustedServerKeys::pinned("production").expect("carried");
    let (kid, raw) = carried.iter().next().expect("one key");
    let stranger = TestIssuer::from_seed(&[9u8; 32]);
    let b64 = |raw: &[u8]| {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(raw)
    };
    let published = CString::new(format!(
        "{{\"enabled\":true,\"keys\":[{{\"kid\":\"{}\",\"publicKey\":\"{}\",\"current\":true,\"use\":\"device\"}},{{\"kid\":\"{kid}\",\"publicKey\":\"{}\",\"current\":false,\"use\":\"device\"}}]}}",
        stranger.kid(),
        b64(&stranger.public_key()),
        b64(&raw),
    ))
    .expect("no NUL");
    let server = CString::new("production").expect("no NUL");

    let mut report = empty_buffer();
    let status = unsafe {
        peachy_mls_server_key_pin_report(published.as_ptr(), server.as_ptr(), &mut report)
    };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    let text = String::from_utf8(bytes_of(&report)).expect("utf-8");
    unsafe { peachy_mls_buffer_free(&mut report) };
    assert_eq!(
        text,
        format!("published but not pinned: {}", stranger.kid())
    );

    let mut narrowed = empty_buffer();
    let status = unsafe {
        peachy_mls_server_keys_pinned(published.as_ptr(), server.as_ptr(), &mut narrowed)
    };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    let json = String::from_utf8(bytes_of(&narrowed)).expect("utf-8");
    unsafe { peachy_mls_buffer_free(&mut narrowed) };
    let trusted = peachy_mls_core::TrustedServerKeys::from_published_json(&json).expect("parses");
    assert_eq!(trusted.len(), 1);
    assert!(trusted.contains(kid));

    let unknown = CString::new("staging").expect("no NUL");
    let mut nothing = empty_buffer();
    let status = unsafe {
        peachy_mls_server_key_pin_report(published.as_ptr(), unknown.as_ptr(), &mut nothing)
    };
    assert_eq!(status, PEACHY_MLS_ERR_INVALID_ARGUMENT);
}

#[test]
fn a_key_package_comes_back_with_the_reference_that_names_it() {
    let fixture = Fixture::new();
    let client = fixture.client(1, "actor-kp", "device-kp");

    let mut package = empty_buffer();
    let mut reference = empty_buffer();
    let mut ciphersuite: u16 = 0;
    let status = unsafe {
        peachy_mls_key_package_with_ref(client, &mut package, &mut reference, &mut ciphersuite)
    };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());

    let package_bytes = bytes_of(&package);
    let reference_bytes = bytes_of(&reference);
    assert!(!package_bytes.is_empty(), "a key package has bytes");
    // RefHash over the bare KeyPackage with SHA-256 — 32 bytes, and NOT a
    // hash of the MlsMessage wrapper that comes back beside it.
    assert_eq!(reference_bytes.len(), 32, "an RFC 9420 KeyPackageRef");
    assert_ne!(
        reference_bytes, package_bytes,
        "the reference is not the package"
    );
    assert_ne!(ciphersuite, 0, "the ciphersuite id is filled in");

    // Single-use: a second call is a different package under a different name.
    // A directory keyed on the reference depends on this, and a core that
    // returned a stable reference would make every republish collapse onto one
    // row while leaving N private halves stranded in the store.
    let mut package2 = empty_buffer();
    let mut reference2 = empty_buffer();
    let status = unsafe {
        peachy_mls_key_package_with_ref(
            client,
            &mut package2,
            &mut reference2,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    assert_ne!(
        bytes_of(&reference2),
        reference_bytes,
        "each key package has its own reference"
    );

    // A null out-parameter for the package is refused BEFORE one is minted, so
    // the call cannot strand a private init half in the store.
    let mut orphan = empty_buffer();
    let status = unsafe {
        peachy_mls_key_package_with_ref(
            client,
            std::ptr::null_mut(),
            &mut orphan,
            std::ptr::null_mut(),
        )
    };
    // `PEACHY_MLS_ERR_INVALID_ARGUMENT` and not `PEACHY_MLS_ERR_NULL_ARGUMENT`:
    // `null_argument()` has always built an `Error::InvalidArgument`, so the
    // null constant is declared and documented but returned by nothing. Left
    // as it is — changing which code a null produces is an ABI-visible break
    // for a caller that switches on it — and asserted here the way every other
    // null test in this file already does.
    assert_eq!(status, PEACHY_MLS_ERR_INVALID_ARGUMENT);
    assert!(last_error().contains("out_key_package"));

    unsafe {
        peachy_mls_buffer_free(&mut package);
        peachy_mls_buffer_free(&mut reference);
        peachy_mls_buffer_free(&mut package2);
        peachy_mls_buffer_free(&mut reference2);
        peachy_mls_client_free(client);
    }
}

#[test]
fn the_group_set_is_enumerable_and_membership_is_answerable() {
    let fixture = Fixture::new();
    let client = fixture.client(2, "actor-enum", "device-enum");

    let mut count: usize = 99;
    let status = unsafe { peachy_mls_group_count(client, &mut count) };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    assert_eq!(count, 0, "a fresh client holds no groups");

    let group = b"peachy-group-enumerable";
    let status = unsafe { peachy_mls_group_create(client, group.as_ptr(), group.len()) };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());

    let status = unsafe { peachy_mls_group_count(client, &mut count) };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    assert_eq!(count, 1);

    let mut id = empty_buffer();
    let status = unsafe { peachy_mls_group_id_at(client, 0, &mut id) };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    assert_eq!(bytes_of(&id), group.to_vec());

    // Past the end is an error rather than an empty buffer: a caller looping
    // on a stale count should find out, not read a group id that is silently
    // nothing.
    let mut past = empty_buffer();
    let status = unsafe { peachy_mls_group_id_at(client, 1, &mut past) };
    assert_eq!(status, PEACHY_MLS_ERR_NO_SUCH_GROUP);

    let mut active = false;
    let status =
        unsafe { peachy_mls_group_is_active(client, group.as_ptr(), group.len(), &mut active) };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    assert!(active, "the creator is an active member");

    // An id this client has never heard of is an ERROR, not `false`. The two
    // questions have different answers — one is fixed by claiming a Welcome
    // and the other is not — and a door that collapsed them would hide that.
    let unknown = b"a-group-nobody-here-has-joined";
    let status =
        unsafe { peachy_mls_group_is_active(client, unknown.as_ptr(), unknown.len(), &mut active) };
    assert_eq!(status, PEACHY_MLS_ERR_NO_SUCH_GROUP);
    assert!(last_error().contains("no such group"), "{}", last_error());

    unsafe {
        peachy_mls_buffer_free(&mut id);
        peachy_mls_client_free(client);
    }
}

/// A held group's envelope through the client's own door: keyed by the
/// epoch, so the clientless door opens nothing, and the client opens it.
#[test]
fn a_client_seals_a_held_groups_envelope_by_the_epoch_through_the_c_door() {
    let fixture = Fixture::new();
    let client = fixture.client(2, "actor-seal", "device-seal");
    let group = b"peachy-group-sealed-by-epoch";
    let status = unsafe { peachy_mls_group_create(client, group.as_ptr(), group.len()) };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());

    let inner = b"hello";
    let mut envelope = empty_buffer();
    let status = unsafe {
        peachy_mls_client_seal_envelope(
            client,
            group.as_ptr(),
            group.len(),
            1,
            inner.as_ptr(),
            inner.len(),
            &mut envelope,
        )
    };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    let sealed = bytes_of(&envelope);
    assert_eq!(sealed[0], 3, "sealed by the epoch");

    let mut kind: u8 = 99;
    let mut bare = empty_buffer();
    let status = unsafe {
        peachy_mls_open_envelope_for(
            group.as_ptr(),
            group.len(),
            sealed.as_ptr(),
            sealed.len(),
            &mut kind,
            &mut bare,
        )
    };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    assert_eq!(
        kind, 0,
        "the group id alone opens nothing keyed by the epoch"
    );

    let mut gid = empty_buffer();
    let mut opened = empty_buffer();
    let status = unsafe {
        peachy_mls_open_envelope(
            client,
            sealed.as_ptr(),
            sealed.len(),
            &mut gid,
            &mut kind,
            &mut opened,
        )
    };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    assert_eq!(kind, 1);
    assert_eq!(bytes_of(&gid), group.to_vec());
    assert_eq!(bytes_of(&opened), inner.to_vec());

    // Not an envelope kind: refused, as the clientless seal refuses it.
    let mut refused = empty_buffer();
    let status = unsafe {
        peachy_mls_client_seal_envelope(
            client,
            group.as_ptr(),
            group.len(),
            0,
            inner.as_ptr(),
            inner.len(),
            &mut refused,
        )
    };
    assert_eq!(status, PEACHY_MLS_ERR_INVALID_ARGUMENT);

    unsafe {
        peachy_mls_buffer_free(&mut envelope);
        peachy_mls_buffer_free(&mut bare);
        peachy_mls_buffer_free(&mut gid);
        peachy_mls_buffer_free(&mut opened);
        peachy_mls_client_free(client);
    }
}

#[test]
fn the_enrollment_helpers_make_a_seed_and_its_public_half() {
    let mut seed = empty_buffer();
    let status = unsafe { peachy_mls_generate_signing_key_seed(&mut seed) };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    let seed_bytes = bytes_of(&seed);
    assert_eq!(seed_bytes.len(), 32);

    let mut other = empty_buffer();
    let status = unsafe { peachy_mls_generate_signing_key_seed(&mut other) };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    assert_ne!(
        bytes_of(&other),
        seed_bytes,
        "two seeds from the CSPRNG differ"
    );

    let mut public_key = empty_buffer();
    let status = unsafe {
        peachy_mls_signing_key_public_key(seed_bytes.as_ptr(), seed_bytes.len(), &mut public_key)
    };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    assert_eq!(bytes_of(&public_key).len(), 32);

    // Deterministic: the same seed is the same device, which is the whole
    // reason a credential can be minted against it once and believed later.
    let mut again = empty_buffer();
    let status = unsafe {
        peachy_mls_signing_key_public_key(seed_bytes.as_ptr(), seed_bytes.len(), &mut again)
    };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    assert_eq!(bytes_of(&again), bytes_of(&public_key));

    // And it agrees with the issuer's own derivation, which is what the server
    // will have signed over. A public key that matched neither would fail as
    // `leaf_key_mismatch` several calls later.
    let seed_array: [u8; 32] = seed_bytes.clone().try_into().expect("a 32-byte seed");
    let (_, expected) = device_key_pair(&seed_array);
    assert_eq!(bytes_of(&public_key), expected.to_vec());

    // A seed of the wrong length is a sentence, not a panic.
    let short = [1u8; 31];
    let mut refused = empty_buffer();
    let status =
        unsafe { peachy_mls_signing_key_public_key(short.as_ptr(), short.len(), &mut refused) };
    assert_eq!(status, PEACHY_MLS_ERR_INVALID_ARGUMENT);
    assert!(last_error().contains("32"), "{}", last_error());

    unsafe {
        peachy_mls_buffer_free(&mut seed);
        peachy_mls_buffer_free(&mut other);
        peachy_mls_buffer_free(&mut public_key);
        peachy_mls_buffer_free(&mut again);
    }
}

#[test]
fn the_device_link_door_signs_verifies_and_compares() {
    // Four unconditional entry points, exercised for the thing a C boundary
    // gets wrong: which buffer is owned, what a length of the wrong size does,
    // and — the one that matters here — that a failed verification comes back
    // as OK-and-false rather than as a status code.
    let seed = [0x11u8; 32];
    let laptop_key = [0x22u8; 32];
    let device_id = CString::new("device-ada-laptop").expect("no NUL");

    let mut statement = empty_buffer();
    let status = unsafe {
        peachy_mls_device_approval_statement(
            device_id.as_ptr(),
            laptop_key.as_ptr(),
            laptop_key.len(),
            &mut statement,
        )
    };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    let statement_bytes = bytes_of(&statement);
    assert_eq!(
        statement_bytes.len(),
        "peachy-device-approval-v1".len() + 1 + "device-ada-laptop".len() + 1 + 32
    );
    assert!(statement_bytes.starts_with(b"peachy-device-approval-v1\0"));

    let mut signature = empty_buffer();
    let status = unsafe {
        peachy_mls_sign_device_approval(
            seed.as_ptr(),
            seed.len(),
            device_id.as_ptr(),
            laptop_key.as_ptr(),
            laptop_key.len(),
            &mut signature,
        )
    };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    let signature_bytes = bytes_of(&signature);
    assert_eq!(signature_bytes.len(), 64);

    let mut approver = empty_buffer();
    let status =
        unsafe { peachy_mls_signing_key_public_key(seed.as_ptr(), seed.len(), &mut approver) };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    let approver_bytes = bytes_of(&approver);

    let mut valid = false;
    let status = unsafe {
        peachy_mls_verify_device_approval(
            approver_bytes.as_ptr(),
            approver_bytes.len(),
            device_id.as_ptr(),
            laptop_key.as_ptr(),
            laptop_key.len(),
            signature_bytes.as_ptr(),
            signature_bytes.len(),
            &mut valid,
        )
    };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    assert!(valid, "the approval this door just signed has to verify");

    // The decision this test exists for: a truncated signature is OK-and-false
    // and NOT a status code, so no caller can tell it from a signature that
    // simply did not check out.
    let mut valid = true;
    let status = unsafe {
        peachy_mls_verify_device_approval(
            approver_bytes.as_ptr(),
            approver_bytes.len(),
            device_id.as_ptr(),
            laptop_key.as_ptr(),
            laptop_key.len(),
            signature_bytes.as_ptr(),
            signature_bytes.len() - 1,
            &mut valid,
        )
    };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    assert!(!valid);

    // …and so is a 31-byte approver key.
    let mut valid = true;
    let status = unsafe {
        peachy_mls_verify_device_approval(
            approver_bytes.as_ptr(),
            approver_bytes.len() - 1,
            device_id.as_ptr(),
            laptop_key.as_ptr(),
            laptop_key.len(),
            signature_bytes.as_ptr(),
            signature_bytes.len(),
            &mut valid,
        )
    };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    assert!(!valid);

    // A null out-parameter is still an error, because it is a bug in the
    // caller and not a fact about an approval.
    let status = unsafe {
        peachy_mls_verify_device_approval(
            approver_bytes.as_ptr(),
            approver_bytes.len(),
            device_id.as_ptr(),
            laptop_key.as_ptr(),
            laptop_key.len(),
            signature_bytes.as_ptr(),
            signature_bytes.len(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(status, PEACHY_MLS_ERR_INVALID_ARGUMENT);
    assert!(last_error().contains("out_valid"), "{}", last_error());

    // The commitment and the number: UTF-8, not NUL-terminated.
    let other_key = [0x33u8; 32];
    let nonce_a = [0x66u8; 32];
    let nonce_n = [0x55u8; 32];
    let mut commitment = empty_buffer();
    let status = unsafe {
        peachy_mls_device_link_commitment(nonce_a.as_ptr(), nonce_a.len(), &mut commitment)
    };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    let commitment_bytes = bytes_of(&commitment);
    assert_eq!(commitment_bytes.len(), 32);

    let mut number = empty_buffer();
    let status = unsafe {
        peachy_mls_device_link_number(
            laptop_key.as_ptr(),
            laptop_key.len(),
            other_key.as_ptr(),
            other_key.len(),
            commitment_bytes.as_ptr(),
            commitment_bytes.len(),
            nonce_n.as_ptr(),
            nonce_n.len(),
            nonce_a.as_ptr(),
            nonce_a.len(),
            &mut number,
        )
    };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    let text = String::from_utf8(bytes_of(&number)).expect("the number is UTF-8");
    assert_eq!(text.len(), 2, "{text:?}");
    assert!(!text.contains('\0'), "the buffer carries its own length");

    // A nonce that does not open the commitment is refused, never answered.
    let mut refused = empty_buffer();
    let status = unsafe {
        peachy_mls_device_link_number(
            laptop_key.as_ptr(),
            laptop_key.len(),
            other_key.as_ptr(),
            other_key.len(),
            commitment_bytes.as_ptr(),
            commitment_bytes.len(),
            nonce_n.as_ptr(),
            nonce_n.len(),
            nonce_n.as_ptr(),
            nonce_n.len(),
            &mut refused,
        )
    };
    assert_eq!(status, PEACHY_MLS_ERR_INVALID_ARGUMENT);
    assert!(last_error().contains("commitment"), "{}", last_error());

    // The approver's number: the same inputs, another domain.
    let mut approver_number = empty_buffer();
    let status = unsafe {
        peachy_mls_device_link_approver_number(
            laptop_key.as_ptr(),
            laptop_key.len(),
            other_key.as_ptr(),
            other_key.len(),
            commitment_bytes.as_ptr(),
            commitment_bytes.len(),
            nonce_n.as_ptr(),
            nonce_n.len(),
            nonce_a.as_ptr(),
            nonce_a.len(),
            &mut approver_number,
        )
    };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    assert_eq!(bytes_of(&approver_number).len(), 2);

    // The QR code, and a scan of it matching only the same id and key.
    let link_secret = [0x5eu8; 32];
    let mut qr = empty_buffer();
    let status = unsafe {
        peachy_mls_device_link_qr(
            device_id.as_ptr(),
            laptop_key.as_ptr(),
            laptop_key.len(),
            link_secret.as_ptr(),
            link_secret.len(),
            &mut qr,
        )
    };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    let qr_text = String::from_utf8(bytes_of(&qr)).expect("the QR text is UTF-8");
    assert!(
        qr_text.starts_with("peachy-link:device-ada-laptop/"),
        "{qr_text}"
    );
    let scanned = CString::new(qr_text).expect("no NUL");
    let mut matches = false;
    let status = unsafe {
        peachy_mls_device_link_qr_matches(
            scanned.as_ptr(),
            device_id.as_ptr(),
            laptop_key.as_ptr(),
            laptop_key.len(),
            &mut matches,
        )
    };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    assert!(matches);
    let mut matches = true;
    let status = unsafe {
        peachy_mls_device_link_qr_matches(
            scanned.as_ptr(),
            device_id.as_ptr(),
            other_key.as_ptr(),
            other_key.len(),
            &mut matches,
        )
    };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    assert!(!matches, "a swapped key is OK-and-false");

    // The secret comes back off the code, and nothing off another key's.
    let mut secret = empty_buffer();
    let status = unsafe {
        peachy_mls_device_link_qr_secret(
            scanned.as_ptr(),
            device_id.as_ptr(),
            laptop_key.as_ptr(),
            laptop_key.len(),
            &mut secret,
        )
    };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    assert_eq!(bytes_of(&secret), link_secret);
    let mut no_secret = empty_buffer();
    let status = unsafe {
        peachy_mls_device_link_qr_secret(
            scanned.as_ptr(),
            device_id.as_ptr(),
            other_key.as_ptr(),
            other_key.len(),
            &mut no_secret,
        )
    };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    assert!(
        bytes_of(&no_secret).is_empty(),
        "another key is OK-and-empty"
    );
    unsafe {
        peachy_mls_buffer_free(&mut approver_number);
        peachy_mls_buffer_free(&mut secret);
        peachy_mls_buffer_free(&mut no_secret);
    }

    // The waiting device's rule: one exchange per pairing. Nothing bound is
    // an empty string and two empty (non-null) slices.
    let approver_id = CString::new("device-ada-phone").expect("no NUL");
    let nothing = CString::new("").expect("no NUL");
    let empty: [u8; 0] = [];
    let waiter_step = |bound_id: &CString,
                       bound_key: &[u8],
                       bound_commitment: &[u8],
                       key: &[u8],
                       commitment: &[u8]|
     -> (i32, u32) {
        let mut step = u32::MAX;
        let status = unsafe {
            peachy_mls_device_link_waiter_step(
                bound_id.as_ptr(),
                bound_key.as_ptr(),
                bound_key.len(),
                bound_commitment.as_ptr(),
                bound_commitment.len(),
                approver_id.as_ptr(),
                key.as_ptr(),
                key.len(),
                commitment.as_ptr(),
                commitment.len(),
                &mut step,
            )
        };
        (status, step)
    };
    assert_eq!(
        waiter_step(&nothing, &empty, &empty, &other_key, &commitment_bytes),
        (PEACHY_MLS_OK, PEACHY_MLS_LINK_ANSWER)
    );
    assert_eq!(
        waiter_step(
            &approver_id,
            &other_key,
            &commitment_bytes,
            &other_key,
            &commitment_bytes
        ),
        (PEACHY_MLS_OK, PEACHY_MLS_LINK_CONTINUE)
    );
    let restarted = [0x77u8; 32];
    assert_eq!(
        waiter_step(
            &approver_id,
            &other_key,
            &commitment_bytes,
            &other_key,
            &restarted
        ),
        (PEACHY_MLS_OK, PEACHY_MLS_LINK_INTERRUPTED)
    );
    let elsewhere = CString::new("device-ada-tablet").expect("no NUL");
    assert_eq!(
        waiter_step(
            &elsewhere,
            &other_key,
            &restarted,
            &other_key,
            &commitment_bytes
        ),
        (PEACHY_MLS_OK, PEACHY_MLS_LINK_IGNORE)
    );
    let (status, _) = waiter_step(
        &nothing,
        &empty,
        &empty,
        &other_key,
        &commitment_bytes[..31],
    );
    assert_eq!(status, PEACHY_MLS_ERR_INVALID_ARGUMENT);
    assert!(
        last_error().contains("approver_commitment"),
        "{}",
        last_error()
    );

    // The approver signs its commitment for the waiting device, and the
    // waiting device checks it: OK-and-false for another key, as for
    // approvals.
    let mut commit_sig = empty_buffer();
    let status = unsafe {
        peachy_mls_sign_device_link_commitment(
            seed.as_ptr(),
            seed.len(),
            device_id.as_ptr(),
            laptop_key.as_ptr(),
            laptop_key.len(),
            commitment_bytes.as_ptr(),
            commitment_bytes.len(),
            &mut commit_sig,
        )
    };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    let commit_sig_bytes = bytes_of(&commit_sig);
    assert_eq!(commit_sig_bytes.len(), 64);
    let verify_commit = |key: &[u8]| -> (i32, bool) {
        let mut valid = false;
        let status = unsafe {
            peachy_mls_verify_device_link_commitment(
                approver_bytes.as_ptr(),
                approver_bytes.len(),
                device_id.as_ptr(),
                key.as_ptr(),
                key.len(),
                commitment_bytes.as_ptr(),
                commitment_bytes.len(),
                commit_sig_bytes.as_ptr(),
                commit_sig_bytes.len(),
                &mut valid,
            )
        };
        (status, valid)
    };
    assert_eq!(verify_commit(&laptop_key), (PEACHY_MLS_OK, true));
    assert_eq!(verify_commit(&other_key), (PEACHY_MLS_OK, false));

    // The approver's rule: a failed reveal followed by another device nonce
    // is INTERRUPTED, never a number.
    let approver_step = |bound: &[u8], listed_nonce: &[u8], listed_reveal: &[u8]| -> (i32, u32) {
        let mut step = u32::MAX;
        let status = unsafe {
            peachy_mls_device_link_approver_step(
                laptop_key.as_ptr(),
                laptop_key.len(),
                commitment_bytes.as_ptr(),
                commitment_bytes.len(),
                bound.as_ptr(),
                bound.len(),
                laptop_key.as_ptr(),
                laptop_key.len(),
                commitment_bytes.as_ptr(),
                commitment_bytes.len(),
                listed_nonce.as_ptr(),
                listed_nonce.len(),
                listed_reveal.as_ptr(),
                listed_reveal.len(),
                &mut step,
            )
        };
        (status, step)
    };
    assert_eq!(
        approver_step(&empty, &empty, &empty),
        (PEACHY_MLS_OK, PEACHY_MLS_APPROVER_WAIT)
    );
    assert_eq!(
        approver_step(&empty, &nonce_n, &empty),
        (PEACHY_MLS_OK, PEACHY_MLS_APPROVER_REVEAL)
    );
    assert_eq!(
        approver_step(&nonce_n, &nonce_n, &nonce_a),
        (PEACHY_MLS_OK, PEACHY_MLS_APPROVER_SHOW)
    );
    assert_eq!(
        approver_step(&nonce_n, &[0x57u8; 32], &nonce_a),
        (PEACHY_MLS_OK, PEACHY_MLS_APPROVER_INTERRUPTED)
    );
    let (status, _) = approver_step(&nonce_n[..31], &nonce_n, &empty);
    assert_eq!(status, PEACHY_MLS_ERR_INVALID_ARGUMENT);
    assert!(
        last_error().contains("bound_device_nonce"),
        "{}",
        last_error()
    );
    unsafe { peachy_mls_buffer_free(&mut commit_sig) };

    unsafe {
        peachy_mls_buffer_free(&mut statement);
        peachy_mls_buffer_free(&mut signature);
        peachy_mls_buffer_free(&mut approver);
        peachy_mls_buffer_free(&mut commitment);
        peachy_mls_buffer_free(&mut number);
        peachy_mls_buffer_free(&mut refused);
        peachy_mls_buffer_free(&mut qr);
    }
}

/// Process one message through `door` and assert it succeeded. The caller
/// frees the result.
fn process(
    client: *mut PeachyMlsClient,
    group: &[u8],
    message: &PeachyMlsBuffer,
    door: u32,
) -> PeachyMlsIncoming {
    let mut incoming = PeachyMlsIncoming {
        kind: 0,
        sender_actor_id: empty_buffer(),
        sender_device_id: empty_buffer(),
        plaintext: empty_buffer(),
        proposal_kind: 0,
        removed_self: false,
        epoch: 0,
        left_actor_ids: empty_buffer(),
    };
    let status = unsafe {
        peachy_mls_group_process_door(
            client,
            group.as_ptr(),
            group.len(),
            message.data,
            message.len,
            door,
            0,
            &mut incoming,
        )
    };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    incoming
}

/// Add `joiner` to `group` from `adder`, merged, the other members following.
fn add_member_through_the_c_door(
    adder: *mut PeachyMlsClient,
    joiner: *mut PeachyMlsClient,
    followers: &[*mut PeachyMlsClient],
    group: &[u8],
) {
    let mut key_package = empty_buffer();
    assert_eq!(
        unsafe { peachy_mls_key_package(joiner, &mut key_package) },
        PEACHY_MLS_OK
    );
    let mut commit = empty_buffer();
    let mut welcome = empty_buffer();
    assert_eq!(
        unsafe {
            peachy_mls_group_add_member(
                adder,
                group.as_ptr(),
                group.len(),
                key_package.data,
                key_package.len,
                &mut commit,
                &mut welcome,
            )
        },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    merge(adder, group);
    for follower in followers {
        let mut incoming = process(*follower, group, &commit, PEACHY_MLS_DOOR_COMMIT);
        unsafe { peachy_mls_incoming_free(&mut incoming) };
    }
    let mut joined = empty_buffer();
    assert_eq!(
        unsafe { peachy_mls_group_join(joiner, welcome.data, welcome.len, &mut joined) },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    unsafe {
        peachy_mls_buffer_free(&mut key_package);
        peachy_mls_buffer_free(&mut commit);
        peachy_mls_buffer_free(&mut welcome);
        peachy_mls_buffer_free(&mut joined);
    }
}

/// A LEAVE through the C door: Bo proposes the removal of his leaf, Ada and
/// Cy take the proposal on the message door, Cy commits it, and Ada reads
/// that Bo left. Nobody else has a leave to commit afterwards: the out-buffer
/// comes back empty and nothing is staged.
#[test]
fn a_leave_is_proposed_committed_and_read_through_the_c_door() {
    let fixture = Fixture::new();
    let ada = fixture.client(1, "actor-ada", "device-ada");
    let bo = fixture.client(2, "actor-bo", "device-bo");
    let cy = fixture.client(3, "actor-cy", "device-cy");
    let group = b"peachy-cabi-leave";
    assert_eq!(
        unsafe { peachy_mls_group_create(ada, group.as_ptr(), group.len()) },
        PEACHY_MLS_OK
    );
    add_member_through_the_c_door(ada, bo, &[], group);
    add_member_through_the_c_door(ada, cy, &[bo], group);

    // Bo's leaf, from his own roster.
    let mut count = 0usize;
    assert_eq!(
        unsafe { peachy_mls_group_member_count(bo, group.as_ptr(), group.len(), &mut count) },
        PEACHY_MLS_OK
    );
    let mut bo_leaf = u32::MAX;
    for position in 0..count {
        let mut leaf = 0u32;
        let mut actor = empty_buffer();
        let mut device = empty_buffer();
        let mut device_key = empty_buffer();
        let mut rejection = 1u32;
        assert_eq!(
            unsafe {
                peachy_mls_group_member(
                    bo,
                    group.as_ptr(),
                    group.len(),
                    position,
                    &mut leaf,
                    &mut actor,
                    &mut device,
                    &mut device_key,
                    std::ptr::null_mut(),
                    &mut rejection,
                )
            },
            PEACHY_MLS_OK
        );
        if bytes_of(&actor) == b"actor-bo" {
            bo_leaf = leaf;
        }
        unsafe {
            peachy_mls_buffer_free(&mut actor);
            peachy_mls_buffer_free(&mut device);
            peachy_mls_buffer_free(&mut device_key);
        }
    }
    assert_ne!(bo_leaf, u32::MAX);

    let mut proposal = empty_buffer();
    assert_eq!(
        unsafe {
            peachy_mls_group_propose_leave(bo, group.as_ptr(), group.len(), bo_leaf, &mut proposal)
        },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    for member in [ada, cy] {
        let mut incoming = process(member, group, &proposal, PEACHY_MLS_DOOR_MESSAGE);
        assert_eq!(incoming.kind, PEACHY_MLS_INCOMING_PROPOSAL);
        assert_eq!(bytes_of(&incoming.sender_actor_id), b"actor-bo");
        unsafe { peachy_mls_incoming_free(&mut incoming) };
    }
    unsafe { peachy_mls_buffer_free(&mut proposal) };

    let mut commit = empty_buffer();
    assert_eq!(
        unsafe {
            peachy_mls_group_commit_proposed_leaves(cy, group.as_ptr(), group.len(), &mut commit)
        },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    assert!(commit.len > 0, "Cy has a leave to commit");
    merge(cy, group);
    let mut incoming = process(ada, group, &commit, PEACHY_MLS_DOOR_COMMIT);
    assert_eq!(incoming.kind, PEACHY_MLS_INCOMING_COMMIT);
    assert!(!incoming.removed_self);
    assert_eq!(
        read_string_list(&bytes_of(&incoming.left_actor_ids)),
        vec!["actor-bo".to_owned()]
    );
    unsafe {
        peachy_mls_incoming_free(&mut incoming);
        peachy_mls_buffer_free(&mut commit);
    }

    let mut count = 0usize;
    assert_eq!(
        unsafe { peachy_mls_group_member_count(ada, group.as_ptr(), group.len(), &mut count) },
        PEACHY_MLS_OK
    );
    assert_eq!(count, 2, "Bo is out");

    let mut nothing = empty_buffer();
    assert_eq!(
        unsafe {
            peachy_mls_group_commit_proposed_leaves(ada, group.as_ptr(), group.len(), &mut nothing)
        },
        PEACHY_MLS_OK
    );
    assert_eq!(nothing.len, 0, "no leave is left to commit");
    let mut pending = true;
    assert_eq!(
        unsafe {
            peachy_mls_group_has_pending_commit(ada, group.as_ptr(), group.len(), &mut pending)
        },
        PEACHY_MLS_OK
    );
    assert!(!pending, "an empty answer stages nothing");
    unsafe { peachy_mls_buffer_free(&mut nothing) };
}

/// The list [`peachy_mls_group_begin_leave`] and
/// [`peachy_mls_group_follow_leave`] write: a count, then each proposal by
/// its length.
fn read_byte_list(bytes: &[u8]) -> Vec<Vec<u8>> {
    let u32_at = |at: usize| u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
    let count = u32_at(0);
    let mut at = 4;
    let mut items = Vec::new();
    for _ in 0..count {
        let len = u32_at(at);
        at += 4;
        items.push(bytes[at..at + len].to_vec());
        at += len;
    }
    assert_eq!(at, bytes.len(), "consumed exactly");
    items
}

fn is_leaving(client: *mut PeachyMlsClient, group: &[u8]) -> bool {
    let mut leaving = false;
    assert_eq!(
        unsafe { peachy_mls_group_is_leaving(client, group.as_ptr(), group.len(), &mut leaving) },
        PEACHY_MLS_OK
    );
    leaving
}

#[test]
fn a_leave_keeps_proposing_through_the_c_door_until_it_takes() {
    let fixture = Fixture::new();
    let ada = fixture.client(1, "actor-ada", "device-ada");
    let bo = fixture.client(2, "actor-bo", "device-bo");
    let cy = fixture.client(3, "actor-cy", "device-cy");
    let group = b"peachy-cabi-begin-leave";
    assert_eq!(
        unsafe { peachy_mls_group_create(ada, group.as_ptr(), group.len()) },
        PEACHY_MLS_OK
    );
    add_member_through_the_c_door(ada, bo, &[], group);
    add_member_through_the_c_door(ada, cy, &[bo], group);

    let mut first = empty_buffer();
    assert_eq!(
        unsafe { peachy_mls_group_begin_leave(bo, group.as_ptr(), group.len(), &mut first) },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    assert_eq!(read_byte_list(&bytes_of(&first)).len(), 1, "Bo's one leaf");
    unsafe { peachy_mls_buffer_free(&mut first) };
    assert!(is_leaving(bo, group));
    let mut pairs = empty_buffer();
    assert_eq!(
        unsafe { peachy_mls_group_leave_recipients(bo, group.as_ptr(), group.len(), &mut pairs) },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    let pairs = {
        let list = read_string_list(&bytes_of(&pairs));
        unsafe { peachy_mls_buffer_free(&mut pairs) };
        list
    };
    let mut devices: Vec<&str> = pairs.chunks(2).map(|pair| pair[1].as_str()).collect();
    devices.sort_unstable();
    assert_eq!(devices, vec!["device-ada", "device-bo", "device-cy"]);

    // Ada's update takes the epoch before anyone commits the leave.
    let mut update = empty_buffer();
    assert_eq!(
        unsafe { peachy_mls_group_self_update(ada, group.as_ptr(), group.len(), &mut update) },
        PEACHY_MLS_OK
    );
    merge(ada, group);
    let mut incoming = process(cy, group, &update, PEACHY_MLS_DOOR_COMMIT);
    unsafe { peachy_mls_incoming_free(&mut incoming) };

    // Bo's stub follows it and proposes again.
    let mut again = empty_buffer();
    assert_eq!(
        unsafe {
            peachy_mls_group_follow_leave(
                bo,
                group.as_ptr(),
                group.len(),
                update.data,
                update.len,
                &mut again,
            )
        },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    let proposals = read_byte_list(&bytes_of(&again));
    assert_eq!(proposals.len(), 1, "proposed again at the new epoch");
    unsafe {
        peachy_mls_buffer_free(&mut again);
        peachy_mls_buffer_free(&mut update);
    }

    // A view of bytes this test owns, never freed through the library.
    let mut held = proposals[0].clone();
    let proposal = PeachyMlsBuffer {
        data: held.as_mut_ptr(),
        len: held.len(),
    };
    let mut incoming = process(cy, group, &proposal, PEACHY_MLS_DOOR_MESSAGE);
    assert_eq!(incoming.kind, PEACHY_MLS_INCOMING_PROPOSAL);
    unsafe { peachy_mls_incoming_free(&mut incoming) };
    let mut commit = empty_buffer();
    assert_eq!(
        unsafe {
            peachy_mls_group_commit_proposed_leaves(cy, group.as_ptr(), group.len(), &mut commit)
        },
        PEACHY_MLS_OK
    );
    assert!(commit.len > 0);
    merge(cy, group);

    let mut nothing = empty_buffer();
    assert_eq!(
        unsafe {
            peachy_mls_group_follow_leave(
                bo,
                group.as_ptr(),
                group.len(),
                commit.data,
                commit.len,
                &mut nothing,
            )
        },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    assert!(read_byte_list(&bytes_of(&nothing)).is_empty());
    assert!(!is_leaving(bo, group), "the leave took");
    unsafe {
        peachy_mls_buffer_free(&mut nothing);
        peachy_mls_buffer_free(&mut commit);
    }
    drop(held);
}

/// The golden-fixture door, driven the way the Swift and Kotlin replays drive
/// it: one case object in as a NUL-terminated string, one verdict out as a
/// buffer the caller frees.
///
/// What it is here to catch is not the policy — `mls/core/tests/rules_fixture.rs`
/// replays all of `mls/fixtures/rules.json` against that — but the three ways a
/// string-in/string-out door goes wrong at a C boundary: a verdict that comes
/// back empty, a verdict that arrives NUL-terminated (it must not; the length
/// is the length), and an unknown name arriving as a DENIAL rather than as an
/// error. The third is the one that would let a replay pass over nothing.
#[cfg(feature = "fixture")]
#[test]
fn the_fixture_door_answers_a_case_and_refuses_a_name_that_does_not_exist() {
    let case =
        CString::new(r#"{"call":"evaluate","proposal":{"kind":"reinit","sender":"member"}}"#)
            .expect("the case has no NUL");
    let mut verdict = empty_buffer();
    assert_eq!(
        unsafe { peachy_mls_fixture_evaluate_case(case.as_ptr(), &mut verdict) },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    let text = String::from_utf8(bytes_of(&verdict)).expect("the verdict is UTF-8");
    assert_eq!(
        text, r#"{"decision":"deny","reason":"reinit_unsupported","reasonCode":5}"#,
        "the door must hand back exactly what peachy_mls_core::fixture wrote"
    );
    assert!(
        !text.ends_with('\0'),
        "the buffer carries its own length; a trailing NUL would be a byte of the verdict"
    );
    unsafe { peachy_mls_buffer_free(&mut verdict) };
    assert!(verdict.data.is_null(), "freeing zeroes the buffer");

    // The whole case object goes in, `expect` and `why` included and ignored,
    // so no wrapper has to strip a key before calling.
    let verbose = CString::new(
        r#"{"id":"x","why":"prose","call":"evaluate","proposal":{"kind":"add","sender":"external"},
            "expect":{"decision":"deny","reason":"external_sender","reasonCode":2}}"#,
    )
    .expect("the case has no NUL");
    let mut verdict = empty_buffer();
    assert_eq!(
        unsafe { peachy_mls_fixture_evaluate_case(verbose.as_ptr(), &mut verdict) },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    assert_eq!(
        String::from_utf8(bytes_of(&verdict)).expect("UTF-8"),
        r#"{"decision":"deny","reason":"external_sender","reasonCode":2}"#
    );
    unsafe { peachy_mls_buffer_free(&mut verdict) };

    // A kind nobody defines is an ERROR, never a verdict.
    let nonsense =
        CString::new(r#"{"call":"evaluate","proposal":{"kind":"teleport","sender":"member"}}"#)
            .expect("the case has no NUL");
    let mut unwritten = empty_buffer();
    assert_eq!(
        unsafe { peachy_mls_fixture_evaluate_case(nonsense.as_ptr(), &mut unwritten) },
        PEACHY_MLS_ERR_INVALID_ARGUMENT
    );
    assert!(last_error().contains("teleport"), "{}", last_error());
    assert!(
        unwritten.data.is_null(),
        "a failure must not write the out-parameter"
    );

    assert_eq!(
        unsafe { peachy_mls_fixture_evaluate_case(std::ptr::null(), &mut unwritten) },
        PEACHY_MLS_ERR_INVALID_ARGUMENT
    );
    assert!(last_error().contains("case_json"), "{}", last_error());
}

/// The leaf-credential renewal, through the C door: a client whose leaf is
/// five days from lapsing sees it is expiring, is refused a credential naming
/// somebody else, takes today's credential, commits the renewal, and the
/// other member processes it. docs/identity.md §Refreshing a seated leaf.
#[test]
fn a_seated_leaf_renews_its_credential_through_the_c_door() {
    let fixture = Fixture::new();
    let group = b"peachy-cabi-credential-refresh";

    // Ada is minted with only five days left, inside the refresh window.
    let mut seed = [0u8; 32];
    seed[0] = 41;
    seed[1] = 0xA5;
    let (_, public) = device_key_pair(&seed);
    let mint = |actor: &str, exp: i64| {
        fixture
            .issuer
            .issue(actor, "device-ada-refresh", &public, now_unix() - DAY, exp)
            .expect("mint")
    };
    let short = mint("actor-ada-refresh", now_unix() + 5 * DAY);
    let (status, ada) =
        fixture.open_in_memory(&short, &seed, Some(&Fixture::held("actor-ada-refresh")));
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    let bo = fixture.client(42, "actor-bo-refresh", "device-bo-refresh");

    assert_eq!(
        unsafe { peachy_mls_group_create(ada, group.as_ptr(), group.len()) },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    let mut bo_kp = empty_buffer();
    assert_eq!(
        unsafe { peachy_mls_key_package(bo, &mut bo_kp) },
        PEACHY_MLS_OK
    );
    let mut commit = empty_buffer();
    let mut welcome = empty_buffer();
    assert_eq!(
        unsafe {
            peachy_mls_group_add_member(
                ada,
                group.as_ptr(),
                group.len(),
                bo_kp.data,
                bo_kp.len,
                &mut commit,
                &mut welcome,
            )
        },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    merge(ada, group);
    let mut joined = empty_buffer();
    assert_eq!(
        unsafe { peachy_mls_group_join(bo, welcome.data, welcome.len, &mut joined) },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    unsafe {
        peachy_mls_buffer_free(&mut bo_kp);
        peachy_mls_buffer_free(&mut commit);
        peachy_mls_buffer_free(&mut welcome);
        peachy_mls_buffer_free(&mut joined);
    }

    let ask = |client: *mut PeachyMlsClient| {
        let (mut expiring, mut due, mut expires_at) = (false, true, 0i64);
        assert_eq!(
            unsafe {
                peachy_mls_group_leaf_credential_expiring(
                    client,
                    group.as_ptr(),
                    group.len(),
                    &mut expiring,
                )
            },
            PEACHY_MLS_OK,
            "{}",
            last_error()
        );
        assert_eq!(
            unsafe {
                peachy_mls_group_credential_refresh_due(
                    client,
                    group.as_ptr(),
                    group.len(),
                    &mut due,
                )
            },
            PEACHY_MLS_OK,
            "{}",
            last_error()
        );
        assert_eq!(
            unsafe {
                peachy_mls_group_own_leaf_credential_expires_at(
                    client,
                    group.as_ptr(),
                    group.len(),
                    &mut expires_at,
                )
            },
            PEACHY_MLS_OK,
            "{}",
            last_error()
        );
        (expiring, due, expires_at)
    };

    // Expiring, but nothing fresher to renew with yet: the cue to fetch one.
    let (expiring, due, leaf_exp) = ask(ada);
    assert!(expiring);
    assert!(!due);
    assert!(leaf_exp <= now_unix() + 5 * DAY);
    // Bo's thirty days are nowhere near the window.
    assert!(!ask(bo).0);
    // Five days left is nowhere near past the grace either.
    let mut past_grace = true;
    assert_eq!(
        unsafe {
            peachy_mls_group_leaf_credential_past_grace(
                ada,
                group.as_ptr(),
                group.len(),
                &mut past_grace,
            )
        },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    assert!(!past_grace);

    // A credential naming somebody else on the same key, certified under the
    // account key Ada holds, is a policy refusal.
    let swapped = fixture
        .issuer
        .issue_for_account(
            "actor-eve-refresh",
            "device-ada-refresh",
            &public,
            Some(&TestIssuer::test_account_key("actor-ada-refresh")),
            now_unix() - DAY,
            now_unix() + 30 * DAY,
        )
        .expect("mint");
    assert_eq!(
        unsafe {
            peachy_mls_client_update_credential(
                ada,
                swapped.as_ptr(),
                swapped.len(),
                std::ptr::null(),
                0,
            )
        },
        PEACHY_MLS_ERR_POLICY,
        "{}",
        last_error()
    );

    // Today's credential: now due, and the renewal commit lands on both sides.
    let fresh = mint("actor-ada-refresh", now_unix() + 30 * DAY);
    assert_eq!(
        unsafe {
            peachy_mls_client_update_credential(
                ada,
                fresh.as_ptr(),
                fresh.len(),
                std::ptr::null(),
                0,
            )
        },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    assert!(ask(ada).1, "a fresher credential in hand makes it due");

    let mut renewal = empty_buffer();
    assert_eq!(
        unsafe {
            peachy_mls_group_refresh_credential(ada, group.as_ptr(), group.len(), &mut renewal)
        },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    let epoch = merge(ada, group);
    let mut incoming = process(bo, group, &renewal, PEACHY_MLS_DOOR_COMMIT);
    assert_eq!(incoming.kind, PEACHY_MLS_INCOMING_COMMIT);
    assert_eq!(incoming.epoch, epoch);
    assert_eq!(bytes_of(&incoming.sender_actor_id), b"actor-ada-refresh");
    unsafe {
        peachy_mls_incoming_free(&mut incoming);
        peachy_mls_buffer_free(&mut renewal);
    }

    let (expiring, due, renewed_exp) = ask(ada);
    assert!(!expiring && !due, "renewed and settled");
    assert!(renewed_exp > now_unix() + 29 * DAY);

    unsafe {
        peachy_mls_client_free(ada);
        peachy_mls_client_free(bo);
    }
}

#[test]
fn the_account_store_door_seals_opens_and_refuses() {
    // Five unconditional entry points. What a C boundary gets wrong: an EMPTY
    // plaintext (a null-data buffer that is still an answer), a box that lost
    // its last byte, and a refusal that must arrive as a status plus a message.
    let mut key = empty_buffer();
    let status = unsafe { peachy_mls_generate_account_key(&mut key) };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    let key_bytes = bytes_of(&key);
    assert_eq!(key_bytes.len(), 32);

    let id = [0x11u8; 16];
    let sentinel = 0u8;
    let mut value = empty_buffer();
    let status = unsafe {
        peachy_mls_store_seal(
            key_bytes.as_ptr(),
            key_bytes.len(),
            id.as_ptr(),
            id.len(),
            &sentinel,
            0,
            &mut value,
        )
    };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    let value_bytes = bytes_of(&value);
    assert_eq!(value_bytes.len(), 1 + 12 + 256 + 16);

    let mut plaintext = empty_buffer();
    let status = unsafe {
        peachy_mls_store_open(
            key_bytes.as_ptr(),
            key_bytes.len(),
            id.as_ptr(),
            id.len(),
            value_bytes.as_ptr(),
            value_bytes.len(),
            &mut plaintext,
        )
    };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    assert!(
        bytes_of(&plaintext).is_empty(),
        "an empty plaintext is an answer"
    );

    // A wrong id is a status and a sentence, never an empty success.
    let other_id = [0x22u8; 16];
    let mut refused = empty_buffer();
    let status = unsafe {
        peachy_mls_store_open(
            key_bytes.as_ptr(),
            key_bytes.len(),
            other_id.as_ptr(),
            other_id.len(),
            value_bytes.as_ptr(),
            value_bytes.len(),
            &mut refused,
        )
    };
    assert_eq!(status, PEACHY_MLS_ERR_INVALID_ARGUMENT);
    assert!(last_error().contains("does not open"), "{}", last_error());

    // The box, both ways.
    let approver_seed = [0x11u8; 32];
    let recipient_seed = [0x33u8; 32];
    let mut approver_key = empty_buffer();
    let mut recipient_key = empty_buffer();
    unsafe {
        assert_eq!(
            peachy_mls_signing_key_public_key(approver_seed.as_ptr(), 32, &mut approver_key),
            PEACHY_MLS_OK
        );
        assert_eq!(
            peachy_mls_signing_key_public_key(recipient_seed.as_ptr(), 32, &mut recipient_key),
            PEACHY_MLS_OK
        );
    }
    let approver_key_bytes = bytes_of(&approver_key);
    let recipient_key_bytes = bytes_of(&recipient_key);
    let device_id = CString::new("0f8e2b1c-6a4d-4e3f-9b2a-7c5d1e0f3a9b").expect("no NUL");

    let mut sealed = empty_buffer();
    let status = unsafe {
        peachy_mls_account_key_seal(
            approver_seed.as_ptr(),
            approver_seed.len(),
            recipient_key_bytes.as_ptr(),
            recipient_key_bytes.len(),
            device_id.as_ptr(),
            key_bytes.as_ptr(),
            key_bytes.len(),
            &mut sealed,
        )
    };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    let sealed_bytes = bytes_of(&sealed);
    assert_eq!(sealed_bytes.len(), 93);

    let mut opened = empty_buffer();
    let status = unsafe {
        peachy_mls_account_key_open(
            recipient_seed.as_ptr(),
            recipient_seed.len(),
            approver_key_bytes.as_ptr(),
            approver_key_bytes.len(),
            device_id.as_ptr(),
            sealed_bytes.as_ptr(),
            sealed_bytes.len(),
            &mut opened,
        )
    };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    assert_eq!(bytes_of(&opened), key_bytes);

    let mut short = empty_buffer();
    let status = unsafe {
        peachy_mls_account_key_open(
            recipient_seed.as_ptr(),
            recipient_seed.len(),
            approver_key_bytes.as_ptr(),
            approver_key_bytes.len(),
            device_id.as_ptr(),
            sealed_bytes.as_ptr(),
            sealed_bytes.len() - 1,
            &mut short,
        )
    };
    assert_eq!(status, PEACHY_MLS_ERR_INVALID_ARGUMENT);
    assert!(last_error().contains("93 bytes"), "{}", last_error());

    // The new device's door: a version-1 box opens only under the device's
    // own switch for server-run approvals, confirmed approver or not, and a
    // linked box (the removed QR code's) never opens.
    let empty: [u8; 0] = [];
    let accept = |sealed: &[u8], confirmed: &[u8], allowed: bool| -> (i32, Vec<u8>) {
        let mut out = empty_buffer();
        let status = unsafe {
            peachy_mls_account_key_accept_hybrid(
                recipient_seed.as_ptr(),
                recipient_seed.len(),
                approver_key_bytes.as_ptr(),
                approver_key_bytes.len(),
                device_id.as_ptr(),
                sealed.as_ptr(),
                sealed.len(),
                empty.as_ptr(),
                0,
                confirmed.as_ptr(),
                confirmed.len(),
                allowed,
                &mut out,
            )
        };
        let bytes = bytes_of(&out);
        unsafe { peachy_mls_buffer_free(&mut out) };
        (status, bytes)
    };
    let (status, _) = accept(&sealed_bytes, &approver_key_bytes, false);
    assert_eq!(status, PEACHY_MLS_ERR_INVALID_ARGUMENT);
    assert!(
        last_error().contains("post-quantum box"),
        "{}",
        last_error()
    );
    let (status, accepted) = accept(&sealed_bytes, &empty, true);
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    assert_eq!(accepted, key_bytes);

    // A version-2 box (the removed QR code's): no door seals one any more.
    let mut linked_bytes = sealed_bytes.clone();
    linked_bytes[0] = 0x02;
    for allowed in [false, true] {
        let (status, _) = accept(&linked_bytes, &approver_key_bytes, allowed);
        assert_eq!(status, PEACHY_MLS_ERR_INVALID_ARGUMENT);
        assert!(
            last_error().contains("showed no QR code"),
            "{}",
            last_error()
        );
    }

    unsafe {
        peachy_mls_buffer_free(&mut key);
        peachy_mls_buffer_free(&mut value);
        peachy_mls_buffer_free(&mut plaintext);
        peachy_mls_buffer_free(&mut refused);
        peachy_mls_buffer_free(&mut approver_key);
        peachy_mls_buffer_free(&mut recipient_key);
        peachy_mls_buffer_free(&mut sealed);
        peachy_mls_buffer_free(&mut opened);
        peachy_mls_buffer_free(&mut short);
    }
}

#[test]
fn the_link_key_and_the_hybrid_box_cross_the_c_door() {
    let approver_seed = [0x11u8; 32];
    let recipient_seed = [0x33u8; 32];
    let account_key = [0xa1u8; 32];
    let device_id = CString::new("0f8e2b1c-6a4d-4e3f-9b2a-7c5d1e0f3a9b").expect("id");
    let commitment = [0x44u8; 32];
    let nonce = [0x55u8; 32];
    let empty: [u8; 0] = [];

    let mut seed = empty_buffer();
    assert_eq!(
        unsafe { peachy_mls_generate_device_link_kem_seed(&mut seed) },
        PEACHY_MLS_OK
    );
    let seed_bytes = bytes_of(&seed);
    assert_eq!(seed_bytes.len(), 32);

    let mut link_key = empty_buffer();
    let status = unsafe {
        peachy_mls_device_link_kem_public_key(seed_bytes.as_ptr(), seed_bytes.len(), &mut link_key)
    };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    let link_key_bytes = bytes_of(&link_key);
    assert_eq!(link_key_bytes.len(), 1216);

    // The waiting device signs its link key; the approver checks it under the
    // key the number was derived over.
    let recipient_key = peachy_mls_core::signing_key_public_key(&recipient_seed).expect("key");
    let approver_key = peachy_mls_core::signing_key_public_key(&approver_seed).expect("key");
    let mut signature = empty_buffer();
    let status = unsafe {
        peachy_mls_sign_device_link_kem(
            recipient_seed.as_ptr(),
            recipient_seed.len(),
            device_id.as_ptr(),
            commitment.as_ptr(),
            commitment.len(),
            nonce.as_ptr(),
            nonce.len(),
            link_key_bytes.as_ptr(),
            link_key_bytes.len(),
            &mut signature,
        )
    };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    let signature_bytes = bytes_of(&signature);
    let verify = |key: &[u8], link: &[u8]| -> bool {
        let mut valid = true;
        let status = unsafe {
            peachy_mls_verify_device_link_kem(
                key.as_ptr(),
                key.len(),
                device_id.as_ptr(),
                commitment.as_ptr(),
                commitment.len(),
                nonce.as_ptr(),
                nonce.len(),
                link.as_ptr(),
                link.len(),
                signature_bytes.as_ptr(),
                signature_bytes.len(),
                &mut valid,
            )
        };
        assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
        valid
    };
    assert!(verify(&recipient_key, &link_key_bytes));
    assert!(!verify(&approver_key, &link_key_bytes));
    assert!(!verify(&recipient_key, &empty));

    let mut sealed = empty_buffer();
    let status = unsafe {
        peachy_mls_account_key_seal_hybrid(
            approver_seed.as_ptr(),
            approver_seed.len(),
            recipient_key.as_ptr(),
            recipient_key.len(),
            link_key_bytes.as_ptr(),
            link_key_bytes.len(),
            device_id.as_ptr(),
            account_key.as_ptr(),
            account_key.len(),
            &mut sealed,
        )
    };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    let sealed_bytes = bytes_of(&sealed);
    assert_eq!(sealed_bytes.len(), 1213);
    assert_eq!(sealed_bytes[0], 0x03);

    let accept = |link_seed: &[u8]| -> (i32, Vec<u8>) {
        let mut out = empty_buffer();
        let status = unsafe {
            peachy_mls_account_key_accept_hybrid(
                recipient_seed.as_ptr(),
                recipient_seed.len(),
                approver_key.as_ptr(),
                approver_key.len(),
                device_id.as_ptr(),
                sealed_bytes.as_ptr(),
                sealed_bytes.len(),
                link_seed.as_ptr(),
                link_seed.len(),
                approver_key.as_ptr(),
                approver_key.len(),
                false,
                &mut out,
            )
        };
        let bytes = bytes_of(&out);
        unsafe { peachy_mls_buffer_free(&mut out) };
        (status, bytes)
    };
    let (status, opened) = accept(&seed_bytes);
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    assert_eq!(opened, account_key);
    let (status, _) = accept(&empty);
    assert_eq!(status, PEACHY_MLS_ERR_INVALID_ARGUMENT);
    assert!(last_error().contains("posted none"), "{}", last_error());
    let (status, _) = accept(&[0x5b; 32]);
    assert_eq!(status, PEACHY_MLS_ERR_INVALID_ARGUMENT);
    assert!(last_error().contains("does not open"), "{}", last_error());

    unsafe {
        peachy_mls_buffer_free(&mut seed);
        peachy_mls_buffer_free(&mut link_key);
        peachy_mls_buffer_free(&mut signature);
        peachy_mls_buffer_free(&mut sealed);
    }
}

#[test]
fn a_signed_self_note_names_its_sender_and_opens_only_under_its_key() {
    let mut key = empty_buffer();
    assert_eq!(
        unsafe { peachy_mls_generate_account_key(&mut key) },
        PEACHY_MLS_OK
    );
    let key_bytes = bytes_of(&key);
    let id = [0x99u8; 16];
    let note = br#"{"peachy":"read","v":1}"#;
    let seed = [0x11u8; 32];
    let (_, phone_key) = device_key_pair(&seed);
    let (_, other_key) = device_key_pair(&[0x55u8; 32]);
    let phone = CString::new("device-ada-phone").expect("no NUL");
    let issued = 1_790_000_000_000_i64;

    let mut value = empty_buffer();
    let status = unsafe {
        peachy_mls_note_seal_signed(
            key_bytes.as_ptr(),
            key_bytes.len(),
            id.as_ptr(),
            id.len(),
            note.as_ptr(),
            note.len(),
            phone.as_ptr(),
            issued,
            seed.as_ptr(),
            seed.len(),
            &mut value,
        )
    };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    let value_bytes = bytes_of(&value);

    let mut sender = empty_buffer();
    let status = unsafe {
        peachy_mls_note_sender(
            key_bytes.as_ptr(),
            key_bytes.len(),
            id.as_ptr(),
            id.len(),
            value_bytes.as_ptr(),
            value_bytes.len(),
            &mut sender,
        )
    };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    assert_eq!(bytes_of(&sender), b"device-ada-phone".to_vec());

    let open = |signing_key: &[u8], now: i64, out: &mut PeachyMlsBuffer| unsafe {
        peachy_mls_note_open_signed(
            key_bytes.as_ptr(),
            key_bytes.len(),
            id.as_ptr(),
            id.len(),
            value_bytes.as_ptr(),
            value_bytes.len(),
            phone.as_ptr(),
            signing_key.as_ptr(),
            signing_key.len(),
            now,
            out,
        )
    };
    let mut opened = empty_buffer();
    assert_eq!(
        open(&phone_key, issued, &mut opened),
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    assert_eq!(bytes_of(&opened), note.to_vec());

    let mut refused = empty_buffer();
    assert_eq!(
        open(&other_key, issued, &mut refused),
        PEACHY_MLS_ERR_INVALID_ARGUMENT
    );
    assert!(last_error().contains("does not verify"), "{}", last_error());
    assert_eq!(
        open(&phone_key, issued + 8 * 24 * 60 * 60 * 1000, &mut refused),
        PEACHY_MLS_ERR_INVALID_ARGUMENT
    );
    assert!(last_error().contains("stale"), "{}", last_error());

    unsafe {
        peachy_mls_buffer_free(&mut key);
        peachy_mls_buffer_free(&mut value);
        peachy_mls_buffer_free(&mut sender);
        peachy_mls_buffer_free(&mut opened);
        peachy_mls_buffer_free(&mut refused);
    }
}

#[test]
fn a_join_request_is_signed_by_the_asker_and_checked_against_their_key_package() {
    let fixture = Fixture::new();
    let ada = fixture.client(21, "actor-ada", "device-ada-phone");
    let mallory = fixture.client(22, "actor-mallory", "device-mallory-phone");
    let admitter = fixture.client(23, "actor-bob", "device-bob-phone");
    let room = b"room-1";

    let sign = |client: *mut PeachyMlsClient| -> Vec<u8> {
        let mut proof = empty_buffer();
        let status =
            unsafe { peachy_mls_sign_join_request(client, room.as_ptr(), room.len(), &mut proof) };
        assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
        let bytes = bytes_of(&proof);
        unsafe { peachy_mls_buffer_free(&mut proof) };
        bytes
    };
    let mut package = empty_buffer();
    let mut reference = empty_buffer();
    let status = unsafe {
        peachy_mls_key_package_with_ref(ada, &mut package, &mut reference, std::ptr::null_mut())
    };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    let ada_package = bytes_of(&package);

    let verify_pending =
        |group: &[u8], actor: &str, device: &str, proof: &[u8], pending: &[u8]| -> u32 {
            let actor = CString::new(actor).expect("no NUL");
            let device = CString::new(device).expect("no NUL");
            let mut verdict = 99u32;
            let status = unsafe {
                peachy_mls_verify_join_request(
                    admitter,
                    group.as_ptr(),
                    group.len(),
                    actor.as_ptr(),
                    device.as_ptr(),
                    proof.as_ptr(),
                    proof.len(),
                    ada_package.as_ptr(),
                    ada_package.len(),
                    if pending.is_empty() {
                        std::ptr::null()
                    } else {
                        pending.as_ptr()
                    },
                    pending.len(),
                    &mut verdict,
                )
            };
            assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
            verdict
        };
    // The admitter holds no copy of the room: Ada is somebody it is adding.
    let verify = |group: &[u8], actor: &str, device: &str, proof: &[u8]| -> u32 {
        verify_pending(
            group,
            actor,
            device,
            proof,
            &string_list(&["actor-cy", "actor-ada"]),
        )
    };

    let honest = sign(ada);
    assert_eq!(honest.len(), 89);
    assert_eq!(
        verify(room, "actor-ada", "device-ada-phone", &honest),
        PEACHY_MLS_JOIN_REQUEST_ACCEPTED
    );
    assert_eq!(
        verify(b"room-2", "actor-ada", "device-ada-phone", &honest),
        PEACHY_MLS_JOIN_REQUEST_BAD_SIGNATURE
    );
    // Mallory asks to seat Ada, signing with her own key.
    let forged = sign(mallory);
    assert_eq!(
        verify(room, "actor-ada", "device-ada-phone", &forged),
        PEACHY_MLS_JOIN_REQUEST_BAD_SIGNATURE
    );
    assert_eq!(
        verify(room, "actor-ada", "device-ada-laptop", &honest),
        PEACHY_MLS_JOIN_REQUEST_IDENTITY_MISMATCH
    );
    assert_eq!(
        verify(room, "actor-ada", "device-ada-phone", &honest[..88]),
        PEACHY_MLS_JOIN_REQUEST_MALFORMED
    );
    // A signed ask proves who is asking, never that they belong.
    assert_eq!(
        verify_pending(room, "actor-ada", "device-ada-phone", &honest, &[]),
        PEACHY_MLS_JOIN_REQUEST_NOT_A_MEMBER
    );
    assert_eq!(
        verify_pending(
            room,
            "actor-ada",
            "device-ada-phone",
            &honest,
            &string_list(&[])
        ),
        PEACHY_MLS_JOIN_REQUEST_NOT_A_MEMBER
    );
    assert_eq!(
        verify_pending(
            room,
            "actor-ada",
            "device-ada-phone",
            &honest,
            &string_list(&["actor-cy"])
        ),
        PEACHY_MLS_JOIN_REQUEST_NOT_A_MEMBER
    );
    // No separator splits an item: one pending actor whose id holds a
    // newline names nobody else.
    assert_eq!(
        verify_pending(
            room,
            "actor-ada",
            "device-ada-phone",
            &honest,
            &string_list(&["actor-cy\nactor-ada"])
        ),
        PEACHY_MLS_JOIN_REQUEST_NOT_A_MEMBER
    );
    // A list that is not consumed exactly is refused, never read short.
    for bad in [
        vec![0, 0, 0],
        vec![0, 0, 0, 2, 0, 0, 0, 1, b'a'],
        [string_list(&["actor-ada"]), vec![0]].concat(),
        vec![0, 0, 0, 1, 0, 0, 0, 9, b'a'],
        vec![0, 0, 0, 1, 0, 0, 0, 1, 0xff],
        vec![0xff, 0xff, 0xff, 0xff],
    ] {
        let actor = CString::new("actor-ada").expect("no NUL");
        let device = CString::new("device-ada-phone").expect("no NUL");
        let mut verdict = 99u32;
        let status = unsafe {
            peachy_mls_verify_join_request(
                admitter,
                room.as_ptr(),
                room.len(),
                actor.as_ptr(),
                device.as_ptr(),
                honest.as_ptr(),
                honest.len(),
                ada_package.as_ptr(),
                ada_package.len(),
                bad.as_ptr(),
                bad.len(),
                &mut verdict,
            )
        };
        assert_eq!(status, PEACHY_MLS_ERR_INVALID_ARGUMENT, "{bad:?}");
        // A refused call still leaves a verdict, and one that seats nobody.
        assert_eq!(verdict, PEACHY_MLS_JOIN_REQUEST_MALFORMED, "{bad:?}");
    }

    // The door for a person the caller admits by its own rule: every check
    // but membership.
    let verify_admitted = |actor: &str, device: &str, proof: &[u8]| -> u32 {
        let actor = CString::new(actor).expect("no NUL");
        let device = CString::new(device).expect("no NUL");
        let mut verdict = 99u32;
        let status = unsafe {
            peachy_mls_verify_admitted_join_request(
                admitter,
                room.as_ptr(),
                room.len(),
                actor.as_ptr(),
                device.as_ptr(),
                proof.as_ptr(),
                proof.len(),
                ada_package.as_ptr(),
                ada_package.len(),
                &mut verdict,
            )
        };
        assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
        verdict
    };
    assert_eq!(
        verify_admitted("actor-ada", "device-ada-phone", &honest),
        PEACHY_MLS_JOIN_REQUEST_ACCEPTED
    );
    assert_eq!(
        verify_admitted("actor-ada", "device-ada-phone", &forged),
        PEACHY_MLS_JOIN_REQUEST_BAD_SIGNATURE
    );
    assert_eq!(
        verify_admitted("actor-ada", "device-ada-laptop", &honest),
        PEACHY_MLS_JOIN_REQUEST_IDENTITY_MISMATCH
    );
    let mut verdict = 99u32;
    let status = unsafe {
        peachy_mls_verify_admitted_join_request(
            admitter,
            room.as_ptr(),
            room.len(),
            std::ptr::null(),
            std::ptr::null(),
            honest.as_ptr(),
            honest.len(),
            ada_package.as_ptr(),
            ada_package.len(),
            &mut verdict,
        )
    };
    assert_ne!(status, PEACHY_MLS_OK, "a NULL actor is a caller bug");

    // The ask's add judges membership again on the store it commits on: in
    // a group the admitter holds, Ada is seated only while it is inviting
    // her, and a refusal stages nothing.
    let held = b"cabi-ask-add";
    assert_eq!(
        unsafe { peachy_mls_group_create(admitter, held.as_ptr(), held.len()) },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    let ask_add = |pending: &[u8]| -> (i32, Vec<u8>) {
        let mut commit = empty_buffer();
        let mut welcome = empty_buffer();
        let status = unsafe {
            peachy_mls_group_add_member_for_ask(
                admitter,
                held.as_ptr(),
                held.len(),
                ada_package.as_ptr(),
                ada_package.len(),
                if pending.is_empty() {
                    std::ptr::null()
                } else {
                    pending.as_ptr()
                },
                pending.len(),
                &mut commit,
                &mut welcome,
            )
        };
        let out = bytes_of(&welcome);
        unsafe {
            peachy_mls_buffer_free(&mut commit);
            peachy_mls_buffer_free(&mut welcome);
        }
        (status, out)
    };
    let (status, _) = ask_add(&[]);
    assert_eq!(status, PEACHY_MLS_ERR_INVALID_ARGUMENT);
    assert!(last_error().contains("not_a_member"), "{}", last_error());
    let (status, welcome) = ask_add(&string_list(&["actor-ada"]));
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    assert!(!welcome.is_empty(), "the ask's add stages a Welcome");

    unsafe {
        peachy_mls_buffer_free(&mut package);
        peachy_mls_buffer_free(&mut reference);
        peachy_mls_client_free(ada);
        peachy_mls_client_free(mallory);
        peachy_mls_client_free(admitter);
    }
}

/// The store key, through the C door: a keyed client writes a file that is not
/// SQLite to anything without the key, reopens under its key with its group,
/// and does not open under another key or none. `mls/core/src/sqlite.rs`
/// §Encryption at rest.
#[test]
fn a_keyed_store_is_encrypted_and_reopens_only_under_its_key() {
    let fixture = Fixture::new();
    let dir = std::env::temp_dir().join(format!("peachy-mls-cabi-key-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let path = dir.join("ada.sqlite");
    let path_str = path.to_str().expect("a UTF-8 path");
    let key = [7u8; 32];
    let group = b"cabi-keyed";

    let ada = fixture.client_keyed(1, "actor-ada", "device-ada", Some(path_str), Some(&key[..]));
    assert_eq!(
        unsafe { peachy_mls_group_create(ada, group.as_ptr(), group.len()) },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    unsafe { peachy_mls_client_free(ada) };

    let bytes = std::fs::read(&path).expect("the store file");
    assert!(bytes.len() >= 16);
    assert_ne!(
        &bytes[..16],
        b"SQLite format 3\0",
        "the file must not be plain SQLite"
    );

    let (status, client) =
        fixture.try_client_keyed(1, "actor-ada", "device-ada", Some(path_str), None);
    assert_eq!(status, PEACHY_MLS_ERR_STORAGE, "no key must not open it");
    assert!(client.is_null());
    let (status, client) = fixture.try_client_keyed(
        1,
        "actor-ada",
        "device-ada",
        Some(path_str),
        Some(&[8u8; 32][..]),
    );
    assert_eq!(
        status, PEACHY_MLS_ERR_STORAGE,
        "another key must not open it"
    );
    assert!(client.is_null());

    let again = fixture.client_keyed(1, "actor-ada", "device-ada", Some(path_str), Some(&key[..]));
    let mut epoch = u64::MAX;
    assert_eq!(
        unsafe { peachy_mls_group_epoch(again, group.as_ptr(), group.len(), &mut epoch) },
        PEACHY_MLS_OK,
        "the group must come back under its key: {}",
        last_error()
    );
    unsafe { peachy_mls_client_free(again) };

    // A key of the wrong length, and a key with no file, are argument errors.
    let (seed, token) = fixture.identity(1, "actor-ada", "device-ada");
    let short = [1u8; 16];
    for (path_ptr, key_ptr, key_len) in [
        (
            CString::new(path_str).expect("no NUL"),
            short.as_ptr(),
            short.len(),
        ),
        (CString::new("").expect("no NUL"), key.as_ptr(), key.len()),
    ] {
        let mut client: *mut PeachyMlsClient = std::ptr::null_mut();
        let status = unsafe {
            peachy_mls_client_open(
                token.as_ptr(),
                token.len(),
                seed.as_ptr(),
                seed.len(),
                fixture.trusted_json.as_ptr(),
                path_ptr.as_ptr(),
                key_ptr,
                key_len,
                std::ptr::null(),
                0,
                &mut client,
            )
        };
        assert_eq!(status, PEACHY_MLS_ERR_INVALID_ARGUMENT, "{}", last_error());
        assert!(client.is_null());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The 48-byte keyspec, through the C door — the Apple clients' shape
/// (`mls/core/src/sqlite.rs` §The plaintext header): the file keeps SQLite's
/// 32-byte header so iOS recognizes it, nothing after it is readable, and the
/// store reopens with its group under the same keyspec and under no other.
#[test]
fn a_keyspec_store_keeps_a_plaintext_header_and_reopens_only_under_its_keyspec() {
    let fixture = Fixture::new();
    let dir = std::env::temp_dir().join(format!("peachy-mls-cabi-keyspec-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let path = dir.join("ada.sqlite");
    let path_str = path.to_str().expect("a UTF-8 path");
    let mut keyspec = [9u8; 48];
    keyspec[32..].copy_from_slice(&[4u8; 16]);
    let group = b"cabi-keyspec";

    let ada = fixture.client_keyed(
        1,
        "actor-ada",
        "device-ada",
        Some(path_str),
        Some(&keyspec[..]),
    );
    assert_eq!(
        unsafe { peachy_mls_group_create(ada, group.as_ptr(), group.len()) },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    unsafe { peachy_mls_client_free(ada) };

    let bytes = std::fs::read(&path).expect("the store file");
    assert_eq!(
        &bytes[..16],
        b"SQLite format 3\0",
        "the header stays SQLite's"
    );
    let wal = std::fs::read(format!("{path_str}-wal")).unwrap_or_default();
    for file in [&bytes, &wal] {
        assert!(
            !file.windows(6).any(|w| w == b"mls_kv"),
            "nothing after the header may be readable"
        );
    }

    // The raw key alone — the same 32 bytes without the salt — does not open it.
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&keyspec[..32]);
    let (status, client) =
        fixture.try_client_keyed(1, "actor-ada", "device-ada", Some(path_str), Some(&raw[..]));
    assert_eq!(
        status, PEACHY_MLS_ERR_STORAGE,
        "the key without its salt must not open it"
    );
    assert!(client.is_null());
    let (status, client) =
        fixture.try_client_keyed(1, "actor-ada", "device-ada", Some(path_str), None);
    assert_eq!(status, PEACHY_MLS_ERR_STORAGE, "no key must not open it");
    assert!(client.is_null());

    let again = fixture.client_keyed(
        1,
        "actor-ada",
        "device-ada",
        Some(path_str),
        Some(&keyspec[..]),
    );
    let mut epoch = u64::MAX;
    assert_eq!(
        unsafe { peachy_mls_group_epoch(again, group.as_ptr(), group.len(), &mut epoch) },
        PEACHY_MLS_OK,
        "the group must come back under its keyspec: {}",
        last_error()
    );
    unsafe { peachy_mls_client_free(again) };
    let _ = std::fs::remove_dir_all(&dir);
}

/// `adder` founds `group` and seats `joiner` in it, all through the C doors.
fn found_with(adder: *mut PeachyMlsClient, joiner: *mut PeachyMlsClient, group: &[u8]) {
    assert_eq!(
        unsafe { peachy_mls_group_create(adder, group.as_ptr(), group.len()) },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    let mut key_package = empty_buffer();
    assert_eq!(
        unsafe { peachy_mls_key_package(joiner, &mut key_package) },
        PEACHY_MLS_OK
    );
    let mut commit = empty_buffer();
    let mut welcome = empty_buffer();
    assert_eq!(
        unsafe {
            peachy_mls_group_add_member(
                adder,
                group.as_ptr(),
                group.len(),
                key_package.data,
                key_package.len,
                &mut commit,
                &mut welcome,
            )
        },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    merge(adder, group);
    let mut joined = empty_buffer();
    assert_eq!(
        unsafe { peachy_mls_group_join(joiner, welcome.data, welcome.len, &mut joined) },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    unsafe {
        peachy_mls_buffer_free(&mut key_package);
        peachy_mls_buffer_free(&mut commit);
        peachy_mls_buffer_free(&mut welcome);
        peachy_mls_buffer_free(&mut joined);
    }
}

/// `peachy_mls_group_observe_account_keys` into a real buffer, as the actor
/// ids it reported.
fn observe(client: *mut PeachyMlsClient, group: &[u8]) -> Vec<String> {
    let mut changed = empty_buffer();
    assert_eq!(
        unsafe {
            peachy_mls_group_observe_account_keys(client, group.as_ptr(), group.len(), &mut changed)
        },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    let actors = read_string_list(&bytes_of(&changed));
    unsafe { peachy_mls_buffer_free(&mut changed) };
    actors
}

/// Rule 5 for the "security code changed" notice. Observing account keys
/// WRITES: it records the new key as seen, so the change is reported once.
/// A null out-parameter must be refused before that record is made, or the
/// notice is consumed with nowhere to go and never shown.
#[test]
fn a_null_out_parameter_does_not_swallow_a_security_code_change() {
    let fixture = Fixture::new();
    let ada = fixture.client(1, "actor-ada", "device-ada");
    let bo = fixture.client(2, "actor-bo", "device-bo");
    let first = b"cabi-account-keys-first";
    let second = b"cabi-account-keys-second";

    // Ada pins Bo's account key on first sight, in silence.
    found_with(ada, bo, first);
    assert!(observe(ada, first).is_empty());

    // Bo comes back on a new phone under a new account key, and Ada starts a
    // conversation with him.
    let bo_again = fixture.client_for_account(3, "actor-bo", "device-bo-new", &[0xb1; 32]);
    found_with(ada, bo_again, second);

    assert_eq!(
        unsafe {
            peachy_mls_group_observe_account_keys(
                ada,
                second.as_ptr(),
                second.len(),
                std::ptr::null_mut(),
            )
        },
        PEACHY_MLS_ERR_INVALID_ARGUMENT
    );
    assert_eq!(
        observe(ada, second),
        vec!["actor-bo".to_string()],
        "a refused call consumed the security code change",
    );
    assert!(observe(ada, second).is_empty(), "and it is reported once");

    unsafe {
        peachy_mls_client_free(ada);
        peachy_mls_client_free(bo);
        peachy_mls_client_free(bo_again);
    }
}

/// Forgetting an own device takes its key too: NULL with length 0 for none,
/// 32 bytes for the device list's key, anything else refused. And the
/// own-sibling and rejoin answers are string lists, not lines.
#[test]
fn forgetting_an_own_device_takes_an_optional_key() {
    let fixture = Fixture::new();
    let ada = fixture.client(41, "actor-ada", "device-ada-laptop");
    let forget = |device: &str, key: Option<&[u8]>| -> (i32, bool) {
        let device = CString::new(device).expect("no NUL");
        let mut new = false;
        let (ptr, len) = key.map_or((std::ptr::null(), 0), |k| (k.as_ptr(), k.len()));
        let status =
            unsafe { peachy_mls_forget_own_device(ada, device.as_ptr(), ptr, len, &mut new) };
        (status, new)
    };
    assert_eq!(forget("device-ada-phone", None), (PEACHY_MLS_OK, true));
    assert_eq!(forget("device-ada-phone", None), (PEACHY_MLS_OK, false));
    // A key not seen before for a forgotten id is news.
    assert_eq!(
        forget("device-ada-phone", Some(&[7u8; 32])),
        (PEACHY_MLS_OK, true)
    );
    assert_eq!(
        forget("device-ada-phone", Some(&[7u8; 32])),
        (PEACHY_MLS_OK, false)
    );
    assert_eq!(
        forget("device-ada-tablet", Some(&[1, 2, 3])).0,
        PEACHY_MLS_ERR_INVALID_ARGUMENT
    );
    // An id outside the charset is refused.
    assert_eq!(
        forget("device-ada-phone#00", None).0,
        PEACHY_MLS_ERR_INVALID_ARGUMENT
    );
    assert_eq!(
        forget("device-ada\nphone", None).0,
        PEACHY_MLS_ERR_INVALID_ARGUMENT
    );

    let mut ids = empty_buffer();
    assert_eq!(
        unsafe { peachy_mls_own_sibling_leaves(ada, &mut ids) },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    assert_eq!(bytes_of(&ids), string_list(&[]));
    unsafe { peachy_mls_buffer_free(&mut ids) };

    let group = b"cabi-no-report";
    let mut report = empty_buffer();
    assert_eq!(
        unsafe {
            peachy_mls_group_take_rejoin_report(ada, group.as_ptr(), group.len(), &mut report)
        },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    assert!(bytes_of(&report).is_empty(), "no report is an empty buffer");
    unsafe { peachy_mls_buffer_free(&mut report) };
    // The doors the apps draw through: nothing to peek, nothing to drop.
    let mut peeked = empty_buffer();
    assert_eq!(
        unsafe {
            peachy_mls_group_peek_rejoin_report(
                ada,
                group.as_ptr(),
                group.len(),
                1_000,
                &mut peeked,
            )
        },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    assert!(
        bytes_of(&peeked).is_empty(),
        "no report peeks as an empty buffer"
    );
    let mut dropped = true;
    assert_eq!(
        unsafe {
            peachy_mls_group_drop_rejoin_report(ada, group.as_ptr(), group.len(), 7, &mut dropped)
        },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    assert!(!dropped, "nothing was there to drop");
    unsafe {
        peachy_mls_buffer_free(&mut peeked);
        peachy_mls_client_free(ada);
    }
}

/// A call link's client adopts the main client's own-device trust through the
/// C door: the main client's forgotten phone is forgotten in the link's
/// client too, another device's trust is refused, and a standing read after
/// any failure is one that is not the person's.
#[test]
fn a_call_link_client_adopts_the_main_clients_trust() {
    let fixture = Fixture::new();
    let main = fixture.client(41, "actor-ada", "device-ada-laptop");
    let link = fixture.client(41, "actor-ada", "device-ada-laptop");
    let tablet = fixture.client(42, "actor-ada", "device-ada-tablet");
    let phone_key = [7u8; 32];
    let phone = CString::new("device-ada-phone").expect("no NUL");
    let mut new = false;
    assert_eq!(
        unsafe {
            peachy_mls_forget_own_device(main, phone.as_ptr(), phone_key.as_ptr(), 32, &mut new)
        },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    let trust_of = |client: *mut PeachyMlsClient| -> CString {
        let mut out = empty_buffer();
        assert_eq!(
            unsafe { peachy_mls_own_device_trust(client, &mut out) },
            PEACHY_MLS_OK,
            "{}",
            last_error()
        );
        let json = CString::new(bytes_of(&out)).expect("no NUL in JSON");
        unsafe { peachy_mls_buffer_free(&mut out) };
        json
    };
    let actor = CString::new("actor-ada").expect("no NUL");
    let standing = |client: *mut PeachyMlsClient| -> (i32, u32) {
        let mut out = u32::MAX;
        let status = unsafe {
            peachy_mls_own_device_standing(
                client,
                actor.as_ptr(),
                phone.as_ptr(),
                phone_key.as_ptr(),
                32,
                &mut out,
            )
        };
        (status, out)
    };
    assert_eq!(
        standing(link),
        (PEACHY_MLS_OK, PEACHY_MLS_OWN_STANDING_OFF_CHAIN)
    );
    assert_eq!(
        unsafe { peachy_mls_adopt_own_device_trust(link, trust_of(tablet).as_ptr()) },
        PEACHY_MLS_ERR_INVALID_ARGUMENT
    );
    assert_eq!(
        unsafe { peachy_mls_adopt_own_device_trust(link, trust_of(main).as_ptr()) },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    assert_eq!(
        standing(link),
        (PEACHY_MLS_OK, PEACHY_MLS_OWN_STANDING_FORGOTTEN)
    );
    // A NULL actor fails, and leaves a standing that is not the person's.
    let mut out = PEACHY_MLS_OWN_STANDING_THIS_DEVICE;
    assert_ne!(
        unsafe {
            peachy_mls_own_device_standing(
                link,
                std::ptr::null(),
                phone.as_ptr(),
                phone_key.as_ptr(),
                32,
                &mut out,
            )
        },
        PEACHY_MLS_OK
    );
    assert_eq!(out, PEACHY_MLS_OWN_STANDING_OFF_CHAIN);
    unsafe {
        peachy_mls_client_free(main);
        peachy_mls_client_free(link);
        peachy_mls_client_free(tablet);
    }
}

/// The call-signal doors read the group the store holds. The notification
/// extension (a second client on the same file) merges a commit that removed
/// Cy; the app, which has not touched the group since, must neither take
/// Cy's live frames through `peachy_mls_group_call_open` nor seal its own
/// heartbeat through `peachy_mls_group_call_seal` (or `_seal_signed`) under
/// the epoch Cy was removed from: the live key never outlives its epoch.
/// Each door is the first the app calls after the merge, on a fresh store, so
/// no other door's catch-up stands in for its own.
#[test]
fn the_call_signal_doors_catch_up_with_a_removal_another_process_merged() {
    for door in [CallDoor::Open, CallDoor::Seal, CallDoor::SealSigned] {
        call_door_after_a_removal_merged_elsewhere(door);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallDoor {
    Open,
    Seal,
    SealSigned,
}

fn call_door_after_a_removal_merged_elsewhere(door: CallDoor) {
    use peachy_mls_core::call::{CallSignal, CallSignalBody};
    use peachy_mls_core::{Client, ClientConfig, PeachyStorage, SqliteKv};

    let fixture = Fixture::new();
    let dir = std::env::temp_dir().join(format!(
        "peachy-mls-call-catch-up-{}-{door:?}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let path = dir.join("ada.sqlite3");
    let path_str = path.to_str().expect("a UTF-8 path").to_string();
    let group = b"cabi-call-catch-up";
    let call_id = *b"cabi-call-catchu";
    let call_hex: String = call_id.iter().map(|b| format!("{b:02x}")).collect();

    let core_client = |tag: u8, name: &str, storage: PeachyStorage| -> Client {
        let (seed, token) =
            fixture.identity(tag, &format!("actor-{name}"), &format!("device-{name}"));
        let trusted = fixture.issuer.trusted_keys().expect("trusted keys");
        let held = Fixture::held(&format!("actor-{name}"));
        Client::new(
            ClientConfig::new(token, seed, trusted)
                .with_storage(storage)
                .with_own_account_identity(Some(held)),
        )
        .expect("client")
    };
    let app = fixture.client_on(1, "actor-ada", "device-ada", Some(&path_str));
    let mut bo = core_client(2, "bo", PeachyStorage::in_memory());
    let mut cy = core_client(3, "cy", PeachyStorage::in_memory());

    // The app founds the group through the C doors and adds Bo, then Cy.
    assert_eq!(
        unsafe { peachy_mls_group_create(app, group.as_ptr(), group.len()) },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    add_through_the_c_door(app, group, &mut bo);
    let cy_added = add_through_the_c_door(app, group, &mut cy);
    bo.process_commit(group, &cy_added)
        .expect("Bo takes Cy's add");
    let cy_leaf = cy.leaf_of_device(group, "device-cy").expect("Cy's leaf");

    // Bo removes Cy; the extension, on the app's own file, merges it.
    let cy_key = bo
        .roster(group)
        .expect("roster")
        .into_iter()
        .find(|entry| entry.leaf_index == cy_leaf)
        .expect("Cy's entry")
        .leaf_key;
    let removal = bo
        .remove_member(group, cy_leaf, &cy_key)
        .expect("remove Cy");
    bo.merge_pending_commit(group).expect("merge");
    {
        let storage = PeachyStorage::open(Box::new(SqliteKv::open(&path_str).expect("open")))
            .expect("storage");
        let mut extension = core_client(1, "ada", storage);
        extension
            .process_commit(group, &removal.commit)
            .expect("the extension merges");
    }

    let live_joined = |member: &mut Client, participant: &str| -> Vec<u8> {
        let leaf = member
            .leaf_of_device(group, &member.identity().device_id.clone())
            .expect("a leaf");
        let signal = CallSignal::new(
            call_id,
            CallSignalBody::Joined {
                participant_id: participant.into(),
                session_id: format!("sess-{participant}"),
                track_names: Vec::new(),
                leaf_index: leaf,
                media_key: Vec::new(),
                started_at_ms: 0,
                media_key_pq: Vec::new(),
                participation: None,
            },
        );
        // A participant's heartbeat.
        member
            .call_media_start(
                group,
                &call_id,
                participant,
                &format!("sess-{participant}"),
                &[],
            )
            .expect("started");
        member
            .seal_call_signal(group, &signal)
            .expect("a live heartbeat")
    };
    // A member's copy opens the envelope: one keyed by the epoch opens for no
    // group id alone. Bo kept the epoch Cy was removed from.
    let unwrap_by = |member: &mut Client, envelope: &[u8]| -> Vec<u8> {
        member
            .open_envelope(envelope)
            .expect("the store answers")
            .expect("a kind-6 envelope")
            .inner
    };
    let open_at_app = |inner: Vec<u8>| -> i32 {
        let mut json = empty_buffer();
        let status = unsafe {
            peachy_mls_group_call_open(
                app,
                group.as_ptr(),
                group.len(),
                inner.as_ptr(),
                inner.len(),
                &mut json,
            )
        };
        unsafe { peachy_mls_buffer_free(&mut json) };
        status
    };

    let joined = CString::new(format!(
        r#"{{"callId":"{call_hex}","type":"joined","participantId":"p-ada","sessionId":"sess-ada","trackNames":[],"leafIndex":0}}"#
    ))
    .expect("no NUL");
    if door == CallDoor::Open {
        // Cy, removed, sends a live heartbeat under the epoch it was removed
        // from: the app's open door refuses it.
        let forged = live_joined(&mut cy, "p-cy");
        assert_ne!(
            open_at_app(unwrap_by(&mut bo, &forged)),
            PEACHY_MLS_OK,
            "the app took a removed member's live frame"
        );
    } else {
        // The app's own heartbeat is not Cy's to read. The app joins the
        // call through the media door.
        let shared = CString::new(format!(
            r#"{{"op":"start","callId":"{call_hex}","participantId":"p-ada","sessionId":"sess-ada","trackNames":[]}}"#
        ))
        .expect("no NUL");
        let mut answer = empty_buffer();
        assert_eq!(
            unsafe {
                peachy_mls_group_call_media(
                    app,
                    group.as_ptr(),
                    group.len(),
                    shared.as_ptr(),
                    &mut answer,
                )
            },
            PEACHY_MLS_OK,
            "{}",
            last_error()
        );
        unsafe { peachy_mls_buffer_free(&mut answer) };
        let seal = if door == CallDoor::Seal {
            peachy_mls_group_call_seal
        } else {
            peachy_mls_group_call_seal_signed
        };
        let mut envelope = empty_buffer();
        assert_eq!(
            unsafe {
                seal(
                    app,
                    group.as_ptr(),
                    group.len(),
                    joined.as_ptr(),
                    &mut envelope,
                )
            },
            PEACHY_MLS_OK,
            "{}",
            last_error()
        );
        let sealed = bytes_of(&envelope);
        unsafe { peachy_mls_buffer_free(&mut envelope) };
        assert!(
            cy.open_envelope(&sealed)
                .expect("the store answers")
                .is_none(),
            "Cy opened the app's envelope ({door:?})"
        );
        let inner = unwrap_by(&mut bo, &sealed);
        assert!(
            cy.open_call_signal(group, &inner).is_err(),
            "Cy read the app's heartbeat ({door:?})"
        );
        assert!(bo.open_call_signal(group, &inner).is_ok(), "Bo reads it");
    }

    // Control: Bo, still a member, is heard.
    let heard = live_joined(&mut bo, "p-bo");
    let heard = unwrap_by(&mut bo, &heard);
    assert_eq!(open_at_app(heard), PEACHY_MLS_OK, "{}", last_error());
    unsafe { peachy_mls_client_free(app) };
    let _ = std::fs::remove_dir_all(&dir);
}

/// The exporter door reads the group the store holds, as the call doors do.
/// The notification extension merges a commit that removed Cy; the app, which
/// has not touched the group since, exports a secret (a typing frame's key)
/// as its first door: the secret is the epoch after the removal, the one Bo
/// derives, and not the one Cy still holds.
#[test]
fn the_exporter_door_catches_up_with_a_removal_another_process_merged() {
    use peachy_mls_core::{Client, ClientConfig, PeachyStorage, SqliteKv};

    let fixture = Fixture::new();
    let dir =
        std::env::temp_dir().join(format!("peachy-mls-export-catch-up-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let path = dir.join("ada.sqlite3");
    let path_str = path.to_str().expect("a UTF-8 path").to_string();
    let group = b"cabi-export-catch-up";
    let label = "peachy typing";
    let core_client = |tag: u8, name: &str, storage: PeachyStorage| -> Client {
        let (seed, token) =
            fixture.identity(tag, &format!("actor-{name}"), &format!("device-{name}"));
        let trusted = fixture.issuer.trusted_keys().expect("trusted keys");
        let held = Fixture::held(&format!("actor-{name}"));
        Client::new(
            ClientConfig::new(token, seed, trusted)
                .with_storage(storage)
                .with_own_account_identity(Some(held)),
        )
        .expect("client")
    };
    let app = fixture.client_on(1, "actor-ada", "device-ada", Some(&path_str));
    let mut bo = core_client(2, "bo", PeachyStorage::in_memory());
    let mut cy = core_client(3, "cy", PeachyStorage::in_memory());
    assert_eq!(
        unsafe { peachy_mls_group_create(app, group.as_ptr(), group.len()) },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    add_through_the_c_door(app, group, &mut bo);
    let cy_added = add_through_the_c_door(app, group, &mut cy);
    bo.process_commit(group, &cy_added)
        .expect("Bo takes Cy's add");
    let cy_leaf = cy.leaf_of_device(group, "device-cy").expect("Cy's leaf");

    // Bo removes Cy; the extension, on the app's own file, merges it.
    let cy_key = bo
        .roster(group)
        .expect("roster")
        .into_iter()
        .find(|entry| entry.leaf_index == cy_leaf)
        .expect("Cy's entry")
        .leaf_key;
    let removal = bo
        .remove_member(group, cy_leaf, &cy_key)
        .expect("remove Cy");
    bo.merge_pending_commit(group).expect("merge");
    {
        let storage = PeachyStorage::open(Box::new(SqliteKv::open(&path_str).expect("open")))
            .expect("storage");
        let mut extension = core_client(1, "ada", storage);
        extension
            .process_commit(group, &removal.commit)
            .expect("the extension merges");
    }

    let label_c = CString::new(label).expect("no NUL");
    let mut secret = empty_buffer();
    assert_eq!(
        unsafe {
            peachy_mls_group_export_secret(
                app,
                group.as_ptr(),
                group.len(),
                label_c.as_ptr(),
                std::ptr::null(),
                0,
                32,
                &mut secret,
            )
        },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    let exported = bytes_of(&secret);
    unsafe { peachy_mls_buffer_free(&mut secret) };
    assert_eq!(
        exported,
        bo.export_secret(group, label, &[], 32).expect("Bo exports"),
        "the app exported from the epoch after the removal"
    );
    assert_ne!(
        exported,
        cy.export_secret(group, label, &[], 32).expect("Cy exports"),
        "Cy, removed, holds the app's exported secret"
    );
    unsafe { peachy_mls_client_free(app) };
    let _ = std::fs::remove_dir_all(&dir);
}

/// The seat-ask verdict reads the group the store holds, as the call and
/// exporter doors do. Bo's app and Bo's notification extension are two
/// handles on one keyed file. Mallory's second device asks Bo for a seat and
/// the app takes the ask in; then Ada removes Mallory and the EXTENSION
/// applies the removal. The app's verdict on the ask, its first door after
/// the extension wrote, is not-a-member: the add that would follow an
/// acceptance seats the device in the group as the store holds it, which
/// would put the person the group just removed back in.
#[test]
fn the_seat_ask_verdict_catches_up_with_a_removal_another_process_applied() {
    let fixture = Fixture::new();
    let dir = std::env::temp_dir().join(format!(
        "peachy-mls-seat-ask-catch-up-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let path = dir.join("bo.sqlite3");
    let path_str = path.to_str().expect("a UTF-8 path").to_string();
    let key = [9u8; 32];
    let group = b"cabi-seat-ask-catch-up";

    let ada = fixture.client(1, "actor-ada", "device-ada");
    let app = fixture.client_keyed(2, "actor-bo", "device-bo", Some(&path_str), Some(&key[..]));
    let extension =
        fixture.client_keyed(2, "actor-bo", "device-bo", Some(&path_str), Some(&key[..]));
    let mal = fixture.client(3, "actor-mal", "device-mal");
    let mal2 = fixture.client(4, "actor-mal", "device-mal-2");

    // Ada founds and seats Bo, then Mallory; Bo's app follows.
    assert_eq!(
        unsafe { peachy_mls_group_create(ada, group.as_ptr(), group.len()) },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    add_member_through_the_c_door(ada, app, &[], group);
    add_member_through_the_c_door(ada, mal, &[app], group);

    // Mallory's second device asks for a seat; Bo's app takes it in.
    let mut proof = empty_buffer();
    assert_eq!(
        unsafe { peachy_mls_sign_join_request(mal2, group.as_ptr(), group.len(), &mut proof) },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    let proof_bytes = bytes_of(&proof);
    let mut first = false;
    assert_eq!(
        unsafe {
            peachy_mls_first_sight_of_join_request(
                app,
                group.as_ptr(),
                group.len(),
                proof_bytes.as_ptr(),
                proof_bytes.len(),
                &mut first,
            )
        },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    assert!(first);
    let mut package = empty_buffer();
    assert_eq!(
        unsafe { peachy_mls_key_package(mal2, &mut package) },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    let verdict_at_app = || -> u32 {
        let actor = CString::new("actor-mal").expect("no NUL");
        let device = CString::new("device-mal-2").expect("no NUL");
        let mut verdict = 99u32;
        let status = unsafe {
            peachy_mls_verify_join_request(
                app,
                group.as_ptr(),
                group.len(),
                actor.as_ptr(),
                device.as_ptr(),
                proof_bytes.as_ptr(),
                proof_bytes.len(),
                package.data,
                package.len,
                std::ptr::null(),
                0,
                &mut verdict,
            )
        };
        assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
        verdict
    };
    // Control: while Mallory holds a leaf, the ask holds.
    assert_eq!(verdict_at_app(), PEACHY_MLS_JOIN_REQUEST_ACCEPTED);

    // Ada removes Mallory; Bo's extension, on the app's own file, applies it.
    let (mal_leaf, mal_key) = (0..3usize)
        .find_map(|position| {
            let mut leaf = u32::MAX;
            let mut device = empty_buffer();
            let mut leaf_key = empty_buffer();
            let status = unsafe {
                peachy_mls_group_member(
                    ada,
                    group.as_ptr(),
                    group.len(),
                    position,
                    &mut leaf,
                    std::ptr::null_mut(),
                    &mut device,
                    std::ptr::null_mut(),
                    &mut leaf_key,
                    std::ptr::null_mut(),
                )
            };
            assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
            let is_mal = bytes_of(&device) == b"device-mal";
            let key = bytes_of(&leaf_key);
            unsafe {
                peachy_mls_buffer_free(&mut device);
                peachy_mls_buffer_free(&mut leaf_key);
            }
            is_mal.then_some((leaf, key))
        })
        .expect("Mallory's leaf");
    let mut removal = empty_buffer();
    assert_eq!(
        unsafe {
            peachy_mls_group_remove_member(
                ada,
                group.as_ptr(),
                group.len(),
                mal_leaf,
                mal_key.as_ptr(),
                mal_key.len(),
                &mut removal,
            )
        },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    merge(ada, group);
    let mut applied = process(extension, group, &removal, PEACHY_MLS_DOOR_COMMIT);
    assert_eq!(applied.kind, PEACHY_MLS_INCOMING_COMMIT);
    unsafe { peachy_mls_incoming_free(&mut applied) };

    // The app's verdict, its first door since the extension wrote.
    assert_eq!(
        verdict_at_app(),
        PEACHY_MLS_JOIN_REQUEST_NOT_A_MEMBER,
        "the app judged a removed member's seat ask from a stale copy"
    );

    unsafe {
        peachy_mls_buffer_free(&mut proof);
        peachy_mls_buffer_free(&mut package);
        peachy_mls_buffer_free(&mut removal);
        peachy_mls_client_free(ada);
        peachy_mls_client_free(app);
        peachy_mls_client_free(extension);
        peachy_mls_client_free(mal);
        peachy_mls_client_free(mal2);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The roster and epoch doors read the group the store holds, as the call,
/// exporter and seat-ask doors do. Bo's app and Bo's notification extension
/// are two handles on one keyed file. Ada removes Mallory and the EXTENSION
/// applies the removal; the app's next roster and epoch reads, with no write
/// door in between, show the group without Mallory.
#[test]
fn the_roster_and_epoch_doors_follow_a_removal_another_process_applied() {
    let fixture = Fixture::new();
    let dir =
        std::env::temp_dir().join(format!("peachy-mls-roster-catch-up-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let path = dir.join("bo.sqlite3");
    let path_str = path.to_str().expect("a UTF-8 path").to_string();
    let key = [7u8; 32];
    let group = b"cabi-roster-catch-up";

    let ada = fixture.client(1, "actor-ada", "device-ada");
    let app = fixture.client_keyed(2, "actor-bo", "device-bo", Some(&path_str), Some(&key[..]));
    let extension =
        fixture.client_keyed(2, "actor-bo", "device-bo", Some(&path_str), Some(&key[..]));
    let mal = fixture.client(3, "actor-mal", "device-mal");
    assert_eq!(
        unsafe { peachy_mls_group_create(ada, group.as_ptr(), group.len()) },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    add_member_through_the_c_door(ada, app, &[], group);
    add_member_through_the_c_door(ada, mal, &[app], group);

    let count_at = |client: *mut PeachyMlsClient| {
        let mut count = 0usize;
        assert_eq!(
            unsafe {
                peachy_mls_group_member_count(client, group.as_ptr(), group.len(), &mut count)
            },
            PEACHY_MLS_OK,
            "{}",
            last_error()
        );
        count
    };
    let epoch_at = |client: *mut PeachyMlsClient| {
        let mut epoch = 0u64;
        assert_eq!(
            unsafe { peachy_mls_group_epoch(client, group.as_ptr(), group.len(), &mut epoch) },
            PEACHY_MLS_OK,
            "{}",
            last_error()
        );
        epoch
    };
    // Control: the app sees Mallory.
    assert_eq!(count_at(app), 3);

    let (mal_leaf, mal_key) = (0..3usize)
        .find_map(|position| {
            let mut leaf = u32::MAX;
            let mut device = empty_buffer();
            let mut leaf_key = empty_buffer();
            let status = unsafe {
                peachy_mls_group_member(
                    ada,
                    group.as_ptr(),
                    group.len(),
                    position,
                    &mut leaf,
                    std::ptr::null_mut(),
                    &mut device,
                    std::ptr::null_mut(),
                    &mut leaf_key,
                    std::ptr::null_mut(),
                )
            };
            assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
            let is_mal = bytes_of(&device) == b"device-mal";
            let key = bytes_of(&leaf_key);
            unsafe {
                peachy_mls_buffer_free(&mut device);
                peachy_mls_buffer_free(&mut leaf_key);
            }
            is_mal.then_some((leaf, key))
        })
        .expect("Mallory's leaf");
    let mut removal = empty_buffer();
    assert_eq!(
        unsafe {
            peachy_mls_group_remove_member(
                ada,
                group.as_ptr(),
                group.len(),
                mal_leaf,
                mal_key.as_ptr(),
                mal_key.len(),
                &mut removal,
            )
        },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    let after = merge(ada, group);
    let mut applied = process(extension, group, &removal, PEACHY_MLS_DOOR_COMMIT);
    assert_eq!(applied.kind, PEACHY_MLS_INCOMING_COMMIT);
    unsafe { peachy_mls_incoming_free(&mut applied) };

    // The app's reads, its first doors since the extension wrote.
    assert_eq!(
        count_at(app),
        2,
        "the app read the roster from a stale copy"
    );
    assert_eq!(
        epoch_at(app),
        after,
        "the app read the epoch from a stale copy"
    );

    unsafe {
        peachy_mls_buffer_free(&mut removal);
        peachy_mls_client_free(ada);
        peachy_mls_client_free(app);
        peachy_mls_client_free(extension);
        peachy_mls_client_free(mal);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// `joiner` is added to `group` through the C add door at `adder`, the
/// delivery service takes it, and `joiner` joins. Returns the commit.
fn add_through_the_c_door(
    adder: *mut PeachyMlsClient,
    group: &[u8],
    joiner: &mut peachy_mls_core::Client,
) -> Vec<u8> {
    let package = joiner.generate_key_package().expect("a key package");
    let mut commit = empty_buffer();
    let mut welcome = empty_buffer();
    assert_eq!(
        unsafe {
            peachy_mls_group_add_member(
                adder,
                group.as_ptr(),
                group.len(),
                package.as_ptr(),
                package.len(),
                &mut commit,
                &mut welcome,
            )
        },
        PEACHY_MLS_OK,
        "{}",
        last_error()
    );
    merge(adder, group);
    joiner
        .join_from_welcome(&bytes_of(&welcome))
        .expect("joins");
    let added = bytes_of(&commit);
    unsafe {
        peachy_mls_buffer_free(&mut commit);
        peachy_mls_buffer_free(&mut welcome);
    }
    added
}

#[test]
fn the_transfer_key_box_crosses_the_c_door() {
    let recipient_seed = [0x33u8; 32];
    let bystander_seed = [0x55u8; 32];
    let mut recipient_key = empty_buffer();
    assert_eq!(
        unsafe {
            peachy_mls_signing_key_public_key(recipient_seed.as_ptr(), 32, &mut recipient_key)
        },
        PEACHY_MLS_OK
    );
    let recipient_key_bytes = bytes_of(&recipient_key);
    let device_id = CString::new("0f8e2b1c-6a4d-4e3f-9b2a-7c5d1e0f3a9b").expect("no NUL");
    let key = [0x7cu8; 32];

    let mut sealed = empty_buffer();
    let status = unsafe {
        peachy_mls_transfer_key_seal(
            recipient_key_bytes.as_ptr(),
            recipient_key_bytes.len(),
            device_id.as_ptr(),
            key.as_ptr(),
            key.len(),
            &mut sealed,
        )
    };
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    let sealed_bytes = bytes_of(&sealed);
    assert_eq!(sealed_bytes.len(), 93);

    let open = |seed: &[u8], sealed: &[u8]| -> (i32, Vec<u8>) {
        let mut out = empty_buffer();
        let status = unsafe {
            peachy_mls_transfer_key_open(
                seed.as_ptr(),
                seed.len(),
                device_id.as_ptr(),
                sealed.as_ptr(),
                sealed.len(),
                &mut out,
            )
        };
        let bytes = bytes_of(&out);
        unsafe { peachy_mls_buffer_free(&mut out) };
        (status, bytes)
    };
    let (status, opened) = open(&recipient_seed, &sealed_bytes);
    assert_eq!(status, PEACHY_MLS_OK, "{}", last_error());
    assert_eq!(opened, key);

    // Another device of the account: a status and a sentence, never bytes.
    let (status, opened) = open(&bystander_seed, &sealed_bytes);
    assert_eq!(status, PEACHY_MLS_ERR_INVALID_ARGUMENT);
    assert!(opened.is_empty());
    assert!(last_error().contains("does not open"), "{}", last_error());

    let (status, _) = open(&recipient_seed, &sealed_bytes[..92]);
    assert_eq!(status, PEACHY_MLS_ERR_INVALID_ARGUMENT);
    assert!(last_error().contains("93 bytes"), "{}", last_error());

    // A key that is not an attachment key is refused at the seal.
    let mut refused = empty_buffer();
    let status = unsafe {
        peachy_mls_transfer_key_seal(
            recipient_key_bytes.as_ptr(),
            recipient_key_bytes.len(),
            device_id.as_ptr(),
            key.as_ptr(),
            16,
            &mut refused,
        )
    };
    assert_eq!(status, PEACHY_MLS_ERR_INVALID_ARGUMENT);
    assert!(
        last_error().contains("exactly 32 bytes, got 16"),
        "{}",
        last_error()
    );
    unsafe {
        peachy_mls_buffer_free(&mut sealed);
        peachy_mls_buffer_free(&mut recipient_key);
    }
}

/// GROUP RECOVERY THROUGH THE C DOOR (docs/mls-core.md §Group recovery): a
/// copy one commit behind meets a message sealed past it, which is
/// `STALE_COPY`, and the head read the driver asks for says to rejoin.
#[test]
fn a_stale_copy_is_told_to_rejoin_through_the_c_door() {
    let fixture = Fixture::new();
    let ada = fixture.client(1, "actor-ada", "device-ada");
    let bo = fixture.client(2, "actor-bo", "device-bo");
    let group = b"cabi-recovery";
    assert_eq!(
        unsafe { peachy_mls_group_create(ada, group.as_ptr(), group.len()) },
        PEACHY_MLS_OK
    );
    add_member_through_the_c_door(ada, bo, &[], group);
    let (level_epoch, level) = head_of(bo, group);

    let begin = |client: *mut PeachyMlsClient| -> u32 {
        let mut step = u32::MAX;
        assert_eq!(
            unsafe {
                peachy_mls_group_recovery_begin(client, group.as_ptr(), group.len(), &mut step)
            },
            PEACHY_MLS_OK,
            "{}",
            last_error()
        );
        step
    };
    let judge = |kind: u32, head: Option<(u64, &[u8])>, now: i64| -> (i32, u32) {
        let mut step = u32::MAX;
        let (has, epoch, verifier) = match head {
            Some((epoch, verifier)) => (true, epoch, verifier),
            None => (false, 0, &[][..]),
        };
        let status = unsafe {
            peachy_mls_group_recovery_judge(
                bo,
                group.as_ptr(),
                group.len(),
                kind,
                has,
                epoch,
                if has {
                    verifier.as_ptr()
                } else {
                    std::ptr::null()
                },
                verifier.len(),
                true,
                now,
                &mut step,
            )
        };
        (status, step)
    };

    // No begin, no judgement.
    assert_eq!(
        judge(PEACHY_MLS_HEAD_READ_CHECK, None, 0).0,
        PEACHY_MLS_ERR_INVALID_ARGUMENT
    );
    assert_eq!(begin(bo), PEACHY_MLS_RECOVERY_READ_HEAD);
    assert_eq!(
        judge(9, None, 0).0,
        PEACHY_MLS_ERR_INVALID_ARGUMENT,
        "an unknown kind"
    );
    assert_eq!(
        judge(PEACHY_MLS_HEAD_READ_CHECK, Some((level_epoch, &level)), 0),
        (PEACHY_MLS_OK, PEACHY_MLS_RECOVERY_IN_STEP)
    );

    // Ada moves on without Bo, and seals past him.
    let mut commit = empty_buffer();
    assert_eq!(
        unsafe { peachy_mls_group_self_update(ada, group.as_ptr(), group.len(), &mut commit) },
        PEACHY_MLS_OK
    );
    unsafe { peachy_mls_buffer_free(&mut commit) };
    merge(ada, group);
    let mut message = empty_buffer();
    let plaintext = b"your turn";
    assert_eq!(
        unsafe {
            peachy_mls_group_encrypt(
                ada,
                group.as_ptr(),
                group.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                &mut message,
            )
        },
        PEACHY_MLS_OK
    );
    let mut incoming = PeachyMlsIncoming {
        kind: 0,
        sender_actor_id: empty_buffer(),
        sender_device_id: empty_buffer(),
        plaintext: empty_buffer(),
        proposal_kind: 0,
        removed_self: false,
        epoch: 0,
        left_actor_ids: empty_buffer(),
    };
    let status = unsafe {
        peachy_mls_group_process_door(
            bo,
            group.as_ptr(),
            group.len(),
            message.data,
            message.len,
            PEACHY_MLS_DOOR_MESSAGE,
            0,
            &mut incoming,
        )
    };
    assert_eq!(status, PEACHY_MLS_ERR_STALE_COPY, "{}", last_error());
    assert!(last_error().starts_with("stale copy"), "{}", last_error());
    unsafe { peachy_mls_buffer_free(&mut message) };

    let mut due = false;
    assert_eq!(
        unsafe {
            peachy_mls_group_recovery_read_due(
                bo,
                group.as_ptr(),
                group.len(),
                true,
                1_000,
                &mut due,
            )
        },
        PEACHY_MLS_OK
    );
    assert!(due);
    let (ahead_epoch, ahead) = head_of(ada, group);
    assert_eq!(begin(bo), PEACHY_MLS_RECOVERY_READ_HEAD);
    assert_eq!(
        judge(
            PEACHY_MLS_HEAD_READ_SEALED_AHEAD,
            Some((ahead_epoch, &ahead)),
            1_000
        ),
        (PEACHY_MLS_OK, PEACHY_MLS_RECOVERY_REJOIN_STUCK)
    );

    let mut owed = empty_buffer();
    assert_eq!(
        unsafe { peachy_mls_recovery_drain_complete(bo, 2_000, true, 2_000, &mut owed) },
        PEACHY_MLS_OK
    );
    assert!(
        read_byte_list(&bytes_of(&owed)).is_empty(),
        "a stranded copy is owed nothing"
    );
    unsafe { peachy_mls_buffer_free(&mut owed) };
    assert_eq!(
        unsafe { peachy_mls_recovery_drain_complete(bo, 2_000, true, 2_000, std::ptr::null_mut()) },
        PEACHY_MLS_ERR_INVALID_ARGUMENT
    );
    unsafe {
        peachy_mls_client_free(ada);
        peachy_mls_client_free(bo);
    }
}
