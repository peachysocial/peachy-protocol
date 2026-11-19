// SPDX-License-Identifier: MIT
//! # peachy-mls-cabi
//!
//! The C ABI over [`peachy_mls_core`]. Six rules hold at every entry point:
//!
//! 1. **Nothing unwinds across the edge.** Every `extern "C"` function body is
//!    inside `catch_unwind`, because a panic crossing into C is undefined
//!    behavior and OpenMLS or a dependency can panic. A caught panic is
//!    [`PEACHY_MLS_ERR_PANIC`].
//! 2. **Every failure has a code and a message.** The code is the return
//!    value; the message is [`peachy_mls_last_error`], thread-local, valid
//!    until the next call *on that thread*.
//! 3. **Every buffer has exactly one free function.** Memory this library
//!    allocates is freed by [`peachy_mls_buffer_free`], never by the caller's
//!    allocator. Freeing a [`PeachyMlsBuffer`] sets it back to empty (a null
//!    pointer and a zero length), so a double free is a no-op. The bytes it
//!    pointed at are wiped before they are released.
//! 4. **A null pointer is an error, not a fault.** Every pointer argument is
//!    checked and a null one is [`PEACHY_MLS_ERR_NULL_ARGUMENT`].
//! 5. **Out-parameters are checked before anything irreversible happens.**
//!    Every entry point that changes durable state starts with `require_out`,
//!    so a null out-parameter cannot strand a minted key package, spend a
//!    Welcome, advance a sender ratchet or move an epoch with its result
//!    thrown away. The tests below pass null on purpose to prove the state
//!    did not move.
//! 6. **No call returns with a store transaction open.** Whatever a call
//!    wrote is committed before it returns, success or error, a staged
//!    commit included, so no transaction spans a request to the delivery
//!    service and no other connection to the store waits on this one's write
//!    lock. `guard` commits after every call as a backstop. A caught panic is
//!    not committed: its transaction is rolled back and the handle is closed
//!    (see `guard`).
//!
//! ## What a caller owns
//!
//! - A `PeachyMlsClient*` from [`peachy_mls_client_new`], freed with
//!   [`peachy_mls_client_free`]. Not thread-safe: one client is one device's
//!   MLS state. Callers serialize.
//! - Every [`PeachyMlsBuffer`] an out-parameter was filled with, even on a
//!   later error: the functions here only ever write an out-parameter on
//!   success, so a buffer you did not get is a buffer you do not free.

use std::cell::{Cell, RefCell};
use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::time::{Duration, Instant};

use peachy_mls_core::{
    Client, ClientConfig, CredentialRejection, Error, Incoming, PeachyStorage, RosterEntry,
    SavedCommit, SqliteKv, TrustedServerKeys, PEACHY_CIPHERSUITE,
};
use zeroize::{Zeroize, Zeroizing};

// ---- Status codes ----------------------------------------------------------

/// Success.
pub const PEACHY_MLS_OK: i32 = 0;
/// A required pointer argument was null, or a length did not match.
pub const PEACHY_MLS_ERR_NULL_ARGUMENT: i32 = 1;
/// A `pdc1` device credential was rejected. The message names which check.
pub const PEACHY_MLS_ERR_CREDENTIAL: i32 = 2;
/// Group policy refused it.
pub const PEACHY_MLS_ERR_POLICY: i32 = 3;
/// OpenMLS refused it.
pub const PEACHY_MLS_ERR_MLS: i32 = 4;
/// A message did not decode.
pub const PEACHY_MLS_ERR_CODEC: i32 = 5;
/// No group with that id is open on this client.
pub const PEACHY_MLS_ERR_NO_SUCH_GROUP: i32 = 6;
/// This client is not an active member of that group.
pub const PEACHY_MLS_ERR_NOT_A_MEMBER: i32 = 7;
/// No member at that index.
pub const PEACHY_MLS_ERR_NO_SUCH_MEMBER: i32 = 8;
/// A shape this build does not implement.
pub const PEACHY_MLS_ERR_UNSUPPORTED: i32 = 9;
/// The caller handed us something unusable.
pub const PEACHY_MLS_ERR_INVALID_ARGUMENT: i32 = 10;
/// The device's own MLS store would not read or would not write. Unlike
/// [`PEACHY_MLS_ERR_MLS`], which is the protocol saying no, this one may
/// succeed on a retry.
pub const PEACHY_MLS_ERR_STORAGE: i32 = 11;
/// A Welcome invited this client into a group it is already in. Not a failure
/// to act on: the group the caller wanted is open already.
pub const PEACHY_MLS_ERR_ALREADY_A_MEMBER: i32 = 12;
/// A group-context change (a rename) could not be made because a member's leaf
/// does not advertise the extension it sets — somebody in the group is on a
/// leaf that predates it. Its own code because it is the one refusal here with
/// a remedy a PERSON can carry out: that member runs a current build, whose
/// next leaf renewal (before its next send into the group, or as its app
/// starts or comes to the foreground) carries the capability. 14 and 15 are
/// retired.
pub const PEACHY_MLS_ERR_EXTENSION_UNSUPPORTED: i32 = 13;
/// A group message handed to the door that does not take its kind: a commit
/// or proposal on the message door, anything but a commit on the commit door
/// ([`peachy_mls_group_process_door`]). Refused before the engine read it, so
/// nothing moved. Not a message that failed to open and not a commit that
/// strands: drop it and log it.
pub const PEACHY_MLS_ERR_WRONG_DOOR: i32 = 16;
/// A message that opened and verified, from a device the group has since
/// removed: sealed at an earlier epoch by a leaf that is no longer in the
/// tree; or from a device whose account signed it out, received at or after
/// the revocation took effect ([`peachy_mls_stale_leaf_removable`]). Not a
/// loss to show and not a fork to look into: drop it in silence, with no
/// placeholder, no resend ask and no head check.
pub const PEACHY_MLS_ERR_NOT_FROM_A_MEMBER: i32 = 17;
/// A Welcome refused for who signed it: a device this account forgot, into
/// any group; or, into a group this device knew, a signer whose credential
/// does not identify, so no line could say who re-added it
/// (docs/delivery.md §A Welcome into a group this device knew).
/// Nothing was taken and the group this device holds, if any, is unchanged.
/// Drop the Welcome and log it; a device waiting to rejoin keeps waiting.
pub const PEACHY_MLS_ERR_WELCOME_FROM_OUTSIDER: i32 = 18;
/// The group holds a saved commit, one found staged at open whose verdict
/// this device never heard ([`peachy_mls_group_has_saved_commit`]):
/// forgetting the group, or a Welcome replacing it, would drop a commit the
/// delivery service may have taken. Nothing changed, and a contested Welcome
/// is still kept. Settle the commit against the group's head
/// ([`peachy_mls_group_settle_saved_commit`]) and call again; never ask to
/// rejoin meanwhile (docs/mls-core.md §A commit saved across a
/// restart).
pub const PEACHY_MLS_ERR_SETTLE_FIRST: i32 = 19;
/// An application message this device already opened, the very bytes handed
/// over again (docs/mls-core.md §Receiving). Nothing in it is new:
/// acknowledge it and drop it in silence, with no placeholder, no resend ask,
/// no notification and no head check.
pub const PEACHY_MLS_ERR_DUPLICATE: i32 = 20;
/// The store at the path is written in the clear, and the open was given a
/// key. Not [`PEACHY_MLS_ERR_STORAGE`]: no retry opens it. Encrypt it with
/// [`peachy_mls_store_encrypt_in_place`] and open it again; never delete it
/// to start over, which drops the device out of every group.
pub const PEACHY_MLS_ERR_PLAINTEXT_STORE: i32 = 21;
/// The store at the path, or its `-wal`, `-shm` or `-journal`, is writable
/// by group or others, or is a symbolic link: another local user could plant
/// a log the bundled SQLite would read as the store's own (RUSTSEC-2026-0459).
/// Nothing was opened. Not [`PEACHY_MLS_ERR_STORAGE`]: no retry opens it.
/// Make the files writable only by their owner. A symbolic link at the
/// store's own path may be replaced with the file it names (for example with
/// `mv`). A link at `-wal`, `-shm` or `-journal` is none the core or SQLite
/// makes: never adopt the file it names; find out who made it, and remove the
/// link only once the store's owner is known to have made it. Then open it
/// again; never delete the store to start over.
pub const PEACHY_MLS_ERR_INSECURE_STORE: i32 = 22;
/// A message or commit framed at an epoch past the one this copy of the
/// group holds: the copy is BEHIND OR FORKED and will not catch up from what
/// was delivered. Nothing moved. Read the group's head and judge it
/// ([`peachy_mls_group_recovery_begin`], then
/// [`peachy_mls_group_recovery_judge`] with
/// [`PEACHY_MLS_HEAD_READ_SEALED_AHEAD`]): it says whether to forget the
/// group and ask back in. Never rejoin on this code alone: the framing is
/// anyone's to write who holds the group id. Show the message as one that
/// will not open. Was [`PEACHY_MLS_ERR_MLS`] ("epoch differs") before ABI 2.
///
/// From [`peachy_mls_client_seal_envelope`] it means something else: the
/// message or commit was made at an epoch this copy no longer keeps, and
/// nothing was sealed. Encrypt the message again at the current epoch and
/// seal that. Never resend the old bytes, and do not read or judge the head.
pub const PEACHY_MLS_ERR_STALE_COPY: i32 = 23;
/// A panic was caught at the boundary. Always a bug in this library or one of
/// its dependencies; never something a caller did.
///
/// What the panicking call wrote is rolled back, and the handle is closed:
/// every later call on it but [`peachy_mls_client_free`] returns this code
/// again, without running. Free it and open a new client over the same store
/// ([`peachy_mls_client_open`]), which reads the last whole operation back.
pub const PEACHY_MLS_ERR_PANIC: i32 = 99;

/// What [`peachy_mls_group_process_door`] found. Mirrors `peachy_mls_core::Incoming`.
/// `peachy_mls_verify_join_request`'s verdicts
/// (`peachy_mls_core::JoinRequestVerdict`, pinned by
/// `mls/fixtures/join-request.json`). Only `ACCEPTED` seats anybody.
pub const PEACHY_MLS_JOIN_REQUEST_ACCEPTED: u32 = 0;
pub const PEACHY_MLS_JOIN_REQUEST_MALFORMED: u32 = 1;
pub const PEACHY_MLS_JOIN_REQUEST_CREDENTIAL_REJECTED: u32 = 2;
pub const PEACHY_MLS_JOIN_REQUEST_IDENTITY_MISMATCH: u32 = 3;
pub const PEACHY_MLS_JOIN_REQUEST_BAD_SIGNATURE: u32 = 4;
pub const PEACHY_MLS_JOIN_REQUEST_STALE: u32 = 5;
pub const PEACHY_MLS_JOIN_REQUEST_FROM_THE_FUTURE: u32 = 6;
/// The request holds in every other way, from a person who holds no leaf in
/// this device's copy of the group, is not this device's own person, and is
/// not among the people the caller is still adding. Judged last.
pub const PEACHY_MLS_JOIN_REQUEST_NOT_A_MEMBER: u32 = 7;

/// `peachy_mls_check_own_device_approval`'s verdicts
/// (`peachy_mls_core::OwnDeviceVerdict`). Only `KNOWN` and `APPROVED` seat a
/// device of your own.
pub const PEACHY_MLS_OWN_DEVICE_KNOWN: u32 = 0;
pub const PEACHY_MLS_OWN_DEVICE_APPROVED: u32 = 1;
pub const PEACHY_MLS_OWN_DEVICE_UNANCHORED: u32 = 2;
pub const PEACHY_MLS_OWN_DEVICE_BAD_APPROVAL: u32 = 3;
pub const PEACHY_MLS_OWN_DEVICE_NOT_OWN_DEVICE: u32 = 4;
pub const PEACHY_MLS_OWN_DEVICE_CREDENTIAL_REJECTED: u32 = 5;

/// `peachy_mls_own_device_standing`'s answers
/// (`peachy_mls_core::OwnDeviceStanding`). Only `THIS_DEVICE` and `ON_CHAIN`
/// count as the person's own device.
pub const PEACHY_MLS_OWN_STANDING_NOT_OWN: u32 = 0;
pub const PEACHY_MLS_OWN_STANDING_THIS_DEVICE: u32 = 1;
pub const PEACHY_MLS_OWN_STANDING_ON_CHAIN: u32 = 2;
pub const PEACHY_MLS_OWN_STANDING_OFF_CHAIN: u32 = 3;
pub const PEACHY_MLS_OWN_STANDING_FORGOTTEN: u32 = 4;

/// `peachy_mls_device_link_waiter_step`'s answers
/// (`peachy_mls_core::DeviceLinkWaiterStep`, pinned by
/// `mls/fixtures/device-link.json`): what a waiting device does with one
/// exchange, given what its pairing already answered.
pub const PEACHY_MLS_LINK_ANSWER: u32 = 0;
pub const PEACHY_MLS_LINK_CONTINUE: u32 = 1;
pub const PEACHY_MLS_LINK_IGNORE: u32 = 2;
pub const PEACHY_MLS_LINK_INTERRUPTED: u32 = 3;

/// `peachy_mls_device_link_approver_step`'s answers
/// (`peachy_mls_core::DeviceLinkApproverStep`, pinned by
/// `mls/fixtures/device-link.json`): what an approving device does next with
/// its exchange for one waiting device.
pub const PEACHY_MLS_APPROVER_COMMIT: u32 = 0;
pub const PEACHY_MLS_APPROVER_WAIT: u32 = 1;
pub const PEACHY_MLS_APPROVER_REVEAL: u32 = 2;
pub const PEACHY_MLS_APPROVER_SHOW: u32 = 3;
pub const PEACHY_MLS_APPROVER_INTERRUPTED: u32 = 4;

/// `peachy_mls_group_settle_saved_commit`'s verdicts
/// (`peachy_mls_core::SavedCommit`): the head was the commit's and it was
/// merged; it was not and the commit was cleared; or the head is past the
/// commit's epoch and it was kept.
pub const PEACHY_MLS_SAVED_COMMIT_MERGED: u32 = 1;
pub const PEACHY_MLS_SAVED_COMMIT_CLEARED: u32 = 2;
pub const PEACHY_MLS_SAVED_COMMIT_WAITING: u32 = 3;

pub const PEACHY_MLS_INCOMING_APPLICATION: i32 = 1;
pub const PEACHY_MLS_INCOMING_PROPOSAL: i32 = 2;
pub const PEACHY_MLS_INCOMING_COMMIT: i32 = 3;
/// A message this client sent, handed back by the delivery service.
pub const PEACHY_MLS_INCOMING_ECHO: i32 = 4;

// ---- Last error ------------------------------------------------------------

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

fn set_last_error(message: &str) {
    // A NUL inside the message would truncate it; replacing rather than
    // failing, because losing the tail of a diagnostic beats losing the
    // diagnostic.
    let cleaned = message.replace('\0', "?");
    let owned = CString::new(cleaned).unwrap_or_default();
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = Some(owned);
    });
}

fn clear_last_error() {
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = None;
    });
}

/// The message for the most recent failure **on this thread**, or null if the
/// last call succeeded.
///
/// The pointer is owned by this library and is valid until the next
/// `peachy_mls_*` call on the same thread. Copy it before calling anything
/// else.
///
/// # Safety
/// The returned pointer must not be freed by the caller.
#[no_mangle]
pub extern "C" fn peachy_mls_last_error() -> *const c_char {
    LAST_ERROR.with(|slot| match slot.borrow().as_ref() {
        Some(message) => message.as_ptr(),
        None => ptr::null(),
    })
}

/// The version of `peachy-mls-core` this library was built against. Static,
/// NUL-terminated, never freed.
#[no_mangle]
pub extern "C" fn peachy_mls_version() -> *const c_char {
    // A byte literal with an explicit trailing NUL, so there is no allocation
    // and no lifetime to explain.
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

/// THE ABI VERSION this header describes. Raised whenever a function's
/// signature, a struct's layout, a constant's value or the meaning of an
/// existing status code changes in a way a caller built against the old
/// header could misread; never for an addition alone. A caller compares
/// [`peachy_mls_abi_version`] with the `PEACHY_MLS_ABI_VERSION` its own copy
/// of the header carries and refuses to run on a mismatch: a hand-written
/// struct of an older layout reads fields that are no longer there.
pub const PEACHY_MLS_ABI_VERSION: u32 = 2;

/// [`PEACHY_MLS_ABI_VERSION`] as this library was built: what a caller
/// compares its header's constant with before any other call.
#[no_mangle]
pub extern "C" fn peachy_mls_abi_version() -> u32 {
    PEACHY_MLS_ABI_VERSION
}

/// Tell the core how far the server's clock is ahead of this device's, in
/// milliseconds (negative when behind), as the caller last measured it from a
/// reply that carries the server's time (`FetchMailbox.server_time`, against
/// the midpoint of the request's send and its reply's arrival).
///
/// Process-wide, not per client: every client in the process stamps and judges
/// the live call lane's frames and typing's on this device's clock plus the
/// offset (`peachy_mls_core::set_server_clock_offset_ms`), so a device whose
/// own clock is off still agrees with its peers. Clamped to ±1 day
/// (`SERVER_CLOCK_OFFSET_MAX_MS`). Credential checks stay on the device's own
/// clock. 0 until called. Cannot fail.
#[no_mangle]
pub extern "C" fn peachy_mls_set_server_clock_offset_ms(offset_ms: i64) {
    peachy_mls_core::set_server_clock_offset_ms(offset_ms);
}

/// The offset [`peachy_mls_set_server_clock_offset_ms`] last set, clamped; 0
/// until then.
#[no_mangle]
pub extern "C" fn peachy_mls_server_clock_offset_ms() -> i64 {
    peachy_mls_core::server_clock_offset_ms()
}

/// The server's published device keys read against the keys this build
/// carries (`peachy_mls_core::server_key_pins`). `published_json` is the body
/// of `GET /healthz/device-credential-keys`; `server` names the carried set,
/// `"production"` for the production API and `"development"` for any other.
///
/// `out_report` receives UTF-8, **not** NUL-terminated, freed with
/// [`peachy_mls_buffer_free`]: EMPTY when the two match, else one line naming
/// the kids that differ, for the device log and nowhere else.
/// [`PEACHY_MLS_ERR_INVALID_ARGUMENT`] for a list that is not JSON or an
/// unknown set name.
///
/// # Safety
/// See the module header. Both strings must be valid and NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_server_key_pin_report(
    published_json: *const c_char,
    server: *const c_char,
    out_report: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let published = cstr_arg(published_json, "published_json")?;
        let server = cstr_arg(server, "server")?;
        let report = peachy_mls_core::server_key_pin_report(published, server)?;
        write_buffer(out_report, "out_report", report.into_bytes())
    })
}

/// The published list with every key removed that this build does not carry
/// for `server` under the same bytes: what a client trusts once pinning is
/// enforced. Same shape as the input, so it goes wherever the published list
/// goes ([`peachy_mls_client_open`]'s `trusted_keys_json`).
///
/// `out_json` receives UTF-8, **not** NUL-terminated, freed with
/// [`peachy_mls_buffer_free`]. Errors as [`peachy_mls_server_key_pin_report`].
///
/// # Safety
/// See the module header. Both strings must be valid and NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_server_keys_pinned(
    published_json: *const c_char,
    server: *const c_char,
    out_json: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let published = cstr_arg(published_json, "published_json")?;
        let server = cstr_arg(server, "server")?;
        let json = peachy_mls_core::server_keys_pinned_json(published, server)?;
        write_buffer(out_json, "out_json", json.into_bytes())
    })
}

fn code_for(error: &Error) -> i32 {
    // core's codes and this file's constants are the same numbers by
    // construction. Spelled out rather than cast, so a divergence is a
    // compile-visible edit here and not a silent renumbering.
    match error {
        Error::CredentialRejected(_) => PEACHY_MLS_ERR_CREDENTIAL,
        Error::PolicyRefused(_) => PEACHY_MLS_ERR_POLICY,
        Error::Mls(_) => PEACHY_MLS_ERR_MLS,
        Error::Codec(_) => PEACHY_MLS_ERR_CODEC,
        Error::NoSuchGroup => PEACHY_MLS_ERR_NO_SUCH_GROUP,
        Error::NotAMember => PEACHY_MLS_ERR_NOT_A_MEMBER,
        Error::NoSuchMember => PEACHY_MLS_ERR_NO_SUCH_MEMBER,
        Error::Unsupported(_) => PEACHY_MLS_ERR_UNSUPPORTED,
        Error::InvalidArgument(_) => PEACHY_MLS_ERR_INVALID_ARGUMENT,
        Error::Storage(_) => PEACHY_MLS_ERR_STORAGE,
        Error::AlreadyAMember => PEACHY_MLS_ERR_ALREADY_A_MEMBER,
        Error::ExtensionUnsupportedByMember(_) => PEACHY_MLS_ERR_EXTENSION_UNSUPPORTED,
        Error::WrongDoor(_) => PEACHY_MLS_ERR_WRONG_DOOR,
        Error::NotFromAMember(_) => PEACHY_MLS_ERR_NOT_FROM_A_MEMBER,
        Error::WelcomeFromOutsider => PEACHY_MLS_ERR_WELCOME_FROM_OUTSIDER,
        Error::SettleFirst => PEACHY_MLS_ERR_SETTLE_FIRST,
        Error::Duplicate(_) => PEACHY_MLS_ERR_DUPLICATE,
        Error::PlaintextStore => PEACHY_MLS_ERR_PLAINTEXT_STORE,
        Error::InsecureStore(_) => PEACHY_MLS_ERR_INSECURE_STORE,
        Error::StaleCopy { .. } => PEACHY_MLS_ERR_STALE_COPY,
    }
}

// ---- The call's client ------------------------------------------------------

thread_local! {
    /// The client handle the running call borrowed through [`client_mut`],
    /// or null: what [`guard`] commits after the call (rule 6).
    static CALL_CLIENT: Cell<*mut PeachyMlsClient> = const { Cell::new(ptr::null_mut()) };
    /// The running call was refused because its handle is closed after a
    /// panic: [`guard`] reports [`PEACHY_MLS_ERR_PANIC`] for it.
    static CALL_ON_CLOSED: Cell<bool> = const { Cell::new(false) };
}

/// Rule 6: a call commits what it wrote before it returns, so no call leaves
/// the store's write transaction (on SQLite, its write lock) open after it.
/// The core's own operations flush on every outcome, a stage and the
/// refusals that follow a write included; this is the backstop for any that
/// does not. After a call that wrote nothing it commits nothing.
///
/// A flush that itself fails changes nothing for the caller: the call's own
/// status is the one it reports, and the next flush retries the commit.
fn commit_after_call(client: *mut PeachyMlsClient) {
    if client.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `client` came through `client_mut` in this same call, so it
        // is a live handle the caller cannot free before the call returns,
        // and the body's borrow of it ended when the body did.
        unsafe { (*client).inner.flush() }
    }));
}

/// Every entry point goes through here: clear the error slot, run the body
/// with a panic guard, and turn whatever comes out into a status code.
fn guard(body: impl FnOnce() -> Result<(), Error>) -> i32 {
    clear_last_error();
    CALL_CLIENT.with(|slot| slot.set(ptr::null_mut()));
    CALL_ON_CLOSED.with(|slot| slot.set(false));
    let outcome = catch_unwind(AssertUnwindSafe(body));
    let client = CALL_CLIENT.with(|slot| slot.replace(ptr::null_mut()));
    match outcome {
        Ok(Ok(())) => {
            commit_after_call(client);
            PEACHY_MLS_OK
        }
        Ok(Err(error)) => {
            commit_after_call(client);
            set_last_error(&error.to_string());
            if CALL_ON_CLOSED.with(|slot| slot.replace(false)) {
                return PEACHY_MLS_ERR_PANIC;
            }
            code_for(&error)
        }
        // A panic is NOT committed: what it wrote is an operation cut off
        // part-way, and making that durable is worse than any error. It is
        // rolled back now, rather than left open for the next call to
        // commit, and the handle is closed, so the platform opens a new
        // client from the store instead of going on with groups in memory
        // that the panic may have left half-changed
        // (docs/mls-core.md §The C ABI contract).
        Err(payload) => {
            close_after_panic(client);
            // The payload is whatever `panic!` was given. Both common shapes
            // are recovered, because "a panic happened somewhere" is a much
            // worse bug report than the message.
            let detail = payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "no message".to_string());
            set_last_error(&format!("panic caught at the C boundary: {detail}"));
            PEACHY_MLS_ERR_PANIC
        }
    }
}

/// After a caught panic: roll back what the call left open and close the
/// handle ([`PEACHY_MLS_ERR_PANIC`]). Only the handle is touched, never
/// freed: freeing is the caller's.
fn close_after_panic(client: *mut PeachyMlsClient) {
    if client.is_null() {
        return;
    }
    // SAFETY: as in `commit_after_call`: `client` came through `client_mut`
    // in this same call, and the body's borrow ended with the unwind.
    unsafe { (*client).closed = true };
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        (*client).inner.abandon_open_writes()
    }));
}

fn null_argument(name: &str) -> Error {
    Error::InvalidArgument(format!("{name} must not be null"))
}

// ---- Buffers ---------------------------------------------------------------

/// A byte buffer this library allocated.
///
/// `data` is null and `len` is 0 for an absent value — a Welcome that was not
/// produced, for instance. Freeing an empty buffer is safe and does nothing.
#[repr(C)]
pub struct PeachyMlsBuffer {
    pub data: *mut u8,
    pub len: usize,
}

impl PeachyMlsBuffer {
    fn empty() -> Self {
        Self {
            data: ptr::null_mut(),
            len: 0,
        }
    }

    fn from_vec(mut bytes: Vec<u8>) -> Self {
        if bytes.is_empty() {
            bytes.zeroize();
            return Self::empty();
        }
        // A boxed slice, so capacity == len and the free side can reconstruct
        // the allocation from (ptr, len) alone. A vector with spare capacity
        // is copied into one rather than shrunk, and wiped: a shrink moves
        // the bytes and frees the old allocation as it was, so a secret in
        // it would outlive the free door's wipe.
        let mut boxed = if bytes.capacity() == bytes.len() {
            bytes.into_boxed_slice()
        } else {
            let exact = Box::<[u8]>::from(bytes.as_slice());
            bytes.zeroize();
            exact
        };
        let buffer = Self {
            data: boxed.as_mut_ptr(),
            len: boxed.len(),
        };
        std::mem::forget(boxed);
        buffer
    }
}

/// Free a buffer this library produced, and set the struct back to empty: a
/// null `data` and a zero `len`. The bytes are wiped (zeroed, in a way the
/// compiler may not skip) before the allocation is freed, so a seed, key or
/// plaintext this library handed out does not stay in freed memory. A copy
/// the caller made of them is the caller's to wipe.
///
/// Calling it twice on the same buffer is safe: the first call empties it and
/// the second sees an empty buffer.
///
/// # Safety
/// `buffer` must be null, or point to a `PeachyMlsBuffer` this library filled
/// in and that has not already been freed.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_buffer_free(buffer: *mut PeachyMlsBuffer) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if buffer.is_null() {
            return;
        }
        let buffer = &mut *buffer;
        if buffer.data.is_null() || buffer.len == 0 {
            buffer.data = ptr::null_mut();
            buffer.len = 0;
            return;
        }
        // `ptr::slice_from_raw_parts_mut` rather than `slice::from_raw_parts_mut`
        // because the latter builds a reference we immediately throw away, and
        // Box wants a raw slice pointer anyway.
        let mut boxed = Box::from_raw(std::ptr::slice_from_raw_parts_mut(buffer.data, buffer.len));
        boxed.zeroize();
        drop(boxed);
        buffer.data = ptr::null_mut();
        buffer.len = 0;
    }));
}

/// # Safety
/// `ptr` must be null or point to at least `len` readable bytes.
unsafe fn slice_from<'a>(ptr: *const u8, len: usize, name: &str) -> Result<&'a [u8], Error> {
    if len == 0 {
        // An empty, non-null slice is legitimate (an empty application
        // message); a null one is not, whatever the length says.
        return if ptr.is_null() {
            Err(null_argument(name))
        } else {
            Ok(&[])
        };
    }
    if ptr.is_null() {
        return Err(null_argument(name));
    }
    Ok(std::slice::from_raw_parts(ptr, len))
}

/// A NUL-terminated UTF-8 argument, or the reason it could not be read.
///
/// The same two checks half a dozen entry points here already write out inline
/// — null, then UTF-8 — named once for the device-link doors, which take a
/// string and nothing else identifying. The inline copies are left alone
/// deliberately: rewriting a working boundary to share a helper is how an
/// argument ends up in the wrong position.
///
/// # Safety
/// `ptr` must be null or point to a NUL-terminated string.
unsafe fn cstr_arg<'a>(ptr: *const c_char, name: &str) -> Result<&'a str, Error> {
    if ptr.is_null() {
        return Err(null_argument(name));
    }
    CStr::from_ptr(ptr)
        .to_str()
        .map_err(|_| Error::InvalidArgument(format!("{name} is not UTF-8")))
}

// ---- Client ----------------------------------------------------------------

/// One signed-in device. Opaque; see [`peachy_mls_client_new`].
pub struct PeachyMlsClient {
    inner: Client,
    /// A call on this handle panicked: every later call but free is
    /// refused with [`PEACHY_MLS_ERR_PANIC`].
    closed: bool,
    /// The roster [`peachy_mls_group_member_count`] last read (§One roster
    /// per read).
    roster: Option<RosterSnapshot>,
}

/// ONE ROSTER PER READ. A platform reads a roster as a count, then one
/// [`peachy_mls_group_member`] and one [`peachy_mls_group_member_account_key`]
/// per position, all under its own lock. Building a roster verifies every
/// leaf's credential, so while each per-position call built its own, one read
/// of an n-leaf group built 2n + 1 rosters: n² signature checks, seconds for
/// a large group, with the platform's client lock held throughout. On iOS
/// another thread then waited behind that lock while holding the
/// cross-process lock file in the app group, and the system suspended the app
/// with it held (`0xdead10cc`). So the count keeps the roster
/// it built and the per-position calls read from it: one roster per read,
/// which is also what their docs always promised ("one read's count, indices
/// and keys agree with each other").
///
/// Used only for the same group at the same epoch, only for
/// [`ROSTER_SNAPSHOT_LIFETIME`] (a verdict that depends on the clock, a
/// credential's expiry, is never older than that), and only until any other
/// door is called on the handle: a forget and rejoin at the same epoch, a
/// commit, or new trusted keys all go through one. A position call with no
/// snapshot to use builds the roster itself, as before.
struct RosterSnapshot {
    group_id: Vec<u8>,
    epoch: u64,
    taken: Instant,
    entries: Vec<RosterEntry>,
}

/// How long a roster snapshot answers the per-position calls (§One roster per
/// read). A read takes milliseconds; this only bounds a stray caller.
const ROSTER_SNAPSHOT_LIFETIME: Duration = Duration::from_secs(5);

/// The roster entry at `position` for one read: from `snapshot` when it is
/// this group's at this epoch and fresh, otherwise built now.
fn roster_entry(
    snapshot: &Option<RosterSnapshot>,
    client: &Client,
    group_id: &[u8],
    position: usize,
) -> Result<RosterEntry, Error> {
    let epoch = client.epoch(group_id)?;
    if let Some(snap) = snapshot {
        if snap.group_id == group_id
            && snap.epoch == epoch
            && snap.taken.elapsed() < ROSTER_SNAPSHOT_LIFETIME
        {
            return snap
                .entries
                .get(position)
                .cloned()
                .ok_or(Error::NoSuchMember);
        }
    }
    client
        .roster(group_id)?
        .into_iter()
        .nth(position)
        .ok_or(Error::NoSuchMember)
}

/// Build a client whose state dies with the process.
///
/// - `credential` / `credential_len`: the `pdc1` token this device was issued.
/// - `signature_seed`: exactly 32 bytes, the device's Ed25519 seed from the
///   platform key store.
/// - `trusted_keys_json`: the body of `GET /healthz/device-credential-keys`,
///   narrowed by [`peachy_mls_server_keys_pinned`] to the keys this build
///   carries, NUL-terminated (handed over as fetched, it trusts any key the
///   server adds: docs/identity.md §The trusted server keys). JSON rather than a parsed struct because that response is
///   the only shape every client already has, and re-picking it apart in
///   three languages is three chances to drop the previous keys.
/// - `out_client`: receives the client on success, untouched on failure.
///
/// Fails with [`PEACHY_MLS_ERR_CREDENTIAL`] if the credential does not check
/// out against those keys, including when the seed is not the one it names.
/// It names no account key, so it opens only an uncertified credential: a
/// certified one fails `not_own_account_key`, as it does for any device
/// holding no key.
///
/// **A shipped app wants [`peachy_mls_client_open`] instead.** This one keeps
/// every group in memory: quit the app and the groups are gone, unrecoverably,
/// because the epochs they were at cannot be re-derived from anything the
/// server holds. It stays because tests and one-shot tools legitimately want a
/// client with nothing behind it, and because deleting it would break every
/// caller written before there was a store.
///
/// # Safety
/// All pointers must be valid for the lengths given, and `out_client` must
/// point to writable storage for one pointer.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_client_new(
    credential: *const u8,
    credential_len: usize,
    signature_seed: *const u8,
    signature_seed_len: usize,
    trusted_keys_json: *const c_char,
    out_client: *mut *mut PeachyMlsClient,
) -> i32 {
    guard(|| {
        build_client(
            credential,
            credential_len,
            signature_seed,
            signature_seed_len,
            trusted_keys_json,
            ptr::null(),
            ptr::null(),
            0,
            ptr::null(),
            0,
            false,
            out_client,
        )
    })
}

/// Build a client whose state lives in a SQLite file, reopening whatever is
/// already there.
///
/// Everything [`peachy_mls_client_new`] takes, plus:
///
/// - `store_path`: the database file, NUL-terminated, created if it is not
///   there. A null or empty path means "no store", and is exactly
///   [`peachy_mls_client_new`] — so a caller with an optional path does not
///   need two call sites.
/// - `store_key`, `store_key_len`: the 32-byte key the file is encrypted
///   under with SQLCipher (`mls/core/src/sqlite.rs` §Encryption at rest), or
///   48 bytes — that key and a 16-byte salt — for a file whose first 32 bytes
///   stay SQLite's plaintext header (the Apple clients; §The plaintext
///   header), or null and 0 for a file with no encryption, which only a
///   build with `insecure-plaintext-store` opens: any other build refuses a
///   store path with no key as [`PEACHY_MLS_ERR_INVALID_ARGUMENT`]. Any other length is
///   [`PEACHY_MLS_ERR_INVALID_ARGUMENT`]. A key with no store path is refused
///   the same way: it would mean a caller thought it was encrypting a file
///   that does not exist.
/// - `own_account_identity`, `own_account_identity_len`: the 32-byte account
///   identity key this device derives from the account key it holds
///   (`peachy_mls_account_identity_public_key`), or null and 0 when it holds
///   none. Never a key read off this device's own credential or handed over
///   by the server (`RegisterDeviceResponse.account_identity_key`): either
///   passes the check whoever certified the credential. A credential
///   certified under any other account key fails with
///   [`PEACHY_MLS_ERR_CREDENTIAL`], `not_own_account_key`, and with null and 0
///   so does any certified credential: a device holding no key opens only
///   uncertified (docs/identity.md §The account identity key). A
///   credential with no certificate still opens.
///
/// The groups this device is in, the key packages it has published, the epoch
/// it is at in each group and its signature key all come back. Nothing else
/// changes: the same group ids, the same roster, the same `peachy_mls_group_*`
/// calls.
///
/// **Where the file goes is the caller's decision and it matters.** It holds
/// group secrets — encrypted when a key is given, in the clear otherwise (a
/// test build only) — and
/// the platform's own protections are what keep it out of a backup: on Apple,
/// a container file marked backup-excluded, like the device key store already
/// is; on Android, `noBackupFilesDir`. docs/mls-core.md §Storage layout spells
/// out both.
///
/// Fails with [`PEACHY_MLS_ERR_PLAINTEXT_STORE`] when a key is given and the
/// file was written in the clear (encrypt it with
/// [`peachy_mls_store_encrypt_in_place`]), with
/// [`PEACHY_MLS_ERR_INSECURE_STORE`] when the file or its `-wal`, `-shm` or
/// `-journal` is writable by group or others or is a symbolic link (nothing
/// is opened), and with
/// [`PEACHY_MLS_ERR_STORAGE`] when the file cannot be opened, does not open
/// under `store_key` (another key), or was written by a newer schema — which is a refusal, not a repair: reading a
/// future layout with today's rules is how a group ends up with a tree from one
/// version and secrets from another.
///
/// # Safety
/// All pointers must be valid for the lengths given, `store_path` must be null
/// or a NUL-terminated string, `store_key` must be null or valid for
/// `store_key_len` bytes, and `out_client` must point to writable storage for
/// one pointer.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_client_open(
    credential: *const u8,
    credential_len: usize,
    signature_seed: *const u8,
    signature_seed_len: usize,
    trusted_keys_json: *const c_char,
    store_path: *const c_char,
    store_key: *const u8,
    store_key_len: usize,
    own_account_identity: *const u8,
    own_account_identity_len: usize,
    out_client: *mut *mut PeachyMlsClient,
) -> i32 {
    guard(|| {
        build_client(
            credential,
            credential_len,
            signature_seed,
            signature_seed_len,
            trusted_keys_json,
            store_path,
            store_key,
            store_key_len,
            own_account_identity,
            own_account_identity_len,
            false,
            out_client,
        )
    })
}

/// [`peachy_mls_client_open`] for a store that must already be there: a path
/// with no file is refused with [`PEACHY_MLS_ERR_INVALID_ARGUMENT`] and
/// nothing is created, rather than opening an empty store that has dropped
/// out of every group. What a daemon reopening its own store calls, so a
/// store lost to a crash or a bad migration is an error, not a fresh start.
/// A null or empty `store_path` is refused the same way.
///
/// # Safety
/// As [`peachy_mls_client_open`].
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_client_open_existing(
    credential: *const u8,
    credential_len: usize,
    signature_seed: *const u8,
    signature_seed_len: usize,
    trusted_keys_json: *const c_char,
    store_path: *const c_char,
    store_key: *const u8,
    store_key_len: usize,
    own_account_identity: *const u8,
    own_account_identity_len: usize,
    out_client: *mut *mut PeachyMlsClient,
) -> i32 {
    guard(|| {
        build_client(
            credential,
            credential_len,
            signature_seed,
            signature_seed_len,
            trusted_keys_json,
            store_path,
            store_key,
            store_key_len,
            own_account_identity,
            own_account_identity_len,
            true,
            out_client,
        )
    })
}

/// ENCRYPT A STORE IN PLACE: the store at `store_path` (NUL-terminated),
/// written in the clear, becomes one under `store_key` (32 bytes, or 48 for
/// the plaintext-header layout, as [`peachy_mls_client_open`] takes it), with
/// every row kept and no plaintext copy, log or index left beside it, and no
/// moment with no store (`peachy_mls_core::sqlite::store_encrypt_in_place`).
/// Refused with [`PEACHY_MLS_ERR_INVALID_ARGUMENT`], with nothing changed,
/// for a path with no store and for a store that is not in the clear, and
/// with [`PEACHY_MLS_ERR_INSECURE_STORE`] for one whose files group or
/// others can write, or that is a symbolic link. A
/// failure part-way leaves the store in the clear, as it was: call it again.
/// Nothing else may hold the store open. The answer to
/// [`PEACHY_MLS_ERR_PLAINTEXT_STORE`].
///
/// # Safety
/// `store_path` must be a NUL-terminated string and `store_key` valid for
/// `store_key_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_store_encrypt_in_place(
    store_path: *const c_char,
    store_key: *const u8,
    store_key_len: usize,
) -> i32 {
    guard(|| {
        let path = cstr_arg(store_path, "store_path")?;
        let key = Zeroizing::new(slice_from(store_key, store_key_len, "store_key")?.to_vec());
        peachy_mls_core::sqlite::store_encrypt_in_place(path, &key)
    })
}

/// A 32-byte key that may be absent: null and 0 is `None`, 32 bytes is the
/// key, anything else is [`PEACHY_MLS_ERR_INVALID_ARGUMENT`].
///
/// # Safety
/// `key` must be null or valid for `key_len` bytes.
unsafe fn optional_key32(
    key: *const u8,
    key_len: usize,
    name: &str,
) -> Result<Option<[u8; 32]>, Error> {
    if key.is_null() && key_len == 0 {
        return Ok(None);
    }
    if key_len != 32 {
        return Err(Error::InvalidArgument(format!(
            "{name} must be 32 bytes, got {key_len}"
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(slice_from(key, key_len, name)?);
    Ok(Some(out))
}

/// The body both constructors share. A null or empty `store_path` is the
/// ephemeral client.
///
/// # Safety
/// As [`peachy_mls_client_open`].
#[allow(clippy::too_many_arguments)]
unsafe fn build_client(
    credential: *const u8,
    credential_len: usize,
    signature_seed: *const u8,
    signature_seed_len: usize,
    trusted_keys_json: *const c_char,
    store_path: *const c_char,
    store_key: *const u8,
    store_key_len: usize,
    own_account_identity: *const u8,
    own_account_identity_len: usize,
    must_exist: bool,
    out_client: *mut *mut PeachyMlsClient,
) -> Result<(), Error> {
    if out_client.is_null() {
        return Err(null_argument("out_client"));
    }
    let credential = slice_from(credential, credential_len, "credential")?.to_vec();

    if signature_seed_len != 32 {
        return Err(Error::InvalidArgument(format!(
            "a device signature seed must be 32 bytes, got {signature_seed_len}"
        )));
    }
    let seed_slice = slice_from(signature_seed, signature_seed_len, "signature_seed")?;
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(seed_slice);

    if trusted_keys_json.is_null() {
        return Err(null_argument("trusted_keys_json"));
    }
    let json = CStr::from_ptr(trusted_keys_json)
        .to_str()
        .map_err(|_| Error::InvalidArgument("trusted_keys_json is not UTF-8".into()))?;
    let trusted = TrustedServerKeys::from_published_json(json)?;

    // 32 bytes is a raw key (Android); 48 is a raw key and a salt, with the
    // file's first 32 bytes left as SQLite's plaintext header (Apple — iOS
    // kills a suspended app holding a lock on a shared-container file it
    // cannot recognize as SQLite; `mls/core/src/sqlite.rs` §The plaintext
    // header).
    let key: Option<StoreKey> = if store_key.is_null() && store_key_len == 0 {
        None
    } else {
        match store_key_len {
            32 => {
                let mut key = Zeroizing::new([0u8; 32]);
                key.copy_from_slice(slice_from(store_key, store_key_len, "store_key")?);
                Some(StoreKey::Raw(key))
            }
            48 => {
                let mut keyspec = Zeroizing::new([0u8; 48]);
                keyspec.copy_from_slice(slice_from(store_key, store_key_len, "store_key")?);
                Some(StoreKey::WithSalt(keyspec))
            }
            other => {
                return Err(Error::InvalidArgument(format!(
                    "a store key must be 32 or 48 bytes, got {other}"
                )))
            }
        }
    };

    let path = if store_path.is_null() {
        ""
    } else {
        CStr::from_ptr(store_path)
            .to_str()
            .map_err(|_| Error::InvalidArgument("store_path is not UTF-8".into()))?
    };
    if must_exist && path.is_empty() {
        return Err(Error::InvalidArgument(
            "an open of an existing store names its path".into(),
        ));
    }
    let storage = match (path.is_empty(), key) {
        (true, None) => PeachyStorage::in_memory(),
        (true, Some(_)) => {
            return Err(Error::InvalidArgument(
                "a store key was given with no store path".into(),
            ))
        }
        // A file in the clear holds group secrets any reader of the disk can
        // take: only a build with `insecure-plaintext-store` (tests and
        // tools) opens one.
        #[cfg(feature = "insecure-plaintext-store")]
        (false, None) => {
            if must_exist && !std::path::Path::new(path).exists() {
                return Err(Error::InvalidArgument(
                    "there is no MLS store at this path, and the open asked for an existing one"
                        .into(),
                ));
            }
            PeachyStorage::open(Box::new(SqliteKv::open(path)?))?
        }
        #[cfg(not(feature = "insecure-plaintext-store"))]
        (false, None) => {
            return Err(Error::InvalidArgument(
                "a store path needs a store key".into(),
            ))
        }
        // A store in the clear is its own refusal, PLAINTEXT_STORE, which no
        // retry fixes; one that does not open under the key stays STORAGE.
        (false, Some(StoreKey::Raw(key))) => {
            PeachyStorage::open(Box::new(SqliteKv::open_store(path, &key[..], must_exist)?))?
        }
        (false, Some(StoreKey::WithSalt(keyspec))) => PeachyStorage::open(Box::new(
            SqliteKv::open_store(path, &keyspec[..], must_exist)?,
        ))?,
    };

    let own_account_identity = optional_key32(
        own_account_identity,
        own_account_identity_len,
        "own_account_identity",
    )?;
    let client = Client::new(
        ClientConfig::with_seed(credential, seed, trusted)
            .with_storage(storage)
            .with_own_account_identity(own_account_identity),
    )?;
    *out_client = Box::into_raw(Box::new(PeachyMlsClient {
        inner: client,
        closed: false,
        roster: None,
    }));
    Ok(())
}

/// What `store_key` was: a raw key, or a key and a salt for a file with a
/// plaintext header.
enum StoreKey {
    Raw(Zeroizing<[u8; 32]>),
    WithSalt(Zeroizing<[u8; 48]>),
}

/// Free a client and everything it holds, including every group's key
/// material.
///
/// # Safety
/// `client` must be null or a pointer from [`peachy_mls_client_new`] that has
/// not already been freed.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_client_free(client: *mut PeachyMlsClient) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !client.is_null() {
            drop(Box::from_raw(client));
        }
    }));
}

/// # Safety
/// `client` must be a live pointer from [`peachy_mls_client_new`].
unsafe fn client_mut<'a>(client: *mut PeachyMlsClient) -> Result<&'a mut Client, Error> {
    // Any door but a roster read's own positions ends that read: whatever it
    // does (a forget, a join, a commit, new trusted keys) no snapshot taken
    // before it answers after it (§One roster per read).
    if !client.is_null() {
        (*client).roster = None;
    }
    roster_read_client(client)
}

/// [`client_mut`] for the per-position calls of one roster read, which read
/// the snapshot [`peachy_mls_group_member_count`] kept.
///
/// # Safety
/// As [`client_mut`].
unsafe fn roster_read_client<'a>(client: *mut PeachyMlsClient) -> Result<&'a mut Client, Error> {
    if client.is_null() {
        return Err(null_argument("client"));
    }
    if (*client).closed {
        CALL_ON_CLOSED.with(|slot| slot.set(true));
        return Err(Error::Unsupported(
            "this client was closed after a panic; free it and open a new one from the store",
        ));
    }
    CALL_CLIENT.with(|slot| slot.set(client));
    Ok(&mut (*client).inner)
}

/// Write `bytes` into an out-parameter, checking it first.
///
/// # Safety
/// `out` must be null or point to writable storage for one `PeachyMlsBuffer`.
unsafe fn write_buffer(
    out: *mut PeachyMlsBuffer,
    name: &str,
    mut bytes: Vec<u8>,
) -> Result<(), Error> {
    if out.is_null() {
        // Nobody will free what is not handed out: wipe it here, as the free
        // door would have (it may be a key or a plaintext).
        bytes.zeroize();
        return Err(null_argument(name));
    }
    *out = PeachyMlsBuffer::from_vec(bytes);
    Ok(())
}

/// A list of strings as this boundary carries it, in both directions: a u32
/// big-endian count, then each item as a u32 big-endian byte length and that
/// many UTF-8 bytes. No separator character, so no item can split or merge
/// another, whatever it holds.
fn encode_string_list<S: AsRef<str>>(items: &[S]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + items.iter().map(|s| 4 + s.as_ref().len()).sum::<usize>());
    out.extend_from_slice(&(items.len() as u32).to_be_bytes());
    for item in items {
        let bytes = item.as_ref().as_bytes();
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
    }
    out
}

/// The list shape of [`encode_string_list`] carrying raw bytes, each item as
/// it is: the proposals a leave sends.
fn encode_byte_list(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + items.iter().map(|b| 4 + b.len()).sum::<usize>());
    out.extend_from_slice(&(items.len() as u32).to_be_bytes());
    for item in items {
        out.extend_from_slice(&(item.len() as u32).to_be_bytes());
        out.extend_from_slice(item);
    }
    out
}

/// Read a list [`encode_string_list`] wrote. An empty buffer is the empty
/// list; anything else must be consumed exactly: a count or length that runs
/// past the end, a byte left over, or an item that is not UTF-8 is
/// [`Error::InvalidArgument`], never a shorter list.
fn decode_string_list(bytes: &[u8], name: &str) -> Result<Vec<String>, Error> {
    decode_byte_list(bytes, name, "string")?
        .into_iter()
        .map(|item| {
            String::from_utf8(item).map_err(|_| {
                Error::InvalidArgument(format!("{name} is not a well-formed string list"))
            })
        })
        .collect()
}

/// The same list shape carrying raw bytes, each item as it is: for
/// [`peachy_mls_group_seat_founding`]'s KeyPackages.
fn decode_byte_list(bytes: &[u8], name: &str, kind: &str) -> Result<Vec<Vec<u8>>, Error> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let malformed = || Error::InvalidArgument(format!("{name} is not a well-formed {kind} list"));
    let mut rest = bytes;
    let take_u32 = |rest: &mut &[u8]| -> Result<usize, Error> {
        let (head, tail) = rest.split_first_chunk::<4>().ok_or_else(malformed)?;
        *rest = tail;
        Ok(u32::from_be_bytes(*head) as usize)
    };
    let count = take_u32(&mut rest)?;
    // Every item takes at least its four length bytes: a count the buffer
    // cannot hold is refused before anything is allocated for it.
    if count > rest.len() / 4 {
        return Err(malformed());
    }
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        let len = take_u32(&mut rest)?;
        if len > rest.len() {
            return Err(malformed());
        }
        let (item, tail) = rest.split_at(len);
        rest = tail;
        items.push(item.to_vec());
    }
    if !rest.is_empty() {
        return Err(malformed());
    }
    Ok(items)
}

/// The string-list codec, for `mls/fuzz`'s `string_list` target and nothing
/// else. Behind the `fuzzing` feature, so no shipped archive carries it, and
/// plain Rust, so the C header does not change.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing {
    /// [`super::decode_string_list`], its refusal as `None`.
    pub fn decode_string_list(bytes: &[u8]) -> Option<Vec<String>> {
        super::decode_string_list(bytes, "list").ok()
    }

    /// [`super::encode_string_list`].
    pub fn encode_string_list(items: &[String]) -> Vec<u8> {
        super::encode_string_list(items)
    }
}

/// Refuse a null out-parameter BEFORE the call that would fill it.
///
/// Rule 5 in the module header, in one line. [`write_buffer`] checks too, but
/// it checks at the end — which is fine for a read and wrong for anything that
/// mints, joins, commits or encrypts, because by then the irreversible half has
/// already happened and only the answer is lost.
///
/// # Safety
/// `out` is only tested for null; it is never read or written here.
unsafe fn require_out<T>(out: *const T, name: &str) -> Result<(), Error> {
    if out.is_null() {
        return Err(null_argument(name));
    }
    Ok(())
}

/// This device's `actor_id` (the KEY layer — never shown to a person) and
/// `device_id`, as UTF-8 bytes. Either out-parameter may be null to skip it.
///
/// # Safety
/// Out-parameters must be null or point to writable `PeachyMlsBuffer` storage.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_client_identity(
    client: *mut PeachyMlsClient,
    out_actor_id: *mut PeachyMlsBuffer,
    out_device_id: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let client = client_mut(client)?;
        let identity = client.identity();
        if !out_actor_id.is_null() {
            *out_actor_id = PeachyMlsBuffer::from_vec(identity.actor_id.clone().into_bytes());
        }
        if !out_device_id.is_null() {
            *out_device_id = PeachyMlsBuffer::from_vec(identity.device_id.clone().into_bytes());
        }
        Ok(())
    })
}

/// The account identity key this device's own credential carries — 32 bytes —
/// or an EMPTY buffer while this device holds no account certificate. A
/// device with an empty answer can open, but cannot publish a key package or
/// found a group ([`PEACHY_MLS_ERR_CREDENTIAL`], `not_approved`). Freed with
/// [`peachy_mls_buffer_free`].
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_client_account_key(
    client: *mut PeachyMlsClient,
    out_key: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let client = client_mut(client)?;
        let key = client
            .identity()
            .account_key
            .map(|key| key.to_vec())
            .unwrap_or_default();
        write_buffer(out_key, "out_key", key)
    })
}

/// The actors in `group_id` whose account identity key CHANGED since this
/// device pinned it, as a string list (a u32 big-endian count, then each id
/// as a u32 big-endian length and its UTF-8 bytes; a count of 0 when none) —
/// each one a "security code changed" notice for this conversation
/// (docs/identity.md §Security code changed). The first key seen for an
/// actor is pinned in silence. It writes, and is idempotent; call it after
/// anything that can change the tree. Freed with [`peachy_mls_buffer_free`].
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_observe_account_keys(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    out_actor_ids: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        // Rule 5: this WRITES. A change is recorded as seen and reported once,
        // so an answer refused after the call is a "security code changed"
        // notice consumed and never shown.
        require_out(out_actor_ids, "out_actor_ids")?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let changed = client.observe_account_keys(group_id)?;
        write_buffer(out_actor_ids, "out_actor_ids", encode_string_list(&changed))
    })
}

/// Mint a key package for somebody else to add this device with. Single-use.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_key_package(
    client: *mut PeachyMlsClient,
    out_key_package: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        // Rule 5: minting leaves fresh private init and encryption halves in
        // this device's store. A mint whose output we then refuse to write is a
        // key pair stranded there for good, and a Welcome nobody can open.
        require_out(out_key_package, "out_key_package")?;
        let client = client_mut(client)?;
        let bytes = client.generate_key_package()?;
        write_buffer(out_key_package, "out_key_package", bytes)
    })
}

/// The same key package, plus the RFC 9420 `KeyPackageRef` that names it and
/// the ciphersuite it is for.
///
/// This is the door a key-package DIRECTORY needs, and
/// [`peachy_mls_key_package`] is not it. Peachy's directory keys each package
/// by `key_package_ref` on `PublishKeyPackages` — the idempotency key that
/// stops a device republishing its pool from growing it forever
/// (docs/delivery.md §The KeyPackage lifecycle). The server holds
/// no MLS implementation and takes the value on trust, so nothing on the wire
/// would catch a caller that invented one.
///
/// And inventing one is the easy mistake: the reference is `RefHash` over the
/// bare TLS-serialized KeyPackage, NOT over the `MlsMessage` wrapper that
/// `out_key_package` hands back. They differ by a framing header, so a caller
/// hashing the published bytes itself gets a plausible value that no other MLS
/// implementation will agree with. Computing it in the one place that already
/// holds the package is how all three bindings get the same answer.
///
/// `out_ciphersuite` receives the MLS ciphersuite id these bytes are for, so a
/// caller filling in `PublishKeyPackages` does not have to hardcode the
/// constant and then be wrong about it after a suite change.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_key_package_with_ref(
    client: *mut PeachyMlsClient,
    out_key_package: *mut PeachyMlsBuffer,
    out_key_package_ref: *mut PeachyMlsBuffer,
    out_ciphersuite: *mut u16,
) -> i32 {
    guard(|| {
        // Checked BEFORE the package is minted. Every call leaves fresh
        // private init and encryption halves in this device's store, so a
        // mint whose output we then refuse to write is a key pair stranded
        // there for good.
        if out_key_package.is_null() {
            return Err(null_argument("out_key_package"));
        }
        if out_key_package_ref.is_null() {
            return Err(null_argument("out_key_package_ref"));
        }
        let client = client_mut(client)?;
        let (key_package, key_package_ref) = client.generate_key_package_with_ref()?;
        if !out_ciphersuite.is_null() {
            *out_ciphersuite = u16::from(PEACHY_CIPHERSUITE);
        }
        *out_key_package = PeachyMlsBuffer::from_vec(key_package);
        *out_key_package_ref = PeachyMlsBuffer::from_vec(key_package_ref);
        Ok(())
    })
}

/// A LAST-RESORT key package, its `KeyPackageRef` and ciphersuite: the one to
/// publish with `last_resort` set on `PublishKeyPackages`.
///
/// It carries the `last_resort` extension, so it opens any number of Welcomes
/// until it is rotated — the directory serves it only once this device's
/// one-time packages are gone. Publish one whenever the pool status says this
/// device has none, or [`peachy_mls_last_resort_rotation_due`] says so
/// (docs/mls-core.md §Last-resort key packages).
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_last_resort_key_package_with_ref(
    client: *mut PeachyMlsClient,
    out_key_package: *mut PeachyMlsBuffer,
    out_key_package_ref: *mut PeachyMlsBuffer,
    out_ciphersuite: *mut u16,
) -> i32 {
    guard(|| {
        // Checked BEFORE the package is minted, as above.
        if out_key_package.is_null() {
            return Err(null_argument("out_key_package"));
        }
        if out_key_package_ref.is_null() {
            return Err(null_argument("out_key_package_ref"));
        }
        let client = client_mut(client)?;
        let (key_package, key_package_ref) = client.generate_last_resort_key_package_with_ref()?;
        if !out_ciphersuite.is_null() {
            *out_ciphersuite = u16::from(PEACHY_CIPHERSUITE);
        }
        *out_key_package = PeachyMlsBuffer::from_vec(key_package);
        *out_key_package_ref = PeachyMlsBuffer::from_vec(key_package_ref);
        Ok(())
    })
}

/// Whether this device owes the directory a new last-resort key package: it
/// holds none this build minted, or its newest is two days old (a two-day
/// last-resort rotation). The rule lives in the core so four clients
/// cannot disagree about it.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_last_resort_rotation_due(
    client: *mut PeachyMlsClient,
    out_due: *mut bool,
) -> i32 {
    guard(|| {
        require_out(out_due, "out_due")?;
        let client = client_mut(client)?;
        *out_due = client.last_resort_rotation_due()?;
        Ok(())
    })
}

// ---- Enrollment --------------------------------------------------------------

/// A fresh 32-byte device signing key seed, from the platform CSPRNG.
///
/// No client handle: this is the FIRST step of enrolling one, and the ordering
/// is load-bearing. Make a seed, publish [`peachy_mls_signing_key_public_key`]
/// of it as `RegisterDevice`'s `signing_key`, take the credential the server
/// mints against it, and only then call [`peachy_mls_client_new`]. A client
/// opened with a seed no credential was minted for fails with
/// [`PEACHY_MLS_ERR_CREDENTIAL`] and a `leaf_key_mismatch` message on every
/// call — which reads as a protocol bug and is really this sequence run out of
/// order.
///
/// The seed goes in the platform key store — the Keychain on Apple, the
/// no-backup directory on Android — and never on the wire.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_generate_signing_key_seed(
    out_seed: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let seed = Zeroizing::new(peachy_mls_core::generate_signing_key_seed()?);
        write_buffer(out_seed, "out_seed", seed.to_vec())
    })
}

/// The raw Ed25519 public key for a seed — which is also the leaf signature
/// key and the `device_key` the credential binds. Three names, one 32 bytes.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_signing_key_public_key(
    seed: *const u8,
    seed_len: usize,
    out_public_key: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let seed = slice_from(seed, seed_len, "seed")?;
        let public_key = peachy_mls_core::signing_key_public_key(seed)?;
        write_buffer(out_public_key, "out_public_key", public_key.to_vec())
    })
}

// ---- Device linking ---------------------------------------------------------
//
// Approving a new device from one you already have, the QR code that carries
// its key past the server, and the commit-then-reveal two-digit number a
// person picks when neither screen can scan (`peachy_mls_core::device_link`).
// Pure functions, no client handle and no group: they are about PUBLIC KEYS
// and nonces and nothing else, which is why none of them takes a
// `PeachyMlsClient*`.
//
// UNCONDITIONAL, unlike the issuer and fixture doors below: an app approving a
// second device is product code on iOS, macOS and Android, so these symbols
// are in every build of this library.
//
// Why the key has to cross through the person, and why the number needs both
// nonces in that order, is in `peachy_mls_core::device_link`'s module header;
// a wrapper author should read it before deciding when to reveal a nonce.

/// The exact bytes an approving device signs to vouch for another device:
/// `"peachy-device-approval-v1" || 0x00 || device_id || 0x00 || signing_key`.
///
/// `device_id` is `devices.id` as a NUL-terminated UTF-8 string; `signing_key`
/// is the approved device's raw 32-byte Ed25519 public key. `out_statement`
/// receives a freshly allocated buffer the caller frees with
/// [`peachy_mls_buffer_free`].
///
/// [`PEACHY_MLS_ERR_INVALID_ARGUMENT`] for an empty `device_id` or a
/// `signing_key` that is not exactly 32 bytes; the message names the field and
/// the size it wanted.
///
/// # Safety
/// See the module header. `device_id` must be a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_device_approval_statement(
    device_id: *const c_char,
    signing_key: *const u8,
    signing_key_len: usize,
    out_statement: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let device_id = cstr_arg(device_id, "device_id")?;
        let signing_key = slice_from(signing_key, signing_key_len, "signing_key")?;
        let statement = peachy_mls_core::device_approval_statement(device_id, signing_key)?;
        write_buffer(out_statement, "out_statement", statement)
    })
}

/// Sign that statement with an approving device's own 32-byte Ed25519 seed —
/// the same seed [`peachy_mls_signing_key_public_key`] takes, from the
/// platform key store.
///
/// `out_signature` receives 64 bytes, freed with [`peachy_mls_buffer_free`].
/// Ed25519 is deterministic, so the same inputs always produce the same bytes;
/// `mls/fixtures/device-link.json` pins several of them.
///
/// # Safety
/// See the module header. `device_id` must be a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_sign_device_approval(
    seed: *const u8,
    seed_len: usize,
    device_id: *const c_char,
    signing_key: *const u8,
    signing_key_len: usize,
    out_signature: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let seed = slice_from(seed, seed_len, "seed")?;
        let device_id = cstr_arg(device_id, "device_id")?;
        let signing_key = slice_from(signing_key, signing_key_len, "signing_key")?;
        let signature = peachy_mls_core::sign_device_approval(seed, device_id, signing_key)?;
        write_buffer(out_signature, "out_signature", signature.to_vec())
    })
}

/// Whether `signature` is a genuine approval of `(device_id, signing_key)` by
/// the holder of `approver_key`.
///
/// **Status [`PEACHY_MLS_OK`] with `*out_valid` false is the "this approval
/// does not hold" answer**, and it is the answer for a malformed approver key,
/// a signature of the wrong length and a signature that simply did not check
/// out alike. That is not laziness at the boundary: a caller able to tell
/// those apart would be holding an oracle, and every call site would then have
/// to decide for itself which failures are safe to read as "no". There is one
/// safe answer.
///
/// A NULL pointer is still an error, because it is a bug in the caller rather
/// than a fact about an approval.
///
/// # Safety
/// See the module header. `device_id` must be a valid NUL-terminated string
/// and `out_valid` must point to writable storage for one `bool`.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn peachy_mls_verify_device_approval(
    approver_key: *const u8,
    approver_key_len: usize,
    device_id: *const c_char,
    signing_key: *const u8,
    signing_key_len: usize,
    signature: *const u8,
    signature_len: usize,
    out_valid: *mut bool,
) -> i32 {
    guard(|| {
        if out_valid.is_null() {
            return Err(null_argument("out_valid"));
        }
        // Fail closed: an error below, or a caught panic, leaves "does not hold".
        *out_valid = false;
        let approver_key = slice_from(approver_key, approver_key_len, "approver_key")?;
        let device_id = cstr_arg(device_id, "device_id")?;
        let signing_key = slice_from(signing_key, signing_key_len, "signing_key")?;
        let signature = slice_from(signature, signature_len, "signature")?;
        *out_valid = peachy_mls_core::verify_device_approval(
            approver_key,
            device_id,
            signing_key,
            signature,
        );
        Ok(())
    })
}

/// The approver's commitment to its 32-byte nonce, published before the new
/// device draws its own. `out_commitment` receives 32 bytes, freed with
/// [`peachy_mls_buffer_free`].
///
/// [`PEACHY_MLS_ERR_INVALID_ARGUMENT`] for a nonce that is not 32 bytes.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_device_link_commitment(
    approver_nonce: *const u8,
    approver_nonce_len: usize,
    out_commitment: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let nonce = slice_from(approver_nonce, approver_nonce_len, "approver_nonce")?;
        let commitment = peachy_mls_core::device_link_commitment(nonce)?;
        write_buffer(out_commitment, "out_commitment", commitment.to_vec())
    })
}

/// The two-digit number the new device shows and the approver offers among
/// three — `"00"` to `"99"`.
///
/// `out_number` receives UTF-8, **not** NUL-terminated, like every other
/// buffer here, freed with [`peachy_mls_buffer_free`].
///
/// [`PEACHY_MLS_ERR_INVALID_ARGUMENT`] for any input that is not 32 bytes, for
/// two IDENTICAL keys, and for an approver nonce that does not open the
/// commitment — never a number in any of those cases.
///
/// # Safety
/// See the module header.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn peachy_mls_device_link_number(
    new_device_key: *const u8,
    new_device_key_len: usize,
    approver_key: *const u8,
    approver_key_len: usize,
    approver_commitment: *const u8,
    approver_commitment_len: usize,
    device_nonce: *const u8,
    device_nonce_len: usize,
    approver_nonce: *const u8,
    approver_nonce_len: usize,
    out_number: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let new_device_key = slice_from(new_device_key, new_device_key_len, "new_device_key")?;
        let approver_key = slice_from(approver_key, approver_key_len, "approver_key")?;
        let commitment = slice_from(
            approver_commitment,
            approver_commitment_len,
            "approver_commitment",
        )?;
        let device_nonce = slice_from(device_nonce, device_nonce_len, "device_nonce")?;
        let approver_nonce = slice_from(approver_nonce, approver_nonce_len, "approver_nonce")?;
        let number = peachy_mls_core::device_link_number(
            new_device_key,
            approver_key,
            commitment,
            device_nonce,
            approver_nonce,
        )?;
        write_buffer(out_number, "out_number", number.into_bytes())
    })
}

/// The approver's two-digit number, `"00"` to `"99"`: what the APPROVING
/// device shows after a correct pick, for the person to pick on the new
/// device. The same inputs, buffer and refusals as
/// [`peachy_mls_device_link_number`], under another domain.
///
/// # Safety
/// See the module header.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn peachy_mls_device_link_approver_number(
    new_device_key: *const u8,
    new_device_key_len: usize,
    approver_key: *const u8,
    approver_key_len: usize,
    approver_commitment: *const u8,
    approver_commitment_len: usize,
    device_nonce: *const u8,
    device_nonce_len: usize,
    approver_nonce: *const u8,
    approver_nonce_len: usize,
    out_number: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let new_device_key = slice_from(new_device_key, new_device_key_len, "new_device_key")?;
        let approver_key = slice_from(approver_key, approver_key_len, "approver_key")?;
        let commitment = slice_from(
            approver_commitment,
            approver_commitment_len,
            "approver_commitment",
        )?;
        let device_nonce = slice_from(device_nonce, device_nonce_len, "device_nonce")?;
        let approver_nonce = slice_from(approver_nonce, approver_nonce_len, "approver_nonce")?;
        let number = peachy_mls_core::device_link_approver_number(
            new_device_key,
            approver_key,
            commitment,
            device_nonce,
            approver_nonce,
        )?;
        write_buffer(out_number, "out_number", number.into_bytes())
    })
}

/// The text the new device's QR code carries:
/// `"peachy-link:" || device_id || "/" || hex(signing_key) || "/" || hex(link_secret)`.
///
/// `out_text` receives UTF-8, **not** NUL-terminated, freed with
/// [`peachy_mls_buffer_free`]. [`PEACHY_MLS_ERR_INVALID_ARGUMENT`] for an empty
/// device id, one with `/` or non-printable bytes, or a key or link secret not
/// 32 bytes.
///
/// # Safety
/// See the module header. `device_id` must be a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_device_link_qr(
    device_id: *const c_char,
    signing_key: *const u8,
    signing_key_len: usize,
    link_secret: *const u8,
    link_secret_len: usize,
    out_text: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let device_id = cstr_arg(device_id, "device_id")?;
        let signing_key = slice_from(signing_key, signing_key_len, "signing_key")?;
        let link_secret = slice_from(link_secret, link_secret_len, "link_secret")?;
        let text = peachy_mls_core::device_link_qr(device_id, signing_key, link_secret)?;
        write_buffer(out_text, "out_text", text.into_bytes())
    })
}

/// The 32-byte link secret a scanned QR code carries, when the code names
/// exactly this waiting device and key.
///
/// Status [`PEACHY_MLS_OK`] with an EMPTY `out_secret` is "not this one", for
/// every way a code can fail to match, like
/// [`peachy_mls_device_link_qr_matches`]. Otherwise `out_secret` receives 32
/// bytes, freed with [`peachy_mls_buffer_free`].
///
/// # Safety
/// See the module header. `scanned` and `device_id` must be valid
/// NUL-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_device_link_qr_secret(
    scanned: *const c_char,
    device_id: *const c_char,
    signing_key: *const u8,
    signing_key_len: usize,
    out_secret: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let scanned = cstr_arg(scanned, "scanned")?;
        let device_id = cstr_arg(device_id, "device_id")?;
        let signing_key = slice_from(signing_key, signing_key_len, "signing_key")?;
        let secret = peachy_mls_core::device_link_qr_secret(scanned, device_id, signing_key)
            .map(|s| Zeroizing::new(s).to_vec())
            .unwrap_or_default();
        write_buffer(out_secret, "out_secret", secret)
    })
}

/// Whether a scanned QR code names exactly this waiting device and key.
///
/// Status [`PEACHY_MLS_OK`] with `*out_matches` false is "not this one", for a
/// code from another app, another device, another key, or a malformed key
/// alike — the same one-answer rule as [`peachy_mls_verify_device_approval`].
///
/// # Safety
/// See the module header. `scanned` and `device_id` must be valid
/// NUL-terminated strings and `out_matches` must point to one writable `bool`.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_device_link_qr_matches(
    scanned: *const c_char,
    device_id: *const c_char,
    signing_key: *const u8,
    signing_key_len: usize,
    out_matches: *mut bool,
) -> i32 {
    guard(|| {
        if out_matches.is_null() {
            return Err(null_argument("out_matches"));
        }
        // Fail closed: an error below, or a caught panic, leaves "not this one".
        *out_matches = false;
        let scanned = cstr_arg(scanned, "scanned")?;
        let device_id = cstr_arg(device_id, "device_id")?;
        let signing_key = slice_from(signing_key, signing_key_len, "signing_key")?;
        *out_matches = peachy_mls_core::device_link_qr_matches(scanned, device_id, signing_key);
        Ok(())
    })
}

/// The waiting device's rule for the two-digit number: one exchange per
/// pairing (`peachy_mls_core::device_link_waiter_step`).
///
/// `bound_*` is what this pairing already answered: an empty string and two
/// empty slices for a pairing that has answered nothing, all three set once it
/// has. The rest is one exchange on the waiting device's row. `*out_step`
/// receives one of the `PEACHY_MLS_LINK_*` codes: `ANSWER` binds the pairing
/// to this exchange, `CONTINUE` is the bound one, `IGNORE` is another
/// approver's, and `INTERRUPTED` ends the pairing.
/// [`PEACHY_MLS_ERR_INVALID_ARGUMENT`] for an empty approver id, a key or
/// commitment not 32 bytes, or half a binding; a caller skips that exchange.
///
/// # Safety
/// See the module header. Both ids must be valid NUL-terminated strings and
/// `out_step` must point to one writable `u32`.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_device_link_waiter_step(
    bound_approver_id: *const c_char,
    bound_approver_key: *const u8,
    bound_approver_key_len: usize,
    bound_commitment: *const u8,
    bound_commitment_len: usize,
    approver_id: *const c_char,
    approver_key: *const u8,
    approver_key_len: usize,
    commitment: *const u8,
    commitment_len: usize,
    out_step: *mut u32,
) -> i32 {
    guard(|| {
        if out_step.is_null() {
            return Err(null_argument("out_step"));
        }
        // Fail closed: ANSWER is 0, and binds the pairing to this exchange.
        // An error below, or a caught panic, leaves the answer a malformed
        // exchange gets: skip it.
        *out_step = PEACHY_MLS_LINK_IGNORE;
        let bound_approver_id = cstr_arg(bound_approver_id, "bound_approver_id")?;
        let bound_approver_key = slice_from(
            bound_approver_key,
            bound_approver_key_len,
            "bound_approver_key",
        )?;
        let bound_commitment =
            slice_from(bound_commitment, bound_commitment_len, "bound_commitment")?;
        let approver_id = cstr_arg(approver_id, "approver_id")?;
        let approver_key = slice_from(approver_key, approver_key_len, "approver_key")?;
        let commitment = slice_from(commitment, commitment_len, "commitment")?;
        let step = peachy_mls_core::device_link_waiter_step(
            bound_approver_id,
            bound_approver_key,
            bound_commitment,
            approver_id,
            approver_key,
            commitment,
        )?;
        *out_step = match step {
            peachy_mls_core::DeviceLinkWaiterStep::Answer => PEACHY_MLS_LINK_ANSWER,
            peachy_mls_core::DeviceLinkWaiterStep::Continue => PEACHY_MLS_LINK_CONTINUE,
            peachy_mls_core::DeviceLinkWaiterStep::Ignore => PEACHY_MLS_LINK_IGNORE,
            peachy_mls_core::DeviceLinkWaiterStep::Interrupted => PEACHY_MLS_LINK_INTERRUPTED,
        };
        Ok(())
    })
}

/// Sign an approver's commitment for one waiting device
/// (`peachy_mls_core::sign_device_link_commitment`): 64 bytes into
/// `out_signature`, freed with [`peachy_mls_buffer_free`]. Posted beside the
/// commitment; the waiting device answers only an exchange whose signature
/// holds.
///
/// # Safety
/// See the module header. `pending_device_id` must be a valid NUL-terminated
/// string.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn peachy_mls_sign_device_link_commitment(
    seed: *const u8,
    seed_len: usize,
    pending_device_id: *const c_char,
    pending_key: *const u8,
    pending_key_len: usize,
    commitment: *const u8,
    commitment_len: usize,
    out_signature: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let seed = slice_from(seed, seed_len, "seed")?;
        let pending_device_id = cstr_arg(pending_device_id, "pending_device_id")?;
        let pending_key = slice_from(pending_key, pending_key_len, "pending_key")?;
        let commitment = slice_from(commitment, commitment_len, "commitment")?;
        let signature = peachy_mls_core::sign_device_link_commitment(
            seed,
            pending_device_id,
            pending_key,
            commitment,
        )?;
        write_buffer(out_signature, "out_signature", signature.to_vec())
    })
}

/// Whether `signature` is `approver_key`'s signature over this commitment for
/// this waiting device (`peachy_mls_core::verify_device_link_commitment`).
/// [`PEACHY_MLS_OK`] with `*out_valid` false is the answer for every way it can
/// fail to hold, as for [`peachy_mls_verify_device_approval`].
///
/// # Safety
/// See the module header. `pending_device_id` must be a valid NUL-terminated
/// string and `out_valid` must point to writable storage for one `bool`.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn peachy_mls_verify_device_link_commitment(
    approver_key: *const u8,
    approver_key_len: usize,
    pending_device_id: *const c_char,
    pending_key: *const u8,
    pending_key_len: usize,
    commitment: *const u8,
    commitment_len: usize,
    signature: *const u8,
    signature_len: usize,
    out_valid: *mut bool,
) -> i32 {
    guard(|| {
        if out_valid.is_null() {
            return Err(null_argument("out_valid"));
        }
        // Fail closed: an error below, or a caught panic, leaves "does not hold".
        *out_valid = false;
        let approver_key = slice_from(approver_key, approver_key_len, "approver_key")?;
        let pending_device_id = cstr_arg(pending_device_id, "pending_device_id")?;
        let pending_key = slice_from(pending_key, pending_key_len, "pending_key")?;
        let commitment = slice_from(commitment, commitment_len, "commitment")?;
        let signature = slice_from(signature, signature_len, "signature")?;
        *out_valid = peachy_mls_core::verify_device_link_commitment(
            approver_key,
            pending_device_id,
            pending_key,
            commitment,
            signature,
        );
        Ok(())
    })
}

/// A fresh 32-byte link-key seed from the platform CSPRNG
/// (`peachy_mls_core::generate_device_link_kem_seed`), freed with
/// [`peachy_mls_buffer_free`]. The waiting device draws one per pairing and
/// keeps it until the account key arrives.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_generate_device_link_kem_seed(
    out_seed: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let seed = Zeroizing::new(peachy_mls_core::generate_device_link_kem_seed()?);
        write_buffer(out_seed, "out_seed", seed.to_vec())
    })
}

/// The 1216-byte X-Wing link key a 32-byte seed derives
/// (`peachy_mls_core::device_link_kem_public_key`), freed with
/// [`peachy_mls_buffer_free`]. Posted beside the waiting device's nonce.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_device_link_kem_public_key(
    seed: *const u8,
    seed_len: usize,
    out_link_key: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let seed = slice_from(seed, seed_len, "seed")?;
        let link_key = peachy_mls_core::device_link_kem_public_key(seed)?;
        write_buffer(out_link_key, "out_link_key", link_key)
    })
}

/// The waiting device's signature over the link key it posts with its nonce
/// (`peachy_mls_core::sign_device_link_kem`): 64 bytes into `out_signature`,
/// freed with [`peachy_mls_buffer_free`]. `seed` is the waiting device's own
/// Ed25519 seed, the key the two-digit number is derived over.
///
/// # Safety
/// See the module header. `pending_device_id` must be a valid NUL-terminated
/// string.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn peachy_mls_sign_device_link_kem(
    seed: *const u8,
    seed_len: usize,
    pending_device_id: *const c_char,
    commitment: *const u8,
    commitment_len: usize,
    device_nonce: *const u8,
    device_nonce_len: usize,
    link_key: *const u8,
    link_key_len: usize,
    out_signature: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let seed = slice_from(seed, seed_len, "seed")?;
        let pending_device_id = cstr_arg(pending_device_id, "pending_device_id")?;
        let commitment = slice_from(commitment, commitment_len, "commitment")?;
        let device_nonce = slice_from(device_nonce, device_nonce_len, "device_nonce")?;
        let link_key = slice_from(link_key, link_key_len, "link_key")?;
        let signature = peachy_mls_core::sign_device_link_kem(
            seed,
            pending_device_id,
            commitment,
            device_nonce,
            link_key,
        )?;
        write_buffer(out_signature, "out_signature", signature.to_vec())
    })
}

/// Whether `signature` is the waiting device's signature over this link key
/// for this exchange (`peachy_mls_core::verify_device_link_kem`).
/// `pending_key` is the key the approver derived the number over.
/// [`PEACHY_MLS_OK`] with `*out_valid` false is the answer for every way it can
/// fail to hold, including an empty link key.
///
/// # Safety
/// See the module header. `pending_device_id` must be a valid NUL-terminated
/// string and `out_valid` must point to writable storage for one `bool`.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn peachy_mls_verify_device_link_kem(
    pending_key: *const u8,
    pending_key_len: usize,
    pending_device_id: *const c_char,
    commitment: *const u8,
    commitment_len: usize,
    device_nonce: *const u8,
    device_nonce_len: usize,
    link_key: *const u8,
    link_key_len: usize,
    signature: *const u8,
    signature_len: usize,
    out_valid: *mut bool,
) -> i32 {
    guard(|| {
        if out_valid.is_null() {
            return Err(null_argument("out_valid"));
        }
        // Fail closed: an error below, or a caught panic, leaves "does not hold".
        *out_valid = false;
        let pending_key = slice_from(pending_key, pending_key_len, "pending_key")?;
        let pending_device_id = cstr_arg(pending_device_id, "pending_device_id")?;
        let commitment = slice_from(commitment, commitment_len, "commitment")?;
        let device_nonce = slice_from(device_nonce, device_nonce_len, "device_nonce")?;
        let link_key = slice_from(link_key, link_key_len, "link_key")?;
        let signature = slice_from(signature, signature_len, "signature")?;
        *out_valid = peachy_mls_core::verify_device_link_kem(
            pending_key,
            pending_device_id,
            commitment,
            device_nonce,
            link_key,
            signature,
        );
        Ok(())
    })
}

/// The approving device's rule for the two-digit number: fix the waiting
/// device's nonce before revealing, and treat any change after that as an
/// interruption (`peachy_mls_core::device_link_approver_step`).
///
/// `pending_key`, `commitment` and `bound_device_nonce` are the caller's own
/// state for one prompt (the last empty until the first `REVEAL`, then the
/// device nonce that read listed, which the caller MUST store before it posts
/// the reveal). The `listed_*` slices are this read: the waiting row's key and
/// this approver's exchange on it, each empty when absent. `*out_step`
/// receives one of the `PEACHY_MLS_APPROVER_*` codes.
/// [`PEACHY_MLS_ERR_INVALID_ARGUMENT`] for a malformed pending key,
/// commitment or bound nonce.
///
/// # Safety
/// See the module header. Every pointer must be non-null (an empty slice is a
/// non-null pointer with length 0) and `out_step` must point to one writable
/// `u32`.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn peachy_mls_device_link_approver_step(
    pending_key: *const u8,
    pending_key_len: usize,
    commitment: *const u8,
    commitment_len: usize,
    bound_device_nonce: *const u8,
    bound_device_nonce_len: usize,
    listed_key: *const u8,
    listed_key_len: usize,
    listed_commitment: *const u8,
    listed_commitment_len: usize,
    listed_device_nonce: *const u8,
    listed_device_nonce_len: usize,
    listed_approver_nonce: *const u8,
    listed_approver_nonce_len: usize,
    out_step: *mut u32,
) -> i32 {
    guard(|| {
        if out_step.is_null() {
            return Err(null_argument("out_step"));
        }
        // Fail closed: COMMIT is 0, and fixes the waiting device's nonce. An
        // error below, or a caught panic, leaves "do nothing on this read".
        *out_step = PEACHY_MLS_APPROVER_WAIT;
        let step = peachy_mls_core::device_link_approver_step(
            slice_from(pending_key, pending_key_len, "pending_key")?,
            slice_from(commitment, commitment_len, "commitment")?,
            slice_from(
                bound_device_nonce,
                bound_device_nonce_len,
                "bound_device_nonce",
            )?,
            slice_from(listed_key, listed_key_len, "listed_key")?,
            slice_from(
                listed_commitment,
                listed_commitment_len,
                "listed_commitment",
            )?,
            slice_from(
                listed_device_nonce,
                listed_device_nonce_len,
                "listed_device_nonce",
            )?,
            slice_from(
                listed_approver_nonce,
                listed_approver_nonce_len,
                "listed_approver_nonce",
            )?,
        )?;
        *out_step = match step {
            peachy_mls_core::DeviceLinkApproverStep::Commit => PEACHY_MLS_APPROVER_COMMIT,
            peachy_mls_core::DeviceLinkApproverStep::Wait => PEACHY_MLS_APPROVER_WAIT,
            peachy_mls_core::DeviceLinkApproverStep::Reveal => PEACHY_MLS_APPROVER_REVEAL,
            peachy_mls_core::DeviceLinkApproverStep::Show => PEACHY_MLS_APPROVER_SHOW,
            peachy_mls_core::DeviceLinkApproverStep::Interrupted => PEACHY_MLS_APPROVER_INTERRUPTED,
        };
        Ok(())
    })
}

// ---- The account identity key ------------------------------------------------
//
// `peachy_mls_core::account_identity`: one Ed25519 key per ACCOUNT, derived
// from the account store's 32-byte key, that signs for each of the account's
// devices. A device holding the account key certifies itself at
// `RegisterDevice`; every peer refuses a leaf or key package without a valid
// certificate (docs/identity.md §The account identity key).
// Unconditional, like the device-link door above.

/// The account's 32-byte public identity key, derived from its 32-byte
/// account key. Freed with [`peachy_mls_buffer_free`].
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_account_identity_public_key(
    account_key: *const u8,
    account_key_len: usize,
    out_key: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let account_key = slice_from(account_key, account_key_len, "account_key")?;
        let key = peachy_mls_core::account_identity_public_key(account_key)?;
        write_buffer(out_key, "out_key", key.to_vec())
    })
}

/// The account identity key's 64-byte signature over `device_key`, the
/// device's raw 32-byte Ed25519 public key. Deterministic, so
/// `mls/fixtures/device-link.json` pins one. Freed with
/// [`peachy_mls_buffer_free`].
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_sign_account_device(
    account_key: *const u8,
    account_key_len: usize,
    device_key: *const u8,
    device_key_len: usize,
    out_signature: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let account_key = slice_from(account_key, account_key_len, "account_key")?;
        let device_key = slice_from(device_key, device_key_len, "device_key")?;
        let signature = peachy_mls_core::sign_account_device(account_key, device_key)?;
        write_buffer(out_signature, "out_signature", signature.to_vec())
    })
}

/// Whether `signature` is the account identity key `account_identity_key`
/// vouching for `device_key`. **Status [`PEACHY_MLS_OK`] with `*out_valid`
/// false** is the answer for every way it can fail, as on
/// [`peachy_mls_verify_device_approval`].
///
/// # Safety
/// See the module header. `out_valid` must point to writable storage for one
/// `bool`.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_verify_account_device(
    account_identity_key: *const u8,
    account_identity_key_len: usize,
    device_key: *const u8,
    device_key_len: usize,
    signature: *const u8,
    signature_len: usize,
    out_valid: *mut bool,
) -> i32 {
    guard(|| {
        if out_valid.is_null() {
            return Err(null_argument("out_valid"));
        }
        // Fail closed: an error below, or a caught panic, leaves "does not hold".
        *out_valid = false;
        let account = slice_from(
            account_identity_key,
            account_identity_key_len,
            "account_identity_key",
        )?;
        let device_key = slice_from(device_key, device_key_len, "device_key")?;
        let signature = slice_from(signature, signature_len, "signature")?;
        *out_valid = peachy_mls_core::verify_account_device(account, device_key, signature);
        Ok(())
    })
}

// ---- The encrypted account store --------------------------------------------
//
// `peachy_mls_core::account_store`: one 32-byte account key, a record sealed
// under a key derived from it and the record's 16-byte id, and the 93-byte box
// that carries the account key to a newly approved device. Five pure
// functions, no client handle, UNCONDITIONAL like the device-link door above —
// the store is product code on iOS, macOS and Android.
//
// Every failure is [`PEACHY_MLS_ERR_INVALID_ARGUMENT`] with a message. An open
// that fails because the key, the id, the approver or the device id is wrong,
// or because the bytes were altered, says "does not open" and nothing more
// specific: the tag cannot tell those apart and a caller should not try. The
// module header of `peachy_mls_core::account_store` says why the box
// authenticates the approver, which is what a wrapper author needs to know
// about where `approver_signing_key` may come from.

/// A fresh 32-byte account key from the platform CSPRNG. Freed with
/// [`peachy_mls_buffer_free`].
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_generate_account_key(out_key: *mut PeachyMlsBuffer) -> i32 {
    guard(|| {
        let key = Zeroizing::new(peachy_mls_core::generate_account_key()?);
        write_buffer(out_key, "out_key", key.to_vec())
    })
}

/// Seal `account_key` as a version-1 (X25519-only) box: `approver_seed` is
/// THIS device's 32-byte Ed25519 seed, `recipient_signing_key` the new
/// device's 32-byte Ed25519 public key, `device_id` its `devices.id`.
/// `out_box` receives exactly 93 bytes. Only a device with its own
/// server-approval switch on (`server_approval_allowed`) opens one: a device
/// a person approves takes only the version-3 box
/// ([`peachy_mls_account_key_seal_hybrid`]). For a server-run approver (a
/// test server, or the store-review login's anchor).
///
/// # Safety
/// See the module header. `device_id` must be a valid NUL-terminated string.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn peachy_mls_account_key_seal(
    approver_seed: *const u8,
    approver_seed_len: usize,
    recipient_signing_key: *const u8,
    recipient_signing_key_len: usize,
    device_id: *const c_char,
    account_key: *const u8,
    account_key_len: usize,
    out_box: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let approver_seed = slice_from(approver_seed, approver_seed_len, "approver_seed")?;
        let recipient_signing_key = slice_from(
            recipient_signing_key,
            recipient_signing_key_len,
            "recipient_signing_key",
        )?;
        let device_id = cstr_arg(device_id, "device_id")?;
        let account_key = slice_from(account_key, account_key_len, "account_key")?;
        let sealed = peachy_mls_core::account_key_seal(
            approver_seed,
            recipient_signing_key,
            device_id,
            account_key,
        )?;
        write_buffer(out_box, "out_box", sealed)
    })
}

/// Seal `account_key` for a new device that posted a link key: the
/// post-quantum version-3 box (`peachy_mls_core::account_key_seal_hybrid`).
/// `recipient_link_key` is the 1216-byte X-Wing key the waiting device posted,
/// which the caller MUST have checked with
/// [`peachy_mls_verify_device_link_kem`]. The rest are
/// [`peachy_mls_account_key_seal`]'s. `out_box` receives exactly 1213 bytes.
///
/// # Safety
/// See the module header. `device_id` must be a valid NUL-terminated string.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn peachy_mls_account_key_seal_hybrid(
    approver_seed: *const u8,
    approver_seed_len: usize,
    recipient_signing_key: *const u8,
    recipient_signing_key_len: usize,
    recipient_link_key: *const u8,
    recipient_link_key_len: usize,
    device_id: *const c_char,
    account_key: *const u8,
    account_key_len: usize,
    out_box: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let approver_seed = slice_from(approver_seed, approver_seed_len, "approver_seed")?;
        let recipient_signing_key = slice_from(
            recipient_signing_key,
            recipient_signing_key_len,
            "recipient_signing_key",
        )?;
        let recipient_link_key = slice_from(
            recipient_link_key,
            recipient_link_key_len,
            "recipient_link_key",
        )?;
        let device_id = cstr_arg(device_id, "device_id")?;
        let account_key = slice_from(account_key, account_key_len, "account_key")?;
        let sealed = peachy_mls_core::account_key_seal_hybrid(
            approver_seed,
            recipient_signing_key,
            recipient_link_key,
            device_id,
            account_key,
        )?;
        write_buffer(out_box, "out_box", sealed)
    })
}

/// THE NEW DEVICE'S DOOR for an account key
/// (`peachy_mls_core::account_key_accept_hybrid`): the version-3 box, and the
/// version-1 box only when `server_approval_allowed`. `link_key_seed` is the
/// seed of the link key this device posted (length 0 for none),
/// `confirmed_approver_key` the approver whose number the person picked on
/// this device (length 0 for none), and `server_approval_allowed` this
/// device's own switch, never set from anything the server says. The rest
/// are [`peachy_mls_account_key_open`]'s. `out_account_key` receives 32
/// bytes.
///
/// # Safety
/// See the module header. `device_id` must be a valid NUL-terminated string.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn peachy_mls_account_key_accept_hybrid(
    recipient_seed: *const u8,
    recipient_seed_len: usize,
    approver_signing_key: *const u8,
    approver_signing_key_len: usize,
    device_id: *const c_char,
    sealed_box: *const u8,
    sealed_box_len: usize,
    link_key_seed: *const u8,
    link_key_seed_len: usize,
    confirmed_approver_key: *const u8,
    confirmed_approver_key_len: usize,
    server_approval_allowed: bool,
    out_account_key: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let recipient_seed = slice_from(recipient_seed, recipient_seed_len, "recipient_seed")?;
        let approver_signing_key = slice_from(
            approver_signing_key,
            approver_signing_key_len,
            "approver_signing_key",
        )?;
        let device_id = cstr_arg(device_id, "device_id")?;
        let sealed_box = slice_from(sealed_box, sealed_box_len, "box")?;
        let link_key_seed = slice_from(link_key_seed, link_key_seed_len, "link_key_seed")?;
        let confirmed = slice_from(
            confirmed_approver_key,
            confirmed_approver_key_len,
            "confirmed_approver_key",
        )?;
        let key = Zeroizing::new(peachy_mls_core::account_key_accept_hybrid(
            recipient_seed,
            approver_signing_key,
            device_id,
            sealed_box,
            link_key_seed,
            confirmed,
            server_approval_allowed,
        )?);
        write_buffer(out_account_key, "out_account_key", key.to_vec())
    })
}

/// Open a version-1 account-key box with no check of who sealed it:
/// `recipient_seed` is THIS device's seed, `approver_signing_key` the
/// approving device's public key, and `device_id` this device's own
/// `devices.id`. `out_account_key` receives 32 bytes. A new device takes its
/// key through [`peachy_mls_account_key_accept_hybrid`], under the person's
/// confirmation of the approver's number; this is for tests and tools, and
/// works only in a build with the `fixture` feature. Every other build
/// refuses it with [`PEACHY_MLS_ERR_UNSUPPORTED`]: whoever lists the approver,
/// the server included, would pick the key it opens to. The symbol stays in
/// every build so that a wrapper links either way.
///
/// # Safety
/// See the module header. `device_id` must be a valid NUL-terminated string.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn peachy_mls_account_key_open(
    recipient_seed: *const u8,
    recipient_seed_len: usize,
    approver_signing_key: *const u8,
    approver_signing_key_len: usize,
    device_id: *const c_char,
    sealed_box: *const u8,
    sealed_box_len: usize,
    out_account_key: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let recipient_seed = slice_from(recipient_seed, recipient_seed_len, "recipient_seed")?;
        let approver_signing_key = slice_from(
            approver_signing_key,
            approver_signing_key_len,
            "approver_signing_key",
        )?;
        let device_id = cstr_arg(device_id, "device_id")?;
        let sealed_box = slice_from(sealed_box, sealed_box_len, "box")?;
        #[cfg(not(feature = "fixture"))]
        {
            let _ = (recipient_seed, approver_signing_key, device_id, sealed_box);
            let _ = out_account_key;
            Err(Error::Unsupported(
                "the unvouched account-key box opener is for tests and tools: take the key \
                 through peachy_mls_account_key_accept_hybrid",
            ))
        }
        #[cfg(feature = "fixture")]
        {
            let key = Zeroizing::new(peachy_mls_core::account_key_open(
                recipient_seed,
                approver_signing_key,
                device_id,
                sealed_box,
            )?);
            write_buffer(out_account_key, "out_account_key", key.to_vec())
        }
    })
}

/// Seal a history hand-off's 32-byte attachment `key` to the device it is
/// handed to: `recipient_signing_key` is that device's 32-byte Ed25519 public
/// key (the one this device just vouched for) and `device_id` its
/// `devices.id`. `out_box` receives exactly 93 bytes, the pointer's `kb`.
///
/// # Safety
/// See the module header. `device_id` must be a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_transfer_key_seal(
    recipient_signing_key: *const u8,
    recipient_signing_key_len: usize,
    device_id: *const c_char,
    key: *const u8,
    key_len: usize,
    out_box: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let recipient_signing_key = slice_from(
            recipient_signing_key,
            recipient_signing_key_len,
            "recipient_signing_key",
        )?;
        let device_id = cstr_arg(device_id, "device_id")?;
        let key = slice_from(key, key_len, "key")?;
        let sealed = peachy_mls_core::transfer_key_seal(recipient_signing_key, device_id, key)?;
        write_buffer(out_box, "out_box", sealed)
    })
}

/// Open a transfer-key box on the device it was sealed to: `recipient_seed`
/// is THIS device's 32-byte seed and `device_id` its own `devices.id`.
/// `out_key` receives the 32-byte attachment key. A box sealed to any other
/// device or row, or an account-key box, does not open.
///
/// # Safety
/// See the module header. `device_id` must be a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_transfer_key_open(
    recipient_seed: *const u8,
    recipient_seed_len: usize,
    device_id: *const c_char,
    sealed_box: *const u8,
    sealed_box_len: usize,
    out_key: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let recipient_seed = slice_from(recipient_seed, recipient_seed_len, "recipient_seed")?;
        let device_id = cstr_arg(device_id, "device_id")?;
        let sealed_box = slice_from(sealed_box, sealed_box_len, "box")?;
        let key = Zeroizing::new(peachy_mls_core::transfer_key_open(
            recipient_seed,
            device_id,
            sealed_box,
        )?);
        write_buffer(out_key, "out_key", key.to_vec())
    })
}

/// Seal `plaintext` (at most 65536 bytes; empty is fine) as the value stored
/// under the 16-byte `id`, with a fresh nonce. The manifest is sealed the same
/// way under sixteen zero bytes, and may be up to 360000 bytes.
///
/// # Safety
/// See the module header.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn peachy_mls_store_seal(
    account_key: *const u8,
    account_key_len: usize,
    id: *const u8,
    id_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    out_value: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let account_key = slice_from(account_key, account_key_len, "account_key")?;
        let id = slice_from(id, id_len, "id")?;
        let plaintext = slice_from(plaintext, plaintext_len, "plaintext")?;
        let value = peachy_mls_core::store_seal(account_key, id, plaintext)?;
        write_buffer(out_value, "out_value", value)
    })
}

/// Open a value [`peachy_mls_store_seal`] made under the same account key and
/// id. `out_plaintext` may come back EMPTY (a null `data` with `len` 0) — an
/// empty plaintext is a real answer.
///
/// # Safety
/// See the module header.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn peachy_mls_store_open(
    account_key: *const u8,
    account_key_len: usize,
    id: *const u8,
    id_len: usize,
    value: *const u8,
    value_len: usize,
    out_plaintext: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let account_key = slice_from(account_key, account_key_len, "account_key")?;
        let id = slice_from(id, id_len, "id")?;
        let value = slice_from(value, value_len, "value")?;
        let plaintext = peachy_mls_core::store_open(account_key, id, value)?;
        write_buffer(out_plaintext, "out_plaintext", plaintext)
    })
}

/// Seal a self-note under the account key and sign it as this device: format
/// 0x02, the domain "peachy self note v2". `sender_device_id` is this device's
/// own `devices.id`, `issued_at_ms` its clock in unix milliseconds, and
/// `device_seed` the 32-byte Ed25519 seed of the key that row carries.
///
/// # Safety
/// See the module header.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn peachy_mls_note_seal_signed(
    account_key: *const u8,
    account_key_len: usize,
    id: *const u8,
    id_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    sender_device_id: *const c_char,
    issued_at_ms: i64,
    device_seed: *const u8,
    device_seed_len: usize,
    out_value: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let account_key = slice_from(account_key, account_key_len, "account_key")?;
        let id = slice_from(id, id_len, "id")?;
        let plaintext = slice_from(plaintext, plaintext_len, "plaintext")?;
        let sender_device_id = cstr_arg(sender_device_id, "sender_device_id")?;
        let device_seed = slice_from(device_seed, device_seed_len, "device_seed")?;
        let value = peachy_mls_core::note_seal_signed(
            account_key,
            id,
            plaintext,
            sender_device_id,
            issued_at_ms,
            device_seed,
        )?;
        write_buffer(out_value, "out_value", value)
    })
}

/// The device a signed note SAYS sent it, as UTF-8 bytes in `out_sender`: what
/// the receiver looks up in its own device list before it calls
/// [`peachy_mls_note_open_signed`]. Refuses a version-1 note, which names no
/// sender.
///
/// # Safety
/// See the module header.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn peachy_mls_note_sender(
    account_key: *const u8,
    account_key_len: usize,
    id: *const u8,
    id_len: usize,
    value: *const u8,
    value_len: usize,
    out_sender: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let account_key = slice_from(account_key, account_key_len, "account_key")?;
        let id = slice_from(id, id_len, "id")?;
        let value = slice_from(value, value_len, "value")?;
        let sender = peachy_mls_core::note_sender(account_key, id, value)?;
        write_buffer(out_sender, "out_sender", sender.into_bytes())
    })
}

/// Open a signed note, believing it only when `sender_device_id` sent it and
/// signed it under `sender_signing_key` (the 32-byte key the receiver's own
/// device list gives that device), issued at most seven days before `now_ms`
/// and at most ten minutes after it.
///
/// # Safety
/// See the module header.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn peachy_mls_note_open_signed(
    account_key: *const u8,
    account_key_len: usize,
    id: *const u8,
    id_len: usize,
    value: *const u8,
    value_len: usize,
    sender_device_id: *const c_char,
    sender_signing_key: *const u8,
    sender_signing_key_len: usize,
    now_ms: i64,
    out_plaintext: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let account_key = slice_from(account_key, account_key_len, "account_key")?;
        let id = slice_from(id, id_len, "id")?;
        let value = slice_from(value, value_len, "value")?;
        let sender_device_id = cstr_arg(sender_device_id, "sender_device_id")?;
        let sender_signing_key = slice_from(
            sender_signing_key,
            sender_signing_key_len,
            "sender_signing_key",
        )?;
        let plaintext = peachy_mls_core::note_open_signed(
            account_key,
            id,
            value,
            sender_device_id,
            sender_signing_key,
            now_ms,
        )?;
        write_buffer(out_plaintext, "out_plaintext", plaintext)
    })
}

// ---- Groups ----------------------------------------------------------------

/// Create a group with this device as its only member.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_create(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
) -> i32 {
    guard(|| {
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        client.create_group(group_id)
    })
}

/// Join from a Welcome. `out_group_id` receives the id joined.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_join(
    client: *mut PeachyMlsClient,
    welcome: *const u8,
    welcome_len: usize,
    out_group_id: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        // Rule 5: a Welcome is single-use. Joining spends the key package it
        // was sealed to and creates a group, and a caller that got a status
        // code but no group id has no way to name what it just joined.
        require_out(out_group_id, "out_group_id")?;
        let client = client_mut(client)?;
        let welcome = slice_from(welcome, welcome_len, "welcome")?;
        let group_id = client.join_from_welcome(welcome)?;
        write_buffer(out_group_id, "out_group_id", group_id)
    })
}

/// The group id of the Welcome the last [`peachy_mls_group_join`] refused
/// with [`PEACHY_MLS_ERR_ALREADY_A_MEMBER`] because this device already held
/// an active group under that id, or EMPTY when there is none. Freed with
/// [`peachy_mls_buffer_free`].
///
/// Two seats under one id are a contest the group's head decides
/// (docs/delivery.md §Two seats under one group id): fetch the head
/// for the group's handle and hand it to
/// [`peachy_mls_group_join_contested_welcome`].
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_contested_welcome_id(
    client: *mut PeachyMlsClient,
    out_group_id: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let client = client_mut(client)?;
        let id = client.contested_welcome_group_id().unwrap_or_default();
        write_buffer(out_group_id, "out_group_id", id)
    })
}

/// Settle the contested Welcome against the group's head: the epoch and the
/// send-key verifier the delivery service holds for the group's handle. The
/// Welcome takes the seat, replacing the held group, only when the held group
/// is not at the head and the Welcome is; `out_group_id` then receives the id
/// joined. [`PEACHY_MLS_ERR_ALREADY_A_MEMBER`] keeps the held group; the
/// Welcome is gone either way, and [`PEACHY_MLS_ERR_INVALID_ARGUMENT`] means
/// there was none to settle.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_join_contested_welcome(
    client: *mut PeachyMlsClient,
    head_epoch: u64,
    head_verifier: *const u8,
    head_verifier_len: usize,
    out_group_id: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_group_id, "out_group_id")?;
        let client = client_mut(client)?;
        let verifier = slice_from(head_verifier, head_verifier_len, "head_verifier")?;
        let group_id = client.join_contested_welcome(head_epoch, verifier)?;
        write_buffer(out_group_id, "out_group_id", group_id)
    })
}

/// The group a Welcome is for, and the epoch it would seat this device at,
/// read without taking it: what a caller needs to fetch the group's head for
/// [`peachy_mls_group_join_at_head`]. Both are as the Welcome claims them,
/// unverified. Nothing is written; a one-time key package is still there.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_welcome_group(
    client: *mut PeachyMlsClient,
    welcome: *const u8,
    welcome_len: usize,
    out_group_id: *mut PeachyMlsBuffer,
    out_epoch: *mut u64,
) -> i32 {
    guard(|| {
        require_out(out_group_id, "out_group_id")?;
        require_out(out_epoch, "out_epoch")?;
        let client = client_mut(client)?;
        let welcome = slice_from(welcome, welcome_len, "welcome")?;
        let (group_id, epoch) = client.welcome_group(welcome)?;
        *out_epoch = epoch;
        write_buffer(out_group_id, "out_group_id", group_id)
    })
}

/// Join from a Welcome against the group's head: the epoch and the send-key
/// verifier the delivery service holds for the group's handle. The door the
/// apps take every Welcome through (docs/delivery.md §Two seats
/// under one group id). A Welcome above the head, or at its epoch under
/// another send key, is refused with [`PEACHY_MLS_ERR_ALREADY_A_MEMBER`]; at
/// the head it is taken and confirmed, replacing an active copy that is not
/// the head; below it, it is taken unconfirmed when no active copy is held.
/// [`PEACHY_MLS_ERR_SETTLE_FIRST`] puts the key package back: the same call
/// succeeds once the group's saved commit is settled. `out_group_id`
/// receives the id joined.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_join_at_head(
    client: *mut PeachyMlsClient,
    welcome: *const u8,
    welcome_len: usize,
    head_epoch: u64,
    head_verifier: *const u8,
    head_verifier_len: usize,
    out_group_id: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_group_id, "out_group_id")?;
        let client = client_mut(client)?;
        let welcome = slice_from(welcome, welcome_len, "welcome")?;
        let verifier = slice_from(head_verifier, head_verifier_len, "head_verifier")?;
        let group_id = client.join_from_welcome_at_head(welcome, head_epoch, verifier)?;
        write_buffer(out_group_id, "out_group_id", group_id)
    })
}

/// The `kept_from` of [`peachy_mls_group_join_at_head_logged`] when the
/// delivery service named no floor for the verifier log.
pub const PEACHY_MLS_NO_FLOOR: u64 = u64::MAX;

/// [`peachy_mls_group_join_at_head`], with the delivery service's
/// verifier-log answer for the Welcome's own epoch (`FetchVerifierAt`,
/// docs/delivery.md §FetchVerifierAt): the verifier logged there,
/// 32 bytes, or none (`logged_verifier_len` 0, the pointer may then be
/// null), and `kept_from`, the lowest epoch from which the log holds every
/// epoch up to the head ([`PEACHY_MLS_NO_FLOOR`] when the server named
/// none). A Welcome below the head whose send key hashes to the verifier is
/// taken and confirmed, as one at the head is; one whose send key does not,
/// or one at or above `kept_from` with no verifier, is refused with
/// [`PEACHY_MLS_ERR_ALREADY_A_MEMBER`]. A verifier of any other length counts
/// as none. Pass only an answer the server gave: a failed read holds the
/// Welcome.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_join_at_head_logged(
    client: *mut PeachyMlsClient,
    welcome: *const u8,
    welcome_len: usize,
    head_epoch: u64,
    head_verifier: *const u8,
    head_verifier_len: usize,
    logged_verifier: *const u8,
    logged_verifier_len: usize,
    kept_from: u64,
    out_group_id: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_group_id, "out_group_id")?;
        let client = client_mut(client)?;
        let welcome = slice_from(welcome, welcome_len, "welcome")?;
        let verifier = slice_from(head_verifier, head_verifier_len, "head_verifier")?;
        let logged = if logged_verifier_len == 0 {
            &[][..]
        } else {
            slice_from(logged_verifier, logged_verifier_len, "logged_verifier")?
        };
        let floor = (kept_from != PEACHY_MLS_NO_FLOOR).then_some(kept_from);
        let group_id = client
            .join_from_welcome_at_head_logged(welcome, head_epoch, verifier, logged, floor)?;
        write_buffer(out_group_id, "out_group_id", group_id)
    })
}

/// Hand the group's head, as the delivery service reports it, to the copy
/// this device holds: an active copy at the head's epoch under its send key
/// is confirmed, and a confirmed one at that epoch under another send key
/// lapses. An active copy no head has matched yet is confirmed by a head at
/// any of its last 64 epochs under its send key there, and contested by one
/// under another (the rejoin report then says `contested`); a head above
/// the copy, and a head below a copy a head matched once, change nothing.
/// `out_confirmed` receives whether the copy is confirmed now; false for a
/// group not held.
/// Only a confirmed copy's epochs raise the epoch mark. No head lowers the
/// mark, or takes away the roster a copy that matched a head once names to
/// the Welcome judge. Call it with every head read.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_confirm_head(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    head_epoch: u64,
    head_verifier: *const u8,
    head_verifier_len: usize,
    out_confirmed: *mut bool,
) -> i32 {
    guard(|| {
        require_out(out_confirmed, "out_confirmed")?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let verifier = slice_from(head_verifier, head_verifier_len, "head_verifier")?;
        *out_confirmed = client.confirm_head(group_id, head_epoch, verifier)?;
        Ok(())
    })
}

/// Whether the group's head, as the delivery service reports it, was ROLLED
/// BACK below the copy this device holds: an active copy past `head_epoch` on
/// which the group's own head once stood above `head_epoch`, and which held
/// that epoch under the send key `head_verifier` names when it is one of the
/// copy's last 64 epochs (below all of them, that the head stood above it is
/// enough only on a copy that has kept 64 epochs since its seat, in a group
/// no steward was ever named for on it). Such a head is no fork: the caller
/// keeps its copy, and neither forgets the group nor asks back in.
/// `out_rolled_back` receives false for a head at or above the copy, a group
/// not held, a head the group's own head never stood above on this copy, a
/// verifier of any length but 32, within the last 64 epochs one that differs
/// from the copy's own there, and below them any other head. Reads only.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_head_rolled_back(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    head_epoch: u64,
    head_verifier: *const u8,
    head_verifier_len: usize,
    out_rolled_back: *mut bool,
) -> i32 {
    guard(|| {
        require_out(out_rolled_back, "out_rolled_back")?;
        let client = client_mut(client)?;
        // Not from a group another process has moved past (§A store two
        // processes share): reloads only when the store moved.
        client.refresh_if_moved()?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let verifier = slice_from(head_verifier, head_verifier_len, "head_verifier")?;
        *out_rolled_back = client.head_rolled_back(group_id, head_epoch, verifier)?;
        Ok(())
    })
}

/// When this device last finished reading the group's head, in unix
/// milliseconds, as [`peachy_mls_group_note_head_read`] recorded it, into
/// `out_at_ms`: -1 when it never did for this copy, or the group is not
/// held. Kept in the group's own records and dropped with the group. Reads
/// only.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_last_head_read(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    out_at_ms: *mut i64,
) -> i32 {
    guard(|| {
        require_out(out_at_ms, "out_at_ms")?;
        let client = client_mut(client)?;
        client.refresh_if_moved()?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        *out_at_ms = client.last_head_read(group_id)?.unwrap_or(-1);
        Ok(())
    })
}

/// Record that a read of the group's head finished at `at_ms` (unix
/// milliseconds), whatever it answered. Refused for a group not held.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_note_head_read(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    at_ms: i64,
) -> i32 {
    guard(|| {
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        client.note_head_read(group_id, at_ms)?;
        Ok(())
    })
}

// ---- Group recovery -----------------------------------------------------------
//
// The recovery driver (`peachy_mls_core::recovery`, docs/mls-core.md §Group
// recovery): what to do with a copy of a group that fell behind its head or
// forked off it. The caller reads heads and sends seat asks; the driver
// decides.

/// [`peachy_mls_group_recovery_judge`]: nothing to do.
pub const PEACHY_MLS_RECOVERY_IN_STEP: u32 = 0;
/// The head is ahead: catch up from the mailbox. If nothing carries the copy
/// up, the next readings strand it.
pub const PEACHY_MLS_RECOVERY_BEHIND: u32 = 1;
/// The server moved its head back below a copy that came through it: keep
/// the copy.
pub const PEACHY_MLS_RECOVERY_ROLLED_BACK: u32 = 2;
/// The group is held for its steward: every rejoin waits.
pub const PEACHY_MLS_RECOVERY_HELD: u32 = 3;
/// The driver just held the group for its steward: fetch the missing commit
/// and read the head again at the hold's cap.
pub const PEACHY_MLS_RECOVERY_HOLD_ENTERED: u32 = 4;
/// Forked: forget the group and ask back in.
pub const PEACHY_MLS_RECOVERY_REJOIN_FORKED: u32 = 5;
/// Behind with nothing to carry it up: forget the group and ask back in.
pub const PEACHY_MLS_RECOVERY_REJOIN_STUCK: u32 = 6;
/// Behind after a lost mailbox: forget the group and ask back in.
pub const PEACHY_MLS_RECOVERY_REJOIN_LOST: u32 = 7;
/// A fork rejoin is due and the last one was too recent: wait.
pub const PEACHY_MLS_RECOVERY_BACKOFF: u32 = 8;
/// No active copy of the group here.
pub const PEACHY_MLS_RECOVERY_NO_COPY: u32 = 9;
/// A head below the copy from a read that may predate it: read a fresh one
/// and judge again.
pub const PEACHY_MLS_RECOVERY_READ_AGAIN: u32 = 10;
/// [`peachy_mls_group_recovery_begin`]: read the head, then judge it.
pub const PEACHY_MLS_RECOVERY_READ_HEAD: u32 = 11;
/// A rejoin is due and the group holds a saved commit: read the verifier the
/// server logged at the copy's epoch plus one (`FetchVerifierAt`), hand it to
/// [`peachy_mls_group_settle_saved_commit`] as the head at that epoch, then
/// read the head again. No backoff was spent.
pub const PEACHY_MLS_RECOVERY_SETTLE_FIRST: u32 = 12;

/// [`peachy_mls_group_recovery_judge`]'s `kind`: the fork check (a refused
/// commit of this device's own, messages that would not open, a second
/// reading a drain owes, a stale open, the caller's own schedule).
pub const PEACHY_MLS_HEAD_READ_CHECK: u32 = 0;
/// The fork check, when a message sealed past the copy is known
/// ([`PEACHY_MLS_ERR_STALE_COPY`]): `behind` strands at once.
pub const PEACHY_MLS_HEAD_READ_SEALED_AHEAD: u32 = 1;
/// After a lost mailbox, an envelope that opened for no group, or a hold
/// that reached its cap: a copy behind the head rejoins at once; nothing
/// else is judged.
pub const PEACHY_MLS_HEAD_READ_LOST: u32 = 2;

/// BEGIN A HEAD READ of the group, before the head is fetched. `out_step`
/// receives [`PEACHY_MLS_RECOVERY_READ_HEAD`] (fetch the head, then
/// [`peachy_mls_group_recovery_judge`]), [`PEACHY_MLS_RECOVERY_HELD`] (held
/// for its steward: read nothing) or [`PEACHY_MLS_RECOVERY_NO_COPY`].
/// Snapshots the copy's epoch, verifier and last complete drain, in memory.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_recovery_begin(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    out_step: *mut u32,
) -> i32 {
    guard(|| {
        require_out(out_step, "out_step")?;
        let client = client_mut(client)?;
        client.refresh_if_moved()?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        *out_step = client.recovery_begin(group_id)?.code();
        Ok(())
    })
}

/// JUDGE A HEAD read since [`peachy_mls_group_recovery_begin`]: the fork
/// check, the stuck-behind count, the lost-mailbox rule, the hold and the
/// fork backoff in one answer. `kind` is one of `PEACHY_MLS_HEAD_READ_*`.
/// `has_head` false: the server holds no head (the epoch and verifier are
/// not read; the verifier may be null). `fresh`: the read began after the
/// begin; a head below the copy from an older read answers
/// [`PEACHY_MLS_RECOVERY_READ_AGAIN`]. `now_ms` is unix milliseconds.
///
/// `out_step` receives one of `PEACHY_MLS_RECOVERY_*`. On a `REJOIN_*` step,
/// read the group's leaves ([`peachy_mls_group_roster`]), forget it
/// ([`peachy_mls_group_forget`]) and send those leaves a sealed seat ask
/// (envelope kind 3; docs/delivery.md §Rejoin with a sealed seat
/// ask). The head is handed to [`peachy_mls_group_confirm_head`] on the
/// way: take any rejoin report after. [`PEACHY_MLS_ERR_INVALID_ARGUMENT`]
/// with no begin first, or an unknown `kind`.
///
/// # Safety
/// See the module header.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn peachy_mls_group_recovery_judge(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    kind: u32,
    has_head: bool,
    head_epoch: u64,
    head_verifier: *const u8,
    head_verifier_len: usize,
    fresh: bool,
    now_ms: i64,
    out_step: *mut u32,
) -> i32 {
    guard(|| {
        require_out(out_step, "out_step")?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let kind = peachy_mls_core::HeadReadKind::from_u32(kind)
            .ok_or_else(|| Error::InvalidArgument(format!("unknown head read kind {kind}")))?;
        let head = if has_head {
            let verifier = if head_verifier.is_null() && head_verifier_len == 0 {
                &[][..]
            } else {
                slice_from(head_verifier, head_verifier_len, "head_verifier")?
            };
            Some(peachy_mls_core::HeadReading {
                epoch: head_epoch,
                verifier: verifier.to_vec(),
            })
        } else {
            None
        };
        *out_step = client
            .recovery_judge(group_id, kind, head.as_ref(), fresh, now_ms)?
            .code();
        Ok(())
    })
}

/// Whether to read the group's head over messages (or a commit) that would
/// not open: at most once a minute per group, except that one sealed past
/// the copy (`sealed_ahead`, as [`PEACHY_MLS_ERR_STALE_COPY`] says) is let
/// through once when the last read did not know of one. True counts as
/// that read. In memory.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_recovery_read_due(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    sealed_ahead: bool,
    now_ms: i64,
    out_due: *mut bool,
) -> i32 {
    guard(|| {
        require_out(out_due, "out_due")?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        *out_due = client.recovery_read_due(group_id, sealed_ahead, now_ms);
        Ok(())
    })
}

/// A MAILBOX DRAIN THAT BEGAN AT `started_at_ms` RAN TO THE END (every page
/// fetched, nothing held back). `evidence` false: its first page came on the
/// stream, read before the drain began. `out_group_ids` is a byte list (a
/// u32 big-endian count, then each id as a u32 big-endian length and its
/// bytes): the groups owed a second head reading now
/// ([`PEACHY_MLS_HEAD_READ_CHECK`]), each handed out once. Freed with
/// [`peachy_mls_buffer_free`].
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_recovery_drain_complete(
    client: *mut PeachyMlsClient,
    started_at_ms: i64,
    evidence: bool,
    now_ms: i64,
    out_group_ids: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_group_ids, "out_group_ids")?;
        let client = client_mut(client)?;
        let due = client.recovery_drain_complete(started_at_ms, evidence, now_ms);
        write_buffer(out_group_ids, "out_group_ids", encode_byte_list(&due))
    })
}

/// Add a member from their published key package.
///
/// `out_commit` is for every existing member; `out_welcome` is for the person
/// being added. Both are always written on success, though a Welcome can be
/// empty in shapes that do not produce one.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_add_member(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    key_package: *const u8,
    key_package_len: usize,
    out_commit: *mut PeachyMlsBuffer,
    out_welcome: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        if out_commit.is_null() {
            return Err(null_argument("out_commit"));
        }
        if out_welcome.is_null() {
            return Err(null_argument("out_welcome"));
        }
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let key_package = slice_from(key_package, key_package_len, "key_package")?;
        let bundle = client.add_member(group_id, key_package)?;
        *out_commit = PeachyMlsBuffer::from_vec(bundle.commit);
        *out_welcome = PeachyMlsBuffer::from_vec(bundle.welcome.unwrap_or_default());
        Ok(())
    })
}

/// [`peachy_mls_group_add_member`] for a rejoin's seat ask whose device holds
/// no leaf, after [`peachy_mls_verify_join_request`] accepted it: the ask's
/// membership is judged again, with the same `pending_actors` (a string
/// list, as that door takes it), on the store this add commits on, so a
/// person another process removed after the verdict is not put back. A
/// refusal is an error naming the verdict, and nothing is staged.
///
/// # Safety
/// See the module header. `pending_actors` must be NULL with length 0 or
/// `pending_actors_len` readable bytes.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn peachy_mls_group_add_member_for_ask(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    key_package: *const u8,
    key_package_len: usize,
    pending_actors: *const u8,
    pending_actors_len: usize,
    out_commit: *mut PeachyMlsBuffer,
    out_welcome: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        if out_commit.is_null() {
            return Err(null_argument("out_commit"));
        }
        if out_welcome.is_null() {
            return Err(null_argument("out_welcome"));
        }
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let key_package = slice_from(key_package, key_package_len, "key_package")?;
        let pending_bytes: &[u8] = if pending_actors.is_null() && pending_actors_len == 0 {
            &[]
        } else {
            slice_from(pending_actors, pending_actors_len, "pending_actors")?
        };
        let pending_owned = decode_string_list(pending_bytes, "pending_actors")?;
        let pending: Vec<&str> = pending_owned.iter().map(String::as_str).collect();
        let bundle = client.add_member_for_ask(group_id, key_package, &pending)?;
        *out_commit = PeachyMlsBuffer::from_vec(bundle.commit);
        *out_welcome = PeachyMlsBuffer::from_vec(bundle.welcome.unwrap_or_default());
        Ok(())
    })
}

/// Seat every device at a founding in ONE commit that names nobody
/// (docs/delivery.md §Founding a conversation). `key_packages` is a
/// byte list (a u32 big-endian count, then each package as a u32 big-endian
/// length and its bytes); `own_key_package` is a package of THIS device the
/// founding fetched like everyone else's, which the Welcome seats too. Send
/// `out_welcome` to every device added and to this one, and submit
/// `out_commit` with no recipients. [`peachy_mls_founding_seats`] says how
/// many devices one founding seats.
///
/// # Safety
/// See the module header.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn peachy_mls_group_seat_founding(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    key_packages: *const u8,
    key_packages_len: usize,
    own_key_package: *const u8,
    own_key_package_len: usize,
    out_commit: *mut PeachyMlsBuffer,
    out_welcome: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        if out_commit.is_null() {
            return Err(null_argument("out_commit"));
        }
        if out_welcome.is_null() {
            return Err(null_argument("out_welcome"));
        }
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let packages = decode_byte_list(
            slice_from(key_packages, key_packages_len, "key_packages")?,
            "key_packages",
            "byte",
        )?;
        let own = slice_from(own_key_package, own_key_package_len, "own_key_package")?;
        let bundle = client.seat_founding(group_id, &packages, own)?;
        *out_commit = PeachyMlsBuffer::from_vec(bundle.commit);
        *out_welcome = PeachyMlsBuffer::from_vec(bundle.welcome.unwrap_or_default());
        Ok(())
    })
}

/// The packages a founding leaves out: the index in `key_packages` (the
/// byte list [`peachy_mls_group_seat_founding`] takes) of each one it would
/// refuse, ascending, written into `out_refusals` as u32 big-endian values,
/// four bytes each (empty when none). Changes nothing stored: it builds the
/// founding commit in memory and drops it. The caller seats everybody else in
/// the founding and offers those devices ordinary adds once it is merged
/// (docs/delivery.md §Founding a conversation).
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_founding_refusals(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    key_packages: *const u8,
    key_packages_len: usize,
    out_refusals: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        if out_refusals.is_null() {
            return Err(null_argument("out_refusals"));
        }
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let packages = decode_byte_list(
            slice_from(key_packages, key_packages_len, "key_packages")?,
            "key_packages",
            "byte",
        )?;
        let refused = client.founding_refusals(group_id, &packages)?;
        let bytes = refused.iter().flat_map(|i| i.to_be_bytes()).collect();
        write_buffer(out_refusals, "out_refusals", bytes)
    })
}

/// How many devices, the founder's own included, one founding commit seats
/// ([`peachy_mls_group_seat_founding`]).
#[no_mangle]
pub extern "C" fn peachy_mls_founding_seats() -> u32 {
    peachy_mls_core::founding::FOUNDING_MAX_SEATS as u32
}

/// Remove the member at `leaf_index`, whose leaf key is `expected_leaf_key`.
/// Use [`peachy_mls_group_member`] to find the index and the leaf key, both
/// from the same entry: a leaf another commit emptied and refilled since that
/// read no longer matches, and the removal is refused (no such member) with
/// nothing staged, rather than removing whoever moved in.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_remove_member(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    leaf_index: u32,
    expected_leaf_key: *const u8,
    expected_leaf_key_len: usize,
    out_commit: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        // Rule 5: this STAGES a commit. Losing the bytes leaves the group
        // holding a pending commit nothing can submit and nothing can resolve.
        require_out(out_commit, "out_commit")?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let expected_leaf_key = slice_from(
            expected_leaf_key,
            expected_leaf_key_len,
            "expected_leaf_key",
        )?;
        let bundle = client.remove_member(group_id, leaf_index, expected_leaf_key)?;
        write_buffer(out_commit, "out_commit", bundle.commit)
    })
}

/// LEAVE: propose the removal of the leaf at `leaf_index`, one of this
/// device's own person's leaves (its own included). A member cannot commit
/// its own removal, so a person leaving proposes each of their leaves and
/// sends each proposal to the group as an ordinary message; another member's
/// device commits them ([`peachy_mls_group_commit_proposed_leaves`]).
/// [`peachy_mls_group_begin_leave`] does all of it and keeps proposing until
/// the leave takes. docs/sealed-messages.md §Leaving.
///
/// Not a commit: nothing is staged, and `out_proposal` is the message to
/// send. Refused when `leaf_index` is another person's.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_propose_leave(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    leaf_index: u32,
    out_proposal: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_proposal, "out_proposal")?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let proposal = client.propose_leave(group_id, leaf_index)?;
        write_buffer(out_proposal, "out_proposal", proposal)
    })
}

/// Commit the LEAVES this device holds: one commit naming every leave queued
/// through the message door that is not this device's own person's.
/// `out_commit` is EMPTY when there is none to commit, and then nothing is
/// staged; otherwise the commit is staged like any other (submit, then merge
/// or clear). Once carried commits are sent, the commit carries the
/// proposals it names (`mls/core/src/carried_commit.rs`); submit it as it is.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_commit_proposed_leaves(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    out_commit: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        // Rule 5: when it is not empty, this stages a commit.
        require_out(out_commit, "out_commit")?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let commit = client
            .commit_proposed_leaves(group_id)?
            .map(|bundle| bundle.commit)
            .unwrap_or_default();
        write_buffer(out_commit, "out_commit", commit)
    })
}

/// LEAVE A GROUP UNTIL IT TAKES: propose the removal of every leaf of this
/// device's own person and keep the group as a LEAVING stub, which nothing
/// but the leave reads (`Client::begin_leave`;
/// docs/sealed-messages.md §Leaving). `out_proposals` is a byte
/// list (a u32 big-endian count, then each item as a u32 big-endian length
/// and its bytes, as [`encode_string_list`] lays strings out): each a
/// proposal to send to the group as a message (envelope kind 1, not urgent).
/// EMPTY (count 0) when the group is already being left, or when nobody but
/// this person holds a leaf, in which case the group is forgotten at once.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_begin_leave(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    out_proposals: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        // The proposals are the leave: losing them leaves a stub proposing
        // nothing until the group's next commit.
        require_out(out_proposals, "out_proposals")?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let proposals = client.begin_leave(group_id)?;
        write_buffer(out_proposals, "out_proposals", encode_byte_list(&proposals))
    })
}

/// Whether this device is LEAVING the group
/// ([`peachy_mls_group_begin_leave`]): hand each commit entry of it to
/// [`peachy_mls_group_follow_leave`], drop every other entry of it unread,
/// and show nothing of it.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_is_leaving(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    out_leaving: *mut bool,
) -> i32 {
    guard(|| {
        if out_leaving.is_null() {
            return Err(null_argument("out_leaving"));
        }
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        *out_leaving = client.is_leaving(group_id);
        Ok(())
    })
}

/// Who a leave's proposals go to (`Client::leave_recipients`): a string list
/// (as [`encode_string_list`] lays it out) of PAIRS, actor id then device id,
/// one pair per identified leaf of a group this device is LEAVING, its own
/// included. Refused (`NoSuchGroup`) for a group it is not leaving, whose
/// roster the member doors read.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_leave_recipients(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    out_pairs: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_pairs, "out_pairs")?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let pairs: Vec<String> = client
            .leave_recipients(group_id)?
            .into_iter()
            .flat_map(|(actor, device)| [actor, device])
            .collect();
        write_buffer(out_pairs, "out_pairs", encode_string_list(&pairs))
    })
}

/// Follow a group this device is LEAVING through one commit entry (raw or
/// carried, as the commit door takes it): `out_proposals` is a byte list, as
/// [`peachy_mls_group_begin_leave`] writes it, of the proposals to send
/// again, EMPTY when there are none (the leave took and the group is gone,
/// it was proposed at this epoch already, or the entry changed nothing).
/// `Client::follow_leave` says which. Only a store failure is an error: hold
/// the entry and try again.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_follow_leave(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    message: *const u8,
    message_len: usize,
    out_proposals: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_proposals, "out_proposals")?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let message = slice_from(message, message_len, "message")?;
        let proposals = client.follow_leave(group_id, message)?;
        write_buffer(out_proposals, "out_proposals", encode_byte_list(&proposals))
    })
}

/// Replace the leaf at `leaf_index` with a fresh key package, in ONE commit.
///
/// THE REJOIN, seen from a member that is still awake
/// (docs/delivery.md §The client contract on `behind_retention`).
/// A device that slept past the delivery service's retention window cannot
/// catch up and cannot act in the group; the recovery is that some member who
/// IS current removes its stale leaf and adds it back from a fresh key
/// package, in one commit, which mints the Welcome it rejoins on.
///
/// Shaped exactly like [`peachy_mls_group_add_member`] and for the same
/// reason: both out-parameters are always written on success, and the Welcome
/// is the whole point here — a replace with no Welcome to hand over is a
/// member removed and not re-added.
///
/// Refused before anything is built when the key package belongs to a
/// different actor than the leaf it would replace, when `leaf_index` is the
/// caller's own leaf, and when nobody occupies `leaf_index`. Those are the
/// core's refusals, not this layer's.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_replace_member(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    leaf_index: u32,
    key_package: *const u8,
    key_package_len: usize,
    out_commit: *mut PeachyMlsBuffer,
    out_welcome: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        if out_commit.is_null() {
            return Err(null_argument("out_commit"));
        }
        if out_welcome.is_null() {
            return Err(null_argument("out_welcome"));
        }
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let key_package = slice_from(key_package, key_package_len, "key_package")?;
        let bundle = client.replace_member(group_id, leaf_index, key_package)?;
        *out_commit = PeachyMlsBuffer::from_vec(bundle.commit);
        *out_welcome = PeachyMlsBuffer::from_vec(bundle.welcome.unwrap_or_default());
        Ok(())
    })
}

/// Reseat a person whose every device is gone (`Client::reseat_person`):
/// remove the `leaf_count` leaves at `leaf_indexes`, which must be every leaf
/// of one person, and add `key_package`, a new device of that same person
/// carrying an account's signature, in ONE commit. The one way a person's
/// last leaf leaves a group without the account's signed revocation or a
/// credential past its grace; a new account key shows every member that
/// person's security code changing. docs/identity.md §Revocation
/// reaches a seated leaf through the roster.
///
/// Shaped like [`peachy_mls_group_replace_member`]: both out-parameters are
/// written on success, and the Welcome is the point. Staged, not merged.
///
/// # Safety
/// See the module header. `leaf_indexes` points at `leaf_count` readable
/// `uint32_t`s.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_reseat_person(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    leaf_indexes: *const u32,
    leaf_count: usize,
    key_package: *const u8,
    key_package_len: usize,
    out_commit: *mut PeachyMlsBuffer,
    out_welcome: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_commit, "out_commit")?;
        require_out(out_welcome, "out_welcome")?;
        if leaf_indexes.is_null() || leaf_count == 0 {
            return Err(null_argument("leaf_indexes"));
        }
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let key_package = slice_from(key_package, key_package_len, "key_package")?;
        let leaves = std::slice::from_raw_parts(leaf_indexes, leaf_count);
        let bundle = client.reseat_person(group_id, leaves, key_package)?;
        *out_commit = PeachyMlsBuffer::from_vec(bundle.commit);
        *out_welcome = PeachyMlsBuffer::from_vec(bundle.welcome.unwrap_or_default());
        Ok(())
    })
}

/// Rotate this device's leaf key and commit it.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_self_update(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    out_commit: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        // Rule 5: as for `remove_member`, this stages a commit.
        require_out(out_commit, "out_commit")?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let bundle = client.self_update(group_id)?;
        write_buffer(out_commit, "out_commit", bundle.commit)
    })
}

// ---- Refreshing this device's leaf credential ------------------------------
//
// docs/identity.md §Refreshing a seated leaf. A leaf carries the
// credential its device held when the leaf was made, every receiver checks it
// on every message, and it lives thirty days. These four are how a fresh
// credential from `RegisterDevice` reaches a leaf that is already seated.

/// Hand this client a newer credential for the SAME device, in place — for a
/// process that got a fresh one from `RegisterDevice` without rebuilding the
/// client. Refused (and the old one kept) unless it is for this client's
/// actor, device and key, of the same kind, currently valid, and no older.
///
/// `own_account_identity` / `own_account_identity_len`: the account identity
/// key this device now derives from the account key it holds, as
/// [`peachy_mls_client_open`] takes it — the certificate has just arrived —
/// or null and 0 to keep the one the client holds. A credential certified
/// under any other key, or certified at all while the client holds no key, is
/// refused, `not_own_account_key`.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_client_update_credential(
    client: *mut PeachyMlsClient,
    credential: *const u8,
    credential_len: usize,
    own_account_identity: *const u8,
    own_account_identity_len: usize,
) -> i32 {
    guard(|| {
        let client = client_mut(client)?;
        let credential = slice_from(credential, credential_len, "credential")?;
        let own = optional_key32(
            own_account_identity,
            own_account_identity_len,
            "own_account_identity",
        )?;
        client.update_credential(credential, own)?;
        Ok(())
    })
}

/// When the credential on this device's OWN leaf in the group expires, in Unix
/// seconds — the leaf's, which is what every other member checks, not the
/// client's. A lapsed leaf answers with its past `exp`, not an error.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_own_leaf_credential_expires_at(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    out_expires_at: *mut i64,
) -> i32 {
    guard(|| {
        require_out(out_expires_at, "out_expires_at")?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        *out_expires_at = client.own_leaf_credential_expires_at(group_id)?;
        Ok(())
    })
}

/// Whether this device should call [`peachy_mls_group_refresh_credential`] in
/// this group now: its leaf's credential is within ten days of `exp` (or past
/// it), this client holds a fresher one, it is an active member, and nothing
/// is staged. The rule lives in
/// the core so four clients cannot disagree about it.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_credential_refresh_due(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    out_due: *mut bool,
) -> i32 {
    guard(|| {
        require_out(out_due, "out_due")?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        *out_due = client.credential_refresh_due(group_id)?;
        Ok(())
    })
}

/// Whether this device's leaf in the group is inside the refresh window
/// (or already lapsed) — whatever credential the client holds. True while
/// `peachy_mls_group_credential_refresh_due` is false is the cue to fetch a
/// fresh credential (RegisterDevice) and hand it to
/// `peachy_mls_client_update_credential` before asking again.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_leaf_credential_expiring(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    out_expiring: *mut bool,
) -> i32 {
    guard(|| {
        require_out(out_expiring, "out_expiring")?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        *out_expiring = client.leaf_credential_expiring(group_id)?;
        Ok(())
    })
}

/// Whether this device's leaf lapsed longer ago than the grace every member
/// allows (56 days), so that nothing it sends — a renewal included — is
/// accepted any more. True means: stop claiming the conversation is sealed
/// and ask for a seat (`RequestGroupRejoin`); never build a renewal, which the
/// delivery service would accept and every member refuse.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_leaf_credential_past_grace(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    out_past_grace: *mut bool,
) -> i32 {
    guard(|| {
        require_out(out_past_grace, "out_past_grace")?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        *out_past_grace = client.leaf_credential_past_grace(group_id)?;
        Ok(())
    })
}

/// Commit a self-update whose new leaf carries this client's current
/// credential. Same actor, device and signing key or no commit
/// ([`PEACHY_MLS_ERR_POLICY`] with `update_of_another_leaf`), and
/// refused when the credential is no fresher than the leaf's.
///
/// **This STAGES a commit**, like `peachy_mls_group_self_update`: submit the
/// bytes, then call exactly one of merge and clear. A renewal never carries a
/// Welcome.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_refresh_credential(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    out_commit: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_commit, "out_commit")?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let bundle = client.refresh_credential(group_id)?;
        write_buffer(out_commit, "out_commit", bundle.commit)
    })
}

// ---- The group's name and photo ---------------------------------------------

/// The group's own name-and-photo value (`peachy_group_meta`), read out of the
/// group's context (docs/sealed-messages.md §The name is in the group).
///
/// `out_meta` receives the value's bytes — the client format governed by
/// `mls/fixtures/formats/group-meta.json`, returned unparsed — or an
/// EMPTY buffer when nobody has set one. A set value is never empty
/// ([`peachy_mls_group_set_meta`] refuses that), so empty means absent.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_meta(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    out_meta: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_meta, "out_meta")?;
        let client = client_mut(client)?;
        // Not from a group another process has moved past (§A store two
        // processes share): reloads only when the store moved.
        client.refresh_if_moved()?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let value = client.group_meta(group_id)?.unwrap_or_default();
        write_buffer(out_meta, "out_meta", value)
    })
}

// ---- Handles and envelopes (member-rostered conversations) -----------------

/// A conversation's handle: `SHA-256("peachy handle v1" ‖ group_id)`, 32
/// bytes into `out_handle`. What the server keys a member-rostered
/// conversation by (docs/delivery.md §Handles and sender-addressed
/// delivery). Needs no client.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_handle(
    group_id: *const u8,
    group_id_len: usize,
    out_handle: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_handle, "out_handle")?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let handle = peachy_mls_core::envelope::group_handle(group_id)?;
        write_buffer(out_handle, "out_handle", handle.to_vec())
    })
}

/// Wrap `inner`, a seat ask (`kind` 3) or a link preview (`kind` 5), in the
/// envelope that hides which conversation it belongs to, as version 2. Needs
/// no client: the group id is the key, and whoever opens these holds no
/// epoch of the group. Any other kind is refused with
/// [`PEACHY_MLS_ERR_INVALID_ARGUMENT`]: a message, commit, typing frame or
/// call signal is sealed by [`peachy_mls_client_seal_envelope`], by the
/// group's epoch, so a removed member or a link holder cannot open it.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_seal_envelope(
    group_id: *const u8,
    group_id_len: usize,
    kind: u8,
    inner: *const u8,
    inner_len: usize,
    out_envelope: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_envelope, "out_envelope")?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let inner = slice_from(inner, inner_len, "inner")?;
        let sealed = peachy_mls_core::envelope::seal_envelope(group_id, kind, inner)?;
        write_buffer(out_envelope, "out_envelope", sealed)
    })
}

/// Wrap `inner` (kind 1 to 6) as an envelope of `group_id`, a group this
/// client holds (`Client::seal_envelope` in the core). A message, commit,
/// typing frame or call signal is sealed as version 3, under the epoch the
/// inner message was made in (a typing frame or a call signal: the epoch the
/// copy is at). The only door for them; none is ever sealed by the group id:
/// - a message or commit made at an epoch this copy no longer keeps:
///   [`PEACHY_MLS_ERR_STALE_COPY`]. Encrypt the message again at the current
///   epoch and seal that; never resend the old bytes;
/// - from a copy no longer in the group: [`PEACHY_MLS_ERR_NOT_A_MEMBER`];
/// - for a group this client does not hold: [`PEACHY_MLS_ERR_NO_SUCH_GROUP`].
///
/// A seat ask and a link preview come out as version 2, keyed by the group
/// id, as from [`peachy_mls_seal_envelope`].
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_client_seal_envelope(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    kind: u8,
    inner: *const u8,
    inner_len: usize,
    out_envelope: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_envelope, "out_envelope")?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let inner = slice_from(inner, inner_len, "inner")?;
        let sealed = client.seal_envelope(group_id, kind, inner)?;
        write_buffer(out_envelope, "out_envelope", sealed)
    })
}

/// Open `envelope` as `group_id`'s, with no client: a group link's preview
/// (kind 5, docs/sealed-messages.md §The preview) read by somebody who holds the
/// link and not the group. When it does not open — wrong group, tampered,
/// not an envelope — `out_kind` is 0 and `out_inner` is empty; that is not an
/// error.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_open_envelope_for(
    group_id: *const u8,
    group_id_len: usize,
    envelope: *const u8,
    envelope_len: usize,
    out_kind: *mut u8,
    out_inner: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_inner, "out_inner")?;
        require_out(out_kind, "out_kind")?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let envelope = slice_from(envelope, envelope_len, "envelope")?;
        let (kind, inner) = match peachy_mls_core::envelope::open_envelope_for(group_id, envelope) {
            Ok(opened) => (opened.kind, opened.inner),
            Err(_) => (0, Vec::new()),
        };
        *out_kind = kind;
        write_buffer(out_inner, "out_inner", inner)
    })
}

/// Open an envelope against every group this client holds.
///
/// On a match, `out_group_id` receives the group id, `out_kind` the kind and
/// `out_inner` the inner bytes. When no group here opens it — a conversation
/// this device left, or bytes that are no envelope — `out_group_id` is EMPTY
/// and `out_kind` is 0; that is not an error.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_open_envelope(
    client: *mut PeachyMlsClient,
    envelope: *const u8,
    envelope_len: usize,
    out_group_id: *mut PeachyMlsBuffer,
    out_kind: *mut u8,
    out_inner: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_group_id, "out_group_id")?;
        require_out(out_inner, "out_inner")?;
        require_out(out_kind, "out_kind")?;
        let client = client_mut(client)?;
        let envelope = slice_from(envelope, envelope_len, "envelope")?;
        let (gid, kind, inner) = match client.open_envelope(envelope)? {
            Some(opened) => (opened.group_id, opened.kind, opened.inner),
            None => (Vec::new(), 0, Vec::new()),
        };
        *out_kind = kind;
        write_buffer(out_group_id, "out_group_id", gid)?;
        write_buffer(out_inner, "out_inner", inner)
    })
}

/// Keep a version 3 envelope that opened for no group here, so that it
/// opens once this device holds the epoch it was sealed at: a copy that
/// fell behind or forked meets these until a member returns its seat, and
/// that Welcome hands back the epochs it missed. Call it for every envelope
/// [`peachy_mls_open_envelope`] did not open, before acknowledging it.
///
/// `id` (UTF-8, NUL-terminated), `mailbox_kind` and `received_at_ms` are
/// the mailbox's own, handed back by [`peachy_mls_next_reopenable`].
/// `out_held` is true when it was kept: not for an envelope that is no
/// version 3 envelope, that opens now, or whose id is held already.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_hold_envelope(
    client: *mut PeachyMlsClient,
    mailbox_kind: u8,
    id: *const c_char,
    received_at_ms: u64,
    envelope: *const u8,
    envelope_len: usize,
    out_held: *mut bool,
) -> i32 {
    guard(|| {
        require_out(out_held, "out_held")?;
        let client = client_mut(client)?;
        let id = cstr_arg(id, "id")?;
        let envelope = slice_from(envelope, envelope_len, "envelope")?;
        *out_held = client.hold_envelope(mailbox_kind, id, received_at_ms, envelope)?;
        Ok(())
    })
}

/// [`peachy_mls_hold_envelope`], with the device seal the mailbox handed
/// over beside the envelope (`MailboxEnvelope.device_seal`; empty, with a
/// non-null pointer, for none). A seal that opens for this device names the
/// group, the sender and the epoch secret, so the envelope is handed out by
/// [`peachy_mls_next_reopenable`] once this device is back in that group,
/// or before the hold would drop it, with no other member in the path.
///
/// `out_held`: `0` not kept, `1` kept (acknowledge it either way), or `2`
/// FULL: the hold on device seals is at its ceiling, and the envelope is
/// kept for now without its seal. Stop the page there, unacknowledged, take
/// what [`peachy_mls_next_reopenable`] hands out through, and drain again:
/// delivered again once that made room, it is held on its seal.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_hold_envelope_sealed(
    client: *mut PeachyMlsClient,
    mailbox_kind: u8,
    id: *const c_char,
    received_at_ms: u64,
    envelope: *const u8,
    envelope_len: usize,
    device_seal: *const u8,
    device_seal_len: usize,
    out_held: *mut u8,
) -> i32 {
    guard(|| {
        require_out(out_held, "out_held")?;
        let client = client_mut(client)?;
        let id = cstr_arg(id, "id")?;
        let envelope = slice_from(envelope, envelope_len, "envelope")?;
        let device_seal = slice_from(device_seal, device_seal_len, "device_seal")?;
        *out_held =
            client.hold_envelope_sealed(mailbox_kind, id, received_at_ms, envelope, device_seal)?
                as u8;
        Ok(())
    })
}

/// The next envelope [`peachy_mls_hold_envelope`] kept that opens now,
/// oldest first. Take it through the same path as a fresh envelope (it opens
/// with [`peachy_mls_open_envelope`]; a message inside that does not decrypt
/// is a loss to draw and ask for again by its content hint), release it with
/// [`peachy_mls_release_held`] once what was made of it is stored, then call
/// this again, until `out_id` comes back EMPTY: nothing more opens. One not
/// released stays kept, and is handed out again in the next pass or after a
/// restart. Call it after every mailbox pass. Cheap when nothing changed
/// since it last came back empty. One handed out on its device seal opens
/// with [`peachy_mls_open_envelope`] until it is released, however many are
/// handed out first; ask [`peachy_mls_held_disposition`] what it is to be
/// made of before taking it through.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_next_reopenable(
    client: *mut PeachyMlsClient,
    out_mailbox_kind: *mut u8,
    out_received_at_ms: *mut u64,
    out_id: *mut PeachyMlsBuffer,
    out_envelope: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_mailbox_kind, "out_mailbox_kind")?;
        require_out(out_received_at_ms, "out_received_at_ms")?;
        require_out(out_id, "out_id")?;
        require_out(out_envelope, "out_envelope")?;
        let client = client_mut(client)?;
        let (kind, at, id, envelope) = match client.next_reopenable()? {
            Some(held) => (
                held.mailbox_kind,
                held.received_at_ms,
                held.id.into_bytes(),
                held.envelope,
            ),
            None => (0, 0, Vec::new(), Vec::new()),
        };
        *out_mailbox_kind = kind;
        *out_received_at_ms = at;
        write_buffer(out_id, "out_id", id)?;
        write_buffer(out_envelope, "out_envelope", envelope)
    })
}

/// Release an envelope [`peachy_mls_next_reopenable`] handed out, by its
/// `id` (UTF-8, NUL-terminated), once what was made of it (a row, a
/// placeholder, a resend ask) is stored: it is kept no longer.
/// `out_released` is true when one with that id was kept.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_release_held(
    client: *mut PeachyMlsClient,
    id: *const c_char,
    out_released: *mut bool,
) -> i32 {
    guard(|| {
        require_out(out_released, "out_released")?;
        let client = client_mut(client)?;
        let id = cstr_arg(id, "id")?;
        *out_released = client.release_held(id)?;
        Ok(())
    })
}

/// [`peachy_mls_held_disposition`]: taken through as any envelope.
pub const PEACHY_MLS_HELD_ORDINARY: u8 = 0;
/// [`peachy_mls_held_disposition`]: from a device of somebody who holds no
/// leaf of the group any more. Also what any unknown value means.
pub const PEACHY_MLS_HELD_FORMER_MEMBER: u8 = 1;
/// [`peachy_mls_held_disposition`]: for a group this device holds no copy of.
pub const PEACHY_MLS_HELD_ORPHAN: u8 = 2;
const _: () = assert!(
    PEACHY_MLS_HELD_ORDINARY == peachy_mls_core::HeldFate::Ordinary as u8
        && PEACHY_MLS_HELD_FORMER_MEMBER == peachy_mls_core::HeldFate::FormerMember as u8
        && PEACHY_MLS_HELD_ORPHAN == peachy_mls_core::HeldFate::Orphan as u8
);

/// What the envelope [`peachy_mls_next_reopenable`] handed out under `id`
/// (UTF-8, NUL-terminated) is to be made of, when it was handed out on its
/// device seal. `out_fate`: [`PEACHY_MLS_HELD_ORDINARY`], taken through as any
/// envelope (also for one handed out on no seal);
/// [`PEACHY_MLS_HELD_FORMER_MEMBER`], from a device of somebody who holds no
/// leaf of the group any more: a placeholder naming them, neither opened nor
/// asked for; [`PEACHY_MLS_HELD_ORPHAN`], for a group this device holds no
/// copy of: a placeholder in the conversation of the group the envelope opens
/// to, naming its sender, asked for again once this device is seated there.
/// A caller MUST treat any other value as [`PEACHY_MLS_HELD_FORMER_MEMBER`]:
/// a fate a newer core adds is never "take it through". `out_author`: the actor id
/// of the person whose device sealed it (UTF-8), empty when it is simply a
/// leaf of the copy.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_held_disposition(
    client: *mut PeachyMlsClient,
    id: *const c_char,
    out_fate: *mut u8,
    out_author: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_fate, "out_fate")?;
        require_out(out_author, "out_author")?;
        let client = client_mut(client)?;
        let id = cstr_arg(id, "id")?;
        let disposition = client.held_disposition(id);
        *out_fate = disposition
            .as_ref()
            .map_or(PEACHY_MLS_HELD_ORDINARY, |d| d.fate as u8);
        let author = disposition
            .and_then(|d| d.author)
            .unwrap_or_default()
            .into_bytes();
        write_buffer(out_author, "out_author", author)
    })
}

/// Set the group's name and photo, in ONE commit carrying a
/// `GroupContextExtensions` proposal that changes `peachy_group_meta` and
/// nothing else. Any member may.
///
/// `value` is 1 to `MAX_GROUP_META_BYTES` bytes of the client format; an empty
/// or oversized value is refused with `PEACHY_MLS_ERR_INVALID_ARGUMENT` before
/// any commit is built.
///
/// **This STAGES a commit.** As for `peachy_mls_group_remove_member`: submit
/// the bytes, then call exactly one of merge and clear.
///
/// [`PEACHY_MLS_ERR_EXTENSION_UNSUPPORTED`] means some member's leaf does
/// not yet advertise `peachy_group_meta`. That leaf's next renewal carries it
/// (`peachy_mls_group_credential_refresh_due` answers true for it once that
/// member runs a build that advertises it), made before that member's next
/// send into the group or as its app starts or comes to the foreground.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_set_meta(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    value: *const u8,
    value_len: usize,
    out_commit: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_commit, "out_commit")?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let value = slice_from(value, value_len, "value")?;
        let bundle = client.set_group_meta(group_id, value)?;
        write_buffer(out_commit, "out_commit", bundle.commit)
    })
}

// ---- The commit lifecycle --------------------------------------------------
//
// `add_member`, `remove_member` and `self_update` above STAGE a commit; they no
// longer merge it. The caller submits the bytes to the delivery service and
// then calls exactly one of the two doors below, depending on the answer. The
// reasoning is in `mls/core/src/group.rs` §The commit lifecycle, and the short
// version is that Peachy's delivery service is the total order: a client that
// merged before it asked would, on every lost race, be alone in an epoch the
// group never entered, still `is_active`, still encrypting, and readable by
// nobody.

/// The delivery service TOOK the staged commit: adopt the new epoch.
///
/// `out_epoch` receives the epoch the group is now in. It is an error to call
/// this with nothing staged ([`PEACHY_MLS_ERR_INVALID_ARGUMENT`]).
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_merge_pending_commit(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    out_epoch: *mut u64,
) -> i32 {
    guard(|| {
        // Rule 5: merging is the durability point for a whole epoch.
        require_out(out_epoch, "out_epoch")?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        *out_epoch = client.merge_pending_commit(group_id)?;
        Ok(())
    })
}

/// The delivery service REFUSED the staged commit: drop the branch.
///
/// Safe to call with nothing staged, unlike
/// [`peachy_mls_group_merge_pending_commit`] — this is the error path, and an
/// error path that can fail for being taken twice is one callers get wrong.
/// After it, the group sits exactly where the server left it and the caller
/// replays the server's commits.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_clear_pending_commit(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
) -> i32 {
    guard(|| {
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        client.clear_pending_commit(group_id)
    })
}

/// Whether this group is holding a staged commit awaiting a verdict.
///
/// `out_pending` receives 1 or 0. For a caller that wants to assert the
/// invariant rather than remember it.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_has_pending_commit(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    out_pending: *mut bool,
) -> i32 {
    guard(|| {
        require_out(out_pending, "out_pending")?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        *out_pending = client.has_pending_commit(group_id)?;
        Ok(())
    })
}

/// Whether this group holds a commit found staged when the client opened,
/// whose verdict this device never heard (a process killed while its commit
/// waited on the delivery service). `out_saved` receives 1 or 0. A stage made
/// since the open is not one.
///
/// The app that owns the store settles each one with
/// [`peachy_mls_group_settle_saved_commit`] before it processes anything for
/// the group (docs/mls-core.md §A commit saved across a restart).
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_has_saved_commit(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    out_saved: *mut bool,
) -> i32 {
    guard(|| {
        require_out(out_saved, "out_saved")?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        *out_saved = client.has_saved_commit(group_id)?;
        Ok(())
    })
}

/// Settle a saved commit against the group's head as the delivery service
/// reports it: its epoch and the SHA-256 of that epoch's send key.
/// `out_verdict` receives [`PEACHY_MLS_SAVED_COMMIT_MERGED`] (the head is the
/// commit's), [`PEACHY_MLS_SAVED_COMMIT_CLEARED`] (it is not), or
/// [`PEACHY_MLS_SAVED_COMMIT_WAITING`] (the head is past the commit's epoch;
/// it is kept, for its own echo or another member's commit at its epoch to
/// decide). A caller that cannot read the head calls nothing.
/// [`PEACHY_MLS_ERR_INVALID_ARGUMENT`] when no saved commit waits.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_settle_saved_commit(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    head_epoch: u64,
    head_verifier: *const u8,
    head_verifier_len: usize,
    out_verdict: *mut u32,
) -> i32 {
    guard(|| {
        require_out(out_verdict, "out_verdict")?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let verifier = slice_from(head_verifier, head_verifier_len, "head_verifier")?;
        *out_verdict = match client.settle_saved_commit(group_id, head_epoch, verifier)? {
            SavedCommit::Merged => PEACHY_MLS_SAVED_COMMIT_MERGED,
            SavedCommit::Cleared => PEACHY_MLS_SAVED_COMMIT_CLEARED,
            SavedCommit::Waiting => PEACHY_MLS_SAVED_COMMIT_WAITING,
        };
        Ok(())
    })
}

/// The number of leaves in the group's roster, including this device and
/// including any leaf whose credential does not currently verify.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_member_count(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    out_count: *mut usize,
) -> i32 {
    guard(|| {
        if out_count.is_null() {
            return Err(null_argument("out_count"));
        }
        let handle = client;
        let client = client_mut(handle)?;
        // Not from a group another process has moved past (§A store two
        // processes share): reloads only when the store moved.
        client.refresh_if_moved()?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        // Kept for this read's per-position calls (§One roster per read).
        (*handle).roster = None;
        let entries = client.roster(group_id)?;
        *out_count = entries.len();
        (*handle).roster = Some(RosterSnapshot {
            group_id: group_id.to_vec(),
            epoch: client.epoch(group_id)?,
            taken: Instant::now(),
            entries,
        });
        Ok(())
    })
}

/// One roster entry, by position in the list [`peachy_mls_group_member_count`]
/// sized.
///
/// `out_rejection` receives 0 when the leaf's credential verifies, and
/// otherwise the `CredentialRejection` code naming why it does not — in which
/// case the actor id, the device id and the device key are all empty. An
/// unverifiable leaf is reported rather than hidden: it is still in the tree
/// and still receives every message, so a roster that omitted it would show a
/// group that does not match who can read it.
///
/// `out_device_key` receives the leaf's raw 32-byte Ed25519 signature key,
/// which the credential has already been checked to bind. **It is what makes a
/// device approval checkable against somebody who is ALREADY in the group.**
/// Before seating a second leaf for an actor the group already holds, the
/// adder verifies that actor's approval signature against the signing key of a
/// leaf of that same actor already in the tree — and it has to be a key read
/// out of the tree, because a key taken from the directory that served the
/// approval is a key the directory got to choose. Without this out-parameter a
/// wrapper could only compare key packages against each other inside one
/// fetch, which covers the moment a group is created and nothing after it.
///
/// `out_leaf_key` receives the leaf's tree signature key for EVERY leaf,
/// verified or not: what [`peachy_mls_group_remove_member`] takes beside the
/// index, so a removal names the leaf this entry described. Not a key to
/// verify anything against; that is `out_device_key`, empty when the leaf
/// does not verify.
///
/// Every out-parameter may be NULL, and each one that is not is written
/// exactly once, so a caller that wants only the leaf index pays for nothing
/// else.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_member(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    position: usize,
    out_leaf_index: *mut u32,
    out_actor_id: *mut PeachyMlsBuffer,
    out_device_id: *mut PeachyMlsBuffer,
    out_device_key: *mut PeachyMlsBuffer,
    out_leaf_key: *mut PeachyMlsBuffer,
    out_rejection: *mut u32,
) -> i32 {
    guard(|| {
        // Fail closed: 0 is "verifies". Every error below, and a caught
        // panic, leave a rejection.
        if !out_rejection.is_null() {
            *out_rejection = CredentialRejection::Malformed.code();
        }
        let handle = client;
        let client = roster_read_client(handle)?;
        // No reload here: the roster is read from the snapshot
        // `peachy_mls_group_member_count` refreshed, so one read's count,
        // indices and keys agree with each other (§One roster per read).
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let entry = roster_entry(&(*handle).roster, client, group_id, position)?;

        if !out_leaf_index.is_null() {
            *out_leaf_index = entry.leaf_index;
        }
        if !out_leaf_key.is_null() {
            *out_leaf_key = PeachyMlsBuffer::from_vec(entry.leaf_key.clone());
        }
        match &entry.identity {
            Ok(identity) => {
                if !out_rejection.is_null() {
                    *out_rejection = 0;
                }
                if !out_actor_id.is_null() {
                    *out_actor_id =
                        PeachyMlsBuffer::from_vec(identity.actor_id.clone().into_bytes());
                }
                if !out_device_id.is_null() {
                    *out_device_id =
                        PeachyMlsBuffer::from_vec(identity.device_id.clone().into_bytes());
                }
                if !out_device_key.is_null() {
                    *out_device_key = PeachyMlsBuffer::from_vec(identity.device_key.to_vec());
                }
            }
            Err(rejection) => {
                if !out_rejection.is_null() {
                    *out_rejection = rejection.code();
                }
                if !out_actor_id.is_null() {
                    *out_actor_id = PeachyMlsBuffer::empty();
                }
                if !out_device_id.is_null() {
                    *out_device_id = PeachyMlsBuffer::empty();
                }
                // Empty, not the leaf's key. A key from a credential that did
                // not check out is a key nothing vouched for, and handing one
                // back beside a rejection invites a caller to verify an
                // approval against it.
                if !out_device_key.is_null() {
                    *out_device_key = PeachyMlsBuffer::empty();
                }
            }
        }
        Ok(())
    })
}

/// The ACCOUNT identity key of one roster entry, by the same position
/// [`peachy_mls_group_member`] takes: the 32-byte Ed25519 key the leaf's
/// credential names and the core has verified signs that leaf's device key
/// (docs/identity.md §The account identity key).
///
/// It is what the security code is computed from (docs/identity.md
/// §The security code): the key has to come from the tree, like the device
/// key beside it, because a key the directory handed over is a key the
/// directory got to choose. `out_account_key` receives empty bytes when the
/// leaf's credential does not verify or carries no certificate.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_member_account_key(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    position: usize,
    out_account_key: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let handle = client;
        let client = roster_read_client(handle)?;
        // No reload here: the roster is read from the snapshot
        // `peachy_mls_group_member_count` refreshed, so one read's count,
        // indices and keys agree with each other (§One roster per read).
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let entry = roster_entry(&(*handle).roster, client, group_id, position)?;
        let key = match &entry.identity {
            Ok(identity) => identity
                .account_key
                .map(|key| key.to_vec())
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        write_buffer(out_account_key, "out_account_key", key)
    })
}

/// The identity INSIDE a raw key package, read out of the bytes rather than
/// taken from whoever handed them over.
///
/// A device approval is only checkable without trusting the directory that
/// served the key package if the device id and signing key come out of the
/// package itself (docs/identity.md §What the adder checks): a server
/// can answer with a truthful pair for a verification and a key package
/// carrying a DIFFERENT key, and the leaf that lands is then one nobody
/// approved. `out_device_key` is that key, straight out of the package.
/// Seating a device of your OWN goes through
/// [`peachy_mls_check_own_device_approval`], which reads the package the same
/// way and checks the approval against keys this device already trusts.
///
/// `out_rejection` receives 0 when the credential verifies, and otherwise the
/// `CredentialRejection` code naming why it does not — in which case the actor
/// id, device id and device key are all empty. That is a VERDICT and a zero
/// return: the caller refuses the add and says why. A NON-zero return means the
/// bytes are not a key package this build accepts at all, which is a different
/// answer and deliberately not reachable through `out_rejection`.
///
/// The accepted encoding is exactly [`peachy_mls_group_add_member`]'s: a
/// serialized `MlsMessage` wrapping a KeyPackage, as a directory publishes it.
/// Anything this door accepts is something that can really be added, so no
/// client has to learn two encodings.
///
/// Every buffer written is the caller's to free with
/// [`peachy_mls_buffer_free`].
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_key_package_identity(
    client: *mut PeachyMlsClient,
    key_package: *const u8,
    key_package_len: usize,
    out_actor_id: *mut PeachyMlsBuffer,
    out_device_id: *mut PeachyMlsBuffer,
    out_device_key: *mut PeachyMlsBuffer,
    out_rejection: *mut u32,
) -> i32 {
    guard(|| {
        // Fail closed, as on `peachy_mls_group_member`.
        if !out_rejection.is_null() {
            *out_rejection = CredentialRejection::Malformed.code();
        }
        let client = client_mut(client)?;
        let key_package = slice_from(key_package, key_package_len, "key_package")?;
        let verdict = client.key_package_identity(key_package)?;

        match verdict {
            Ok(identity) => {
                if !out_rejection.is_null() {
                    *out_rejection = 0;
                }
                // Nulls tolerated, exactly as on `peachy_mls_group_member`: a
                // caller that only wants the signing key should not have to
                // take — and then free — two strings it will throw away.
                for (out, bytes) in [
                    (out_actor_id, identity.actor_id.clone().into_bytes()),
                    (out_device_id, identity.device_id.clone().into_bytes()),
                    (out_device_key, identity.device_key.to_vec()),
                ] {
                    if !out.is_null() {
                        *out = PeachyMlsBuffer::from_vec(bytes);
                    }
                }
            }
            Err(rejection) => {
                if !out_rejection.is_null() {
                    *out_rejection = rejection.code();
                }
                for out in [out_actor_id, out_device_id, out_device_key] {
                    if !out.is_null() {
                        *out = PeachyMlsBuffer::empty();
                    }
                }
            }
        }
        Ok(())
    })
}

/// The ACCOUNT identity key inside a raw key package: the 32-byte Ed25519
/// key its credential names and the core has verified signs the device key
/// [`peachy_mls_key_package_identity`] reads (docs/identity.md §The
/// account identity key).
///
/// What an adder compares with a security code this device verified before it
/// seats somebody else's device (docs/identity.md §Verified): read out
/// of the package's own bytes, never the directory's word. `out_account_key`
/// receives empty bytes when the credential does not verify or carries no
/// certificate. A NON-zero return means the bytes are not a key package this
/// build accepts at all, as for [`peachy_mls_key_package_identity`].
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_key_package_account_key(
    client: *mut PeachyMlsClient,
    key_package: *const u8,
    key_package_len: usize,
    out_account_key: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let client = client_mut(client)?;
        let key_package = slice_from(key_package, key_package_len, "key_package")?;
        let key = match client.key_package_identity(key_package)? {
            Ok(identity) => identity
                .account_key
                .map(|key| key.to_vec())
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        write_buffer(out_account_key, "out_account_key", key)
    })
}

/// Whether this device may seat `key_package`, a device of its OWN person,
/// given the approval the directory listed for it: `approver_device_id` and
/// `approval_signature`, both empty when it listed none.
///
/// A certificate alone does not decide who joins: the approval is checked only
/// against the devices on this device's approval chain (itself, the device
/// that let it in, and the devices whose approvals it verified under one of
/// those), never against a leaf it only saw in a tree or watched another
/// device seat (docs/identity.md §What the adder checks).
///
/// `*out_verdict` receives one of the `PEACHY_MLS_OWN_DEVICE_*` codes, and the
/// return is [`PEACHY_MLS_OK`] for every one of them. Only
/// [`PEACHY_MLS_OWN_DEVICE_KNOWN`] and [`PEACHY_MLS_OWN_DEVICE_APPROVED`] may
/// seat the device. `UNANCHORED` is worth asking again once this device's
/// chain grows; `BAD_APPROVAL` is not. `*out_verdict` is set to
/// [`PEACHY_MLS_OWN_DEVICE_UNANCHORED`] before anything else, so a caller that
/// reads it after any failure reads a verdict that seats nobody.
///
/// # Safety
/// See the module header. `approver_device_id` must be a valid NUL-terminated
/// string (empty for none), `approval_signature` may be NULL only with a zero
/// length, and `out_verdict` must point to one writable `u32`.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_check_own_device_approval(
    client: *mut PeachyMlsClient,
    key_package: *const u8,
    key_package_len: usize,
    approver_device_id: *const c_char,
    approval_signature: *const u8,
    approval_signature_len: usize,
    out_verdict: *mut u32,
) -> i32 {
    guard(|| {
        if out_verdict.is_null() {
            return Err(null_argument("out_verdict"));
        }
        // Fail closed: every error below, and a caught panic, leave a verdict
        // that seats nobody and hands nothing over.
        *out_verdict = PEACHY_MLS_OWN_DEVICE_UNANCHORED;
        let client = client_mut(client)?;
        let key_package = slice_from(key_package, key_package_len, "key_package")?;
        let approver = cstr_arg(approver_device_id, "approver_device_id")?;
        // No approval listed is an ordinary answer, and a wrapper handing
        // over an empty buffer may well hand over NULL with it.
        let signature: &[u8] = if approval_signature_len == 0 {
            &[]
        } else {
            slice_from(
                approval_signature,
                approval_signature_len,
                "approval_signature",
            )?
        };
        *out_verdict = client
            .check_own_device_approval(key_package, approver, signature)
            .code();
        Ok(())
    })
}

/// May this device hand its account's history to `device_id`, a row of its
/// own account's device list? The same verdict
/// [`peachy_mls_check_own_device_approval`] gives, read from the row instead
/// of a key package: `device_key` is the row's 32-byte signing key, and
/// `approver_device_id` and `approval_signature` its `approved_by_device_id`
/// and `approval_signature`, both empty when it lists none.
///
/// A device sends the history hand-off only when this answers
/// [`PEACHY_MLS_OWN_DEVICE_KNOWN`] or [`PEACHY_MLS_OWN_DEVICE_APPROVED`], and
/// the nothing-to-send note otherwise (docs/sealed-messages.md
/// §Handing history to your own new device): a removed device keeps the
/// account key, so the list's `account_certified` says nothing about who
/// holds a row. The hand-off a device sends as it approves another skips the
/// check, since it has just signed that approval.
///
/// `*out_verdict` receives one of the `PEACHY_MLS_OWN_DEVICE_*` codes, and the
/// return is [`PEACHY_MLS_OK`] for every one of them. It reads only; nothing
/// is recorded. `*out_verdict` is set to [`PEACHY_MLS_OWN_DEVICE_UNANCHORED`]
/// before anything else, so a caller that reads it after any failure reads a
/// verdict that hands nothing over.
///
/// # Safety
/// See the module header. `device_id` and `approver_device_id` must be valid
/// NUL-terminated strings (the approver empty for none), `device_key` and
/// `approval_signature` may be NULL only with a zero length, and
/// `out_verdict` must point to one writable `u32`.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_check_own_device_key(
    client: *mut PeachyMlsClient,
    device_id: *const c_char,
    device_key: *const u8,
    device_key_len: usize,
    approver_device_id: *const c_char,
    approval_signature: *const u8,
    approval_signature_len: usize,
    out_verdict: *mut u32,
) -> i32 {
    guard(|| {
        if out_verdict.is_null() {
            return Err(null_argument("out_verdict"));
        }
        // Fail closed: every error below, and a caught panic, leave a verdict
        // that seats nobody and hands nothing over.
        *out_verdict = PEACHY_MLS_OWN_DEVICE_UNANCHORED;
        let client = client_mut(client)?;
        let device_id = cstr_arg(device_id, "device_id")?;
        // A row with no key is an answer (`CREDENTIAL_REJECTED`), not a fault.
        let device_key: &[u8] = if device_key_len == 0 {
            &[]
        } else {
            slice_from(device_key, device_key_len, "device_key")?
        };
        let approver = cstr_arg(approver_device_id, "approver_device_id")?;
        let signature: &[u8] = if approval_signature_len == 0 {
            &[]
        } else {
            slice_from(
                approval_signature,
                approval_signature_len,
                "approval_signature",
            )?
        };
        *out_verdict = client
            .check_own_device_key(device_id, device_key, approver, signature)
            .code();
        Ok(())
    })
}

/// Remember the device that let this one in (its id and 32-byte signing key,
/// as the approval named it), so this device trusts it before the two share a
/// group. Called once, right after [`peachy_mls_account_key_accept_hybrid`]
/// succeeds.
///
/// # Safety
/// See the module header. `device_id` must be a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_remember_own_approver(
    client: *mut PeachyMlsClient,
    device_id: *const c_char,
    signing_key: *const u8,
    signing_key_len: usize,
) -> i32 {
    guard(|| {
        let client = client_mut(client)?;
        let device_id = cstr_arg(device_id, "device_id")?;
        let signing_key = slice_from(signing_key, signing_key_len, "signing_key")?;
        client.remember_own_approver(device_id, signing_key)?;
        Ok(())
    })
}

/// The account identity key's 64-byte signature REVOKING `device_key`, the
/// removed device's raw 32-byte Ed25519 public key
/// (`"peachy-device-revocation-v1" 0x00 device_key`): what a device sends with
/// `RevokeDevice`, so a peer removes the leaf on the account's word rather
/// than the server's. Deterministic, so `mls/fixtures/device-link.json` pins
/// one. Freed with [`peachy_mls_buffer_free`].
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_sign_device_revocation(
    account_key: *const u8,
    account_key_len: usize,
    device_key: *const u8,
    device_key_len: usize,
    out_signature: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let account_key = slice_from(account_key, account_key_len, "account_key")?;
        let device_key = slice_from(device_key, device_key_len, "device_key")?;
        let signature = peachy_mls_core::sign_device_revocation(account_key, device_key)?;
        write_buffer(out_signature, "out_signature", signature.to_vec())
    })
}

/// Whether the leaf at `leaf_index` of `group_id`, which the delivery service
/// or this account's device list named as revoked, may be removed: its own
/// account signed `revocation` over its key, or its credential has lapsed on
/// both this device's clock and the group's tree clock (with the person
/// keeping a live leaf there, or past the grace), or (until signed
/// revocations are enforced) its person keeps another leaf in the group. A
/// person's last leaf never goes on the server's word alone. Reads the group
/// as another process may have moved it. `revocation` is NULL with length 0
/// when the server handed out none.
/// docs/identity.md §Revocation reaches a seated leaf through the
/// roster.
///
/// A `revocation` that verifies is kept, with `revoked_at`: the second the
/// delivery service says it took effect (`Device.revoked_at`, or
/// `DeviceRevocation.revoked_at` beside `stale_revocations`), Unix seconds,
/// `0` when it did not say. From then on this device refuses that key's
/// messages received at or after it, in every group, and reads those
/// received before it ([`peachy_mls_group_process_door`]'s `received_at`).
///
/// # Safety
/// See the module header. `revocation` NULL or `revocation_len` readable
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_stale_leaf_removable(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    leaf_index: u32,
    revocation: *const u8,
    revocation_len: usize,
    revoked_at: i64,
    out_removable: *mut bool,
) -> i32 {
    guard(|| {
        require_out(out_removable, "out_removable")?;
        let client = client_mut(client)?;
        // Not from a group another process has moved past (§A store two
        // processes share): reloads only when the store moved.
        client.refresh_if_moved()?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let revocation: &[u8] = if revocation.is_null() && revocation_len == 0 {
            &[]
        } else {
            slice_from(revocation, revocation_len, "revocation")?
        };
        *out_removable =
            client.stale_leaf_removable(group_id, leaf_index, revocation, revoked_at)?;
        Ok(())
    })
}

/// THE DOOR FOR A LEAF THE SERVER NAMED (`stale_device_ids`,
/// `retired_device_ids`): judge it as [`peachy_mls_stale_leaf_removable`]
/// does and, only where that allows, stage its removal as
/// [`peachy_mls_group_remove_member`] does, with the same leaf-key check
/// (`peachy_mls_core::Client::remove_stale_leaf`). `out_staged` is false, with
/// nothing staged and `out_commit` empty, when the leaf stays: a person's last
/// leaf on the server's word alone, a leaf whose credential does not verify,
/// or this device's own leaf.
///
/// [`peachy_mls_group_remove_member`] does not ask the judge, and receivers
/// do not re-judge a removal: a client that acts on a list the server handed
/// it removes through this door, never the plain one.
///
/// # Safety
/// See the module header. `revocation` NULL or `revocation_len` readable
/// bytes.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_remove_stale_leaf(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    leaf_index: u32,
    expected_leaf_key: *const u8,
    expected_leaf_key_len: usize,
    revocation: *const u8,
    revocation_len: usize,
    revoked_at: i64,
    out_staged: *mut bool,
    out_commit: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_staged, "out_staged")?;
        // Rule 5: this may STAGE a commit, whose bytes must not be lost.
        require_out(out_commit, "out_commit")?;
        let client = client_mut(client)?;
        client.refresh_if_moved()?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let expected_leaf_key = slice_from(
            expected_leaf_key,
            expected_leaf_key_len,
            "expected_leaf_key",
        )?;
        let revocation: &[u8] = if revocation.is_null() && revocation_len == 0 {
            &[]
        } else {
            slice_from(revocation, revocation_len, "revocation")?
        };
        match client.remove_stale_leaf(
            group_id,
            leaf_index,
            expected_leaf_key,
            revocation,
            revoked_at,
        )? {
            Some(bundle) => {
                *out_staged = true;
                write_buffer(out_commit, "out_commit", bundle.commit)
            }
            None => {
                *out_staged = false;
                write_buffer(out_commit, "out_commit", Vec::new())
            }
        }
    })
}

/// Pin the links this account's device list states (`Client::note_own_install_links`):
/// `rows_json` is a JSON array of `{"id","twinOf"}` (any other field
/// ignored), and the first `twinOf` this device sees for an id is the one it
/// keeps. Called on every read of the device list. `out_pinned` receives how
/// many links it pinned now.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_note_own_install_links(
    client: *mut PeachyMlsClient,
    rows_json: *const c_char,
    out_pinned: *mut u32,
) -> i32 {
    guard(|| {
        require_out(out_pinned, "out_pinned")?;
        let rows_json = cstr_arg(rows_json, "rows_json")?;
        let client = client_mut(client)?;
        *out_pinned = client.note_own_install_links(rows_json)?;
        Ok(())
    })
}

/// The account's revocations of the rows a removal signs, made with
/// `account_key` (`Client::sign_install_revocations`): only rows whose keys
/// this device vouches for on its own approval chain, a linked row only when
/// the confirmation named it (`"namedWith"`) and on the link it pinned,
/// nothing for a denial (`"denying":true`), and nothing that touches this
/// install; or, with `"restoredSince"` (Unix seconds), the rows a PIN restore
/// signed out, only keys the restoring registration's answer kept
/// ([`peachy_mls_note_restore_signed_out`]), none before. `request_json` is
/// `{"named","denying","namedWith",
/// "ownDeviceIds","rows","restoredSince"}`, each row `{"id","twinOf",
/// "signingKey","approvedByDeviceId","approvalSignature","revoked",
/// "revokedAt"}`, bytes as hex.
/// `out_json` receives `[{"deviceId","signature"}]`, the signature as hex,
/// freed with [`peachy_mls_buffer_free`]. docs/identity.md
/// §RevokeDevice.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_sign_install_revocations(
    client: *mut PeachyMlsClient,
    account_key: *const u8,
    account_key_len: usize,
    request_json: *const c_char,
    out_json: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_json, "out_json")?;
        let account_key = slice_from(account_key, account_key_len, "account_key")?;
        let request_json = cstr_arg(request_json, "request_json")?;
        let client = client_mut(client)?;
        // Judge on the chain the store holds now: the app's other process
        // may have forgotten a device since this one loaded.
        client.refresh_if_moved()?;
        let signed = client.sign_install_revocations(account_key, request_json)?;
        write_buffer(out_json, "out_json", signed.into_bytes())
    })
}

/// Keep what the registration that restored this device from its PIN answered
/// as signed out (`Client::note_restore_signed_out`): `request_json` is
/// `{"restoredSince","keys","certificates","accountIdentityKey"}`, bytes as
/// hex, the identity key derived from the account key this device holds: a
/// key is kept only when its certificate verifies under the identity key the
/// client holds (a request naming another is refused), or under the
/// request's while it holds none, and only when nothing is kept for that
/// restore yet; a kept key is never
/// approved here again. `out_kept` receives how many keys it kept now.
/// docs/identity.md §RevokeDevice.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_note_restore_signed_out(
    client: *mut PeachyMlsClient,
    request_json: *const c_char,
    out_kept: *mut u32,
) -> i32 {
    guard(|| {
        require_out(out_kept, "out_kept")?;
        let request_json = cstr_arg(request_json, "request_json")?;
        let client = client_mut(client)?;
        client.refresh_if_moved()?;
        *out_kept = client.note_restore_signed_out(request_json)?;
        Ok(())
    })
}

/// This device's approval of the device `device_id` holding `signing_key`,
/// signed with this device's own key (`Client::sign_own_device_approval`):
/// the 64 bytes [`peachy_mls_sign_device_approval`] makes from its seed.
/// Refuses a key this device forgot, signed the account's revocation of, or
/// took from a restore's answer as signed out: that device starts over under
/// a new key. With `restored_since` above zero (this device's PIN restore,
/// Unix seconds as [`peachy_mls_sign_install_revocations`] takes it), it
/// closes that restore when no answer is kept for it yet.
/// `out_signature` receives 64 bytes, freed with [`peachy_mls_buffer_free`].
///
/// # Safety
/// See the module header. `device_id` must be a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_sign_own_device_approval(
    client: *mut PeachyMlsClient,
    device_id: *const c_char,
    signing_key: *const u8,
    signing_key_len: usize,
    restored_since: i64,
    out_signature: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_signature, "out_signature")?;
        let device_id = cstr_arg(device_id, "device_id")?;
        let signing_key = slice_from(signing_key, signing_key_len, "signing_key")?;
        let client = client_mut(client)?;
        // Judge on the store as it is now: the app's other process may have
        // forgotten or signed out a device since this one loaded.
        client.refresh_if_moved()?;
        let signature = client.sign_own_device_approval(device_id, signing_key, restored_since)?;
        write_buffer(out_signature, "out_signature", signature)
    })
}

/// Forget `device_id`, a device of this account that the account removed
/// (this device's own `RevokeDevice`, or a revoked row on the device list).
/// It is no longer trusted as the device that let this one in, its leaves no
/// longer count as known, its approvals vouch for nobody, and
/// [`peachy_mls_check_own_device_approval`] never seats it again.
///
/// Forgotten with it is every key this device saw that id hold, and
/// `signing_key` too when given (the device list's key for the row, 32
/// bytes; NULL with length 0 for none): a forgotten key counts for nothing
/// under any id, since the account's certificate covers a key and never the
/// id the server files it under. Idempotent: `*out_new` is true when the
/// device, or a key of it, was not forgotten already. This device's own id
/// is refused, and its own key is never forgotten.
///
/// # Safety
/// See the module header. `device_id` must be a valid NUL-terminated string;
/// `signing_key` NULL or `signing_key_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_forget_own_device(
    client: *mut PeachyMlsClient,
    device_id: *const c_char,
    signing_key: *const u8,
    signing_key_len: usize,
    out_new: *mut bool,
) -> i32 {
    guard(|| {
        require_out(out_new, "out_new")?;
        let client = client_mut(client)?;
        let device_id = cstr_arg(device_id, "device_id")?;
        let signing_key: &[u8] = if signing_key.is_null() && signing_key_len == 0 {
            &[]
        } else {
            slice_from(signing_key, signing_key_len, "signing_key")?
        };
        *out_new = client.forget_own_device_with_key(device_id, signing_key)?;
        Ok(())
    })
}

/// The device ids of this account's OTHER devices that are leaves of a group
/// this device is active in, each once, as a string list (a u32 big-endian
/// count, then each id as a u32 big-endian length and its UTF-8 bytes; a
/// count of 0 for none). This is what the device has seen of
/// its own account, from commits it verified, and the "new device linked"
/// notice is keyed on it. A leaf under a key its id was not first seen with,
/// or under this device's own id with a key not its own, comes back as
/// `<device id>#<device key, 64 hex>` (`Client::own_sibling_leaves`).
/// `out_ids` is freed with [`peachy_mls_buffer_free`].
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_own_sibling_leaves(
    client: *mut PeachyMlsClient,
    out_ids: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let client = client_mut(client)?;
        let ids = client.own_sibling_leaves()?;
        write_buffer(out_ids, "out_ids", encode_string_list(&ids))
    })
}

// ---- A call link's core ------------------------------------------------------
//
// A call link's group lives in a second, in-memory client with this device's
// own credential (docs/calls.md §Call links on participant keys). It
// holds none of the main client's own-device records, so the main client
// hands them over and the link's client adopts them.

/// This client's own-device trust as UTF-8 JSON (`Client::own_device_trust`):
/// its identity, its approval chain, and every device id and key this
/// account forgot. Handed to [`peachy_mls_adopt_own_device_trust`] of a call
/// link's client on the same device; it never leaves the device. Reads only.
/// `out_json` is freed with [`peachy_mls_buffer_free`].
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_own_device_trust(
    client: *mut PeachyMlsClient,
    out_json: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_json, "out_json")?;
        let client = client_mut(client)?;
        // Judge on what the store holds now: the app's other process may
        // have forgotten a device since this one loaded.
        client.refresh_if_moved()?;
        let trust = client.own_device_trust()?;
        write_buffer(out_json, "out_json", trust.into_bytes())
    })
}

/// Adopt `trust_json`, the [`peachy_mls_own_device_trust`] form of this
/// device's main client, into this client (`Client::adopt_own_device_trust`):
/// from then on its adds refuse a forgotten device of the account, a Welcome
/// signed by one seats it in nothing, and its own-device checks run on the
/// main client's chain. Refused unless the form is this very device's, and
/// nothing is adopted unless all of it reads. In memory only. Forgotten ids
/// and keys accumulate across adoptions; the chain is the latest one.
///
/// # Safety
/// See the module header. `trust_json` must be a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_adopt_own_device_trust(
    client: *mut PeachyMlsClient,
    trust_json: *const c_char,
) -> i32 {
    guard(|| {
        let trust = cstr_arg(trust_json, "trust_json")?;
        let client = client_mut(client)?;
        client.adopt_own_device_trust(trust)?;
        Ok(())
    })
}

/// Grow the refusals this client enforces by `names`, the refusals the
/// delivery service switched on as the app holds them: names separated by
/// commas or newlines (`Client::adopt_client_refusals`,
/// docs/delivery.md §The protocol floor). Handed in after every open
/// and whenever the app's list grows. Never shrinks; a name this build does
/// not know is ignored. In memory.
///
/// # Safety
/// See the module header. `names` must be a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_client_adopt_refusals(
    client: *mut PeachyMlsClient,
    names: *const c_char,
) -> i32 {
    guard(|| {
        let names = cstr_arg(names, "names")?;
        let client = client_mut(client)?;
        client.adopt_client_refusals(&peachy_mls_core::client_refusals::parse_names(names));
        Ok(())
    })
}

/// What this client makes of `(actor_id, device_id, device_key)`, a leaf in
/// one of its groups (`Client::own_device_standing`). `*out_standing`
/// receives one of the `PEACHY_MLS_OWN_STANDING_*` codes; only
/// [`PEACHY_MLS_OWN_STANDING_THIS_DEVICE`] and
/// [`PEACHY_MLS_OWN_STANDING_ON_CHAIN`] count as the person's own device. It
/// is set to [`PEACHY_MLS_OWN_STANDING_OFF_CHAIN`] before anything else, so a
/// caller that reads it after any failure counts nobody as the person's.
/// Reads only.
///
/// # Safety
/// See the module header. `actor_id` and `device_id` must be valid
/// NUL-terminated strings, `device_key` NULL only with a zero length, and
/// `out_standing` must point to one writable `u32`.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_own_device_standing(
    client: *mut PeachyMlsClient,
    actor_id: *const c_char,
    device_id: *const c_char,
    device_key: *const u8,
    device_key_len: usize,
    out_standing: *mut u32,
) -> i32 {
    guard(|| {
        if out_standing.is_null() {
            return Err(null_argument("out_standing"));
        }
        // Fail closed: every error below, and a caught panic, leave a
        // standing that is not the person's.
        *out_standing = PEACHY_MLS_OWN_STANDING_OFF_CHAIN;
        let client = client_mut(client)?;
        let actor_id = cstr_arg(actor_id, "actor_id")?;
        let device_id = cstr_arg(device_id, "device_id")?;
        let device_key: &[u8] = if device_key_len == 0 {
            &[]
        } else {
            slice_from(device_key, device_key_len, "device_key")?
        };
        *out_standing = client
            .own_device_standing(actor_id, device_id, device_key)
            .code();
        Ok(())
    })
}

// ---- Signed join requests ---------------------------------------------------
//
// `peachy_mls_core::join_request`. A request to be seated in a group (an open
// community room's join inbox, or a rejoin) is signed by the asking device's
// own key, and the admitting device checks it against the key package it
// fetched to seat the asker. Without it, anybody who could read a group id
// could ask to seat somebody else.

/// Sign a request to be seated in `group_id` as this client's own device, now.
///
/// `out_proof` receives the 89-byte proof (version, time, nonce, signature),
/// freed with [`peachy_mls_buffer_free`]. It travels beside the ask's
/// `{actor, device}` claim.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_sign_join_request(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    out_proof: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let proof = client.sign_join_request(group_id)?;
        write_buffer(out_proof, "out_proof", proof)
    })
}

/// Whether `(actor_id, device_id)`'s signed request to be seated in `group_id`
/// holds, checked against `key_package`: the package fetched to seat that
/// device, in [`peachy_mls_group_add_member`]'s encoding.
///
/// `*out_verdict` receives one of the `PEACHY_MLS_JOIN_REQUEST_*` codes, and
/// the return is [`PEACHY_MLS_OK`] for every one of them, a refusal included.
/// Only [`PEACHY_MLS_JOIN_REQUEST_ACCEPTED`] may seat anybody. A non-zero
/// return is a NULL pointer or a string that is not UTF-8: a bug in the
/// caller, not a fact about the request. `*out_verdict` is set to
/// [`PEACHY_MLS_JOIN_REQUEST_MALFORMED`] before any work, so a non-zero return
/// (a caught panic included) leaves a verdict that seats nobody.
///
/// `pending_actors` is the actor ids, as a string list (a u32 big-endian
/// count, then each id as a u32 big-endian length and its UTF-8 bytes; an
/// empty buffer or a count of 0 for none; a list that is not consumed
/// exactly is refused), of the
/// people the caller is itself still trying to add to the group, from its own
/// invitations and never from the ask: the only people besides current
/// members and this device's own person whose request can be
/// [`PEACHY_MLS_JOIN_REQUEST_ACCEPTED`]. Anybody else is
/// [`PEACHY_MLS_JOIN_REQUEST_NOT_A_MEMBER`]: a signed ask proves who is
/// asking, never that they belong. So is a person whose last leaf this device
/// saw leave the group, even when `pending_actors` names them; a person the
/// caller admits by its own rule goes through
/// [`peachy_mls_verify_admitted_join_request`].
///
/// # Safety
/// See the module header. `actor_id` and `device_id` must be valid
/// NUL-terminated strings, `pending_actors` NULL with length 0 or
/// `pending_actors_len` readable bytes, and `out_verdict` must point to one
/// writable `u32`.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn peachy_mls_verify_join_request(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    actor_id: *const c_char,
    device_id: *const c_char,
    proof: *const u8,
    proof_len: usize,
    key_package: *const u8,
    key_package_len: usize,
    pending_actors: *const u8,
    pending_actors_len: usize,
    out_verdict: *mut u32,
) -> i32 {
    guard(|| {
        if out_verdict.is_null() {
            return Err(null_argument("out_verdict"));
        }
        // Fail closed: ACCEPTED is 0. Every error below, and a caught panic,
        // leave a verdict that seats nobody.
        *out_verdict = PEACHY_MLS_JOIN_REQUEST_MALFORMED;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let actor_id = cstr_arg(actor_id, "actor_id")?;
        let device_id = cstr_arg(device_id, "device_id")?;
        let proof = slice_from(proof, proof_len, "proof")?;
        let key_package = slice_from(key_package, key_package_len, "key_package")?;
        let pending_bytes: &[u8] = if pending_actors.is_null() && pending_actors_len == 0 {
            &[]
        } else {
            slice_from(pending_actors, pending_actors_len, "pending_actors")?
        };
        let pending_owned = decode_string_list(pending_bytes, "pending_actors")?;
        let pending: Vec<&str> = pending_owned.iter().map(String::as_str).collect();
        // Not from a group the notification extension has moved past (a
        // member it just removed still holds a leaf in a stale copy). The
        // add that follows this verdict judges membership again
        // ([`peachy_mls_group_add_member_for_ask`]), for a removal that lands
        // in between. A failed catch-up leaves the MALFORMED verdict set above.
        client.refresh_if_moved()?;
        *out_verdict = client
            .verify_join_request(group_id, actor_id, device_id, proof, key_package, &pending)
            .code();
        Ok(())
    })
}

/// [`peachy_mls_verify_join_request`] for a person this device has itself
/// decided to admit by its own rule: somebody who asked through a group link
/// it approved, or through an open group's join inbox. Every check but
/// membership, which the caller's rule already decided; a person who left the
/// group may come back this way. Never for a rejoin's seat ask (envelope
/// kind 3), which claims a seat the asker already holds.
///
/// `*out_verdict` and the return are as [`peachy_mls_verify_join_request`]'s;
/// this door never answers [`PEACHY_MLS_JOIN_REQUEST_NOT_A_MEMBER`].
///
/// # Safety
/// See the module header. `actor_id` and `device_id` must be valid
/// NUL-terminated strings and `out_verdict` must point to one writable `u32`.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn peachy_mls_verify_admitted_join_request(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    actor_id: *const c_char,
    device_id: *const c_char,
    proof: *const u8,
    proof_len: usize,
    key_package: *const u8,
    key_package_len: usize,
    out_verdict: *mut u32,
) -> i32 {
    guard(|| {
        if out_verdict.is_null() {
            return Err(null_argument("out_verdict"));
        }
        // Fail closed: ACCEPTED is 0. Every error below, and a caught panic,
        // leave a verdict that seats nobody.
        *out_verdict = PEACHY_MLS_JOIN_REQUEST_MALFORMED;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let actor_id = cstr_arg(actor_id, "actor_id")?;
        let device_id = cstr_arg(device_id, "device_id")?;
        let proof = slice_from(proof, proof_len, "proof")?;
        let key_package = slice_from(key_package, key_package_len, "key_package")?;
        *out_verdict = client
            .verify_admitted_join_request(group_id, actor_id, device_id, proof, key_package)
            .code();
        Ok(())
    })
}

/// Whether this is the first time this device has taken in this signed seat
/// ask for `group_id`: true once, then false for the same proof for as long as
/// the proof could still verify. Asked when a seat ask ARRIVES, before it is
/// queued, so a delivery service handing the same ask over again seats nobody
/// twice; never on a retry of an ask already taken in. A proof that does not
/// parse is false.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_first_sight_of_join_request(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    proof: *const u8,
    proof_len: usize,
    out_first: *mut bool,
) -> i32 {
    guard(|| {
        if out_first.is_null() {
            return Err(null_argument("out_first"));
        }
        // Fail closed: an error below, or a caught panic, leaves "taken in
        // before", which queues nothing.
        *out_first = false;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let proof = slice_from(proof, proof_len, "proof")?;
        *out_first = client.first_sight_of_join_request(group_id, proof)?;
        Ok(())
    })
}

/// Whether this device has already taken in this signed seat ask for
/// `group_id` ([`peachy_mls_first_sight_of_join_request`]), keeping no
/// record: for an ask that waits in a join inbox and is read again on every
/// pass until somebody acts on it. False for a proof that does not parse, is
/// stale, or is from too far ahead.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_join_request_seen(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    proof: *const u8,
    proof_len: usize,
    out_seen: *mut bool,
) -> i32 {
    guard(|| {
        if out_seen.is_null() {
            return Err(null_argument("out_seen"));
        }
        // Fail closed: an error below, or a caught panic, leaves "already
        // taken in", which acts on nothing.
        *out_seen = true;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let proof = slice_from(proof, proof_len, "proof")?;
        *out_seen = client.join_request_seen(group_id, proof)?;
        Ok(())
    })
}

/// How many groups this client currently holds state for.
///
/// Pairs with [`peachy_mls_group_id_at`], in the same two-call shape as
/// [`peachy_mls_group_member_count`] and [`peachy_mls_group_member`], because
/// a list of variable-length byte strings has no good single-call C shape that
/// does not invent an ownership rule this header would then have to explain.
///
/// The question it answers is "have I been here before" — a device that
/// restarted and is deciding whether a conversation needs a Welcome or merely
/// a stream replay. Local state only: a group this device has been added to
/// but has not yet claimed the Welcome for is not in here.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_count(
    client: *mut PeachyMlsClient,
    out_count: *mut usize,
) -> i32 {
    guard(|| {
        if out_count.is_null() {
            return Err(null_argument("out_count"));
        }
        let client = client_mut(client)?;
        *out_count = client.group_ids().len();
        Ok(())
    })
}

/// One group id, by position in the list [`peachy_mls_group_count`] sized.
///
/// The order is not specified and not stable across calls — it is a map's key
/// order. A caller enumerating the set must take the whole range without
/// mutating in between, which is the same contract the roster pair has.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_id_at(
    client: *mut PeachyMlsClient,
    position: usize,
    out_group_id: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let client = client_mut(client)?;
        let ids = client.group_ids();
        let id = ids.get(position).ok_or(Error::NoSuchGroup)?;
        write_buffer(out_group_id, "out_group_id", id.clone())
    })
}

/// Whether this client is still an active member of the group.
///
/// False means removed, or the group left — the state is still here and still
/// readable for history, but nothing can be sent to it and no commit will be
/// accepted from it.
///
/// An id this client holds no state for is [`PEACHY_MLS_ERR_NO_SUCH_GROUP`],
/// NOT `false`. The two are different questions and a caller that wants them
/// collapsed can collapse them; a door that answered `false` for both would
/// make "I was removed" and "I have never heard of this" indistinguishable,
/// and only one of those is fixed by claiming a Welcome.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_is_active(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    out_active: *mut bool,
) -> i32 {
    guard(|| {
        if out_active.is_null() {
            return Err(null_argument("out_active"));
        }
        let client = client_mut(client)?;
        // Not from a group another process has moved past (§A store two
        // processes share): reloads only when the store moved.
        client.refresh_if_moved()?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        *out_active = client.is_active(group_id)?;
        Ok(())
    })
}

/// The actor id (UTF-8) of the member whose commit seated this device in the
/// group by a Welcome — the Welcome's verified GroupInfo signer, kept with the
/// group's state. EMPTY for a group this device founded, or joined on a build
/// before this was kept. A Welcome from one of this account's own devices is
/// a linked device being seated, never this person being added back
/// (docs/account-store.md §Record values, **Leaving a group**). Freed with
/// [`peachy_mls_buffer_free`].
///
/// Empty too for a group this client does not hold.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_welcome_sender(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    out_actor_id: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let actor = client.welcome_sender(group_id)?.unwrap_or_default();
        write_buffer(out_actor_id, "out_actor_id", actor.into_bytes())
    })
}

/// The group's current epoch.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_epoch(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    out_epoch: *mut u64,
) -> i32 {
    guard(|| {
        if out_epoch.is_null() {
            return Err(null_argument("out_epoch"));
        }
        let client = client_mut(client)?;
        // Not from a group another process has moved past (§A store two
        // processes share): reloads only when the store moved.
        client.refresh_if_moved()?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        *out_epoch = client.epoch(group_id)?;
        Ok(())
    })
}

/// The OLDEST report a Welcome that restored or replaced `group_id` on this
/// device left, or a head contradicting its copy did, TAKEN: written into
/// `out_report` as a string list (a u32 big-endian count, then each item as
/// a u32 big-endian length and its UTF-8 bytes): the actor id of the member
/// who re-seated this device, then the device id of the device that did it
/// (empty when the Welcome named none), then `"1"` when the signer was a
/// device of this device's own person that it does not trust and `""`
/// otherwise, then a flags item of letters: `a` when the admins changed, `c`
/// when a head contradicted the copy before any matched it (the actor and
/// device are then empty). Then one item per actor: `+` and the actor for
/// each the new tree holds whom the roster this device last saw there did
/// not, `-` and the actor for each of that roster the new tree leaves out
/// (docs/delivery.md §A Welcome into a group this device knew), then
/// `~` and `actor device` for each device of a person the new tree keeps
/// that it leaves out, then `#` and the report's id, and `@` and the time
/// it was first peeked at, when it has them. An
/// EMPTY buffer when there is nothing left to tell. Each Welcome leaves its
/// own report, in order: call until the buffer is empty, and draw each as
/// its own lines in the conversation. Past 32 waiting, a new one is folded
/// into the newest, which then names only the later re-adder. Freed with
/// [`peachy_mls_buffer_free`].
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_take_rejoin_report(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    out_report: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        // Rule 5: this WRITES. A report taken is gone, so an answer refused
        // after the call is a line never drawn.
        require_out(out_report, "out_report")?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let bytes = client
            .take_rejoin_report(group_id)?
            .map(encode_rejoin_report)
            .unwrap_or_default();
        write_buffer(out_report, "out_report", bytes)
    })
}

/// A rejoin report as the string list [`peachy_mls_group_take_rejoin_report`]
/// and [`peachy_mls_group_peek_rejoin_report`] lay it out.
fn encode_rejoin_report(report: peachy_mls_core::RejoinReport) -> Vec<u8> {
    let mut flags = String::new();
    if report.admins_changed {
        flags.push('a');
    }
    if report.contested {
        flags.push('c');
    }
    let mut items = vec![
        report.readded_by,
        report.readded_by_device,
        if report.readded_by_untrusted { "1" } else { "" }.to_owned(),
        flags,
    ];
    items.extend(
        report
            .added_actors
            .into_iter()
            .map(|actor| format!("+{actor}")),
    );
    items.extend(
        report
            .departed_actors
            .into_iter()
            .map(|actor| format!("-{actor}")),
    );
    items.extend(
        report
            .dropped_devices
            .into_iter()
            .map(|(actor, device)| format!("~{actor} {device}")),
    );
    if report.id != 0 {
        items.push(format!("#{}", report.id));
    }
    if report.drawn_at_ms != 0 {
        items.push(format!("@{}", report.drawn_at_ms));
    }
    encode_string_list(&items)
}

/// The OLDEST rejoin report waiting for `group_id`, LEFT IN PLACE: the door
/// the apps draw through (docs/delivery.md §A Welcome into a group
/// this device knew). Laid out as [`peachy_mls_group_take_rejoin_report`]'s,
/// and always with a `#` item (the report's id) and an `@` item (the time
/// to draw it at, in Unix milliseconds: `now_ms` on the first peek of a
/// report, and that same time on every later one; absent only when
/// `now_ms` was 0 on every peek). Draw the report at that time, keyed so a
/// second draw rewrites the same lines, then drop it by its id
/// ([`peachy_mls_group_drop_rejoin_report`]) and peek again, until the
/// buffer is empty. A report not dropped is answered again after a restart.
/// Freed with [`peachy_mls_buffer_free`].
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_peek_rejoin_report(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    now_ms: u64,
    out_report: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_report, "out_report")?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let bytes = client
            .peek_rejoin_report(group_id, now_ms)?
            .map(encode_rejoin_report)
            .unwrap_or_default();
        write_buffer(out_report, "out_report", bytes)
    })
}

/// Drop the rejoin report [`peachy_mls_group_peek_rejoin_report`] answered
/// with `report_id`, once its lines are drawn. `out_dropped` receives whether
/// one was: false when none waiting has that id (another process drew and
/// dropped it first), which is no error.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_drop_rejoin_report(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    report_id: u64,
    out_dropped: *mut bool,
) -> i32 {
    guard(|| {
        require_out(out_dropped, "out_dropped")?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        *out_dropped = client.drop_rejoin_report(group_id, report_id)?;
        Ok(())
    })
}

/// Drop the roster [`peachy_mls_group_forget`] kept for `group_id`: for a
/// person who LEFT the group on purpose, so a later Welcome into the id is a
/// new invitation from whoever sends it rather than a rejoin drawn against
/// the old roster. The record of who left and any report not taken yet go
/// with it. A no-op when nothing is kept.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_forget_remembered_roster(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
) -> i32 {
    guard(|| {
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        client.forget_remembered_roster(group_id)
    })
}

// ---- Falling behind the delivery service's retention window -----------------

// A group this device does not hold is PEACHY_MLS_ERR_NO_SUCH_GROUP here, and
// each wrapper (Swift, Kotlin, wasm) turns that into `false`: every caller
// wants "not behind" there, and one that forgot the catch would turn a
// stranger id into a refusal to seal. (A plain comment, not a doc comment, so
// it stays out of the cbindgen header.)

/// Whether this group's local state is older than what the delivery service
/// still holds.
///
/// `server_oldest_epoch` is the oldest epoch the delivery service can still serve
/// (docs/delivery.md §Retention). Equality is NOT behind: a device
/// sitting at exactly the oldest retained epoch holds the one commit it needs.
///
/// THIS IS THE LOCAL SECOND OPINION, and it is why the flag on the wire is not
/// acted on alone. `FetchMailboxResponse.lost` is the server's arithmetic over
/// its own rows; this is the device's arithmetic over its own epoch. A client that
/// threw its group away on the server's word alone would be a client any
/// delivery service could make forget every group it holds, which is a good
/// deal more than a delivery service is trusted with.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_is_behind(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    server_oldest_epoch: u64,
    out_behind: *mut bool,
) -> i32 {
    guard(|| {
        if out_behind.is_null() {
            return Err(null_argument("out_behind"));
        }
        let client = client_mut(client)?;
        // Not from a group another process has moved past (§A store two
        // processes share): reloads only when the store moved.
        client.refresh_if_moved()?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        *out_behind = client.is_behind(group_id, server_oldest_epoch)?;
        Ok(())
    })
}

/// Whether failing to apply `message` strands this device in the group — off
/// the ratchet for good, exactly as if it had slept past the retention window
/// (docs/delivery.md §A commit this device cannot apply).
///
/// Asked AFTER [`peachy_mls_group_process_door`] refused a stream entry on the
/// commit door: true exactly when the message is the COMMIT at this device's
/// epoch that the commit door refused last AFTER it opened and verified (a
/// member built it, and this device's policy refused what the rest of the
/// group merged). A commit that did not open is false at any epoch, because
/// its framing is anyone's to write: the caller asks the group's head instead
/// (docs/delivery.md §A commit this device cannot apply). False too
/// for a commit from an epoch already left, anything that is not a commit,
/// bytes that do not parse, and a group this device holds no active state
/// for. A transient failure ([`PEACHY_MLS_ERR_STORAGE`]) is the caller's to
/// hold back on before asking this.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_commit_strands(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    message: *const u8,
    message_len: usize,
    out_strands: *mut bool,
) -> i32 {
    guard(|| {
        if out_strands.is_null() {
            return Err(null_argument("out_strands"));
        }
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let message = slice_from(message, message_len, "message")?;
        *out_strands = client.commit_strands(group_id, message)?;
        Ok(())
    })
}

// ---- The steward: stamps, the hold, vetoes, repair notices ------------------
//
// The steward key, not part of this specification. This build READS all of it and
// writes none of it: the stamp check only alerts, and the hold engages only in
// a group whose meta names a steward key, which no build writes.

/// Hand in the SEALED STAMP the delivery service attached to the commit about
/// to go through [`peachy_mls_group_process_door`] on the commit door for
/// `group_id` (`MailboxEnvelope.commit_stamp`; docs/delivery.md
/// §The sealed stamp). Kept in memory for that one commit; an empty stamp
/// hands in nothing.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_note_commit_stamp(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    stamp: *const u8,
    stamp_len: usize,
) -> i32 {
    guard(|| {
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let stamp = slice_from(stamp, stamp_len, "stamp")?;
        client.note_commit_stamp(group_id, stamp);
        Ok(())
    })
}

/// What the commit door found checking the last commit it merged in
/// `group_id` against its sealed stamp, TAKEN: UTF-8 JSON in `out_check`,
/// `{"epoch","stamp","mac","steward"}` and `"blame"` (an actor id) when the
/// committer is blamed; `stamp` is one of `absent`, `unopened`, `match`,
/// `blame`, `repair`, `unjudged`. An EMPTY buffer when no commit merged since
/// the last take. A caller only alerts on it in this build. Freed with
/// [`peachy_mls_buffer_free`].
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_take_commit_check(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    out_check: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_check, "out_check")?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let bytes = match client.take_commit_check(group_id) {
            None => Vec::new(),
            Some(check) => check.to_json().into_bytes(),
        };
        write_buffer(out_check, "out_check", bytes)
    })
}

/// The GROUP HOLD of `group_id`, when it holds now: UTF-8 JSON in `out_hold`,
/// `{"epoch","since","until","reason"}` (`reason` one of `RefusedCommit`,
/// `UnopenableCommit`, `FalseRepair`). An EMPTY buffer for none. While held, a
/// caller makes no commit of its own, links no device, answers no seat ask,
/// and every rejoin path waits. Freed with [`peachy_mls_buffer_free`].
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_hold(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    out_hold: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_hold, "out_hold")?;
        let client = client_mut(client)?;
        client.refresh_if_moved()?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let bytes = match client.group_hold(group_id)? {
            None => Vec::new(),
            Some(hold) => hold.to_json().into_bytes(),
        };
        write_buffer(out_hold, "out_hold", bytes)
    })
}

/// Hold `group_id` for its steward's repair or veto, for `reason` (1 a
/// refused commit, 2 an unopenable or lost one, 3 a false repair notice).
/// `out_held` is false, and nothing changes, for a group this device does
/// not count as enrolled (its meta's steward key is not the one the server's
/// sealed stamp named): such a group behaves as it always did. False too for
/// a hold that already lapsed or was released at the group's current epoch:
/// at most one hold an epoch, and the caller falls back to rejoining.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_enter_hold(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    reason: u32,
    out_held: *mut bool,
) -> i32 {
    guard(|| {
        if out_held.is_null() {
            return Err(null_argument("out_held"));
        }
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let reason = peachy_mls_core::steward::HoldReason::from_u32(reason)
            .ok_or_else(|| Error::InvalidArgument("a hold reason is 1, 2 or 3".into()))?;
        *out_held = client.enter_hold(group_id, reason)?;
        Ok(())
    })
}

/// Release the hold of `group_id`, if any: it lapses now and stays on
/// record, so the group is not held again at this epoch.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_release_hold(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
) -> i32 {
    guard(|| {
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        client.release_hold(group_id)
    })
}

/// What a commit entry's VETO FRAME means to this device, in `out_verdict`:
/// 0 nothing (no frame, or one that does not verify under the steward key the
/// group held at the vetoed epoch), 1 a valid veto of the commit at this
/// device's own epoch (skip the vetoed commit and take this one), 2 a valid
/// veto of a commit this device already merged (rejoin now), 3 a valid veto
/// of an epoch whose successor this copy keeps no verifier for, more than 63
/// epochs back or before its seat (read the group's head now, through the
/// fork check; never a rejoin on the frame's word).
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_judge_veto(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    entry: *const u8,
    entry_len: usize,
    out_verdict: *mut u32,
) -> i32 {
    guard(|| {
        if out_verdict.is_null() {
            return Err(null_argument("out_verdict"));
        }
        let client = client_mut(client)?;
        client.refresh_if_moved()?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let entry = slice_from(entry, entry_len, "entry")?;
        *out_verdict = client.judge_veto(group_id, entry)? as u32;
        Ok(())
    })
}

/// Judge a REPAIR NOTICE lane frame (`wire`, its UTF-8 JSON) from `sender`
/// (the MLS sender's actor id, UTF-8, as the message door reported it)
/// against the verifier this device's copy had at its epoch, in
/// `out_verdict`: 0 consistent, 1 inconsistent (an admin repointing the
/// head: alert, and an enrolled group is held, at most once an epoch), 2
/// nothing to judge (not a repair notice, a sender the group does not name
/// as an admin, or no verifier kept for that epoch).
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_check_repair_notice(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    sender: *const u8,
    sender_len: usize,
    wire: *const u8,
    wire_len: usize,
    out_verdict: *mut u32,
) -> i32 {
    guard(|| {
        if out_verdict.is_null() {
            return Err(null_argument("out_verdict"));
        }
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let sender = std::str::from_utf8(slice_from(sender, sender_len, "sender")?)
            .map_err(|_| Error::InvalidArgument("sender is not UTF-8".into()))?;
        let wire = slice_from(wire, wire_len, "wire")?;
        *out_verdict = client.check_repair_notice(group_id, sender, wire)? as u32;
        Ok(())
    })
}

/// Open FetchCommitAt's `sealed_commit` for the commit built at this device's
/// epoch of `group_id`, with that epoch's send key: the commit envelope as it
/// was placed, in `out_envelope`, which the caller opens and takes through
/// the commit door like any other (FetchCommitAt, not part of this specification).
/// [`PEACHY_MLS_ERR_INVALID_ARGUMENT`] for a copy that does not open. Freed with [`peachy_mls_buffer_free`].
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_open_fetched_commit(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    sealed: *const u8,
    sealed_len: usize,
    out_envelope: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_envelope, "out_envelope")?;
        let client = client_mut(client)?;
        client.refresh_if_moved()?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let sealed = slice_from(sealed, sealed_len, "sealed")?;
        let envelope = client.open_fetched_commit(group_id, sealed)?;
        write_buffer(out_envelope, "out_envelope", envelope)
    })
}

/// Drop every trace of a group from this device.
///
/// The other half of the rejoin, and everything it does is LOCAL — which is
/// the point: a device off the ratchet cannot sign a Remove of its own leaf
/// that anybody would accept, so forgetting is the only move it has. The state
/// goes from storage and not merely from the open map, so the Welcome a live
/// member's [`peachy_mls_group_replace_member`] mints can create the group
/// fresh rather than collide with the stale copy.
///
/// [`PEACHY_MLS_ERR_NO_SUCH_GROUP`] for a group this client does not hold: the
/// caller asking is a caller who believed it held one.
///
/// It KEEPS the people this device last saw in the group, when they name
/// anybody but this device's own person, until a copy in the id is
/// confirmed; each person it sees leave in the meantime is dropped from
/// them, and nobody is added. A later Welcome into the id is drawn against
/// them: who was added, who is gone, whether the admins changed
/// ([`peachy_mls_group_take_rejoin_report`]). They refuse nobody
/// (docs/delivery.md §A Welcome into a group this device knew).
/// Reports not taken yet are kept too. A person leaving on purpose calls
/// [`peachy_mls_group_forget_remembered_roster`] after this.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_forget(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
) -> i32 {
    guard(|| {
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        client.forget_group(group_id)
    })
}

// ---- Messages --------------------------------------------------------------

/// Encrypt an application message under the default content hint (0, show
/// the loss): no message leaves without one.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_encrypt(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    out_message: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        // Rule 5, and the sharpest of the five: encrypting ADVANCES THE SENDER
        // RATCHET and persists the advance. Throwing the ciphertext away burns
        // a generation nothing will ever use — which is not itself unsafe, but
        // it is a message the caller believes it sent and nobody will receive.
        require_out(out_message, "out_message")?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let plaintext = slice_from(plaintext, plaintext_len, "plaintext")?;
        let bytes = client.encrypt(group_id, plaintext)?;
        write_buffer(out_message, "out_message", bytes)
    })
}

/// Encrypt an application message carrying a content hint: 0 show the loss,
/// 1 ask for it again, 2 show nothing, 3 ask for a lane frame again
/// (docs/sealed-messages.md §Content hints).
/// Any other `hint` is [`PEACHY_MLS_ERR_INVALID_ARGUMENT`].
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_encrypt_with_hint(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    hint: u8,
    out_message: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        // As `peachy_mls_group_encrypt`: the ratchet has moved once this runs.
        require_out(out_message, "out_message")?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let plaintext = slice_from(plaintext, plaintext_len, "plaintext")?;
        let bytes = client.encrypt_with_hint(group_id, plaintext, hint)?;
        write_buffer(out_message, "out_message", bytes)
    })
}

/// Read a group message's epoch and content hint with no key and no client:
/// what a receiver needs about a message that will not open. `out_epoch` is -1
/// for bytes that are not a group message; `out_hint` is -1 when the message
/// carries no hint this build knows.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_peek_message(
    message: *const u8,
    message_len: usize,
    out_epoch: *mut i64,
    out_hint: *mut i32,
) -> i32 {
    guard(|| {
        if out_epoch.is_null() {
            return Err(null_argument("out_epoch"));
        }
        if out_hint.is_null() {
            return Err(null_argument("out_hint"));
        }
        let message = slice_from(message, message_len, "message")?;
        let peek = peachy_mls_core::hint::peek_message(message);
        *out_epoch = peek
            .map(|p| i64::try_from(p.epoch).unwrap_or(i64::MAX))
            .unwrap_or(-1);
        *out_hint = peek.and_then(|p| p.hint).map(i32::from).unwrap_or(-1);
        Ok(())
    })
}

/// What [`peachy_mls_group_process_door`] found.
///
/// Every buffer in here is owned by the caller and must go to
/// [`peachy_mls_buffer_free`] — or, in one call,
/// [`peachy_mls_incoming_free`].
#[repr(C)]
pub struct PeachyMlsIncoming {
    /// One of the `PEACHY_MLS_INCOMING_*` constants.
    pub kind: i32,
    /// The sender's `actor_id`. Empty for [`PEACHY_MLS_INCOMING_ECHO`].
    pub sender_actor_id: PeachyMlsBuffer,
    /// The sender's `device_id`. Empty for [`PEACHY_MLS_INCOMING_ECHO`].
    pub sender_device_id: PeachyMlsBuffer,
    /// The decrypted message. Only for [`PEACHY_MLS_INCOMING_APPLICATION`].
    pub plaintext: PeachyMlsBuffer,
    /// The `ProposalKind` code. Only for [`PEACHY_MLS_INCOMING_PROPOSAL`].
    pub proposal_kind: u32,
    /// Whether the commit removed this device. Only for
    /// [`PEACHY_MLS_INCOMING_COMMIT`]; after it, the group is inactive.
    pub removed_self: bool,
    /// The epoch after processing.
    pub epoch: u64,
    /// The people the commit took out because they LEFT: each proposed the
    /// removal of their own leaves, and the commit removed every one
    /// (`peachy_mls_core::CommitOutcome::left`). A string list as
    /// [`encode_string_list`] writes it, sorted actor ids; empty when nobody
    /// left. Only for [`PEACHY_MLS_INCOMING_COMMIT`].
    pub left_actor_ids: PeachyMlsBuffer,
}

impl PeachyMlsIncoming {
    fn blank() -> Self {
        Self {
            kind: PEACHY_MLS_INCOMING_ECHO,
            sender_actor_id: PeachyMlsBuffer::empty(),
            sender_device_id: PeachyMlsBuffer::empty(),
            plaintext: PeachyMlsBuffer::empty(),
            proposal_kind: 0,
            removed_self: false,
            epoch: 0,
            left_actor_ids: PeachyMlsBuffer::empty(),
        }
    }
}

/// **DEPRECATED: use [`peachy_mls_group_process_mailbox_entry`].** This door
/// trusts the caller to pick it, and a caller that picks it from the sealed
/// kind alone takes a commit the delivery service never ordered (one sealed
/// into an ordinary mailbox entry). The mailbox door takes the entry's
/// mailbox kind beside the sealed kind and refuses that. This one stays,
/// unchanged, for code written against it, and will go in a later ABI
/// version.
///
/// Process one incoming group message through one DOOR: the message door
/// ([`PEACHY_MLS_DOOR_MESSAGE`], application messages, and the one proposal
/// a member takes, a LEAVE, see [`peachy_mls_group_propose_leave`]) or the
/// commit door ([`PEACHY_MLS_DOOR_COMMIT`], commits only). Bytes of the other
/// kind, and any other proposal, are refused with
/// [`PEACHY_MLS_ERR_WRONG_DOOR`], so nothing moves. There is no doorless form: a
/// commit that arrived as a message must never be merged off the commit path
/// (`peachy_mls_core::Client::process_message` says why).
///
/// A commit is merged before this returns, so the roster and epoch are already
/// the new ones. A commit that group policy refuses returns
/// [`PEACHY_MLS_ERR_POLICY`] and changes nothing.
///
/// Richer commit detail — who exactly was added — is deliberately not here.
/// Re-read the roster with [`peachy_mls_group_member_count`] and
/// [`peachy_mls_group_member`]; a variable-length list of identities across
/// this boundary is three ownership rules for something a caller can ask for
/// directly.
///
/// `received_at` is the second the delivery service received the message
/// (the mailbox envelope's `received_at`), Unix seconds, or `0` when the
/// caller does not know it; only the message door reads it
/// (`peachy_mls_core::Client::process_message_received_at`). A message from
/// a device whose account signed it out, which this device holds
/// ([`peachy_mls_stale_leaf_removable`]), is read only when it was received
/// before the revocation took effect, and `0` counts as after: refused with
/// [`PEACHY_MLS_ERR_NOT_FROM_A_MEMBER`].
///
/// # Safety
/// `out_incoming` must point to writable storage for one `PeachyMlsIncoming`.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_process_door(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    message: *const u8,
    message_len: usize,
    door: u32,
    received_at: i64,
    out_incoming: *mut PeachyMlsIncoming,
) -> i32 {
    guard(|| {
        if out_incoming.is_null() {
            return Err(null_argument("out_incoming"));
        }
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let message = slice_from(message, message_len, "message")?;
        let incoming = match door {
            PEACHY_MLS_DOOR_MESSAGE => {
                client.process_message_received_at(group_id, message, received_at)?
            }
            PEACHY_MLS_DOOR_COMMIT => client.process_commit(group_id, message)?,
            other => return Err(Error::InvalidArgument(format!("unknown door {other}"))),
        };
        *out_incoming = incoming_out(client, group_id, incoming);
        Ok(())
    })
}

/// THE MAILBOX DOOR: one opened mailbox entry, routed by BOTH the kind the
/// delivery service put on the entry (`mailbox_kind`:
/// [`PEACHY_MLS_MAILBOX_KIND_MLS`] or [`PEACHY_MLS_MAILBOX_KIND_COMMIT`]) and
/// the kind sealed inside it (`envelope_kind`, what
/// [`peachy_mls_open_envelope`] answered), never one of them alone
/// (`peachy_mls_core::Client::process_mailbox_entry`). A commit is taken only
/// from a COMMIT entry, one the arbiter ordered, and a message only from an
/// MLS entry; anything else, a commit sealed into an MLS entry included, is
/// refused with [`PEACHY_MLS_ERR_WRONG_DOOR`] before the engine reads it, so
/// nothing moves. A seat ask and a call signal are refused too: they are not
/// group messages ([`peachy_mls_envelope_door`] says which reader takes
/// them). Use this, not [`peachy_mls_group_process_door`] (deprecated),
/// whose door the caller picks: picking it from the envelope kind alone
/// loses the check.
///
/// # Safety
/// As [`peachy_mls_group_process_door`].
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_process_mailbox_entry(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    mailbox_kind: u32,
    envelope_kind: u8,
    inner: *const u8,
    inner_len: usize,
    received_at: i64,
    out_incoming: *mut PeachyMlsIncoming,
) -> i32 {
    guard(|| {
        if out_incoming.is_null() {
            return Err(null_argument("out_incoming"));
        }
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let inner = slice_from(inner, inner_len, "inner")?;
        let incoming = client.process_mailbox_entry(
            group_id,
            mailbox_kind,
            envelope_kind,
            inner,
            received_at,
        )?;
        *out_incoming = incoming_out(client, group_id, incoming);
        Ok(())
    })
}

/// Which path an opened mailbox entry takes, from the kind the delivery
/// service put on the entry and the kind sealed inside it
/// (`peachy_mls_core::envelope::envelope_door`): one of the
/// `PEACHY_MLS_ENVELOPE_DOOR_*` codes. A commit only from a COMMIT entry; a
/// message, a seat ask or a call signal only from an MLS entry; anything else
/// [`PEACHY_MLS_ENVELOPE_DOOR_DROP`] (acknowledged unread). A code this build
/// does not know is to be read as a drop.
#[no_mangle]
pub extern "C" fn peachy_mls_envelope_door(mailbox_kind: u32, envelope_kind: u8) -> u32 {
    peachy_mls_core::envelope::envelope_door(mailbox_kind, envelope_kind) as u32
}

/// The delivery service's `MAILBOX_KIND_MLS`: an envelope of anything but a commit.
pub const PEACHY_MLS_MAILBOX_KIND_MLS: u32 = 1;
/// The delivery service's `MAILBOX_KIND_COMMIT`: a commit the arbiter ordered.
pub const PEACHY_MLS_MAILBOX_KIND_COMMIT: u32 = 5;
// Spelled as literals so the header names them; held to the core's here.
const _: () = assert!(
    PEACHY_MLS_MAILBOX_KIND_MLS == peachy_mls_core::envelope::MAILBOX_KIND_MLS
        && PEACHY_MLS_MAILBOX_KIND_COMMIT == peachy_mls_core::envelope::MAILBOX_KIND_COMMIT
);
/// [`peachy_mls_envelope_door`]: acknowledge it unread.
pub const PEACHY_MLS_ENVELOPE_DOOR_DROP: u32 = 0;
/// [`peachy_mls_envelope_door`]: the message door.
pub const PEACHY_MLS_ENVELOPE_DOOR_MESSAGE: u32 = 1;
/// [`peachy_mls_envelope_door`]: the commit door.
pub const PEACHY_MLS_ENVELOPE_DOOR_COMMIT: u32 = 2;
/// [`peachy_mls_envelope_door`]: a seat ask.
pub const PEACHY_MLS_ENVELOPE_DOOR_SEAT_ASK: u32 = 3;
/// [`peachy_mls_envelope_door`]: call signaling.
pub const PEACHY_MLS_ENVELOPE_DOOR_CALL: u32 = 4;

/// The message door ([`PEACHY_MLS_DOOR_MESSAGE`]) for the message inside
/// mailbox envelope `envelope_id` (UTF-8, NUL-terminated), with what an
/// application message opens to kept in the same write that spends its key
/// until [`peachy_mls_release_opened`]: the same envelope handed over again,
/// after the app died before storing it, answers the same words rather than
/// a duplicate (`peachy_mls_core::Client::process_message_as`). An empty id
/// keeps nothing. `received_at` is as [`peachy_mls_group_process_door`]'s
/// (`peachy_mls_core::Client::process_message_as_received_at`).
///
/// # Safety
/// As [`peachy_mls_group_process_door`].
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_process_message_as(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    message: *const u8,
    message_len: usize,
    envelope_id: *const c_char,
    received_at: i64,
    out_incoming: *mut PeachyMlsIncoming,
) -> i32 {
    guard(|| {
        if out_incoming.is_null() {
            return Err(null_argument("out_incoming"));
        }
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let message = slice_from(message, message_len, "message")?;
        let envelope_id = cstr_arg(envelope_id, "envelope_id")?;
        let incoming =
            client.process_message_as_received_at(group_id, message, envelope_id, received_at)?;
        *out_incoming = incoming_out(client, group_id, incoming);
        Ok(())
    })
}

/// The app's own copy of what envelope `envelope_id` (UTF-8, NUL-terminated)
/// opened to is stored: what [`peachy_mls_group_process_message_as`] kept of
/// it goes. Call it for every envelope acknowledged. `out_released` is true
/// when anything was kept.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_release_opened(
    client: *mut PeachyMlsClient,
    envelope_id: *const c_char,
    out_released: *mut bool,
) -> i32 {
    guard(|| {
        require_out(out_released, "out_released")?;
        let client = client_mut(client)?;
        let envelope_id = cstr_arg(envelope_id, "envelope_id")?;
        *out_released = client.release_opened(envelope_id)?;
        Ok(())
    })
}

/// [`peachy_mls_release_opened`] for many envelopes in ONE WRITE
/// (`peachy_mls_core::Client::release_opened_all`): `envelope_ids` is
/// `envelope_ids_len` bytes of UTF-8 ids, each followed by a NUL. A page's
/// acknowledged envelopes go together, so the page ends one write rather
/// than one per envelope. `out_released` is how many held a record.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_release_opened_all(
    client: *mut PeachyMlsClient,
    envelope_ids: *const u8,
    envelope_ids_len: usize,
    out_released: *mut u32,
) -> i32 {
    guard(|| {
        require_out(out_released, "out_released")?;
        let client = client_mut(client)?;
        let bytes = slice_from(envelope_ids, envelope_ids_len, "envelope_ids")?;
        let text = std::str::from_utf8(bytes)
            .map_err(|_| Error::InvalidArgument("envelope_ids is not UTF-8".into()))?;
        let ids: Vec<&str> = text.split_terminator('\0').collect();
        let released = client.release_opened_all(&ids)?;
        *out_released = u32::try_from(released).unwrap_or(u32::MAX);
        Ok(())
    })
}

/// The message door: [`peachy_mls_group_process_door`] takes only an
/// application message.
pub const PEACHY_MLS_DOOR_MESSAGE: u32 = 1;
/// The commit door: [`peachy_mls_group_process_door`] takes only a commit.
pub const PEACHY_MLS_DOOR_COMMIT: u32 = 2;

/// What a door answered, in the C shape.
fn incoming_out(client: &mut Client, group_id: &[u8], incoming: Incoming) -> PeachyMlsIncoming {
    let epoch = client.epoch(group_id).unwrap_or(0);

    let mut out = PeachyMlsIncoming::blank();
    out.epoch = epoch;
    match incoming {
        Incoming::Application { sender, plaintext } => {
            out.kind = PEACHY_MLS_INCOMING_APPLICATION;
            out.sender_actor_id = PeachyMlsBuffer::from_vec(sender.actor_id.into_bytes());
            out.sender_device_id = PeachyMlsBuffer::from_vec(sender.device_id.into_bytes());
            out.plaintext = PeachyMlsBuffer::from_vec(plaintext);
        }
        Incoming::ProposalQueued { sender, kind } => {
            out.kind = PEACHY_MLS_INCOMING_PROPOSAL;
            out.sender_actor_id = PeachyMlsBuffer::from_vec(sender.actor_id.into_bytes());
            out.sender_device_id = PeachyMlsBuffer::from_vec(sender.device_id.into_bytes());
            out.proposal_kind = kind.code();
        }
        Incoming::Commit(outcome) => {
            out.kind = PEACHY_MLS_INCOMING_COMMIT;
            out.sender_actor_id = PeachyMlsBuffer::from_vec(outcome.sender.actor_id.into_bytes());
            out.sender_device_id = PeachyMlsBuffer::from_vec(outcome.sender.device_id.into_bytes());
            out.removed_self = outcome.removed_self;
            out.epoch = outcome.epoch;
            out.left_actor_ids = PeachyMlsBuffer::from_vec(encode_string_list(&outcome.left));
        }
        Incoming::Echo => {
            out.kind = PEACHY_MLS_INCOMING_ECHO;
        }
    }
    out
}

/// Free every buffer inside a [`PeachyMlsIncoming`], in one call.
///
/// # Safety
/// `incoming` must be null or point to a `PeachyMlsIncoming` this library
/// filled in and that has not already been freed.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_incoming_free(incoming: *mut PeachyMlsIncoming) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if incoming.is_null() {
            return;
        }
        let incoming = &mut *incoming;
        peachy_mls_buffer_free(&mut incoming.sender_actor_id);
        peachy_mls_buffer_free(&mut incoming.sender_device_id);
        peachy_mls_buffer_free(&mut incoming.plaintext);
        peachy_mls_buffer_free(&mut incoming.left_actor_ids);
    }));
}

/// Derive a secret from the current epoch (RFC 9420 §8.5).
///
/// `label` is a NUL-terminated string and namespaces the secret: two features
/// exporting under different labels cannot derive each other's.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_export_secret(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    label: *const c_char,
    context: *const u8,
    context_len: usize,
    length: usize,
    out_secret: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        if label.is_null() {
            return Err(null_argument("label"));
        }
        let label = CStr::from_ptr(label)
            .to_str()
            .map_err(|_| Error::InvalidArgument("label is not UTF-8".into()))?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        // An empty context is normal and is not the same as a missing one, so
        // a null pointer with zero length is accepted here.
        let context = if context.is_null() && context_len == 0 {
            &[][..]
        } else {
            slice_from(context, context_len, "context")?
        };
        // Not from a group the notification extension has moved past (a
        // typing frame sealed under an epoch a removal left would stay
        // readable by the removed member).
        client.refresh_if_moved()?;
        let secret = client.export_secret(group_id, label, context, length)?;
        write_buffer(out_secret, "out_secret", secret)
    })
}

/// Seal this device's typing frame for a group at its current epoch, signed
/// by its leaf and stamped (docs/sealed-messages.md §Typing inside
/// the group): the inner bytes of a kind-4 envelope.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_typing_seal(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    typing: bool,
    out_frame: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_frame, "out_frame")?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        // As the export door: never under an epoch the notification
        // extension has moved past.
        client.catch_up_with_store()?;
        let frame = client.seal_typing(group_id, typing)?;
        write_buffer(out_frame, "out_frame", frame)
    })
}

/// Open a typing frame for a group: `{"actorId","typing"}`, or
/// `null` for a frame to drop (another epoch, a forged author, a replay,
/// outside two minutes). A device's own person comes back too; the caller
/// drops it by name.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_typing_open(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    frame: *const u8,
    frame_len: usize,
    out_json: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_json, "out_json")?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let frame = slice_from(frame, frame_len, "frame")?;
        client.catch_up_with_store()?;
        let opened = client.open_typing_json(group_id, frame)?;
        write_buffer(out_json, "out_json", opened.into_bytes())
    })
}

/// The author's commitment a group message carries (16 bytes), read with no
/// key, or an empty buffer when it carries none
/// (docs/sealed-messages.md §Asking for a message again).
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_peek_commitment(
    message: *const u8,
    message_len: usize,
    out_commitment: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_commitment, "out_commitment")?;
        let message = slice_from(message, message_len, "message")?;
        let commitment = peachy_mls_core::hint::peek_message(message)
            .and_then(|peek| peek.commitment)
            .map(|c| c.to_vec())
            .unwrap_or_default();
        write_buffer(out_commitment, "out_commitment", commitment)
    })
}

/// The commitment to `actor_id` (NUL-terminated) as the author of a message
/// whose secret is `secret`, in `group_id`: 16 bytes. An answer to a resend
/// ask is taken only when this, for its MLS sender and the secret it
/// carries, equals what the unopened message carried.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_resend_author_commitment(
    group_id: *const u8,
    group_id_len: usize,
    actor_id: *const c_char,
    secret: *const u8,
    secret_len: usize,
    out_commitment: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_commitment, "out_commitment")?;
        if actor_id.is_null() {
            return Err(null_argument("actor_id"));
        }
        let actor_id = CStr::from_ptr(actor_id)
            .to_str()
            .map_err(|_| Error::InvalidArgument("actor_id is not UTF-8".into()))?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let secret = slice_from(secret, secret_len, "secret")?;
        let commitment =
            peachy_mls_core::hint::resend_author_commitment(group_id, actor_id, secret);
        write_buffer(out_commitment, "out_commitment", commitment.to_vec())
    })
}

/// Derive a secret from the epoch this client's STAGED commit would move the
/// group to, before the commit is merged (RFC 9420 §8.5 over the staged
/// epoch's exporter secret). `SubmitCommit` carries the next epoch's send-key
/// verifier in the same request as the commit
/// (docs/delivery.md §SubmitCommit), and this is where the committer gets it.
/// Fails when nothing is staged.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_export_pending_secret(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    label: *const c_char,
    context: *const u8,
    context_len: usize,
    length: usize,
    out_secret: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        if label.is_null() {
            return Err(null_argument("label"));
        }
        let label = CStr::from_ptr(label)
            .to_str()
            .map_err(|_| Error::InvalidArgument("label is not UTF-8".into()))?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let context = if context.is_null() && context_len == 0 {
            &[][..]
        } else {
            slice_from(context, context_len, "context")?
        };
        // Not from a group the notification extension has moved past, as at
        // `peachy_mls_group_export_secret`.
        client.refresh_if_moved()?;
        let secret = client.export_pending_secret(group_id, label, context, length)?;
        write_buffer(out_secret, "out_secret", secret)
    })
}

// ---- Calls (docs/calls.md §Keys, §Signaling, §Ringing) ----------------
//
// Signals cross this door as JSON text in the form `mls/fixtures/calls.json`
// pins (`{"version":1,"callId":"<32 hex>","type":"offer",…}`), so every
// wrapper reads the same shape the fixture replays and no wrapper re-implements
// the protobuf.

/// Read an optional NUL-terminated JSON argument; null reads as `"null"`.
unsafe fn json_arg_or_null<'a>(ptr: *const c_char, name: &str) -> Result<&'a str, Error> {
    if ptr.is_null() {
        Ok("null")
    } else {
        cstr_arg(ptr, name)
    }
}

/// A call's frame-encryption keys at the group's current epoch, or (with
/// `pending`) at the epoch this client's STAGED commit moves it to.
///
/// `out_keys` receives `epoch u64be ‖ key_index u8 ‖ call_root[32] ‖
/// count u32be ‖ (leaf_index u32be ‖ sender_key[16])*`, one entry per leaf in
/// leaf order. Each sender key goes into the frame encryptor's key provider at
/// slot `key_index` for that participant; the provider derives the AES key
/// with HKDF under the ratchet salt `"peachy call frame v1"`
/// ([`peachy_mls_call_frame_key`] is that derivation, for a client that
/// encrypts frames itself).
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_call_keys(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    call_id: *const u8,
    call_id_len: usize,
    pending: bool,
    out_keys: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_keys, "out_keys")?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let call_id = slice_from(call_id, call_id_len, "call_id")?;
        // Not from a group the notification extension has moved past (a
        // removal it processed would otherwise keep the removed leaf's key).
        client.refresh_if_moved()?;
        let keys = if pending {
            client.pending_call_keys(group_id, call_id)?
        } else {
            client.call_keys(group_id, call_id)?
        };
        write_buffer(out_keys, "out_keys", keys.to_bytes())
    })
}

/// Seal a call signal (JSON form) for `group_id`: the whole kind-6 envelope,
/// ready for `SendSealed`. `Offer`, `Answer`, `Hangup`, `Remove`, `Direct`
/// and the in-call controls (`RaiseHand`, `React`, `RemoteMute`, `Media`,
/// `MediaKey`) go as an MLS application message (this advances the sender
/// ratchet and persists, like [`peachy_mls_group_encrypt`]) that is as long as
/// a message of the same padding block; every `Left` goes that way too, and `Joined` as a live frame.
/// [`peachy_mls_call_signal_is_urgent`] says which are sent `urgent`.
///
/// On participant media keys a `Left` always goes signed, and only one naming
/// this device's current participation ends its media keys; one naming a
/// participant id it held before (a rejoin's old one) leaves them alone.
/// After its own `Left` ended them, a `Joined` is refused until `start` or
/// `end` (docs/calls.md §Participant media keys).
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_call_seal(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    signal_json: *const c_char,
    out_envelope: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_envelope, "out_envelope")?;
        let signal_json = cstr_arg(signal_json, "signal_json")?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        // The live lane reads the key and the tree from memory: never from a
        // group the notification extension has moved past, or a member its
        // commit removed would still read this device's heartbeats.
        client.refresh_if_moved()?;
        let sealed = client.seal_call_signal_json(group_id, signal_json)?;
        write_buffer(out_envelope, "out_envelope", sealed)
    })
}

/// Seal ANY call signal (JSON form) on the MLS lane, sender-authenticated: a
/// participant's first `Joined` in each epoch goes this way so receivers bind
/// its tracks to its own leaf (docs/calls.md §Disagreements,
/// D10). Send it through `SendSealed`, not urgent.
///
/// On participant media keys a `Left` always goes signed, and only one naming
/// this device's current participation ends its media keys; one naming a
/// participant id it held before (a rejoin's old one) leaves them alone.
/// After its own `Left` ended them, a `Joined` is refused until `start` or
/// `end` (docs/calls.md §Participant media keys).
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_call_seal_signed(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    signal_json: *const c_char,
    out_envelope: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_envelope, "out_envelope")?;
        let signal_json = cstr_arg(signal_json, "signal_json")?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        // As for the live seal: from the group the store holds.
        client.refresh_if_moved()?;
        let sealed = client.seal_call_signal_on_mls_lane_json(group_id, signal_json)?;
        write_buffer(out_envelope, "out_envelope", sealed)
    })
}

/// The stagger of a participant's in-call self-updates: it commits its own
/// `self_update` at `joined + offset + k * 600 s`. `rank` is its position
/// among the participants by ascending leaf index, `participants` their
/// count (docs/calls.md, R-K4).
///
/// # Safety
/// `out_offset_ms` must point to writable storage for one `u64`.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_call_self_update_offset_ms(
    rank: u32,
    participants: u32,
    out_offset_ms: *mut u64,
) -> i32 {
    guard(|| {
        if out_offset_ms.is_null() {
            return Err(null_argument("out_offset_ms"));
        }
        *out_offset_ms = peachy_mls_core::call::call_self_update_offset_ms(rank, participants);
        Ok(())
    })
}

/// Open a kind-6 envelope's inner bytes (what [`peachy_mls_open_envelope`]
/// returned). `out_json` receives UTF-8 JSON
/// `{"lane":"mls"|"live","sender":{"actorId","deviceId"}|null,"senderLeaf":n|null,"urgent":bool,"signal":{…},"send":[hex…],"media":{…}|null,"unboundLeaf":n|null,"applyAfterMs":n|null,"applied":bool}`.
/// An MLS-lane signal is attributed (and a signed `Joined` must name its
/// sender's own leaf, and with a call key it keeps the participant id its
/// participation is bound under); a live-lane one names no sender, and a live frame carrying a
/// signal that must be signed (a hangup, an offer, a `Left`) is refused. `send` lists
/// the envelopes a v2 participant owes now (grants to a newcomer, or a
/// rotation after a leaver), to send through `SendSealed`, not urgent, in
/// order; `media` is what a `MediaKey` granted this device
/// (docs/calls.md §Participant media keys); `unboundLeaf` is the
/// leaf a signed `Left` unbound (its sender's own), the only leaf a client
/// drops a tile at for it. A signed `Left` naming any participant but its
/// sender's own is refused. `applyAfterMs` and `applied` say, as the
/// media door's answers do, when this device's pending rotation switches
/// and whether the core switched it at this open.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_call_open(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    inner: *const u8,
    inner_len: usize,
    out_json: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_json, "out_json")?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        let inner = slice_from(inner, inner_len, "inner")?;
        // A live frame opens under the key and tree in memory: never those
        // of a group the notification extension has moved past, or a member
        // its commit removed would still be heard.
        client.refresh_if_moved()?;
        let opened = client.open_call_signal_json(group_id, inner)?;
        write_buffer(out_json, "out_json", opened.into_bytes())
    })
}

/// A v2 call's participant media keys (docs/calls.md §Participant
/// media keys), one JSON request in and one JSON answer out:
/// `{"op":"start","callId","participantId","sessionId","trackNames"}` →
/// `{"mediaKeyHex"}` (`participantId` is the server's answer to JoinCall);
/// `{"op":"share","callId"}` → `{"send":[hex…]}`;
/// `{"op":"remove","callId","participantId"}` (an admin's honored `Remove`:
/// the id is never bound again in this call) or
/// `{"op":"remove","callId","leafIndex"}` → `{"send":[hex…]}`;
/// `{"op":"epoch","callId"}` (on every epoch change: a commit that removed a
/// participant rotates like a leave) → `{"send":[hex…]}`;
/// `{"op":"apply","callId"}` → `{"send":[hex…]}`; `{"op":"end","callId"}` → `{}`;
/// `{"op":"keys","callId","pending"?}` →
/// `{"epoch","ownLeaf","sendKeyIndex","senders":[{"leafIndex","generation","keyIndex","senderKeyHex"}],"participants":[…]}`.
/// `keys`, like sealing a `Joined`, fails with "call state lost" when this
/// core holds no participation in the call (it was rebuilt): the client
/// joins again (`start` under the id it holds, a signed `Joined`, `share`).
/// Every answer but `start`'s and `end`'s also carries `applyAfterMs` (ms
/// until a pending rotation switches, null when none is pending) and
/// `applied` (the core switched this device's sending key since a door last
/// said so). The core switches by itself at the first door call at or after
/// the due time; `apply` is only a door to knock at then.
/// Each `send` entry is a whole kind-6 envelope for `SendSealed`, not urgent.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_group_call_media(
    client: *mut PeachyMlsClient,
    group_id: *const u8,
    group_id_len: usize,
    request_json: *const c_char,
    out_json: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_json, "out_json")?;
        let request_json = cstr_arg(request_json, "request_json")?;
        let client = client_mut(client)?;
        let group_id = slice_from(group_id, group_id_len, "group_id")?;
        // As for the call keys: answer from the group the store holds.
        client.refresh_if_moved()?;
        let answer = client.call_media_json(group_id, request_json)?;
        write_buffer(out_json, "out_json", answer.into_bytes())
    })
}

/// Encode a call signal (JSON form) to its protobuf bytes. Needs no client.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_call_signal_encode(
    signal_json: *const c_char,
    out_bytes: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_bytes, "out_bytes")?;
        let signal =
            peachy_mls_core::call::signal_from_json(cstr_arg(signal_json, "signal_json")?)?;
        let bytes = peachy_mls_core::call::encode_call_signal(&signal)?;
        write_buffer(out_bytes, "out_bytes", bytes)
    })
}

/// Decode a call signal's protobuf bytes to its JSON form. Unknown fields are
/// skipped and an unknown message type reads as `"type":"unknown"`.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_call_signal_decode(
    bytes: *const u8,
    bytes_len: usize,
    out_json: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_json, "out_json")?;
        let bytes = slice_from(bytes, bytes_len, "bytes")?;
        let signal = peachy_mls_core::call::decode_call_signal(bytes)?;
        let json = peachy_mls_core::call::signal_to_json(&signal)?;
        write_buffer(out_json, "out_json", json.into_bytes())
    })
}

/// Whether a call signal (JSON form) is sent `urgent` through `SendSealed`:
/// `Offer`, `Answer` and `Hangup` are; nothing else is.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_call_signal_is_urgent(
    signal_json: *const c_char,
    out_urgent: *mut bool,
) -> i32 {
    guard(|| {
        if out_urgent.is_null() {
            return Err(null_argument("out_urgent"));
        }
        let signal_json = cstr_arg(signal_json, "signal_json")?;
        *out_urgent = peachy_mls_core::call::call_signal_is_urgent_json(signal_json)?;
        Ok(())
    })
}

/// One sender's 16-byte key from a 32-byte call root:
/// `HKDF-Expand-SHA256(call_root, "peachy call sender" ‖ u32be(leaf), 16)`.
/// For a leaf a staged commit adds, which [`peachy_mls_group_call_keys`] does
/// not list.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_call_sender_key(
    call_root: *const u8,
    call_root_len: usize,
    leaf_index: u32,
    out_key: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_key, "out_key")?;
        let root = slice_from(call_root, call_root_len, "call_root")?;
        let key = peachy_mls_core::call::call_sender_key(root, leaf_index)?;
        write_buffer(out_key, "out_key", key.to_vec())
    })
}

/// The AES-128-GCM frame key a frame encryptor derives from a sender key:
/// `HKDF-SHA256(salt "peachy call frame v1", ikm sender_key, info [0;128], 16)`.
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_call_frame_key(
    sender_key: *const u8,
    sender_key_len: usize,
    out_key: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_key, "out_key")?;
        let sender = slice_from(sender_key, sender_key_len, "sender_key")?;
        let key = peachy_mls_core::call::call_frame_key(sender)?;
        write_buffer(out_key, "out_key", key.to_vec())
    })
}

/// One step of the ring-state reducer: `state_json` (null for idle) and
/// `event_json` in, `{"state":{…},"effects":[…]}` out as UTF-8 JSON. Pure: the
/// caller keeps the state and performs the effects (ring, send, join, arm a
/// timer, record how the call ended).
///
/// # Safety
/// See the module header.
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_call_ring_step(
    state_json: *const c_char,
    event_json: *const c_char,
    out_json: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        require_out(out_json, "out_json")?;
        let state = json_arg_or_null(state_json, "state_json")?;
        let event = cstr_arg(event_json, "event_json")?;
        let step = peachy_mls_core::call::ring_step_json(state, event)?;
        write_buffer(out_json, "out_json", step.into_bytes())
    })
}

// ---- The test issuer, behind `test-issuer` ---------------------------------
//
// Not part of the shipped ABI. Compiled only with `--features test-issuer`,
// and guarded in the committed header by `#if defined(PEACHY_MLS_TEST_ISSUER)`
// so that one header describes both builds — the alternative was two committed
// headers, and the one nobody regenerated would be the one a wrapper was read
// against.
//
// The reason it exists at all: a wrapper's test suite needs a *valid* `pdc1`
// credential, and there are only three ways to get one. Talk to a server (a
// running server and its signing key in a unit test), re-implement the token format
// in the wrapper's language (a second opinion about the format, which is
// exactly what `docs/identity.md` §Format says not to have), or reach
// through this door to the same issuer `mls/core/src/issuer.rs` already gives
// the Rust tests. The third is the only one that keeps one implementation of
// the format.

/// A `pdc1` issuer. Opaque; `test-issuer` builds only. **Not the server.**
#[cfg(feature = "test-issuer")]
pub struct PeachyMlsTestIssuer {
    inner: peachy_mls_core::issuer::TestIssuer,
}

/// # Safety
/// `issuer` must be null or a pointer from [`peachy_mls_test_issuer_new`].
#[cfg(feature = "test-issuer")]
unsafe fn issuer_ref<'a>(
    issuer: *mut PeachyMlsTestIssuer,
) -> Result<&'a peachy_mls_core::issuer::TestIssuer, Error> {
    if issuer.is_null() {
        return Err(null_argument("issuer"));
    }
    Ok(&(*issuer).inner)
}

/// An issuer from a fixed 32-byte seed, so a fixture mints the same bytes on
/// every machine.
///
/// # Safety
/// `seed` must be valid for `seed_len` bytes and `out_issuer` must point to
/// writable storage for one pointer.
#[cfg(feature = "test-issuer")]
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_test_issuer_new(
    seed: *const u8,
    seed_len: usize,
    out_issuer: *mut *mut PeachyMlsTestIssuer,
) -> i32 {
    guard(|| {
        if out_issuer.is_null() {
            return Err(null_argument("out_issuer"));
        }
        if seed_len != 32 {
            return Err(Error::InvalidArgument(format!(
                "an issuer seed must be 32 bytes, got {seed_len}"
            )));
        }
        let slice = slice_from(seed, seed_len, "seed")?;
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        let inner = peachy_mls_core::issuer::TestIssuer::from_seed(&bytes);
        *out_issuer = Box::into_raw(Box::new(PeachyMlsTestIssuer { inner }));
        Ok(())
    })
}

/// Free an issuer.
///
/// # Safety
/// `issuer` must be null or a pointer from [`peachy_mls_test_issuer_new`] that
/// has not already been freed.
#[cfg(feature = "test-issuer")]
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_test_issuer_free(issuer: *mut PeachyMlsTestIssuer) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !issuer.is_null() {
            drop(Box::from_raw(issuer));
        }
    }));
}

/// The JSON `GET /healthz/device-credential-keys` would return for this
/// issuer, as UTF-8 bytes — feed it straight to
/// [`peachy_mls_client_new`]'s `trusted_keys_json` (NUL-terminating it first).
///
/// # Safety
/// See the module header.
#[cfg(feature = "test-issuer")]
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_test_issuer_published_keys(
    issuer: *mut PeachyMlsTestIssuer,
    out_json: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let issuer = issuer_ref(issuer)?;
        write_buffer(out_json, "out_json", issuer.published_json().into_bytes())
    })
}

/// Mint a credential for a device whose Ed25519 seed is `device_seed`.
///
/// The device key in the token is derived from that seed here, rather than
/// taken as a separate argument, so the caller cannot accidentally mint a
/// credential for a key it does not hold — which
/// [`peachy_mls_client_new`] would then reject, five layers from the mistake.
///
/// `issued_at` and `expires_at` are unix seconds. Pass a past `expires_at` to
/// mint the expired credential an error-path test needs.
///
/// # Safety
/// The string arguments must be NUL-terminated UTF-8, `device_seed` must be
/// valid for `device_seed_len` bytes, and `out_credential` must point to
/// writable storage for one `PeachyMlsBuffer`.
#[cfg(feature = "test-issuer")]
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn peachy_mls_test_issuer_issue(
    issuer: *mut PeachyMlsTestIssuer,
    actor_id: *const c_char,
    device_id: *const c_char,
    device_seed: *const u8,
    device_seed_len: usize,
    issued_at: i64,
    expires_at: i64,
    out_credential: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        let issuer = issuer_ref(issuer)?;
        if actor_id.is_null() {
            return Err(null_argument("actor_id"));
        }
        if device_id.is_null() {
            return Err(null_argument("device_id"));
        }
        let actor = CStr::from_ptr(actor_id)
            .to_str()
            .map_err(|_| Error::InvalidArgument("actor_id is not UTF-8".into()))?;
        let device = CStr::from_ptr(device_id)
            .to_str()
            .map_err(|_| Error::InvalidArgument("device_id is not UTF-8".into()))?;
        if device_seed_len != 32 {
            return Err(Error::InvalidArgument(format!(
                "a device signature seed must be 32 bytes, got {device_seed_len}"
            )));
        }
        let slice = slice_from(device_seed, device_seed_len, "device_seed")?;
        let mut seed = [0u8; 32];
        seed.copy_from_slice(slice);
        let (_, public) = peachy_mls_core::issuer::device_key_pair(&seed);
        let token = issuer.issue(actor, device, &public, issued_at, expires_at)?;
        write_buffer(out_credential, "out_credential", token)
    })
}

// ---- The golden-fixture door, behind `fixture` -----------------------------
//
// Not part of the shipped ABI either. Compiled only with `--features fixture`
// and guarded in the committed header by `#if defined(PEACHY_MLS_FIXTURE)`,
// exactly like the issuer above and for the same reason: one header describes
// every build, so `tests/header.rs` holds whichever features are on.
//
// Why it is here at all. `mls/fixtures/rules.json` is the table that holds
// every client to one answer about group policy (docs/mls-core.md §Golden
// rules fixture). Rust replays it through `peachy_mls_core::fixture` and the
// web replays it through the wasm binding, but Swift and Kotlin reach this
// crate only across C — so without this entry point their replays could not
// exist, and the fixture would ask those clients for an answer it had no way
// to hear.
//
// The shape is the core's, unchanged: one case object in as JSON, one verdict
// object out as JSON. Nothing is re-implemented here — this function parses no
// case, knows no proposal kind and decides nothing. It moves a string across
// the boundary and back.

/// Evaluate ONE case from `mls/fixtures/rules.json` and hand back the verdict.
///
/// `case_json` is the whole case object, NUL-terminated UTF-8, `expect` and
/// `why` included: the door ignores them, so no caller has to strip a key
/// first and every language's replay sends the same bytes it read.
/// `out_verdict` receives freshly allocated UTF-8 — **not** NUL-terminated,
/// like every other buffer here — that the caller frees with
/// [`peachy_mls_buffer_free`].
///
/// A case naming a proposal kind, a sender or a `call` that does not exist is
/// [`PEACHY_MLS_ERR_INVALID_ARGUMENT`] with the reason in
/// [`peachy_mls_last_error`], and is deliberately NOT a verdict: a replay that
/// turned "this no longer exists" into a denial would go on passing over
/// nothing.
///
/// # Safety
/// `case_json` must be a valid NUL-terminated string and `out_verdict` must
/// point to writable storage for one [`PeachyMlsBuffer`].
#[cfg(feature = "fixture")]
#[no_mangle]
pub unsafe extern "C" fn peachy_mls_fixture_evaluate_case(
    case_json: *const c_char,
    out_verdict: *mut PeachyMlsBuffer,
) -> i32 {
    guard(|| {
        if case_json.is_null() {
            return Err(null_argument("case_json"));
        }
        let case = CStr::from_ptr(case_json)
            .to_str()
            .map_err(|_| Error::InvalidArgument("case_json is not UTF-8".into()))?;
        let verdict = peachy_mls_core::fixture::evaluate_case_json(case)?;
        write_buffer(out_verdict, "out_verdict", verdict.into_bytes())
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use peachy_mls_core::issuer::{device_key_pair, TestIssuer};
    use peachy_mls_core::{Clock, Incoming};

    use super::*;

    const G: &[u8] = b"77777777-7777-4777-8777-77777777cab1";
    const NOW: i64 = 1_789_516_800;
    const DAY: i64 = 86_400;

    /// A clock that panics while armed: stands in for any panic inside a
    /// door.
    #[derive(Debug)]
    struct TrippableClock(Arc<AtomicBool>);

    impl Clock for TrippableClock {
        fn now_unix(&self) -> i64 {
            assert!(
                !self.0.load(Ordering::SeqCst),
                "injected panic inside a door"
            );
            NOW
        }
    }

    fn fresh_path(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("peachy-cabi-{}-{name}.sqlite", std::process::id()));
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
        path
    }

    fn core_client(
        issuer: &TestIssuer,
        tag: u8,
        actor: &str,
        storage: PeachyStorage,
        armed: Arc<AtomicBool>,
    ) -> Client {
        let seed = [tag; 32];
        let (_, public) = device_key_pair(&seed);
        let token = issuer
            .issue(
                actor,
                &format!("device-{actor}"),
                &public,
                NOW - DAY,
                NOW + 30 * DAY,
            )
            .expect("mint");
        let held =
            peachy_mls_core::account_identity_public_key(&TestIssuer::test_account_key(actor))
                .expect("derive");
        let mut config = ClientConfig::new(token, seed, issuer.trusted_keys().expect("keys"))
            .with_storage(storage)
            .with_own_account_identity(Some(held));
        config.clock = Some(Box::new(TrippableClock(armed)));
        Client::new(config).expect("client")
    }

    fn on_file(path: &Path) -> PeachyStorage {
        PeachyStorage::open(Box::new(SqliteKv::open(path).expect("open"))).expect("storage")
    }

    /// A call that panics part-way: its writes are rolled back at once (a
    /// second client on the file can write, and the message the call was
    /// opening is unspent there), and the handle is closed, so every later
    /// call returns `PEACHY_MLS_ERR_PANIC` without running, until the caller
    /// frees it and opens a new client from the store.
    #[test]
    fn a_panic_rolls_back_the_call_and_closes_the_handle() {
        let issuer = TestIssuer::from_seed(&[7u8; 32]);
        let path = fresh_path("panic");
        let armed = Arc::new(AtomicBool::new(false));
        let mut ada = core_client(&issuer, 1, "ada", on_file(&path), armed.clone());
        let mut bo = core_client(
            &issuer,
            2,
            "bo",
            PeachyStorage::in_memory(),
            Arc::new(AtomicBool::new(false)),
        );
        ada.create_group(G).unwrap();
        let package = bo.generate_key_package().unwrap();
        let bundle = ada.add_member(G, &package).unwrap();
        ada.merge_pending_commit(G).unwrap();
        bo.join_from_welcome(&bundle.welcome.unwrap()).unwrap();
        let m0 = bo.encrypt(G, b"m0").unwrap();

        let handle = Box::into_raw(Box::new(PeachyMlsClient {
            inner: ada,
            closed: false,
            roster: None,
        }));

        let quiet = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        armed.store(true, Ordering::SeqCst);
        let status = guard(|| {
            let client = unsafe { client_mut(handle)? };
            client.process_message(G, &m0).map(drop)
        });
        armed.store(false, Ordering::SeqCst);
        std::panic::set_hook(quiet);
        assert_eq!(status, PEACHY_MLS_ERR_PANIC);

        // Closed: the next call is refused before its body runs.
        let mut ran = false;
        let status = guard(|| {
            let client = unsafe { client_mut(handle)? };
            ran = true;
            client.process_message(G, &m0).map(drop)
        });
        assert_eq!(status, PEACHY_MLS_ERR_PANIC, "a closed handle is refused");
        assert!(!ran, "a call on a closed handle ran");
        let message = unsafe { CStr::from_ptr(peachy_mls_last_error()) }
            .to_string_lossy()
            .into_owned();
        assert!(message.contains("closed after a panic"), "{message}");

        // Rolled back, not left open for the next call to commit: a second
        // client on the file writes at once, and m0 is still unread there.
        let mut reopened = core_client(
            &issuer,
            1,
            "ada",
            on_file(&path),
            Arc::new(AtomicBool::new(false)),
        );
        assert!(matches!(
            reopened.process_message(G, &m0),
            Ok(Incoming::Application { .. })
        ));
        drop(reopened);

        unsafe { peachy_mls_client_free(handle) };
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    /// A client of `actor` whose device id is `device`, on `storage`.
    fn device_client(
        issuer: &TestIssuer,
        tag: u8,
        actor: &str,
        device: &str,
        storage: PeachyStorage,
    ) -> Client {
        let seed = [tag; 32];
        let (_, public) = device_key_pair(&seed);
        let token = issuer
            .issue(actor, device, &public, NOW - DAY, NOW + 30 * DAY)
            .expect("mint");
        let held =
            peachy_mls_core::account_identity_public_key(&TestIssuer::test_account_key(actor))
                .expect("derive");
        let mut config = ClientConfig::new(token, seed, issuer.trusted_keys().expect("keys"))
            .with_storage(storage)
            .with_own_account_identity(Some(held));
        config.clock = Some(Box::new(TrippableClock(Arc::new(AtomicBool::new(false)))));
        Client::new(config).expect("client")
    }

    /// The stale-leaf verdict answers from the group as the store holds it,
    /// not as this handle last loaded it: another process (the extension)
    /// that seated Cy's second device moved the tree this verdict is about.
    #[test]
    fn the_stale_leaf_verdict_reads_the_group_another_process_moved() {
        let issuer = TestIssuer::from_seed(&[7u8; 32]);
        let path = fresh_path("stale-leaf");
        let mut app = device_client(&issuer, 1, "ada", "device-ada", on_file(&path));
        let cy = device_client(&issuer, 3, "cy", "device-cy", PeachyStorage::in_memory());
        let cy_tablet = device_client(
            &issuer,
            4,
            "cy",
            "device-cy-tablet",
            PeachyStorage::in_memory(),
        );
        app.create_group(G).unwrap();
        app.add_member(G, &cy.generate_key_package().unwrap())
            .unwrap();
        app.merge_pending_commit(G).unwrap();

        // The extension's handle loads the group with Cy's one device.
        let extension = device_client(&issuer, 1, "ada", "device-ada", on_file(&path));
        let handle = Box::into_raw(Box::new(PeachyMlsClient {
            inner: extension,
            closed: false,
            roster: None,
        }));

        app.add_member(G, &cy_tablet.generate_key_package().unwrap())
            .unwrap();
        app.merge_pending_commit(G).unwrap();
        let tablet_leaf = app.leaf_of_device(G, "device-cy-tablet").unwrap();
        drop(app);

        let mut removable = false;
        let status = unsafe {
            peachy_mls_stale_leaf_removable(
                handle,
                G.as_ptr(),
                G.len(),
                tablet_leaf,
                std::ptr::null(),
                0,
                0,
                &mut removable,
            )
        };
        assert_eq!(status, PEACHY_MLS_OK, "{}", unsafe {
            CStr::from_ptr(peachy_mls_last_error()).to_string_lossy()
        });
        // Cy keeps another leaf there, which the stale tree did not hold.
        assert_eq!(removable, !peachy_mls_core::SIGNED_REVOCATIONS_ENFORCED);

        unsafe { peachy_mls_client_free(handle) };
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    /// The actor id at `position`, read through the per-position door.
    unsafe fn member_actor(handle: *mut PeachyMlsClient, position: usize) -> Result<String, i32> {
        let mut actor = PeachyMlsBuffer::empty();
        let mut rejection = u32::MAX;
        let status = peachy_mls_group_member(
            handle,
            G.as_ptr(),
            G.len(),
            position,
            ptr::null_mut(),
            &mut actor,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut rejection,
        );
        if status != PEACHY_MLS_OK {
            return Err(status);
        }
        assert_eq!(rejection, 0, "a seated test leaf verifies");
        let id = String::from_utf8(std::slice::from_raw_parts(actor.data, actor.len).to_vec())
            .expect("utf-8");
        peachy_mls_buffer_free(&mut actor);
        Ok(id)
    }

    unsafe fn member_count(handle: *mut PeachyMlsClient) -> usize {
        let mut count = 0usize;
        let status = peachy_mls_group_member_count(handle, G.as_ptr(), G.len(), &mut count);
        assert_eq!(status, PEACHY_MLS_OK);
        count
    }

    /// One roster per read (§One roster per read): the count keeps the roster
    /// it built, the per-position doors answer from it, and it is never used
    /// for the group at another epoch, so a commit after the count is seen by
    /// the next position call rather than hidden behind the old snapshot.
    #[test]
    fn the_count_keeps_one_roster_for_the_read_and_a_commit_retires_it() {
        let issuer = TestIssuer::from_seed(&[9u8; 32]);
        let calm = || Arc::new(AtomicBool::new(false));
        let mut ada = core_client(&issuer, 1, "ada", PeachyStorage::in_memory(), calm());
        let bo = core_client(&issuer, 2, "bo", PeachyStorage::in_memory(), calm());
        let cy = core_client(&issuer, 3, "cy", PeachyStorage::in_memory(), calm());
        ada.create_group(G).unwrap();
        ada.add_member(G, &bo.generate_key_package().unwrap())
            .unwrap();
        ada.merge_pending_commit(G).unwrap();
        let expected: Vec<String> = ada
            .roster(G)
            .unwrap()
            .into_iter()
            .map(|entry| entry.identity.expect("verifies").actor_id)
            .collect();

        let handle = Box::into_raw(Box::new(PeachyMlsClient {
            inner: ada,
            closed: false,
            roster: None,
        }));
        unsafe {
            assert_eq!(member_count(handle), 2);
            let snapshot = (*handle)
                .roster
                .as_ref()
                .expect("the count keeps its roster");
            assert_eq!(snapshot.group_id, G);
            assert_eq!(snapshot.entries.len(), 2);
            let read: Vec<String> = (0..2).map(|p| member_actor(handle, p).unwrap()).collect();
            assert_eq!(read, expected);
            assert_eq!(member_actor(handle, 2), Err(PEACHY_MLS_ERR_NO_SUCH_MEMBER));

            // A commit after the count: the epoch moved, so the snapshot is
            // not this group's any more and the position door builds afresh.
            (*handle)
                .inner
                .add_member(G, &cy.generate_key_package().unwrap())
                .unwrap();
            (*handle).inner.merge_pending_commit(G).unwrap();
            assert_eq!(member_actor(handle, 2).as_deref(), Ok("cy"));
            assert_eq!(member_count(handle), 3);
            assert_eq!(member_actor(handle, 2).as_deref(), Ok("cy"));

            // Any other door ends the read, at the same epoch too: no
            // snapshot outlives a forget, a join or new trusted keys.
            assert!((*handle).roster.is_some());
            let mut epoch = 0u64;
            assert_eq!(
                peachy_mls_group_epoch(handle, G.as_ptr(), G.len(), &mut epoch),
                PEACHY_MLS_OK
            );
            assert!((*handle).roster.is_none(), "a door dropped the snapshot");
            peachy_mls_client_free(handle);
        }
    }
}
