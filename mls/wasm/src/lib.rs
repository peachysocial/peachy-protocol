// SPDX-License-Identifier: MIT
//! # peachy-mls-wasm
//!
//! One of the three bindings over [`peachy_mls_core`], for JavaScript. It
//! wraps [`peachy_mls_core::Client`] directly, not the C ABI.
//!
//! ## The shape at the JS edge
//!
//! - **Bytes cross as `Uint8Array`**, copied both ways.
//! - **Structured results are plain JS objects**, built by `serde-wasm-bindgen`
//!   from the DTOs below, with no `free()`.
//! - **Every failure throws** the core's own `Display` text verbatim, e.g.
//!   `"group policy refused: external_join"`.
//! - **Epochs and timestamps are JS numbers**, not `BigInt`; neither reaches
//!   2^53.
//!
//! ## After a panic
//!
//! `wasm32-unknown-unknown` cannot unwind, so a panic is a trap: the call
//! throws a `WebAssembly.RuntimeError` and the module instance is left
//! mid-operation, its memory and every client in it in whatever state the
//! panic interrupted. The panic hook marks the instance POISONED before the
//! trap, and from then on every export refuses to run: a call throws
//! [`POISONED_MESSAGE`], and `flush()` rejects with it before a byte reaches
//! the store, so the interrupted state is never written. `isPoisoned()` says
//! whether it happened. The instance stays refused until the host makes a
//! fresh one (a page reload, or the glue's `__wbg_reset_state`) and reopens
//! its client over the store, which holds the last flushed state
//! (docs/mls-core.md §wasm binding).
//!
//! ## Storage
//!
//! - **`new MlsClient(...)`** is ephemeral: group state dies with the object.
//! - **`await MlsClient.open(store, ...)`** is durable. `store` implements
//!   `MlsKvStore`, three async methods over bytes, with the core's key layout
//!   (docs/mls-core.md §Storage layout). OpenMLS' storage is synchronous, so
//!   `open` loads the whole store into memory, and nothing is durable until
//!   `await client.flush()`. The crash window that leaves is described in the
//!   `kv` module.
//!
//! ## Committing
//!
//! `addMember`, `removeMember` and `selfUpdate` stage a commit; they do not
//! adopt it:
//!
//! ```js
//! const bundle = client.addMember(groupId, keyPackage);
//! await client.flush();                 // the stage is durable before the server can take it
//! try {
//!   await ds.submitCommit(groupId, bundle); // your SubmitCommit: handle, wrapped commit,
//!                                           // send key, recipients
//!                                           // (docs/delivery.md §SubmitCommit);
//!                                           // the group id never leaves the device
//! } catch (err) {
//!   client.clearPendingCommit(groupId); // refused: this branch never happened
//!   await client.flush();
//!   throw err;                          // then replay what the server DID take
//! }
//! client.mergePendingCommit(groupId);
//! await client.flush();                 // the merge, only once the server agreed
//! ```
//!
//! The delivery service's acceptance is the group's total order
//! (docs/delivery.md §The ordering rule). A device that merges a
//! commit the server then refuses is on a branch no other member follows: it
//! keeps encrypting, nobody can read it, and no error is raised. Merging
//! before the server agrees, and flushing that, makes the fork durable.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

mod kv;

use js_sys::futures::{future_to_promise, JsFuture};
use js_sys::{Array, Function, Promise, Reflect, Uint8Array};
use serde::Serialize;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use zeroize::{Zeroize, Zeroizing};

use peachy_mls_core::credential::ED25519_PUBLIC_KEY_BYTES;
use peachy_mls_core::{
    check_schema_stamp, schema_prefix, schema_stamp_key, Client, ClientConfig, CommitBundle,
    CredentialRejection, Incoming, KvEntry, PeachyIdentity, PeachyStorage, RosterEntry,
    TrustedServerKeys, PEACHY_CIPHERSUITE,
};

use kv::CacheKv;

// ---- Poisoning ----------------------------------------------------------------

/// What every export throws once a panic has poisoned this module instance.
pub const POISONED_MESSAGE: &str =
    "poisoned: the MLS engine panicked in this module instance; make a fresh instance and reopen";

/// Set by the panic hook, before the trap, and never cleared: a fresh module
/// instance starts with fresh memory and so with this false.
static POISONED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Install the hook that poisons the instance, once, on the first call into
/// it. Only on wasm32: a host build (the crate's own tests) keeps the test
/// harness's hook.
fn install_poison_hook() {
    #[cfg(target_arch = "wasm32")]
    {
        static HOOK: std::sync::Once = std::sync::Once::new();
        HOOK.call_once(|| {
            let previous = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                POISONED.store(true, std::sync::atomic::Ordering::SeqCst);
                previous(info);
            }));
        });
    }
}

fn poisoned() -> bool {
    POISONED.load(std::sync::atomic::Ordering::SeqCst)
}

/// The first line of every export that answers a `Result`: refuse on a
/// poisoned instance.
fn live() -> Result<(), JsError> {
    install_poison_hook();
    if poisoned() {
        return Err(JsError::new(POISONED_MESSAGE));
    }
    Ok(())
}

/// The first line of every export that answers a plain value: throw on a
/// poisoned instance, before anything is read. Nothing is held yet, so the
/// throw unwinds nothing it should have dropped.
fn refuse_if_poisoned() {
    install_poison_hook();
    if poisoned() {
        wasm_bindgen::throw_str(POISONED_MESSAGE);
    }
}

/// Whether a panic has poisoned this module instance. The one export that
/// still answers afterwards: a host asks it to tell a trap out of this
/// module from one out of any other.
#[wasm_bindgen(js_name = isPoisoned)]
pub fn is_poisoned() -> bool {
    install_poison_hook();
    poisoned()
}

/// Poison this instance by panicking, as a bug would: the door the tests use
/// to prove every export refuses afterwards. Behind `fixture`, so no shipped
/// bundle carries it.
#[cfg(feature = "fixture")]
#[wasm_bindgen(js_name = panicForTest)]
#[allow(clippy::panic)]
pub fn panic_for_test() {
    install_poison_hook();
    panic!("a panic on purpose, to poison the instance");
}

// ---- The TypeScript surface -------------------------------------------------
//
// wasm-bindgen types a method returning `JsValue` as `any`, and `any` is how a
// binding stops being checkable: the web client would get a `roster()` it could
// misspell a field of without TypeScript noticing, which is exactly the class
// of mistake this crate exists to make impossible.
//
// So each structured result is declared here as a real interface and bound to
// an imported type. The declarations are hand-written and the DTOs below are
// Rust — they have to be kept in step by a person, and the two tests are what
// hold them there: `tests/journey.rs` parses the objects back into typed Rust
// structs, and `tests/node/journey.test.mjs` reads them as JavaScript.

#[wasm_bindgen(typescript_custom_section)]
const TS_SURFACE: &'static str = r#"
/** What the recovery driver says to do with a copy of a group
 *  (`recoveryBegin`, `recoveryJudge`; docs/mls-core.md §Group recovery). */
export type MlsRecoveryStep =
    | "in_step" | "behind" | "rolled_back" | "held" | "hold_entered"
    | "rejoin_forked" | "rejoin_stuck" | "rejoin_lost" | "backoff"
    | "no_copy" | "read_again" | "read_head" | "settle_first";

/** Why a head was read (`recoveryJudge`): the fork check, the fork check
 *  with a message sealed past the copy known, or a lost mailbox. */
export type MlsHeadReadKind = "check" | "sealed_ahead" | "lost";

/** An opened envelope of a member-rostered conversation: which group, what
 *  kind (1 message, 2 commit, 3 seat ask, 4 typing, 5 link preview) and the
 *  inner bytes. */
export interface MlsOpenedEnvelope {
    groupId: Uint8Array;
    kind: number;
    inner: Uint8Array;
}

/** An envelope `holdEnvelope` kept that opens now, with the mailbox's own
 *  kind, id and receive time: take it through the same path as a fresh one. */
export interface MlsHeldEnvelope {
    mailboxKind: number;
    receivedAtMs: number;
    id: string;
    envelope: Uint8Array;
}

/** What an envelope `nextReopenable` handed out on its device seal is to be
 *  made of (`heldDisposition`). `fate`: 0, taken through as any envelope; 1,
 *  from a device of somebody who holds no leaf of the group any more: a
 *  placeholder naming `author`, neither opened nor asked for; 2, for a group
 *  this device holds no copy of: a placeholder in the conversation of the
 *  group it opens to, naming `author`, asked for again once this device is
 *  seated there. `author`: the actor id of the person whose device sealed
 *  it, absent when it is simply a leaf of the copy. */
export interface MlsHeldDisposition {
    fate: number;
    author?: string;
}

/**
 * A call's frame-encryption keys at one epoch (docs/calls.md §Keys).
 * Each sender's key goes into the key provider at slot `keyIndex`; the frame
 * key is `callFrameKey(key)`, which is what a frame encryptor's key provider
 * derives with
 * HKDF under the ratchet salt "peachy call frame v1".
 */
export interface MlsCallKeys {
    epoch: number;
    keyIndex: number;
    callRoot: Uint8Array;
    senders: Array<{ leafIndex: number; key: Uint8Array }>;
}

/** A verified leaf identity. `deviceKey` is the raw Ed25519 public key. */
export interface MlsIdentity {
    actorId: string;
    deviceId: string;
    deviceKey: Uint8Array;
    kid: string;
    /** Unix seconds. */
    expiresAt: number;
    /**
     * The account identity key that signed for this device, already checked
     * (docs/identity.md §The account identity key). Null only on this
     * device's OWN identity while it waits to be let in; every peer's leaf and
     * key package carries one.
     */
    accountKey: Uint8Array | null;
}

/** Why a leaf's credential did not check out. The codes match `peachy_mls.h`. */
export interface MlsCredentialRejection {
    code: number;
    name: string;
}

/** Exactly one of `identity` and `rejection` is non-null. */
export interface MlsRosterEntry {
    leafIndex: number;
    /** The leaf's tree signature key, for every leaf: what `removeMember` takes. */
    leafKey: Uint8Array;
    identity: MlsIdentity | null;
    rejection: MlsCredentialRejection | null;
}

/**
 * What `keyPackageIdentity` read out of a raw key package. Exactly one of
 * `identity` and `rejection` is non-null, the same way a roster entry carries
 * its verdict.
 *
 * `identity.deviceKey` is the value to hand `verifyDeviceApproval` as its
 * `signingKey`: it comes out of the key package itself, so a directory that
 * served a truthful device id beside a package carrying a different key
 * cannot slip an unapproved leaf past the check.
 */
export interface MlsKeyPackageIdentity {
    identity: MlsIdentity | null;
    rejection: MlsCredentialRejection | null;
}

/**
 * What `verifyJoinRequest` decided about a signed request to be seated. Only
 * `code === 0` (`"accepted"`) may seat anybody. The codes match `peachy_mls.h`
 * (`PEACHY_MLS_JOIN_REQUEST_*`) and `mls/fixtures/join-request.json`.
 */
export interface MlsJoinRequestVerdict {
    code: number;
    name: string;
}

/**
 * What `checkOwnDeviceApproval` (or `checkOwnDeviceKey`) decided about one of
 * this account's own devices. Only `seats` (`"known"`, 0, or `"approved"`, 1)
 * may be seated or handed history; `"unanchored"` (2) is "not from here, not
 * now". The codes match
 * `peachy_mls.h` (`PEACHY_MLS_OWN_DEVICE_*`).
 */
export interface MlsOwnDeviceVerdict {
    code: number;
    name: string;
    seats: boolean;
}

/**
 * What one Welcome that restored or replaced a group this device knew
 * brought with it (`takeRejoinReport`): who re-seated this device and from
 * which of their devices (empty when the Welcome named none), whether that
 * was a device of this person's own that this device does not trust as one
 * of theirs (`readdedByUntrusted`), the actors the new tree holds whom the
 * roster it last saw there did not (`added`), and those of that roster it
 * leaves out (`departed`). `adminsChanged`: the admins changed. `contested`:
 * a head contradicted the copy before any matched it (`readdedBy` is then
 * empty). Drawn once, as lines in the conversation.
 */
export interface MlsRejoinReport {
    readdedBy: string;
    readdedByDevice: string;
    readdedByUntrusted: boolean;
    added: string[];
    departed: string[];
    adminsChanged: boolean;
    contested: boolean;
    /**
     * The devices of people the new tree keeps that it leaves out, never
     * this device nor one this account forgot. Logged, never drawn; the
     * client re-seats its own person's at once.
     */
    droppedDevices: { actorId: string; deviceId: string }[];
    /** What `dropRejoinReport` drops it by: a decimal u64, "0" from `takeRejoinReport` on a stored report with no id. */
    id: string;
    /** When to draw it, in Unix milliseconds: `peekRejoinReport`'s `nowMs` the first time, the same on every later peek; 0 from `takeRejoinReport` on a report never peeked. */
    drawnAtMs: number;
}

/**
 * A key package with the name a directory files it under.
 *
 * `keyPackageRef` is the RFC 9420 KeyPackageRef — a hash of the KeyPackage
 * INSIDE `keyPackage`, not of `keyPackage` itself, which carries an
 * `MlsMessage` header around it. Hashing the published bytes yourself produces
 * a different value that nothing else in MLS recognizes.
 */
export interface MlsKeyPackage {
    /** The MLS ciphersuite id these bytes are for. */
    ciphersuite: number;
    /** The serialized `MlsMessage`, as a directory publishes it. */
    keyPackage: Uint8Array;
    keyPackageRef: Uint8Array;
}

/** The commit goes to the group; the Welcome goes to whoever was added. */
export interface MlsCommitBundle {
    commit: Uint8Array;
    welcome: Uint8Array | null;
    epoch: number;
}

/** The group a Welcome is for and the epoch it seals, as it claims them. */
export interface MlsWelcomeGroup {
    groupId: Uint8Array;
    epoch: number;
}

/** What `processMessage()` or `processCommit()` made of one incoming message. Switch on `kind`. */
export type MlsIncoming =
    | {
          kind: "application";
          sender: MlsIdentity;
          plaintext: Uint8Array;
      }
    | { kind: "proposal"; sender: MlsIdentity; proposal: string }
    | {
          kind: "commit";
          sender: MlsIdentity;
          added: MlsIdentity[];
          removed: number[];
          removedSelf: boolean;
          /** Actor ids of the people who LEFT in this commit: each proposed the removal of their own leaves, and the commit removed every one. Sorted; empty when nobody left. */
          left: string[];
          epoch: number;
      }
    | { kind: "echo" };

/**
 * The durable store behind `MlsClient.open()`.
 *
 * Bytes in, bytes out, three methods, all async. Keys are opaque: they carry a
 * schema version byte and a namespace and they sort meaningfully, so an
 * implementation must preserve BYTE ORDER and must treat a key as a whole
 * value rather than a string (a key is not valid UTF-8, and `TextDecoder`
 * round-trips will corrupt it).
 *
 * `MlsClient.open()` calls `get` once — for the schema stamp, so a store this
 * build cannot read is refused before it is downloaded — then `iterate` once
 * for everything else. `MlsClient.flush()` calls `writeBatch` once. Nothing
 * else is called during an operation: see the crate docs for why.
 *
 * A rejected promise from any of the three surfaces as a thrown error from the
 * `open()` or `flush()` that called it, with its message kept.
 */
export interface MlsKvStore {
    /** The value at `key`, or null/undefined if there is none. */
    get(key: Uint8Array): Promise<Uint8Array | null | undefined>;
    /**
     * Apply every entry ATOMICALLY: all of them land or none of them do.
     *
     * A `null` value is a delete, and deleting a key that is not there is not
     * an error. Entries arrive in byte order and must be applied in one
     * transaction — a commit's worth of MLS state is a dozen keys that are one
     * state, and a store that writes them in separate transactions can be
     * interrupted into a group that loads as absent. The promise must not
     * resolve until the write is DURABLE; a caller reads `pendingWrites` to
     * decide whether it is safe to close the tab, and that number goes to zero
     * on this promise.
     */
    writeBatch(entries: Array<[Uint8Array, Uint8Array | null]>): Promise<void>;
    /** Every `[key, value]` whose key starts with `prefix`, in byte order. */
    iterate(prefix: Uint8Array): Promise<Array<[Uint8Array, Uint8Array]>>;
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "MlsIdentity")]
    pub type MlsIdentityJs;

    #[wasm_bindgen(typescript_type = "MlsKvStore")]
    pub type MlsKvStoreJs;

    /// `flush()` returns a promise and resolves with nothing. Spelled as an
    /// imported type because wasm-bindgen types a bare `js_sys::Promise` as
    /// `Promise<any>`, and `any` is how a binding stops being checkable.
    #[wasm_bindgen(typescript_type = "Promise<void>")]
    pub type PromiseVoidJs;

    #[wasm_bindgen(typescript_type = "MlsRosterEntry[]")]
    pub type MlsRosterJs;

    #[wasm_bindgen(typescript_type = "MlsKeyPackageIdentity")]
    pub type MlsKeyPackageIdentityJs;

    #[wasm_bindgen(typescript_type = "MlsKeyPackage")]
    pub type MlsKeyPackageJs;

    #[wasm_bindgen(typescript_type = "MlsJoinRequestVerdict")]
    pub type MlsJoinRequestVerdictJs;

    #[wasm_bindgen(typescript_type = "MlsOwnDeviceVerdict")]
    pub type MlsOwnDeviceVerdictJs;

    #[wasm_bindgen(typescript_type = "MlsRejoinReport | undefined")]
    pub type MlsRejoinReportJs;

    #[wasm_bindgen(typescript_type = "MlsCommitBundle")]
    pub type MlsCommitBundleJs;

    #[wasm_bindgen(typescript_type = "MlsCommitBundle | undefined")]
    pub type MlsMaybeCommitBundleJs;

    #[wasm_bindgen(typescript_type = "MlsWelcomeGroup")]
    pub type MlsWelcomeGroupJs;

    #[wasm_bindgen(typescript_type = "MlsIncoming")]
    pub type MlsIncomingJs;

    #[wasm_bindgen(typescript_type = "MlsOpenedEnvelope | undefined")]
    pub type MlsOpenedEnvelopeJs;

    #[wasm_bindgen(typescript_type = "MlsHeldEnvelope | undefined")]
    pub type MlsHeldEnvelopeJs;

    #[wasm_bindgen(typescript_type = "MlsHeldDisposition | undefined")]
    pub type MlsHeldDispositionJs;

    #[wasm_bindgen(typescript_type = "MlsCallKeys")]
    pub type MlsCallKeysJs;

    #[wasm_bindgen(typescript_type = "string[]")]
    pub type ActorIdsJs;
    #[wasm_bindgen(typescript_type = "Uint8Array[]")]
    pub type GroupIdsJs;
    #[wasm_bindgen(typescript_type = "MlsRecoveryStep")]
    pub type MlsRecoveryStepJs;
    #[wasm_bindgen(typescript_type = "Uint8Array[]")]
    pub type ProposalsJs;
    #[wasm_bindgen(typescript_type = "{ actorId: string; deviceId: string }[]")]
    pub type LeaveRecipientsJs;
}

/// Each proposal a leave sends, as its own `Uint8Array`.
fn proposals_to_js(proposals: Vec<Vec<u8>>) -> ProposalsJs {
    let out = Array::new();
    for proposal in proposals {
        out.push(&Uint8Array::from(proposal.as_slice()));
    }
    JsValue::from(out).unchecked_into()
}

// ---- DTOs -------------------------------------------------------------------
//
// One struct per shape that crosses, all `camelCase`, all serialize-only. They
// are spelled out rather than derived on the core's own types on purpose: the
// core's types are Rust API, and renaming a field there should not silently
// rename a key three clients read.

/// A verified leaf identity.
/// `{ actorId, deviceId, deviceKey, kid, expiresAt, accountKey }`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IdentityDto {
    actor_id: String,
    device_id: String,
    #[serde(with = "serde_bytes")]
    device_key: Vec<u8>,
    kid: String,
    expires_at: f64,
    #[serde(with = "serde_bytes")]
    account_key: Option<Vec<u8>>,
}

impl From<&PeachyIdentity> for IdentityDto {
    fn from(identity: &PeachyIdentity) -> Self {
        Self {
            actor_id: identity.actor_id.clone(),
            device_id: identity.device_id.clone(),
            device_key: identity.device_key.to_vec(),
            kid: identity.kid.clone(),
            expires_at: identity.expires_at as f64,
            account_key: identity.account_key.map(|key| key.to_vec()),
        }
    }
}

/// Why a leaf's credential did not check out. `{ code, name }` — the same
/// numbers `peachy_mls.h` names, so a JS caller and a C caller can be held to
/// one fixture.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RejectionDto {
    code: u32,
    name: &'static str,
}

impl From<CredentialRejection> for RejectionDto {
    fn from(rejection: CredentialRejection) -> Self {
        Self {
            code: rejection.code(),
            name: rejection.name(),
        }
    }
}

/// A roster entry. Exactly one of `identity` and `rejection` is non-null: a
/// member whose credential has expired is still in the tree and still receives
/// every message, so it is listed with its reason rather than hidden.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RosterEntryDto {
    leaf_index: u32,
    #[serde(with = "serde_bytes")]
    leaf_key: Vec<u8>,
    identity: Option<IdentityDto>,
    rejection: Option<RejectionDto>,
}

impl From<&RosterEntry> for RosterEntryDto {
    fn from(entry: &RosterEntry) -> Self {
        match &entry.identity {
            Ok(identity) => Self {
                leaf_index: entry.leaf_index,
                leaf_key: entry.leaf_key.clone(),
                identity: Some(IdentityDto::from(identity)),
                rejection: None,
            },
            Err(rejection) => Self {
                leaf_index: entry.leaf_index,
                leaf_key: entry.leaf_key.clone(),
                identity: None,
                rejection: Some(RejectionDto::from(*rejection)),
            },
        }
    }
}

/// What was read out of a raw key package. Exactly one of `identity` and
/// `rejection` is non-null, the same shape a roster entry carries — a key
/// package whose credential has expired is a refusal a caller must be able to
/// explain, not an error that only says "no".
/// `verifyJoinRequest`'s verdict: the number and the name, as the fixture
/// writes them.
#[derive(Serialize)]
struct JoinRequestVerdictDto {
    code: u32,
    name: &'static str,
}

/// `checkOwnDeviceApproval`'s verdict.
#[derive(Serialize)]
struct OwnDeviceVerdictDto {
    code: u32,
    name: &'static str,
    seats: bool,
}

/// `takeRejoinReport`'s answer: `{ readdedBy, readdedByDevice,
/// readdedByUntrusted, added, departed, adminsChanged, contested }`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RejoinReportDto {
    readded_by: String,
    readded_by_device: String,
    readded_by_untrusted: bool,
    added: Vec<String>,
    departed: Vec<String>,
    admins_changed: bool,
    contested: bool,
    dropped_devices: Vec<DroppedDeviceDto>,
    id: String,
    drawn_at_ms: f64,
}

/// One of [`RejoinReportDto::dropped_devices`].
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DroppedDeviceDto {
    actor_id: String,
    device_id: String,
}

impl From<peachy_mls_core::RejoinReport> for RejoinReportDto {
    fn from(report: peachy_mls_core::RejoinReport) -> Self {
        Self {
            readded_by: report.readded_by,
            readded_by_device: report.readded_by_device,
            readded_by_untrusted: report.readded_by_untrusted,
            added: report.added_actors,
            departed: report.departed_actors,
            admins_changed: report.admins_changed,
            contested: report.contested,
            dropped_devices: report
                .dropped_devices
                .into_iter()
                .map(|(actor_id, device_id)| DroppedDeviceDto {
                    actor_id,
                    device_id,
                })
                .collect(),
            id: report.id.to_string(),
            drawn_at_ms: report.drawn_at_ms as f64,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KeyPackageIdentityDto {
    identity: Option<IdentityDto>,
    rejection: Option<RejectionDto>,
}

impl From<&std::result::Result<PeachyIdentity, CredentialRejection>> for KeyPackageIdentityDto {
    fn from(verdict: &std::result::Result<PeachyIdentity, CredentialRejection>) -> Self {
        match verdict {
            Ok(identity) => Self {
                identity: Some(IdentityDto::from(identity)),
                rejection: None,
            },
            Err(rejection) => Self {
                identity: None,
                rejection: Some(RejectionDto::from(*rejection)),
            },
        }
    }
}

/// A key package and the RFC 9420 reference naming it, as a directory files
/// the pair. See [`MlsClient::generate_key_package_with_ref`].
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KeyPackageDto {
    ciphersuite: u16,
    #[serde(with = "serde_bytes")]
    key_package: Vec<u8>,
    #[serde(with = "serde_bytes")]
    key_package_ref: Vec<u8>,
}

/// What `openEnvelope` returns. Its inner bytes, once copied out to
/// JavaScript, are wiped where this binding drops them.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OpenedEnvelopeDto {
    #[serde(with = "serde_bytes")]
    group_id: Vec<u8>,
    kind: u8,
    #[serde(with = "serde_bytes")]
    inner: Vec<u8>,
}

impl Drop for OpenedEnvelopeDto {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

/// What `nextReopenable` returns.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HeldEnvelopeDto {
    mailbox_kind: u8,
    received_at_ms: u64,
    id: String,
    #[serde(with = "serde_bytes")]
    envelope: Vec<u8>,
}

/// What `heldDisposition` returns.
#[derive(Serialize)]
struct HeldDispositionDto {
    fate: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    author: Option<String>,
}

/// One sender's call key, inside [`CallKeysDto`].
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CallSenderKeyDto<'a> {
    leaf_index: u32,
    #[serde(with = "serde_bytes")]
    key: &'a [u8],
}

/// What `callKeys` / `pendingCallKeys` return. It borrows the keys, which
/// wipe themselves when they drop, so the module keeps no copy of its own:
/// the root and each key go straight into a `Uint8Array`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CallKeysDto<'a> {
    epoch: f64,
    key_index: u8,
    #[serde(with = "serde_bytes")]
    call_root: &'a [u8],
    senders: Vec<CallSenderKeyDto<'a>>,
}

impl<'a> From<&'a peachy_mls_core::call::CallKeys> for CallKeysDto<'a> {
    fn from(keys: &'a peachy_mls_core::call::CallKeys) -> Self {
        CallKeysDto {
            // Epochs are far below 2^53.
            epoch: keys.epoch as f64,
            key_index: keys.key_index,
            call_root: &keys.call_root[..],
            senders: keys
                .senders
                .iter()
                .map(|sender| CallSenderKeyDto {
                    leaf_index: sender.leaf_index,
                    key: &sender.key[..],
                })
                .collect(),
        }
    }
}

/// What a commit-producing call returns: the commit for every other member,
/// the Welcome for whoever was added, and the epoch after the local merge.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CommitBundleDto {
    #[serde(with = "serde_bytes")]
    commit: Vec<u8>,
    #[serde(with = "serde_bytes")]
    welcome: Option<Vec<u8>>,
    epoch: f64,
}

/// What `welcomeGroup` returns.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WelcomeGroupDto {
    #[serde(with = "serde_bytes")]
    group_id: Vec<u8>,
    epoch: f64,
}

impl From<CommitBundle> for CommitBundleDto {
    fn from(bundle: CommitBundle) -> Self {
        Self {
            commit: bundle.commit,
            welcome: bundle.welcome,
            epoch: bundle.epoch as f64,
        }
    }
}

/// The result of [`MlsClient::process_message`] and
/// [`MlsClient::process_commit`], internally tagged on `kind` so a JS
/// caller switches on one string rather than probing for fields.
#[derive(Serialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
enum IncomingDto {
    Application {
        sender: IdentityDto,
        #[serde(with = "serde_bytes")]
        plaintext: Vec<u8>,
    },
    Proposal {
        sender: IdentityDto,
        /// `add`, `remove`, `update`, … — `ProposalKind::name`.
        proposal: &'static str,
    },
    Commit {
        sender: IdentityDto,
        added: Vec<IdentityDto>,
        removed: Vec<u32>,
        /// After a commit that removed us, the group is no longer active and
        /// [`MlsClient::encrypt`] refuses.
        removed_self: bool,
        /// Who left in it (`CommitOutcome::left`).
        left: Vec<String>,
        epoch: f64,
    },
    /// A message this client sent, handed back by the delivery service.
    Echo,
}

/// A message's words, once copied out to JavaScript, are wiped where this
/// binding drops them.
impl Drop for IncomingDto {
    fn drop(&mut self) {
        if let Self::Application { plaintext, .. } = self {
            plaintext.zeroize();
        }
    }
}

impl From<Incoming> for IncomingDto {
    fn from(incoming: Incoming) -> Self {
        match incoming {
            Incoming::Application { sender, plaintext } => Self::Application {
                sender: IdentityDto::from(&sender),
                plaintext,
            },
            Incoming::ProposalQueued { sender, kind } => Self::Proposal {
                sender: IdentityDto::from(&sender),
                proposal: kind.name(),
            },
            Incoming::Commit(outcome) => Self::Commit {
                sender: IdentityDto::from(&outcome.sender),
                added: outcome.added.iter().map(IdentityDto::from).collect(),
                removed: outcome.removed,
                removed_self: outcome.removed_self,
                left: outcome.left,
                epoch: outcome.epoch as f64,
            },
            Incoming::Echo => Self::Echo,
        }
    }
}

// ---- Conversions ------------------------------------------------------------

/// A Unix-seconds time JS handed in as an optional number: whole seconds,
/// and `0` (unknown) for absent, zero, negative or not finite.
fn unix_seconds(value: Option<f64>) -> i64 {
    match value {
        Some(seconds) if seconds.is_finite() && seconds >= 1.0 => seconds.floor() as i64,
        _ => 0,
    }
}

/// The core's error, as the exception JS will catch. The message is the core's
/// `Display` and nothing else — a wrapper that decorates it is a wrapper whose
/// text the core's own tests cannot hold.
fn throw(err: peachy_mls_core::Error) -> JsError {
    JsError::new(&err.to_string())
}

/// Every structured result goes through this one serializer.
///
/// `serialize_missing_as_null` is on, against serde-wasm-bindgen's default of
/// `undefined`. An absent Welcome and an absent rejection are *answers* — "this
/// commit welcomed nobody", "this leaf is fine" — and `undefined` cannot say
/// that: it is also what a misspelled property name gives back, it vanishes
/// through `JSON.stringify`, and it reads as "not implemented yet" to anyone
/// who did not write this file. `null` is present and means nothing is there.
///
/// The large-number default is left alone: nothing crosses as `u64`, because
/// every epoch and timestamp here is already an `f64`.
///
/// The cast at the end is unchecked by construction: the object was *just*
/// built from the DTO the interface was written for, so there is nothing to
/// check against that is not already this line.
fn to_js<T: Serialize, J: JsCast>(value: &T) -> Result<J, JsError> {
    let serializer = serde_wasm_bindgen::Serializer::new().serialize_missing_as_null(true);
    value
        .serialize(&serializer)
        .map(JsValue::unchecked_into)
        .map_err(|err| JsError::new(&format!("could not build the result object: {err}")))
}

/// An optional 32-byte account identity key from JavaScript: absent is
/// `None`, anything but 32 bytes is an error.
fn optional_identity(key: Option<Vec<u8>>) -> Result<Option<[u8; 32]>, JsError> {
    key.map(|key| fixed32("an account identity key", &key))
        .transpose()
}

/// A 32-byte Ed25519 quantity — a seed or a public key — named in the error, so
/// that a caller who passed a base64 string by mistake is told which argument
/// and how long it should have been.
fn fixed32(what: &str, bytes: &[u8]) -> Result<[u8; ED25519_PUBLIC_KEY_BYTES], JsError> {
    <[u8; ED25519_PUBLIC_KEY_BYTES]>::try_from(bytes).map_err(|_| {
        JsError::new(&format!(
            "{what} must be exactly {ED25519_PUBLIC_KEY_BYTES} bytes, got {}",
            bytes.len()
        ))
    })
}

// ---- Calling the host store -------------------------------------------------
//
// The KV crosses as a plain JS object rather than as a wasm-bindgen class,
// because the implementation is JavaScript: the web client's is IndexedDB, a
// test's is a Map, and a future one might be a worker port. A duck-typed object
// is the only shape all three can have. The cost is that every call is a
// `Reflect::get` plus a dynamic cast, and every failure of that lookup has to
// say which of the four methods was missing — which is what these do.

/// What went wrong, as a sentence rather than as `JsValue(Object)`.
///
/// An `Error` gives up its `message`; a thrown string is itself; anything else
/// falls back to Debug, which is the honest answer for a thrown `{}`.
fn describe(value: &JsValue) -> String {
    if let Some(text) = value.as_string() {
        return text;
    }
    if let Ok(message) = Reflect::get(value, &JsValue::from_str("message")) {
        if let Some(text) = message.as_string() {
            return text;
        }
    }
    format!("{value:?}")
}

/// Look one of the four methods up on the store object.
fn host_method(store: &JsValue, name: &str) -> Result<Function, JsError> {
    let value = Reflect::get(store, &JsValue::from_str(name)).map_err(|err| {
        JsError::new(&format!(
            "could not read `{name}` off the store: {}",
            describe(&err)
        ))
    })?;
    value.dyn_into::<Function>().map_err(|_| {
        JsError::new(&format!(
            "the store object has no `{name}` method; it must implement MlsKvStore"
        ))
    })
}

/// Call a host method and await whatever it returned.
///
/// `Promise::resolve` rather than a cast, so a synchronous implementation — a
/// test double backed by a `Map` that forgot to be async — works instead of
/// failing with a type error about a value that was perfectly good.
async fn awaited(
    method: &Function,
    store: &JsValue,
    args: &[JsValue],
    name: &str,
) -> Result<JsValue, JsError> {
    let arguments = Array::new();
    for arg in args {
        arguments.push(arg);
    }
    let returned = method
        .apply(store, &arguments)
        .map_err(|err| JsError::new(&format!("the store's `{name}` threw: {}", describe(&err))))?;
    JsFuture::from(Promise::resolve(&returned))
        .await
        .map_err(|err| {
            JsError::new(&format!(
                "the store's `{name}` rejected: {}",
                describe(&err)
            ))
        })
}

/// A secret or plaintext text argument, taken as its UTF-8 bytes rather than
/// as a JS string: the glue copies a `Uint8Array` into one block of its exact
/// length, where it grows a string with a non-ASCII character by a
/// reallocation that can leave the string's start in the block it frees.
/// Borrowed, so the binding's own wiped copy is the only one it makes.
fn utf8_argument<'a>(bytes: &'a [u8], what: &str) -> Result<&'a str, JsError> {
    std::str::from_utf8(bytes).map_err(|_| JsError::new(&format!("{what} is not UTF-8")))
}

/// A `Uint8Array` from JS, as bytes. Anything else is the caller's bug, named.
fn bytes_from_js(value: &JsValue, what: &str) -> Result<Vec<u8>, JsError> {
    value
        .dyn_ref::<Uint8Array>()
        .map(Uint8Array::to_vec)
        .ok_or_else(|| JsError::new(&format!("{what} must be a Uint8Array")))
}

/// The store's schema stamp, or `None` if it has never been written to.
async fn host_get(store: &JsValue, key: &[u8]) -> Result<Option<Vec<u8>>, JsError> {
    let method = host_method(store, "get")?;
    let value = awaited(&method, store, &[Uint8Array::from(key).into()], "get").await?;
    if value.is_null() || value.is_undefined() {
        return Ok(None);
    }
    bytes_from_js(&value, "what the store's `get` returned").map(Some)
}

/// Everything under `prefix`, as the cache will hold it.
async fn host_iterate(store: &JsValue, prefix: &[u8]) -> Result<Vec<KvEntry>, JsError> {
    let method = host_method(store, "iterate")?;
    let value = awaited(
        &method,
        store,
        &[Uint8Array::from(prefix).into()],
        "iterate",
    )
    .await?;
    let rows = value.dyn_into::<Array>().map_err(|_| {
        JsError::new("the store's `iterate` must resolve to an array of [key, value] pairs")
    })?;

    // Store values, wiped if a row further on is refused; handed on whole
    // otherwise.
    let mut entries = Zeroizing::new(Vec::with_capacity(rows.length() as usize));
    for row in rows.iter() {
        let pair = row
            .dyn_into::<Array>()
            .map_err(|_| JsError::new("every row from `iterate` must be a [key, value] pair"))?;
        if pair.length() != 2 {
            return Err(JsError::new(&format!(
                "every row from `iterate` must be a [key, value] pair; got one of length {}",
                pair.length()
            )));
        }
        entries.push((
            bytes_from_js(&pair.get(0), "a key from `iterate`")?,
            bytes_from_js(&pair.get(1), "a value from `iterate`")?,
        ));
    }
    Ok(std::mem::take(&mut *entries))
}

/// Write everything the cache owes the host, in ONE transaction, and stop
/// owing it once the host says it landed.
///
/// ## Why the whole batch goes over in one call
///
/// A commit's worth of writes is a dozen keys — a tree, a group context, an
/// epoch's key pairs, a group state — and they are one state, not twelve.
/// `kv.rs` promises "a lost flush loses the LAST OPERATION WHOLE, never half of
/// one", and that promise is the host's to keep. Handed over one key at a
/// time, to a store that opens a fresh readwrite transaction per call (as
/// the web client's IndexedDB store does), a tab closed midway
/// through the loop would leave a TORN group — some of an
/// epoch's rows at the new epoch and some at the old — which
/// `MlsGroup::load` reads back as `Ok(None)`, i.e. a group the device quietly
/// forgets. So the contract is one method, `writeBatch`, taking the lot.
///
/// ## Why nothing is discharged until the host answers
///
/// The dirty set is PEEKED, not taken, and only cleared once `writeBatch`
/// resolves. Until then `client.pendingWrites` still counts every key — which
/// is the point of that number: it is what a caller checks before letting the
/// tab go, and a count that dropped to zero when the work was picked up rather
/// than when it landed is a count that says "safe" in exactly the window it
/// exists to warn about.
///
/// A rejection leaves the whole batch owed, so the next `flush()` retries all
/// of it. Nothing is retried automatically: a caller that gets a rejection has
/// to decide whether to try again or to tell the reader, and a silent retry
/// loop inside a binding is how a full disk becomes a hang.
async fn drain(store: &JsValue, cache: &CacheKv) -> Result<(), JsError> {
    // Checked again here, and not only at `flush()`: a drain's future can be
    // polled after a panic elsewhere poisoned the instance.
    live()?;
    // Resolved BEFORE anything is read off the dirty set: a store missing its
    // `writeBatch` must not also cost us the record of what to write.
    let write_batch = host_method(store, "writeBatch")?;

    let pending = cache.peek_pending();
    if pending.is_empty() {
        return Ok(());
    }

    let rows = Array::new();
    for (key, value) in &pending {
        let row = Array::new();
        row.push(&Uint8Array::from(key.as_slice()).into());
        match value {
            // `null`, not `undefined`: a delete has to be distinguishable from
            // a missing element, and `undefined` is also what a misspelled
            // property gives back.
            Some(bytes) => row.push(&Uint8Array::from(bytes.as_slice()).into()),
            None => row.push(&JsValue::NULL),
        };
        rows.push(&row);
    }

    awaited(&write_batch, store, &[rows.into()], "writeBatch").await?;
    cache.commit_pending(&pending);
    Ok(())
}

// ---- The clock --------------------------------------------------------------
//
// `SystemClock`, the core's default, calls `std::time::SystemTime::now()` —
// which on `wasm32-unknown-unknown` is not "wrong", it is `unreachable`. The
// whole test suite failed on it first time round, four tests deep inside the
// credential check, with a stack that names `std::time::SystemTime::now` and
// nothing about the browser. There is no host clock in that target at all, so
// the time has to come from JS.
//
// It goes here rather than in the core for the same reason the getrandom
// opt-in does: only the crate that knows it is being compiled for a browser can
// answer "what is the clock?", and `ClientConfig::clock` is the door the core
// already opens for it. The alternative — teaching `SystemClock` to use
// `web_time` under `cfg(wasm32)` — is a change to the core that every other
// binding pays for, and would still be this decision, made somewhere a reader
// of the wasm build would not look.

/// The wall clock, from JavaScript. `Date.now()` and not `performance.now()`:
/// a credential expiry is an absolute unix time, and performance timers are
/// monotonic from an arbitrary origin.
#[cfg(target_arch = "wasm32")]
#[derive(Debug, Clone, Copy)]
struct JsClock;

#[cfg(target_arch = "wasm32")]
impl peachy_mls_core::Clock for JsClock {
    fn now_unix(&self) -> i64 {
        (js_sys::Date::now() / 1000.0) as i64
    }

    /// The live call lane's stamps want milliseconds (threat model D3).
    fn now_unix_ms(&self) -> i64 {
        js_sys::Date::now() as i64
    }

    /// `performance.now()`: monotonic from the page's (or worker's) start,
    /// for a call's rotation due time, which setting the wall clock must not
    /// move. Mandatory here: the core's default reads `std::time::Instant`,
    /// which traps on wasm32-unknown-unknown. `Date.now()` only where a host
    /// has no `performance` (every browser and Node 16+ do).
    fn monotonic_ms(&self) -> u64 {
        use wasm_bindgen::JsCast as _;
        let perf = js_sys::Reflect::get(&js_sys::global(), &"performance".into())
            .ok()
            .filter(|value| value.is_object());
        let now = perf.and_then(|perf| {
            let now: js_sys::Function = js_sys::Reflect::get(&perf, &"now".into())
                .ok()?
                .dyn_into()
                .ok()?;
            now.call0(&perf).ok()?.as_f64()
        });
        match now {
            Some(ms) if ms.is_finite() && ms >= 0.0 => ms as u64,
            _ => js_sys::Date::now() as u64,
        }
    }
}

/// `None` on the host, where the core's `SystemClock` is correct; the JS clock
/// on wasm32, where it is a trap.
fn platform_clock() -> Option<Box<dyn peachy_mls_core::Clock>> {
    #[cfg(target_arch = "wasm32")]
    {
        Some(Box::new(JsClock))
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        None
    }
}

// ---- The client -------------------------------------------------------------

/// The durable half of a client: the JS store, and the cache that owes it
/// writes. `None` on a client built with `new MlsClient(...)`.
///
/// `Clone` is two handles on one store — the cache shares its map through an
/// `Arc` — which is what lets `flush()` hand an owned copy to a future instead
/// of borrowing the client across an await.
#[derive(Clone)]
struct Backing {
    store: JsValue,
    cache: CacheKv,
}

/// One signed-in device, and the groups it is in.
///
/// Built with `new MlsClient(...)` it holds every group's secret in memory and
/// a page reload loses them. Built with `await MlsClient.open(store, ...)` it
/// reads its state back from `store` and writes it there on every awaited
/// `flush()`.
///
/// Call `free()` when you are done with it — wasm-bindgen will not collect the
/// Rust side for you. `free()` does NOT flush: dropping a client with pending
/// writes discards them, deliberately, because a destructor cannot await.
#[wasm_bindgen]
pub struct MlsClient {
    inner: Client,
    backing: Option<Backing>,
}

#[wasm_bindgen]
impl MlsClient {
    /// Build a client from this device's identity material.
    ///
    /// - `trustedServerKeys` — the body of `GET /healthz/device-credential-keys`
    ///   as text, not a parsed object: the core reads it in one place so that
    ///   three clients cannot each find their own way to drop the previous keys
    ///   and each be surprised by a rotation.
    /// - `deviceCredentialToken` — the `pdc1.…` token the server issued, as the
    ///   ASCII string it is.
    /// - `deviceSigningKeySeed` — the raw 32-byte Ed25519 seed from the
    ///   platform key store. **Required**, unlike the optional third argument a
    ///   reader might expect: the credential binds this key's public half, so a
    ///   client built with a seed nobody minted a credential for fails here
    ///   with `leaf_key_mismatch` on every single call. Use
    ///   `generateSigningKeySeed()` + `signingKeyPublicKey()` to make one at
    ///   enrollment, *before* asking the server for a credential.
    ///
    /// - `ownAccountIdentity` — optional: the 32-byte account identity key this
    ///   device derives from the account key it HOLDS
    ///   (`accountIdentityPublicKey`), or `undefined`/`null` when it holds
    ///   none. A credential certified under any other account key throws
    ///   `not_own_account_key`, and without one so does any certified
    ///   credential: a device holding no key opens only uncertified. A
    ///   credential with no certificate still opens
    ///   (docs/identity.md §The account identity key).
    ///
    /// Throws if the credential does not check out against the trusted keys, or
    /// if it is not bound to this seed.
    #[wasm_bindgen(constructor)]
    pub fn new(
        trusted_server_keys: &str,
        device_credential_token: &str,
        device_signing_key_seed: Vec<u8>,
        own_account_identity: Option<Vec<u8>>,
    ) -> Result<MlsClient, JsError> {
        // A secret argument: this module's own copy, wiped on return.
        let device_signing_key_seed = Zeroizing::new(device_signing_key_seed);
        let device_signing_key_seed: &[u8] = &device_signing_key_seed;
        live()?;
        let trusted = TrustedServerKeys::from_published_json(trusted_server_keys).map_err(throw)?;
        let seed = Zeroizing::new(fixed32(
            "a device signing key seed",
            device_signing_key_seed,
        )?);
        let own_account_identity = optional_identity(own_account_identity)?;
        let config = ClientConfig {
            clock: platform_clock(),
            ..ClientConfig::with_seed(device_credential_token.as_bytes().to_vec(), seed, trusted)
                .with_own_account_identity(own_account_identity)
        };
        Ok(Self {
            inner: Client::new(config).map_err(throw)?,
            backing: None,
        })
    }

    /// Build a client over a durable store, reading back whatever it holds.
    ///
    /// The constructor's three identity arguments, unchanged and in the same
    /// order, then `store` — a JavaScript object implementing `MlsKvStore`. The
    /// web client's is IndexedDB (the web client's IndexedDB store).
    /// Then the constructor's optional `ownAccountIdentity`.
    ///
    /// What it does, in order: reads the store's schema stamp (one `get`, so a
    /// store written by a newer build is refused before it is downloaded);
    /// reads every key this schema owns (one `iterate`); rebuilds every group
    /// the device was in; and flushes, which stamps a brand-new store. From
    /// then on nothing touches the store until `flush()`.
    ///
    /// **Every mutating call needs a `flush()` after it** — `createGroup`,
    /// `addMember`, `encrypt`, `processCommit`, all of them. The crate docs explain
    /// why it cannot be automatic and what a missed one costs.
    ///
    /// Throws for the constructor's reasons, plus: the store is unreadable, the
    /// store is at a schema this build does not read, or the object is not an
    /// `MlsKvStore`. It never falls back to an ephemeral client — a chat that
    /// silently stopped persisting is worse than one that would not open.
    #[wasm_bindgen(js_name = open)]
    pub async fn open(
        trusted_server_keys: String,
        device_credential_token: String,
        device_signing_key_seed: Vec<u8>,
        store: MlsKvStoreJs,
        own_account_identity: Option<Vec<u8>>,
    ) -> Result<MlsClient, JsError> {
        // The seed came in as a vector of its own: wiped wherever this
        // returns, an early `?` included. The JavaScript array it was copied
        // from is the caller's.
        let device_signing_key_seed = Zeroizing::new(device_signing_key_seed);
        live()?;
        // Owned `String`/`Vec<u8>` rather than the constructor's borrows: an
        // async fn's future outlives the call that made it, so wasm-bindgen
        // cannot lend it a view of a JS buffer.
        let store: JsValue = store.into();

        let stamp = host_get(&store, &schema_stamp_key()).await?;
        check_schema_stamp(stamp.as_deref()).map_err(|err| JsError::new(&err.to_string()))?;

        let cache = CacheKv::hydrated(host_iterate(&store, &schema_prefix()).await?);
        let storage = PeachyStorage::open(Box::new(cache.clone()))
            .map_err(|err| JsError::new(&err.to_string()))?;

        let trusted =
            TrustedServerKeys::from_published_json(&trusted_server_keys).map_err(throw)?;
        let seed = Zeroizing::new(fixed32(
            "a device signing key seed",
            &device_signing_key_seed,
        )?);
        let mut config =
            ClientConfig::with_seed(device_credential_token.into_bytes(), seed, trusted)
                .with_storage(storage)
                .with_own_account_identity(optional_identity(own_account_identity)?);
        config.clock = platform_clock();

        let inner = Client::new(config).map_err(throw)?;

        // Opening a fresh store writes its schema stamp, and reopening one can
        // drop a group id whose state did not survive. Neither is worth losing.
        drain(&store, &cache).await?;

        Ok(Self {
            inner,
            backing: Some(Backing { store, cache }),
        })
    }

    /// Write everything this client owes its store, and resolve when it is
    /// there. Resolves immediately on an ephemeral client, which owes nothing.
    ///
    /// Call it after every mutating operation, and **await it before telling
    /// the delivery service anything** — a commit the server has that this
    /// device did not keep is the state worth avoiding.
    ///
    /// Rejects if the store did. The batch is one transaction, so a rejection
    /// leaves ALL of it owed and a later `flush()` retries the whole thing —
    /// there is no half-written state to reason about.
    #[wasm_bindgen(js_name = flush)]
    pub fn flush(&self) -> PromiseVoidJs {
        // A poisoned instance writes nothing: what it holds is whatever the
        // panic interrupted.
        install_poison_hook();
        if poisoned() {
            return JsValue::from(Promise::reject(&JsError::new(POISONED_MESSAGE).into()))
                .unchecked_into();
        }
        // An owned snapshot of two cheap handles, so the future borrows nothing
        // from `self`. A `&self` async method would make a second call while a
        // flush is in flight a "recursive use of an object" panic, and flushing
        // is exactly the thing a caller will do concurrently.
        let backing = self.backing.clone();
        let promise = future_to_promise(async move {
            match backing {
                None => Ok(JsValue::UNDEFINED),
                Some(backing) => drain(&backing.store, &backing.cache)
                    .await
                    .map(|()| JsValue::UNDEFINED)
                    .map_err(JsValue::from),
            }
        });
        JsValue::from(promise).unchecked_into()
    }

    /// How many keys are waiting on a `flush()`. `0` on an ephemeral client.
    ///
    /// This is the number that makes the crash window measurable instead of
    /// rhetorical: a test asserts it is non-zero after a commit and zero after
    /// the flush, and a caller can assert it is zero before it lets the tab go.
    ///
    /// It counts what is still OWED, not what is unstarted: a flush in flight
    /// leaves every one of its keys counted until the store's promise resolves.
    /// Dropping to zero the moment the drain picks the work up would make it
    /// read "safe" during precisely the window it exists to warn about.
    #[wasm_bindgen(getter, js_name = pendingWrites)]
    pub fn pending_writes(&self) -> usize {
        refuse_if_poisoned();
        self.backing
            .as_ref()
            .map_or(0, |backing| backing.cache.pending_count())
    }

    /// This device's verified identity.
    #[wasm_bindgen(getter)]
    pub fn identity(&self) -> Result<MlsIdentityJs, JsError> {
        live()?;
        to_js(&IdentityDto::from(self.inner.identity()))
    }

    /// The identity INSIDE a raw key package, read out of the bytes rather
    /// than taken from whoever handed them over.
    ///
    /// This is what makes a device approval checkable without trusting the
    /// directory that served the key package
    /// (docs/identity.md §What the adder checks). Before seating
    /// another device of its own account, a client checks that device's
    /// stored approval against a key it already trusts
    /// (`checkOwnDeviceApproval`, which reads the package this way itself),
    /// and that needs the new device's `deviceId` and signing key. Taking
    /// either from the server would defeat the check: a
    /// server can answer with a truthful pair for the verification and a key
    /// package carrying a DIFFERENT key, and the leaf that lands is then one
    /// nobody approved. `identity.deviceKey` is that key, straight out of the
    /// package.
    ///
    /// A well-formed package whose credential does not verify comes back as
    /// `{ identity: null, rejection }` — a verdict, not a throw, exactly as on
    /// the roster. It THROWS only when the bytes are not a key package this
    /// build accepts at all, which is a different answer and deliberately not
    /// reachable through `rejection`. The accepted encoding is `addMember`'s.
    #[wasm_bindgen(js_name = keyPackageIdentity)]
    pub fn key_package_identity(
        &self,
        key_package: &[u8],
    ) -> Result<MlsKeyPackageIdentityJs, JsError> {
        live()?;
        let verdict = self
            .inner
            .key_package_identity(key_package)
            .map_err(throw)?;
        to_js(&KeyPackageIdentityDto::from(&verdict))
    }

    /// Sign a request to be seated in `groupId` as this device, now: the
    /// 89-byte proof (`mls/core/src/join_request.rs`) that travels beside a
    /// seat ask's `{actor, device}` claim. Every seat ask carries one.
    #[wasm_bindgen(js_name = signJoinRequest)]
    pub fn sign_join_request(&self, group_id: &[u8]) -> Result<Vec<u8>, JsError> {
        live()?;
        self.inner.sign_join_request(group_id).map_err(throw)
    }

    /// Whether this is the first time this device has taken in this signed
    /// seat ask for `groupId`: true once, then false for the same proof while
    /// it could still verify. Asked when a seat ask ARRIVES, before it is
    /// queued, never on a retry of one already taken in, so a delivery
    /// service handing the same ask over again seats nobody twice.
    #[wasm_bindgen(js_name = firstSightOfJoinRequest)]
    pub fn first_sight_of_join_request(
        &mut self,
        group_id: &[u8],
        proof: &[u8],
    ) -> Result<bool, JsError> {
        live()?;
        self.inner
            .first_sight_of_join_request(group_id, proof)
            .map_err(throw)
    }

    /// Whether this device has already taken in this signed seat ask
    /// (`firstSightOfJoinRequest`), keeping no record: for an ask that waits
    /// in a join inbox and is read again on every pass until somebody acts
    /// on it.
    #[wasm_bindgen(js_name = joinRequestSeen)]
    pub fn join_request_seen(&mut self, group_id: &[u8], proof: &[u8]) -> Result<bool, JsError> {
        live()?;
        self.inner.join_request_seen(group_id, proof).map_err(throw)
    }

    /// May this device seat the device in `keyPackage`, one of its own
    /// account's? (docs/identity.md §What the adder checks.)
    /// `approverDeviceId` and `approvalSignature` are that device's
    /// `Device.approved_by_device_id` and `Device.approval_signature` from
    /// ListDevices, or empty; they count only if the signature verifies under
    /// a device on this device's approval chain. Never throws; only `seats`
    /// may seat.
    #[wasm_bindgen(js_name = checkOwnDeviceApproval)]
    pub fn check_own_device_approval(
        &mut self,
        key_package: &[u8],
        approver_device_id: &str,
        approval_signature: &[u8],
    ) -> Result<MlsOwnDeviceVerdictJs, JsError> {
        live()?;
        let verdict = self.inner.check_own_device_approval(
            key_package,
            approver_device_id,
            approval_signature,
        );
        to_js(&OwnDeviceVerdictDto {
            code: verdict.code(),
            name: verdict.name(),
            seats: verdict.seats(),
        })
    }

    /// May this device hand its account's history to `deviceId`, a row of its
    /// own account's device list? The verdict `checkOwnDeviceApproval` gives,
    /// read from the row: `deviceKey` is `Device.signing_key`, and
    /// `approverDeviceId` and `approvalSignature` the row's
    /// `approved_by_device_id` and `approval_signature`, or empty. Only
    /// `seats` gets the hand-off; anything else gets the nothing-to-send note
    /// (docs/sealed-messages.md §Handing history to your own new
    /// device). Reads only. Never throws.
    #[wasm_bindgen(js_name = checkOwnDeviceKey)]
    pub fn check_own_device_key(
        &self,
        device_id: &str,
        device_key: &[u8],
        approver_device_id: &str,
        approval_signature: &[u8],
    ) -> Result<MlsOwnDeviceVerdictJs, JsError> {
        live()?;
        let verdict = self.inner.check_own_device_key(
            device_id,
            device_key,
            approver_device_id,
            approval_signature,
        );
        to_js(&OwnDeviceVerdictDto {
            code: verdict.code(),
            name: verdict.name(),
            seats: verdict.seats(),
        })
    }

    /// Remember the device that let this one in, as this device learned it
    /// while taking the account key (the box opened under `signingKey`).
    /// Call it once, right after the account key is accepted from an
    /// approval. It writes and flushes.
    #[wasm_bindgen(js_name = rememberOwnApprover)]
    pub fn remember_own_approver(
        &mut self,
        device_id: &str,
        signing_key: &[u8],
    ) -> Result<(), JsError> {
        live()?;
        self.inner
            .remember_own_approver(device_id, signing_key)
            .map_err(throw)
    }

    /// Forget `deviceId`, a device of this account that the account removed
    /// (this device's own `RevokeDevice`, or a revoked row on the device
    /// list): no longer trusted as the device that let this one in, its
    /// leaves no longer known, its approvals vouch for nobody, and
    /// `checkOwnDeviceApproval` never seats it again. Forgotten with it is
    /// every key this device saw that id hold, and `signingKey` too when
    /// given (the device list's key for the row, 32 bytes): a forgotten key
    /// counts for nothing under any id. Idempotent; answers whether the
    /// device, or a key of it, was not forgotten already. Throws for this
    /// device's own id, an id outside the id charset, or a key that is not 32
    /// bytes. It writes and flushes.
    #[wasm_bindgen(js_name = forgetOwnDevice)]
    pub fn forget_own_device(
        &mut self,
        device_id: &str,
        signing_key: Option<Vec<u8>>,
    ) -> Result<bool, JsError> {
        live()?;
        self.inner
            .forget_own_device_with_key(device_id, signing_key.as_deref().unwrap_or_default())
            .map_err(throw)
    }

    /// The device ids of this account's OTHER devices that are leaves of a
    /// group this device is active in, each once: what this device has seen
    /// of its own account, from commits it verified. The "new device linked"
    /// notice is keyed on it. A leaf under a key its id was not first seen
    /// with comes back as `<device id>#<device key, 64 hex>`.
    #[wasm_bindgen(js_name = ownSiblingLeaves)]
    pub fn own_sibling_leaves(&mut self) -> Result<Vec<String>, JsError> {
        live()?;
        self.inner.own_sibling_leaves().map_err(throw)
    }

    /// This client's own-device trust, as JSON: its identity, its approval
    /// chain, and every device id and key this account forgot. Handed to
    /// `adoptOwnDeviceTrust` of a call link's client on the same device
    /// (docs/calls.md §Call links on participant keys); it never
    /// leaves the device. Reads only.
    #[wasm_bindgen(js_name = ownDeviceTrust)]
    pub fn own_device_trust(&self) -> Result<String, JsError> {
        self.inner.own_device_trust().map_err(throw)
    }

    /// Adopt `trust`, the `ownDeviceTrust()` of this device's main client,
    /// into this (call link) client: its adds then refuse a forgotten device
    /// of the account, a Welcome signed by one seats it in nothing, and its
    /// own-device checks run on the main client's chain. Throws unless the
    /// form is this very device's; nothing is adopted unless all of it reads.
    /// Forgotten ids and keys accumulate across adoptions. In memory only.
    #[wasm_bindgen(js_name = adoptOwnDeviceTrust)]
    pub fn adopt_own_device_trust(&mut self, trust: &str) -> Result<(), JsError> {
        self.inner.adopt_own_device_trust(trust).map_err(throw)
    }

    /// Grow the refusals this client enforces by `names`, the refusals the
    /// delivery service switched on as the app holds them, separated by
    /// commas (docs/delivery.md §The protocol floor). Hand them in
    /// after every open and whenever the app's list grows. Never shrinks; a
    /// name this build does not know is ignored. In memory.
    #[wasm_bindgen(js_name = adoptClientRefusals)]
    pub fn adopt_client_refusals(&mut self, names: &str) -> Result<(), JsError> {
        live()?;
        self.inner
            .adopt_client_refusals(&peachy_mls_core::client_refusals::parse_names(names));
        Ok(())
    }

    /// What this client makes of a leaf `(actorId, deviceId, deviceKey)` in
    /// one of its groups, as a code: 0 another person's device, 1 this very
    /// device, 2 a device of this account on this client's approval chain, 3
    /// one on no chain here (or wearing this device's id or key), 4 one this
    /// account forgot. Only 1 and 2 count as the person's own. Never throws.
    #[wasm_bindgen(js_name = ownDeviceStanding)]
    pub fn own_device_standing(&self, actor_id: &str, device_id: &str, device_key: &[u8]) -> u32 {
        self.inner
            .own_device_standing(actor_id, device_id, device_key)
            .code()
    }

    /// Whether `(actorId, deviceId)`'s signed request to be seated in
    /// `groupId` holds, checked against `keyPackage`: the package fetched to
    /// seat that device. Never throws; only `code === 0` may seat anybody.
    ///
    /// `pendingActors` names the people the caller is itself still trying to
    /// add, from its own invitations and never from the ask: besides current
    /// members and this device's own person, the only askers who can be
    /// accepted. Anybody else is `not_a_member` (7): a signed ask proves who
    /// is asking, never that they belong. So is a person whose last leaf this
    /// device saw leave the group, even when `pendingActors` names them; a
    /// person the caller admits by its own rule goes through
    /// `verifyAdmittedJoinRequest`.
    #[wasm_bindgen(js_name = verifyJoinRequest)]
    pub fn verify_join_request(
        &self,
        group_id: &[u8],
        actor_id: &str,
        device_id: &str,
        proof: &[u8],
        key_package: &[u8],
        pending_actors: Vec<String>,
    ) -> Result<MlsJoinRequestVerdictJs, JsError> {
        live()?;
        let pending: Vec<&str> = pending_actors.iter().map(String::as_str).collect();
        let verdict = self.inner.verify_join_request(
            group_id,
            actor_id,
            device_id,
            proof,
            key_package,
            &pending,
        );
        to_js(&JoinRequestVerdictDto {
            code: verdict.code(),
            name: verdict.name(),
        })
    }

    /// `verifyJoinRequest` for a person this device has itself decided to
    /// admit by its own rule: somebody who asked through a group link it
    /// approved, or through an open group's join inbox. Every check but
    /// membership, which the caller's rule already decided; a person who left
    /// the group may come back this way. Never for a rejoin's seat ask
    /// (envelope kind 3). Never throws; only `code === 0` may seat anybody.
    #[wasm_bindgen(js_name = verifyAdmittedJoinRequest)]
    pub fn verify_admitted_join_request(
        &self,
        group_id: &[u8],
        actor_id: &str,
        device_id: &str,
        proof: &[u8],
        key_package: &[u8],
    ) -> Result<MlsJoinRequestVerdictJs, JsError> {
        live()?;
        let verdict = self.inner.verify_admitted_join_request(
            group_id,
            actor_id,
            device_id,
            proof,
            key_package,
        );
        to_js(&JoinRequestVerdictDto {
            code: verdict.code(),
            name: verdict.name(),
        })
    }

    /// The group ids this client holds state for, as an array of `Uint8Array`.
    /// The actors in `groupId` whose account identity key CHANGED since this
    /// device pinned it — each one a "security code changed" notice for this
    /// conversation (docs/identity.md §Security code changed). The
    /// first key seen is pinned in silence. Call after anything that can
    /// change the tree; it writes, so `flush()` after.
    #[wasm_bindgen(js_name = observeAccountKeys)]
    pub fn observe_account_keys(&mut self, group_id: &[u8]) -> Result<ActorIdsJs, JsError> {
        live()?;
        let out = Array::new();
        for actor in self.inner.observe_account_keys(group_id).map_err(throw)? {
            out.push(&JsValue::from(actor));
        }
        Ok(JsValue::from(out).unchecked_into())
    }

    #[wasm_bindgen(js_name = groupIds)]
    pub fn group_ids(&self) -> GroupIdsJs {
        refuse_if_poisoned();
        let out = Array::new();
        for id in self.inner.group_ids() {
            out.push(&Uint8Array::from(id.as_slice()));
        }
        JsValue::from(out).unchecked_into()
    }

    /// Mint a key package for somebody else to add us with. Single-use: each
    /// call leaves a fresh private half in this client's storage, so publishing
    /// N of them is how a person is added N times while offline.
    #[wasm_bindgen(js_name = generateKeyPackage)]
    pub fn generate_key_package(&self) -> Result<Vec<u8>, JsError> {
        live()?;
        self.inner.generate_key_package().map_err(throw)
    }

    /// Mint a key package together with the RFC 9420 KeyPackageRef naming it.
    ///
    /// What a client publishing to a key-package directory wants, rather than
    /// the bare bytes above: Peachy's `PublishKeyPackages` takes the ref as the
    /// idempotency key, and it is a hash of the TLS-serialized KeyPackage —
    /// NOT of the `MlsMessage`-framed bytes it comes back beside — so a caller
    /// that hashes what it was handed computes a value no other MLS
    /// implementation agrees with, and republishing a pool grows it instead of
    /// being the no-op it is meant to be.
    #[wasm_bindgen(js_name = generateKeyPackageWithRef)]
    pub fn generate_key_package_with_ref(&self) -> Result<MlsKeyPackageJs, JsError> {
        live()?;
        let (key_package, key_package_ref) =
            self.inner.generate_key_package_with_ref().map_err(throw)?;
        to_js(&KeyPackageDto {
            ciphersuite: u16::from(PEACHY_CIPHERSUITE),
            key_package,
            key_package_ref,
        })
    }

    /// A LAST-RESORT key package with its ref: the one to publish with
    /// `lastResort` set. It carries the `last_resort` extension, so unlike
    /// `generateKeyPackageWithRef` it opens any number of Welcomes until it is
    /// rotated (docs/mls-core.md §Last-resort key packages).
    #[wasm_bindgen(js_name = generateLastResortKeyPackageWithRef)]
    pub fn generate_last_resort_key_package_with_ref(&self) -> Result<MlsKeyPackageJs, JsError> {
        live()?;
        let (key_package, key_package_ref) = self
            .inner
            .generate_last_resort_key_package_with_ref()
            .map_err(throw)?;
        to_js(&KeyPackageDto {
            ciphersuite: u16::from(PEACHY_CIPHERSUITE),
            key_package,
            key_package_ref,
        })
    }

    /// Whether this device owes the directory a new last-resort key package:
    /// none minted by this build yet, or the newest is two days old.
    #[wasm_bindgen(js_name = lastResortRotationDue)]
    pub fn last_resort_rotation_due(&self) -> Result<bool, JsError> {
        live()?;
        self.inner.last_resort_rotation_due().map_err(throw)
    }

    /// Create a group with this client as its only member.
    #[wasm_bindgen(js_name = createGroup)]
    pub fn create_group(&mut self, group_id: &[u8]) -> Result<(), JsError> {
        live()?;
        self.inner.create_group(group_id).map_err(throw)
    }

    /// Join from a Welcome. Returns the group id joined.
    #[wasm_bindgen(js_name = joinFromWelcome)]
    pub fn join_from_welcome(&mut self, welcome: &[u8]) -> Result<Vec<u8>, JsError> {
        live()?;
        self.inner.join_from_welcome(welcome).map_err(throw)
    }

    /// The group id of the Welcome the last `joinFromWelcome` refused as
    /// `already a member` because this device already held an active group
    /// under that id, or `undefined`. Two seats under one id are a contest
    /// the group's head decides (docs/delivery.md §Two seats under
    /// one group id): fetch the head for the group's handle and hand it to
    /// `joinContestedWelcome`.
    #[wasm_bindgen(js_name = contestedWelcomeGroupId)]
    pub fn contested_welcome_group_id(&self) -> Option<Vec<u8>> {
        refuse_if_poisoned();
        self.inner.contested_welcome_group_id()
    }

    /// Settle the contested Welcome against the group's head (its epoch and
    /// send-key verifier). Returns the group id when the Welcome took the
    /// seat, replacing the held group; throws `already a member` when the held
    /// group keeps it. The Welcome is gone either way.
    #[wasm_bindgen(js_name = joinContestedWelcome)]
    pub fn join_contested_welcome(
        &mut self,
        head_epoch: f64,
        head_verifier: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        live()?;
        if !(head_epoch.is_finite() && head_epoch >= 0.0 && head_epoch.fract() == 0.0) {
            return Err(JsError::new(
                "invalid argument: the head epoch is not a whole number",
            ));
        }
        self.inner
            .join_contested_welcome(head_epoch as u64, head_verifier)
            .map_err(throw)
    }

    /// The group a Welcome is for, and the epoch it would seat this device
    /// at, read without taking it: what `joinFromWelcomeAtHead` needs the
    /// group's head for. Both as the Welcome claims them. Writes nothing.
    #[wasm_bindgen(js_name = welcomeGroup)]
    pub fn welcome_group(&mut self, welcome: &[u8]) -> Result<MlsWelcomeGroupJs, JsError> {
        live()?;
        let (group_id, epoch) = self.inner.welcome_group(welcome).map_err(throw)?;
        // Epochs are far below 2^53.
        to_js(&WelcomeGroupDto {
            group_id,
            epoch: epoch as f64,
        })
    }

    /// Join from a Welcome against the group's head (its epoch and send-key
    /// verifier): the door every Welcome goes through. Above the head, or at
    /// its epoch under another send key, it throws `already a member`; at
    /// the head it is taken and confirmed; below it, taken unconfirmed when
    /// no active copy is held. `settle first` puts the key package back: the
    /// same call succeeds once the saved commit is settled. Returns the group
    /// id joined (docs/delivery.md §Two seats under one group id).
    #[wasm_bindgen(js_name = joinFromWelcomeAtHead)]
    pub fn join_from_welcome_at_head(
        &mut self,
        welcome: &[u8],
        head_epoch: f64,
        head_verifier: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        live()?;
        if !(head_epoch.is_finite() && head_epoch >= 0.0 && head_epoch.fract() == 0.0) {
            return Err(JsError::new(
                "invalid argument: the head epoch is not a whole number",
            ));
        }
        self.inner
            .join_from_welcome_at_head(welcome, head_epoch as u64, head_verifier)
            .map_err(throw)
    }

    /// `joinFromWelcomeAtHead`, with the delivery service's verifier-log
    /// answer for the Welcome's own epoch (`FetchVerifierAt`,
    /// docs/delivery.md §FetchVerifierAt): the verifier logged
    /// there, or an empty array when it holds none, and `keptFrom`, the
    /// lowest epoch from which the log holds every epoch up to the head
    /// (`undefined` when the server named none). A Welcome below the head
    /// whose send key hashes to the verifier is taken and confirmed, as one
    /// at the head is; one whose send key does not, or one at or above
    /// `keptFrom` with nothing logged, throws `already a member`. Pass only
    /// an answer the server gave: a failed read holds the Welcome.
    #[wasm_bindgen(js_name = joinFromWelcomeAtHeadLogged)]
    pub fn join_from_welcome_at_head_logged(
        &mut self,
        welcome: &[u8],
        head_epoch: f64,
        head_verifier: &[u8],
        logged_verifier: &[u8],
        kept_from: Option<f64>,
    ) -> Result<Vec<u8>, JsError> {
        live()?;
        let whole = |n: f64| n.is_finite() && n >= 0.0 && n.fract() == 0.0;
        if !whole(head_epoch) {
            return Err(JsError::new(
                "invalid argument: the head epoch is not a whole number",
            ));
        }
        if kept_from.is_some_and(|floor| !whole(floor)) {
            return Err(JsError::new(
                "invalid argument: the verifier log's floor is not a whole number",
            ));
        }
        self.inner
            .join_from_welcome_at_head_logged(
                welcome,
                head_epoch as u64,
                head_verifier,
                logged_verifier,
                kept_from.map(|floor| floor as u64),
            )
            .map_err(throw)
    }

    /// Hand the group's head to the copy this device holds: a copy at the
    /// head is confirmed, and a confirmed one beside it (same epoch, another
    /// send key) lapses. An active copy no head has matched yet is confirmed
    /// by a head at any of its last 64 epochs under its send key there, and
    /// contested by one under another (the rejoin report then says
    /// `contested`); a head above the copy, and a head below a copy a head
    /// matched once, change nothing. Returns
    /// whether the copy is confirmed now; false for a group not held. Only a
    /// confirmed copy's epochs raise the epoch mark; no head lowers the mark or
    /// takes away the roster a copy that matched a head once names to the
    /// Welcome judge. Call it with every head read.
    #[wasm_bindgen(js_name = confirmHead)]
    pub fn confirm_head(
        &mut self,
        group_id: &[u8],
        head_epoch: f64,
        head_verifier: &[u8],
    ) -> Result<bool, JsError> {
        live()?;
        if !(head_epoch.is_finite() && head_epoch >= 0.0 && head_epoch.fract() == 0.0) {
            return Err(JsError::new(
                "invalid argument: the head epoch is not a whole number",
            ));
        }
        self.inner
            .confirm_head(group_id, head_epoch as u64, head_verifier)
            .map_err(throw)
    }

    /// Whether the group's head was ROLLED BACK below the copy this device
    /// holds: an active copy past `head_epoch` on which the group's own head
    /// once stood above `head_epoch`, and which held that epoch under the send
    /// key `head_verifier` names when it is one of the copy's last 64 epochs
    /// (below all of them, that the head stood above it is enough only on a
    /// copy that has kept 64 epochs since its seat, in a group no steward was
    /// ever named for on it). Such a head is no fork: keep the copy, neither
    /// forget the group nor ask back in. False for a head at or above the
    /// copy, a group not held, a head the group's own head never stood above
    /// on this copy, a verifier of any length but 32, within the last 64
    /// epochs one that differs from the copy's own there, and below them any
    /// other head. Reads only.
    #[wasm_bindgen(js_name = headRolledBack)]
    pub fn head_rolled_back(
        &self,
        group_id: &[u8],
        head_epoch: f64,
        head_verifier: &[u8],
    ) -> Result<bool, JsError> {
        live()?;
        if !(head_epoch.is_finite() && head_epoch >= 0.0 && head_epoch.fract() == 0.0) {
            return Err(JsError::new(
                "invalid argument: the head epoch is not a whole number",
            ));
        }
        self.inner
            .head_rolled_back(group_id, head_epoch as u64, head_verifier)
            .map_err(throw)
    }

    /// When this device last finished reading the group's head, in unix
    /// milliseconds, as `noteHeadRead` recorded it; undefined when it never
    /// did for this copy, or the group is not held. Kept in the group's own
    /// records and dropped with the group. Reads only.
    #[wasm_bindgen(js_name = lastHeadRead)]
    pub fn last_head_read(&self, group_id: &[u8]) -> Result<Option<f64>, JsError> {
        live()?;
        Ok(self
            .inner
            .last_head_read(group_id)
            .map_err(throw)?
            .map(|at| at as f64))
    }

    /// Record that a read of the group's head finished at `atMs` (unix
    /// milliseconds), whatever it answered. Refused for a group not held.
    #[wasm_bindgen(js_name = noteHeadRead)]
    pub fn note_head_read(&mut self, group_id: &[u8], at_ms: f64) -> Result<(), JsError> {
        live()?;
        if !(at_ms.is_finite() && at_ms.fract() == 0.0) {
            return Err(JsError::new(
                "invalid argument: the read time is not a whole number",
            ));
        }
        self.inner
            .note_head_read(group_id, at_ms as i64)
            .map_err(throw)
    }

    /// BEGIN A HEAD READ of the group, before the head is fetched
    /// (docs/mls-core.md §Group recovery): `"read_head"` (fetch it, then
    /// `recoveryJudge`), `"held"` (held for its steward: read nothing) or
    /// `"no_copy"`. Snapshots the copy's epoch, verifier and last complete
    /// drain, in memory.
    #[wasm_bindgen(js_name = recoveryBegin)]
    pub fn recovery_begin(&mut self, group_id: &[u8]) -> Result<MlsRecoveryStepJs, JsError> {
        live()?;
        let step = self.inner.recovery_begin(group_id).map_err(throw)?;
        Ok(JsValue::from_str(step.name()).unchecked_into())
    }

    /// JUDGE A HEAD read since `recoveryBegin`: one of `MlsRecoveryStep`.
    /// `kind` is `"check"`, `"sealed_ahead"` or `"lost"`. `headEpoch`
    /// undefined: the server holds no head. `fresh`: the read began after
    /// the begin. On a `rejoin_*` step: read the leaves, `forgetGroup`, and
    /// send them a sealed seat ask. The head is handed to `confirmHead` on
    /// the way. `await flush()` after it.
    #[wasm_bindgen(js_name = recoveryJudge)]
    pub fn recovery_judge(
        &mut self,
        group_id: &[u8],
        kind: &str,
        head_epoch: Option<f64>,
        head_verifier: Option<Vec<u8>>,
        fresh: bool,
        now_ms: f64,
    ) -> Result<MlsRecoveryStepJs, JsError> {
        live()?;
        let kind = match kind {
            "check" => peachy_mls_core::HeadReadKind::Check,
            "sealed_ahead" => peachy_mls_core::HeadReadKind::SealedAhead,
            "lost" => peachy_mls_core::HeadReadKind::Lost,
            other => {
                return Err(JsError::new(&format!(
                    "invalid argument: unknown head read kind {other:?}"
                )))
            }
        };
        let head = match head_epoch {
            None => None,
            Some(epoch) if epoch.is_finite() && epoch >= 0.0 && epoch.fract() == 0.0 => {
                Some(peachy_mls_core::HeadReading {
                    epoch: epoch as u64,
                    verifier: head_verifier.unwrap_or_default(),
                })
            }
            Some(_) => {
                return Err(JsError::new(
                    "invalid argument: the head epoch is not a whole number",
                ))
            }
        };
        let now = millis_arg(now_ms, "nowMs")?;
        let step = self
            .inner
            .recovery_judge(group_id, kind, head.as_ref(), fresh, now)
            .map_err(throw)?;
        Ok(JsValue::from_str(step.name()).unchecked_into())
    }

    /// Whether to read the group's head over messages that would not open:
    /// at most once a minute per group, except that one sealed past the copy
    /// (`sealedAhead`, as a `stale copy:` refusal says) is let through once
    /// when the last read did not know of one. True counts as that read.
    #[wasm_bindgen(js_name = recoveryReadDue)]
    pub fn recovery_read_due(
        &mut self,
        group_id: &[u8],
        sealed_ahead: bool,
        now_ms: f64,
    ) -> Result<bool, JsError> {
        live()?;
        let now = millis_arg(now_ms, "nowMs")?;
        Ok(self.inner.recovery_read_due(group_id, sealed_ahead, now))
    }

    /// A mailbox drain that began at `startedAtMs` ran to the end. `evidence`
    /// false: its first page came on the stream. Answers the groups owed a
    /// second head reading now (kind `"check"`), each handed out once.
    #[wasm_bindgen(js_name = recoveryDrainComplete)]
    pub fn recovery_drain_complete(
        &mut self,
        started_at_ms: f64,
        evidence: bool,
        now_ms: f64,
    ) -> Result<GroupIdsJs, JsError> {
        live()?;
        let started = millis_arg(started_at_ms, "startedAtMs")?;
        let now = millis_arg(now_ms, "nowMs")?;
        let out = Array::new();
        for id in self.inner.recovery_drain_complete(started, evidence, now) {
            out.push(&Uint8Array::from(id.as_slice()));
        }
        Ok(JsValue::from(out).unchecked_into())
    }

    /// Add a member from their published key package.
    #[wasm_bindgen(js_name = addMember)]
    pub fn add_member(
        &mut self,
        group_id: &[u8],
        key_package: &[u8],
    ) -> Result<MlsCommitBundleJs, JsError> {
        live()?;
        let bundle = self
            .inner
            .add_member(group_id, key_package)
            .map_err(throw)?;
        to_js(&CommitBundleDto::from(bundle))
    }

    /// `addMember` for a rejoin's seat ask whose device holds no leaf, after
    /// `verifyJoinRequest` accepted it: the ask's membership is judged again,
    /// with the same `pendingActors`, on the store this add commits on, so a
    /// person removed after the verdict is not put back. A refusal throws and
    /// stages nothing.
    #[wasm_bindgen(js_name = addMemberForAsk)]
    pub fn add_member_for_ask(
        &mut self,
        group_id: &[u8],
        key_package: &[u8],
        pending_actors: Vec<String>,
    ) -> Result<MlsCommitBundleJs, JsError> {
        live()?;
        let pending: Vec<&str> = pending_actors.iter().map(String::as_str).collect();
        let bundle = self
            .inner
            .add_member_for_ask(group_id, key_package, &pending)
            .map_err(throw)?;
        to_js(&CommitBundleDto::from(bundle))
    }

    /// Seat every device at a founding in ONE commit that names nobody, its
    /// Welcome carrying a seat for `ownKeyPackage`, a package of this device
    /// the founding fetched like everyone else's. Send the Welcome to every
    /// device added and to this one, and submit the commit with no
    /// recipients (`peachy_mls_core::founding`). `foundingSeats()` says how
    /// many devices one founding seats, and 0 while founding is one add per
    /// commit.
    #[wasm_bindgen(js_name = seatFounding)]
    pub fn seat_founding(
        &mut self,
        group_id: &[u8],
        key_packages: Vec<js_sys::Uint8Array>,
        own_key_package: &[u8],
    ) -> Result<MlsCommitBundleJs, JsError> {
        live()?;
        let packages: Vec<Vec<u8>> = key_packages.iter().map(|p| p.to_vec()).collect();
        let bundle = self
            .inner
            .seat_founding(group_id, &packages, own_key_package)
            .map_err(throw)?;
        to_js(&CommitBundleDto::from(bundle))
    }

    /// The packages a founding leaves out: the index in `keyPackages` of each
    /// one `seatFounding` would refuse, ascending. Changes nothing stored: it
    /// builds the founding commit in memory and drops it. Seat everybody else
    /// in the founding and offer those devices ordinary adds once it is merged
    /// (docs/delivery.md §Founding a conversation).
    #[wasm_bindgen(js_name = foundingRefusals)]
    pub fn founding_refusals(
        &mut self,
        group_id: &[u8],
        key_packages: Vec<js_sys::Uint8Array>,
    ) -> Result<Vec<u32>, JsError> {
        live()?;
        let packages: Vec<Vec<u8>> = key_packages.iter().map(|p| p.to_vec()).collect();
        self.inner
            .founding_refusals(group_id, &packages)
            .map_err(throw)
    }

    /// Remove the member at a leaf index. By index and not by actor id, because
    /// one person may hold several leaves and which of them "remove Ada" means
    /// is a product decision — `leafOfDevice` turns a device id into an index.
    ///
    /// `leafKey` is the `leafKey` of the same roster entry the index came
    /// from: a leaf another commit emptied and refilled since that read no
    /// longer matches, and the removal is refused (`no such member`) with
    /// nothing staged, rather than removing whoever moved in.
    #[wasm_bindgen(js_name = removeMember)]
    pub fn remove_member(
        &mut self,
        group_id: &[u8],
        leaf_index: u32,
        leaf_key: &[u8],
    ) -> Result<MlsCommitBundleJs, JsError> {
        live()?;
        let bundle = self
            .inner
            .remove_member(group_id, leaf_index, leaf_key)
            .map_err(throw)?;
        to_js(&CommitBundleDto::from(bundle))
    }

    /// LEAVE: propose the removal of the leaf at `leafIndex`, one of this
    /// device's own person's leaves (its own included). A member cannot commit
    /// its own removal, so a person leaving proposes each of their leaves and
    /// sends each proposal to the group as an ordinary message (envelope
    /// kind 1); another member's device commits them (`commitProposedLeaves`).
    /// `beginLeave` does all of it and keeps proposing until the leave takes.
    /// Not a commit: nothing is staged. Refused when `leafIndex` is another
    /// person's. It writes; `await flush()` after it.
    #[wasm_bindgen(js_name = proposeLeave)]
    pub fn propose_leave(&mut self, group_id: &[u8], leaf_index: u32) -> Result<Vec<u8>, JsError> {
        live()?;
        self.inner
            .propose_leave(group_id, leaf_index)
            .map_err(throw)
    }

    /// LEAVE A GROUP UNTIL IT TAKES: propose the removal of every leaf of
    /// this device's own person and keep the group as a LEAVING stub that
    /// nothing but the leave reads (docs/sealed-messages.md
    /// §Leaving). Returns the proposals, each to send to the group as a
    /// message (envelope kind 1, not urgent); empty when the group is already
    /// being left, or when nobody but this person holds a leaf (the group is
    /// then forgotten at once). It writes; `await flush()` after it.
    #[wasm_bindgen(js_name = beginLeave)]
    pub fn begin_leave(&mut self, group_id: &[u8]) -> Result<ProposalsJs, JsError> {
        live()?;
        Ok(proposals_to_js(
            self.inner.begin_leave(group_id).map_err(throw)?,
        ))
    }

    /// Whether this device is LEAVING `groupId` (`beginLeave`): hand each
    /// commit envelope of it to `followLeave`, drop every other envelope of
    /// it unread, and show nothing of it.
    #[wasm_bindgen(js_name = isLeaving)]
    pub fn is_leaving(&self, group_id: &[u8]) -> bool {
        refuse_if_poisoned();
        self.inner.is_leaving(group_id)
    }

    /// Who a leave's proposals go to: the actor and device of every
    /// identified leaf of a group this device is LEAVING, its own included.
    /// Throws for a group it is not leaving, whose `roster` says this.
    #[wasm_bindgen(js_name = leaveRecipients)]
    pub fn leave_recipients(&self, group_id: &[u8]) -> Result<LeaveRecipientsJs, JsError> {
        live()?;
        let out = Array::new();
        for (actor, device) in self.inner.leave_recipients(group_id).map_err(throw)? {
            let entry = js_sys::Object::new();
            js_sys::Reflect::set(&entry, &JsValue::from_str("actorId"), &JsValue::from(actor))
                .map_err(|_| JsError::new("could not build a recipient"))?;
            js_sys::Reflect::set(
                &entry,
                &JsValue::from_str("deviceId"),
                &JsValue::from(device),
            )
            .map_err(|_| JsError::new("could not build a recipient"))?;
            out.push(&entry);
        }
        Ok(JsValue::from(out).unchecked_into())
    }

    /// Follow a group this device is LEAVING through one commit entry (raw
    /// or carried, as `processCommit` takes it), and return the proposals to
    /// send again: empty when the leave took (the group is gone), when it
    /// was proposed at this epoch already, or when the entry changed
    /// nothing. Throws only on a store failure: hold the entry and try
    /// again. It writes; `await flush()` after it.
    #[wasm_bindgen(js_name = followLeave)]
    pub fn follow_leave(
        &mut self,
        group_id: &[u8],
        message: &[u8],
    ) -> Result<ProposalsJs, JsError> {
        live()?;
        Ok(proposals_to_js(
            self.inner.follow_leave(group_id, message).map_err(throw)?,
        ))
    }

    /// Commit the LEAVES this device holds: one commit naming every leave
    /// queued through `processMessage` that is not this device's own
    /// person's. `undefined` when there is none (nothing is staged);
    /// otherwise the commit is staged like any other: submit it, then merge
    /// or clear. Once carried commits are sent, the commit carries the
    /// proposals it names (`mls/core/src/carried_commit.rs`).
    #[wasm_bindgen(js_name = commitProposedLeaves)]
    pub fn commit_proposed_leaves(
        &mut self,
        group_id: &[u8],
    ) -> Result<MlsMaybeCommitBundleJs, JsError> {
        live()?;
        match self.inner.commit_proposed_leaves(group_id).map_err(throw)? {
            None => Ok(JsValue::UNDEFINED.unchecked_into()),
            Some(bundle) => to_js(&CommitBundleDto::from(bundle)),
        }
    }

    /// Replace the leaf at `leafIndex` with a fresh key package, in ONE commit.
    ///
    /// THE REJOIN, seen from a member that is still awake
    /// (docs/delivery.md §The client contract on
    /// `behind_retention`). A device that slept past the delivery service's
    /// retention window can neither catch up nor act in the group; some member
    /// who IS current removes its stale leaf and adds it back from a fresh key
    /// package, in one commit, and the Welcome in the returned bundle is what
    /// the returning device joins on.
    ///
    /// One commit and not two, because two would put the group through an
    /// epoch the person is not in: every other roster flickers, anything said
    /// in that window is unreadable to them forever, and a concurrent
    /// committer can wedge itself between the halves and leave a removal that
    /// was never followed by an add.
    ///
    /// Refused before anything is built when the key package belongs to a
    /// different actor than the leaf it would replace, when `leafIndex` is this
    /// device's own leaf, or when nobody occupies it.
    #[wasm_bindgen(js_name = replaceMember)]
    pub fn replace_member(
        &mut self,
        group_id: &[u8],
        leaf_index: u32,
        key_package: &[u8],
    ) -> Result<MlsCommitBundleJs, JsError> {
        live()?;
        let bundle = self
            .inner
            .replace_member(group_id, leaf_index, key_package)
            .map_err(throw)?;
        to_js(&CommitBundleDto::from(bundle))
    }

    /// Reseat a person whose every device is gone: remove `leafIndexes`,
    /// which must be every leaf of one person, and add `keyPackage`, a new
    /// device of that same person carrying an account's signature, in ONE
    /// commit. The one way a person's last leaf leaves without the account's
    /// signed revocation or a credential past its grace; a new account key
    /// shows every member that person's security code changing
    /// (docs/identity.md §Revocation reaches a seated leaf through
    /// the roster). Staged, not merged.
    #[wasm_bindgen(js_name = reseatPerson)]
    pub fn reseat_person(
        &mut self,
        group_id: &[u8],
        leaf_indexes: &[u32],
        key_package: &[u8],
    ) -> Result<MlsCommitBundleJs, JsError> {
        live()?;
        let bundle = self
            .inner
            .reseat_person(group_id, leaf_indexes, key_package)
            .map_err(throw)?;
        to_js(&CommitBundleDto::from(bundle))
    }

    /// Rotate this device's leaf key and commit it.
    #[wasm_bindgen(js_name = selfUpdate)]
    pub fn self_update(&mut self, group_id: &[u8]) -> Result<MlsCommitBundleJs, JsError> {
        live()?;
        let bundle = self.inner.self_update(group_id).map_err(throw)?;
        to_js(&CommitBundleDto::from(bundle))
    }

    /// Hand this client a fresh device credential (the `pdc1` token
    /// `RegisterDevice` just returned) for the SAME seat and signing key.
    /// Nothing is committed; it is what `refreshCredential` will carry.
    /// Throws a policy error for a credential naming another actor, device or
    /// key, and an invalid-argument one for a credential no fresher than the
    /// one held. docs/identity.md §Refreshing a seated leaf.
    ///
    /// `ownAccountIdentity`, optional: the account identity key this device
    /// now derives from the account key it holds (the certificate has just
    /// arrived); absent keeps the one the client holds. A credential certified
    /// under any other key, or certified at all while the client holds no key,
    /// throws `not_own_account_key` and the client keeps what it had.
    #[wasm_bindgen(js_name = updateCredential)]
    pub fn update_credential(
        &mut self,
        credential: &str,
        own_account_identity: Option<Vec<u8>>,
    ) -> Result<(), JsError> {
        live()?;
        let own = optional_identity(own_account_identity)?;
        self.inner
            .update_credential(credential.as_bytes(), own)
            .map_err(throw)
    }

    /// Unix seconds at which this device's leaf credential in the group lapses.
    #[wasm_bindgen(js_name = ownLeafCredentialExpiresAt)]
    pub fn own_leaf_credential_expires_at(&self, group_id: &[u8]) -> Result<f64, JsError> {
        live()?;
        self.inner
            .own_leaf_credential_expires_at(group_id)
            .map(|exp| exp as f64)
            .map_err(throw)
    }

    /// Whether this device's leaf is inside the refresh window (or lapsed),
    /// whatever credential the client holds. True while `credentialRefreshDue`
    /// is false means: fetch today's credential and `updateCredential` first.
    #[wasm_bindgen(js_name = leafCredentialExpiring)]
    pub fn leaf_credential_expiring(&self, group_id: &[u8]) -> Result<bool, JsError> {
        live()?;
        self.inner.leaf_credential_expiring(group_id).map_err(throw)
    }

    /// Whether this device's leaf lapsed longer ago than the grace every
    /// member allows, so nothing it sends is accepted any more. True means:
    /// stop claiming a seal and ask for a seat; never build a renewal.
    #[wasm_bindgen(js_name = leafCredentialPastGrace)]
    pub fn leaf_credential_past_grace(&self, group_id: &[u8]) -> Result<bool, JsError> {
        live()?;
        self.inner
            .leaf_credential_past_grace(group_id)
            .map_err(throw)
    }

    /// Whether a renewal commit should be built now: the leaf is expiring,
    /// nothing is staged, and the client holds a fresher credential.
    #[wasm_bindgen(js_name = credentialRefreshDue)]
    pub fn credential_refresh_due(&self, group_id: &[u8]) -> Result<bool, JsError> {
        live()?;
        self.inner.credential_refresh_due(group_id).map_err(throw)
    }

    /// STAGE a self-update whose leaf carries the client's current credential.
    /// Submit it, then merge or clear, exactly like `selfUpdate`; it never
    /// carries a Welcome.
    #[wasm_bindgen(js_name = refreshCredential)]
    pub fn refresh_credential(&mut self, group_id: &[u8]) -> Result<MlsCommitBundleJs, JsError> {
        live()?;
        let bundle = self.inner.refresh_credential(group_id).map_err(throw)?;
        to_js(&CommitBundleDto::from(bundle))
    }

    /// Adopt the staged commit: this device moves to the new epoch.
    ///
    /// Call it **only once the delivery service has accepted the commit**, and
    /// `await flush()` after it. `addMember`, `removeMember` and `selfUpdate`
    /// stage a commit and stop; until one of this method and
    /// `clearPendingCommit` is called the group is still at the old epoch and
    /// will refuse to build a second commit.
    ///
    /// Returns the epoch the group is now at. Throws if nothing is staged.
    #[wasm_bindgen(js_name = mergePendingCommit)]
    pub fn merge_pending_commit(&mut self, group_id: &[u8]) -> Result<f64, JsError> {
        live()?;
        self.inner
            .merge_pending_commit(group_id)
            .map(|epoch| epoch as f64)
            .map_err(throw)
    }

    /// Throw the staged commit away: the delivery service refused it.
    ///
    /// This is the half that makes a lost race survivable. A refused commit was
    /// built on a branch the server never took, so the only way back is to drop
    /// it, `processCommit()` the commits the server did accept, and build again.
    /// Merging it instead forks the group permanently — this device would go on
    /// encrypting at an epoch no other member will ever reach.
    ///
    /// Clearing when nothing is staged is not an error: a caller unwinding an
    /// error path should not have to know how far it got.
    #[wasm_bindgen(js_name = clearPendingCommit)]
    pub fn clear_pending_commit(&mut self, group_id: &[u8]) -> Result<(), JsError> {
        live()?;
        self.inner.clear_pending_commit(group_id).map_err(throw)
    }

    /// Whether a commit is staged and waiting on a verdict.
    #[wasm_bindgen(js_name = hasPendingCommit)]
    pub fn has_pending_commit(&self, group_id: &[u8]) -> Result<bool, JsError> {
        live()?;
        self.inner.has_pending_commit(group_id).map_err(throw)
    }

    /// Whether the group holds a commit found staged when this client opened,
    /// whose verdict this device never heard (docs/mls-core.md §A
    /// commit saved across a restart). Settled with `settleSavedCommit`
    /// before anything is processed for the group.
    #[wasm_bindgen(js_name = hasSavedCommit)]
    pub fn has_saved_commit(&self, group_id: &[u8]) -> Result<bool, JsError> {
        live()?;
        self.inner.has_saved_commit(group_id).map_err(throw)
    }

    /// Settle a saved commit against the group's head (its epoch and
    /// send-key verifier): `"merged"` when the head is the commit's,
    /// `"cleared"` when it is not, `"waiting"` when the head is past the
    /// commit's epoch and it is kept. A caller that cannot read the head
    /// calls nothing.
    #[wasm_bindgen(js_name = settleSavedCommit)]
    pub fn settle_saved_commit(
        &mut self,
        group_id: &[u8],
        head_epoch: f64,
        head_verifier: &[u8],
    ) -> Result<String, JsError> {
        live()?;
        if !(head_epoch.is_finite() && head_epoch >= 0.0 && head_epoch.fract() == 0.0) {
            return Err(JsError::new(
                "invalid argument: the head epoch is not a whole number",
            ));
        }
        let verdict = self
            .inner
            .settle_saved_commit(group_id, head_epoch as u64, head_verifier)
            .map_err(throw)?;
        Ok(match verdict {
            peachy_mls_core::SavedCommit::Merged => "merged",
            peachy_mls_core::SavedCommit::Cleared => "cleared",
            peachy_mls_core::SavedCommit::Waiting => "waiting",
        }
        .to_owned())
    }

    /// The roster, each entry carrying its verification result.
    pub fn roster(&self, group_id: &[u8]) -> Result<MlsRosterJs, JsError> {
        live()?;
        let entries: Vec<RosterEntryDto> = self
            .inner
            .roster(group_id)
            .map_err(throw)?
            .iter()
            .map(RosterEntryDto::from)
            .collect();
        to_js(&entries)
    }

    /// Whether the leaf at `leafIndex`, which the delivery service or this
    /// account's device list named as revoked, may be removed: its own account
    /// signed `revocation` (empty for none) over its key, or its credential has
    /// lapsed on both this device's clock and the group's tree clock (with the
    /// person keeping a live leaf there, or past the grace), or (until signed
    /// revocations are enforced) its person keeps another leaf here. A person's
    /// last leaf never goes on the server's word alone
    /// (docs/identity.md §Revocation reaches a seated leaf through the
    /// roster).
    ///
    /// A revocation that verifies is kept, with `revokedAt`: the second the
    /// delivery service says it took effect (Unix seconds; absent or 0 when
    /// it did not say). From then on this device refuses that key's messages
    /// received at or after it, in every group, and reads those received
    /// before it (`processMessage`'s `receivedAt`).
    #[wasm_bindgen(js_name = staleLeafRemovable)]
    pub fn stale_leaf_removable(
        &mut self,
        group_id: &[u8],
        leaf_index: u32,
        revocation: &[u8],
        revoked_at: Option<f64>,
    ) -> Result<bool, JsError> {
        live()?;
        self.inner
            .stale_leaf_removable(group_id, leaf_index, revocation, unix_seconds(revoked_at))
            .map_err(throw)
    }

    /// THE DOOR FOR A LEAF THE SERVER NAMED (`stale_device_ids`,
    /// `retired_device_ids`): judge it as `staleLeafRemovable` does and, only
    /// where that allows, stage its removal as `removeMember` does, with the
    /// same `leafKey` check. `undefined`, with nothing staged, when the leaf
    /// stays: a person's last leaf on the server's word alone, a leaf whose
    /// credential does not verify, or this device's own leaf.
    ///
    /// `removeMember` does not ask the judge, and receivers do not re-judge
    /// a removal: a client that acts on a list the server handed it removes
    /// through this door, never the plain one. It writes; `await flush()`
    /// after it.
    #[wasm_bindgen(js_name = removeStaleLeaf)]
    pub fn remove_stale_leaf(
        &mut self,
        group_id: &[u8],
        leaf_index: u32,
        leaf_key: &[u8],
        revocation: &[u8],
        revoked_at: Option<f64>,
    ) -> Result<Option<MlsCommitBundleJs>, JsError> {
        live()?;
        match self
            .inner
            .remove_stale_leaf(
                group_id,
                leaf_index,
                leaf_key,
                revocation,
                unix_seconds(revoked_at),
            )
            .map_err(throw)?
        {
            Some(bundle) => Ok(Some(to_js(&CommitBundleDto::from(bundle))?)),
            None => Ok(None),
        }
    }

    /// Pin the links this account's device list states: `rowsJson` is a
    /// JSON array of `{"id","twinOf"}` (any other field ignored), and the
    /// first `twinOf` this device sees for an id is the one it keeps. Called
    /// on every read of the device list; answers how many it pinned now.
    #[wasm_bindgen(js_name = noteOwnInstallLinks)]
    pub fn note_own_install_links(&mut self, rows_json: &str) -> Result<u32, JsError> {
        live()?;
        self.inner.note_own_install_links(rows_json).map_err(throw)
    }

    /// The account's revocations of the rows a removal signs, made with
    /// `accountKey`: only rows whose keys this device vouches for on its own
    /// approval chain, a linked row only when the confirmation named it
    /// (`namedWith`) and on the link it pinned, nothing for a denial, and
    /// nothing that touches this install. `requestJson` is
    /// `{"named","denying","namedWith","ownDeviceIds","rows","restoredSince"}`
    /// (the last, Unix seconds, for the rows a PIN restore signed out, only
    /// keys the restoring registration's answer kept, `noteRestoreSignedOut`,
    /// and none before), each row
    /// `{"id","twinOf","signingKey","approvedByDeviceId","approvalSignature",
    /// "revoked","revokedAt"}`,
    /// bytes as hex; answers `[{"deviceId","signature"}]`, the signature as hex
    /// (docs/identity.md §RevokeDevice).
    #[wasm_bindgen(js_name = signInstallRevocations)]
    pub fn sign_install_revocations(
        &mut self,
        account_key: Vec<u8>,
        request_json: &str,
    ) -> Result<String, JsError> {
        // A secret argument: this module's own copy, wiped on return.
        let account_key = Zeroizing::new(account_key);
        let account_key: &[u8] = &account_key;
        live()?;
        self.inner
            .sign_install_revocations(account_key, request_json)
            .map_err(throw)
    }

    /// Keep what the registration that restored this device from its PIN
    /// answered as signed out: `requestJson` is
    /// `{"restoredSince","keys","certificates","accountIdentityKey"}`, bytes as
    /// hex, the identity key derived from the account key this device holds,
    /// never one the server published: a key is kept only when its
    /// certificate verifies under the identity key the client holds (a
    /// request naming another is refused), or under the request's while it
    /// holds none, and only when nothing is kept for that restore yet; a kept
    /// key is never approved here again. Answers how many keys it kept now
    /// (docs/identity.md §RevokeDevice).
    #[wasm_bindgen(js_name = noteRestoreSignedOut)]
    pub fn note_restore_signed_out(&mut self, request_json: &str) -> Result<u32, JsError> {
        live()?;
        self.inner
            .note_restore_signed_out(request_json)
            .map_err(throw)
    }

    /// This device's approval of `deviceId` holding `signingKey`, signed with
    /// this device's own key: the 64 bytes `signDeviceApproval` makes from its
    /// seed. Refuses a key this device forgot, signed the account's
    /// revocation of, or took from a restore's answer as signed out. With
    /// `restoredSince` above zero (this device's PIN restore, Unix seconds) it
    /// closes that restore when no answer is kept for it yet.
    #[wasm_bindgen(js_name = signOwnDeviceApproval)]
    pub fn sign_own_device_approval(
        &mut self,
        device_id: &str,
        signing_key: &[u8],
        restored_since: f64,
    ) -> Result<Vec<u8>, JsError> {
        live()?;
        if !restored_since.is_finite()
            || restored_since.fract() != 0.0
            || restored_since.abs() > 9_007_199_254_740_991.0
        {
            return Err(JsError::new(
                "restoredSince must be a whole number of seconds",
            ));
        }
        #[allow(clippy::cast_possible_truncation)] // whole and within 2^53, checked above
        let restored_since = restored_since as i64;
        self.inner
            .sign_own_device_approval(device_id, signing_key, restored_since)
            .map_err(throw)
    }

    /// The leaf index of a device id in this group.
    #[wasm_bindgen(js_name = leafOfDevice)]
    pub fn leaf_of_device(&self, group_id: &[u8], device_id: &str) -> Result<u32, JsError> {
        live()?;
        self.inner
            .leaf_of_device(group_id, device_id)
            .map_err(throw)
    }

    /// The current epoch.
    pub fn epoch(&self, group_id: &[u8]) -> Result<f64, JsError> {
        live()?;
        self.inner
            .epoch(group_id)
            .map(|epoch| epoch as f64)
            .map_err(throw)
    }

    /// Whether this client is still an active member.
    #[wasm_bindgen(js_name = isActive)]
    pub fn is_active(&self, group_id: &[u8]) -> Result<bool, JsError> {
        live()?;
        self.inner.is_active(group_id).map_err(throw)
    }

    /// The actor id of the member whose commit seated this device in
    /// `groupId` by a Welcome (the Welcome's verified GroupInfo signer, kept
    /// with the group's state), or `undefined` for a group this device
    /// founded or joined on a build before it was kept. A Welcome from one of
    /// this account's own devices is a linked device being seated, never this
    /// person being added back (docs/account-store.md §Record values,
    /// **Leaving a group**). `undefined` too for a group not held.
    #[wasm_bindgen(js_name = welcomeSender)]
    pub fn welcome_sender(&self, group_id: &[u8]) -> Result<Option<String>, JsError> {
        live()?;
        self.inner.welcome_sender(group_id).map_err(throw)
    }

    /// Whether this group's local state is older than what the delivery
    /// service still holds.
    ///
    /// `serverOldestEpoch` is the oldest epoch the delivery service can still serve
    /// (docs/delivery.md §Retention). Equality is NOT behind: a
    /// device at exactly the oldest retained epoch holds the one commit it
    /// needs.
    ///
    /// THE LOCAL SECOND OPINION on `FetchMailboxResponse.lost`, and the reason the flag
    /// on the wire is never acted on alone: a client that threw a group away on
    /// the server's word would be a client any delivery service could make
    /// forget every group it holds. A group this device holds no state for
    /// answers false — there is nothing here to be behind with.
    #[wasm_bindgen(js_name = isBehind)]
    pub fn is_behind(&self, group_id: &[u8], server_oldest_epoch: f64) -> Result<bool, JsError> {
        live()?;
        match self.inner.is_behind(group_id, server_oldest_epoch as u64) {
            Ok(behind) => Ok(behind),
            // A group this device holds no state for is not one it has fallen
            // behind — there is nothing here to be behind WITH, and nothing to
            // forget. False rather than a throw because every caller of this
            // would have to write the same catch, and the one that forgot would
            // turn a stranger id into a refusal to seal.
            Err(peachy_mls_core::Error::NoSuchGroup) => Ok(false),
            Err(err) => Err(throw(err)),
        }
    }

    /// Whether failing to apply `message` strands this device in the group —
    /// off the ratchet for good, exactly as if it had slept past the retention
    /// window (docs/delivery.md §A commit this device cannot
    /// apply).
    ///
    /// Asked after `processCommit` threw on a stream entry. True exactly when
    /// it is the COMMIT at this device's epoch that `processCommit` refused
    /// last AFTER it opened and verified (a member built it, and this
    /// device's policy refused what the rest of the group merged). A commit
    /// that did not open is false at any epoch, because its framing is
    /// anyone's to write: ask the group's head instead
    /// (docs/delivery.md §A commit this device cannot apply). False
    /// too for a replay from an epoch already left, for anything that is not
    /// a commit, for bytes that do not parse and for a group held nowhere
    /// here. A storage failure is transient and the caller's to hold back on
    /// first.
    #[wasm_bindgen(js_name = commitStrands)]
    pub fn commit_strands(&self, group_id: &[u8], message: &[u8]) -> Result<bool, JsError> {
        live()?;
        self.inner.commit_strands(group_id, message).map_err(throw)
    }

    /// Hand in the SEALED STAMP the delivery service attached to the commit
    /// about to go through `processCommit` (`MailboxEnvelope.commitStamp`;
    /// docs/delivery.md §The sealed stamp). Kept in memory for that
    /// one commit; an empty stamp hands in nothing.
    #[wasm_bindgen(js_name = noteCommitStamp)]
    pub fn note_commit_stamp(&mut self, group_id: &[u8], stamp: &[u8]) {
        self.inner.note_commit_stamp(group_id, stamp);
    }

    /// What `processCommit` found checking the last commit it merged against
    /// its sealed stamp, TAKEN, as JSON: `{epoch, stamp, mac, steward}` and
    /// `blame` (an actor id) when the committer is blamed; `stamp` is one of
    /// `absent`, `unopened`, `match`, `blame`, `repair`, `unjudged`.
    /// `undefined` when no commit merged since the last take. This build only
    /// alerts on it.
    #[wasm_bindgen(js_name = takeCommitCheck)]
    pub fn take_commit_check(&mut self, group_id: &[u8]) -> Option<String> {
        self.inner
            .take_commit_check(group_id)
            .map(|check| check.to_json())
    }

    /// The GROUP HOLD, when it holds now, as JSON: `{epoch, since, until,
    /// reason}`; `undefined` for none. Only a group whose meta names a
    /// steward key is ever held, and no build writes one.
    #[wasm_bindgen(js_name = groupHold)]
    pub fn group_hold(&self, group_id: &[u8]) -> Result<Option<String>, JsError> {
        Ok(self
            .inner
            .group_hold(group_id)
            .map_err(throw)?
            .map(|hold| hold.to_json()))
    }

    /// Hold the group for its steward's repair or veto: `reason` 1 a refused
    /// commit, 2 an unopenable or lost one, 3 a false repair notice. False,
    /// and nothing changes, for a group this device does not count as
    /// enrolled, and for one whose hold already lapsed or was released at
    /// its current epoch (at most one hold an epoch: the caller rejoins).
    /// `await flush()` after it.
    #[wasm_bindgen(js_name = enterHold)]
    pub fn enter_hold(&mut self, group_id: &[u8], reason: u32) -> Result<bool, JsError> {
        let reason = peachy_mls_core::steward::HoldReason::from_u32(reason)
            .ok_or_else(|| JsError::new("a hold reason is 1, 2 or 3"))?;
        self.inner.enter_hold(group_id, reason).map_err(throw)
    }

    /// Release the group's hold, if any: it lapses now and stays on record,
    /// so the group is not held again at this epoch. `await flush()` after it.
    #[wasm_bindgen(js_name = releaseHold)]
    pub fn release_hold(&mut self, group_id: &[u8]) -> Result<(), JsError> {
        self.inner.release_hold(group_id).map_err(throw)
    }

    /// What a commit entry's VETO FRAME means here: 0 nothing, 1 a valid veto
    /// of the commit at this device's epoch (skip the vetoed commit, take
    /// this one), 2 a valid veto of a commit this device already merged
    /// (rejoin now), 3 a valid veto too far back for this copy to tell (read
    /// the group's head now, through the fork check).
    #[wasm_bindgen(js_name = judgeVeto)]
    pub fn judge_veto(&self, group_id: &[u8], entry: &[u8]) -> Result<u32, JsError> {
        Ok(self.inner.judge_veto(group_id, entry).map_err(throw)? as u32)
    }

    /// Judge a REPAIR NOTICE lane frame (its UTF-8 JSON) from `sender`, the
    /// MLS sender's actor id: 0 consistent, 1 inconsistent (alert; an
    /// enrolled group is held, at most once an epoch), 2 nothing to judge
    /// (including a sender the group does not name as an admin).
    /// `await flush()` after it.
    #[wasm_bindgen(js_name = checkRepairNotice)]
    pub fn check_repair_notice(
        &mut self,
        group_id: &[u8],
        sender: &str,
        wire: &[u8],
    ) -> Result<u32, JsError> {
        Ok(self
            .inner
            .check_repair_notice(group_id, sender, wire)
            .map_err(throw)? as u32)
    }

    /// Open FetchCommitAt's `sealedCommit` for the commit built at this
    /// device's epoch, with that epoch's send key: the commit envelope as it
    /// was placed, to open and take through `processCommit` like any other
    /// (FetchCommitAt, not part of this specification). Throws for a copy that
    /// does not open.
    #[wasm_bindgen(js_name = openFetchedCommit)]
    pub fn open_fetched_commit(&self, group_id: &[u8], sealed: &[u8]) -> Result<Vec<u8>, JsError> {
        self.inner
            .open_fetched_commit(group_id, sealed)
            .map_err(throw)
    }

    /// Drop every trace of a group from this device.
    ///
    /// The other half of the rejoin, and everything it does is LOCAL — which is
    /// the point: a device off the ratchet cannot sign a Remove of its own leaf
    /// that anybody would accept. The state goes from storage and not merely
    /// from the open map, so the Welcome a live member's `replaceMember` mints
    /// creates the group fresh rather than colliding with the stale copy.
    ///
    /// `await flush()` after it, like every other write.
    ///
    /// It KEEPS the people this device last saw in the group, when they name
    /// anybody but this device's own person, until a copy in the id is
    /// confirmed; each person it sees leave in the meantime is dropped from
    /// them, and nobody is added. A later Welcome into the id is drawn
    /// against them: who was added, who is gone, whether the admins changed
    /// (`takeRejoinReport`). They refuse nobody (docs/delivery.md
    /// §A Welcome into a group this device knew). Reports not taken yet are
    /// kept too. A person leaving on purpose calls `forgetRememberedRoster`
    /// after it.
    #[wasm_bindgen(js_name = forgetGroup)]
    pub fn forget_group(&mut self, group_id: &[u8]) -> Result<(), JsError> {
        live()?;
        self.inner.forget_group(group_id).map_err(throw)
    }

    /// Drop the roster `forgetGroup` kept for `groupId`: for a person who
    /// LEFT on purpose, so a later Welcome into the id is a new invitation
    /// from whoever sends it. The record of who left and any report not
    /// taken yet go with it. A no-op when nothing is kept. `await flush()`
    /// after it.
    #[wasm_bindgen(js_name = forgetRememberedRoster)]
    pub fn forget_remembered_roster(&mut self, group_id: &[u8]) -> Result<(), JsError> {
        live()?;
        self.inner.forget_remembered_roster(group_id).map_err(throw)
    }

    /// The OLDEST report a Welcome that restored or replaced `groupId` on
    /// this device left, or a head contradicting its copy did, TAKEN
    /// (`undefined` when there is nothing left to tell): who re-seated this
    /// device, who came in and who left while it was away, whether the
    /// admins changed, and whether a head contradicted the copy. Each
    /// Welcome leaves its own report, in order: call until `undefined` and
    /// draw each as its own lines. Past 32 waiting, a new one is folded into
    /// the newest, which then names only the later re-adder. It writes;
    /// `await flush()` after it.
    #[wasm_bindgen(js_name = takeRejoinReport)]
    pub fn take_rejoin_report(&mut self, group_id: &[u8]) -> Result<MlsRejoinReportJs, JsError> {
        live()?;
        match self.inner.take_rejoin_report(group_id).map_err(throw)? {
            None => Ok(JsValue::UNDEFINED.unchecked_into()),
            Some(report) => to_js(&RejoinReportDto::from(report)),
        }
    }

    /// The OLDEST report waiting for `groupId`, LEFT IN PLACE (`undefined`
    /// when there is nothing left to tell): the door the client draws
    /// through (docs/delivery.md §A Welcome into a group this
    /// device knew). Its `drawnAtMs` is `nowMs` the first time a report is
    /// peeked and the same on every later peek: draw its lines at that time,
    /// keyed so a second draw rewrites them, then `dropRejoinReport` it by
    /// its `id` and peek again. A report not dropped is answered again after
    /// a reload. It writes the first time; `await flush()` after it.
    #[wasm_bindgen(js_name = peekRejoinReport)]
    pub fn peek_rejoin_report(
        &mut self,
        group_id: &[u8],
        now_ms: f64,
    ) -> Result<MlsRejoinReportJs, JsError> {
        live()?;
        let now_ms = if now_ms.is_finite() && now_ms > 0.0 {
            now_ms as u64
        } else {
            0
        };
        match self
            .inner
            .peek_rejoin_report(group_id, now_ms)
            .map_err(throw)?
        {
            None => Ok(JsValue::UNDEFINED.unchecked_into()),
            Some(report) => to_js(&RejoinReportDto::from(report)),
        }
    }

    /// Drop the report `peekRejoinReport` answered with `id` (its decimal
    /// u64), once its lines are drawn. Returns whether one was dropped:
    /// false when none waiting has that id. `await flush()` after it.
    #[wasm_bindgen(js_name = dropRejoinReport)]
    pub fn drop_rejoin_report(&mut self, group_id: &[u8], id: &str) -> Result<bool, JsError> {
        live()?;
        let id: u64 = id
            .parse()
            .map_err(|_| JsError::new("invalid argument: a report id is a decimal u64"))?;
        self.inner.drop_rejoin_report(group_id, id).map_err(throw)
    }

    /// The group's own name-and-photo value (`peachy_group_meta`), read out
    /// of its context, or `undefined` when nobody has set one
    /// (docs/sealed-messages.md §The name is in the group). The bytes are the
    /// client format and are returned unparsed.
    #[wasm_bindgen(js_name = groupMeta)]
    pub fn group_meta(&self, group_id: &[u8]) -> Result<Option<Vec<u8>>, JsError> {
        live()?;
        self.inner.group_meta(group_id).map_err(throw)
    }

    /// Set the group's name and photo, in ONE commit that changes
    /// `peachy_group_meta` and nothing else. Any member may.
    ///
    /// **This STAGES a commit**, like `addMember`: submit the bytes, then call
    /// exactly one of `mergePendingCommit` and `clearPendingCommit`.
    #[wasm_bindgen(js_name = setGroupMeta)]
    pub fn set_group_meta(
        &mut self,
        group_id: &[u8],
        value: &[u8],
    ) -> Result<MlsCommitBundleJs, JsError> {
        live()?;
        let bundle = self.inner.set_group_meta(group_id, value).map_err(throw)?;
        to_js(&CommitBundleDto::from(bundle))
    }

    /// Open a member-rostered conversation's envelope against every group
    /// this client holds; `undefined` when none opens it
    /// (docs/delivery.md §Handles and sender-addressed delivery).
    #[wasm_bindgen(js_name = openEnvelope)]
    pub fn open_envelope(&self, envelope: &[u8]) -> Result<MlsOpenedEnvelopeJs, JsError> {
        live()?;
        match self.inner.open_envelope(envelope).map_err(throw)? {
            Some(opened) => to_js(&OpenedEnvelopeDto {
                group_id: opened.group_id,
                kind: opened.kind,
                inner: opened.inner,
            }),
            None => Ok(JsValue::UNDEFINED.unchecked_into()),
        }
    }

    /// Keep a version 3 envelope that opened for no group here, so that it
    /// opens once this device holds the epoch it was sealed at: a copy that
    /// fell behind or forked meets these until a member returns its seat,
    /// and that Welcome hands back the epochs it missed. Call it for every
    /// envelope `openEnvelope` did not open, before acknowledging it.
    /// `mailboxKind`, `id` and `receivedAtMs` are the mailbox's own, and
    /// `deviceSeal` the device seal it handed over beside the envelope
    /// (`MailboxEnvelope.deviceSeal`; absent or empty for none): one that
    /// opens for this device names the group, the sender and the epoch
    /// secret, so the envelope is handed out once this device is back in
    /// that group, or before the hold would drop it. Answers `0` not kept,
    /// `1` kept (acknowledge it either way), or `2` FULL: the hold on device
    /// seals is at its ceiling and the envelope is kept for now without its
    /// seal; stop the page there, unacknowledged, take what `nextReopenable`
    /// hands out through, and drain again.
    #[wasm_bindgen(js_name = holdEnvelope)]
    pub fn hold_envelope(
        &mut self,
        mailbox_kind: u8,
        id: &str,
        received_at_ms: f64,
        envelope: &[u8],
        device_seal: Option<Vec<u8>>,
    ) -> Result<u8, JsError> {
        live()?;
        let received_at_ms = if received_at_ms.is_finite() && received_at_ms > 0.0 {
            received_at_ms as u64
        } else {
            0
        };
        self.inner
            .hold_envelope_sealed(
                mailbox_kind,
                id,
                received_at_ms,
                envelope,
                device_seal.as_deref().unwrap_or_default(),
            )
            .map(|answer| answer as u8)
            .map_err(throw)
    }

    /// The next envelope `holdEnvelope` kept that opens now, oldest first;
    /// `undefined` when none does. Take each through the same path as a
    /// fresh envelope, `releaseHeld` it once what was made of it is stored,
    /// and ask again until `undefined`. One not released stays kept and is
    /// handed out again in the next pass. Call it after every mailbox pass.
    #[wasm_bindgen(js_name = nextReopenable)]
    pub fn next_reopenable(&mut self) -> Result<MlsHeldEnvelopeJs, JsError> {
        live()?;
        match self.inner.next_reopenable().map_err(throw)? {
            Some(held) => to_js(&HeldEnvelopeDto {
                mailbox_kind: held.mailbox_kind,
                received_at_ms: held.received_at_ms,
                id: held.id,
                envelope: held.envelope,
            }),
            None => Ok(JsValue::UNDEFINED.unchecked_into()),
        }
    }

    /// What the envelope `nextReopenable` handed out under `id` is to be
    /// made of, when it was handed out on its device seal; `undefined` for
    /// one handed out on no seal, taken through as any other.
    #[wasm_bindgen(js_name = heldDisposition)]
    pub fn held_disposition(&self, id: &str) -> Result<MlsHeldDispositionJs, JsError> {
        live()?;
        match self.inner.held_disposition(id) {
            Some(disposition) => to_js(&HeldDispositionDto {
                fate: disposition.fate as u8,
                author: disposition.author,
            }),
            None => Ok(JsValue::UNDEFINED.unchecked_into()),
        }
    }

    /// Release an envelope `nextReopenable` handed out, once what was made
    /// of it is stored: it is kept no longer. True when one with that id was
    /// kept.
    #[wasm_bindgen(js_name = releaseHeld)]
    pub fn release_held(&mut self, id: &str) -> Result<bool, JsError> {
        live()?;
        self.inner.release_held(id).map_err(throw)
    }

    /// Wrap `inner` as an envelope of `groupId`, a group this client holds:
    /// sealed under the epoch the inner message was made in (a typing frame
    /// or call signal: the copy's epoch), never by the group id. The only door
    /// for a send, commit, typing frame or call signal (the free
    /// `sealEnvelope` refuses them). `kind`: 1 message, 2 commit, 3 seat ask,
    /// 4 typing, 5 link preview, 6 call; a seat ask and a link preview are
    /// keyed by the group id. Throws the core's stale-copy refusal for a
    /// message or commit made at an epoch this copy no longer keeps (encrypt
    /// it again and seal that; never resend it), "not an active member" from
    /// a copy no longer in the group, and "no such group" for a group this
    /// client does not hold.
    #[wasm_bindgen(js_name = sealEnvelope)]
    pub fn seal_envelope(
        &self,
        group_id: &[u8],
        kind: u8,
        inner: Vec<u8>,
    ) -> Result<Vec<u8>, JsError> {
        // A plaintext argument: this module's own copy, wiped on return.
        let inner = Zeroizing::new(inner);
        live()?;
        self.inner
            .seal_envelope(group_id, kind, &inner)
            .map_err(throw)
    }

    /// Encrypt an application message under the default content hint (0,
    /// show the loss): no message leaves without one.
    pub fn encrypt(&mut self, group_id: &[u8], plaintext: Vec<u8>) -> Result<Vec<u8>, JsError> {
        // A plaintext argument: this module's own copy, wiped on return.
        let plaintext = Zeroizing::new(plaintext);
        live()?;
        self.inner.encrypt(group_id, &plaintext).map_err(throw)
    }

    /// Encrypt an application message carrying a content hint (0 show the
    /// loss, 1 ask for it again, 2 show nothing, 3 ask for a lane frame again).
    #[wasm_bindgen(js_name = encryptWithHint)]
    pub fn encrypt_with_hint(
        &mut self,
        group_id: &[u8],
        plaintext: Vec<u8>,
        hint: u8,
    ) -> Result<Vec<u8>, JsError> {
        // A plaintext argument: this module's own copy, wiped on return.
        let plaintext = Zeroizing::new(plaintext);
        live()?;
        self.inner
            .encrypt_with_hint(group_id, &plaintext, hint)
            .map_err(throw)
    }

    /// Process one incoming message through the MESSAGE door: an application
    /// message, or a LEAVE (`kind: "proposal"`, queued for
    /// `commitProposedLeaves`). A commit, or any other proposal, throws
    /// `wrong door: …` and nothing moves
    /// (`peachy_mls_core::Client::process_message`). Returns the `IncomingDto`
    /// shape — switch on `kind`. There is no doorless form: the drain's
    /// message path calls this and its commit path `processCommit`.
    ///
    /// `receivedAt` is the second the delivery service received the message
    /// (the mailbox envelope's `receivedAt`, Unix seconds), absent or 0 when
    /// the caller does not know it. A message from a device whose account
    /// signed it out, which this device holds (`staleLeafRemovable`), is read
    /// only when it was received before the revocation took effect; an
    /// unknown time counts as after, and it throws `not from a member`
    /// (`peachy_mls_core::Client::process_message_received_at`).
    #[wasm_bindgen(js_name = processMessage)]
    pub fn process_message(
        &mut self,
        group_id: &[u8],
        message: &[u8],
        received_at: Option<f64>,
    ) -> Result<MlsIncomingJs, JsError> {
        live()?;
        let incoming = self
            .inner
            .process_message_received_at(group_id, message, unix_seconds(received_at))
            .map_err(throw)?;
        to_js(&IncomingDto::from(incoming))
    }

    /// `processMessage` for the message inside mailbox envelope
    /// `envelopeId`, with what an application message opens to kept in the
    /// same write that spends its key until `releaseOpened`
    /// (`peachy_mls_core::Client::process_message_as`): the same envelope
    /// handed over again, after the archive refused the words, answers the
    /// same words rather than a duplicate. An empty id keeps nothing.
    /// `receivedAt` is as `processMessage`'s
    /// (`peachy_mls_core::Client::process_message_as_received_at`).
    #[wasm_bindgen(js_name = processMessageAs)]
    pub fn process_message_as(
        &mut self,
        group_id: &[u8],
        message: &[u8],
        envelope_id: &str,
        received_at: Option<f64>,
    ) -> Result<MlsIncomingJs, JsError> {
        live()?;
        let incoming = self
            .inner
            .process_message_as_received_at(
                group_id,
                message,
                envelope_id,
                unix_seconds(received_at),
            )
            .map_err(throw)?;
        to_js(&IncomingDto::from(incoming))
    }

    /// The host's own copy of what envelope `envelopeId` opened to is
    /// stored: what `processMessageAs` kept of it goes. True when anything
    /// was kept.
    #[wasm_bindgen(js_name = releaseOpened)]
    pub fn release_opened(&mut self, envelope_id: &str) -> Result<bool, JsError> {
        live()?;
        self.inner.release_opened(envelope_id).map_err(throw)
    }

    /// `releaseOpened` for every envelope in `envelopeIds` at once
    /// (`peachy_mls_core::Client::release_opened_all`): one write for them
    /// all. Answers how many held a record.
    #[wasm_bindgen(js_name = releaseOpenedAll)]
    pub fn release_opened_all(&mut self, envelope_ids: Vec<String>) -> Result<u32, JsError> {
        live()?;
        let ids: Vec<&str> = envelope_ids.iter().map(String::as_str).collect();
        let released = self.inner.release_opened_all(&ids).map_err(throw)?;
        Ok(u32::try_from(released).unwrap_or(u32::MAX))
    }

    /// THE MAILBOX DOOR: one opened mailbox entry, routed by BOTH the kind
    /// the delivery service put on the entry (`mailboxKind`: 1 MLS, 5
    /// COMMIT) and the kind sealed inside it (`envelopeKind`, what
    /// `openEnvelope` answered), never one of them alone. A commit is taken
    /// only from a COMMIT entry and a message only from an MLS entry; anything
    /// else, a commit sealed into an MLS entry included, is refused (`wrong
    /// door`) before the engine reads it. A seat ask and a call signal are
    /// refused too: `envelopeDoor` says which reader takes them. Prefer this
    /// to choosing `processMessage` or `processCommit` yourself.
    #[wasm_bindgen(js_name = processMailboxEntry)]
    pub fn process_mailbox_entry(
        &mut self,
        group_id: &[u8],
        mailbox_kind: u32,
        envelope_kind: u8,
        inner: &[u8],
        received_at: Option<f64>,
    ) -> Result<MlsIncomingJs, JsError> {
        live()?;
        let incoming = self
            .inner
            .process_mailbox_entry(
                group_id,
                mailbox_kind,
                envelope_kind,
                inner,
                unix_seconds(received_at),
            )
            .map_err(throw)?;
        to_js(&IncomingDto::from(incoming))
    }

    /// Process one incoming message through the COMMIT door: a commit only.
    /// Anything else throws `wrong door: …` before the engine reads it.
    #[wasm_bindgen(js_name = processCommit)]
    pub fn process_commit(
        &mut self,
        group_id: &[u8],
        message: &[u8],
    ) -> Result<MlsIncomingJs, JsError> {
        live()?;
        let incoming = self
            .inner
            .process_commit(group_id, message)
            .map_err(throw)?;
        to_js(&IncomingDto::from(incoming))
    }

    /// Derive a secret from the current epoch, RFC 9420 §8.5. The label
    /// namespaces it: two features exporting under different labels cannot
    /// derive each other's secret.
    #[wasm_bindgen(js_name = exportSecret)]
    pub fn export_secret(
        &self,
        group_id: &[u8],
        label: &str,
        context: &[u8],
        length: usize,
    ) -> Result<Vec<u8>, JsError> {
        live()?;
        self.inner
            .export_secret(group_id, label, context, length)
            .map_err(throw)
    }

    /// Seal this device's typing frame for a group at its current epoch,
    /// signed by its leaf and stamped (docs/sealed-messages.md
    /// §Typing inside the group): the inner bytes of a kind-4 envelope.
    #[wasm_bindgen(js_name = sealTyping)]
    pub fn seal_typing(&mut self, group_id: &[u8], typing: bool) -> Result<Vec<u8>, JsError> {
        live()?;
        self.inner.seal_typing(group_id, typing).map_err(throw)
    }

    /// Open a typing frame for a group: `{"actorId","typing"}` as
    /// text, or `"null"` for a frame to drop (another epoch, a forged
    /// author, a replay, outside two minutes).
    #[wasm_bindgen(js_name = openTyping)]
    pub fn open_typing(&mut self, group_id: &[u8], frame: &[u8]) -> Result<String, JsError> {
        live()?;
        self.inner.open_typing_json(group_id, frame).map_err(throw)
    }

    /// Derive a secret from the epoch this client's STAGED commit would move
    /// the group to, before it is merged: the next epoch's send key, whose
    /// verifier rides the same `SubmitCommit` as the commit
    /// (docs/delivery.md §SubmitCommit). Throws when nothing is staged.
    #[wasm_bindgen(js_name = exportPendingSecret)]
    pub fn export_pending_secret(
        &self,
        group_id: &[u8],
        label: &str,
        context: &[u8],
        length: usize,
    ) -> Result<Vec<u8>, JsError> {
        live()?;
        self.inner
            .export_pending_secret(group_id, label, context, length)
            .map_err(throw)
    }

    // ---- Calls (docs/calls.md §Keys, §Signaling) -----------------------

    /// A call's frame-encryption keys at the group's current epoch. Call again
    /// on every epoch change; keep the previous ring for 10 s.
    #[wasm_bindgen(js_name = callKeys)]
    pub fn call_keys(&self, group_id: &[u8], call_id: &[u8]) -> Result<MlsCallKeysJs, JsError> {
        live()?;
        let keys = self.inner.call_keys(group_id, call_id).map_err(throw)?;
        to_js(&CallKeysDto::from(&keys))
    }

    /// The keys at the epoch this client's STAGED commit moves the group to,
    /// so a committer can load them before the first frame under them.
    #[wasm_bindgen(js_name = pendingCallKeys)]
    pub fn pending_call_keys(
        &self,
        group_id: &[u8],
        call_id: &[u8],
    ) -> Result<MlsCallKeysJs, JsError> {
        live()?;
        let keys = self
            .inner
            .pending_call_keys(group_id, call_id)
            .map_err(throw)?;
        to_js(&CallKeysDto::from(&keys))
    }

    /// Seal a call signal (JSON text, the `mls/fixtures/calls.json` form) for
    /// `groupId`: the whole kind-6 envelope, ready for `SendSealed`. Offer,
    /// Answer, Hangup, Remove, Direct, the in-call controls and every `Left`
    /// go as an MLS message as long as a message of the same padding block
    /// (persist after, like `encrypt`); a `Joined` as a live frame. A
    /// `Joined` from a device that is not a participant in the call throws
    /// "call state lost": join again instead (docs/calls.md
    /// §Participant media keys).
    ///
    /// The signal comes as its JSON text's UTF-8 bytes (a `Uint8Array`, as
    /// `TextEncoder` writes it), which the caller zeroes after.
    #[wasm_bindgen(js_name = sealCallSignal)]
    pub fn seal_call_signal(
        &mut self,
        group_id: &[u8],
        signal_json: Vec<u8>,
    ) -> Result<Vec<u8>, JsError> {
        // A plaintext argument: this module's own copy, wiped on return.
        let signal_json = Zeroizing::new(signal_json);
        live()?;
        self.inner
            .seal_call_signal_json(group_id, utf8_argument(&signal_json, "a call signal")?)
            .map_err(throw)
    }

    /// Seal ANY call signal on the MLS lane, sender-authenticated: a
    /// participant's first `Joined` in each epoch goes this way, so receivers
    /// bind its tracks to its own leaf (docs/calls.md, D10).
    /// Send through `SendSealed`, not urgent.
    /// On participant media keys only a `Left` naming the participant id
    /// `start` named ends this device's media keys, and after it a `Joined`
    /// is refused ("call state lost") until `start` (docs/calls.md
    /// §Participant media keys).
    /// The signal comes as UTF-8 bytes, as for `sealCallSignal`.
    #[wasm_bindgen(js_name = sealCallSignalSigned)]
    pub fn seal_call_signal_signed(
        &mut self,
        group_id: &[u8],
        signal_json: Vec<u8>,
    ) -> Result<Vec<u8>, JsError> {
        // A plaintext argument: this module's own copy, wiped on return.
        let signal_json = Zeroizing::new(signal_json);
        live()?;
        self.inner
            .seal_call_signal_on_mls_lane_json(
                group_id,
                utf8_argument(&signal_json, "a call signal")?,
            )
            .map_err(throw)
    }

    /// Open a kind-6 envelope's inner bytes. JSON text
    /// `{"lane","sender":{"actorId","deviceId"}|null,"senderLeaf","urgent","signal","send":[hex…],"media","unboundLeaf","applyAfterMs","applied"}`.
    /// A signed `Joined` must name its sender's own leaf (with a call key,
    /// it keeps the participant id its participation is bound under), and a
    /// signed `Left` its sender's own participant. `send` lists the envelopes a v2
    /// participant owes now (not urgent, in order); `unboundLeaf` is the leaf
    /// a signed `Left` unbound, or null, the only leaf a client drops a tile
    /// at for it. `applyAfterMs` is the milliseconds until this device's
    /// pending rotation in the call switches (null when none is pending), and
    /// `applied` whether the core switched its sending key since a door last
    /// said so (reload `keys`).
    #[wasm_bindgen(js_name = openCallSignal)]
    pub fn open_call_signal(&mut self, group_id: &[u8], inner: &[u8]) -> Result<String, JsError> {
        live()?;
        self.inner
            .open_call_signal_json(group_id, inner)
            .map_err(throw)
    }

    /// A v2 call's participant media keys through one JSON door
    /// (docs/calls.md §Participant media keys): `op` is `start`
    /// (with `participantId`, the server's answer to JoinCall),
    /// `share`, `remove`, `epoch`, `apply`, `end` or `keys`; the answer is
    /// JSON text. `remove` with a `participantId` (an admin's honored
    /// `Remove`) unbinds that id for the rest of the call. `keys` throws "call state lost" when this core holds no
    /// participation in the call: join again (`start`, a signed `Joined`,
    /// `share`).
    #[wasm_bindgen(js_name = callMedia)]
    pub fn call_media(&mut self, group_id: &[u8], request_json: &str) -> Result<String, JsError> {
        live()?;
        self.inner
            .call_media_json(group_id, request_json)
            .map_err(throw)
    }
}

// ---- Calls, no client ---------------------------------------------------------

/// A call signal (its JSON text's UTF-8 bytes) to its protobuf bytes.
#[wasm_bindgen(js_name = encodeCallSignal)]
pub fn encode_call_signal(signal_json: Vec<u8>) -> Result<Vec<u8>, JsError> {
    // A plaintext argument: this module's own copy, wiped on return.
    let signal_json = Zeroizing::new(signal_json);
    live()?;
    let signal =
        peachy_mls_core::call::signal_from_json(utf8_argument(&signal_json, "a call signal")?)
            .map_err(throw)?;
    peachy_mls_core::call::encode_call_signal(&signal).map_err(throw)
}

/// A call signal's protobuf bytes to JSON text; unknown fields are skipped
/// and an unknown message type reads as `"type":"unknown"`.
#[wasm_bindgen(js_name = decodeCallSignal)]
pub fn decode_call_signal(bytes: &[u8]) -> Result<String, JsError> {
    live()?;
    let signal = peachy_mls_core::call::decode_call_signal(bytes).map_err(throw)?;
    peachy_mls_core::call::signal_to_json(&signal).map_err(throw)
}

/// Whether a call signal (its JSON text's UTF-8 bytes) is sent `urgent`:
/// Offer, Answer, Hangup.
#[wasm_bindgen(js_name = callSignalIsUrgent)]
pub fn call_signal_is_urgent(signal_json: Vec<u8>) -> Result<bool, JsError> {
    // A plaintext argument: this module's own copy, wiped on return.
    let signal_json = Zeroizing::new(signal_json);
    live()?;
    peachy_mls_core::call::call_signal_is_urgent_json(utf8_argument(&signal_json, "a call signal")?)
        .map_err(throw)
}

/// One sender's 16-byte key from a 32-byte call root (for a leaf a staged
/// commit adds).
#[wasm_bindgen(js_name = callSenderKey)]
pub fn call_sender_key(call_root: Vec<u8>, leaf_index: u32) -> Result<Vec<u8>, JsError> {
    // A secret argument: this module's own copy, wiped on return.
    let call_root = Zeroizing::new(call_root);
    live()?;
    peachy_mls_core::call::call_sender_key(&call_root, leaf_index)
        .map(|key| key.to_vec())
        .map_err(throw)
}

/// The AES-128-GCM frame key a frame encryptor's key provider derives from a sender
/// key: HKDF-SHA256, salt "peachy call frame v1", info 128 zero bytes. The
/// web's RTCRtpScriptTransform worker imports this as its AES-GCM key.
#[wasm_bindgen(js_name = callFrameKey)]
pub fn call_frame_key(sender_key: Vec<u8>) -> Result<Vec<u8>, JsError> {
    // A secret argument: this module's own copy, wiped on return.
    let sender_key = Zeroizing::new(sender_key);
    live()?;
    peachy_mls_core::call::call_frame_key(&sender_key)
        .map(|key| key.to_vec())
        .map_err(throw)
}

/// The stagger of this device's in-call self-updates: commit its own
/// `selfUpdate` at `joined + offset + k * 600 s`. `rank` is its position among
/// the participants by ascending leaf index (docs/calls.md, R-K4).
#[wasm_bindgen(js_name = callSelfUpdateOffsetMs)]
pub fn call_self_update_offset_ms(rank: u32, participants: u32) -> f64 {
    refuse_if_poisoned();
    peachy_mls_core::call::call_self_update_offset_ms(rank, participants) as f64
}

/// One step of the ring-state reducer: state JSON (`null` for idle) and event
/// JSON in, `{"state","effects"}` JSON out. Pure.
#[wasm_bindgen(js_name = callRingStep)]
pub fn call_ring_step(state_json: Option<String>, event_json: &str) -> Result<String, JsError> {
    live()?;
    peachy_mls_core::call::ring_step_json(state_json.as_deref().unwrap_or("null"), event_json)
        .map_err(throw)
}

// ---- Content hints (docs/sealed-messages.md §Content hints) ---------------------

/// A group message's epoch, read with no key: -1 for bytes that are not a
/// group message.
#[wasm_bindgen(js_name = messageEpoch)]
pub fn message_epoch(message: &[u8]) -> f64 {
    refuse_if_poisoned();
    peachy_mls_core::hint::peek_message(message)
        .map(|peek| peek.epoch as f64)
        .unwrap_or(-1.0)
}

/// A group message's content hint, read with no key: 0 show the loss, 1 ask
/// for it again, 2 show nothing, 3 ask for a lane frame again; -1 when it
/// carries none this build knows.
#[wasm_bindgen(js_name = messageHint)]
pub fn message_hint(message: &[u8]) -> i32 {
    refuse_if_poisoned();
    peachy_mls_core::hint::peek_message(message)
        .and_then(|peek| peek.hint)
        .map(i32::from)
        .unwrap_or(-1)
}

/// The author's commitment a group message carries (16 bytes), read with no
/// key; empty when it carries none (docs/sealed-messages.md §Asking
/// for a message again).
#[wasm_bindgen(js_name = messageCommitment)]
pub fn message_commitment(message: &[u8]) -> Vec<u8> {
    refuse_if_poisoned();
    peachy_mls_core::hint::peek_message(message)
        .and_then(|peek| peek.commitment)
        .map(|c| c.to_vec())
        .unwrap_or_default()
}

/// The commitment to `actor_id` as the author of a message whose secret is
/// `secret`, in `group_id` (16 bytes): an answer to a resend ask is taken
/// only when this, for its MLS sender and the secret it carries, equals what
/// the unopened message carried.
#[wasm_bindgen(js_name = resendAuthorCommitment)]
pub fn resend_author_commitment(group_id: &[u8], actor_id: &str, secret: Vec<u8>) -> Vec<u8> {
    // A secret argument: this module's own copy, wiped on return.
    let secret = Zeroizing::new(secret);
    let secret: &[u8] = &secret;
    refuse_if_poisoned();
    peachy_mls_core::hint::resend_author_commitment(group_id, actor_id, secret).to_vec()
}

// ---- Handles and envelopes (member-rostered conversations) ------------------

/// How many devices, the founder's own included, one founding commit seats
/// (`MlsClient.seatFounding`): `peachy_mls_core::founding::FOUNDING_MAX_SEATS`.
#[wasm_bindgen(js_name = foundingSeats)]
pub fn founding_seats() -> u32 {
    refuse_if_poisoned();
    peachy_mls_core::founding::FOUNDING_MAX_SEATS as u32
}

/// Tell the core how far the server's clock is ahead of this browser's, in
/// milliseconds (negative when behind), as last measured from a
/// `FetchMailbox` reply's `server_time` against the midpoint of the request's
/// send and its reply's arrival. Every `MlsClient` in this module instance
/// stamps and judges the live call lane's frames and typing's on this
/// browser's clock plus the offset
/// (`peachy_mls_core::set_server_clock_offset_ms`); clamped to ±1 day.
/// A `number` rather than a `bigint`: a millisecond offset is far inside
/// 2^53, and a non-finite one reads as 0. A fresh module instance (after a
/// panic) starts at 0 again, so the caller sets it again.
#[wasm_bindgen(js_name = setServerClockOffsetMs)]
pub fn set_server_clock_offset_ms(offset_ms: f64) {
    refuse_if_poisoned();
    // `as` saturates out of range and maps NaN to 0; the core then clamps.
    let offset = if offset_ms.is_finite() {
        offset_ms.round() as i64
    } else {
        0
    };
    peachy_mls_core::set_server_clock_offset_ms(offset);
}

/// The offset `setServerClockOffsetMs` last set, clamped; 0 until then.
#[wasm_bindgen(js_name = serverClockOffsetMs)]
pub fn server_clock_offset_ms() -> f64 {
    refuse_if_poisoned();
    peachy_mls_core::server_clock_offset_ms() as f64
}

/// The published list (the body of `GET /healthz/device-credential-keys`)
/// read against the server keys this build carries
/// (`peachy_mls_core::server_key_pins`): `""` when they match, else one line
/// naming the kids that differ, for this device's console only. `server` is
/// `"production"` for the production API and `"development"` for any other.
#[wasm_bindgen(js_name = serverKeyPinReport)]
pub fn server_key_pin_report(published_json: &str, server: &str) -> Result<String, JsError> {
    live()?;
    peachy_mls_core::server_key_pin_report(published_json, server).map_err(throw)
}

/// The published list narrowed to the keys the carried set holds under the
/// same bytes, in the same shape: what to trust once pinning is enforced.
#[wasm_bindgen(js_name = serverKeysPinned)]
pub fn server_keys_pinned(published_json: &str, server: &str) -> Result<String, JsError> {
    live()?;
    peachy_mls_core::server_keys_pinned_json(published_json, server).map_err(throw)
}

/// A conversation's handle, `SHA-256("peachy handle v1" ‖ groupId)`: what
/// the server keys a member-rostered conversation by.
#[wasm_bindgen(js_name = groupHandle)]
pub fn group_handle(group_id: &[u8]) -> Result<Vec<u8>, JsError> {
    live()?;
    peachy_mls_core::envelope::group_handle(group_id)
        .map(|handle| handle.to_vec())
        .map_err(throw)
}

/// Wrap `inner`, a seat ask (`kind` 3) or a link preview (`kind` 5), in the
/// envelope that hides which conversation it belongs to, keyed by the group
/// id. Any other kind throws: a message, commit, typing frame or call signal
/// is sealed by `Client.sealEnvelope`, by the group's epoch.
#[wasm_bindgen(js_name = sealEnvelope)]
pub fn seal_envelope(group_id: &[u8], kind: u8, inner: Vec<u8>) -> Result<Vec<u8>, JsError> {
    // A plaintext argument: this module's own copy, wiped on return.
    let inner = Zeroizing::new(inner);
    live()?;
    peachy_mls_core::envelope::seal_envelope(group_id, kind, &inner).map_err(throw)
}

/// Open `envelope` as `groupId`'s, with no client: a group link's preview
/// (kind 5, docs/sealed-messages.md §The preview), read by a holder of the link
/// who is not in the group. `undefined` when it does not open.
#[wasm_bindgen(js_name = openEnvelopeFor)]
pub fn open_envelope_for(group_id: &[u8], envelope: &[u8]) -> Result<MlsOpenedEnvelopeJs, JsError> {
    live()?;
    match peachy_mls_core::envelope::open_envelope_for(group_id, envelope) {
        Ok(opened) => to_js(&OpenedEnvelopeDto {
            group_id: opened.group_id,
            kind: opened.kind,
            inner: opened.inner,
        }),
        Err(_) => Ok(JsValue::UNDEFINED.unchecked_into()),
    }
}

// ---- Enrollment helpers ------------------------------------------------------

/// A fresh 32-byte Ed25519 seed, from the platform CSPRNG
/// (`crypto.getRandomValues` in a browser or a Node worker).
///
/// The first step of enrolling a device: make a seed, publish
/// `signingKeyPublicKey(seed)`, and the credential the server mints comes back
/// bound to it. The seed itself belongs in the key store and never on the wire.
///
/// Both of these forward to `peachy_mls_core::identity`, which is also what
/// the C door Swift and Kotlin come through calls. Three bindings, one answer
/// to where a Peachy signing key comes from — they were two implementations
/// until the C ABI needed the same pair, and the second one would have been a
/// third.
#[wasm_bindgen(js_name = generateSigningKeySeed)]
pub fn generate_signing_key_seed() -> Result<Vec<u8>, JsError> {
    live()?;
    Ok(peachy_mls_core::generate_signing_key_seed()
        .map_err(throw)?
        .to_vec())
}

/// The raw Ed25519 public key for a seed — which is also the leaf signature key
/// and the `device_key` the credential binds. Three names, one 32 bytes.
#[wasm_bindgen(js_name = signingKeyPublicKey)]
pub fn signing_key_public_key(seed: Vec<u8>) -> Result<Vec<u8>, JsError> {
    // A secret argument: this module's own copy, wiped on return.
    let seed = Zeroizing::new(seed);
    let seed: &[u8] = &seed;
    live()?;
    Ok(peachy_mls_core::signing_key_public_key(seed)
        .map_err(throw)?
        .to_vec())
}

// ---- Device linking ---------------------------------------------------------
//
// Approving a new device from one you already have, the QR code that carries
// its key past the server, and the commit-then-reveal two-digit number
// (`peachy_mls_core::device_link`). No client and no group: these are about
// PUBLIC KEYS and nonces and nothing else.
//
// Unconditional, unlike `evaluateFixtureCase` and `TestIssuer` below: this is
// product code, and the bundle a browser loads carries all of it.
//
// **Read the core module's header before putting a number on a screen.** What
// an approving device signs is a public key the SERVER handed it, so the key
// has to cross once through the person: scanned as a QR code, or compared as a
// number over both keys and a nonce from each side, the approver committing to
// its nonce before the new device draws its own.

/// The exact bytes an approving device signs to vouch for another device:
/// `"peachy-device-approval-v1" || 0x00 || deviceId || 0x00 || signingKey`.
///
/// `signingKey` is the approved device's raw 32-byte Ed25519 public key.
/// Throws for an empty `deviceId` or a key that is not 32 bytes, naming the
/// field and the size it wanted.
#[wasm_bindgen(js_name = deviceApprovalStatement)]
pub fn device_approval_statement(device_id: &str, signing_key: &[u8]) -> Result<Vec<u8>, JsError> {
    live()?;
    peachy_mls_core::device_approval_statement(device_id, signing_key).map_err(throw)
}

/// Sign that statement with an approving device's own 32-byte Ed25519 seed —
/// the same seed `signingKeyPublicKey` takes. Deterministic, so the same
/// inputs always produce the same 64 bytes.
#[wasm_bindgen(js_name = signDeviceApproval)]
pub fn sign_device_approval(
    seed: Vec<u8>,
    device_id: &str,
    signing_key: &[u8],
) -> Result<Vec<u8>, JsError> {
    // A secret argument: this module's own copy, wiped on return.
    let seed = Zeroizing::new(seed);
    let seed: &[u8] = &seed;
    live()?;
    Ok(
        peachy_mls_core::sign_device_approval(seed, device_id, signing_key)
            .map_err(throw)?
            .to_vec(),
    )
}

/// Whether `signature` is a genuine approval of `(deviceId, signingKey)` by
/// the holder of `approverKey`.
///
/// **Returns a plain boolean and never throws**, which is the one thing about
/// it worth knowing at a call site: a malformed key, a signature of the wrong
/// length and a signature that did not check out all mean "this approval does
/// not hold". A caller that could tell them apart would be holding an oracle,
/// and every call site would then have to decide which failures are safe to
/// read as `false`.
#[wasm_bindgen(js_name = verifyDeviceApproval)]
pub fn verify_device_approval(
    approver_key: &[u8],
    device_id: &str,
    signing_key: &[u8],
    signature: &[u8],
) -> bool {
    refuse_if_poisoned();
    peachy_mls_core::verify_device_approval(approver_key, device_id, signing_key, signature)
}

/// The approver's 32-byte commitment to its 32-byte nonce, published before
/// the new device draws its own. Throws for a nonce that is not 32 bytes.
#[wasm_bindgen(js_name = deviceLinkCommitment)]
pub fn device_link_commitment(approver_nonce: &[u8]) -> Result<Vec<u8>, JsError> {
    live()?;
    Ok(peachy_mls_core::device_link_commitment(approver_nonce)
        .map_err(throw)?
        .to_vec())
}

/// The two-digit number both devices show, `"00"` to `"99"`. Throws for any
/// input that is not 32 bytes, for two identical keys, and for an approver
/// nonce that does not open the commitment.
#[wasm_bindgen(js_name = deviceLinkNumber)]
pub fn device_link_number(
    new_device_key: &[u8],
    approver_key: &[u8],
    approver_commitment: &[u8],
    device_nonce: &[u8],
    approver_nonce: &[u8],
) -> Result<String, JsError> {
    live()?;
    peachy_mls_core::device_link_number(
        new_device_key,
        approver_key,
        approver_commitment,
        device_nonce,
        approver_nonce,
    )
    .map_err(throw)
}

/// The approver's two-digit number: what the APPROVING device shows after a
/// correct pick, for the person to pick on the new device. Same inputs and
/// throws as `deviceLinkNumber`, another domain.
#[wasm_bindgen(js_name = deviceLinkApproverNumber)]
pub fn device_link_approver_number(
    new_device_key: &[u8],
    approver_key: &[u8],
    approver_commitment: &[u8],
    device_nonce: &[u8],
    approver_nonce: &[u8],
) -> Result<String, JsError> {
    live()?;
    peachy_mls_core::device_link_approver_number(
        new_device_key,
        approver_key,
        approver_commitment,
        device_nonce,
        approver_nonce,
    )
    .map_err(throw)
}

/// The text the new device's QR code carries: its id, its key and the 32-byte
/// link secret it drew for this pairing. Throws for a bad id, key or secret.
#[wasm_bindgen(js_name = deviceLinkQr)]
pub fn device_link_qr(
    device_id: &str,
    signing_key: &[u8],
    link_secret: Vec<u8>,
) -> Result<String, JsError> {
    // A secret argument: this module's own copy, wiped on return.
    let link_secret = Zeroizing::new(link_secret);
    let link_secret: &[u8] = &link_secret;
    live()?;
    peachy_mls_core::device_link_qr(device_id, signing_key, link_secret).map_err(throw)
}

/// Whether a scanned QR code (its text's UTF-8 bytes) names exactly this
/// waiting device and key. A plain boolean that never throws: bytes that are
/// not UTF-8 name nothing.
#[wasm_bindgen(js_name = deviceLinkQrMatches)]
pub fn device_link_qr_matches(scanned: Vec<u8>, device_id: &str, signing_key: &[u8]) -> bool {
    // A secret argument (the code spells the link secret): this module's own
    // copy, wiped on return.
    let scanned = Zeroizing::new(scanned);
    refuse_if_poisoned();
    std::str::from_utf8(&scanned).is_ok_and(|scanned| {
        peachy_mls_core::device_link_qr_matches(scanned, device_id, signing_key)
    })
}

/// The link secret a scanned QR code (its text's UTF-8 bytes) carries, when
/// the code names exactly this waiting device and key; `undefined` for any
/// other code, bytes that are not UTF-8 among them. Never throws.
#[wasm_bindgen(js_name = deviceLinkQrSecret)]
pub fn device_link_qr_secret(
    scanned: Vec<u8>,
    device_id: &str,
    signing_key: &[u8],
) -> Option<Vec<u8>> {
    // A secret argument (the code spells the link secret): this module's own
    // copy, wiped on return.
    let scanned = Zeroizing::new(scanned);
    refuse_if_poisoned();
    let scanned = std::str::from_utf8(&scanned).ok()?;
    peachy_mls_core::device_link_qr_secret(scanned, device_id, signing_key).map(|s| s.to_vec())
}

/// The waiting device's rule: one exchange per pairing. `bound*` is what the
/// pairing already answered (`""` and two empty arrays for nothing yet); the
/// rest is one exchange on the waiting device's row. Answers `"answer"`,
/// `"continue"`, `"ignore"` or `"interrupted"`. Throws for an empty approver
/// id, a key or commitment not 32 bytes, or half a binding.
#[wasm_bindgen(js_name = deviceLinkWaiterStep)]
pub fn device_link_waiter_step(
    bound_approver_id: &str,
    bound_approver_key: &[u8],
    bound_commitment: &[u8],
    approver_id: &str,
    approver_key: &[u8],
    commitment: &[u8],
) -> Result<String, JsError> {
    live()?;
    Ok(peachy_mls_core::device_link_waiter_step(
        bound_approver_id,
        bound_approver_key,
        bound_commitment,
        approver_id,
        approver_key,
        commitment,
    )
    .map_err(throw)?
    .as_str()
    .to_string())
}

/// Sign the approver's commitment for one waiting device: 64 deterministic
/// bytes, posted beside the commitment. Throws for a seed, key or commitment
/// of the wrong length, or an empty device id.
#[wasm_bindgen(js_name = signDeviceLinkCommitment)]
pub fn sign_device_link_commitment(
    seed: Vec<u8>,
    pending_device_id: &str,
    pending_key: &[u8],
    commitment: &[u8],
) -> Result<Vec<u8>, JsError> {
    // A secret argument: this module's own copy, wiped on return.
    let seed = Zeroizing::new(seed);
    let seed: &[u8] = &seed;
    live()?;
    Ok(peachy_mls_core::sign_device_link_commitment(
        seed,
        pending_device_id,
        pending_key,
        commitment,
    )
    .map_err(throw)?
    .to_vec())
}

/// Whether `signature` is `approverKey`'s signature over this commitment for
/// this waiting device. A plain boolean that never throws, as for
/// `verifyDeviceApproval`.
#[wasm_bindgen(js_name = verifyDeviceLinkCommitment)]
pub fn verify_device_link_commitment(
    approver_key: &[u8],
    pending_device_id: &str,
    pending_key: &[u8],
    commitment: &[u8],
    signature: &[u8],
) -> bool {
    refuse_if_poisoned();
    peachy_mls_core::verify_device_link_commitment(
        approver_key,
        pending_device_id,
        pending_key,
        commitment,
        signature,
    )
}

/// A fresh 32-byte link-key seed. The waiting device draws one per pairing
/// and keeps it until its account key arrives.
#[wasm_bindgen(js_name = generateDeviceLinkKemSeed)]
pub fn generate_device_link_kem_seed() -> Result<Vec<u8>, JsError> {
    live()?;
    Ok(peachy_mls_core::generate_device_link_kem_seed()
        .map_err(throw)?
        .to_vec())
}

/// The 1216-byte X-Wing link key a 32-byte seed derives, posted beside the
/// waiting device's nonce. Throws for a seed of the wrong length.
#[wasm_bindgen(js_name = deviceLinkKemPublicKey)]
pub fn device_link_kem_public_key(seed: Vec<u8>) -> Result<Vec<u8>, JsError> {
    // A secret argument: this module's own copy, wiped on return.
    let seed = Zeroizing::new(seed);
    let seed: &[u8] = &seed;
    live()?;
    peachy_mls_core::device_link_kem_public_key(seed).map_err(throw)
}

/// The waiting device's signature over the link key it posts with its nonce:
/// 64 deterministic bytes under its own Ed25519 seed, the key the two-digit
/// number is derived over. Throws for an input of the wrong length or an
/// empty device id.
#[wasm_bindgen(js_name = signDeviceLinkKem)]
pub fn sign_device_link_kem(
    seed: Vec<u8>,
    pending_device_id: &str,
    commitment: &[u8],
    device_nonce: &[u8],
    link_key: &[u8],
) -> Result<Vec<u8>, JsError> {
    // A secret argument: this module's own copy, wiped on return.
    let seed = Zeroizing::new(seed);
    let seed: &[u8] = &seed;
    live()?;
    Ok(peachy_mls_core::sign_device_link_kem(
        seed,
        pending_device_id,
        commitment,
        device_nonce,
        link_key,
    )
    .map_err(throw)?
    .to_vec())
}

/// Whether `signature` is the waiting device's (`pendingKey`, the key the
/// number was derived over) signature over `linkKey` for this exchange. A
/// plain boolean that never throws; an empty link key is `false`.
#[wasm_bindgen(js_name = verifyDeviceLinkKem)]
pub fn verify_device_link_kem(
    pending_key: &[u8],
    pending_device_id: &str,
    commitment: &[u8],
    device_nonce: &[u8],
    link_key: &[u8],
    signature: &[u8],
) -> bool {
    refuse_if_poisoned();
    peachy_mls_core::verify_device_link_kem(
        pending_key,
        pending_device_id,
        commitment,
        device_nonce,
        link_key,
        signature,
    )
}

/// The approving device's rule: fix the waiting device's nonce before
/// revealing, and treat any change after that as an interruption. Answers
/// `"commit"`, `"wait"`, `"reveal"`, `"show"` or `"interrupted"`. On
/// `"reveal"` with nothing bound, the caller stores `listedDeviceNonce` as
/// the bound nonce BEFORE it posts the reveal. Throws for a malformed pending
/// key, commitment or bound nonce.
#[wasm_bindgen(js_name = deviceLinkApproverStep)]
pub fn device_link_approver_step(
    pending_key: &[u8],
    commitment: &[u8],
    bound_device_nonce: &[u8],
    listed_key: &[u8],
    listed_commitment: &[u8],
    listed_device_nonce: &[u8],
    listed_approver_nonce: &[u8],
) -> Result<String, JsError> {
    live()?;
    Ok(peachy_mls_core::device_link_approver_step(
        pending_key,
        commitment,
        bound_device_nonce,
        listed_key,
        listed_commitment,
        listed_device_nonce,
        listed_approver_nonce,
    )
    .map_err(throw)?
    .as_str()
    .to_string())
}

// ---- The account identity key ------------------------------------------------
//
// `peachy_mls_core::account_identity`: one Ed25519 key per account, derived
// from the account store's key, that signs for each of the account's devices.
// A device holding the account key certifies itself; a peer refuses any leaf
// without a certificate (docs/identity.md §The account identity key).

/// The account's public identity key, derived from its 32-byte account key —
/// what `RegisterDevice` publishes as `accountIdentityKey`.
#[wasm_bindgen(js_name = accountIdentityPublicKey)]
pub fn account_identity_public_key(account_key: Vec<u8>) -> Result<Vec<u8>, JsError> {
    // A secret argument: this module's own copy, wiped on return.
    let account_key = Zeroizing::new(account_key);
    let account_key: &[u8] = &account_key;
    live()?;
    Ok(peachy_mls_core::account_identity_public_key(account_key)
        .map_err(throw)?
        .to_vec())
}

/// The account identity key's 64-byte signature over `deviceKey` — what
/// `RegisterDevice` sends as `accountSignature`.
#[wasm_bindgen(js_name = signAccountDevice)]
pub fn sign_account_device(account_key: Vec<u8>, device_key: &[u8]) -> Result<Vec<u8>, JsError> {
    // A secret argument: this module's own copy, wiped on return.
    let account_key = Zeroizing::new(account_key);
    let account_key: &[u8] = &account_key;
    live()?;
    Ok(
        peachy_mls_core::sign_account_device(account_key, device_key)
            .map_err(throw)?
            .to_vec(),
    )
}

/// The account identity key's 64-byte signature REVOKING `deviceKey` — what
/// `RevokeDevice` sends for each row of the removed install, so a peer removes
/// its leaf on the account's word rather than the server's.
#[wasm_bindgen(js_name = signDeviceRevocation)]
pub fn sign_device_revocation(account_key: Vec<u8>, device_key: &[u8]) -> Result<Vec<u8>, JsError> {
    // A secret argument: this module's own copy, wiped on return.
    let account_key = Zeroizing::new(account_key);
    let account_key: &[u8] = &account_key;
    live()?;
    Ok(
        peachy_mls_core::sign_device_revocation(account_key, device_key)
            .map_err(throw)?
            .to_vec(),
    )
}

/// Whether `signature` is `accountIdentityKey` revoking `deviceKey`. A plain
/// boolean that never throws, like `verifyAccountDevice`.
#[wasm_bindgen(js_name = verifyDeviceRevocation)]
pub fn verify_device_revocation(
    account_identity_key: &[u8],
    device_key: &[u8],
    signature: &[u8],
) -> bool {
    peachy_mls_core::verify_device_revocation(account_identity_key, device_key, signature)
}

/// Whether `signature` is `accountIdentityKey` vouching for `deviceKey`. A
/// plain boolean that never throws, like `verifyDeviceApproval`.
#[wasm_bindgen(js_name = verifyAccountDevice)]
pub fn verify_account_device(
    account_identity_key: &[u8],
    device_key: &[u8],
    signature: &[u8],
) -> bool {
    refuse_if_poisoned();
    peachy_mls_core::verify_account_device(account_identity_key, device_key, signature)
}

// ---- The encrypted account store --------------------------------------------
//
// `peachy_mls_core::account_store`, unconditional: the web client keeps the
// same encrypted store as the apps. Every function throws on refusal; an open
// that fails because the key, id, approver or device id is wrong, or because
// the bytes were altered, throws "does not open" and nothing more specific.
// The core module's header says why `approverSigningKey` must come from a
// device on this one's own approver list.

/// A fresh 32-byte account key from the platform CSPRNG.
#[wasm_bindgen(js_name = generateAccountKey)]
pub fn generate_account_key() -> Result<Vec<u8>, JsError> {
    live()?;
    Ok(peachy_mls_core::generate_account_key()
        .map_err(throw)?
        .to_vec())
}

/// Seal `accountKey` as a version-1 (X25519-only) box: `approverSeed` is
/// THIS device's Ed25519 seed, `recipientSigningKey` the new device's public
/// key, `deviceId` its `devices.id`. Returns the 93-byte box. Only a device
/// with its own server-approval switch on opens one: a device a person
/// approves takes only the version-3 box (`accountKeySealHybrid`). For a
/// server-run approver (a test server, or the store-review login's anchor).
#[wasm_bindgen(js_name = accountKeySeal)]
pub fn account_key_seal(
    approver_seed: Vec<u8>,
    recipient_signing_key: &[u8],
    device_id: &str,
    account_key: Vec<u8>,
) -> Result<Vec<u8>, JsError> {
    // A secret argument: this module's own copy, wiped on return.
    let approver_seed = Zeroizing::new(approver_seed);
    let approver_seed: &[u8] = &approver_seed;
    let account_key = Zeroizing::new(account_key);
    let account_key: &[u8] = &account_key;
    live()?;
    peachy_mls_core::account_key_seal(approver_seed, recipient_signing_key, device_id, account_key)
        .map_err(throw)
}

/// Seal `accountKey` for a new device that posted a link key: the
/// post-quantum version-3 box. `recipientLinkKey` is the 1216-byte key the
/// waiting device posted, which the caller MUST have checked with
/// `verifyDeviceLinkKem`. Returns the 1213-byte box.
#[wasm_bindgen(js_name = accountKeySealHybrid)]
pub fn account_key_seal_hybrid(
    approver_seed: Vec<u8>,
    recipient_signing_key: &[u8],
    recipient_link_key: &[u8],
    device_id: &str,
    account_key: Vec<u8>,
) -> Result<Vec<u8>, JsError> {
    // A secret argument: this module's own copy, wiped on return.
    let approver_seed = Zeroizing::new(approver_seed);
    let approver_seed: &[u8] = &approver_seed;
    let account_key = Zeroizing::new(account_key);
    let account_key: &[u8] = &account_key;
    live()?;
    peachy_mls_core::account_key_seal_hybrid(
        approver_seed,
        recipient_signing_key,
        recipient_link_key,
        device_id,
        account_key,
    )
    .map_err(throw)
}

/// The new device's door: the version-3 box, and the version-1 box only when
/// `serverApprovalAllowed`. `linkKeySeed` is the seed of the link key this
/// device posted (empty for none), `confirmedApproverKey` the approver whose
/// number the person picked here (empty for none), `serverApprovalAllowed`
/// this device's own switch. Returns the 32-byte account key.
#[wasm_bindgen(js_name = accountKeyAcceptHybrid)]
#[allow(clippy::too_many_arguments)]
pub fn account_key_accept_hybrid(
    recipient_seed: Vec<u8>,
    approver_signing_key: &[u8],
    device_id: &str,
    sealed_box: &[u8],
    link_key_seed: Vec<u8>,
    confirmed_approver_key: &[u8],
    server_approval_allowed: bool,
) -> Result<Vec<u8>, JsError> {
    // A secret argument: this module's own copy, wiped on return.
    let recipient_seed = Zeroizing::new(recipient_seed);
    let recipient_seed: &[u8] = &recipient_seed;
    let link_key_seed = Zeroizing::new(link_key_seed);
    let link_key_seed: &[u8] = &link_key_seed;
    live()?;
    Ok(peachy_mls_core::account_key_accept_hybrid(
        recipient_seed,
        approver_signing_key,
        device_id,
        sealed_box,
        link_key_seed,
        confirmed_approver_key,
        server_approval_allowed,
    )
    .map_err(throw)?
    .to_vec())
}

/// Which path an opened mailbox entry takes, from the kind the delivery
/// service put on the entry (1 MLS, 5 COMMIT) and the kind sealed inside it:
/// 0 drop (acknowledged unread), 1 message, 2 commit, 3 seat ask, 4 call. A
/// commit only from a COMMIT entry; a message, seat ask or call signal only
/// from an MLS entry. A code this build does not know is a drop.
#[wasm_bindgen(js_name = envelopeDoor)]
pub fn envelope_door(mailbox_kind: u32, envelope_kind: u8) -> u32 {
    peachy_mls_core::envelope::envelope_door(mailbox_kind, envelope_kind) as u32
}

/// Open a version-1 account-key box with no check of who sealed it. Returns
/// the 32-byte account key. A new device takes its key through
/// `accountKeyAcceptHybrid`, under the person's confirmation of the
/// approver's number; this is for tests and tools, and is exported only by a
/// bundle built with the `fixture` feature (`pkg-node/`), never the shipped
/// `pkg/`: whoever lists the approver, the server included, would pick the
/// key it opens to.
#[cfg(feature = "fixture")]
#[wasm_bindgen(js_name = accountKeyOpen)]
pub fn account_key_open(
    recipient_seed: Vec<u8>,
    approver_signing_key: &[u8],
    device_id: &str,
    sealed_box: &[u8],
) -> Result<Vec<u8>, JsError> {
    // A secret argument: this module's own copy, wiped on return.
    let recipient_seed = Zeroizing::new(recipient_seed);
    let recipient_seed: &[u8] = &recipient_seed;
    live()?;
    Ok(peachy_mls_core::account_key_open(
        recipient_seed,
        approver_signing_key,
        device_id,
        sealed_box,
    )
    .map_err(throw)?
    .to_vec())
}

/// Seal a history hand-off's 32-byte attachment `key` to the device it is
/// handed to: `recipientSigningKey` is that device's Ed25519 public key (the
/// one this device just vouched for) and `deviceId` its `devices.id`.
/// Returns the 93-byte box, the pointer's `kb`.
#[wasm_bindgen(js_name = transferKeySeal)]
pub fn transfer_key_seal(
    recipient_signing_key: &[u8],
    device_id: &str,
    key: Vec<u8>,
) -> Result<Vec<u8>, JsError> {
    // A secret argument: this module's own copy, wiped on return.
    let key = Zeroizing::new(key);
    peachy_mls_core::transfer_key_seal(recipient_signing_key, device_id, &key).map_err(throw)
}

/// Open a transfer-key box on the device it was sealed to: `recipientSeed`
/// is THIS device's seed and `deviceId` its own `devices.id`. Returns the
/// 32-byte attachment key; any other device, row or box throws.
#[wasm_bindgen(js_name = transferKeyOpen)]
pub fn transfer_key_open(
    recipient_seed: Vec<u8>,
    device_id: &str,
    sealed_box: &[u8],
) -> Result<Vec<u8>, JsError> {
    // A secret argument: this module's own copy, wiped on return.
    let recipient_seed = Zeroizing::new(recipient_seed);
    let recipient_seed: &[u8] = &recipient_seed;
    Ok(
        peachy_mls_core::transfer_key_open(recipient_seed, device_id, sealed_box)
            .map_err(throw)?
            .to_vec(),
    )
}

/// Seal `plaintext` (at most 65536 bytes; the manifest at most 360000) as the
/// value stored under the 16-byte `id`. The manifest uses sixteen zero bytes.
#[wasm_bindgen(js_name = storeSeal)]
pub fn store_seal(account_key: Vec<u8>, id: &[u8], plaintext: Vec<u8>) -> Result<Vec<u8>, JsError> {
    // Secret and plaintext arguments: this module's own copies, wiped on return.
    let account_key = Zeroizing::new(account_key);
    let account_key: &[u8] = &account_key;
    let plaintext = Zeroizing::new(plaintext);
    live()?;
    peachy_mls_core::store_seal(account_key, id, &plaintext).map_err(throw)
}

/// Open a value `storeSeal` made under the same account key and id.
#[wasm_bindgen(js_name = storeOpen)]
pub fn store_open(account_key: Vec<u8>, id: &[u8], value: &[u8]) -> Result<Vec<u8>, JsError> {
    // A secret argument: this module's own copy, wiped on return.
    let account_key = Zeroizing::new(account_key);
    let account_key: &[u8] = &account_key;
    live()?;
    peachy_mls_core::store_open(account_key, id, value).map_err(throw)
}

/// Unix milliseconds from JS: a whole, finite number, or a refusal.
fn millis_arg(ms: f64, name: &str) -> Result<i64, JsError> {
    if !ms.is_finite() || ms.fract() != 0.0 || ms.abs() > 9_007_199_254_740_991.0 {
        return Err(JsError::new(&format!(
            "{name} must be a whole number of milliseconds"
        )));
    }
    #[allow(clippy::cast_possible_truncation)] // whole and within 2^53, checked above
    Ok(ms as i64)
}

/// Seal a self-note under the account key and sign it as this device (format
/// 0x02, domain "peachy self note v2"). `senderDeviceId` is this device's own
/// `devices.id`, `issuedAtMs` its clock (`Date.now()`), and `deviceSeed` the
/// 32-byte Ed25519 seed of the key that row carries.
#[wasm_bindgen(js_name = noteSealSigned)]
pub fn note_seal_signed(
    account_key: Vec<u8>,
    id: &[u8],
    plaintext: Vec<u8>,
    sender_device_id: &str,
    issued_at_ms: f64,
    device_seed: Vec<u8>,
) -> Result<Vec<u8>, JsError> {
    // Secret and plaintext arguments: this module's own copies, wiped on return.
    let account_key = Zeroizing::new(account_key);
    let account_key: &[u8] = &account_key;
    let device_seed = Zeroizing::new(device_seed);
    let device_seed: &[u8] = &device_seed;
    let plaintext = Zeroizing::new(plaintext);
    live()?;
    peachy_mls_core::note_seal_signed(
        account_key,
        id,
        &plaintext,
        sender_device_id,
        millis_arg(issued_at_ms, "issuedAtMs")?,
        device_seed,
    )
    .map_err(throw)
}

/// The device a signed note SAYS sent it: look it up in this device's own
/// device list before `noteOpenSigned`. Throws on a version-1 note, which
/// names no sender.
#[wasm_bindgen(js_name = noteSender)]
pub fn note_sender(account_key: Vec<u8>, id: &[u8], value: &[u8]) -> Result<String, JsError> {
    // A secret argument: this module's own copy, wiped on return.
    let account_key = Zeroizing::new(account_key);
    let account_key: &[u8] = &account_key;
    live()?;
    peachy_mls_core::note_sender(account_key, id, value).map_err(throw)
}

/// Open a signed note, believing it only when `senderDeviceId` sent it under
/// `senderSigningKey` (the key this device's own list gives that device),
/// issued at most seven days before `nowMs` and at most ten minutes after it.
#[wasm_bindgen(js_name = noteOpenSigned)]
pub fn note_open_signed(
    account_key: Vec<u8>,
    id: &[u8],
    value: &[u8],
    sender_device_id: &str,
    sender_signing_key: &[u8],
    now_ms: f64,
) -> Result<Vec<u8>, JsError> {
    // A secret argument: this module's own copy, wiped on return.
    let account_key = Zeroizing::new(account_key);
    let account_key: &[u8] = &account_key;
    live()?;
    peachy_mls_core::note_open_signed(
        account_key,
        id,
        value,
        sender_device_id,
        sender_signing_key,
        millis_arg(now_ms, "nowMs")?,
    )
    .map_err(throw)
}

/// The core crate's version, for a log line and for a compatibility check.
#[wasm_bindgen(js_name = version)]
pub fn version() -> String {
    refuse_if_poisoned();
    peachy_mls_core::VERSION.to_string()
}

// ---- The golden fixtures ----------------------------------------------------

/// Evaluate one case from `mls/fixtures/rules.json` or
/// `mls/fixtures/credentials.json` and return its verdict as JSON. **Not the
/// server, not a product API, and absent from `pkg/`.**
///
/// One function for both tables, picked by the case's own `kind` — the same
/// shape `peachy_mls_fixture_evaluate_case` has across C, so Swift, Kotlin and
/// JavaScript all feed a new fixture through a door that is already wrapped
/// and already proven to carry a JSON object each way.
///
/// Behind the `fixture` feature, like [`TestIssuer`] is behind `test-issuer`:
/// the bundle a browser loads carries no test harness. `pkg-node/` (tests only)
/// is built with both on.
///
/// A string in and a string out, which is not how one would design a JS API
/// and is exactly the point — the same signature crosses the Swift, Kotlin and
/// JavaScript boundaries unchanged, so the replays of each fixture differ
/// only in their loop and never in the decision. See
/// `peachy_mls_core::fixture`, docs/mls-core.md §Golden rules fixture and
/// docs/mls-core.md §Golden credential fixture.
///
/// Throws on a malformed case, an unknown kind, an unknown proposal kind or an
/// unknown call — which is the behavior a replay needs. A case that no longer
/// addresses anything real has to fail loudly rather than come back with a
/// verdict that happens to match.
#[cfg(feature = "fixture")]
#[wasm_bindgen(js_name = evaluateFixtureCase)]
pub fn evaluate_fixture_case(case_json: &str) -> Result<String, JsError> {
    live()?;
    peachy_mls_core::fixture::evaluate_case_json(case_json).map_err(throw)
}

// ---- The test issuer --------------------------------------------------------

/// A `pdc1` issuer, for tests. **Not the server.**
///
/// Behind the `test-issuer` feature and absent from `pkg/`: the shipped bundle
/// contains no code that can mint a credential. The real issuer is
/// the server's credential issuer and there is exactly one of it.
#[cfg(feature = "test-issuer")]
#[wasm_bindgen]
pub struct TestIssuer {
    inner: peachy_mls_core::issuer::TestIssuer,
}

#[cfg(feature = "test-issuer")]
#[wasm_bindgen]
impl TestIssuer {
    /// An issuer from a fixed 32-byte seed, so a fixture mints the same bytes
    /// on every machine.
    #[wasm_bindgen(constructor)]
    pub fn new(seed: &[u8]) -> Result<TestIssuer, JsError> {
        live()?;
        let seed = fixed32("an issuer seed", seed)?;
        Ok(Self {
            inner: peachy_mls_core::issuer::TestIssuer::from_seed(&seed),
        })
    }

    /// The `kid` this issuer signs with: the first 8 hex of sha256 over its raw
    /// public key, exactly as `keyIdFor` in the server's credential issuer.
    #[wasm_bindgen(getter)]
    pub fn kid(&self) -> String {
        refuse_if_poisoned();
        self.inner.kid().to_string()
    }

    /// The JSON `GET /healthz/device-credential-keys` would return for this
    /// issuer — feed it straight to `new MlsClient(...)`.
    #[wasm_bindgen(js_name = publishedJson)]
    pub fn published_json(&self) -> String {
        refuse_if_poisoned();
        self.inner.published_json()
    }

    /// Mint a credential bound to a device public key. Times are unix seconds.
    pub fn issue(
        &self,
        actor_id: &str,
        device_id: &str,
        device_key: &[u8],
        issued_at: f64,
        expires_at: f64,
    ) -> Result<String, JsError> {
        live()?;
        let device_key = fixed32("a device public key", device_key)?;
        let token = self
            .inner
            .issue(
                actor_id,
                device_id,
                &device_key,
                issued_at as i64,
                expires_at as i64,
            )
            .map_err(throw)?;
        String::from_utf8(token)
            .map_err(|_| JsError::new("the issued credential was not valid UTF-8"))
    }

    /// Mint a credential under the account key you name — its identity key
    /// signs for the device — or, with `undefined`, one with no account
    /// certificate: a device nobody on the account has let in. `issue` signs
    /// under a stand-in account key per actor.
    #[wasm_bindgen(js_name = issueForAccount)]
    pub fn issue_for_account(
        &self,
        actor_id: &str,
        device_id: &str,
        device_key: &[u8],
        account_key: Option<Vec<u8>>,
        issued_at: f64,
        expires_at: f64,
    ) -> Result<String, JsError> {
        live()?;
        let device_key = fixed32("a device public key", device_key)?;
        let token = self
            .inner
            .issue_for_account(
                actor_id,
                device_id,
                &device_key,
                account_key.as_deref(),
                issued_at as i64,
                expires_at as i64,
            )
            .map_err(throw)?;
        String::from_utf8(token)
            .map_err(|_| JsError::new("the issued credential was not valid UTF-8"))
    }
}
