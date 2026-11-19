// SPDX-License-Identifier: MIT
//! # peachy-mls-core
//!
//! Peachy's MLS (RFC 9420) core, over OpenMLS 0.9: the engine behind every
//! Peachy client. docs/mls-core.md is the map.
//!
//! ## The pieces
//!
//! - [`identity`]: a leaf is somebody only if its credential is a `pdc1`
//!   device credential signed by a trusted key, unexpired, and bound to the
//!   leaf's own signature key.
//! - [`rules`]: which proposal types a commit may carry, as a named decision
//!   with pinned discriminants; who may make them is [`policy`].
//! - [`group_meta`]: the group's own state (name, photo, topic, admins,
//!   policy), one `peachy_group_meta` group context extension changed by
//!   commit.
//! - [`group`]: the facade: create, key package, Welcome, send, receive,
//!   remove, self-update, rename, export.
//! - [`device_link`]: approving a new device from one the person already
//!   has: the bytes an approver signs and the commit-then-reveal two-digit
//!   number the person confirms. A QR variant is implemented and reserved;
//!   no client uses it.
//! - [`device_seal`]: the 226-byte box beside a version 3 envelope that
//!   tells its one recipient device the group, the sender and the epoch
//!   secret, with no group state; read always, written once
//!   [`device_seal::DEVICE_SEAL_SENDS`] is true.
//! - [`account_store`]: the account key, records sealed under keys derived
//!   from it, and the 1,213-byte post-quantum box that carries it to a newly
//!   approved device.
//! - [`welcome_frame`]: the padded Welcome frame, the only form a Welcome is read
//!   in, and the form every add and reseat is sent in.
//! - [`carried_commit`]: a commit that brings the leave proposals it names,
//!   sent with every leave's commit.
//! - [`call`]: the media key schedule off the MLS exporter, the sealed
//!   signaling codec and the ring-state reducer (docs/calls.md).
//! - [`storage`]: one `StorageProvider` over a four-verb key-value backend.
//! - [`recovery`]: the group-recovery driver: whether a copy behind or
//!   forked off the group's head keeps going, waits, or forgets the group and
//!   asks back in, judged from a head the client reads.
//!
//! ## Rules of the crate
//!
//! - **No panics across the API.** Everything returns [`error::Result`].
//! - **No `unwrap`, `expect`, slicing or indexing** in the library. `clippy`
//!   denies the first two; the others are review.
//! - **Logs name an event, never a thing.** The core logs through the `log`
//!   facade, at debug to error, only conditions a `Result` cannot carry. Log
//!   lines are fixed text, at most followed by an error's message; none names
//!   a group, handle, key, credential field or content. Errors are returned
//!   as data. OpenMLS logs through the same facade under its own rules.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![forbid(unsafe_code)]

// On x86, polyval's run-time backend dispatch frees every AES-GCM cipher's
// GHASH key unwiped; its portable backend wipes it. mls/.cargo/config.toml
// forces that backend, and a shipping x86 build that lost it is refused here.
#[cfg(all(
    target_os = "android",
    any(target_arch = "x86_64", target_arch = "x86"),
    not(polyval_force_soft)
))]
compile_error!(
    "build the Android x86 core with `--cfg polyval_force_soft` (mls/.cargo/config.toml), \
     or its AES-GCM ciphers free their GHASH keys unwiped"
);

pub mod account_identity;
pub mod account_store;
pub mod call;
pub mod carried_commit;
pub mod client_refusals;
mod commit_padding;
pub mod credential;
pub mod device_link;
pub mod device_seal;
pub mod envelope;
pub mod error;
pub mod founding;
pub mod group;
pub mod group_meta;
pub mod hint;
pub mod identity;
pub mod join_request;
pub mod key_package_lifetime;
pub mod own_devices;
pub mod policy;
pub mod recovery;
pub mod revocation;
pub mod rules;
pub mod secret;
pub mod server_key_pins;
pub mod steward;
pub mod storage;
pub mod typing;
pub mod welcome_frame;

/// The SQLite backend for [`storage::KvStore`], behind the `sqlite` feature.
///
/// On by default for `peachy-mls-cabi` (Apple and Android reach it through the
/// C door) and OFF for `peachy-mls-wasm`, which has no filesystem and would be
/// compiling a C library into a browser bundle for nothing.
#[cfg(feature = "sqlite")]
pub mod sqlite;

#[cfg(feature = "test-issuer")]
pub mod issuer;

/// Replaying the golden fixtures — `mls/fixtures/rules.json` (group policy)
/// and `mls/fixtures/credentials.json` (device-credential rejections). Behind
/// the `fixture` feature: a shipped client has no use for a JSON-driven test
/// harness. See docs/mls-core.md §Golden rules fixture and
/// docs/mls-core.md §Golden credential fixture.
#[cfg(feature = "fixture")]
pub mod fixture;

pub use account_identity::{
    account_device_statement, account_identity_public_key, sign_account_device,
    verify_account_device, ACCOUNT_DEVICE_DOMAIN, ACCOUNT_IDENTITY_DOMAIN, ACCOUNT_SIGNATURE_BYTES,
};
// The unvouched version-1 box opener: for tests and tools only, never a
// client's door (docs/identity.md §Pairing a device with no screen).
#[cfg(feature = "fixture")]
pub use account_store::account_key_open;
// The removed QR code's version-2 sealer: tests and the fixture only.
#[cfg(feature = "fixture")]
pub use account_store::account_key_seal_linked;
pub use account_store::{
    account_key_accept_hybrid, account_key_seal, account_key_seal_hybrid, generate_account_key,
    note_open_signed, note_seal_signed, note_sender, store_open, store_seal, transfer_key_open,
    transfer_key_seal, ACCOUNT_KEY_BOX_BYTES, ACCOUNT_KEY_BOX_HYBRID_BYTES,
    ACCOUNT_KEY_BOX_HYBRID_VERSION, ACCOUNT_KEY_BOX_LINKED_VERSION, ACCOUNT_KEY_BYTES,
    LINK_KEY_BYTES, MANIFEST_ID, MAX_MANIFEST_PLAINTEXT_BYTES, MAX_NOTE_SENDER_BYTES,
    MAX_STORE_PLAINTEXT_BYTES, NOTE_MAX_AGE_MS, NOTE_MAX_AHEAD_MS, NOTE_SIGNED_VERSION,
    STORE_ID_BYTES, TRANSFER_KEY_BOX_BYTES, TRANSFER_KEY_BYTES,
};
pub use client_refusals::{ClientRefusal, ClientRefusals, CLIENT_REFUSALS};
pub use credential::{is_valid_id, CredentialPayload, DeviceCredential, MAX_ID_BYTES};
pub use device_link::{
    device_approval_statement, device_link_approver_number, device_link_approver_step,
    device_link_commitment, device_link_commitment_statement, device_link_kem_public_key,
    device_link_kem_statement, device_link_number, device_link_qr, device_link_qr_matches,
    device_link_qr_secret, device_link_waiter_step, generate_device_link_kem_seed,
    sign_device_approval, sign_device_link_commitment, sign_device_link_kem,
    verify_device_approval, verify_device_link_commitment, verify_device_link_kem,
    DeviceLinkApproverStep, DeviceLinkWaiterStep, DEVICE_APPROVAL_DOMAIN,
    DEVICE_APPROVAL_SIGNATURE_BYTES, DEVICE_LINK_APPROVER_NUMBER_DOMAIN, DEVICE_LINK_COMMIT_DOMAIN,
    DEVICE_LINK_COMMIT_SIGNATURE_DOMAIN, DEVICE_LINK_KEM_PUBLIC_KEY_BYTES,
    DEVICE_LINK_KEM_SEED_BYTES, DEVICE_LINK_KEM_SIGNATURE_DOMAIN, DEVICE_LINK_KEY_BYTES,
    DEVICE_LINK_NONCE_BYTES, DEVICE_LINK_NUMBER_DOMAIN, DEVICE_LINK_QR_PREFIX,
};
#[cfg(any(test, feature = "fixture"))]
#[doc(hidden)]
pub use device_seal::device_seal_with_ephemeral;
pub use device_seal::{
    device_seal, device_seal_open, OpenedSeal, DEVICE_SEAL_BYTES, DEVICE_SEAL_MAX_GROUP_ID_BYTES,
    DEVICE_SEAL_SENDS, DEVICE_SEAL_VERSION,
};
pub use error::{CredentialRejection, Error, Result};
pub use group::{
    Client, ClientConfig, CommitBundle, CommitOutcome, HeldDisposition, HeldFate, HoldAnswer,
    Incoming, RejoinReport, RosterEntry, SavedCommit, APPLICATION_PADDING_BLOCK,
    ENVELOPE_PAST_EPOCHS, HELD_ENVELOPES_KEPT, HELD_ENVELOPE_MAX_AGE_MS,
    LAST_RESORT_ARCHIVE_AGE_SECONDS, LAST_RESORT_ROTATION_INTERVAL_SECONDS,
    LEAF_ROTATION_FRAME_BUDGET, LEAF_ROTATION_INTERVAL_SECONDS, MAXIMUM_FORWARD_DISTANCE,
    OUT_OF_ORDER_TOLERANCE, PEACHY_CIPHERSUITE, PEACHY_READS_EPOCH_ENVELOPES, RETAINED_PAST_EPOCHS,
    ROUND_TRIP_ROTATION_MIN_SECONDS, SEALED_HELD_BUDGET_BYTES, SEALED_HELD_MAX,
    SEALED_HELD_MAX_BYTES, SEND_KEY_LABEL,
};
pub use group_meta::{MAX_GROUP_META_BYTES, PEACHY_GROUP_META_EXTENSION_TYPE};
pub use identity::{
    generate_signing_key_seed, judge_message_sender, server_clock_offset_ms,
    set_server_clock_offset_ms, signing_key_public_key, Clock, FixedClock, MessageSenderVerdict,
    PeachyIdentity, PeachyIdentityProvider, SystemClock, TrustedServerKeys,
    CREDENTIAL_REFRESH_WINDOW_SECONDS, ED25519_SEED_BYTES, EXPIRED_LEAF_GRACE_SECONDS,
    MAX_TREE_CLOCK_JUMP_SECONDS, RENEWAL_CUTOFF_MARGIN_SECONDS, SERVER_CLOCK_OFFSET_MAX_MS,
};
pub use join_request::{
    check_join_request, join_request_nonce, join_request_statement, sign_join_request,
    verify_join_request_signature, JoinRequestVerdict, JOIN_REQUEST_DOMAIN,
    JOIN_REQUEST_FUTURE_SKEW_SECONDS, JOIN_REQUEST_MAX_AGE_SECONDS, JOIN_REQUEST_NONCE_BYTES,
    JOIN_REQUEST_PROOF_BYTES,
};
pub use own_devices::{OwnDeviceStanding, OwnDeviceVerdict, OWN_DEVICE_TRUST_VERSION};
pub use recovery::{HeadReadKind, HeadReading, RecoveryStep};
pub use revocation::{
    device_revocation_statement, install_revocation_targets, sign_device_revocation,
    stale_leaf_removable, stale_leaf_removable_when, verify_device_revocation,
    InstallRevocationRequest, InstallRevocationRow, StaleLeafClock, DEVICE_REVOCATION_BYTES,
    DEVICE_REVOCATION_DOMAIN, RESTORE_SIGN_OUT_SECONDS, SIGNED_REVOCATIONS_ENFORCED,
};
pub use rules::{
    DenyReason, PeachyMlsRules, PolicyDecision, ProposalContext, ProposalKind, SenderKind,
};
pub use secret::Secret;
pub use server_key_pins::{
    server_key_pin_report, server_keys_pinned_json, PinComparison, PinMode, PINNED_DEVELOPMENT,
    PINNED_PRODUCTION,
};
#[cfg(feature = "sqlite")]
pub use sqlite::SqliteKv;
pub use storage::{
    check_schema_stamp, schema_prefix, schema_stamp_key, storage_key, KvEntry, KvError, KvStore,
    MemoryKv, PeachyProvider, PeachyStorage, STORAGE_SCHEMA_VERSION,
};

/// The version of this crate, for a C caller and for a log line somewhere else.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod derivation_labels {
    /// No two derivations from one input secret alias: within each group of
    /// labels fed the same input, no label is a prefix of another, so no
    /// label with its suffix can equal another's. Across groups a prefix is
    /// allowed (`"peachy call sender"` is one of `"peachy call sender v2"`),
    /// because the inputs differ. A new label is a new row in its group.
    #[test]
    fn no_derivation_domain_is_a_prefix_of_another() {
        use crate::account_store::{
            ACCOUNT_KEY_BOX_DOMAIN, ACCOUNT_KEY_BOX_HYBRID_DOMAIN, ACCOUNT_KEY_BOX_LINKED_DOMAIN,
            NOTE_KEY_DOMAIN, NOTE_SIGNED_KEY_DOMAIN, STORE_RECORD_KEY_DOMAIN, TRANSFER_KEY_DOMAIN,
        };
        use crate::call::{
            CALL_MEDIA_ADVANCE_INFO, CALL_MEDIA_KEY_INFO, CALL_SENDER_INFO, CALL_SENDER_INFO_V2,
        };
        use crate::envelope::{
            ENVELOPE_LABEL, EPOCH_ENVELOPE_LABEL, EPOCH_ROUTE_LABEL, HANDLE_LABEL, ROUTE_LABEL,
        };

        let groups: [(&str, &[&[u8]]); 15] = [
            // Every row of the table on `account_store::hkdf32`: the identity
            // domain bare, the rest followed by `0x00` and a suffix.
            (
                "hkdf32",
                &[
                    crate::account_identity::ACCOUNT_IDENTITY_DOMAIN.as_bytes(),
                    STORE_RECORD_KEY_DOMAIN.as_bytes(),
                    NOTE_KEY_DOMAIN.as_bytes(),
                    NOTE_SIGNED_KEY_DOMAIN.as_bytes(),
                    ACCOUNT_KEY_BOX_DOMAIN.as_bytes(),
                    ACCOUNT_KEY_BOX_LINKED_DOMAIN.as_bytes(),
                    ACCOUNT_KEY_BOX_HYBRID_DOMAIN.as_bytes(),
                    TRANSFER_KEY_DOMAIN.as_bytes(),
                    // The registration lock's token, which the clients derive
                    // themselves (docs/account-store.md §Key
                    // derivation domains).
                    b"peachy registration lock v1",
                ],
            ),
            // SHA-256 over the label, then the group id with no separator.
            ("group id", &[HANDLE_LABEL, ENVELOPE_LABEL, ROUTE_LABEL]),
            // SHA-256 over the label, then an epoch's envelope secret.
            (
                "epoch envelope secret",
                &[EPOCH_ENVELOPE_LABEL, EPOCH_ROUTE_LABEL],
            ),
            // HKDF-Expand infos on the v1 call root, then the leaf index.
            ("v1 call root", &[CALL_SENDER_INFO]),
            // HKDF-Expand infos on Extract(v2 call root, media secret), then
            // the leaf index.
            ("v2 sender key", &[CALL_SENDER_INFO_V2]),
            // HKDF-Expand infos on a media secret.
            ("media secret", &[CALL_MEDIA_ADVANCE_INFO]),
            // HKDF-Extract salts over a call sender key; the frame keys are
            // expanded from that extract alone.
            (
                "call sender key salt",
                &[crate::call::keys::CALL_FRAME_RATCHET_SALT.as_bytes()],
            ),
            // HPKE infos on a media grant's key agreement, then call id and
            // the two leaves.
            ("media grant", &[CALL_MEDIA_KEY_INFO]),
            // Statements one device key signs: the domain, then 0x00 and the
            // fields. The device key is also the device's MLS leaf key, so
            // the typing and live-lane signatures are here too, and so is the
            // proof a registration carries that its login holds the device
            // key, which the clients sign outside this crate. (MLS's own
            // signatures sign a length-prefixed content under an "MLS 1.0 "
            // label, so they cannot collide with these; the account
            // certificate is signed by the account identity key, another key.)
            (
                "device key signature",
                &[
                    crate::device_link::DEVICE_APPROVAL_DOMAIN.as_bytes(),
                    crate::device_link::DEVICE_LINK_COMMIT_SIGNATURE_DOMAIN.as_bytes(),
                    crate::device_link::DEVICE_LINK_KEM_SIGNATURE_DOMAIN.as_bytes(),
                    crate::account_store::NOTE_SIGNATURE_DOMAIN.as_bytes(),
                    crate::join_request::JOIN_REQUEST_DOMAIN.as_bytes(),
                    crate::typing::TYPING_SIGNATURE_DOMAIN.as_bytes(),
                    crate::call::frame::CALL_LIVE_SIGNATURE_DOMAIN.as_bytes(),
                    b"peachy-device-key-proof-v1",
                ],
            ),
            // SHA-256 over the domain, then 0x00 and the device link's
            // values: the approver's commitment, and the two numbers.
            (
                "device link hash",
                &[
                    crate::device_link::DEVICE_LINK_COMMIT_DOMAIN.as_bytes(),
                    crate::device_link::DEVICE_LINK_NUMBER_DOMAIN.as_bytes(),
                    crate::device_link::DEVICE_LINK_APPROVER_NUMBER_DOMAIN.as_bytes(),
                ],
            ),
            // SHA-256 over the label, then length-prefixed fields: the resend
            // author's commitment, and two keys this device's own store
            // files under. Their inputs differ; checked together anyway.
            (
                "length-prefixed digest",
                &[
                    crate::hint::RESEND_COMMITMENT_DOMAIN.as_bytes(),
                    b"peachy welcome taken v2",
                    crate::group::ACCOUNT_LEAF_DOMAIN,
                    crate::group::ACCOUNT_LEAF_V1_DOMAIN,
                ],
            ),
            // HKDF-SHA256 infos over a device seal's agreements, then 0x00
            // and the public keys.
            (
                "device seal agreement",
                &[
                    crate::device_seal::DEVICE_SEAL_SENDER_DOMAIN.as_bytes(),
                    crate::device_seal::DEVICE_SEAL_BODY_DOMAIN.as_bytes(),
                ],
            ),
            // Statements the account identity key signs: the domain, then
            // 0x00 and the device key.
            (
                "account identity key signature",
                &[
                    crate::account_identity::ACCOUNT_DEVICE_DOMAIN.as_bytes(),
                    crate::revocation::DEVICE_REVOCATION_DOMAIN.as_bytes(),
                ],
            ),
            // HKDF-SHA256 infos over an epoch's send key.
            (
                "send key",
                &[
                    crate::steward::COMMIT_STAMP_INFO.as_bytes(),
                    crate::steward::COMMIT_LOG_INFO.as_bytes(),
                ],
            ),
            // Statements the steward key signs: the domain, then the fields.
            (
                "steward key signature",
                &[
                    crate::steward::STEWARD_REPAIR_DOMAIN.as_bytes(),
                    crate::steward::STEWARD_VETO_DOMAIN.as_bytes(),
                    crate::steward::STEWARD_CHANGE_DOMAIN.as_bytes(),
                ],
            ),
        ];
        for (input, labels) in groups {
            for (i, a) in labels.iter().enumerate() {
                assert!(!a.contains(&0), "{input}: {a:?} holds the separator byte");
                for (j, b) in labels.iter().enumerate() {
                    if i != j {
                        assert!(!b.starts_with(a), "{input}: {a:?} is a prefix of {b:?}");
                    }
                }
            }
        }

        // The MLS exporter labels: MLS length-prefixes the label, so distinct
        // is enough.
        let exporter = [
            crate::SEND_KEY_LABEL,
            crate::call::CALL_EXPORTER_LABEL,
            crate::call::CALL_EXPORTER_LABEL_V2,
            crate::call::CALL_LIVE_EXPORTER_LABEL,
            crate::envelope::EPOCH_ENVELOPE_EXPORTER_LABEL,
            crate::steward::COMMIT_MAC_LABEL,
            crate::typing::TYPING_EXPORTER_LABEL,
            crate::welcome_frame::WELCOME_GAP_EXPORTER_LABEL,
        ];
        for (i, a) in exporter.iter().enumerate() {
            for b in &exporter[i + 1..] {
                assert_ne!(a, b, "two exporter labels are {a:?}");
            }
        }
    }
}
